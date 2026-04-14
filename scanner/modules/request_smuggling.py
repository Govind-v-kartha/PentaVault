"""HTTP request smuggling probe module.

Tests for CL.TE, TE.CL, and TE.TE obfuscation desync vulnerabilities
using timing-based differential analysis and multiple framing probes.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Callable
from urllib.parse import urlparse

from scanner.utils.logger import get_logger

log = get_logger("request_smuggling")

# ── Raw socket helpers ─────────────────────────────────────────────
# httpx normalizes headers, defeating smuggling probes. Raw sockets
# are required to send intentionally malformed framing headers.


def _raw_request(host: str, port: int, use_tls: bool, raw_bytes: bytes, timeout: float = 10.0) -> tuple[float, bytes]:
    """Send raw bytes and return (elapsed_seconds, response_bytes)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        start = time.monotonic()
        sock.sendall(raw_bytes)
        chunks = []
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        except (socket.timeout, ConnectionResetError, ssl.SSLError):
            pass
        elapsed = time.monotonic() - start
        return elapsed, b"".join(chunks)
    except Exception:
        return 0.0, b""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _parse_target(base_url: str) -> tuple[str, int, bool, str]:
    """Return (host, port, use_tls, path) from a URL."""
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    return host, port, use_tls, path


def _measure_baseline(host: str, port: int, use_tls: bool, path: str, cookie: str | None, timeout: float) -> float:
    """Send a normal POST and return the response time."""
    headers = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\nConnection: close\r\n"
    if cookie:
        headers += f"Cookie: {cookie}\r\n"
    raw = (headers + "\r\nx=1").encode()
    elapsed, _ = _raw_request(host, port, use_tls, raw, timeout=timeout)
    return elapsed


# ── Probe functions ────────────────────────────────────────────────

def _probe_cl_te(host: str, port: int, use_tls: bool, path: str, cookie: str | None, baseline_time: float, timeout: float) -> dict | None:
    """CL.TE probe: front-end uses Content-Length, back-end uses Transfer-Encoding.
    
    Sends a request where CL says the body is short, but the chunked body
    contains an incomplete chunk that would cause the back-end to wait/timeout.
    """
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
    )
    if cookie:
        headers += f"Cookie: {cookie}\r\n"
    # Body: CL=4 reads "1\r\nZ" but chunked sees chunk of size 1 ("Z") then waits
    # for next chunk — if back-end uses TE, it hangs.
    body = "1\r\nZ\r\nQ\r\n"
    raw = (headers + "\r\n" + body).encode()
    elapsed, resp = _raw_request(host, port, use_tls, raw, timeout=timeout)

    # Desync indicator: response took significantly longer than baseline
    if elapsed > baseline_time * 2.5 and elapsed > 3.0:
        return {
            "variant": "CL.TE",
            "evidence": f"Response delayed {elapsed:.1f}s vs baseline {baseline_time:.1f}s — potential CL.TE desync",
            "payload": "Content-Length: 4 + Transfer-Encoding: chunked with incomplete chunk",
        }

    # Status-based: unusual error that differs from baseline
    resp_str = resp.decode("utf-8", errors="ignore")[:500]
    for code in ("400", "500", "502", "504"):
        if f"HTTP/1.1 {code}" in resp_str or f"HTTP/1.0 {code}" in resp_str:
            return {
                "variant": "CL.TE",
                "evidence": f"Ambiguous CL+TE request produced HTTP {code} — parser disagreement likely",
                "payload": "POST with conflicting Content-Length and Transfer-Encoding",
            }
    return None


def _probe_te_cl(host: str, port: int, use_tls: bool, path: str, cookie: str | None, baseline_time: float, timeout: float) -> dict | None:
    """TE.CL probe: front-end uses Transfer-Encoding, back-end uses Content-Length.
    
    Sends chunked request where CL is longer than actual chunked data.
    Back-end waits for more data if it trusts CL over TE.
    """
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 50\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
    )
    if cookie:
        headers += f"Cookie: {cookie}\r\n"
    # TE sees: chunk "0\r\n\r\n" (end), but CL=50 makes server wait for more
    body = "0\r\n\r\n"
    raw = (headers + "\r\n" + body).encode()
    elapsed, resp = _raw_request(host, port, use_tls, raw, timeout=timeout)

    if elapsed > baseline_time * 2.5 and elapsed > 3.0:
        return {
            "variant": "TE.CL",
            "evidence": f"Response delayed {elapsed:.1f}s vs baseline {baseline_time:.1f}s — potential TE.CL desync",
            "payload": "Transfer-Encoding: chunked + oversized Content-Length",
        }
    return None


def _probe_te_te_obfuscation(host: str, port: int, use_tls: bool, path: str, cookie: str | None, baseline_time: float, timeout: float) -> dict | None:
    """TE.TE probe: obfuscated Transfer-Encoding to cause parser disagreement.
    
    One server may process the TE header, another may ignore it due to
    the obfuscation, falling back to Content-Length.
    """
    obfuscations = [
        "Transfer-Encoding: chunked\r\nTransfer-encoding: identity",
        "Transfer-Encoding: \tchunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        "Transfer-Encoding : chunked",
        " Transfer-Encoding: chunked",
    ]
    for te_header in obfuscations:
        headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{te_header}\r\n"
            f"Connection: close\r\n"
        )
        if cookie:
            headers += f"Cookie: {cookie}\r\n"
        body = "0\r\n\r\n"
        raw = (headers + "\r\n" + body).encode()
        elapsed, resp = _raw_request(host, port, use_tls, raw, timeout=timeout)

        resp_str = resp.decode("utf-8", errors="ignore")[:500]

        if elapsed > baseline_time * 2.5 and elapsed > 3.0:
            return {
                "variant": "TE.TE Obfuscation",
                "evidence": f"Obfuscated TE header caused {elapsed:.1f}s delay (baseline {baseline_time:.1f}s)",
                "payload": te_header,
            }

        for code in ("400", "500", "502"):
            if f"HTTP/1.1 {code}" in resp_str or f"HTTP/1.0 {code}" in resp_str:
                return {
                    "variant": "TE.TE Obfuscation",
                    "evidence": f"Obfuscated TE produced HTTP {code} — inconsistent TE parsing",
                    "payload": te_header,
                }
    return None


# ── Public API ─────────────────────────────────────────────────────

def test_request_smuggling(
    base_url: str,
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Probe for HTTP request smuggling via CL.TE, TE.CL, and TE.TE desync."""
    findings: list[dict] = []
    host, port, use_tls, path = _parse_target(base_url)

    # Measure baseline timing
    try:
        baseline_time = _measure_baseline(host, port, use_tls, path, cookie, timeout)
    except Exception:
        baseline_time = 1.0
    if baseline_time <= 0:
        baseline_time = 0.5

    log.info("[Smuggling] Baseline response time: %.2fs", baseline_time)

    probes = [
        ("CL.TE", _probe_cl_te),
        ("TE.CL", _probe_te_cl),
        ("TE.TE", _probe_te_te_obfuscation),
    ]
    if quick:
        probes = probes[:2]

    for probe_name, probe_fn in probes:
        if should_stop and should_stop():
            log.info("Request smuggling scan cancelled before %s probe", probe_name)
            break
        try:
            result = probe_fn(host, port, use_tls, path, cookie, baseline_time, timeout)
            if result:
                findings.append(_to_finding(base_url, result))
                log.info("[Smuggling] %s detected at %s", result["variant"], base_url)
        except Exception as exc:
            log.debug("[Smuggling] %s probe failed: %s", probe_name, exc)

    log.info("Request smuggling scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, result: dict) -> dict:
    from scanner.core.cvss_builder import build_finding_cvss
    vector, score, severity = build_finding_cvss("request_smuggling")
    return {
        "title": f"HTTP Request Smuggling ({result['variant']}) on {urlparse(url).path or '/'}",
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "affected_url": url,
        "parameter": "Request framing",
        "payload": result["payload"],
        "evidence": result["evidence"],
        "remediation": "Ensure front-end and back-end servers enforce identical request parsing. "
                       "Disable conflicting TE/CL handling, normalize Transfer-Encoding, "
                       "and reject ambiguous requests at the proxy layer.",
        "owasp_category": "A05:2025 - Injection",
    }
