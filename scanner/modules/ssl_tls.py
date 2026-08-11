"""SSL/TLS Security Analysis Module for PentaVault.

Analyzes SSL/TLS configuration, certificate validity, deprecated protocol support,
cipher strength, and transport security headers (HSTS).
"""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("ssl_tls")

# Denylist for weak / deprecated ciphers
_WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON", "ADH", "AECDH", "EXP"
}

# (Protocol Name, Max TLS Version Enum, Severity, CVSS Score, Vector)
_DEPRECATED_PROTOCOLS: list[tuple[str, Any, str, float, str]] = []

if hasattr(ssl, "TLSVersion"):
    if hasattr(ssl.TLSVersion, "SSLv3"):
        _DEPRECATED_PROTOCOLS.append((
            "SSLv3",
            ssl.TLSVersion.SSLv3,
            "High",
            7.5,
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ))
    if hasattr(ssl.TLSVersion, "TLSv1"):
        _DEPRECATED_PROTOCOLS.append((
            "TLSv1.0",
            ssl.TLSVersion.TLSv1,
            "Medium",
            5.3,
            "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ))
    if hasattr(ssl.TLSVersion, "TLSv1_1"):
        _DEPRECATED_PROTOCOLS.append((
            "TLSv1.1",
            ssl.TLSVersion.TLSv1_1,
            "Medium",
            5.3,
            "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ))


def _extract_host_port(base_url: str) -> tuple[str, int, str]:
    """Parse base_url into (hostname, port, scheme)."""
    parsed = urlparse(base_url)
    scheme = (parsed.scheme or "http").lower()
    hostname = parsed.hostname or "localhost"
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if scheme == "https" else 80
    return hostname, port, scheme


def test_ssl_tls(
    base_url: str,
    should_stop: Callable[[], bool] | None = None,
    timeout: float = 10.0,
    quick: bool = False,
) -> list[dict[str, Any]]:

    """Analyze SSL/TLS security configuration for the given base URL.

    Returns a list of finding dicts.
    """
    findings: list[dict[str, Any]] = []
    hostname, port, scheme = _extract_host_port(base_url)

    # 1. HSTS Header Check (HTTP Level)
    if not (should_stop and should_stop()):
        try:
            target_url = base_url if base_url.startswith("http") else f"https://{hostname}:{port}"
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
                resp = client.get(target_url)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                if "strict-transport-security" not in resp_headers:
                    findings.append({
                        "title": f"Missing HTTP Strict Transport Security (HSTS) on {hostname}",
                        "severity": "Medium",
                        "cvss_score": 4.2,
                        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        "affected_url": target_url,
                        "parameter": "Strict-Transport-Security",
                        "payload": "N/A",
                        "evidence": "Strict-Transport-Security header not present in response",
                        "remediation": "Add Strict-Transport-Security header with max-age >= 31536000.",
                        "owasp_category": "A02:2025 - Security Misconfiguration",
                    })
        except httpx.HTTPError as exc:
            log.debug("HSTS check HTTP request failed for %s: %s", base_url, exc)

    # If scheme is plain HTTP and port is 80, attempt HTTPS port 443 checks if target accepts it
    if scheme == "http" and port == 80:
        port = 443

    # Check cancellation checkpoint
    if should_stop and should_stop():
        return findings

    # 2. Establish TLS Connection & Inspect Certificate
    cert: dict[str, Any] | None = None
    cert_verified = True
    verified_cipher: tuple[str, str, int] | None = None

    # First attempt: Verified Default Context
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                verified_cipher = ssock.cipher()
    except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
        cert_verified = False
        findings.append({
            "title": f"Untrusted or Self-Signed SSL/TLS Certificate on {hostname}",
            "severity": "High",
            "cvss_score": 7.4,
            "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "affected_url": f"https://{hostname}:{port}",
            "parameter": "SSL/TLS Certificate",
            "payload": "N/A",
            "evidence": f"Certificate verification failed: {exc}",
            "remediation": "Replace self-signed or untrusted certificate with one signed by a trusted CA.",
            "owasp_category": "A02:2025 - Security Misconfiguration",
        })
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        log.info("Could not establish TLS connection to %s:%d: %s", hostname, port, exc)
        return findings

    # Second attempt: Unverified Context (if verification failed) to gather cert metadata
    if not cert_verified:
        try:
            ctx_unverified = ssl.create_default_context()
            ctx_unverified.check_hostname = False
            ctx_unverified.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx_unverified.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    verified_cipher = ssock.cipher()
        except Exception as exc:
            log.debug("Unverified cert fetch failed for %s: %s", hostname, exc)

    # 3. Certificate Expiry & Hostname Mismatch Checks
    if cert:
        # Expiry Check
        not_after_str = cert.get("notAfter")
        if not_after_str:
            try:
                # Format: 'May 22 23:59:59 2026 GMT'
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                days_left = (not_after - now).days

                if days_left < 0:
                    findings.append({
                        "title": f"Expired SSL/TLS Certificate on {hostname}",
                        "severity": "High",
                        "cvss_score": 7.5,
                        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:P/I:P/A:N",
                        "affected_url": f"https://{hostname}:{port}",
                        "parameter": "Certificate Expiry",
                        "payload": "N/A",
                        "evidence": f"Certificate expired {abs(days_left)} days ago (Not After: {not_after_str})",
                        "remediation": "Renew the SSL/TLS certificate immediately.",
                        "owasp_category": "A02:2025 - Security Misconfiguration",
                    })
                elif days_left <= 30:
                    findings.append({
                        "title": f"SSL/TLS Certificate Expiring Soon on {hostname}",
                        "severity": "Low",
                        "cvss_score": 3.7,
                        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        "affected_url": f"https://{hostname}:{port}",
                        "parameter": "Certificate Expiry",
                        "payload": "N/A",
                        "evidence": f"Certificate expires in {days_left} days (Not After: {not_after_str})",
                        "remediation": "Plan certificate renewal before expiration date.",
                        "owasp_category": "A02:2025 - Security Misconfiguration",
                    })
            except ValueError as exc:
                log.debug("Failed to parse cert notAfter date '%s': %s", not_after_str, exc)

        # Hostname Mismatch Check
        alt_names: list[str] = []
        for item in cert.get("subjectAltName", ()):
            if len(item) == 2 and item[0].lower() in ("dns", "ip"):
                alt_names.append(item[1])

        # Common Name
        common_names: list[str] = []
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                if key == "commonName":
                    common_names.append(val)

        all_names = set(alt_names + common_names)
        if all_names and cert_verified:
            # Check basic match
            match = any(
                name == hostname or (name.startswith("*.") and hostname.endswith(name[1:]))
                for name in all_names
            )
            if not match:
                findings.append({
                    "title": f"SSL/TLS Certificate Hostname Mismatch on {hostname}",
                    "severity": "Medium",
                    "cvss_score": 6.5,
                    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "affected_url": f"https://{hostname}:{port}",
                    "parameter": "Subject Alternative Name",
                    "payload": "N/A",
                    "evidence": f"Target hostname '{hostname}' not covered by certificate names: {', '.join(all_names)}",
                    "remediation": "Reissue certificate to include valid Subject Alternative Names for target host.",
                    "owasp_category": "A02:2025 - Security Misconfiguration",
                })

    # 4. Cipher Suite Check
    if verified_cipher:
        cipher_name = verified_cipher[0].upper()
        if any(weak in cipher_name for weak in _WEAK_CIPHERS):
            findings.append({
                "title": f"Weak SSL/TLS Cipher Suite Offered on {hostname}",
                "severity": "Medium",
                "cvss_score": 5.9,
                "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "affected_url": f"https://{hostname}:{port}",
                "parameter": "Cipher Suite",
                "payload": "N/A",
                "evidence": f"Negotiated cipher suite '{cipher_name}' uses weak algorithms.",
                "remediation": "Disable legacy/weak ciphers (RC4, 3DES, MD5) in web server SSL configuration.",
                "owasp_category": "A02:2025 - Security Misconfiguration",
            })

    # 5. Deprecated Protocol Support Checks (Skipped in Quick Mode)
    if not quick:
        for proto_name, proto_enum, severity, score, vector in _DEPRECATED_PROTOCOLS:
            if should_stop and should_stop():
                break
            try:
                ctx_proto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_proto.check_hostname = False
                ctx_proto.verify_mode = ssl.CERT_NONE
                if hasattr(ctx_proto, "minimum_version"):
                    ctx_proto.minimum_version = proto_enum
                if hasattr(ctx_proto, "maximum_version"):
                    ctx_proto.maximum_version = proto_enum

                with socket.create_connection((hostname, port), timeout=min(3.0, timeout)) as sock:
                    with ctx_proto.wrap_socket(sock, server_hostname=hostname) as ssock:
                        findings.append({
                            "title": f"Deprecated {proto_name} Protocol Supported on {hostname}",
                            "severity": severity,
                            "cvss_score": score,
                            "cvss_vector": vector,
                            "affected_url": f"https://{hostname}:{port}",
                            "parameter": "TLS Protocol Version",
                            "payload": "N/A",
                            "evidence": f"Server successfully negotiated a handshake using deprecated protocol {proto_name}.",
                            "remediation": f"Disable support for {proto_name}. Mandate TLS 1.2 or TLS 1.3.",
                            "owasp_category": "A02:2025 - Security Misconfiguration",
                        })
            except Exception as exc:
                log.debug("Protocol check for %s on %s failed (expected if disabled): %s", proto_name, hostname, exc)

    log.info("SSL/TLS analysis complete for %s — %d findings", hostname, len(findings))
    return findings


test_ssl_tls.__test__ = False  # type: ignore[attr-defined]


