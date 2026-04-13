"""CRLF injection checks."""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("crlf")

_PAYLOADS = [
    "%0d%0aX-PentaVault-Injected:%20yes",
    "%0D%0AX-Injected-Header:%20crlf",
    "%0d%0aSet-Cookie:%20pv=1",
]


def _inject(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def test_crlf_injection(
    endpoints: list[str],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Detect potential HTTP response splitting via CRLF payloads."""
    findings: list[dict[str, Any]] = []
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payloads = _PAYLOADS[:2] if quick else _PAYLOADS
    test_endpoints = endpoints[:15] if quick else endpoints

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False, headers=headers) as client:
        for url in test_endpoints:
            if should_stop and should_stop():
                break
            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            if not params:
                continue

            for param in params:
                if should_stop and should_stop():
                    break

                for payload in payloads:
                    if should_stop and should_stop():
                        break
                    target = _inject(url, param, payload)
                    try:
                        resp = client.get(target)
                    except httpx.HTTPError:
                        continue

                    injected_headers = [k for k in resp.headers.keys() if "injected" in k.lower() or "pentavault" in k.lower()]
                    if injected_headers:
                        findings.append(_to_finding(url, param, payload, f"Injected response header observed: {', '.join(injected_headers)}"))
                        break

    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    return {
        "title": f"Potential CRLF Injection on {urlparse(url).path}",
        "severity": "Medium",
        "cvss_score": 6.1,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence,
        "remediation": "Reject CR/LF characters in untrusted input used in headers and ensure strict header encoding/normalization.",
        "owasp_category": "A05:2025 - Injection",
    }
