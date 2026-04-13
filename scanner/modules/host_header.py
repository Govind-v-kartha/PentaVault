"""Host Header injection checks."""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("host_header")


_HOST_PAYLOADS = [
    "evil.com",
    "evil.com:80",
    "attacker.local",
]


def test_host_header_injection(
    base_url: str,
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Send modified Host headers and detect host reflection/poison indicators."""
    findings: list[dict] = []
    req_headers: dict[str, str] = {}
    if cookie:
        req_headers["Cookie"] = cookie

    payloads = _HOST_PAYLOADS[:2] if quick else _HOST_PAYLOADS

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False, headers=req_headers) as client:
        try:
            baseline = client.get(base_url)
        except httpx.HTTPError:
            return findings

        base_text = baseline.text[:3000]

        for host_payload in payloads:
            if should_stop and should_stop():
                break
            headers = dict(req_headers)
            headers["Host"] = host_payload
            headers["X-Forwarded-Host"] = host_payload
            try:
                resp = client.get(base_url, headers=headers)
            except httpx.HTTPError:
                continue

            body = resp.text[:3000]
            location = resp.headers.get("location", "")
            if host_payload in body and host_payload not in base_text:
                findings.append(_to_finding(base_url, host_payload, "Host header value reflected in response body"))
                continue
            if host_payload in location:
                findings.append(_to_finding(base_url, host_payload, "Host header value reflected in redirect location"))
                continue

    return findings


def _to_finding(url: str, payload: str, evidence: str) -> dict:
    return {
        "title": f"Host Header Injection on {urlparse(url).path or '/'}",
        "severity": "Medium",
        "cvss_score": 6.5,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "affected_url": url,
        "parameter": "Host header",
        "payload": payload,
        "evidence": evidence,
        "remediation": "Validate Host/X-Forwarded-Host against trusted domains and avoid using untrusted host headers for URL generation or security decisions.",
        "owasp_category": "A05:2025 - Injection",
    }
