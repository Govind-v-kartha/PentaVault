"""Security headers check module.

Verifies the presence and correctness of critical HTTP security headers.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("headers")

# (header_name, missing_title, severity, score, vector, remediation)
_HEADER_CHECKS: list[tuple[str, str, str, float, str, str]] = [
    (
        "Content-Security-Policy",
        "Missing Content-Security-Policy (CSP)",
        "Low",
        3.1,
        "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "Add a strict CSP header to restrict resource loading sources. "
        "Example: Content-Security-Policy: default-src 'self'",
    ),
    (
        "Strict-Transport-Security",
        "Missing HTTP Strict Transport Security (HSTS)",
        "Medium",
        4.2,
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "Add the Strict-Transport-Security header with a minimum max-age of 31536000 "
        "and include the includeSubDomains directive.",
    ),
    (
        "X-Frame-Options",
        "Missing X-Frame-Options (Clickjacking)",
        "Medium",
        4.3,
        "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
    ),
    (
        "X-Content-Type-Options",
        "Missing X-Content-Type-Options",
        "Low",
        3.1,
        "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    ),
    (
        "X-XSS-Protection",
        "Missing X-XSS-Protection Header",
        "Low",
        2.0,
        "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "Set X-XSS-Protection: 1; mode=block (legacy; CSP is preferred).",
    ),
    (
        "Referrer-Policy",
        "Missing Referrer-Policy Header",
        "Low",
        2.0,
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
    ),
    (
        "Permissions-Policy",
        "Missing Permissions-Policy Header",
        "Low",
        2.0,
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "Add a Permissions-Policy header to restrict browser features "
        "(e.g., camera, microphone, geolocation).",
    ),
]


def test_headers(
    url: str,
    cookie: str | None = None,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Check the target URL for missing security headers.

    Returns a list of finding dicts — one per missing header.
    """
    findings: list[dict[str, Any]] = []
    req_headers: dict[str, str] = {}
    if cookie:
        req_headers["Cookie"] = cookie

    try:
        with httpx.Client(
            verify=False, timeout=timeout, follow_redirects=True, headers=req_headers
        ) as client:
            resp = client.get(url)
    except httpx.HTTPError as exc:
        log.warning("Could not fetch %s for header check: %s", url, exc)
        return findings

    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    path = urlparse(url).path or "/"

    for hdr_name, title, severity, score, vector, remediation in _HEADER_CHECKS:
        if hdr_name.lower() not in resp_headers:
            findings.append({
                "title": f"{title} on {path}",
                "severity": severity,
                "cvss_score": score,
                "cvss_vector": vector,
                "affected_url": url,
                "parameter": "N/A",
                "payload": "N/A",
                "evidence": f"Header '{hdr_name}' not present in HTTP response",
                "remediation": remediation,
                "owasp_category": "A02:2025 - Security Misconfiguration",
            })
            log.info("[Headers] Missing: %s on %s", hdr_name, url)

    # Additional: check for Server header leaking version info
    server = resp_headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({
            "title": f"Server Version Disclosure on {path}",
            "severity": "Low",
            "cvss_score": 2.0,
            "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "affected_url": url,
            "parameter": "N/A",
            "payload": "N/A",
            "evidence": f"Server header: {server}",
            "remediation": "Remove or obfuscate the Server header to avoid leaking version info.",
            "owasp_category": "A02:2025 - Security Misconfiguration",
        })

    log.info("Security headers scan complete — %d findings on %s", len(findings), url)
    return findings
