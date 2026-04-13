"""CORS misconfiguration checks."""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("cors")


_ORIGIN_PAYLOADS = [
    "https://evil.com",
    "null",
    "https://attacker.example",
]


def test_cors_misconfig(
    url: str,
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Detect permissive CORS policies that may enable data exfiltration."""
    findings: list[dict] = []
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    origins = _ORIGIN_PAYLOADS[:2] if quick else _ORIGIN_PAYLOADS

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False, headers=headers) as client:
        for origin in origins:
            if should_stop and should_stop():
                break
            req_headers = {
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
            }
            try:
                resp = client.options(url, headers=req_headers)
            except httpx.HTTPError:
                continue

            aco = resp.headers.get("access-control-allow-origin", "")
            acc = resp.headers.get("access-control-allow-credentials", "")

            if aco == "*" and acc.lower() == "true":
                findings.append(_to_finding(url, origin, "Wildcard ACAO with credentials enabled", "High", 8.2))
            elif aco == origin and acc.lower() == "true":
                findings.append(_to_finding(url, origin, "Arbitrary Origin reflected with credentials enabled", "High", 8.0))
            elif aco == origin:
                findings.append(_to_finding(url, origin, "Arbitrary Origin reflected in ACAO", "Medium", 6.5))

    return findings


def _to_finding(url: str, payload: str, evidence: str, severity: str, score: float) -> dict:
    return {
        "title": f"CORS Misconfiguration on {urlparse(url).path or '/'}",
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N" if severity == "High" else "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "affected_url": url,
        "parameter": "Origin header",
        "payload": payload,
        "evidence": evidence,
        "remediation": "Use an explicit allowlist of trusted origins and avoid allowing credentials with wildcard or dynamically reflected origins.",
        "owasp_category": "A02:2025 - Security Misconfiguration",
    }
