"""HTTP request smuggling probe module (non-destructive heuristics)."""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("request_smuggling")


def test_request_smuggling(
    base_url: str,
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Send ambiguous TE/CL combination requests and flag parsing inconsistencies."""
    findings: list[dict] = []
    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False, headers=headers) as client:
        if should_stop and should_stop():
            return findings

        # Baseline request
        try:
            baseline = client.post(base_url, content="x=1")
        except httpx.HTTPError:
            return findings

        ambiguous_headers = {
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        }
        body = "0\r\n\r\n"

        try:
            probe = client.post(base_url, headers=ambiguous_headers, content=body)
        except httpx.HTTPError:
            return findings

        # Heuristic only: major status discrepancy with TE/CL ambiguity
        if baseline.status_code != probe.status_code and probe.status_code in (400, 404, 413, 500, 502):
            findings.append(_to_finding(
                base_url,
                "TE/CL ambiguity produced differential response",
                "POST with Content-Length + Transfer-Encoding",
            ))

    return findings


def _to_finding(url: str, evidence: str, payload: str) -> dict:
    return {
        "title": f"Potential HTTP Request Smuggling on {urlparse(url).path or '/'}",
        "severity": "Medium",
        "cvss_score": 6.8,
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L",
        "affected_url": url,
        "parameter": "Request framing",
        "payload": payload,
        "evidence": evidence,
        "remediation": "Ensure front-end and back-end servers enforce identical request parsing, disable conflicting TE/CL handling, and normalize transfer semantics.",
        "owasp_category": "A05:2025 - Injection",
    }
