"""Open Redirect detection module.

Tests parameters that accept URL/path values for unvalidated redirects
to external domains.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("open_redirect")

_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/%2f..",
    "////evil.com",
    "https:///evil.com",
    "\\\\evil.com",
]

_URL_PARAM_NAMES = re.compile(
    r"(url|uri|redirect|next|dest|return|continue|goto|target|rurl|redir|forward|out|view|login_to)",
    re.IGNORECASE,
)


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_open_redirect(
    endpoints: list[str],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
) -> list[dict[str, Any]]:
    """Test URL-like GET parameters for open redirect vulnerabilities.

    Returns a list of confirmed finding dicts.
    """
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    # In quick mode, limit scope
    if quick:
        endpoints = endpoints[:15]

    with httpx.Client(
        verify=False,
        timeout=timeout,
        follow_redirects=False,
        headers=headers,
    ) as client:
        for url in endpoints:
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            for param in qs:
                if not _URL_PARAM_NAMES.search(param):
                    continue
                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue
                seen.add(sig)
                for payload in _REDIRECT_PAYLOADS:
                    target = _inject_param(url, param, payload)
                    try:
                        resp = client.get(target)
                    except httpx.HTTPError:
                        continue

                    # 3xx with external Location header
                    if 300 <= resp.status_code < 400:
                        loc = resp.headers.get("location", "")
                        if "evil.com" in loc:
                            log.info("[Redirect] %s param=%s → %s", url, param, loc)
                            findings.append(_to_finding(url, param, payload, loc))
                            break

    log.info("Open redirect scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, param: str, payload: str, location: str) -> dict[str, Any]:
    return {
        "title": f"Open Redirect on {urlparse(url).path}",
        "severity": "Medium",
        "cvss_score": 4.7,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": f"Redirected to: {location}",
        "remediation": "Validate redirect targets against an allowlist of trusted domains. "
                       "Never pass raw user input as a redirect destination.",
        "owasp_category": "A01:2025 - Broken Access Control",
    }
