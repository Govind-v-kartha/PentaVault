"""HTTP Parameter Pollution (HPP) detection module."""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("hpp")

_PAYLOADS = [
    ["1", "2"],
    ["admin", "guest"],
    ["true", "false"],
]


def _inject_multi(url: str, param: str, values: list[str]) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = values
    query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=query))


def test_hpp(
    endpoints: list[str],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Detect potential HPP by duplicating query params and comparing behavior."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payloads = _PAYLOADS[:2] if quick else _PAYLOADS
    test_endpoints = endpoints[:15] if quick else endpoints

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("HPP scan cancelled")
                break

            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            if not params:
                continue

            try:
                baseline = client.get(url)
            except httpx.HTTPError:
                continue

            for param in params:
                if should_stop and should_stop():
                    break
                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue

                for values in payloads:
                    if should_stop and should_stop():
                        break
                    polluted = _inject_multi(url, param, values)
                    try:
                        resp = client.get(polluted)
                    except httpx.HTTPError:
                        continue

                    if resp.status_code != baseline.status_code:
                        findings.append(_to_finding(url, param, values, "Status code changed for duplicated parameter"))
                        seen.add(sig)
                        break

                    len_diff = abs(len(resp.text) - len(baseline.text))
                    if len_diff >= max(120, int(len(baseline.text) * 0.08)):
                        findings.append(_to_finding(url, param, values, f"Response length changed by {len_diff} bytes"))
                        seen.add(sig)
                        break

    return findings


def _to_finding(url: str, param: str, values: list[str], evidence: str) -> dict[str, Any]:
    return {
        "title": f"HTTP Parameter Pollution on {urlparse(url).path}",
        "severity": "Medium",
        "cvss_score": 5.9,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "affected_url": url,
        "parameter": param,
        "payload": "&".join(f"{param}={v}" for v in values),
        "evidence": evidence,
        "remediation": "Normalize duplicate parameter handling server-side and reject or canonicalize ambiguous repeated parameters.",
        "owasp_category": "A05:2025 - Injection",
    }
