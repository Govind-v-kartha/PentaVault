"""GraphQL security misconfiguration and abuse checks."""

from __future__ import annotations

from typing import Callable
from urllib.parse import parse_qs, urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("graphql")

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/query"]

_INTROSPECTION_QUERY = "{__schema{types{name}}}"
_DEEP_QUERY = "query { a0:a{a1:a{a2:a{a3:a{a4:a{a5:a{a6:a{a7:a{a8:a{name}}}}}}}}}}"


def test_graphql_abuse(
    base_url: str,
    endpoints: list[str],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Detect exposed GraphQL introspection and weak query controls."""
    findings: list[dict] = []
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie

    candidates: list[str] = []
    origin = urlparse(base_url)._replace(path="", query="", fragment="").geturl().rstrip("/")
    candidates.extend(origin + p for p in _GRAPHQL_PATHS)

    for ep in endpoints[:20]:
        parsed = urlparse(ep)
        if "graphql" in parsed.path.lower():
            candidates.append(parsed._replace(query="", fragment="").geturl())

    # dedupe preserving order
    deduped: list[str] = list(dict.fromkeys(candidates))

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for endpoint in deduped[: (4 if quick else 8)]:
            if should_stop and should_stop():
                log.info("GraphQL scan cancelled")
                break

            # Introspection
            try:
                resp = client.post(endpoint, json={"query": _INTROSPECTION_QUERY})
            except httpx.HTTPError:
                continue

            text = resp.text[:5000]
            if resp.status_code == 200 and "__schema" in text and "types" in text:
                findings.append(_to_finding(
                    endpoint,
                    "Introspection query enabled in production",
                    _INTROSPECTION_QUERY,
                    "GraphQL introspection returned schema metadata",
                    "Medium",
                    6.5,
                ))
                log.info("[GraphQL] Introspection enabled at %s", endpoint)

            # Query depth/complexity stress canary
            try:
                deep_resp = client.post(endpoint, json={"query": _DEEP_QUERY})
            except httpx.HTTPError:
                continue

            if deep_resp.status_code == 200 and "errors" not in deep_resp.text:
                findings.append(_to_finding(
                    endpoint,
                    "Potential missing GraphQL depth/complexity limits",
                    _DEEP_QUERY,
                    "Nested query executed without visible rejection",
                    "Low",
                    3.9,
                ))
                log.info("[GraphQL] Missing depth guard at %s", endpoint)

    return findings


def _to_finding(url: str, title: str, payload: str, evidence: str, severity: str, score: float) -> dict:
    return {
        "title": f"GraphQL: {title}",
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if severity == "Medium" else "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "affected_url": url,
        "parameter": "GraphQL query",
        "payload": payload,
        "evidence": evidence,
        "remediation": "Disable introspection in production where possible, apply depth/complexity/query-cost limits, and enforce authentication/authorization per resolver.",
        "owasp_category": "A06:2025 - Insecure Design",
    }
