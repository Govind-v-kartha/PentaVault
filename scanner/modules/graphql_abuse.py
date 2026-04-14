"""GraphQL security misconfiguration and abuse checks.

Tests introspection exposure, depth/complexity limits, batch query abuse,
alias-based rate limit bypass, and field suggestion information disclosure.
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("graphql")

_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/query",
    "/v1/graphql", "/api/v1/graphql", "/graphql/v1", "/gql",
]

_INTROSPECTION_QUERY = "{__schema{types{name}}}"
_DEEP_QUERY = "query { a0:a{a1:a{a2:a{a3:a{a4:a{a5:a{a6:a{a7:a{a8:a{name}}}}}}}}}}"

# Batch query: array of multiple queries in one request
_BATCH_QUERY = [
    {"query": "{__typename}"},
    {"query": "{__typename}"},
    {"query": "{__typename}"},
]

# Alias abuse: 50 aliases for the same field in one query
_ALIAS_QUERY = "query { " + " ".join(f"a{i}:__typename" for i in range(50)) + " }"

# Field suggestion probe: intentionally misspelled field
_SUGGESTION_QUERY = '{__schema{tyeps{name}}}'  # "tyeps" instead of "types"

# Generic mutation probes
_MUTATION_PROBES = [
    'mutation { createUser(input: {email: "test@test.com"}) { id } }',
    'mutation { updateSettings(input: {debug: true}) { success } }',
]


def test_graphql_abuse(
    base_url: str,
    endpoints: list[str],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Detect exposed GraphQL introspection, weak query controls, and abuse vectors."""
    findings: list[dict] = []
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie

    candidates: list[str] = []
    origin = urlparse(base_url)._replace(path="", query="", fragment="").geturl().rstrip("/")
    candidates.extend(origin + p for p in _GRAPHQL_PATHS)

    for ep in endpoints[:20]:
        parsed = urlparse(ep)
        if "graphql" in parsed.path.lower() or "gql" in parsed.path.lower():
            candidates.append(parsed._replace(query="", fragment="").geturl())

    deduped: list[str] = list(dict.fromkeys(candidates))

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for endpoint in deduped[: (4 if quick else 10)]:
            if should_stop and should_stop():
                log.info("GraphQL scan cancelled")
                break

            # ── 1. Introspection ────────────────────────────────
            try:
                resp = client.post(endpoint, json={"query": _INTROSPECTION_QUERY})
            except httpx.HTTPError:
                continue

            text = resp.text[:5000]
            is_graphql = resp.status_code == 200 and ("__schema" in text or "__typename" in text or "errors" in text)
            if not is_graphql:
                continue  # Not a GraphQL endpoint

            if "__schema" in text and "types" in text:
                findings.append(_to_finding(
                    endpoint,
                    "Introspection query enabled in production",
                    _INTROSPECTION_QUERY,
                    "GraphQL introspection returned schema metadata",
                    "Medium", 6.5,
                ))
                log.info("[GraphQL] Introspection enabled at %s", endpoint)

            # ── 2. Query depth/complexity ───────────────────────
            if should_stop and should_stop():
                break
            try:
                deep_resp = client.post(endpoint, json={"query": _DEEP_QUERY})
            except httpx.HTTPError:
                deep_resp = None

            if deep_resp and deep_resp.status_code == 200 and "errors" not in deep_resp.text:
                findings.append(_to_finding(
                    endpoint,
                    "Missing GraphQL depth/complexity limits",
                    _DEEP_QUERY,
                    "Deeply nested query executed without rejection",
                    "Low", 3.9,
                ))
                log.info("[GraphQL] Missing depth guard at %s", endpoint)

            # ── 3. Batch query abuse ────────────────────────────
            if should_stop and should_stop():
                break
            try:
                batch_resp = client.post(endpoint, json=_BATCH_QUERY)
                if batch_resp.status_code == 200:
                    try:
                        batch_data = batch_resp.json()
                        if isinstance(batch_data, list) and len(batch_data) >= 3:
                            findings.append(_to_finding(
                                endpoint,
                                "Batch query accepted — rate limiting bypassable",
                                str(_BATCH_QUERY),
                                f"Server processed {len(batch_data)} batched queries in a single request",
                                "Medium", 5.3,
                            ))
                            log.info("[GraphQL] Batch query accepted at %s", endpoint)
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass

            # ── 4. Alias-based rate limit bypass ────────────────
            if should_stop and should_stop():
                break
            try:
                alias_resp = client.post(endpoint, json={"query": _ALIAS_QUERY})
                if alias_resp.status_code == 200 and "errors" not in alias_resp.text:
                    findings.append(_to_finding(
                        endpoint,
                        "Alias abuse accepted — query cost analysis missing",
                        _ALIAS_QUERY[:200] + "...",
                        "50 aliases resolved in a single query without cost rejection",
                        "Low", 3.9,
                    ))
                    log.info("[GraphQL] Alias abuse accepted at %s", endpoint)
            except httpx.HTTPError:
                pass

            # ── 5. Field suggestion information disclosure ──────
            if should_stop and should_stop():
                break
            try:
                suggest_resp = client.post(endpoint, json={"query": _SUGGESTION_QUERY})
                suggest_text = suggest_resp.text.lower()
                if "did you mean" in suggest_text or "suggestion" in suggest_text:
                    findings.append(_to_finding(
                        endpoint,
                        "Field suggestions expose schema information",
                        _SUGGESTION_QUERY,
                        "Server returned field name suggestions for misspelled query — "
                        "leaks internal schema structure",
                        "Low", 3.1,
                    ))
                    log.info("[GraphQL] Field suggestions at %s", endpoint)
            except httpx.HTTPError:
                pass

            # ── 6. Unauthorized mutation probes ─────────────────
            if quick or (should_stop and should_stop()):
                continue
            for mutation in _MUTATION_PROBES:
                if should_stop and should_stop():
                    break
                try:
                    mut_resp = client.post(endpoint, json={"query": mutation})
                    if mut_resp.status_code == 200 and "errors" not in mut_resp.text:
                        findings.append(_to_finding(
                            endpoint,
                            "Mutation accepted without authentication",
                            mutation,
                            "Server executed mutation without requiring authentication",
                            "High", 8.1,
                        ))
                        log.info("[GraphQL] Unauthenticated mutation at %s", endpoint)
                        break  # One proof is enough
                except httpx.HTTPError:
                    pass

    return findings


def _to_finding(url: str, title: str, payload: str, evidence: str, severity: str, score: float) -> dict:
    from scanner.core.cvss_builder import build_finding_cvss
    vector, computed_score, computed_severity = build_finding_cvss("graphql")
    # Use the more specific score/severity if provided
    final_score = score if score != computed_score else computed_score
    final_severity = severity if severity != computed_severity else computed_severity
    return {
        "title": f"GraphQL: {title}",
        "severity": final_severity,
        "cvss_score": final_score,
        "cvss_vector": vector,
        "affected_url": url,
        "parameter": "GraphQL query",
        "payload": payload[:300],
        "evidence": evidence,
        "remediation": "Disable introspection in production, apply depth/complexity/query-cost limits, "
                       "reject batch queries or limit batch size, disable field suggestions, "
                       "and enforce authentication/authorization per resolver.",
        "owasp_category": "A06:2025 - Insecure Design",
    }
