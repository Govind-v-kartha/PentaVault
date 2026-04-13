"""Prototype pollution heuristic checks (non-destructive)."""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("prototype_pollution")

_CANARY = "PENTAVAULT_PP_CANARY"

_QUERY_PROBES: list[tuple[str, str]] = [
    ("__proto__[pentavault_canary]", _CANARY),
    ("constructor[prototype][pentavault_canary]", _CANARY),
    ("prototype[pentavault_canary]", _CANARY),
    ("__proto__.pentavault_canary", _CANARY),
    ("constructor.prototype.pentavault_canary", _CANARY),
]

_PATH_HINT = re.compile(
    r"(api|json|graphql|profile|account|config|settings|update|merge|patch)",
    re.IGNORECASE,
)


def _inject_query(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _looks_like_object_surface(url: str) -> bool:
    parsed = urlparse(url)
    if parse_qs(parsed.query, keep_blank_values=True):
        return True
    return bool(_PATH_HINT.search(parsed.path))


def _submit_form(client: httpx.Client, method: str, action: str, data: dict[str, str]) -> httpx.Response:
    normalized = method.upper()
    if normalized == "POST":
        return client.post(action, data=data)
    if normalized == "PUT":
        return client.put(action, data=data)
    if normalized == "PATCH":
        return client.patch(action, data=data)
    if normalized == "GET":
        return client.get(action, params=data)
    return client.post(action, data=data)


def _extract_evidence(
    baseline: httpx.Response,
    candidate: httpx.Response,
    follow_up: httpx.Response,
    probe_key: str,
) -> str | None:
    baseline_text = baseline.text

    if _CANARY in candidate.text and _CANARY not in baseline_text:
        return f"Prototype payload reflected using key '{probe_key}'"

    if _CANARY in follow_up.text and _CANARY not in baseline_text:
        return f"Prototype canary persisted after probe '{probe_key}'"

    if baseline.status_code < 500 and candidate.status_code >= 500:
        return (
            f"Status changed from {baseline.status_code} to {candidate.status_code} "
            f"after prototype key '{probe_key}'"
        )

    if baseline.status_code < 500 and follow_up.status_code >= 500:
        return (
            f"Follow-up request changed from {baseline.status_code} to {follow_up.status_code} "
            f"after prototype key '{probe_key}'"
        )

    return None


def test_prototype_pollution(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Probe endpoints/forms for potential prototype pollution behavior."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    probes = _QUERY_PROBES[:2] if quick else _QUERY_PROBES
    test_endpoints = endpoints[:12] if quick else endpoints
    test_forms = forms[:8] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("Prototype pollution scan cancelled during endpoint tests")
                break
            if not _looks_like_object_surface(url):
                continue

            path = urlparse(url).path or "/"
            sig = (path, "query")
            if sig in seen:
                continue

            try:
                baseline = client.get(url)
            except httpx.HTTPError:
                continue

            for probe_key, probe_value in probes:
                if should_stop and should_stop():
                    break

                try:
                    candidate = client.get(_inject_query(url, probe_key, probe_value))
                    follow_up = client.get(url)
                except httpx.HTTPError:
                    continue

                evidence = _extract_evidence(baseline, candidate, follow_up, probe_key)
                if evidence:
                    findings.append(
                        _to_finding(
                            url,
                            probe_key,
                            f"{probe_key}={probe_value}",
                            evidence,
                        )
                    )
                    seen.add(sig)
                    break

        for form in test_forms:
            if should_stop and should_stop():
                log.info("Prototype pollution scan cancelled during form tests")
                break

            method = form.get("method", "GET").upper()
            if method not in {"POST", "PUT", "PATCH"}:
                continue

            action = form.get("action", "")
            base_data = {inp["name"]: inp.get("value", "") for inp in form.get("inputs", []) if inp.get("name")}
            if not action or not base_data:
                continue

            path = urlparse(action).path or "/"
            sig = (path, "form")
            if sig in seen:
                continue

            try:
                baseline = _submit_form(client, method, action, base_data)
            except httpx.HTTPError:
                continue

            for probe_key, probe_value in probes:
                if should_stop and should_stop():
                    break

                candidate_data = dict(base_data)
                candidate_data[probe_key] = probe_value

                try:
                    candidate = _submit_form(client, method, action, candidate_data)
                    follow_up = _submit_form(client, method, action, base_data)
                except httpx.HTTPError:
                    continue

                evidence = _extract_evidence(baseline, candidate, follow_up, probe_key)
                if evidence:
                    findings.append(
                        _to_finding(
                            action,
                            probe_key,
                            f"{probe_key}={probe_value}",
                            evidence,
                        )
                    )
                    seen.add(sig)
                    break

    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    return {
        "title": f"Potential Prototype Pollution on {urlparse(url).path or '/'}",
        "severity": "High",
        "cvss_score": 8.1,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence,
        "remediation": "Reject dangerous prototype keys (__proto__, constructor.prototype), deep-clone safely, and enforce strict input schemas.",
        "owasp_category": "A08:2025 - Software & Data Integrity Failures",
    }
