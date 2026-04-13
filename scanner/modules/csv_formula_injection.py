"""CSV/formula injection heuristic checks (non-destructive)."""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("csv_formula_injection")

_FORMULA_PAYLOADS: list[str] = [
    "=PENTAVAULT_CANARY",
    "+PENTAVAULT_CANARY",
    "-PENTAVAULT_CANARY",
    "@PENTAVAULT_CANARY",
    '=CONCAT("PENTA","VAULT")',
    "=SUM(1,2)",
]

_PARAM_HINT = re.compile(
    r"(name|title|company|comment|note|description|query|search|email|username)",
    re.IGNORECASE,
)

_PATH_HINT = re.compile(r"(export|report|download|csv|sheet|spreadsheet)", re.IGNORECASE)



def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


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


def _looks_relevant(url: str, name: str) -> bool:
    return bool(_PATH_HINT.search(urlparse(url).path) or _PARAM_HINT.search(name))


def _extract_evidence(
    baseline: httpx.Response,
    candidate: httpx.Response,
    payload: str,
) -> str | None:
    baseline_text = baseline.text
    candidate_text = candidate.text

    if payload in candidate_text and payload not in baseline_text:
        return f"Formula-like value '{payload}' reflected without neutralization"

    if baseline.status_code < 500 and candidate.status_code >= 500:
        return f"Status changed from {baseline.status_code} to {candidate.status_code} after formula payload"

    return None


def test_csv_formula_injection(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Probe for unsafe formula-prefixed value handling in CSV/report workflows."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payloads = _FORMULA_PAYLOADS[:3] if quick else _FORMULA_PAYLOADS
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:8] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("CSV/formula scan cancelled during endpoint tests")
                break

            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            if not params:
                continue

            try:
                baseline = client.get(url)
            except httpx.HTTPError:
                continue

            for param, values in params.items():
                if should_stop and should_stop():
                    break

                value = values[0] if values else ""
                if not _looks_relevant(url, param) and not value:
                    continue

                sig = (urlparse(url).path or "/", param)
                if sig in seen:
                    continue

                for payload in payloads:
                    if should_stop and should_stop():
                        break
                    try:
                        candidate = client.get(_inject_query(url, param, payload))
                    except httpx.HTTPError:
                        continue

                    evidence = _extract_evidence(baseline, candidate, payload)
                    if evidence:
                        findings.append(_to_finding(url, param, payload, evidence))
                        seen.add(sig)
                        break

        for form in test_forms:
            if should_stop and should_stop():
                log.info("CSV/formula scan cancelled during form tests")
                break

            method = form.get("method", "GET").upper()
            if method not in {"POST", "PUT", "PATCH", "GET"}:
                continue

            action = form.get("action", "")
            base_data = {inp["name"]: inp.get("value", "") for inp in form.get("inputs", []) if inp.get("name")}
            if not action or not base_data:
                continue

            try:
                baseline = _submit_form(client, method, action, base_data)
            except httpx.HTTPError:
                continue

            for name in base_data:
                if should_stop and should_stop():
                    break
                if not _looks_relevant(action, name):
                    continue

                sig = (urlparse(action).path or "/", name)
                if sig in seen:
                    continue

                for payload in payloads:
                    if should_stop and should_stop():
                        break
                    candidate_data = dict(base_data)
                    candidate_data[name] = payload
                    try:
                        candidate = _submit_form(client, method, action, candidate_data)
                    except httpx.HTTPError:
                        continue

                    evidence = _extract_evidence(baseline, candidate, payload)
                    if evidence:
                        findings.append(_to_finding(action, name, payload, evidence))
                        seen.add(sig)
                        break

    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    return {
        "title": f"Potential CSV/Formula Injection on {urlparse(url).path or '/'}",
        "severity": "Medium",
        "cvss_score": 6.5,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence,
        "remediation": "Prefix spreadsheet-bound values with a single quote or otherwise neutralize formula-leading characters (=,+,-,@).",
        "owasp_category": "A03:2025 - Injection",
    }
