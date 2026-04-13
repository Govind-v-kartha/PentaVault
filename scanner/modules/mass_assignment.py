"""Mass assignment and BOLA heuristic checks."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("mass_assignment")

_SENSITIVE_FIELDS: list[tuple[str, str]] = [
    ("role", "admin"),
    ("is_admin", "true"),
    ("admin", "1"),
    ("permission", "superuser"),
    ("permissions", "all"),
    ("scope", "*"),
    ("access_level", "owner"),
    ("user_id", "1"),
    ("owner_id", "1"),
    ("account_id", "1"),
    ("organization_id", "1"),
    ("tenant_id", "1"),
    ("status", "approved"),
    ("email_verified", "true"),
    ("credit_limit", "999999"),
]

_ID_PARAM_NAMES = re.compile(r"(id|user_id|account_id|owner_id|profile_id|member_id)", re.IGNORECASE)


def _inject_query(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _responses_differ(baseline: str, candidate: str) -> bool:
    if baseline == candidate:
        return False

    len_diff = abs(len(candidate) - len(baseline))
    if len_diff >= max(120, int(len(baseline) * 0.08)):
        return True

    ratio = SequenceMatcher(None, baseline[:8000], candidate[:8000]).ratio()
    return ratio <= 0.92


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


def _bola_evidence(
    baseline: httpx.Response,
    candidate: httpx.Response,
    param: str,
    original_id: int,
    mutated_id: int,
) -> str | None:
    if baseline.status_code != 200 or candidate.status_code != 200:
        return None
    if not _responses_differ(baseline.text, candidate.text):
        return None
    return (
        f"Object reference changed via {param}: {original_id}→{mutated_id} and returned "
        "a different HTTP 200 response"
    )


def _mass_assignment_evidence(
    baseline: httpx.Response,
    candidate: httpx.Response,
    field: str,
    value: str,
) -> str | None:
    if baseline.status_code in (401, 403) and candidate.status_code in (200, 201, 202, 204, 302):
        return f"Access changed from {baseline.status_code} to {candidate.status_code} after setting {field}"

    baseline_text = baseline.text.lower()
    candidate_text = candidate.text.lower()

    interesting_markers = [field.lower(), str(value).lower(), "admin", "superuser", "permission"]
    reflected = [m for m in interesting_markers if len(m) >= 3 and m in candidate_text and m not in baseline_text]
    if reflected and candidate.status_code in (200, 201, 202, 204, 302):
        return f"Privileged field influence observed: {', '.join(reflected)}"

    if baseline.status_code == candidate.status_code and candidate.status_code in (200, 201, 202):
        if _responses_differ(baseline.text, candidate.text):
            return f"Response changed after setting sensitive field {field}={value}"

    return None


def test_mass_assignment_bola(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Detect potential mass assignment and query-parameter BOLA behavior."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payload_fields = _SENSITIVE_FIELDS[:5] if quick else _SENSITIVE_FIELDS
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:8] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("Mass assignment/BOLA scan cancelled during endpoint tests")
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
                raw_value = values[0] if values else ""
                if not (_ID_PARAM_NAMES.search(param) and raw_value.isdigit()):
                    continue

                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue

                original_id = int(raw_value)
                mutated_id = original_id + 1
                candidate_url = _inject_query(url, param, str(mutated_id))

                try:
                    candidate = client.get(candidate_url)
                except httpx.HTTPError:
                    continue

                evidence = _bola_evidence(baseline, candidate, param, original_id, mutated_id)
                if evidence:
                    findings.append(
                        _to_finding(
                            url,
                            param,
                            f"{param}={mutated_id}",
                            evidence,
                            variant="BOLA",
                        )
                    )
                    seen.add(sig)

        for form in test_forms:
            if should_stop and should_stop():
                log.info("Mass assignment/BOLA scan cancelled during form tests")
                break

            method = form.get("method", "GET").upper()
            if method not in {"POST", "PUT", "PATCH"}:
                continue

            action = form.get("action", "")
            base_data = {inp["name"]: inp.get("value", "") for inp in form.get("inputs", []) if inp.get("name")}
            if not action or not base_data:
                continue

            try:
                baseline = _submit_form(client, method, action, base_data)
            except httpx.HTTPError:
                continue

            for field, value in payload_fields:
                if should_stop and should_stop():
                    break
                sig = (urlparse(action).path, field)
                if sig in seen:
                    continue

                candidate_data = dict(base_data)
                candidate_data[field] = value

                try:
                    candidate = _submit_form(client, method, action, candidate_data)
                except httpx.HTTPError:
                    continue

                evidence = _mass_assignment_evidence(baseline, candidate, field, value)
                if evidence:
                    findings.append(
                        _to_finding(
                            action,
                            field,
                            f"{field}={value}",
                            evidence,
                            variant="Mass Assignment",
                        )
                    )
                    seen.add(sig)
                    break

    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str, variant: str) -> dict[str, Any]:
    is_bola = variant == "BOLA"
    return {
        "title": f"{variant} on {urlparse(url).path or '/'}",
        "severity": "High" if is_bola else "Medium",
        "cvss_score": 8.1 if is_bola else 6.9,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if is_bola else "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence,
        "remediation": "Apply server-side allowlists for writable fields and enforce object-level authorization checks for every object reference.",
        "owasp_category": "A01:2025 - Broken Access Control",
    }
