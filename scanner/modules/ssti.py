"""Server-Side Template Injection (SSTI) detection module."""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("ssti")

_PAYLOAD_MARKERS: list[tuple[str, str]] = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("${{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("{{1337+1}}", "1338"),
    ("{{21+21}}", "42"),
    ("{{'PENTA'+'VAULT'}}", "PENTAVAULT"),
    ("${'PENTA'+'VAULT'}", "PENTAVAULT"),
    ("<%= 'PENTA' + 'VAULT' %>", "PENTAVAULT"),
    ("{{7|add:7}}", "14"),
]

_PARAM_NAMES = re.compile(
    r"(name|user|username|q|query|search|message|comment|template|view|email|title)",
    re.IGNORECASE,
)


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _looks_like_rendered_input(name: str) -> bool:
    return bool(_PARAM_NAMES.search(name))


def _marker_evidence(text: str, baseline_text: str, marker: str) -> str | None:
    if marker in text and marker not in baseline_text:
        return f"Observed SSTI marker '{marker}' in response"
    return None


def test_ssti(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run SSTI checks against likely rendered parameters."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payloads = _PAYLOAD_MARKERS[:4] if quick else _PAYLOAD_MARKERS
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:6] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("SSTI scan cancelled during GET tests")
                break

            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            if not params:
                continue

            try:
                baseline = client.get(url).text
            except httpx.HTTPError:
                baseline = ""

            for param in params:
                if should_stop and should_stop():
                    break
                if not _looks_like_rendered_input(param):
                    continue
                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue

                for payload, marker in payloads:
                    if should_stop and should_stop():
                        break
                    try:
                        resp = client.get(_inject_param(url, param, payload))
                    except httpx.HTTPError:
                        continue
                    evidence = _marker_evidence(resp.text, baseline, marker)
                    if evidence:
                        findings.append(_to_finding(url, param, payload, evidence))
                        seen.add(sig)
                        log.info("[SSTI] %s param=%s", url, param)
                        break

        for form in test_forms:
            if should_stop and should_stop():
                log.info("SSTI scan cancelled during POST tests")
                break
            if form["method"] != "POST":
                continue

            base_data = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
            if not base_data:
                continue

            try:
                baseline = client.post(form["action"], data=base_data).text
            except httpx.HTTPError:
                baseline = ""

            for inp in form["inputs"]:
                if should_stop and should_stop():
                    break
                name = inp["name"]
                if not name:
                    continue
                if not _looks_like_rendered_input(name):
                    continue
                sig = (urlparse(form["action"]).path, name)
                if sig in seen:
                    continue

                for payload, marker in payloads:
                    if should_stop and should_stop():
                        break
                    data = dict(base_data)
                    data[name] = payload
                    try:
                        resp = client.post(form["action"], data=data)
                    except httpx.HTTPError:
                        continue
                    evidence = _marker_evidence(resp.text, baseline, marker)
                    if evidence:
                        findings.append(_to_finding(form["action"], name, payload, evidence))
                        seen.add(sig)
                        break

    log.info("SSTI scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    return {
        "title": f"Server-Side Template Injection on {urlparse(url).path}",
        "severity": "High",
        "cvss_score": 8.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence[:300],
        "remediation": "Avoid rendering untrusted input as templates, use strict context escaping, and disable dangerous template engine features.",
        "owasp_category": "A05:2025 - Injection",
    }
