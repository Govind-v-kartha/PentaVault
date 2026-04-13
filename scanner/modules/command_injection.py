"""OS command injection detection module.

Tests URL and form parameters with safe command-separator payloads and
looks for high-signal command output markers in responses.
"""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("command_injection")

# (payload, expected marker in command output)
_PAYLOADS: list[tuple[str, str]] = [
    (";expr 9137 + 133", "9270"),
    ("|expr 9137 + 133", "9270"),
    ("&&expr 9137 + 133", "9270"),
    ("$(expr 9137 + 133)", "9270"),
    ("`expr 9137 + 133`", "9270"),
    (";echo $((9137+133))", "9270"),
    (";set /a 6000+37", "6037"),
    ("|set /a 6000+37", "6037"),
    ("&&set /a 6000+37", "6037"),
    ("&set /a 6000+37", "6037"),
    (";printf PENTAVAULT_CMDI_CANARY", "PENTAVAULT_CMDI_CANARY"),
    ("|printf PENTAVAULT_CMDI_CANARY", "PENTAVAULT_CMDI_CANARY"),
    ("&&printf PENTAVAULT_CMDI_CANARY", "PENTAVAULT_CMDI_CANARY"),
    (";echo PENTAVAULT_CMDI_CANARY", "PENTAVAULT_CMDI_CANARY"),
    ("|echo PENTAVAULT_CMDI_CANARY", "PENTAVAULT_CMDI_CANARY"),
    ("&&echo PENTAVAULT_CMDI_CANARY", "PENTAVAULT_CMDI_CANARY"),
    ("`echo PENTAVAULT_CMDI_CANARY`", "PENTAVAULT_CMDI_CANARY"),
    ("$(printf PENTAVAULT_CMDI_CANARY)", "PENTAVAULT_CMDI_CANARY"),
]

_CMD_PARAM_NAMES = re.compile(
    r"(cmd|command|exec|execute|run|shell|ping|host|ip|query|search|dir|path|file|arg)",
    re.IGNORECASE,
)

_OUTPUT_PATTERNS = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"uid=\d+\([^)]+\)", re.IGNORECASE),
    re.compile(r"volume serial number", re.IGNORECASE),
    re.compile(r"microsoft windows", re.IGNORECASE),
    re.compile(r"/bin/(?:bash|sh)", re.IGNORECASE),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _looks_like_exec_param(name: str, value: str) -> bool:
    if _CMD_PARAM_NAMES.search(name):
        return True
    if value and re.fullmatch(r"[\w\-.]{1,64}", value):
        return True
    return False


def _extract_evidence(response_text: str, baseline_text: str, marker: str) -> str | None:
    response_lower = response_text.lower()
    baseline_lower = baseline_text.lower()

    if marker.lower() in response_lower and marker.lower() not in baseline_lower:
        return f"Observed command output marker '{marker}' in response body"

    for pattern in _OUTPUT_PATTERNS:
        match = pattern.search(response_text)
        if match and not pattern.search(baseline_text):
            return f"Observed OS command output pattern: {match.group(0)}"

    return None


def test_command_injection(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run command injection checks against discovered endpoints and forms."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payloads = _PAYLOADS[:6] if quick else _PAYLOADS
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:6] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        # ── GET parameters ──────────────────────────────────────────
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("Command injection scan cancelled during GET tests")
                break

            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            if not qs:
                continue

            try:
                baseline_resp = client.get(url)
                baseline_text = baseline_resp.text
            except httpx.HTTPError:
                baseline_text = ""

            for param, values in qs.items():
                if should_stop and should_stop():
                    log.info("Command injection scan cancelled on %s", urlparse(url).path)
                    break
                value = values[0] if values else ""
                if not _looks_like_exec_param(param, value):
                    continue

                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue

                for payload, marker in payloads:
                    if should_stop and should_stop():
                        break
                    target = _inject_param(url, param, payload)
                    try:
                        resp = client.get(target)
                    except httpx.HTTPError:
                        continue

                    evidence = _extract_evidence(resp.text, baseline_text, marker)
                    if evidence:
                        log.info("[Command Injection] %s param=%s", url, param)
                        findings.append(_to_finding(url, param, payload, evidence))
                        seen.add(sig)
                        break

        # ── POST form parameters ────────────────────────────────────
        for form in test_forms:
            if should_stop and should_stop():
                log.info("Command injection scan cancelled during POST tests")
                break
            if form["method"] != "POST":
                continue

            base_data = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
            if not base_data:
                continue

            try:
                baseline_resp = client.post(form["action"], data=base_data)
                baseline_text = baseline_resp.text
            except httpx.HTTPError:
                baseline_text = ""

            for inp in form["inputs"]:
                if should_stop and should_stop():
                    log.info("Command injection POST cancelled on %s", form["action"])
                    break
                name = inp["name"]
                if not name:
                    continue
                if not _looks_like_exec_param(name, inp.get("value", "")):
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

                    evidence = _extract_evidence(resp.text, baseline_text, marker)
                    if evidence:
                        log.info("[Command Injection] POST %s param=%s", form["action"], name)
                        findings.append(_to_finding(form["action"], name, payload, evidence))
                        seen.add(sig)
                        break

    log.info("Command injection scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    return {
        "title": f"OS Command Injection on {urlparse(url).path}",
        "severity": "High",
        "cvss_score": 8.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence[:300],
        "remediation": "Avoid shell invocation with user input. Use strict allowlists, "
        "parameterized process APIs, and server-side input validation before execution.",
        "owasp_category": "A05:2025 - Injection",
    }
