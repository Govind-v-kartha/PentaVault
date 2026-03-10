"""Cross-Site Scripting (XSS) detection module.

Tests reflected, stored, and DOM-based XSS across all discovered endpoints
and form input fields.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("xss")

# ── Payloads ────────────────────────────────────────────────────────
REFLECTED_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '{{7*7}}',  # template injection canary
]

ENCODED_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    '<img src=x onerror="&#x61;lert(1)">',
]

# DOM-based dangerous sinks in JavaScript
_DOM_SINKS = re.compile(
    r"(document\.write|\.innerHTML\s*=|\.outerHTML\s*=|eval\(|setTimeout\(|"
    r"setInterval\(|document\.location|window\.location\s*=|\.src\s*=)",
    re.IGNORECASE,
)
_DOM_SOURCES = re.compile(
    r"(document\.URL|document\.referrer|location\.hash|location\.search|"
    r"location\.href|window\.name)",
    re.IGNORECASE,
)


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _test_reflected(
    client: httpx.Client, url: str, param: str, use_waf_bypass: bool = False
) -> dict[str, Any] | None:
    payloads = ENCODED_PAYLOADS if use_waf_bypass else REFLECTED_PAYLOADS
    for payload in payloads:
        target = _inject_param(url, param, payload)
        try:
            resp = client.get(target)
        except httpx.HTTPError:
            continue
        # Check if the payload is reflected unescaped in the response body
        if payload in resp.text:
            log.info("[XSS] Reflected on %s param=%s", url, param)
            return {
                "xss_type": "Reflected",
                "parameter": param,
                "payload": payload,
                "evidence": _snippet(resp.text, payload),
                "url": url,
            }
    return None


def _test_stored(
    client: httpx.Client,
    form: dict[str, Any],
    retrieve_url: str,
) -> dict[str, Any] | None:
    """Submit a payload via POST form, then GET the page to see if it persists."""
    # Use a unique canary so we don't false-positive on other content
    canary = "XSS_CANARY_9a3f"
    payload = f'<script>alert("{canary}")</script>'

    data = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
    target_param = None
    for inp in form["inputs"]:
        if inp["type"] in ("text", "textarea", "search", "hidden", "") and inp["name"]:
            target_param = inp["name"]
            data[inp["name"]] = payload
            break

    if target_param is None:
        return None

    try:
        client.post(form["action"], data=data)
        resp = client.get(retrieve_url)
    except httpx.HTTPError:
        return None

    if canary in resp.text and payload in resp.text:
        log.info("[XSS] Stored via form %s param=%s", form["action"], target_param)
        return {
            "xss_type": "Stored",
            "parameter": target_param,
            "payload": payload,
            "evidence": _snippet(resp.text, payload),
            "url": form["action"],
        }
    return None


def _test_dom_based(body: str, url: str) -> list[dict[str, Any]]:
    """Analyze page JavaScript for DOM-based XSS patterns (source → sink)."""
    findings: list[dict[str, Any]] = []
    sinks = _DOM_SINKS.findall(body)
    sources = _DOM_SOURCES.findall(body)
    if sinks and sources:
        log.info("[XSS] DOM-based potential on %s (sinks=%d, sources=%d)",
                 url, len(sinks), len(sources))
        findings.append({
            "xss_type": "DOM-based",
            "parameter": "N/A",
            "payload": "N/A (source-to-sink analysis)",
            "evidence": f"Sources: {sources[:3]}, Sinks: {sinks[:3]}",
            "url": url,
        })
    return findings


def _snippet(body: str, marker: str, context: int = 80) -> str:
    idx = body.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - context)
    end = min(len(body), idx + len(marker) + context)
    return body[start:end]


def test_xss(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    waf_detected: bool = False,
    cookie: str | None = None,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Run XSS tests against all endpoints and forms.

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
        # ── Reflected XSS on GET params ─────────────────────────────
        for url in endpoints:
            params = parse_qs(urlparse(url).query)
            path = urlparse(url).path
            for param in params:
                sig = (path, param)
                if sig in seen:
                    continue
                result = _test_reflected(client, url, param, use_waf_bypass=waf_detected)
                if result:
                    findings.append(_to_finding(result))
                    seen.add(sig)

        # ── DOM-based XSS analysis ──────────────────────────────────
        visited: set[str] = set()
        for url in endpoints:
            base = urlparse(url)._replace(query="", fragment="").geturl()
            if base in visited:
                continue
            visited.add(base)
            try:
                resp = client.get(url)
                for dom_finding in _test_dom_based(resp.text, url):
                    findings.append(_to_finding(dom_finding))
            except httpx.HTTPError:
                continue

        # ── Stored XSS via forms ────────────────────────────────────
        for form in forms:
            if form["method"] != "POST":
                continue
            result = _test_stored(client, form, form["action"])
            if result:
                findings.append(_to_finding(result))

    log.info("XSS scan complete — %d findings", len(findings))
    return findings


def _to_finding(raw: dict[str, Any]) -> dict[str, Any]:
    xss_type = raw["xss_type"]
    if xss_type == "Stored":
        severity, score, vector = "High", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    elif xss_type == "DOM-based":
        severity, score, vector = "Medium", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    else:
        severity, score, vector = "Medium", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    return {
        "title": f"{xss_type} XSS on {urlparse(raw['url']).path}",
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "affected_url": raw["url"],
        "parameter": raw["parameter"],
        "payload": raw["payload"],
        "evidence": raw["evidence"][:300],
        "remediation": "Encode all user-supplied output contextually (HTML, JS, URL). "
                       "Implement a strict Content-Security-Policy header.",
        "owasp_category": "A05:2025 - Injection",
    }
