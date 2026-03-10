"""Selenium-powered web crawler.

Renders pages in a real browser, discovering JS-generated links, dynamic forms,
AJAX endpoints, and SPA routes that a static HTTP crawler misses entirely.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
    StaleElementReferenceException,
    NoSuchElementException,
)

from scanner.core.browser import create_browser, inject_cookie
from scanner.core.crawler import CrawlResult          # reuse the dataclass
from scanner.utils.logger import get_logger

log = get_logger("selenium_crawler")

# Regex for API paths in page source / XHR
_API_PATH_RE = re.compile(r"""['"](/api/[^'"]+)['"]""")
_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.\w+|XMLHttpRequest\.open)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _is_same_origin(base: str, url: str) -> bool:
    return urlparse(base).netloc == urlparse(url).netloc


def _extract_forms_selenium(driver: webdriver.Chrome, page_url: str) -> list[dict[str, Any]]:
    """Extract forms from the live DOM (including JS-generated ones)."""
    forms: list[dict[str, Any]] = []
    try:
        form_elements = driver.find_elements(By.TAG_NAME, "form")
    except WebDriverException:
        return forms

    for form_el in form_elements:
        try:
            action = form_el.get_attribute("action") or ""
            method = (form_el.get_attribute("method") or "GET").upper()
            action_url = urljoin(page_url, action) if action else page_url
            inputs: list[dict[str, str]] = []
            for inp in form_el.find_elements(By.CSS_SELECTOR, "input, textarea, select"):
                inputs.append({
                    "name": inp.get_attribute("name") or "",
                    "type": inp.get_attribute("type") or "text",
                    "value": inp.get_attribute("value") or "",
                })
            forms.append({"action": action_url, "method": method, "inputs": inputs})
        except StaleElementReferenceException:
            continue
    return forms


def _extract_links_selenium(driver: webdriver.Chrome, base_url: str) -> list[str]:
    """Extract all anchor hrefs from the live DOM."""
    links: list[str] = []
    try:
        anchors = driver.find_elements(By.TAG_NAME, "a")
        for a in anchors:
            try:
                href = a.get_attribute("href")
                if href and _is_same_origin(base_url, href):
                    links.append(href)
            except StaleElementReferenceException:
                continue
    except WebDriverException:
        pass
    return links


def _extract_js_endpoints(page_source: str, base_url: str) -> list[str]:
    found: set[str] = set()
    for m in _FETCH_RE.finditer(page_source):
        found.add(urljoin(base_url, m.group(1)))
    for m in _API_PATH_RE.finditer(page_source):
        found.add(urljoin(base_url, m.group(1)))
    return list(found)


def _intercept_xhr(driver: webdriver.Chrome) -> list[str]:
    """Inject JS to capture XHR/fetch URLs fired after page load."""
    script = """
    if (!window.__capturedUrls) {
        window.__capturedUrls = [];
        const origOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            window.__capturedUrls.push(url);
            return origOpen.apply(this, arguments);
        };
        const origFetch = window.fetch;
        window.fetch = function(input) {
            if (typeof input === 'string') window.__capturedUrls.push(input);
            else if (input && input.url) window.__capturedUrls.push(input.url);
            return origFetch.apply(this, arguments);
        };
    }
    return window.__capturedUrls || [];
    """
    try:
        return driver.execute_script(script) or []
    except WebDriverException:
        return []


def selenium_crawl(
    base_url: str,
    max_depth: int = 3,
    max_pages: int = 200,
    cookie: str | None = None,
    headless: bool = True,
    wait_per_page: float = 0.5,
) -> CrawlResult:
    """Crawl *base_url* using a headless Chrome browser.

    This discovers JavaScript-rendered content that a simple HTTP crawler cannot.
    """
    log.info("=== STAGE 04: Selenium Crawler — %s ===", base_url)

    result = CrawlResult()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]

    with create_browser(headless=headless) as driver:
        # Inject XHR/fetch interceptor early
        driver.get(base_url)
        if cookie:
            inject_cookie(driver, base_url, cookie)

        _intercept_xhr(driver)

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)

            # Normalise
            parsed = urlparse(url)
            normalized = parsed._replace(fragment="").geturl()
            if normalized in visited:
                continue
            if not _is_same_origin(base_url, normalized):
                continue

            visited.add(normalized)
            result.endpoints.append(normalized)

            # Collect query-string parameter names
            for param in parse_qs(parsed.query):
                result.parameters.add(param)

            try:
                driver.get(normalized)
                # Wait for JS rendering
                time.sleep(wait_per_page)
            except TimeoutException:
                log.debug("Timeout loading %s", normalized)
                continue
            except WebDriverException as exc:
                log.debug("Failed to load %s: %s", normalized, exc)
                continue

            # Detect authentication walls
            if "login" in driver.current_url.lower() and normalized != driver.current_url:
                result.authenticated_pages.append(normalized)

            # Forms (from live DOM)
            forms = _extract_forms_selenium(driver, normalized)
            result.forms.extend(forms)
            for form in forms:
                for inp in form["inputs"]:
                    if inp["name"]:
                        result.parameters.add(inp["name"])

            # JS endpoints from page source
            page_source = driver.page_source
            result.js_api_endpoints.extend(_extract_js_endpoints(page_source, normalized))

            # Captured XHR/fetch URLs
            captured = _intercept_xhr(driver)
            for api_url in captured:
                full = urljoin(normalized, api_url)
                if _is_same_origin(base_url, full):
                    result.js_api_endpoints.append(full)

            # Enqueue discovered links from live DOM
            if depth < max_depth:
                for link in _extract_links_selenium(driver, base_url):
                    queue.append((link, depth + 1))

    # Deduplicate
    result.js_api_endpoints = list(set(result.js_api_endpoints))

    summary = result.summary()
    log.info(
        "Selenium crawl complete — Endpoints: %d | Forms: %d | Params: %d | JS APIs: %d | Auth pages: %d",
        summary["endpoints_found"],
        summary["forms_discovered"],
        summary["input_parameters"],
        summary["js_api_endpoints"],
        summary["authenticated_pages"],
    )
    return result
