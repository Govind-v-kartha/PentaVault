"""Shared Selenium browser session manager.

Provides a headless Chrome instance configured for security scanning.
Usage:

    with create_browser() as driver:
        driver.get("https://example.com")
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

from scanner.utils.logger import get_logger

log = get_logger("browser")


def _chrome_options(
    headless: bool = True,
    proxy: str | None = None,
) -> Options:
    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--window-size=1920,1080")
    # Disable image loading for speed
    opts.add_experimental_option("prefs", {
        "profile.managed_default_content_settings.images": 2,
    })
    if proxy:
        opts.add_argument(f"--proxy-server={proxy}")
    return opts


@contextmanager
def create_browser(
    headless: bool = True,
    proxy: str | None = None,
    page_load_timeout: int = 15,
    implicit_wait: int = 1,
) -> Generator[webdriver.Chrome, None, None]:
    """Context manager that yields a configured Chrome WebDriver."""
    opts = _chrome_options(headless=headless, proxy=proxy)
    driver: webdriver.Chrome | None = None
    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(page_load_timeout)
        driver.implicitly_wait(implicit_wait)
        log.info("Browser session started (headless=%s, timeout=%ds)", headless, page_load_timeout)
        yield driver
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
            log.info("Browser session closed")


def inject_cookie(driver: webdriver.Chrome, url: str, cookie_str: str | None) -> None:
    """Load *url* and inject a raw cookie string (e.g. ``session=abc123``)."""
    if not cookie_str:
        return
    driver.get(url)
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        driver.add_cookie({"name": name.strip(), "value": value.strip()})
    driver.refresh()


def take_screenshot(driver: webdriver.Chrome, label: str, output_dir: str = ".") -> str | None:
    """Save a PNG screenshot and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    safe_label = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)
    path = os.path.join(output_dir, f"evidence_{safe_label}.png")
    try:
        driver.save_screenshot(path)
        log.debug("Screenshot saved: %s", path)
        return path
    except Exception as exc:
        log.warning("Failed to save screenshot: %s", exc)
        return None
