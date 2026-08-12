"""Shared browser session manager supporting Playwright (primary) and Selenium (fallback).

Provides a headless browser instance configured for security scanning.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Generator
from urllib.parse import urlparse

# Try importing Playwright (primary)
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Try importing Selenium (fallback)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    SELENIUM_AVAILABLE = True
except ImportError:
    webdriver = None  # type: ignore
    Options = object  # type: ignore
    Service = object  # type: ignore
    SELENIUM_AVAILABLE = False

from scanner.utils.logger import get_logger

log = get_logger("browser")


class PlaywrightElementAdapter:
    def __init__(self, locator: Any, page: Any):
        self._locator = locator
        self._page = page

    def get_attribute(self, name: str) -> str | None:
        try:
            val = self._locator.get_attribute(name)
            return val if val is not None else ""
        except Exception:
            return ""

    @property
    def text(self) -> str:
        try:
            return self._locator.text_content() or ""
        except Exception:
            return ""

    def send_keys(self, value: str) -> None:
        try:
            self._locator.fill(value)
        except Exception:
            try:
                self._locator.type(value)
            except Exception:
                pass

    def click(self) -> None:
        try:
            self._locator.click(timeout=3000)
        except Exception:
            pass

    def submit(self) -> None:
        try:
            self._locator.evaluate("el => el.form ? el.form.submit() : el.submit()")
        except Exception:
            pass


class PlaywrightDriverAdapter:
    """Selenium-compatible driver wrapper around Playwright Chromium."""

    def __init__(self, pw_instance: Any, browser: Any, context: Any, page: Any, timeout_sec: int = 15):
        self._pw = pw_instance
        self._browser = browser
        self._context = context
        self.page = page
        self._timeout_ms = timeout_sec * 1000

    def get(self, url: str) -> None:
        try:
            self.page.goto(url, timeout=self._timeout_ms, wait_until="domcontentloaded")
        except Exception as exc:
            log.debug("Playwright goto failed/timed out for %s: %s", url, exc)

    @property
    def page_source(self) -> str:
        try:
            return self.page.content()
        except Exception:
            return ""

    @property
    def current_url(self) -> str:
        try:
            return self.page.url
        except Exception:
            return ""

    def execute_script(self, script: str, *args: Any) -> Any:
        try:
            if "return " in script or "window." in script or "{" in script:
                js_fn = f"() => {{ {script} }}"
                return self.page.evaluate(js_fn, *args)
            return self.page.evaluate(script, *args)
        except Exception as exc:
            log.debug("Playwright execute_script failed: %s", exc)
            return None

    def find_elements(self, by: str, value: str) -> list[PlaywrightElementAdapter]:
        try:
            css_selector = value
            by_lower = str(by).lower()
            if "tag" in by_lower or "css" in by_lower:
                css_selector = value
            elif "id" in by_lower:
                css_selector = f"#{value}"
            elif "class" in by_lower:
                css_selector = f".{value}"

            locators = self.page.locator(css_selector).all()
            return [PlaywrightElementAdapter(loc, self.page) for loc in locators]
        except Exception:
            return []

    def set_page_load_timeout(self, timeout_sec: int) -> None:
        self._timeout_ms = timeout_sec * 1000
        self.page.set_default_navigation_timeout(self._timeout_ms)

    def implicitly_wait(self, time_sec: int) -> None:
        self.page.set_default_timeout(time_sec * 1000)

    def add_cookie(self, cookie_dict: dict[str, Any]) -> None:
        try:
            self._context.add_cookies([cookie_dict])
        except Exception as exc:
            log.debug("Playwright add_cookie failed: %s", exc)

    def refresh(self) -> None:
        try:
            self.page.reload(timeout=self._timeout_ms)
        except Exception:
            pass

    def save_screenshot(self, filename: str) -> None:
        try:
            self.page.screenshot(path=filename)
        except Exception as exc:
            log.debug("Playwright save_screenshot failed: %s", exc)

    def quit(self) -> None:
        try:
            self._context.close()
            self._browser.close()
            self._pw.stop()
        except Exception:
            pass


def _chrome_options(
    headless: bool = True,
    proxy: str | None = None,
) -> Options:
    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    if os.environ.get("PENTAVAULT_ALLOW_NO_SANDBOX") == "1":
        opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--window-size=1920,1080")
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
) -> Generator[Any, None, None]:
    """Context manager that yields a configured headless browser driver (Playwright primary, Selenium fallback)."""
    # 1. Primary: Playwright Engine
    if PLAYWRIGHT_AVAILABLE:
        pw = None
        try:
            pw = sync_playwright().start()
            launch_kwargs: dict[str, Any] = {"headless": headless}
            if proxy:
                launch_kwargs["proxy"] = {"server": proxy}
            browser = pw.chromium.launch(**launch_kwargs)
            context = browser.new_context(ignore_https_errors=True, viewport={"width": 1920, "height": 1080})
            page = context.new_page()
            page.set_default_navigation_timeout(page_load_timeout * 1000)
            driver = PlaywrightDriverAdapter(pw, browser, context, page, timeout_sec=page_load_timeout)
            log.info("Playwright browser session started (headless=%s, timeout=%ds)", headless, page_load_timeout)
            yield driver
            return
        except Exception as exc:
            log.warning("Playwright launch failed (%s); attempting Selenium fallback...", exc)
            if pw:
                try:
                    pw.stop()
                except Exception:
                    pass

    # 2. Fallback: Selenium Engine
    if SELENIUM_AVAILABLE and webdriver is not None:
        opts = _chrome_options(headless=headless, proxy=proxy)
        driver_sel: Any = None
        try:
            driver_sel = webdriver.Chrome(options=opts)
            driver_sel.set_page_load_timeout(page_load_timeout)
            driver_sel.implicitly_wait(implicit_wait)
            log.info("Selenium browser session started (headless=%s, timeout=%ds)", headless, page_load_timeout)
            yield driver_sel
            return
        finally:
            if driver_sel:
                try:
                    driver_sel.quit()
                except Exception:
                    pass
                log.info("Selenium browser session closed")

    raise RuntimeError("No suitable browser engine available. Neither Playwright nor Selenium Chrome could be started.")


def inject_cookie(driver: Any, url: str, cookie_str: str | None) -> None:
    """Load *url* and inject a raw cookie string (e.g. ``session=abc123``)."""
    if not cookie_str:
        return
    parsed = urlparse(url)
    domain = parsed.hostname
    if not domain:
        return
    driver.get(url)
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookie = {
            "name": name.strip(),
            "value": value.strip(),
            "domain": domain,
            "path": "/",
        }
        try:
            driver.add_cookie(cookie)
        except Exception as exc:
            log.debug("Cookie injection skipped for %s: %s", name.strip(), exc)
    driver.refresh()


def take_screenshot(driver: Any, label: str, output_dir: str = ".") -> str | None:
    """Save a PNG screenshot and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    safe_label = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)
    path = os.path.join(output_dir, f"evidence_{safe_label}.png")
    try:
        driver.save_screenshot(path)
        log.debug("Screenshot saved: %s", path)
        return path
    except Exception as exc:
        log.warning("Screenshot capture failed for %s: %s", label, exc)
        return None

