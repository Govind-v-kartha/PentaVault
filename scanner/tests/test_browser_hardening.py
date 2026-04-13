import os
import unittest
from unittest.mock import patch

from scanner.core.browser import _chrome_options, inject_cookie


class _FakeDriver:
    def __init__(self):
        self.visited: list[str] = []
        self.cookies: list[dict] = []
        self.refreshed = False

    def get(self, url: str):
        self.visited.append(url)

    def add_cookie(self, cookie: dict):
        self.cookies.append(cookie)

    def refresh(self):
        self.refreshed = True


class TestBrowserHardening(unittest.TestCase):
    def test_no_sandbox_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            opts = _chrome_options(headless=True)

        self.assertNotIn("--no-sandbox", opts.arguments)

    def test_no_sandbox_enabled_only_by_explicit_env_flag(self):
        with patch.dict(os.environ, {"PENTAVAULT_ALLOW_NO_SANDBOX": "1"}, clear=True):
            opts = _chrome_options(headless=True)

        self.assertIn("--no-sandbox", opts.arguments)

    def test_inject_cookie_sets_domain_and_path(self):
        driver = _FakeDriver()

        inject_cookie(driver, "https://example.com/login", "session=abc123; theme=dark")

        self.assertEqual(driver.visited, ["https://example.com/login"])
        self.assertTrue(driver.refreshed)
        self.assertEqual(len(driver.cookies), 2)
        self.assertEqual(driver.cookies[0]["name"], "session")
        self.assertEqual(driver.cookies[0]["value"], "abc123")
        self.assertEqual(driver.cookies[0]["domain"], "example.com")
        self.assertEqual(driver.cookies[0]["path"], "/")

    def test_inject_cookie_ignores_invalid_cookie_parts(self):
        driver = _FakeDriver()

        inject_cookie(driver, "https://example.com", "badpart; token=xyz")

        self.assertEqual(len(driver.cookies), 1)
        self.assertEqual(driver.cookies[0]["name"], "token")


if __name__ == "__main__":
    unittest.main()
