from contextlib import contextmanager
import unittest
from unittest.mock import patch

from scanner.core.crawler import crawl
from scanner.core.selenium_crawler import selenium_crawl


class _Resp:
    def __init__(self, text: str = "", status_code: int = 200, content_type: str = "text/plain"):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": content_type}


class _FakeHttpClient:
    def __init__(self):
        self.calls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str):
        self.calls.append(url)
        return _Resp()


class _FakeDriver:
    def __init__(self):
        self.current_url = ""
        self.page_source = ""

    def get(self, url: str):
        self.current_url = url

    def find_elements(self, *_args, **_kwargs):
        return []

    def execute_script(self, *_args, **_kwargs):
        return []


class TestCrawlerRequestDelay(unittest.TestCase):
    def test_httpx_crawler_applies_request_delay(self):
        client = _FakeHttpClient()
        with patch("scanner.core.crawler.httpx.Client", return_value=client), patch(
            "scanner.core.crawler.time.sleep"
        ) as mocked_sleep:
            crawl(
                "https://example.com",
                max_depth=0,
                max_pages=1,
                respect_robots=False,
                request_delay=0.25,
            )

        mocked_sleep.assert_called_once_with(0.25)
        self.assertEqual(client.calls, ["https://example.com"])

    def test_selenium_crawler_applies_request_delay(self):
        driver = _FakeDriver()

        @contextmanager
        def _fake_browser(*_args, **_kwargs):
            yield driver

        with patch("scanner.core.selenium_crawler.create_browser", _fake_browser), patch(
            "scanner.core.selenium_crawler.time.sleep"
        ) as mocked_sleep:
            selenium_crawl(
                "https://example.com",
                max_depth=0,
                max_pages=1,
                request_delay=0.4,
                wait_per_page=0,
            )

        delays = [c.args[0] for c in mocked_sleep.call_args_list if c.args]
        self.assertIn(0.4, delays)


if __name__ == "__main__":
    unittest.main()
