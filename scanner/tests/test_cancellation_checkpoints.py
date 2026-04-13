import unittest
from unittest.mock import patch

from scanner.core.crawler import crawl
from scanner.modules.open_redirect import test_open_redirect


class _SpyClient:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")


class TestCancellationCheckpoints(unittest.TestCase):
    def test_crawler_honors_should_stop_before_fetch(self):
        client = _SpyClient()
        with patch("scanner.core.crawler.httpx.Client", return_value=client):
            result = crawl(
                "https://example.com",
                max_depth=2,
                max_pages=10,
                respect_robots=False,
                should_stop=lambda: True,
            )

        self.assertEqual(result.endpoints, [])
        self.assertEqual(client.calls, 0)

    def test_open_redirect_honors_should_stop_before_requests(self):
        client = _SpyClient()
        with patch("scanner.modules.open_redirect.httpx.Client", return_value=client):
            findings = test_open_redirect(
                ["https://example.com/login?next=/home"],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
