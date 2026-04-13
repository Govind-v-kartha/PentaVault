import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from scanner.modules.nosqli import test_nosqli


class _Resp:
    def __init__(self, text: str = "", status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "text/html"}


class _FakeClient:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str):
        self.calls += 1
        payload = next(iter(parse_qs(urlparse(url).query, keep_blank_values=True).values()), [""])[0]
        if "$ne" in payload:
            return _Resp("baseline content " + ("A" * 520))
        if "$eq" in payload:
            return _Resp("access denied")
        return _Resp("baseline content " + ("A" * 420))

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        joined = " ".join(str(v) for v in (data or {}).values())
        if "$ne" in joined:
            return _Resp("baseline content " + ("A" * 520))
        if "$eq" in joined:
            return _Resp("access denied")
        return _Resp("baseline content " + ("A" * 420))


class _SpyClient:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, _url: str):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")


class TestNoSQLiModule(unittest.TestCase):
    def test_detects_boolean_based_nosqli(self):
        client = _FakeClient()
        with patch("scanner.modules.nosqli.httpx.Client", return_value=client):
            findings = test_nosqli(["https://example.com/login?username=admin"], [], quick=True)

        self.assertEqual(len(findings), 1)
        self.assertIn("NoSQL Injection", findings[0]["title"])

    def test_honors_should_stop_before_requests(self):
        client = _SpyClient()
        with patch("scanner.modules.nosqli.httpx.Client", return_value=client):
            findings = test_nosqli(
                ["https://example.com/login?username=admin"],
                [],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
