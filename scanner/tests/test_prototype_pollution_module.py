import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from scanner.modules.prototype_pollution import test_prototype_pollution


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
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        if "__proto__[pentavault_canary]" in qs:
            return _Resp("received prototype key PENTAVAULT_PP_CANARY", 200)
        return _Resp("baseline response", 200)

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        data = data or {}
        if "__proto__[pentavault_canary]" in data:
            return _Resp("received prototype key PENTAVAULT_PP_CANARY", 200)
        return _Resp("baseline response", 200)

    def put(self, url: str, data: dict | None = None):
        return self.post(url, data=data)

    def patch(self, url: str, data: dict | None = None):
        return self.post(url, data=data)


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

    def put(self, _url: str, data: dict | None = None):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")

    def patch(self, _url: str, data: dict | None = None):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")


class TestPrototypePollutionModule(unittest.TestCase):
    def test_detects_prototype_key_reflection(self):
        client = _FakeClient()
        with patch("scanner.modules.prototype_pollution.httpx.Client", return_value=client):
            findings = test_prototype_pollution(
                ["https://example.com/api/profile?user=alice"],
                [],
                quick=True,
            )

        self.assertEqual(len(findings), 1)
        self.assertIn("Prototype Pollution", findings[0]["title"])
        self.assertIn("__proto__", findings[0]["parameter"])

    def test_honors_should_stop_before_requests(self):
        client = _SpyClient()
        with patch("scanner.modules.prototype_pollution.httpx.Client", return_value=client):
            findings = test_prototype_pollution(
                ["https://example.com/api/profile?user=alice"],
                [],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
