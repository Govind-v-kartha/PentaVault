import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from scanner.modules.command_injection import test_command_injection


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
        payload = next(iter(qs.values()), [""])[0]

        if "expr 9137 + 133" in payload:
            return _Resp("command-result=9270")
        if "set /a 6000+37" in payload:
            return _Resp("command-result=6037")
        return _Resp("normal page")

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        data = data or {}
        joined = " ".join(str(v) for v in data.values())
        if "expr 9137 + 133" in joined:
            return _Resp("command-result=9270")
        if "set /a 6000+37" in joined:
            return _Resp("command-result=6037")
        return _Resp("normal form response")


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


class TestCommandInjectionModule(unittest.TestCase):
    def test_detects_output_based_command_injection(self):
        client = _FakeClient()
        with patch("scanner.modules.command_injection.httpx.Client", return_value=client):
            findings = test_command_injection(
                ["https://example.com/search?q=test"],
                [],
                quick=True,
            )

        self.assertEqual(len(findings), 1)
        self.assertIn("OS Command Injection", findings[0]["title"])
        self.assertEqual(findings[0]["parameter"], "q")

    def test_honors_should_stop_before_requests(self):
        client = _SpyClient()
        with patch("scanner.modules.command_injection.httpx.Client", return_value=client):
            findings = test_command_injection(
                ["https://example.com/search?q=test"],
                [],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
