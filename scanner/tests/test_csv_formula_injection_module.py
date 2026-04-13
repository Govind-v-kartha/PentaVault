import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from scanner.modules.csv_formula_injection import test_csv_formula_injection


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
        if payload.startswith(("=", "+", "-", "@")):
            return _Resp(f"export row value={payload}", 200)
        return _Resp("export row value=baseline", 200)

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        data = data or {}
        payload = next(iter(data.values()), "")
        if str(payload).startswith(("=", "+", "-", "@")):
            return _Resp(f"export row value={payload}", 200)
        return _Resp("export row value=baseline", 200)

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


class TestCsvFormulaInjectionModule(unittest.TestCase):
    def test_detects_formula_value_reflection(self):
        client = _FakeClient()
        with patch("scanner.modules.csv_formula_injection.httpx.Client", return_value=client):
            findings = test_csv_formula_injection(
                ["https://example.com/export.csv?name=alice"],
                [],
                quick=True,
            )

        self.assertEqual(len(findings), 1)
        self.assertIn("CSV/Formula Injection", findings[0]["title"])
        self.assertEqual(findings[0]["parameter"], "name")

    def test_honors_should_stop_before_requests(self):
        client = _SpyClient()
        with patch("scanner.modules.csv_formula_injection.httpx.Client", return_value=client):
            findings = test_csv_formula_injection(
                ["https://example.com/export.csv?name=alice"],
                [],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
