import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from scanner.modules.xxe import test_xxe


class _Resp:
    def __init__(self, text: str = "", status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "application/xml"}


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

        if "<!DOCTYPE" in payload and "xxe" in payload:
            return _Resp("root:x:0:0:root:/root:/bin/bash")
        return _Resp("ok")

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        data = data or {}
        joined = " ".join(str(v) for v in data.values())

        if "<!DOCTYPE" in joined and "xxe" in joined:
            return _Resp("root:x:0:0:root:/root:/bin/bash")
        return _Resp("ok")


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


class TestXXEModule(unittest.TestCase):
    def test_detects_xxe_file_disclosure_markers(self):
        client = _FakeClient()
        with patch("scanner.modules.xxe.httpx.Client", return_value=client):
            findings = test_xxe(
                ["https://example.com/api/import?xml=<root/>"] ,
                [],
                quick=True,
            )

        self.assertEqual(len(findings), 1)
        self.assertIn("XXE", findings[0]["title"])
        self.assertEqual(findings[0]["parameter"], "xml")

    def test_honors_should_stop_before_requests(self):
        client = _SpyClient()
        with patch("scanner.modules.xxe.httpx.Client", return_value=client):
            findings = test_xxe(
                ["https://example.com/api/import?xml=<root/>"] ,
                [],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
