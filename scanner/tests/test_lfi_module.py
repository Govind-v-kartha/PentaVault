import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from scanner.modules.lfi import test_lfi


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
        if "etc/passwd" in payload:
            return _Resp("root:x:0:0:root:/root:/bin/bash")
        return _Resp("normal")

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        joined = " ".join(str(v) for v in (data or {}).values())
        if "etc/passwd" in joined:
            return _Resp("root:x:0:0:root:/root:/bin/bash")
        return _Resp("normal")


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


class TestLFIModule(unittest.TestCase):
    def test_detects_lfi_file_disclosure_marker(self):
        client = _FakeClient()
        with patch("scanner.modules.lfi.httpx.Client", return_value=client):
            findings = test_lfi(["https://example.com/download?file=index.php"], [], quick=True)

        self.assertEqual(len(findings), 1)
        self.assertIn("LFI", findings[0]["title"])
        self.assertEqual(findings[0]["parameter"], "file")

    def test_honors_should_stop_before_requests(self):
        client = _SpyClient()
        with patch("scanner.modules.lfi.httpx.Client", return_value=client):
            findings = test_lfi(
                ["https://example.com/download?file=index.php"],
                [],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
