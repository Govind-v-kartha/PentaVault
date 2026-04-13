import unittest
from unittest.mock import patch

from scanner.modules.sensitive_files import test_sensitive_files


class _Resp:
    def __init__(self, text: str = "", status_code: int = 404):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "text/plain"}


class _FakeClient:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str):
        self.calls += 1
        if url.endswith("/.env"):
            return _Resp("DB_PASSWORD=secret", 200)
        return _Resp("Not found", 404)


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


class TestSensitiveFilesModule(unittest.TestCase):
    def test_detects_exposed_sensitive_path(self):
        client = _FakeClient()
        with patch("scanner.modules.sensitive_files.httpx.Client", return_value=client):
            findings = test_sensitive_files("https://example.com", quick=True)

        self.assertEqual(len(findings), 1)
        self.assertIn("Sensitive File Exposure", findings[0]["title"])
        self.assertIn("/.env", findings[0]["payload"])

    def test_honors_should_stop_before_requests(self):
        client = _SpyClient()
        with patch("scanner.modules.sensitive_files.httpx.Client", return_value=client):
            findings = test_sensitive_files(
                "https://example.com",
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
