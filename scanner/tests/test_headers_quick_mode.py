import unittest
from unittest.mock import patch

from scanner.modules.headers import test_headers


class _FakeResponse:
    def __init__(self):
        self.status_code = 200
        self.headers = {"server": "nginx/1.25.0"}


class _FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url):
        return _FakeResponse()


class TestHeadersQuickMode(unittest.TestCase):
    @patch("scanner.modules.headers.httpx.Client", new=_FakeClient)
    def test_quick_mode_checks_only_critical_headers(self):
        findings = test_headers("https://example.com", quick=True)
        titles = [f["title"] for f in findings]

        self.assertEqual(len(findings), 4)
        self.assertFalse(any("Server Version Disclosure" in t for t in titles))

    @patch("scanner.modules.headers.httpx.Client", new=_FakeClient)
    def test_full_mode_includes_server_disclosure(self):
        findings = test_headers("https://example.com", quick=False)
        titles = [f["title"] for f in findings]

        self.assertGreaterEqual(len(findings), 8)
        self.assertTrue(any("Server Version Disclosure" in t for t in titles))


if __name__ == "__main__":
    unittest.main()
