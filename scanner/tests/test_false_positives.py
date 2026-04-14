"""Negative test cases — false positive prevention.

These tests verify that detection modules do NOT fire on benign inputs.
Each test mocks HTTP responses with realistic non-vulnerable content and
asserts that the module returns zero findings.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock


class _FakeResponse:
    """Minimal httpx.Response mock."""
    def __init__(self, text: str = "", status_code: int = 200, headers: dict | None = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/html"}


class _FakeClient:
    """Mock httpx.Client that returns preconfigured responses."""
    def __init__(self, responses: dict[str, _FakeResponse] | None = None, default: _FakeResponse | None = None):
        self._responses = responses or {}
        self._default = default or _FakeResponse()

    def get(self, url, **kw):
        return self._responses.get(url, self._default)

    def post(self, url, **kw):
        return self._responses.get(url, self._default)

    def put(self, url, **kw):
        return self._responses.get(url, self._default)

    def patch(self, url, **kw):
        return self._responses.get(url, self._default)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ── SQLi False Positives ──────────────────────────────────────────

class TestSqliFalsePositives(unittest.TestCase):
    """Verify SQLi module doesn't fire on dynamic but non-vulnerable content."""

    def test_dynamic_timestamps_no_boolean_sqli(self):
        """Pages with dynamic timestamps should not trigger boolean-based SQLi."""
        import time
        ts = str(int(time.time()))

        # Each request returns slightly different content (timestamps, CSRF tokens)
        call_count = [0]
        def _varying_response(*args, **kwargs):
            call_count[0] += 1
            body = f'<html><body>Request {call_count[0]} at {ts}{call_count[0]}</body></html>'
            return _FakeResponse(text=body)

        client = MagicMock()
        client.get = _varying_response
        client.__enter__ = lambda s: s
        client.__exit__ = lambda s, *a: None

        with patch("httpx.Client", return_value=client):
            from scanner.modules.sqli import test_sqli
            findings = test_sqli(
                endpoints=["http://example.com/search?q=test"],
                forms=[],
                quick=True,
            )
        self.assertEqual(len(findings), 0, "Dynamic timestamps should not trigger boolean SQLi")

    def test_no_error_on_benign_responses(self):
        """Normal HTML pages should not trigger error-based SQLi."""
        benign_html = '<html><head><title>Welcome</title></head><body><p>Hello world</p></body></html>'
        client = _FakeClient(default=_FakeResponse(text=benign_html))

        with patch("httpx.Client", return_value=client):
            from scanner.modules.sqli import test_sqli
            findings = test_sqli(
                endpoints=["http://example.com/page?id=5"],
                forms=[],
                quick=True,
            )
        self.assertEqual(len(findings), 0, "Benign HTML should not trigger SQLi")


# ── XSS False Positives ──────────────────────────────────────────

class TestXssFalsePositives(unittest.TestCase):
    """Verify XSS module doesn't fire on pages that use JS frameworks."""

    def test_react_app_no_dom_xss(self):
        """A React app using dangerouslySetInnerHTML should NOT trigger DOM XSS.

        After the fix, the HTTP XSS module no longer does static DOM analysis,
        so this test validates the fix is in place.
        """
        react_page = '''
        <html><body>
        <div id="root"></div>
        <script>
        document.getElementById("root").innerHTML = "<h1>Hello</h1>";
        var url = document.URL;
        var ref = document.referrer;
        location.hash;
        eval("console.log('safe')");
        </script>
        </body></html>
        '''
        client = _FakeClient(default=_FakeResponse(text=react_page))

        with patch("httpx.Client", return_value=client):
            from scanner.modules.xss import test_xss
            findings = test_xss(
                endpoints=["http://example.com/app"],
                forms=[],
                quick=True,
            )
        # Should be 0: no reflected payload, no DOM analysis in HTTP module
        self.assertEqual(len(findings), 0, "React app should not trigger XSS in HTTP module")

    def test_no_reflected_without_reflection(self):
        """If the payload isn't reflected in the response, no finding."""
        safe_page = '<html><body><p>Search results for: (sanitized)</p></body></html>'
        client = _FakeClient(default=_FakeResponse(text=safe_page))

        with patch("httpx.Client", return_value=client):
            from scanner.modules.xss import test_xss
            findings = test_xss(
                endpoints=["http://example.com/search?q=test"],
                forms=[],
                quick=True,
            )
        self.assertEqual(len(findings), 0, "Non-reflecting page should not trigger XSS")


# ── IDOR False Positives ─────────────────────────────────────────

class TestIdorFalsePositives(unittest.TestCase):
    """Verify IDOR module doesn't fire on dynamic or non-identity content."""

    def test_pagination_no_idor(self):
        """Pages with different content per page number should not trigger IDOR."""
        # Both responses are 200 with similar structure but no identity fields
        base_resp = _FakeResponse(text='{"items": [1,2,3], "page": 1, "total": 100}')
        alt_resp = _FakeResponse(text='{"items": [4,5,6], "page": 2, "total": 100}')

        def _get(url, **kw):
            if "/2/" in url or "/2?" in url:
                return alt_resp
            return base_resp

        client = MagicMock()
        client.get = _get
        client.__enter__ = lambda s: s
        client.__exit__ = lambda s, *a: None

        with patch("httpx.Client", return_value=client):
            from scanner.modules.idor import test_idor
            findings = test_idor(
                endpoints=["http://example.com/api/items/1"],
                quick=True,
            )
        self.assertEqual(len(findings), 0, "Pagination should not trigger IDOR")


# ── NoSQLi False Positives ───────────────────────────────────────

class TestNosqliFalsePositives(unittest.TestCase):
    """Verify NoSQLi module doesn't fire on variable search results."""

    def test_search_results_no_nosqli(self):
        """Variable search result lengths should not trigger boolean NoSQLi."""
        # All responses return the same status and similar content
        base = _FakeResponse(text='{"results": ["a", "b", "c"], "count": 3}')
        client = _FakeClient(default=base)

        with patch("httpx.Client", return_value=client):
            from scanner.modules.nosqli import test_nosqli
            findings = test_nosqli(
                endpoints=["http://example.com/api/search?query=test"],
                forms=[],
                quick=True,
            )
        self.assertEqual(len(findings), 0, "Identical search results should not trigger NoSQLi")


# ── Command Injection False Positives ────────────────────────────

class TestCommandInjectionFalsePositives(unittest.TestCase):
    """Verify command injection doesn't fire on benign content."""

    def test_no_false_positive_on_math_in_page(self):
        """A page that naturally contains '9270' should not trigger if param is not exec-like."""
        page = '<html><body>Item #9270 - Regular product page. PENTAVAULT_CMDI_CANARY is not here.</body></html>'
        baseline = '<html><body>Item #9270 - Regular product page.</body></html>'
        # The marker "9270" is in BOTH baseline and response, so evidence fn should return None
        client = _FakeClient(default=_FakeResponse(text=page))

        with patch("httpx.Client", return_value=client):
            from scanner.modules.command_injection import test_command_injection
            findings = test_command_injection(
                endpoints=["http://example.com/product?name=test"],
                forms=[],
                quick=True,
            )
        # "name" doesn't match exec param regex, so it should be skipped
        self.assertEqual(len(findings), 0, "Non-exec parameter should not trigger command injection")


# ── Mass Assignment False Positives ──────────────────────────────

class TestMassAssignmentFalsePositives(unittest.TestCase):
    """Verify mass assignment doesn't fire on forms that echo input."""

    def test_echo_form_no_mass_assignment(self):
        """A form that echoes submitted values should not trigger mass assignment."""
        # Baseline and candidate return same status with similar content
        base_resp = _FakeResponse(text='{"status": "ok", "message": "Form submitted"}')
        client = _FakeClient(default=base_resp)

        with patch("httpx.Client", return_value=client):
            from scanner.modules.mass_assignment import test_mass_assignment_bola
            findings = test_mass_assignment_bola(
                endpoints=[],
                forms=[{
                    "action": "http://example.com/profile",
                    "method": "POST",
                    "inputs": [
                        {"name": "username", "type": "text", "value": "testuser"},
                        {"name": "bio", "type": "textarea", "value": "hello"},
                    ],
                }],
                quick=True,
            )
        self.assertEqual(len(findings), 0, "Identical responses should not trigger mass assignment")


if __name__ == "__main__":
    unittest.main()
