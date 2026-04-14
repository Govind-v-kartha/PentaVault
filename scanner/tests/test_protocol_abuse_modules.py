import base64
import json
import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from scanner.modules.cors_misconfig import test_cors_misconfig
from scanner.modules.crlf_injection import test_crlf_injection
from scanner.modules.graphql_abuse import test_graphql_abuse
from scanner.modules.host_header import test_host_header_injection
from scanner.modules.hpp import test_hpp
from scanner.modules.jwt_checks import test_jwt_checks
from scanner.modules.request_smuggling import test_request_smuggling


class _Resp:
    def __init__(self, text: str = "", status_code: int = 200, headers: dict | None = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


class _BaseClient:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _GraphQLClient(_BaseClient):
    def post(self, _url: str, json=None):
        self.calls += 1
        # Handle batch queries (list of dicts)
        if isinstance(json, list):
            return _Resp('[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]', 200)
        query = (json or {}).get("query", "")
        if "__schema" in query:
            return _Resp('{"data":{"__schema":{"types":[{"name":"Query"}]}}}', 200)
        if "__typename" in query:
            return _Resp('{"data":{"__typename":"Query"}}', 200)
        return _Resp('{"data":{"a0":{"a1":{"a2":{"name":"ok"}}}}}', 200)

    def json(self):
        import json as _json
        return _json.loads(self.text)


class _GraphQLSpyClient(_BaseClient):
    def post(self, _url: str, json=None):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")


class _HostHeaderClient(_BaseClient):
    def get(self, _url: str, headers: dict | None = None):
        self.calls += 1
        if headers and "Host" in headers:
            host = headers["Host"]
            return _Resp(f"welcome {host}", 302, {"location": f"https://{host}/redirect"})
        return _Resp("welcome safe-host", 200, {})


class _HostHeaderSpyClient(_BaseClient):
    def get(self, _url: str, headers: dict | None = None):
        self.calls += 1
        if headers and "Host" in headers:
            raise AssertionError("Host payload request should not execute when cancellation is requested")
        return _Resp("welcome safe-host", 200, {})


class _CorsClient(_BaseClient):
    def options(self, _url: str, headers: dict | None = None):
        self.calls += 1
        origin = (headers or {}).get("Origin", "")
        return _Resp(
            "",
            200,
            {
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            },
        )


class _CorsSpyClient(_BaseClient):
    def options(self, _url: str, headers: dict | None = None):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")


class _HppClient(_BaseClient):
    def get(self, url: str):
        self.calls += 1
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        if any(len(values) > 1 for values in qs.values()):
            return _Resp("polluted-" + ("A" * 400), 200, {})
        return _Resp("baseline", 200, {})


class _HppSpyClient(_BaseClient):
    def get(self, _url: str):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")


class _CrlfClient(_BaseClient):
    def get(self, url: str):
        self.calls += 1
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        values = [v for items in qs.values() for v in items]
        if any("%0d%0a" in value.lower() for value in values):
            return _Resp("ok", 200, {"X-Injected-Header": "crlf"})
        return _Resp("ok", 200, {})


class _CrlfSpyClient(_BaseClient):
    def get(self, _url: str):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")


class _SmugglingClient(_BaseClient):
    def post(self, _url: str, headers: dict | None = None, content: str | None = None):
        self.calls += 1
        if headers and headers.get("Transfer-Encoding") == "chunked":
            return _Resp("", 500, {})
        return _Resp("", 200, {})


class _SmugglingSpyClient(_BaseClient):
    def post(self, _url: str, headers: dict | None = None, content: str | None = None):
        self.calls += 1
        raise AssertionError("HTTP request should not execute when cancellation is requested")


class TestGraphQLAbuseModule(unittest.TestCase):
    def test_detects_introspection_or_depth_weakness(self):
        client = _GraphQLClient()
        with patch("scanner.modules.graphql_abuse.httpx.Client", return_value=client):
            findings = test_graphql_abuse("https://example.com", [], quick=True)

        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("GraphQL:" in f["title"] for f in findings))

    def test_honors_should_stop_before_requests(self):
        client = _GraphQLSpyClient()
        with patch("scanner.modules.graphql_abuse.httpx.Client", return_value=client):
            findings = test_graphql_abuse("https://example.com", [], should_stop=lambda: True)

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


class TestJwtChecksModule(unittest.TestCase):
    @staticmethod
    def _b64url(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def test_detects_none_alg_kid_path_and_missing_exp(self):
        header = self._b64url({"alg": "none", "kid": "../etc/passwd", "typ": "JWT"})
        payload = self._b64url({"sub": "1"})
        token = f"{header}.{payload}.signature"

        findings = test_jwt_checks([f"https://example.com/profile?token={token}"], [], quick=True)
        titles = "\n".join(f["title"] for f in findings)

        self.assertIn("none", titles.lower())
        self.assertIn("kid", titles.lower())
        self.assertIn("missing exp", titles.lower())

    def test_honors_should_stop_before_processing_tokens(self):
        header = self._b64url({"alg": "none"})
        payload = self._b64url({"sub": "1"})
        token = f"{header}.{payload}.signature"

        findings = test_jwt_checks([f"https://example.com/profile?token={token}"], [], should_stop=lambda: True)
        self.assertEqual(findings, [])


class TestHostHeaderModule(unittest.TestCase):
    def test_detects_host_reflection(self):
        client = _HostHeaderClient()
        with patch("scanner.modules.host_header.httpx.Client", return_value=client):
            findings = test_host_header_injection("https://example.com")

        self.assertGreaterEqual(len(findings), 1)
        self.assertIn("Host Header Injection", findings[0]["title"])

    def test_honors_should_stop_before_payload_requests(self):
        client = _HostHeaderSpyClient()
        with patch("scanner.modules.host_header.httpx.Client", return_value=client):
            findings = test_host_header_injection("https://example.com", should_stop=lambda: True)

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 1)  # baseline only


class TestCorsMisconfigModule(unittest.TestCase):
    def test_detects_reflected_origin_with_credentials(self):
        client = _CorsClient()
        with patch("scanner.modules.cors_misconfig.httpx.Client", return_value=client):
            findings = test_cors_misconfig("https://example.com")

        self.assertGreaterEqual(len(findings), 1)
        self.assertIn("CORS Misconfiguration", findings[0]["title"])

    def test_honors_should_stop_before_requests(self):
        client = _CorsSpyClient()
        with patch("scanner.modules.cors_misconfig.httpx.Client", return_value=client):
            findings = test_cors_misconfig("https://example.com", should_stop=lambda: True)

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


class TestHppModule(unittest.TestCase):
    def test_detects_duplicate_parameter_behavior_change(self):
        client = _HppClient()
        with patch("scanner.modules.hpp.httpx.Client", return_value=client):
            findings = test_hpp(["https://example.com/search?q=test"], quick=True)

        self.assertEqual(len(findings), 1)
        self.assertIn("Parameter Pollution", findings[0]["title"])

    def test_honors_should_stop_before_requests(self):
        client = _HppSpyClient()
        with patch("scanner.modules.hpp.httpx.Client", return_value=client):
            findings = test_hpp(["https://example.com/search?q=test"], should_stop=lambda: True)

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


class TestCrlfInjectionModule(unittest.TestCase):
    def test_detects_injected_response_header_marker(self):
        client = _CrlfClient()
        with patch("scanner.modules.crlf_injection.httpx.Client", return_value=client):
            findings = test_crlf_injection(["https://example.com/search?q=test"], quick=True)

        self.assertEqual(len(findings), 1)
        self.assertIn("CRLF Injection", findings[0]["title"])

    def test_honors_should_stop_before_requests(self):
        client = _CrlfSpyClient()
        with patch("scanner.modules.crlf_injection.httpx.Client", return_value=client):
            findings = test_crlf_injection(["https://example.com/search?q=test"], should_stop=lambda: True)

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


class TestRequestSmugglingModule(unittest.TestCase):
    def test_detects_smuggling_via_status_response(self):
        """Mock _raw_request to return error status for CL.TE probe."""
        call_count = [0]
        def fake_raw_request(host, port, use_tls, raw_bytes, timeout=10.0):
            call_count[0] += 1
            # First call is baseline
            if call_count[0] == 1:
                return 0.5, b"HTTP/1.1 200 OK\r\n\r\n"
            # Subsequent probes return 500 error
            return 0.5, b"HTTP/1.1 500 Internal Server Error\r\n\r\n"

        with patch("scanner.modules.request_smuggling._raw_request", side_effect=fake_raw_request):
            with patch("scanner.modules.request_smuggling._measure_baseline", return_value=0.5):
                findings = test_request_smuggling("https://example.com")

        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("Request Smuggling" in f["title"] for f in findings))

    def test_honors_should_stop_before_requests(self):
        findings = test_request_smuggling("https://example.com", should_stop=lambda: True)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
