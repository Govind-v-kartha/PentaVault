import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from scanner.modules.insecure_deserialization import test_insecure_deserialization
from scanner.modules.mass_assignment import test_mass_assignment_bola


class _Resp:
    def __init__(self, text: str = "", status_code: int = 200, headers: dict | None = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _BaseClient:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _MassAssignmentClient(_BaseClient):
    def get(self, url: str, params: dict | None = None):
        self.calls += 1
        if params:
            query = urlencode_like(params)
            url = f"{url}?{query}"
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        user_id = (qs.get("user_id") or ["2"])[0]
        if user_id == "1":
            return _Resp("profile for admin account" + ("A" * 250), 200)
        return _Resp("profile for normal account", 200)

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        values = {k: str(v) for k, v in (data or {}).items()}
        if values.get("is_admin") == "true" or values.get("role") == "admin":
            return _Resp("profile updated role=admin permissions=all", 200)
        return _Resp("profile updated", 200)

    def put(self, url: str, data: dict | None = None):
        return self.post(url, data=data)

    def patch(self, url: str, data: dict | None = None):
        return self.post(url, data=data)


class _MassAssignmentSpyClient(_BaseClient):
    def get(self, _url: str, params: dict | None = None):
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


class _DeserializationClient(_BaseClient):
    def get(self, url: str, params: dict | None = None):
        self.calls += 1
        if params:
            query = urlencode_like(params)
            url = f"{url}?{query}"
        payload = next(iter(parse_qs(urlparse(url).query, keep_blank_values=True).values()), [""])[0]
        if payload.startswith("O:") or payload.startswith("rO0"):
            return _Resp("Fatal error: unserialize(): invalid stream", 500)
        return _Resp("baseline page", 200)

    def post(self, _url: str, data: dict | None = None):
        self.calls += 1
        joined = " ".join(str(v) for v in (data or {}).values())
        if "O:8:\"stdClass\"" in joined or "rO0" in joined:
            return _Resp("java.io.StreamCorruptedException", 500)
        return _Resp("baseline page", 200)

    def put(self, url: str, data: dict | None = None):
        return self.post(url, data=data)

    def patch(self, url: str, data: dict | None = None):
        return self.post(url, data=data)


class _DeserializationSpyClient(_BaseClient):
    def get(self, _url: str, params: dict | None = None):
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


def urlencode_like(data: dict[str, str]) -> str:
    return "&".join(f"{k}={v}" for k, v in data.items())


class TestMassAssignmentBolaModule(unittest.TestCase):
    def test_detects_bola_and_mass_assignment_behaviors(self):
        client = _MassAssignmentClient()
        endpoints = ["https://example.com/profile?user_id=2"]
        forms = [
            {
                "action": "https://example.com/api/profile/update",
                "method": "POST",
                "inputs": [
                    {"name": "display_name", "value": "alice"},
                    {"name": "email", "value": "a@example.com"},
                ],
            }
        ]

        with patch("scanner.modules.mass_assignment.httpx.Client", return_value=client):
            findings = test_mass_assignment_bola(endpoints, forms, quick=True)

        self.assertGreaterEqual(len(findings), 1)
        titles = "\n".join(f["title"] for f in findings)
        self.assertTrue("BOLA" in titles or "Mass Assignment" in titles)

    def test_honors_should_stop_before_requests(self):
        client = _MassAssignmentSpyClient()
        with patch("scanner.modules.mass_assignment.httpx.Client", return_value=client):
            findings = test_mass_assignment_bola(
                ["https://example.com/profile?user_id=2"],
                [],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


class TestInsecureDeserializationModule(unittest.TestCase):
    def test_detects_deserializer_error_markers(self):
        client = _DeserializationClient()
        endpoints = ["https://example.com/import?payload=eyJ0eXBlIjoiYmFzZWxpbmUifQ=="]
        forms = [
            {
                "action": "https://example.com/api/import",
                "method": "POST",
                "inputs": [
                    {"name": "payload", "value": "eyJ0eXBlIjoiYmFzZWxpbmUifQ=="},
                ],
            }
        ]

        with patch("scanner.modules.insecure_deserialization.httpx.Client", return_value=client):
            findings = test_insecure_deserialization(endpoints, forms, quick=True)

        self.assertGreaterEqual(len(findings), 1)
        self.assertIn("Insecure Deserialization", findings[0]["title"])

    def test_honors_should_stop_before_requests(self):
        client = _DeserializationSpyClient()
        with patch("scanner.modules.insecure_deserialization.httpx.Client", return_value=client):
            findings = test_insecure_deserialization(
                ["https://example.com/import?payload=abc"],
                [],
                should_stop=lambda: True,
            )

        self.assertEqual(findings, [])
        self.assertEqual(client.calls, 0)


if __name__ == "__main__":
    unittest.main()
