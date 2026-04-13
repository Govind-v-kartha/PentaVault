import unittest
from datetime import datetime
from unittest.mock import patch

from fastapi import HTTPException

from scanner.web import app as web_app


class TestAiErrorContract(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.scan_id = "ai-error-contract-test"
        web_app.scans[self.scan_id] = {
            "scan_id": self.scan_id,
            "status": "completed",
            "target": "https://example.com",
            "mode": "quick",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "findings": [
                {
                    "type": "xss",
                    "module": "XSS",
                    "severity": "High",
                    "parameter": "q",
                    "detail": "Reflected marker",
                    "payload": "<script>alert(1)</script>",
                    "mitre_attack": [{"technique": "T1059", "name": "Command and Scripting Interpreter"}],
                }
            ],
        }

    def tearDown(self):
        web_app.scans.pop(self.scan_id, None)

    async def test_missing_ai_key_returns_structured_config_error(self):
        req = web_app.AIRequest(scan_id=self.scan_id)
        with (
            patch("scanner.web.app.build_mitre_breakdown", return_value=[]),
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics_with_hits": 0, "total_tactics": 14, "total_technique_hits": 0}),
            patch("scanner.web.app.load_gemini_api_keys", return_value=[]),
        ):
            with self.assertRaises(HTTPException) as exc_info:
                await web_app.ai_analyze(req)

        err = exc_info.exception
        self.assertEqual(err.status_code, 400)
        self.assertIsInstance(err.detail, dict)
        self.assertEqual(err.detail.get("code"), "AI_CONFIG_MISSING")
        self.assertEqual(err.detail.get("retryable"), False)
        self.assertIsInstance(err.detail.get("message"), str)
        self.assertTrue(err.detail["message"])

    async def test_upstream_failure_is_sanitized_and_retryable(self):
        req = web_app.AIRequest(scan_id=self.scan_id)
        with (
            patch("scanner.web.app._require_gemini_api_keys", return_value=["k"]),
            patch("scanner.web.app.build_mitre_breakdown", return_value=[]),
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics_with_hits": 0, "total_tactics": 14, "total_technique_hits": 0}),
            patch("scanner.web.app.ai_threat_analysis", side_effect=RuntimeError("Gemini API key not configured")),
        ):
            with self.assertRaises(HTTPException) as exc_info:
                await web_app.ai_analyze(req)

        err = exc_info.exception
        self.assertEqual(err.status_code, 502)
        self.assertEqual(err.detail.get("code"), "AI_UPSTREAM_UNAVAILABLE")
        self.assertEqual(err.detail.get("retryable"), True)
        self.assertNotIn("Gemini", err.detail.get("message", ""))
        self.assertNotIn("API key", err.detail.get("message", ""))

    async def test_pool_exhaustion_message_stays_sanitized(self):
        req = web_app.AIRequest(scan_id=self.scan_id)
        with (
            patch("scanner.web.app._require_gemini_api_keys", return_value=["k1", "k2"]),
            patch("scanner.web.app.build_mitre_breakdown", return_value=[]),
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics_with_hits": 0, "total_tactics": 14, "total_technique_hits": 0}),
            patch("scanner.web.app.ai_threat_analysis", side_effect=RuntimeError("All API keys/models exhausted: HTTP 429 (key ...abc123, model gemini-2.0-flash)")),
        ):
            with self.assertRaises(HTTPException) as exc_info:
                await web_app.ai_analyze(req)

        err = exc_info.exception
        self.assertEqual(err.status_code, 502)
        self.assertEqual(err.detail.get("code"), "AI_UPSTREAM_UNAVAILABLE")
        self.assertEqual(err.detail.get("retryable"), True)
        self.assertNotIn("abc123", err.detail.get("message", ""))
        self.assertNotIn("Gemini", err.detail.get("message", ""))

    async def test_preserves_already_sanitized_http_exception(self):
        req = web_app.AIRequest(scan_id=self.scan_id)
        detail = {"code": "AI_UPSTREAM_UNAVAILABLE", "message": "AI service is temporarily unavailable.", "retryable": True}
        with (
            patch("scanner.web.app._require_gemini_api_keys", return_value=["k"]),
            patch("scanner.web.app.build_mitre_breakdown", return_value=[]),
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics_with_hits": 0, "total_tactics": 14, "total_technique_hits": 0}),
            patch("scanner.web.app.ai_threat_analysis", side_effect=HTTPException(status_code=502, detail=detail)),
        ):
            with self.assertRaises(HTTPException) as exc_info:
                await web_app.ai_analyze(req)

        self.assertEqual(exc_info.exception.status_code, 502)
        self.assertEqual(exc_info.exception.detail, detail)


if __name__ == "__main__":
    unittest.main()
