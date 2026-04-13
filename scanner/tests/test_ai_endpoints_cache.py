import unittest
from datetime import datetime
from unittest.mock import patch

from fastapi import HTTPException

from scanner.web import app as web_app


class TestAiEndpointCaching(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.scan_id = "ai-cache-test"
        self.base_scan = {
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
                    "detail": "Reflected XSS marker found",
                    "payload": "<script>alert(1)</script>",
                    "mitre_attack": [{"technique": "T1059", "name": "Command and Scripting Interpreter"}],
                },
                {
                    "type": "headers",
                    "module": "Headers",
                    "severity": "Medium",
                    "parameter": "",
                    "detail": "Missing CSP header",
                    "payload": "",
                    "mitre_attack": [{"technique": "T1190", "name": "Exploit Public-Facing Application"}],
                },
            ],
        }
        web_app.scans[self.scan_id] = dict(self.base_scan)

    def tearDown(self):
        web_app.scans.pop(self.scan_id, None)

    async def test_ai_analyze_uses_cache_on_repeat(self):
        request = web_app.AIRequest(scan_id=self.scan_id)
        with (
            patch("scanner.web.app._require_gemini_api_keys", return_value=["k"]),
            patch("scanner.web.app.build_mitre_breakdown", return_value=[{"tactic": "Execution", "technique_count": 1}]),
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics_with_hits": 1, "total_tactics": 14, "total_technique_hits": 1}),
            patch("scanner.web.app.ai_threat_analysis", return_value="analysis-result") as mocked_ai,
        ):
            first = await web_app.ai_analyze(request)
            second = await web_app.ai_analyze(request)

        self.assertEqual(first["analysis"], "analysis-result")
        self.assertEqual(second["analysis"], "analysis-result")
        self.assertEqual(mocked_ai.call_count, 1)

    async def test_ai_remediate_cache_key_depends_on_index(self):
        web_app.scans[self.scan_id]["findings"].append(
            {
                "type": "sqli",
                "module": "SQLi",
                "severity": "High",
                "parameter": "id",
                "detail": "SQL error pattern",
                "payload": "' OR 1=1--",
                "mitre_attack": [{"technique": "T1190", "name": "Exploit Public-Facing Application"}],
            }
        )

        with (
            patch("scanner.web.app._require_gemini_api_keys", return_value=["k"]),
            patch("scanner.web.app.ai_remediation", side_effect=["fix-0", "fix-1"]) as mocked_rem,
        ):
            first = await web_app.ai_remediate(web_app.AIRequest(scan_id=self.scan_id, finding_index=0))
            second = await web_app.ai_remediate(web_app.AIRequest(scan_id=self.scan_id, finding_index=1))
            third = await web_app.ai_remediate(web_app.AIRequest(scan_id=self.scan_id, finding_index=0))

        self.assertEqual(first["remediation"], "fix-0")
        self.assertEqual(second["remediation"], "fix-1")
        self.assertEqual(third["remediation"], "fix-0")
        self.assertEqual(mocked_rem.call_count, 2)

    async def test_ai_exec_summary_cache_preserves_report_field(self):
        req = web_app.AIRequest(scan_id=self.scan_id)
        with (
            patch("scanner.web.app._require_gemini_api_keys", return_value=["k"]),
            patch("scanner.web.app.ai_executive_summary", return_value="exec-summary") as mocked_exec,
        ):
            first = await web_app.ai_exec_summary(req)
            second = await web_app.ai_exec_summary(req)

        self.assertEqual(first["summary"], "exec-summary")
        self.assertEqual(second["summary"], "exec-summary")
        self.assertEqual(mocked_exec.call_count, 1)
        self.assertEqual(web_app.scans[self.scan_id].get("_ai_executive_summary"), "exec-summary")

    async def test_ai_mitre_explain_cache_normalizes_question_whitespace(self):
        with (
            patch("scanner.web.app._require_gemini_api_keys", return_value=["k"]),
            patch("scanner.web.app.ai_mitre_explain", return_value="mitre-answer") as mocked_explain,
        ):
            first = await web_app.ai_mitre_explain_endpoint(
                web_app.MitreExplainRequest(
                    scan_id=self.scan_id,
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    tactic="Initial Access",
                    question="What is the exploit path?",
                )
            )
            second = await web_app.ai_mitre_explain_endpoint(
                web_app.MitreExplainRequest(
                    scan_id=self.scan_id,
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    tactic="Initial Access",
                    question="  What is the exploit path?   ",
                )
            )

        self.assertEqual(first["explanation"], "mitre-answer")
        self.assertEqual(second["explanation"], "mitre-answer")
        self.assertEqual(mocked_explain.call_count, 1)

    async def test_ai_failure_is_not_cached(self):
        req = web_app.AIRequest(scan_id=self.scan_id)
        with (
            patch("scanner.web.app._require_gemini_api_keys", return_value=["k"]),
            patch("scanner.web.app.build_mitre_breakdown", return_value=[]),
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics_with_hits": 0, "total_tactics": 14, "total_technique_hits": 0}),
            patch("scanner.web.app.ai_threat_analysis", side_effect=[RuntimeError("boom"), "ok"]) as mocked_ai,
        ):
            with self.assertRaises(HTTPException) as first_exc:
                await web_app.ai_analyze(req)
            second = await web_app.ai_analyze(req)

        self.assertEqual(first_exc.exception.status_code, 502)
        self.assertIsInstance(first_exc.exception.detail, dict)
        self.assertEqual(first_exc.exception.detail.get("code"), "AI_UPSTREAM_UNAVAILABLE")
        self.assertEqual(second["analysis"], "ok")
        self.assertEqual(mocked_ai.call_count, 2)


if __name__ == "__main__":
    unittest.main()
