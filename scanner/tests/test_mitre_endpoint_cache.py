import unittest
from datetime import datetime
from unittest.mock import patch

from scanner.web import app as web_app


class TestMitreEndpointCache(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.scan_id = "mitre-cache-test"
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
                    "detail": "reflected marker",
                    "payload": "<script>alert(1)</script>",
                }
            ],
        }

    def tearDown(self):
        web_app.scans.pop(self.scan_id, None)

    async def test_reuses_cached_payload_for_same_findings(self):
        with (
            patch("scanner.web.app.build_mitre_breakdown", return_value=[{"tactic": "Execution"}]) as mocked_breakdown,
            patch("scanner.web.app.build_attack_paths", return_value=[{"phase": "Exploitation"}]) as mocked_paths,
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics": [], "overall_coverage_pct": 0}) as mocked_cov,
            patch("scanner.web.app.build_threat_narrative", return_value={"finding_count": 1}) as mocked_narr,
        ):
            first = await web_app.get_mitre_breakdown(self.scan_id)
            second = await web_app.get_mitre_breakdown(self.scan_id)

        self.assertEqual(first, second)
        self.assertEqual(mocked_breakdown.call_count, 1)
        self.assertEqual(mocked_paths.call_count, 1)
        self.assertEqual(mocked_cov.call_count, 1)
        self.assertEqual(mocked_narr.call_count, 1)

    async def test_cache_invalidates_when_findings_change(self):
        with (
            patch("scanner.web.app.build_mitre_breakdown", side_effect=[[{"tactic": "Execution"}], [{"tactic": "Discovery"}]]) as mocked_breakdown,
            patch("scanner.web.app.build_attack_paths", return_value=[]),
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics": [], "overall_coverage_pct": 0}),
            patch("scanner.web.app.build_threat_narrative", return_value={"finding_count": 1}),
        ):
            first = await web_app.get_mitre_breakdown(self.scan_id)
            web_app.scans[self.scan_id]["findings"].append(
                {
                    "type": "headers",
                    "module": "Headers",
                    "severity": "Medium",
                    "parameter": "",
                    "detail": "missing csp",
                    "payload": "",
                }
            )
            second = await web_app.get_mitre_breakdown(self.scan_id)

        self.assertNotEqual(first["mitre_breakdown"], second["mitre_breakdown"])
        self.assertEqual(mocked_breakdown.call_count, 2)

    async def test_response_shape_remains_compatible(self):
        with (
            patch("scanner.web.app.build_mitre_breakdown", return_value=[]),
            patch("scanner.web.app.build_attack_paths", return_value=[]),
            patch("scanner.web.app.compute_matrix_coverage", return_value={"tactics": [], "overall_coverage_pct": 0}),
            patch("scanner.web.app.build_threat_narrative", return_value={"finding_count": 0}),
        ):
            payload = await web_app.get_mitre_breakdown(self.scan_id)

        self.assertEqual(payload["target"], "https://example.com")
        self.assertIn("threat_narrative", payload)
        self.assertIn("mitre_breakdown", payload)
        self.assertIn("attack_paths", payload)
        self.assertIn("matrix_coverage", payload)


if __name__ == "__main__":
    unittest.main()
