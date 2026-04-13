import unittest
from unittest.mock import patch

from scanner.utils import ai_engine


class TestAiEnginePromptComposition(unittest.TestCase):
    def test_compose_prompt_includes_shared_sections(self):
        prompt = ai_engine._compose_prompt(
            role="Role text",
            context="Target: https://example.com",
            body="Do something specific.",
            extra_rules=["Extra rule"],
        )

        self.assertIn("Role: Role text", prompt)
        self.assertIn("SCAN CONTEXT:\nTarget: https://example.com", prompt)
        self.assertIn("OUTPUT RULES:", prompt)
        self.assertIn("- Do not use markdown syntax.", prompt)
        self.assertIn("- Extra rule", prompt)
        self.assertIn("TASK:\nDo something specific.", prompt)

    def test_threat_analysis_prompt_uses_composed_style(self):
        scan = {"target": "https://example.com", "mode": "quick"}
        findings = [{"type": "xss", "severity": "High", "detail": "xss", "parameter": "q", "mitre_attack": []}]
        mitre_breakdown = [{"tactic": "Execution", "technique_count": 1}]
        coverage = {"tactics_with_hits": 1, "total_tactics": 14, "total_technique_hits": 1}

        with patch("scanner.utils.ai_engine._call_gemini", return_value="ok") as mocked:
            ai_engine.ai_threat_analysis(["k"], scan, findings, mitre_breakdown, coverage)

        prompt = mocked.call_args.args[1]
        self.assertIn("Role:", prompt)
        self.assertIn("Risk Overview", prompt)
        self.assertIn("Attack Chain Analysis", prompt)
        self.assertNotIn("You are a senior", prompt)

    def test_remediation_prompt_uses_composed_style(self):
        scan = {"target": "https://example.com", "mode": "full"}
        finding = {
            "type": "sqli",
            "severity": "High",
            "detail": "sql marker",
            "parameter": "id",
            "payload": "' OR 1=1--",
            "url": "https://example.com/login",
            "owasp_category": "A03:2025",
            "mitre_attack": [{"technique": "T1190", "name": "Exploit Public-Facing Application"}],
            "recommendation": "Use parameterized queries",
        }

        with patch("scanner.utils.ai_engine._call_gemini", return_value="ok") as mocked:
            ai_engine.ai_remediation(["k"], finding, scan)

        prompt = mocked.call_args.args[1]
        self.assertIn("What's the risk?", prompt)
        self.assertIn("Proper Fix", prompt)
        self.assertIn("Verification", prompt)
        self.assertNotIn("You are a senior", prompt)

    def test_mitre_explain_prompt_includes_user_question(self):
        scan = {"target": "https://example.com", "mode": "full"}
        findings = [{"mitre_attack": [{"technique": "T1190"}], "type": "xss", "severity": "High"}]

        with patch("scanner.utils.ai_engine._call_gemini", return_value="ok") as mocked:
            ai_engine.ai_mitre_explain(
                ["k"],
                "T1190",
                "Exploit Public-Facing Application",
                "Initial Access",
                scan,
                findings,
                "How would this be detected?",
            )

        prompt = mocked.call_args.args[1]
        self.assertIn("USER'S SPECIFIC QUESTION:", prompt)
        self.assertIn("How would this be detected?", prompt)
        self.assertNotIn("You are a senior", prompt)


if __name__ == "__main__":
    unittest.main()
