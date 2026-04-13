import os
import time
import unittest
from unittest.mock import Mock, patch

import httpx

from scanner.utils import ai_engine


class TestAiEngineConfigAndFallback(unittest.TestCase):
    def setUp(self):
        ai_engine._KEY_POOL = ai_engine._GeminiKeyPool()

    def _state_for(self, key: str):
        for state in ai_engine._KEY_POOL._states:
            if state.key == key:
                return state
        return None

    def test_load_gemini_api_keys_from_csv(self):
        with patch.dict(os.environ, {"PENTAVAULT_GEMINI_API_KEYS": "k1, k2 , ,k3", "GEMINI_API_KEY": "single"}, clear=False):
            self.assertEqual(ai_engine.load_gemini_api_keys(), ["k1", "k2", "k3"])

    def test_load_gemini_api_keys_single_fallback(self):
        with patch.dict(os.environ, {"PENTAVAULT_GEMINI_API_KEYS": "", "GEMINI_API_KEY": "single-key"}, clear=False):
            self.assertEqual(ai_engine.load_gemini_api_keys(), ["single-key"])

    def test_load_gemini_models_override(self):
        with patch.dict(os.environ, {"PENTAVAULT_GEMINI_MODELS": "gemini-2.0-flash, gemini-1.5-flash"}, clear=False):
            self.assertEqual(ai_engine.load_gemini_models(), ["gemini-2.0-flash", "gemini-1.5-flash"])

    def test_call_gemini_rotates_on_retryable_status(self):
        req = httpx.Request("POST", "https://example.com")
        first_response = httpx.Response(status_code=404, request=req)

        failing = Mock()
        failing.raise_for_status.side_effect = httpx.HTTPStatusError(
            "model not found",
            request=req,
            response=first_response,
        )

        succeeding = Mock()
        succeeding.raise_for_status.return_value = None
        succeeding.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}]
        }

        with patch("scanner.utils.ai_engine.httpx.post", side_effect=[failing, succeeding]) as mock_post, patch(
            "scanner.utils.ai_engine.load_gemini_models",
            return_value=["gemini-bad", "gemini-good"],
        ):
            result = ai_engine._call_gemini("testkey123456", "prompt")

        self.assertEqual(result, "ok")
        self.assertEqual(mock_post.call_count, 2)
        self.assertIn("gemini-bad", mock_post.call_args_list[0].args[0])
        self.assertIn("gemini-good", mock_post.call_args_list[1].args[0])

    def test_call_gemini_raises_when_no_key(self):
        with self.assertRaises(RuntimeError):
            ai_engine._call_gemini([], "prompt")

    def test_call_gemini_round_robin_across_requests(self):
        req = httpx.Request("POST", "https://example.com")

        def make_success(text: str):
            response = Mock()
            response.raise_for_status.return_value = None
            response.json.return_value = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
            return response

        with patch("scanner.utils.ai_engine.load_gemini_models", return_value=["gemini-2.0-flash"]), patch(
            "scanner.utils.ai_engine.httpx.post",
            side_effect=[make_success("first"), make_success("second")],
        ) as mock_post:
            first = ai_engine._call_gemini(["k1", "k2"], "prompt")
            second = ai_engine._call_gemini(["k1", "k2"], "prompt")

        self.assertEqual(first, "first")
        self.assertEqual(second, "second")
        self.assertEqual(mock_post.call_count, 2)
        self.assertEqual(mock_post.call_args_list[0].kwargs["params"]["key"], "k1")
        self.assertEqual(mock_post.call_args_list[1].kwargs["params"]["key"], "k2")

    def test_call_gemini_marks_unauthorized_key_disabled(self):
        req = httpx.Request("POST", "https://example.com")

        unauthorized = Mock()
        unauthorized.raise_for_status.side_effect = httpx.HTTPStatusError(
            "unauthorized",
            request=req,
            response=httpx.Response(status_code=401, request=req),
        )

        ok = Mock()
        ok.raise_for_status.return_value = None
        ok.json.return_value = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}

        with patch("scanner.utils.ai_engine.load_gemini_models", return_value=["gemini-2.0-flash"]), patch(
            "scanner.utils.ai_engine.httpx.post",
            side_effect=[unauthorized, ok],
        ):
            result = ai_engine._call_gemini(["bad-key", "good-key"], "prompt")

        self.assertEqual(result, "ok")
        bad_state = self._state_for("bad-key")
        self.assertIsNotNone(bad_state)
        self.assertTrue(bad_state.disabled)

    def test_call_gemini_applies_cooldown_on_rate_limit(self):
        req = httpx.Request("POST", "https://example.com")

        rate_limited = Mock()
        rate_limited.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited",
            request=req,
            response=httpx.Response(status_code=429, request=req),
        )

        ok = Mock()
        ok.raise_for_status.return_value = None
        ok.json.return_value = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}

        with patch("scanner.utils.ai_engine.load_gemini_models", return_value=["gemini-2.0-flash"]), patch(
            "scanner.utils.ai_engine.httpx.post",
            side_effect=[rate_limited, ok],
        ):
            result = ai_engine._call_gemini(["k1", "k2"], "prompt")

        self.assertEqual(result, "ok")
        k1_state = self._state_for("k1")
        self.assertIsNotNone(k1_state)
        self.assertGreater(k1_state.cooldown_until, time.time())

    def test_call_gemini_skips_key_in_cooldown_on_next_request(self):
        req = httpx.Request("POST", "https://example.com")

        rate_limited = Mock()
        rate_limited.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited",
            request=req,
            response=httpx.Response(status_code=429, request=req),
        )

        ok_one = Mock()
        ok_one.raise_for_status.return_value = None
        ok_one.json.return_value = {"candidates": [{"content": {"parts": [{"text": "first"}]}}]}

        ok_two = Mock()
        ok_two.raise_for_status.return_value = None
        ok_two.json.return_value = {"candidates": [{"content": {"parts": [{"text": "second"}]}}]}

        with patch("scanner.utils.ai_engine.load_gemini_models", return_value=["gemini-2.0-flash"]), patch(
            "scanner.utils.ai_engine.httpx.post",
            side_effect=[rate_limited, ok_one, ok_two],
        ) as mock_post:
            first = ai_engine._call_gemini(["k1", "k2"], "prompt")
            second = ai_engine._call_gemini(["k1", "k2"], "prompt")

        self.assertEqual(first, "first")
        self.assertEqual(second, "second")
        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual(mock_post.call_args_list[0].kwargs["params"]["key"], "k1")
        self.assertEqual(mock_post.call_args_list[1].kwargs["params"]["key"], "k2")
        self.assertEqual(mock_post.call_args_list[2].kwargs["params"]["key"], "k2")

    def test_call_gemini_reuses_key_after_cooldown_expires(self):
        req = httpx.Request("POST", "https://example.com")

        rate_limited = Mock()
        rate_limited.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited",
            request=req,
            response=httpx.Response(status_code=429, request=req),
        )

        ok_a = Mock()
        ok_a.raise_for_status.return_value = None
        ok_a.json.return_value = {"candidates": [{"content": {"parts": [{"text": "a"}]}}]}

        ok_b = Mock()
        ok_b.raise_for_status.return_value = None
        ok_b.json.return_value = {"candidates": [{"content": {"parts": [{"text": "b"}]}}]}

        ok_c = Mock()
        ok_c.raise_for_status.return_value = None
        ok_c.json.return_value = {"candidates": [{"content": {"parts": [{"text": "c"}]}}]}

        with patch("scanner.utils.ai_engine.load_gemini_models", return_value=["gemini-2.0-flash"]), patch(
            "scanner.utils.ai_engine.httpx.post",
            side_effect=[rate_limited, ok_a, ok_b, ok_c],
        ) as mock_post:
            first = ai_engine._call_gemini(["k1", "k2"], "prompt")
            second = ai_engine._call_gemini(["k1", "k2"], "prompt")
            state = self._state_for("k1")
            self.assertIsNotNone(state)
            state.cooldown_until = time.time() - 1
            third = ai_engine._call_gemini(["k1", "k2"], "prompt")

        self.assertEqual(first, "a")
        self.assertEqual(second, "b")
        self.assertEqual(third, "c")
        self.assertEqual(mock_post.call_count, 4)
        self.assertEqual(mock_post.call_args_list[0].kwargs["params"]["key"], "k1")
        self.assertEqual(mock_post.call_args_list[1].kwargs["params"]["key"], "k2")
        self.assertEqual(mock_post.call_args_list[2].kwargs["params"]["key"], "k2")
        self.assertEqual(mock_post.call_args_list[3].kwargs["params"]["key"], "k1")

    def test_public_prompt_functions_use_expected_token_limits(self):
        scan = {"target": "https://example.com", "mode": "quick"}
        findings = [{"type": "xss", "severity": "High", "detail": "x", "parameter": "q", "mitre_attack": []}]
        mitre_breakdown = [{"tactic": "Execution", "technique_count": 1}]
        coverage = {"tactics_with_hits": 1, "total_tactics": 14, "total_technique_hits": 1}
        finding = {
            "type": "sqli",
            "severity": "High",
            "detail": "sql",
            "parameter": "id",
            "payload": "' OR 1=1--",
            "url": "https://example.com/login",
            "mitre_attack": [],
        }

        with patch("scanner.utils.ai_engine._call_gemini", return_value="ok") as mocked:
            ai_engine.ai_threat_analysis(["k"], scan, findings, mitre_breakdown, coverage)
            ai_engine.ai_remediation(["k"], finding, scan)
            ai_engine.ai_mitre_explain(["k"], "T1190", "Exploit Public-Facing Application", "Initial Access", scan, findings)
            ai_engine.ai_executive_summary(["k"], scan, findings)

        token_limits = [call.kwargs.get("max_tokens") for call in mocked.call_args_list]
        self.assertEqual(token_limits, [4096, 2048, 4096, 2048])


if __name__ == "__main__":
    unittest.main()
