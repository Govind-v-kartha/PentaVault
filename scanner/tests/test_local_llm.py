import os
import unittest
from unittest.mock import Mock, patch

import httpx

from scanner.utils import ai_engine


class TestLocalLlmIntegration(unittest.TestCase):
    def setUp(self):
        ai_engine._KEY_POOL = ai_engine._GeminiKeyPool()

    def test_call_ollama_success(self):
        fake_response = Mock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {"response": "Ollama generated analysis"}

        with patch("scanner.utils.ai_engine.httpx.post", return_value=fake_response) as mock_post:
            res = ai_engine._call_ollama("test prompt")
            self.assertEqual(res, "Ollama generated analysis")
            self.assertIn("/api/generate", mock_post.call_args.args[0])

    def test_call_openai_compatible_success(self):
        fake_response = Mock()
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "choices": [{"message": {"content": "LocalAI generated analysis"}}]
        }

        with patch("scanner.utils.ai_engine.httpx.post", return_value=fake_response) as mock_post:
            res = ai_engine._call_openai_compatible("test prompt")
            self.assertEqual(res, "LocalAI generated analysis")
            self.assertIn("/chat/completions", mock_post.call_args.args[0])

    def test_call_ai_auto_fallback_to_ollama_on_gemini_failure(self):
        req = httpx.Request("POST", "https://example.com")
        gemini_429 = Mock()
        gemini_429.raise_for_status.side_effect = httpx.HTTPStatusError(
            "rate limited",
            request=req,
            response=httpx.Response(status_code=429, request=req),
        )

        ollama_resp = Mock()
        ollama_resp.raise_for_status.return_value = None
        ollama_resp.json.return_value = {"response": "Fallback Ollama response"}

        with patch.dict(os.environ, {"PENTAVAULT_AI_PROVIDER": "auto"}):
            with patch("scanner.utils.ai_engine.httpx.post", side_effect=[gemini_429, ollama_resp]) as mock_post:
                res = ai_engine._call_ai("gemini-key", "test prompt")
                self.assertEqual(res, "Fallback Ollama response")
                self.assertEqual(mock_post.call_count, 2)

    def test_call_ai_direct_ollama_provider(self):
        ollama_resp = Mock()
        ollama_resp.raise_for_status.return_value = None
        ollama_resp.json.return_value = {"response": "Direct Ollama response"}

        with patch.dict(os.environ, {"PENTAVAULT_AI_PROVIDER": "ollama"}):
            with patch("scanner.utils.ai_engine.httpx.post", return_value=ollama_resp) as mock_post:
                res = ai_engine._call_ai("", "test prompt")
                self.assertEqual(res, "Direct Ollama response")
                self.assertIn("11434", mock_post.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
