import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from scanner.modules import sqli


class _Resp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


class _BooleanClient:
    def __init__(self, baseline: str, true_text: str, false_text: str):
        self.baseline = baseline
        self.true_text = true_text
        self.false_text = false_text

    def get(self, url: str):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        payload = None
        if qs:
            payload = next(iter(qs.values()))[0]

        if payload in {"' OR 1=1--", "' AND 1=1--"}:
            return _Resp(self.true_text)
        if payload in {"' OR 1=2--", "' AND 1=2--"}:
            return _Resp(self.false_text)
        return _Resp(self.baseline)


class _NoopClient:
    def get(self, url: str):
        return _Resp("ok")


class TestSqliHeuristics(unittest.TestCase):
    def test_boolean_guard_rejects_small_response_jitter(self):
        baseline = "A" * 2000
        true_text = baseline + ("B" * 40)
        false_text = baseline + ("C" * 50)
        client = _BooleanClient(baseline, true_text, false_text)

        finding = sqli._check_boolean_based(client, "https://example.com/search?id=1", "id")
        self.assertIsNone(finding)

    def test_boolean_detection_accepts_clear_true_false_signal(self):
        baseline = "Welcome user list\n" * 80
        true_text = baseline + ("extra row\n" * 60)
        false_text = "No records found"
        client = _BooleanClient(baseline, true_text, false_text)

        finding = sqli._check_boolean_based(client, "https://example.com/search?id=1", "id")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["type"], "boolean-based blind")

    def test_time_based_guard_rejects_small_latency_spike(self):
        client = _NoopClient()
        with patch.object(sqli, "TIME_PAYLOADS", [("' OR SLEEP(5)--", 5)]), patch(
            "scanner.modules.sqli._measure_baseline_latency",
            return_value=(0.2, 0.05),
        ), patch("scanner.modules.sqli.time.monotonic", side_effect=[0.0, 0.7]):
            finding = sqli._check_time_based(client, "https://example.com/api?id=1", "id")

        self.assertIsNone(finding)

    def test_time_based_detection_requires_delay_above_baseline_and_jitter(self):
        client = _NoopClient()
        with patch.object(sqli, "TIME_PAYLOADS", [("' OR SLEEP(5)--", 5)]), patch(
            "scanner.modules.sqli._measure_baseline_latency",
            return_value=(0.2, 0.05),
        ), patch("scanner.modules.sqli.time.monotonic", side_effect=[0.0, 4.6]):
            finding = sqli._check_time_based(client, "https://example.com/api?id=1", "id")

        self.assertIsNotNone(finding)
        self.assertEqual(finding["type"], "time-based blind")


if __name__ == "__main__":
    unittest.main()
