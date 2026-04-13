import unittest

from scanner.core import fingerprint


class TestFingerprintRobustness(unittest.TestCase):
    def test_parse_not_after_supports_multiple_formats(self):
        parsed_compact = fingerprint._parse_not_after("20260412010203Z")
        parsed_iso = fingerprint._parse_not_after("2026-04-12T01:02:03Z")

        self.assertIsNotNone(parsed_compact)
        self.assertIsNotNone(parsed_iso)
        self.assertEqual(parsed_compact.year, 2026)
        self.assertEqual(parsed_iso.year, 2026)

    def test_parse_not_after_returns_none_for_unknown_format(self):
        self.assertIsNone(fingerprint._parse_not_after("12/04/2026 01:02:03"))

    def test_framework_signatures_avoid_generic_false_positives(self):
        body = "This dashboard has reactive updates and angular momentum widgets."
        techs = fingerprint._match_signatures({}, body, fingerprint._TECH_SIGNATURES)

        self.assertNotIn("React", techs)
        self.assertNotIn("Angular", techs)

    def test_framework_signatures_detect_real_artifacts(self):
        body = (
            '<script src="/static/js/react.production.min.js"></script>'
            '<script src="/assets/vue.runtime.global.js"></script>'
            '<div ng-version="16.2.0"></div>'
        )
        techs = fingerprint._match_signatures({}, body, fingerprint._TECH_SIGNATURES)

        self.assertIn("React", techs)
        self.assertIn("Vue.js", techs)
        self.assertIn("Angular", techs)


if __name__ == "__main__":
    unittest.main()
