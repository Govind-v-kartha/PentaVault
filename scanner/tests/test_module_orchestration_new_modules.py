import unittest
from contextlib import ExitStack
from unittest.mock import patch

import scanner.main as cli_main
from scanner.web import app as web_app


class TestCliModuleOrchestration(unittest.TestCase):
    def test_run_web_modules_includes_all_advanced_modules(self):
        endpoints = ["https://example.com/search?q=1"]
        forms = []

        patch_specs = [
            ("scanner.main.test_sqli", [{"title": "sqli"}]),
            ("scanner.main.test_xss", [{"title": "xss"}]),
            ("scanner.main.test_headers", [{"title": "headers"}]),
            ("scanner.main.test_ssrf", [{"title": "ssrf"}]),
            ("scanner.main.test_idor", [{"title": "idor"}]),
            ("scanner.main.test_open_redirect", [{"title": "open_redirect"}]),
            ("scanner.main.test_command_injection", [{"title": "cmdi"}]),
            ("scanner.main.test_xxe", [{"title": "xxe"}]),
            ("scanner.main.test_lfi", [{"title": "lfi"}]),
            ("scanner.main.test_sensitive_files", [{"title": "sensitive_files"}]),
            ("scanner.main.test_nosqli", [{"title": "nosqli"}]),
            ("scanner.main.test_ssti", [{"title": "ssti"}]),
            ("scanner.main.test_graphql_abuse", [{"title": "graphql"}]),
            ("scanner.main.test_jwt_checks", [{"title": "jwt"}]),
            ("scanner.main.test_host_header_injection", [{"title": "host_header"}]),
            ("scanner.main.test_cors_misconfig", [{"title": "cors"}]),
            ("scanner.main.test_hpp", [{"title": "hpp"}]),
            ("scanner.main.test_crlf_injection", [{"title": "crlf"}]),
            ("scanner.main.test_request_smuggling", [{"title": "request_smuggling"}]),
            ("scanner.main.test_mass_assignment_bola", [{"title": "mass_assignment"}]),
            ("scanner.main.test_insecure_deserialization", [{"title": "insecure_deserialization"}]),
            ("scanner.main.test_prototype_pollution", [{"title": "prototype_pollution"}]),
            ("scanner.main.test_csv_formula_injection", [{"title": "csv_formula"}]),
            ("scanner.main.test_ssl_tls", [{"title": "ssl_tls"}]),
            ("scanner.main.test_cloud_misconfig", [{"title": "cloud_misconfig"}]),
        ]

        with ExitStack() as stack:
            for target, result in patch_specs:
                stack.enter_context(patch(target, return_value=result))

            findings = cli_main._run_web_modules(
                endpoints=endpoints,
                forms=forms,
                base_url="https://example.com",
                waf_detected=False,
                cookie=None,
                timeout=5.0,
                threads=4,
                quick=True,
                use_browser=False,
            )

        titles = {f.get("title") for f in findings}
        expected = {
            "sqli",
            "xss",
            "headers",
            "ssrf",
            "idor",
            "open_redirect",
            "cmdi",
            "xxe",
            "lfi",
            "sensitive_files",
            "nosqli",
            "ssti",
            "graphql",
            "jwt",
            "host_header",
            "cors",
            "hpp",
            "crlf",
            "request_smuggling",
            "mass_assignment",
            "insecure_deserialization",
            "prototype_pollution",
            "csv_formula",
            "ssl_tls",
            "cloud_misconfig",
        }
        self.assertTrue(expected.issubset(titles))


class TestWebModuleOrchestration(unittest.TestCase):
    def test_web_modules_list_contains_all_advanced_modules(self):
        file_path = web_app.__file__
        self.assertIsNotNone(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        required_entries = [
            '("Command Injection", lambda: test_command_injection',
            '("XXE", lambda: test_xxe',
            '("LFI", lambda: test_lfi',
            '("Sensitive Files", lambda: test_sensitive_files',
            '("NoSQLi", lambda: test_nosqli',
            '("SSTI", lambda: test_ssti',
            '("GraphQL Abuse", lambda: test_graphql_abuse',
            '("JWT Checks", lambda: test_jwt_checks',
            '("Host Header Injection", lambda: test_host_header_injection',
            '("CORS Misconfiguration", lambda: test_cors_misconfig',
            '("HTTP Parameter Pollution", lambda: test_hpp',
            '("CRLF Injection", lambda: test_crlf_injection',
            '("Request Smuggling", lambda: test_request_smuggling',
            '("Mass Assignment/BOLA", lambda: test_mass_assignment_bola',
            '("Insecure Deserialization", lambda: test_insecure_deserialization',
            '("Prototype Pollution", lambda: test_prototype_pollution',
            '("CSV/Formula Injection", lambda: test_csv_formula_injection',
            '("SSL/TLS Analysis", lambda: test_ssl_tls',
            '("Cloud Misconfiguration", lambda: test_cloud_misconfig',
        ]
        for entry in required_entries:
            self.assertIn(entry, source)



if __name__ == "__main__":
    unittest.main()
