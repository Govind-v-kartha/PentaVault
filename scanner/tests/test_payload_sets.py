import unittest

from scanner.modules import (
    command_injection,
    cors_misconfig,
    crlf_injection,
    csv_formula_injection,
    graphql_abuse,
    host_header,
    hpp,
    jwt_checks,
    lfi,
    nosqli,
    open_redirect,
    prototype_pollution,
    request_smuggling,
    sensitive_files,
    mass_assignment,
    insecure_deserialization,
    sqli,
    sqli_selenium,
    ssrf,
    ssti,
    xss,
    xss_selenium,
    xxe,
)


class TestPayloadSets(unittest.TestCase):
    def test_sqli_payload_sets_expanded(self):
        self.assertGreaterEqual(len(sqli.ERROR_PAYLOADS), 32)
        self.assertGreaterEqual(len(sqli.ERROR_PAYLOADS_QUICK), 10)
        self.assertGreaterEqual(len(sqli.TIME_PAYLOADS), 20)
        self.assertGreaterEqual(len(sqli.BOOLEAN_PAYLOADS), 24)
        self.assertGreaterEqual(len(sqli.BOOLEAN_PAYLOADS_QUICK), 8)

    def test_sqli_selenium_payload_sets_expanded(self):
        self.assertGreaterEqual(len(sqli_selenium.PAYLOADS_QUICK), 8)
        self.assertGreaterEqual(len(sqli_selenium.PAYLOADS_FULL), 14)

    def test_xss_payload_sets_expanded(self):
        self.assertGreaterEqual(len(xss.REFLECTED_PAYLOADS), 18)
        self.assertGreaterEqual(len(xss.ENCODED_PAYLOADS), 10)
        self.assertGreaterEqual(len(xss_selenium.PAYLOADS), 16)
        self.assertGreaterEqual(len(xss_selenium.WAF_BYPASS_PAYLOADS), 10)

    def test_ssrf_payload_sets_expanded(self):
        self.assertGreaterEqual(len(ssrf.INTERNAL_URLS), 24)
        self.assertGreaterEqual(len(ssrf.CLOUD_METADATA_URLS), 14)

    def test_open_redirect_payload_sets_expanded(self):
        self.assertGreaterEqual(len(open_redirect._REDIRECT_PAYLOADS), 18)

    def test_command_injection_payload_sets_expanded(self):
        self.assertGreaterEqual(len(command_injection._PAYLOADS), 18)

    def test_xxe_payload_sets_expanded(self):
        self.assertGreaterEqual(len(xxe._XXE_PAYLOADS), 10)

    def test_lfi_payload_sets_expanded(self):
        self.assertGreaterEqual(len(lfi._PAYLOADS), 15)

    def test_sensitive_files_paths_expanded(self):
        self.assertGreaterEqual(len(sensitive_files._COMMON_PATHS), 12)

    def test_nosqli_payload_sets_expanded(self):
        self.assertGreaterEqual(len(nosqli._BOOLEAN_PAYLOADS), 6)
        self.assertGreaterEqual(len(nosqli._ERROR_PAYLOADS), 7)

    def test_ssti_payload_sets_expanded(self):
        self.assertGreaterEqual(len(ssti._PAYLOAD_MARKERS), 12)

    def test_graphql_payload_sets_expanded(self):
        self.assertGreaterEqual(len(graphql_abuse._GRAPHQL_PATHS), 3)

    def test_host_header_payload_sets_expanded(self):
        self.assertGreaterEqual(len(host_header._HOST_PAYLOADS), 3)

    def test_cors_payload_sets_expanded(self):
        self.assertGreaterEqual(len(cors_misconfig._ORIGIN_PAYLOADS), 3)

    def test_hpp_payload_sets_expanded(self):
        self.assertGreaterEqual(len(hpp._PAYLOADS), 3)

    def test_crlf_payload_sets_expanded(self):
        self.assertGreaterEqual(len(crlf_injection._PAYLOADS), 3)

    def test_jwt_module_token_extractor_exists(self):
        self.assertTrue(callable(jwt_checks._extract_jwt_candidates))

    def test_request_smuggling_module_entrypoint_exists(self):
        self.assertTrue(callable(request_smuggling.test_request_smuggling))

    def test_mass_assignment_payload_set_expanded(self):
        self.assertGreaterEqual(len(mass_assignment._SENSITIVE_FIELDS), 15)

    def test_insecure_deserialization_payload_set_expanded(self):
        self.assertGreaterEqual(len(insecure_deserialization._SERIALIZED_PAYLOADS), 4)

    def test_prototype_pollution_payload_set_expanded(self):
        self.assertGreaterEqual(len(prototype_pollution._QUERY_PROBES), 5)

    def test_csv_formula_payload_set_expanded(self):
        self.assertGreaterEqual(len(csv_formula_injection._FORMULA_PAYLOADS), 6)


if __name__ == "__main__":
    unittest.main()
