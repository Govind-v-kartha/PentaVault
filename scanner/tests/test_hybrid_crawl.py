import unittest

from scanner.core.crawler import CrawlResult
from scanner.main import _merge_crawl_results


class TestHybridCrawlMerge(unittest.TestCase):
    def test_merge_crawl_results_deduplicates_and_unions_fields(self):
        primary = CrawlResult()
        primary.endpoints = ["https://example.com/", "https://example.com/a"]
        primary.forms = [{"action": "https://example.com/form-a", "method": "POST", "inputs": []}]
        primary.parameters = {"id", "q"}
        primary.js_api_endpoints = ["https://example.com/api/a"]
        primary.authenticated_pages = ["https://example.com/admin"]

        fallback = CrawlResult()
        fallback.endpoints = ["https://example.com/a", "https://example.com/b"]
        fallback.forms = [{"action": "https://example.com/form-b", "method": "POST", "inputs": []}]
        fallback.parameters = {"token"}
        fallback.js_api_endpoints = ["https://example.com/api/a", "https://example.com/api/b"]
        fallback.authenticated_pages = ["https://example.com/admin", "https://example.com/profile"]

        merged = _merge_crawl_results(primary, fallback)

        self.assertEqual(
            merged.endpoints,
            ["https://example.com/", "https://example.com/a", "https://example.com/b"],
        )
        self.assertEqual(len(merged.forms), 2)
        self.assertEqual(merged.parameters, {"id", "q", "token"})
        self.assertEqual(
            merged.js_api_endpoints,
            ["https://example.com/api/a", "https://example.com/api/b"],
        )
        self.assertEqual(
            merged.authenticated_pages,
            ["https://example.com/admin", "https://example.com/profile"],
        )


if __name__ == "__main__":
    unittest.main()
