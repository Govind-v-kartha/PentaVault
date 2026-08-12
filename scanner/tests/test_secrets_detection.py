"""Unit tests for Secrets Detection module (scanner/modules/secrets_detection.py)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import httpx

from scanner.core.crawler import CrawlResult
from scanner.modules.secrets_detection import redact_secret, test_secrets_detection


def test_redact_secret_helper():
    """Verify redaction masks mid/full credentials to prevent leaking live secrets."""
    # Short secret <= 8 chars
    assert redact_secret("secret12") == "********"

    # Long secret >= 12 chars
    redacted = redact_secret("AKIAIOSFODNN7EXAMPLE")
    assert redacted == "AKIAIO...MPLE"
    assert "EXAMPLE" not in redacted

    # GitHub token
    gh_redacted = redact_secret("ghp_1234567890abcdefghijklmnopqrstuv")
    assert gh_redacted.startswith("ghp_12...")
    assert gh_redacted.endswith("stuv")
    assert "1234567890" not in gh_redacted


def test_secrets_detection_positive_matches():
    """Verify detection of hardcoded AWS, Google, GitHub, and private key secrets."""
    crawl_res = CrawlResult()
    crawl_res.page_sources["https://example.com/app"] = """
    <html>
        <script>
            const awsKey = "AKIA1234567890ABCDEF";
            const googleKey = "AIzaSyAf8dNCOe8DC9Wu2gopEfcFGNq4IgYODv8";
            const privateKey = "-----BEGIN RSA PRIVATE KEY-----";
        </script>
    </html>
    """

    findings = test_secrets_detection(crawl_res)
    assert len(findings) == 3

    types = [f["title"] for f in findings]
    assert "Exposed AWS Access Key in Client Code" in types
    assert "Exposed Google API Key in Client Code" in types
    assert "Exposed Generic Private Key Header in Client Code" in types

    # Assert secrets are redacted in evidence and payload and schema keys exist
    for f in findings:
        assert "AKIA1234567890ABCDEF" not in f["evidence"]
        assert "AIzaSyAf8dNCOe8DC9Wu2gopEfcFGNq4IgYODv8" not in f["evidence"]
        assert f["parameter"] == "N/A"
        assert f["owasp_category"] == "A02:2025 - Security Misconfiguration"
        assert "cvss_vector" in f and f["cvss_vector"].startswith("AV:N")
        assert "mitre_attack" in f
        assert f["mitre_attack"][0]["technique"] == "T1552.001"



def test_secrets_detection_deduplication():
    """Verify duplicate secrets across multiple pages are collapsed into a single finding."""
    crawl_res = CrawlResult()
    secret = "AKIA9876543210ZYXWVU"
    crawl_res.page_sources["https://example.com/page1"] = f"var key = '{secret}';"
    crawl_res.page_sources["https://example.com/page2"] = f"var key = '{secret}';"
    crawl_res.page_sources["https://example.com/page3"] = f"var key = '{secret}';"

    findings = test_secrets_detection(crawl_res)
    assert len(findings) == 1
    assert findings[0]["affected_url"] == "https://example.com/page1"


def test_secrets_detection_quick_mode_skips_js_files():
    """Verify quick=True skips fetching separate JS files."""
    crawl_res = CrawlResult()
    crawl_res.page_sources["https://example.com/"] = "<html><body>Home</body></html>"
    crawl_res.js_files = ["https://example.com/static/bundle.js"]

    mock_client = MagicMock()

    with patch("httpx.Client", return_value=mock_client):
        findings = test_secrets_detection(crawl_res, quick=True)
        assert len(findings) == 0
        # Ensure client was never called in quick mode
        mock_client.__enter__.return_value.get.assert_not_called()


def test_secrets_detection_full_mode_scans_js_files():
    """Verify quick=False fetches and scans external JS files."""
    crawl_res = CrawlResult()
    crawl_res.page_sources["https://example.com/"] = "<html><body>Home</body></html>"
    crawl_res.js_files = ["https://example.com/static/bundle.js"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = 'const stripe = "sk_live_' + ('0' * 24) + '";'


    mock_client = MagicMock()
    mock_client.__enter__.return_value.get.return_value = mock_resp

    with patch("httpx.Client", return_value=mock_client):
        findings = test_secrets_detection(crawl_res, quick=False)
        assert len(findings) == 1
        assert "Stripe API Key" in findings[0]["title"]
        assert findings[0]["affected_url"] == "https://example.com/static/bundle.js"


def test_secrets_detection_should_stop_cancellation():
    """Verify should_stop halts processing immediately."""
    crawl_res = CrawlResult()
    crawl_res.page_sources["https://example.com/"] = "const key = 'AKIA1234567890ABCDEF';"

    should_stop = MagicMock(return_value=True)
    findings = test_secrets_detection(crawl_res, should_stop=should_stop)
    assert len(findings) == 0
