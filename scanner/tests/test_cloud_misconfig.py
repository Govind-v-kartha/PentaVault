"""Unit tests for the Cloud Misconfiguration module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock
import pytest
import httpx

from scanner.core.crawler import CrawlResult
from scanner.modules.cloud_misconfig import test_cloud_misconfig, _derive_bucket_candidates
from scanner.modules.ssrf import CLOUD_METADATA_URLS


def test_ssrf_metadata_urls_reused():
    """Verify that CLOUD_METADATA_URLS is imported from ssrf.py rather than redefined."""
    import scanner.modules.cloud_misconfig as cm
    assert hasattr(cm, "CLOUD_METADATA_URLS")
    assert cm.CLOUD_METADATA_URLS is CLOUD_METADATA_URLS
    assert len(CLOUD_METADATA_URLS) >= 14


def test_derive_bucket_candidates():
    """Verify bucket name candidates generation for quick vs full mode."""
    quick_candidates = _derive_bucket_candidates("https://sub.example.com", quick=True)
    assert "sub" in quick_candidates
    assert "sub-example-com" in quick_candidates
    assert "sub.example.com" in quick_candidates
    assert len(quick_candidates) == 3

    full_candidates = _derive_bucket_candidates("https://example.com", quick=False)
    assert "example-assets" in full_candidates
    assert "example-backup" in full_candidates
    assert len(full_candidates) > 3


def test_public_readable_bucket_listing():
    """Verify HTTP 200 with bucket listing generates a High severity finding."""
    def mock_get(url, **kwargs):
        if "example.s3.amazonaws.com" in url:
            return MagicMock(
                status_code=200,
                text="<ListBucketResult><Name>example</Name><Contents><Key>secret.pdf</Key></Contents></ListBucketResult>",
            )
        return MagicMock(status_code=404, text="NoSuchBucket")

    with patch("httpx.Client.get", side_effect=mock_get):
        findings = test_cloud_misconfig("https://example.com", quick=True)

    high_findings = [f for f in findings if f["severity"] == "High"]
    assert len(high_findings) == 1
    f = high_findings[0]
    assert f["title"] == "Publicly Readable Cloud Storage Bucket"
    assert f["owasp_category"] == "A02:2025 - Security Misconfiguration"
    assert f["mitre_attack"][0]["technique"] == "T1530"


def test_bucket_access_denied():
    """Verify HTTP 403 AccessDenied generates a Low severity finding."""
    def mock_get(url, **kwargs):
        if "example.s3.amazonaws.com" in url:
            return MagicMock(
                status_code=403,
                text="<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
            )
        return MagicMock(status_code=404, text="NoSuchBucket")

    with patch("httpx.Client.get", side_effect=mock_get):
        findings = test_cloud_misconfig("https://example.com", quick=True)

    low_findings = [f for f in findings if f["severity"] == "Low"]
    assert len(low_findings) == 1
    f = low_findings[0]
    assert f["title"] == "Existing Cloud Storage Bucket (Access Denied)"
    assert f["owasp_category"] == "A02:2025 - Security Misconfiguration"


def test_bucket_not_found():
    """Verify HTTP 404 responses generate no findings."""
    def mock_get(url, **kwargs):
        return MagicMock(status_code=404, text="NoSuchBucket")

    with patch("httpx.Client.get", side_effect=mock_get):
        findings = test_cloud_misconfig("https://nonexistent-target-999.com", quick=True)

    assert len(findings) == 0


def test_cloud_metadata_leak_in_crawl_result():
    """Verify leaking instance metadata markers in page source yields a Critical finding."""
    crawl_res = CrawlResult()
    crawl_res.page_sources = {
        "https://example.com/debug": "<html>AWS Config: ami-1234567890abcdef instance loaded</html>",
    }

    def mock_get(url, **kwargs):
        return MagicMock(status_code=404, text="")

    with patch("httpx.Client.get", side_effect=mock_get):
        findings = test_cloud_misconfig("https://example.com", crawl_result=crawl_res, quick=True)

    crit_findings = [f for f in findings if f["severity"] == "Critical"]
    assert len(crit_findings) == 1
    f = crit_findings[0]
    assert f["title"] == "Leaked Cloud Instance Metadata (AWS AMI ID) in Response"
    assert f["mitre_attack"][0]["technique"] == "T1552.005"


def test_cloud_misconfig_should_stop():
    """Verify should_stop checkpoint cancels execution early."""
    stop_flag = False

    def mock_get(url, **kwargs):
        nonlocal stop_flag
        stop_flag = True
        return MagicMock(status_code=404, text="")

    with patch("httpx.Client.get", side_effect=mock_get):
        findings = test_cloud_misconfig("https://example.com", should_stop=lambda: stop_flag, quick=False)

    assert len(findings) == 0
