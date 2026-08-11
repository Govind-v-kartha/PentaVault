"""Unit tests for scanner/modules/ssl_tls.py."""

from __future__ import annotations

import datetime
import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest
import httpx

from scanner.modules.ssl_tls import test_ssl_tls


@pytest.fixture
def mock_httpx_missing_hsts():
    """Mock httpx client returning response without HSTS header."""
    mock_resp = MagicMock()
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_client = MagicMock()
    mock_client.__enter__.return_value.get.return_value = mock_resp
    return mock_client


@pytest.fixture
def mock_httpx_with_hsts():
    """Mock httpx client returning response with HSTS header."""
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }
    mock_client = MagicMock()
    mock_client.__enter__.return_value.get.return_value = mock_resp
    return mock_client


def test_missing_hsts_and_expired_cert(mock_httpx_missing_hsts):
    """Test detection of missing HSTS header and expired certificate."""
    future_past_date = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
    ).strftime("%b %d %H:%M:%S %Y GMT")

    mock_cert = {
        "notAfter": future_past_date,
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"),),
    }

    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = mock_cert
    mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    with patch("httpx.Client", return_value=mock_httpx_missing_hsts), \
         patch("ssl.create_default_context", return_value=mock_ctx), \
         patch("socket.create_connection"):

        findings = test_ssl_tls("https://example.com", quick=True)

        titles = [f["title"] for f in findings]
        assert any("Missing HTTP Strict Transport Security (HSTS)" in t for t in titles)
        assert any("Expired SSL/TLS Certificate" in t for t in titles)


def test_untrusted_self_signed_cert(mock_httpx_with_hsts):
    """Test detection of untrusted / self-signed certificate."""
    mock_ssock_unverified = MagicMock()
    mock_ssock_unverified.getpeercert.return_value = {
        "notAfter": "Dec 31 23:59:59 2030 GMT",
        "subject": ((("commonName", "example.com"),),),
        "subjectAltName": (("DNS", "example.com"),),
    }
    mock_ssock_unverified.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)

    def side_effect_context():
        ctx = MagicMock()
        # First call raises SSLCertVerificationError
        ctx.wrap_socket.side_effect = [
            ssl.SSLCertVerificationError(1, "certificate verify failed"),
            MagicMock(__enter__=MagicMock(return_value=mock_ssock_unverified)),
        ]
        return ctx

    with patch("httpx.Client", return_value=mock_httpx_with_hsts), \
         patch("ssl.create_default_context", side_effect=side_effect_context), \
         patch("socket.create_connection"):

        findings = test_ssl_tls("https://example.com", quick=True)

        titles = [f["title"] for f in findings]
        assert any("Untrusted or Self-Signed SSL/TLS Certificate" in t for t in titles)


def test_hostname_mismatch(mock_httpx_with_hsts):
    """Test detection of hostname mismatch in SSL cert."""
    future_date = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100)
    ).strftime("%b %d %H:%M:%S %Y GMT")

    mock_cert = {
        "notAfter": future_date,
        "subject": ((("commonName", "otherhost.com"),),),
        "subjectAltName": (("DNS", "otherhost.com"),),
    }

    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = mock_cert
    mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3", 256)

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    with patch("httpx.Client", return_value=mock_httpx_with_hsts), \
         patch("ssl.create_default_context", return_value=mock_ctx), \
         patch("socket.create_connection"):

        findings = test_ssl_tls("https://example.com", quick=True)

        titles = [f["title"] for f in findings]
        assert any("Hostname Mismatch" in t for t in titles)


def test_should_stop_cancellation(mock_httpx_missing_hsts):
    """Test should_stop halts execution before socket checks."""
    should_stop = MagicMock(return_value=True)

    findings = test_ssl_tls("https://example.com", should_stop=should_stop, quick=True)

    assert len(findings) == 0
