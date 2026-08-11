"""Unit tests for subdomain takeover detection in scanner/core/recon.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import dns.resolver
import httpx

from scanner.core.recon import check_subdomain_takeover


def test_subdomain_takeover_positive():
    """Test detection when CNAME matches vulnerable pattern and HTTP response contains unclaimed fingerprint."""
    mock_rdata = MagicMock()
    mock_rdata.to_text.return_value = "myapp.herokuapp.com."

    def fake_resolve(qname, rtype):
        if rtype == "CNAME" and qname == "app.example.com":
            return [mock_rdata]
        raise dns.resolver.NoAnswer()

    mock_resp = MagicMock()
    mock_resp.text = "<html><body><h1>No such app</h1></body></html>"
    mock_client = MagicMock()
    mock_client.__enter__.return_value.get.return_value = mock_resp

    with patch("dns.resolver.resolve", side_effect=fake_resolve), \
         patch("httpx.Client", return_value=mock_client):

        findings = check_subdomain_takeover(["app.example.com"])

        assert len(findings) == 1
        f = findings[0]
        assert "Subdomain Takeover Vulnerability" in f["title"]
        assert f["severity"] == "High"
        assert f["payload"] == "myapp.herokuapp.com"
        assert "mitre_attack" in f
        assert f["mitre_attack"][0]["technique"] == "T1584.001"



def test_subdomain_takeover_negative_claimed_resource():
    """Test no finding reported if CNAME matches but resource is actively claimed (fingerprint absent)."""
    mock_rdata = MagicMock()
    mock_rdata.to_text.return_value = "myapp.herokuapp.com."

    def fake_resolve(qname, rtype):
        if rtype == "CNAME" and qname == "app.example.com":
            return [mock_rdata]
        raise dns.resolver.NoAnswer()

    mock_resp = MagicMock()
    mock_resp.text = "<html><body>Welcome to My Active Heroku App</body></html>"
    mock_client = MagicMock()
    mock_client.__enter__.return_value.get.return_value = mock_resp

    with patch("dns.resolver.resolve", side_effect=fake_resolve), \
         patch("httpx.Client", return_value=mock_client):

        findings = check_subdomain_takeover(["app.example.com"])

        assert len(findings) == 0


def test_subdomain_no_cname():
    """Test cleanly skipping subdomains that have no CNAME record."""
    def fake_resolve(qname, rtype):
        raise dns.resolver.NoAnswer()

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        findings = check_subdomain_takeover(["sub.example.com"])
        assert len(findings) == 0


def test_should_stop_cancellation():
    """Test should_stop halts loop execution immediately."""
    should_stop = MagicMock(return_value=True)

    findings = check_subdomain_takeover(
        ["sub1.example.com", "sub2.example.com"],
        should_stop=should_stop,
    )

    assert len(findings) == 0
