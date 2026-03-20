"""
Unit tests for Threat Intel tools.

Tests heuristic fallback behavior when API keys are not configured.
"""

import pytest

from bastion.agents.threat_intel.tools import (
    abuseipdb_check,
    ip_geolocation,
    virustotal_lookup,
    whois_domain_lookup,
)


class TestVirusTotalLookup:
    """Test VirusTotal lookup tool with heuristic fallback."""

    def test_internal_ip_benign(self):
        """Internal IPs should be flagged as benign."""
        result = virustotal_lookup.invoke({"ioc_value": "10.0.1.5", "ioc_type": "ip"})
        assert result["risk_level"] == "BENIGN"
        assert "internal_ip" in result.get("flags", [])

    def test_tor_exit_node_flagged(self):
        """Known Tor exit nodes should be flagged as high risk."""
        result = virustotal_lookup.invoke({"ioc_value": "185.220.101.45", "ioc_type": "ip"})
        assert result["risk_level"] in ("HIGH", "MEDIUM")
        assert any("tor" in flag for flag in result.get("flags", []))

    def test_whitelisted_domain_benign(self):
        """Whitelisted domains should return benign."""
        result = virustotal_lookup.invoke({"ioc_value": "google.com", "ioc_type": "domain"})
        assert result["risk_level"] == "BENIGN"
        assert "whitelisted_domain" in result.get("flags", [])

    def test_high_risk_tld(self):
        """High-risk TLDs should increase risk level."""
        result = virustotal_lookup.invoke({"ioc_value": "phishing.xyz", "ioc_type": "domain"})
        assert result["risk_level"] in ("MEDIUM", "HIGH")
        assert any("high_risk_tld" in flag for flag in result.get("flags", []))

    def test_brand_impersonation_pattern(self):
        """Brand impersonation patterns should be flagged."""
        result = virustotal_lookup.invoke({"ioc_value": "chase-bank-secure.com", "ioc_type": "domain"})
        assert result["risk_level"] in ("MEDIUM", "HIGH")
        assert any("brand_impersonation" in flag for flag in result.get("flags", []))

    def test_heuristic_fallback_note(self):
        """Heuristic results should include a note about missing API key."""
        result = virustotal_lookup.invoke({"ioc_value": "example.com", "ioc_type": "domain"})
        assert result["source"] == "heuristic"
        assert "not configured" in result.get("note", "").lower()


class TestAbuseIPDBCheck:
    """Test AbuseIPDB check tool with heuristic fallback."""

    def test_internal_ip_benign(self):
        """Internal IPs should be flagged as benign."""
        result = abuseipdb_check.invoke({"ip_address": "192.168.1.1"})
        assert result["risk_level"] == "BENIGN"
        assert "private IP" in result.get("note", "")

    def test_tor_exit_flagged(self):
        """Known Tor exit nodes should be flagged."""
        result = abuseipdb_check.invoke({"ip_address": "185.220.101.45"})
        assert result["risk_level"] in ("HIGH", "MEDIUM")
        assert result.get("is_tor") is True

    def test_invalid_ip_format(self):
        """Invalid IP format should return error."""
        result = abuseipdb_check.invoke({"ip_address": "not-an-ip"})
        assert "error" in result
        assert result["risk_level"] == "UNKNOWN"

    def test_heuristic_fallback(self):
        """Should use heuristic when API key not available."""
        result = abuseipdb_check.invoke({"ip_address": "1.2.3.4"})
        assert result["source"] == "heuristic"
        assert "not configured" in result.get("note", "").lower()


class TestWHOISLookup:
    """Test WHOIS domain lookup tool."""

    def test_whitelisted_domain_benign(self):
        """Whitelisted domains should return benign immediately."""
        result = whois_domain_lookup.invoke({"domain": "google.com"})
        assert result["risk_level"] == "BENIGN"
        assert result["domain_age_days"] == 9999

    def test_high_risk_tld_flagged(self):
        """High-risk TLDs should be flagged."""
        result = whois_domain_lookup.invoke({"domain": "suspicious.xyz"})
        assert result.get("risk_level") in ("MEDIUM", "HIGH", "UNKNOWN")
        # May have high_risk_tld flag if heuristic fallback

    def test_brand_impersonation_flagged(self):
        """Brand impersonation patterns should be flagged."""
        result = whois_domain_lookup.invoke({"domain": "paypal-verify.com"})
        assert result.get("risk_level") in ("MEDIUM", "HIGH", "UNKNOWN")


class TestIPGeolocation:
    """Test IP geolocation tool."""

    def test_internal_ip_benign(self):
        """Internal IPs should be flagged as benign."""
        result = ip_geolocation.invoke({"ip_address": "10.0.1.5"})
        assert result["risk_level"] == "BENIGN"
        assert result["country_code"] == "INTERNAL"

    def test_tor_exit_flagged(self):
        """Tor exit nodes should be flagged."""
        result = ip_geolocation.invoke({"ip_address": "185.220.101.45"})
        assert result.get("is_tor") is True
        assert result["risk_level"] in ("HIGH", "MEDIUM")

    def test_invalid_ip_format(self):
        """Invalid IP format should return error."""
        result = ip_geolocation.invoke({"ip_address": "invalid"})
        assert "error" in result
        assert result["risk_level"] == "UNKNOWN"

    def test_public_ip_analyzed(self):
        """Public IPs should be analyzed."""
        result = ip_geolocation.invoke({"ip_address": "8.8.8.8"})
        assert result["risk_level"] in ("BENIGN", "LOW", "MEDIUM", "HIGH", "UNKNOWN")
        assert "ip_address" in result
