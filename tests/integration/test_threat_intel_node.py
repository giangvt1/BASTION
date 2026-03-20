"""
Integration tests for Threat Intel Agent node.

Tests the full Tier 1 → Tier 2 → Self-Reflection workflow.
"""

import pytest

from bastion.agents.threat_intel.node import threat_intel_node
from bastion.agents.threat_intel.tools import (
    abuseipdb_check,
    ip_geolocation,
    whois_domain_lookup,
)
from bastion.models.state import BastionState


class TestThreatIntelNode:
    """Integration tests for the Threat Intel node."""

    def test_empty_iocs_skip(self):
        """Should skip analysis when no IOCs provided."""
        state: BastionState = {
            "event_payload": {},
            "event_type": "cloudtrail",
            "messages": [],
            "next_agent": "",
            "findings": [],
            "iocs": [],
            "iteration_count": 0,
            "error_logs": [],
            "risk_score": None,
            "final_report": None,
            "report_id": None,
        }

        result = threat_intel_node(state)

        assert "findings" in result
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "INFO"
        assert "SKIP" in result["findings"][0]["description"]

    def test_internal_iocs_skip(self):
        """Should skip when all IOCs are internal/whitelisted."""
        state: BastionState = {
            "event_payload": {},
            "event_type": "cloudtrail",
            "messages": [],
            "next_agent": "",
            "findings": [],
            "iocs": [
                {"ioc_type": "ip", "value": "10.0.1.5", "source_agent": "forensic"},
                {"ioc_type": "domain", "value": "google.com", "source_agent": "email"},
            ],
            "iteration_count": 0,
            "error_logs": [],
            "risk_score": None,
            "final_report": None,
            "report_id": None,
        }

        result = threat_intel_node(state)

        assert "findings" in result
        assert result["findings"][0]["severity"] == "INFO"
        assert "benign/whitelisted" in result["findings"][0]["description"].lower()

    def test_suspicious_iocs_analyzed(self):
        """Should analyze suspicious IOCs through Tier 2."""
        state: BastionState = {
            "event_payload": {},
            "event_type": "email",
            "messages": [],
            "next_agent": "",
            "findings": [
                {
                    "agent": "email_analyst",
                    "severity": "HIGH",
                    "description": "Phishing email detected",
                }
            ],
            "iocs": [
                {
                    "ioc_type": "domain",
                    "value": "phishing-site.xyz",
                    "source_agent": "email_analyst",
                    "context": "Suspicious domain in email",
                },
                {
                    "ioc_type": "ip",
                    "value": "185.220.101.45",
                    "source_agent": "email_analyst",
                    "context": "Tor exit node",
                },
            ],
            "iteration_count": 1,
            "error_logs": [],
            "risk_score": None,
            "final_report": None,
            "report_id": None,
        }

        result = threat_intel_node(state)

        # Should have findings
        assert "findings" in result
        assert len(result["findings"]) >= 1

        # Should have enriched IOCs
        assert "iocs" in result
        assert len(result["iocs"]) >= 1

        # Should have messages
        assert "messages" in result
        assert len(result["messages"]) >= 1

        # Check finding structure
        finding = result["findings"][0]
        assert finding["agent"] == "threat_intel"
        assert finding["finding_type"] == "ioc_assessment"
        assert finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert "evidence" in finding
        assert "status" in finding["evidence"]
        assert "confidence_score" in finding["evidence"]

    def test_tor_exit_node_critical(self):
        """Tor exit nodes should be flagged as high risk."""
        state: BastionState = {
            "event_payload": {},
            "event_type": "cloudtrail",
            "messages": [],
            "next_agent": "",
            "findings": [],
            "iocs": [
                {
                    "ioc_type": "ip",
                    "value": "185.220.101.45",
                    "source_agent": "forensic_analyst",
                    "context": "Login from foreign IP",
                },
            ],
            "iteration_count": 1,
            "error_logs": [],
            "risk_score": None,
            "final_report": None,
            "report_id": None,
        }

        result = threat_intel_node(state)

        finding = result["findings"][0]
        assert finding["severity"] in ("CRITICAL", "HIGH")
        assert "tor" in finding["description"].lower() or "tor" in str(finding["evidence"]).lower()

    def test_brand_impersonation_domain(self):
        """Brand impersonation domains should be flagged."""
        state: BastionState = {
            "event_payload": {},
            "event_type": "email",
            "messages": [],
            "next_agent": "",
            "findings": [],
            "iocs": [
                {
                    "ioc_type": "domain",
                    "value": "chase-bank-secure-login.com",
                    "source_agent": "email_analyst",
                    "context": "Phishing domain",
                },
            ],
            "iteration_count": 1,
            "error_logs": [],
            "risk_score": None,
            "final_report": None,
            "report_id": None,
        }

        result = threat_intel_node(state)

        finding = result["findings"][0]
        assert finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM")
        assert "brand" in finding["description"].lower() or "impersonation" in str(finding["evidence"]).lower()

    def test_multiple_iocs_correlation(self):
        """Should correlate multiple IOCs from different agents."""
        state: BastionState = {
            "event_payload": {},
            "event_type": "cloudtrail",
            "messages": [],
            "next_agent": "",
            "findings": [
                {
                    "agent": "email_analyst",
                    "severity": "HIGH",
                    "description": "Phishing email detected",
                },
                {
                    "agent": "forensic_analyst",
                    "severity": "HIGH",
                    "description": "Suspicious login from foreign IP",
                },
            ],
            "iocs": [
                {
                    "ioc_type": "domain",
                    "value": "evil-phishing.xyz",
                    "source_agent": "email_analyst",
                    "context": "Phishing domain",
                },
                {
                    "ioc_type": "ip",
                    "value": "185.220.101.45",
                    "source_agent": "forensic_analyst",
                    "context": "Login IP",
                },
            ],
            "iteration_count": 2,
            "error_logs": [],
            "risk_score": None,
            "final_report": None,
            "report_id": None,
        }

        result = threat_intel_node(state)

        # Should analyze both IOCs
        assert len(result["iocs"]) >= 2
        finding = result["findings"][0]
        assert finding["severity"] in ("CRITICAL", "HIGH")


class TestAbuseIPDBCheck:
    """Test AbuseIPDB check tool."""

    def test_internal_ip_benign(self):
        """Internal IPs should be benign."""
        result = abuseipdb_check.invoke({"ip_address": "192.168.1.1"})
        assert result["risk_level"] == "BENIGN"

    def test_tor_exit_flagged(self):
        """Tor exit nodes should be flagged."""
        result = abuseipdb_check.invoke({"ip_address": "185.220.101.45"})
        assert result.get("is_tor") is True
        assert result["risk_level"] in ("HIGH", "MEDIUM")

    def test_invalid_ip_error(self):
        """Invalid IP should return error."""
        result = abuseipdb_check.invoke({"ip_address": "not-an-ip"})
        assert "error" in result


class TestWHOISLookup:
    """Test WHOIS domain lookup tool."""

    def test_whitelisted_domain(self):
        """Whitelisted domains should be benign."""
        result = whois_domain_lookup.invoke({"domain": "microsoft.com"})
        assert result["risk_level"] == "BENIGN"

    def test_subdomain_extraction(self):
        """Should extract base domain from subdomains."""
        result = whois_domain_lookup.invoke({"domain": "api.github.com"})
        assert result["risk_level"] == "BENIGN"
        assert "github.com" in result.get("note", "").lower()


class TestIPGeolocation:
    """Test IP geolocation tool."""

    def test_internal_ip_benign(self):
        """Internal IPs should be benign."""
        result = ip_geolocation.invoke({"ip_address": "10.0.1.5"})
        assert result["risk_level"] == "BENIGN"
        assert result["country_code"] == "INTERNAL"

    def test_tor_exit_flagged(self):
        """Tor exit nodes should be flagged."""
        result = ip_geolocation.invoke({"ip_address": "185.220.101.45"})
        assert result.get("is_tor") is True

    def test_public_ip_analyzed(self):
        """Public IPs should be analyzed."""
        result = ip_geolocation.invoke({"ip_address": "8.8.8.8"})
        assert "ip_address" in result
        assert result["risk_level"] in ("BENIGN", "LOW", "MEDIUM", "HIGH", "UNKNOWN")
