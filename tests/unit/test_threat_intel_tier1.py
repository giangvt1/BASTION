"""
Unit tests for Threat Intel Tier 1 filter.

Tests IOC filtering, deduplication, whitelisting, and risk scoring.
"""

import pytest

from bastion.agents.threat_intel.tier1_filter import run_ioc_filter


class TestTier1IOCFilter:
    """Test suite for the Tier 1 IOC static filter."""

    def test_empty_ioc_list(self):
        """Should return SKIP with zero risk score for empty input."""
        result = run_ioc_filter([])
        assert result.decision == "SKIP"
        assert result.static_risk_score == 0
        assert len(result.filtered_iocs) == 0

    def test_internal_ip_filtered(self):
        """Internal IPs should be skipped."""
        iocs = [
            {"ioc_type": "ip", "value": "10.0.1.5", "source_agent": "forensic"},
            {"ioc_type": "ip", "value": "192.168.1.100", "source_agent": "forensic"},
            {"ioc_type": "ip", "value": "172.16.0.1", "source_agent": "forensic"},
            {"ioc_type": "ip", "value": "127.0.0.1", "source_agent": "forensic"},
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "SKIP"
        assert len(result.filtered_iocs) == 0
        assert len(result.skipped_iocs) == 4
        assert all(s["_skip_reason"] == "internal_ip" for s in result.skipped_iocs)

    def test_whitelisted_domain_filtered(self):
        """Whitelisted domains should be skipped."""
        iocs = [
            {"ioc_type": "domain", "value": "google.com", "source_agent": "email"},
            {"ioc_type": "domain", "value": "api.github.com", "source_agent": "email"},
            {"ioc_type": "domain", "value": "s3.amazonaws.com", "source_agent": "forensic"},
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "SKIP"
        assert len(result.filtered_iocs) == 0
        assert len(result.skipped_iocs) == 3

    def test_tor_exit_node_flagged(self):
        """Tor exit nodes should be flagged with high risk."""
        iocs = [
            {"ioc_type": "ip", "value": "185.220.101.45", "source_agent": "forensic"},
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "ANALYZE"
        assert len(result.filtered_iocs) == 1
        assert result.static_risk_score >= 20
        assert any("tor_exit_prefix" in ind for ind in result.static_risk_indicators)

    def test_high_risk_tld_flagged(self):
        """High-risk TLDs should increase risk score."""
        iocs = [
            {"ioc_type": "domain", "value": "malicious-site.xyz", "source_agent": "email"},
            {"ioc_type": "domain", "value": "phishing.tk", "source_agent": "email"},
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "ANALYZE"
        assert len(result.filtered_iocs) == 2
        assert result.static_risk_score >= 30  # 15 per TLD + 5 per domain
        assert any("high_risk_tld" in ind for ind in result.static_risk_indicators)

    def test_brand_impersonation_flagged(self):
        """Brand impersonation patterns should be flagged."""
        iocs = [
            {"ioc_type": "domain", "value": "chase-bank-secure.com", "source_agent": "email"},
            {"ioc_type": "domain", "value": "paypal-verify.net", "source_agent": "email"},
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "ANALYZE"
        assert len(result.filtered_iocs) == 2
        assert result.static_risk_score >= 40  # 20 per brand + 5 per domain
        assert any("brand_impersonation" in ind for ind in result.static_risk_indicators)

    def test_deduplication(self):
        """Duplicate IOCs should be removed."""
        iocs = [
            {"ioc_type": "ip", "value": "1.2.3.4", "source_agent": "email"},
            {"ioc_type": "ip", "value": "1.2.3.4", "source_agent": "forensic"},
            {"ioc_type": "domain", "value": "evil.com", "source_agent": "email"},
            {"ioc_type": "domain", "value": "EVIL.COM", "source_agent": "forensic"},  # Case insensitive
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "ANALYZE"
        assert len(result.filtered_iocs) == 2  # Deduplicated

    def test_mixed_benign_and_suspicious(self):
        """Should filter benign, keep suspicious."""
        iocs = [
            {"ioc_type": "ip", "value": "10.0.1.5", "source_agent": "forensic"},  # Internal
            {"ioc_type": "domain", "value": "google.com", "source_agent": "email"},  # Whitelisted
            {"ioc_type": "ip", "value": "185.220.101.45", "source_agent": "forensic"},  # Tor
            {"ioc_type": "domain", "value": "phishing.xyz", "source_agent": "email"},  # High-risk TLD
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "ANALYZE"
        assert len(result.filtered_iocs) == 2
        assert len(result.skipped_iocs) == 2
        assert result.static_risk_score >= 35  # Tor + TLD

    def test_url_with_whitelisted_domain(self):
        """URLs from whitelisted domains should be skipped."""
        iocs = [
            {"ioc_type": "url", "value": "https://github.com/user/repo", "source_agent": "email"},
            {"ioc_type": "url", "value": "https://docs.google.com/document/123", "source_agent": "email"},
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "SKIP"
        assert len(result.filtered_iocs) == 0
        assert len(result.skipped_iocs) == 2

    def test_suspicious_url_not_filtered(self):
        """Suspicious URLs should pass through."""
        iocs = [
            {"ioc_type": "url", "value": "http://evil-phishing.xyz/login", "source_agent": "email"},
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "ANALYZE"
        assert len(result.filtered_iocs) == 1
        assert result.static_risk_score >= 15  # High-risk TLD

    def test_hash_always_analyzed(self):
        """File hashes should always be analyzed (no whitelist)."""
        iocs = [
            {"ioc_type": "hash", "value": "a" * 64, "source_agent": "forensic"},
        ]
        result = run_ioc_filter(iocs)
        assert result.decision == "ANALYZE"
        assert len(result.filtered_iocs) == 1

    def test_risk_score_capped_at_100(self):
        """Risk score should not exceed 100."""
        iocs = [
            {"ioc_type": "ip", "value": f"185.220.{i}.{j}", "source_agent": "forensic"}
            for i in range(10)
            for j in range(10)
        ]
        result = run_ioc_filter(iocs)
        assert result.static_risk_score <= 100
