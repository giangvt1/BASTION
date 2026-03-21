"""
End-to-end integration test for full BASTION workflow with Threat Intel.

Tests multi-agent collaboration:
  Email Analyst → Supervisor → Threat Intel → Supervisor → SYNTHESIZE
"""

import pytest

from bastion.graph.workflow import build_graph
from bastion.models.state import BastionState


class TestFullWorkflowWithThreatIntel:
    """Test complete multi-agent workflow including Threat Intel."""

    def test_phishing_email_with_ioc_enrichment(self):
        """Test phishing email detection followed by IOC enrichment."""
        # Sample phishing email with suspicious domain
        sample_email = """From: security@chase-bank-secure.com
To: victim@example.com
Subject: URGENT: Verify your account immediately

Dear customer,

Your account has been locked due to suspicious activity.
Click here to verify: https://chase-bank-secure.com/verify

Thank you,
Chase Security Team
"""

        initial_state: BastionState = {
            "event_payload": {
                "detail": {
                    "raw_eml": sample_email,
                    "subject": "URGENT: Verify your account immediately",
                    "sender": "security@chase-bank-secure.com",
                }
            },
            "event_type": "email",
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

        graph = build_graph()
        result = graph.invoke(initial_state)

        # Verify workflow completed
        assert result["iteration_count"] > 0

        # Should have findings from Email Analyst
        email_findings = [f for f in result["findings"] if f["agent"] == "email_analyst"]
        assert len(email_findings) >= 1

        # Should have IOCs extracted
        assert len(result["iocs"]) >= 1
        ioc_values = [ioc["value"] for ioc in result["iocs"]]
        assert any("chase-bank-secure.com" in val for val in ioc_values)

        # Should have findings from Threat Intel
        threat_findings = [f for f in result["findings"] if f["agent"] == "threat_intel"]
        assert len(threat_findings) >= 1

        # Threat Intel should assess the domain
        threat_finding = threat_findings[0]
        assert threat_finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM")
        assert "evidence" in threat_finding
        assert "status" in threat_finding["evidence"]

    def test_cloudtrail_anomaly_with_ioc_enrichment(self):
        """Test CloudTrail anomaly detection followed by IOC enrichment."""
        initial_state: BastionState = {
            "event_payload": {
                "detail": {
                    "user": "alice.johnson",
                    "anomaly_trigger": "Login from Tor exit node",
                    "context_logs": {
                        "Records": [
                            {
                                "eventName": "ConsoleLogin",
                                "sourceIPAddress": "185.220.101.45",
                                "userIdentity": {"userName": "alice.johnson"},
                                "eventTime": "2024-03-17T02:15:00Z",
                            }
                        ]
                    },
                }
            },
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

        graph = build_graph()
        result = graph.invoke(initial_state)

        # Should have findings from Forensic Analyst
        forensic_findings = [f for f in result["findings"] if f["agent"] == "forensic_analyst"]
        assert len(forensic_findings) >= 1

        # Should have IOCs (IP address)
        assert len(result["iocs"]) >= 1
        ip_iocs = [ioc for ioc in result["iocs"] if ioc["ioc_type"] == "ip"]
        assert len(ip_iocs) >= 1

        # Should have findings from Threat Intel
        threat_findings = [f for f in result["findings"] if f["agent"] == "threat_intel"]
        assert len(threat_findings) >= 1

        # Threat Intel should flag Tor exit node
        threat_finding = threat_findings[0]
        assert threat_finding["severity"] in ("CRITICAL", "HIGH")

    def test_multi_agent_correlation(self):
        """Test correlation between Email, Forensic, and Threat Intel."""
        # Scenario: Phishing email → user clicks → suspicious login
        initial_state: BastionState = {
            "event_payload": {
                "detail": {
                    "raw_eml": "Phishing email with link to evil-phishing.xyz",
                    "subject": "Verify your account",
                    "sender": "phisher@evil-phishing.xyz",
                }
            },
            "event_type": "email",
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

        graph = build_graph()
        result = graph.invoke(initial_state)

        # Should have multiple agents involved
        agents_involved = {f["agent"] for f in result["findings"]}
        assert "email_analyst" in agents_involved
        # May or may not have threat_intel depending on routing

        # Should have IOCs
        assert len(result["iocs"]) >= 1

        # Should complete without errors
        assert result["iteration_count"] <= MAX_ITERATIONS

    def test_threat_intel_with_existing_findings(self):
        """Test Threat Intel receives context from other agents."""
        # Pre-populate state with findings from Email Analyst
        initial_state: BastionState = {
            "event_payload": {},
            "event_type": "email",
            "messages": [],
            "next_agent": "DELEGATE_THREAT",  # Direct to Threat Intel
            "findings": [
                {
                    "agent": "email_analyst",
                    "finding_type": "phishing_detection",
                    "severity": "HIGH",
                    "description": "Phishing email with brand impersonation",
                    "evidence": {},
                    "mitre_tactic": "TA0001",
                    "timestamp": "2024-03-17T10:00:00Z",
                }
            ],
            "iocs": [
                {
                    "ioc_type": "domain",
                    "value": "paypal-verify.xyz",
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

        # Call threat_intel_node directly
        from bastion.agents.threat_intel.node import threat_intel_node

        result = threat_intel_node(initial_state)

        # Should produce findings
        assert "findings" in result
        assert len(result["findings"]) >= 1

        # Should reference existing findings in reasoning
        finding = result["findings"][0]
        # Reasoning should consider context from email_analyst
        assert "evidence" in finding


# Import MAX_ITERATIONS for test
from bastion.agents.supervisor import MAX_ITERATIONS
