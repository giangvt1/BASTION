"""
End-to-end test for Threat Intel Agent integration.

Tests the complete workflow:
1. Email Analyst detects phishing → extracts IOCs
2. Supervisor routes to Threat Intel
3. Threat Intel enriches IOCs
4. Supervisor synthesizes final report
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bastion.config import config
from bastion.graph.workflow import build_graph
from bastion.logger import configure_logging, get_logger
from bastion.models.state import BastionState

configure_logging(env=config.environment, log_level=config.log_level)
logger = get_logger(__name__)


def test_phishing_email_to_threat_intel():
    """Test: Phishing email → Email Analyst → Threat Intel → Report."""
    print("\n" + "=" * 70)
    print("  TEST: Phishing Email → Threat Intel Enrichment")
    print("=" * 70 + "\n")

    # Sample phishing email with suspicious IOCs
    sample_email = """From: security@chase-bank-verify.xyz
To: victim@example.com
Subject: URGENT: Verify your account now

Dear customer,

Your account has been locked. Click here immediately:
https://chase-bank-verify.xyz/login?token=abc123

Failure to verify within 24 hours will result in permanent suspension.

Chase Security Team
"""

    initial_state: BastionState = {
        "event_payload": {
            "detail": {
                "raw_eml": sample_email,
                "subject": "URGENT: Verify your account now",
                "sender": "security@chase-bank-verify.xyz",
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

    print("Building LangGraph...")
    graph = build_graph()

    print("Invoking workflow...\n")
    result = graph.invoke(initial_state)

    print("\n" + "-" * 70)
    print("  RESULTS")
    print("-" * 70)

    # Print agent execution flow
    print("\nAgent Execution Flow:")
    for msg in result.get("messages", []):
        content = msg.content if hasattr(msg, "content") else str(msg)
        print(f"  → {content}")

    # Print findings
    print(f"\nFindings ({len(result.get('findings', []))}):")
    for i, finding in enumerate(result.get("findings", []), 1):
        print(f"\n  #{i} [{finding['agent']}] {finding['severity']}")
        print(f"      {finding.get('description', '')[:150]}")

    # Print IOCs
    print(f"\nIOCs ({len(result.get('iocs', []))}):")
    for ioc in result.get("iocs", [])[:10]:
        print(f"  [{ioc['ioc_type']}] {ioc['value']} (from {ioc['source_agent']})")

    # Verify expectations
    print("\n" + "-" * 70)
    print("  VERIFICATION")
    print("-" * 70)

    agents_involved = {f["agent"] for f in result["findings"]}
    print(f"\n✓ Agents involved: {', '.join(agents_involved)}")

    has_email = "email_analyst" in agents_involved
    has_threat = "threat_intel" in agents_involved

    print(f"✓ Email Analyst executed: {has_email}")
    print(f"✓ Threat Intel executed: {has_threat}")
    print(f"✓ IOCs extracted: {len(result['iocs'])} IOCs")
    print(f"✓ Iterations: {result['iteration_count']}")

    # Check if Threat Intel was actually called
    if has_threat:
        threat_findings = [f for f in result["findings"] if f["agent"] == "threat_intel"]
        print(f"✓ Threat Intel findings: {len(threat_findings)}")

        if threat_findings:
            tf = threat_findings[0]
            print(f"  - Status: {tf['evidence'].get('status', 'N/A')}")
            print(f"  - Confidence: {tf['evidence'].get('confidence_score', 0):.0%}")
            print(f"  - IOCs enriched: {len(tf['evidence'].get('ioc_enrichments', []))}")
    else:
        print("⚠ WARNING: Threat Intel was not invoked by Supervisor")
        print("  This may be expected if Email Analyst didn't extract IOCs")

    print()
    return result


def test_cloudtrail_anomaly_to_threat_intel():
    """Test: CloudTrail anomaly → Forensic Analyst → Threat Intel → Report."""
    print("\n" + "=" * 70)
    print("  TEST: CloudTrail Anomaly → Threat Intel Enrichment")
    print("=" * 70 + "\n")

    # Sample CloudTrail event with Tor exit node
    cloudtrail_event = {
        "user": "alice.johnson",
        "anomaly_trigger": "Login from Tor exit node at unusual time",
        "context_logs": {
            "Records": [
                {
                    "eventName": "ConsoleLogin",
                    "sourceIPAddress": "185.220.101.45",
                    "userIdentity": {"userName": "alice.johnson"},
                    "eventTime": "2024-03-17T02:15:00Z",
                    "responseElements": {"ConsoleLogin": "Success"},
                },
                {
                    "eventName": "ListBuckets",
                    "sourceIPAddress": "185.220.101.45",
                    "userIdentity": {"userName": "alice.johnson"},
                    "eventTime": "2024-03-17T02:16:00Z",
                },
                {
                    "eventName": "AssumeRole",
                    "sourceIPAddress": "185.220.101.45",
                    "userIdentity": {"userName": "alice.johnson"},
                    "eventTime": "2024-03-17T02:17:00Z",
                    "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/AdminRole"},
                },
            ]
        },
    }

    initial_state: BastionState = {
        "event_payload": {"detail": cloudtrail_event},
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

    print("Building LangGraph...")
    graph = build_graph()

    print("Invoking workflow...\n")
    result = graph.invoke(initial_state)

    print("\n" + "-" * 70)
    print("  RESULTS")
    print("-" * 70)

    # Print agent execution flow
    print("\nAgent Execution Flow:")
    for msg in result.get("messages", []):
        content = msg.content if hasattr(msg, "content") else str(msg)
        print(f"  → {content}")

    # Print findings
    print(f"\nFindings ({len(result.get('findings', []))}):")
    for i, finding in enumerate(result.get("findings", []), 1):
        print(f"\n  #{i} [{finding['agent']}] {finding['severity']}")
        print(f"      {finding.get('description', '')[:150]}")

    # Print IOCs
    print(f"\nIOCs ({len(result.get('iocs', []))}):")
    for ioc in result.get("iocs", [])[:10]:
        print(f"  [{ioc['ioc_type']}] {ioc['value']} (from {ioc['source_agent']})")

    # Verify expectations
    print("\n" + "-" * 70)
    print("  VERIFICATION")
    print("-" * 70)

    agents_involved = {f["agent"] for f in result["findings"]}
    print(f"\n✓ Agents involved: {', '.join(agents_involved)}")

    has_forensic = "forensic_analyst" in agents_involved
    has_threat = "threat_intel" in agents_involved

    print(f"✓ Forensic Analyst executed: {has_forensic}")
    print(f"✓ Threat Intel executed: {has_threat}")
    print(f"✓ IOCs extracted: {len(result['iocs'])} IOCs")
    print(f"✓ Iterations: {result['iteration_count']}")

    # Check Tor IP was flagged
    tor_iocs = [ioc for ioc in result["iocs"] if "185.220.101.45" in ioc["value"]]
    if tor_iocs:
        print(f"✓ Tor exit node detected: {tor_iocs[0]['value']}")

    print()
    return result


def test_direct_threat_intel_call():
    """Test: Direct call to Threat Intel with pre-populated IOCs."""
    print("\n" + "=" * 70)
    print("  TEST: Direct Threat Intel Call")
    print("=" * 70 + "\n")

    from bastion.agents.threat_intel import threat_intel_node

    state: BastionState = {
        "event_payload": {},
        "event_type": "threat_intel",
        "messages": [],
        "next_agent": "",
        "findings": [
            {
                "agent": "email_analyst",
                "severity": "HIGH",
                "description": "Phishing email with brand impersonation",
            }
        ],
        "iocs": [
            {
                "ioc_type": "domain",
                "value": "paypal-verify.xyz",
                "source_agent": "email_analyst",
                "context": "Phishing domain",
            },
            {
                "ioc_type": "ip",
                "value": "185.220.101.45",
                "source_agent": "forensic_analyst",
                "context": "Tor exit node",
            },
            {
                "ioc_type": "domain",
                "value": "google.com",
                "source_agent": "email_analyst",
                "context": "Legitimate domain (should be filtered)",
            },
        ],
        "iteration_count": 1,
        "error_logs": [],
        "risk_score": None,
        "final_report": None,
        "report_id": None,
    }

    print("Calling threat_intel_node()...\n")
    result = threat_intel_node(state)

    print("\n" + "-" * 70)
    print("  RESULTS")
    print("-" * 70)

    # Print findings
    print(f"\nFindings: {len(result.get('findings', []))}")
    for finding in result["findings"]:
        print(f"\n  Agent:    {finding['agent']}")
        print(f"  Severity: {finding['severity']}")
        print(f"  Status:   {finding['evidence'].get('status', 'N/A')}")
        print(f"  Confidence: {finding['evidence'].get('confidence_score', 0):.0%}")
        print(f"  Description: {finding.get('description', '')[:200]}")

    # Print enriched IOCs
    print(f"\nEnriched IOCs: {len(result.get('iocs', []))}")
    for ioc in result["iocs"]:
        print(f"  [{ioc['ioc_type']}] {ioc['value']}")
        print(f"      Context: {ioc.get('context', '')[:100]}")

    # Verify Tier 1 filtering worked
    print("\n" + "-" * 70)
    print("  VERIFICATION")
    print("-" * 70)

    # google.com should have been filtered out
    enriched_values = [ioc["value"] for ioc in result["iocs"]]
    print(f"\n✓ google.com filtered: {'google.com' not in enriched_values}")
    print(f"✓ Suspicious IOCs analyzed: {len(result['iocs'])} IOCs")
    print(f"✓ Findings generated: {len(result['findings'])} findings")

    print()
    return result


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  BASTION -- Threat Intel E2E Tests")
    print("=" * 70)

    try:
        # Test 1: Direct call
        print("\n[TEST 1/3] Direct Threat Intel Call")
        test_direct_threat_intel_call()

        # Test 2: Phishing email workflow
        print("\n[TEST 2/3] Phishing Email → Threat Intel")
        test_phishing_email_to_threat_intel()

        # Test 3: CloudTrail anomaly workflow
        print("\n[TEST 3/3] CloudTrail Anomaly → Threat Intel")
        test_cloudtrail_anomaly_to_threat_intel()

        print("\n" + "=" * 70)
        print("  ALL TESTS COMPLETED")
        print("=" * 70 + "\n")

    except Exception as e:
        logger.exception("test_failed")
        print(f"\n❌ TEST FAILED: {e}\n")
        sys.exit(1)
