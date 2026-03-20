"""
Quick validation script for Threat Intel Agent integration.

Verifies:
1. All imports work
2. Tier 1 filter functions correctly
3. Tools have graceful fallback
4. Node can be called without errors
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def validate_imports():
    """Verify all Threat Intel imports work."""
    print("\n[1/5] Validating imports...")
    try:
        from bastion.agents.threat_intel import threat_intel_node
        from bastion.agents.threat_intel.models import (
            IOCEnrichment,
            Tier1IOCFilterResult,
            ThreatIntelOutput,
        )
        from bastion.agents.threat_intel.tier1_filter import run_ioc_filter
        from bastion.agents.threat_intel.tools import (
            abuseipdb_check,
            ip_geolocation,
            virustotal_lookup,
            whois_domain_lookup,
        )
        print("  ✓ All imports successful")
        return True
    except ImportError as e:
        print(f"  ✗ Import failed: {e}")
        return False


def validate_tier1_filter():
    """Verify Tier 1 filter logic."""
    print("\n[2/5] Validating Tier 1 filter...")
    from bastion.agents.threat_intel.tier1_filter import run_ioc_filter

    # Test 1: Empty IOCs
    result = run_ioc_filter([])
    assert result.decision == "SKIP", "Empty IOCs should SKIP"
    print("  ✓ Empty IOCs → SKIP")

    # Test 2: Internal IPs filtered
    result = run_ioc_filter([
        {"ioc_type": "ip", "value": "10.0.1.5", "source_agent": "test"}
    ])
    assert result.decision == "SKIP", "Internal IPs should be filtered"
    assert len(result.skipped_iocs) == 1
    print("  ✓ Internal IPs filtered")

    # Test 3: Whitelisted domains filtered
    result = run_ioc_filter([
        {"ioc_type": "domain", "value": "google.com", "source_agent": "test"}
    ])
    assert result.decision == "SKIP", "Whitelisted domains should be filtered"
    print("  ✓ Whitelisted domains filtered")

    # Test 4: Suspicious IOCs pass through
    result = run_ioc_filter([
        {"ioc_type": "domain", "value": "phishing.xyz", "source_agent": "test"}
    ])
    assert result.decision == "ANALYZE", "Suspicious IOCs should pass"
    assert len(result.filtered_iocs) == 1
    assert result.static_risk_score > 0
    print("  ✓ Suspicious IOCs → ANALYZE")

    # Test 5: Tor exit nodes flagged
    result = run_ioc_filter([
        {"ioc_type": "ip", "value": "185.220.101.45", "source_agent": "test"}
    ])
    assert result.decision == "ANALYZE"
    assert any("tor" in ind for ind in result.static_risk_indicators)
    print("  ✓ Tor exit nodes flagged")

    print("  ✓ Tier 1 filter working correctly")
    return True


def validate_tools():
    """Verify tools have graceful fallback."""
    print("\n[3/5] Validating tools (heuristic fallback)...")

    from bastion.agents.threat_intel.tools import (
        abuseipdb_check,
        ip_geolocation,
        virustotal_lookup,
        whois_domain_lookup,
    )

    # Test VirusTotal
    result = virustotal_lookup.invoke({"ioc_value": "10.0.1.5", "ioc_type": "ip"})
    assert result["risk_level"] == "BENIGN", "Internal IP should be benign"
    print("  ✓ virustotal_lookup works")

    # Test AbuseIPDB
    result = abuseipdb_check.invoke({"ip_address": "192.168.1.1"})
    assert result["risk_level"] == "BENIGN", "Internal IP should be benign"
    print("  ✓ abuseipdb_check works")

    # Test WHOIS
    result = whois_domain_lookup.invoke({"domain": "google.com"})
    assert result["risk_level"] == "BENIGN", "Whitelisted domain should be benign"
    print("  ✓ whois_domain_lookup works")

    # Test GeoIP
    result = ip_geolocation.invoke({"ip_address": "10.0.1.5"})
    assert result["risk_level"] == "BENIGN", "Internal IP should be benign"
    print("  ✓ ip_geolocation works")

    print("  ✓ All tools have graceful fallback")
    return True


def validate_node():
    """Verify node can be called without errors."""
    print("\n[4/5] Validating node execution...")

    from bastion.agents.threat_intel import threat_intel_node
    from bastion.models.state import BastionState

    # Test with empty IOCs (should SKIP)
    state: BastionState = {
        "event_payload": {},
        "event_type": "threat_intel",
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
    assert "SKIP" in result["findings"][0]["description"]
    print("  ✓ Empty IOCs → SKIP response")

    # Test with internal IOCs (should SKIP)
    state["iocs"] = [
        {"ioc_type": "ip", "value": "10.0.1.5", "source_agent": "test"}
    ]
    result = threat_intel_node(state)
    assert result["findings"][0]["severity"] == "INFO"
    print("  ✓ Internal IOCs → SKIP response")

    print("  ✓ Node execution successful")
    return True


def validate_supervisor_integration():
    """Verify Supervisor can route to Threat Intel."""
    print("\n[5/5] Validating Supervisor integration...")

    from bastion.agents.supervisor import supervisor_node
    from bastion.graph.workflow import build_graph

    # Check graph has threat_intel node
    graph = build_graph()
    print("  ✓ Graph compiled successfully")

    # Check Supervisor routing logic
    from bastion.agents.supervisor import SUPERVISOR_SYSTEM_PROMPT
    assert "DELEGATE_THREAT" in SUPERVISOR_SYSTEM_PROMPT
    print("  ✓ Supervisor prompt includes DELEGATE_THREAT")

    # Check workflow routing
    from bastion.graph.workflow import route_from_supervisor
    from bastion.models.state import BastionState

    state: BastionState = {
        "event_payload": {},
        "event_type": "threat_intel",
        "messages": [],
        "next_agent": "DELEGATE_THREAT",
        "findings": [],
        "iocs": [],
        "iteration_count": 0,
        "error_logs": [],
        "risk_score": None,
        "final_report": None,
        "report_id": None,
    }
    route = route_from_supervisor(state)
    assert route == "DELEGATE_THREAT"
    print("  ✓ Routing logic works")

    print("  ✓ Supervisor integration verified")
    return True


def main():
    """Run all validation checks."""
    print("\n" + "=" * 70)
    print("  BASTION -- Threat Intel Agent Validation")
    print("=" * 70)

    checks = [
        validate_imports,
        validate_tier1_filter,
        validate_tools,
        validate_node,
        validate_supervisor_integration,
    ]

    results = []
    for check in checks:
        try:
            results.append(check())
        except Exception as e:
            print(f"  ✗ FAILED: {e}")
            results.append(False)

    print("\n" + "=" * 70)
    print("  VALIDATION SUMMARY")
    print("=" * 70)
    print(f"\n  Passed: {sum(results)}/{len(results)}")

    if all(results):
        print("\n  ✅ ALL CHECKS PASSED")
        print("\n  Threat Intel Agent is ready for testing!")
        print("\n  Next steps:")
        print("    1. Run: python scripts/run_local.py --threat")
        print("    2. Run: python scripts/test_e2e_threat_intel.py")
        print("    3. Run: python scripts/run_local.py --full")
        print()
        return 0
    else:
        print("\n  ❌ SOME CHECKS FAILED")
        print("\n  Please fix the issues above before proceeding.")
        print()
        return 1


if __name__ == "__main__":
    sys.exit(main())
