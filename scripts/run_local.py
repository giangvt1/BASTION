"""
Local test runner for the BASTION pipeline.

Loads sample data and runs the LangGraph multi-agent workflow
without requiring Lambda or EventBridge deployment.

Usage:
    python scripts/run_local.py --email        # Test email analysis
    python scripts/run_local.py --forensic     # Test forensic analysis
    python scripts/run_local.py --threat       # Test threat intel analysis
    python scripts/run_local.py --full         # Full Supervisor-routed pipeline
"""

from __future__ import annotations

import argparse
import json
import sys
import random
import pandas as pd
from pathlib import Path

# Ensure the bastion package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bastion.config import config
from bastion.logger import configure_logging, get_logger
from bastion.services.pii_scrubber import scrub_event_payload

configure_logging(env=config.environment, log_level=config.log_level)
logger = get_logger(__name__)


DATA_DIR = Path(__file__).resolve().parent.parent / "bastion" / "data" / "sample_events"


def _clean_record(d):
    """Sanitize pandas NaNs and cast all values to strings for downstream compatibility."""
    return {k: ("" if pd.isna(v) else str(v)) for k, v in d.items()}

def load_email_event() -> dict:
    """Load a random phishing email from the dataset as an event payload."""
    dataset_path = DATA_DIR.parent.parent.parent / "dataset" / "mail" / "Nigerian_Fraud.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    # Read 100 rows to keep memory usage low, then sample 1 row for variety
    df = pd.read_csv(dataset_path, nrows=100, encoding="utf-8")
    record = _clean_record(df.sample(1).iloc[0].to_dict())
    
    raw_eml = f"From: {record.get('sender', 'unknown')}\nTo: {record.get('receiver', 'unknown')}\nSubject: {record.get('subject', 'unknown')}\n\n{record.get('body', '')}"
    
    return {
        "event_type": "email",
        "source": "aws.s3",
        "detail": {
            "raw_eml": raw_eml,
            "s3_key": "emails/dataset_fraud_sample.eml",
        },
    }

def load_forensic_event() -> dict:
    """Load a random CloudTrail log from the dataset as an event payload."""
    dataset_path = DATA_DIR.parent.parent.parent / "dataset" / "logs" / "dec12_18features.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    # Read 100 rows to keep memory usage low, then sample 1 row for variety
    df = pd.read_csv(dataset_path, nrows=100, encoding="utf-8")
    record = _clean_record(df.sample(1).iloc[0].to_dict())
    
    return {
        "event_type": "cloudtrail",
        "source": "aws.cloudtrail",
        "detail": record,
    }


def run_single_agent(event: dict, agent_name: str):
    """Run a single agent node directly (bypasses Supervisor routing)."""
    from bastion.models.state import BastionState

    initial_state: dict = {
        "event_payload": event,
        "event_type": event.get("event_type", "unknown"),
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

    # Scrub PII before data reaches LLM agents
    initial_state["event_payload"] = scrub_event_payload(initial_state["event_payload"])

    if agent_name == "email":
        from bastion.agents.email_analyst import email_analyst_node
        print("\n" + "=" * 70)
        print("  BASTION -- Email Analyst Agent (Direct)")
        print("=" * 70 + "\n")
        result = email_analyst_node(initial_state)
    elif agent_name == "forensic":
        from bastion.agents.forensic_analyst import forensic_analyst_node
        print("\n" + "=" * 70)
        print("  BASTION -- Forensic Analyst Agent (Direct)")
        print("=" * 70 + "\n")
        result = forensic_analyst_node(initial_state)
    elif agent_name == "threat":
        from bastion.agents.threat_intel import threat_intel_node
        print("\n" + "=" * 70)
        print("  BASTION -- Threat Intel Agent (Direct)")
        print("=" * 70 + "\n")
        result = threat_intel_node(initial_state)
    else:
        raise ValueError(f"Unknown agent: {agent_name}")

    _print_results(result)


def run_full_pipeline(event: dict):
    """Run the full Supervisor-routed LangGraph pipeline."""
    from bastion.graph.workflow import build_graph

    print("\n" + "=" * 70)
    print("  BASTION -- Full Multi-Agent Pipeline")
    print("=" * 70 + "\n")

    graph = build_graph()

    initial_state = {
        "event_payload": event,
        "event_type": event.get("event_type", "unknown"),
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

    # Scrub PII before data reaches LLM agents
    initial_state["event_payload"] = scrub_event_payload(initial_state["event_payload"])

    print(f"Event type: {event.get('event_type')}")
    print(f"Invoking LangGraph...\n")

    result = graph.invoke(initial_state)

    print("\n" + "-" * 70)
    print("  FINAL STATE")
    print("-" * 70)

    for msg in result.get("messages", []):
        content = msg.content if hasattr(msg, "content") else str(msg)
        print(f"  {content}")

    print(f"\n  Findings: {len(result.get('findings', []))}")
    print(f"  IOCs:     {len(result.get('iocs', []))}")
    print(f"  Iterations: {result.get('iteration_count', 0)}")

    for i, finding in enumerate(result.get("findings", []), 1):
        print(f"\n  Finding #{i}:")
        print(f"    Agent:    {finding.get('agent')}")
        print(f"    Severity: {finding.get('severity')}")
        print(f"    MITRE:    {finding.get('mitre_tactic')}")
        print(f"    Desc:     {finding.get('description', '')[:200]}")

    print()


def _print_results(result: dict):
    """Print agent results in a readable format."""
    print("\n" + "-" * 70)
    print("  RESULTS")
    print("-" * 70)

    for msg in result.get("messages", []):
        content = msg.content if hasattr(msg, "content") else str(msg)
        print(f"\n  {content}")

    findings = result.get("findings", [])
    iocs = result.get("iocs", [])

    print(f"\n  Findings: {len(findings)}")
    for i, f in enumerate(findings, 1):
        print(f"\n  Finding #{i}:")
        print(f"    Agent:    {f.get('agent')}")
        print(f"    Type:     {f.get('finding_type')}")
        print(f"    Severity: {f.get('severity')}")
        print(f"    MITRE:    {f.get('mitre_tactic')}")
        desc = f.get("description", "")
        print(f"    Desc:     {desc[:300]}")

        evidence = f.get("evidence", {})
        if evidence.get("has_sigma_rule"):
            print(f"    Sigma:    YES (auto-generated)")

    print(f"\n  IOCs: {len(iocs)}")
    for ioc in iocs[:10]:
        print(f"    [{ioc.get('ioc_type')}] {ioc.get('value')} (from {ioc.get('source_agent')})")

    print()


def load_threat_intel_event() -> dict:
    """Load a sample event with IOCs for Threat Intel testing."""
    return {
        "event_type": "threat_intel",
        "source": "manual",
        "detail": {
            "iocs": [
                {
                    "ioc_type": "domain",
                    "value": "chase-bank-secure.xyz",
                    "source_agent": "email_analyst",
                    "context": "Phishing domain with brand impersonation",
                },
                {
                    "ioc_type": "ip",
                    "value": "185.220.101.45",
                    "source_agent": "forensic_analyst",
                    "context": "Login from Tor exit node at 2AM",
                },
                {
                    "ioc_type": "domain",
                    "value": "google.com",
                    "source_agent": "email_analyst",
                    "context": "Legitimate domain (should be filtered)",
                },
                {
                    "ioc_type": "ip",
                    "value": "10.0.1.5",
                    "source_agent": "forensic_analyst",
                    "context": "Internal IP (should be filtered)",
                },
            ],
        },
    }


def main():
    parser = argparse.ArgumentParser(description="BASTION local test runner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--email", action="store_true", help="Test Email Analyst Agent")
    group.add_argument("--forensic", action="store_true", help="Test Forensic Analyst Agent")
    group.add_argument("--threat", action="store_true", help="Test Threat Intel Agent")
    group.add_argument("--full", action="store_true", help="Run full Supervisor-routed pipeline")

    parser.add_argument(
        "--event-type",
        choices=["email", "cloudtrail"],
        default=None,
        help="Event type for --full mode (default: email)",
    )

    args = parser.parse_args()

    if args.email:
        event = load_email_event()
        run_single_agent(event, "email")
    elif args.forensic:
        event = load_forensic_event()
        run_single_agent(event, "forensic")
    elif args.threat:
        event = load_threat_intel_event()
        # Pre-populate IOCs in state for Threat Intel
        from bastion.models.state import BastionState
        initial_state: BastionState = {
            "event_payload": event,
            "event_type": "threat_intel",
            "messages": [],
            "next_agent": "",
            "findings": [
                {
                    "agent": "email_analyst",
                    "severity": "HIGH",
                    "description": "Phishing email detected with brand impersonation",
                }
            ],
            "iocs": event["detail"]["iocs"],
            "iteration_count": 1,
            "error_logs": [],
            "risk_score": None,
            "final_report": None,
            "report_id": None,
        }
        from bastion.agents.threat_intel import threat_intel_node
        print("\n" + "=" * 70)
        print("  BASTION -- Threat Intel Agent (Direct)")
        print("=" * 70 + "\n")
        result = threat_intel_node(initial_state)
        _print_results(result)
    elif args.full:
        event_type = args.event_type or "email"
        event = load_email_event() if event_type == "email" else load_forensic_event()
        run_full_pipeline(event)


if __name__ == "__main__":
    main()
