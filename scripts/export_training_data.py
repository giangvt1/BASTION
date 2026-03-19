#!/usr/bin/env python3
"""
Export training data from BASTION DynamoDB reports.

Converts LLM analysis outputs into labeled training data for semantic analyzer.
This allows bootstrapping the semantic analyzer from existing LLM verdicts.

Usage:
    python scripts/export_training_data.py \
        --source dynamodb \
        --table bastion-results \
        --output labeled_cloudtrail.json \
        --min-samples 1000
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).parent.parent))

from bastion.logger import get_logger

logger = get_logger(__name__)


def export_from_dynamodb(
    table_name: str,
    min_samples: int = 100,
) -> list[dict]:
    """Export labeled samples from DynamoDB reports."""
    logger.info("exporting_from_dynamodb", table=table_name)
    
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    
    # Scan table for all reports
    response = table.scan()
    items = response.get("Items", [])
    
    # Handle pagination
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
    
    logger.info("dynamodb_items_fetched", count=len(items))
    
    # Convert to training format
    training_samples = []
    
    for item in items:
        # Skip if not forensic analysis
        if item.get("event_type") != "cloudtrail":
            continue
        
        # Extract required fields
        findings = item.get("findings", [])
        forensic_finding = None
        
        for f in findings:
            if f.get("agent") == "forensic_analyst":
                forensic_finding = f
                break
        
        if not forensic_finding:
            continue
        
        evidence = forensic_finding.get("evidence", {})
        
        # Get context logs
        context_logs = item.get("event_payload", {}).get("detail", {}).get("context_logs", {})
        records = context_logs.get("Records", [])
        
        if not records:
            continue
        
        # Get labels
        status = evidence.get("status", "MEDIUM_RISK")
        kill_chain = evidence.get("kill_chain", [])
        mitre_tactics = evidence.get("mitre_tactics", [])
        
        # Encode labels
        killchain_labels = _encode_killchain(kill_chain)
        mitre_labels = _encode_mitre(mitre_tactics)
        
        # Get user
        user = item.get("event_payload", {}).get("detail", {}).get("user", "")
        
        training_samples.append({
            "events": records,
            "user": user,
            "label": status,
            "killchain_labels": killchain_labels,
            "mitre_labels": mitre_labels,
            "report_id": item.get("report_id", ""),
            "timestamp": item.get("timestamp", ""),
        })
    
    logger.info("training_samples_created", count=len(training_samples))
    
    if len(training_samples) < min_samples:
        logger.warning(
            "insufficient_samples",
            found=len(training_samples),
            required=min_samples,
        )
    
    return training_samples


def _encode_killchain(kill_chain: list[str]) -> list[int]:
    """Encode kill-chain stages to binary vector."""
    stages = [
        "Reconnaissance",
        "Initial Access",
        "Credential Access",
        "Privilege Escalation",
        "Lateral Movement",
        "Data Exfiltration",
        "Defense Evasion",
    ]
    
    labels = [0] * len(stages)
    
    for stage in kill_chain:
        # Fuzzy match
        stage_lower = stage.lower()
        for i, s in enumerate(stages):
            if s.lower() in stage_lower or stage_lower in s.lower():
                labels[i] = 1
                break
    
    return labels


def _encode_mitre(mitre_tactics: list[str]) -> list[int]:
    """Encode MITRE tactics to binary vector."""
    tactics = [
        "TA0001",  # Initial Access
        "TA0002",  # Execution
        "TA0003",  # Persistence
        "TA0004",  # Privilege Escalation
        "TA0005",  # Defense Evasion
        "TA0006",  # Credential Access
        "TA0007",  # Discovery
        "TA0008",  # Lateral Movement
        "TA0009",  # Collection
        "TA0010",  # Exfiltration
        "TA0011",  # Command and Control
        "TA0040",  # Impact
        "TA0042",  # Resource Development
        "TA0043",  # Reconnaissance
    ]
    
    labels = [0] * len(tactics)
    
    for tactic in mitre_tactics:
        # Extract tactic ID (e.g., "TA0001" from "TA0001 - Initial Access")
        tactic_id = tactic.split()[0] if " " in tactic else tactic
        
        if tactic_id in tactics:
            labels[tactics.index(tactic_id)] = 1
    
    return labels


def export_from_json(
    file_path: Path,
    min_samples: int = 100,
) -> list[dict]:
    """Export from local JSON file (for testing)."""
    logger.info("exporting_from_json", path=str(file_path))
    
    with open(file_path, "r") as f:
        data = json.load(f)
    
    # Assume data is already in training format or needs conversion
    if isinstance(data, list) and len(data) > 0:
        # Check if already in training format
        if "label" in data[0]:
            logger.info("data_already_labeled", count=len(data))
            return data
    
    logger.warning("json_format_not_recognized")
    return []


def validate_training_data(samples: list[dict]) -> dict:
    """Validate training data quality."""
    logger.info("validating_training_data", samples=len(samples))
    
    stats = {
        "total_samples": len(samples),
        "label_distribution": {},
        "avg_events_per_sample": 0,
        "samples_with_killchain": 0,
        "samples_with_mitre": 0,
    }
    
    total_events = 0
    
    for sample in samples:
        # Label distribution
        label = sample.get("label", "UNKNOWN")
        stats["label_distribution"][label] = stats["label_distribution"].get(label, 0) + 1
        
        # Event count
        events = sample.get("events", [])
        total_events += len(events)
        
        # Kill-chain
        if any(sample.get("killchain_labels", [])):
            stats["samples_with_killchain"] += 1
        
        # MITRE
        if any(sample.get("mitre_labels", [])):
            stats["samples_with_mitre"] += 1
    
    stats["avg_events_per_sample"] = total_events / len(samples) if samples else 0
    
    logger.info("validation_complete", **stats)
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Export training data for semantic analyzer"
    )
    parser.add_argument(
        "--source",
        choices=["dynamodb", "json"],
        default="dynamodb",
        help="Data source",
    )
    parser.add_argument(
        "--table",
        type=str,
        default="bastion-results",
        help="DynamoDB table name (for dynamodb source)",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Input JSON file (for json source)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSON file for training data",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=100,
        help="Minimum number of samples required",
    )
    
    args = parser.parse_args()
    
    # Export data
    if args.source == "dynamodb":
        samples = export_from_dynamodb(args.table, args.min_samples)
    else:
        if not args.input:
            print("Error: --input required for json source")
            sys.exit(1)
        samples = export_from_json(args.input, args.min_samples)
    
    if len(samples) < args.min_samples:
        print(f"\n⚠️  Warning: Only {len(samples)} samples found (minimum: {args.min_samples})")
        print("Consider:")
        print("  1. Running BASTION longer to collect more data")
        print("  2. Lowering --min-samples threshold")
        print("  3. Using synthetic data for initial training")
        
        if len(samples) < 50:
            print("\n❌ Error: Too few samples for meaningful training")
            sys.exit(1)
    
    # Validate data quality
    stats = validate_training_data(samples)
    
    # Save to file
    with open(args.output, "w") as f:
        json.dump(samples, f, indent=2)
    
    print("\n" + "=" * 60)
    print("Export Complete")
    print("=" * 60)
    print(f"Source: {args.source}")
    print(f"Total samples: {len(samples)}")
    print(f"Output: {args.output}")
    print(f"File size: {args.output.stat().st_size / 1024:.1f} KB")
    print("\nLabel Distribution:")
    for label, count in stats["label_distribution"].items():
        print(f"  {label}: {count} ({count/len(samples):.1%})")
    print(f"\nAverage events per sample: {stats['avg_events_per_sample']:.1f}")
    print(f"Samples with kill-chain: {stats['samples_with_killchain']}")
    print(f"Samples with MITRE tactics: {stats['samples_with_mitre']}")
    print("=" * 60)
    print("\nNext step:")
    print(f"  python scripts/train_semantic_analyzer.py cloudtrail --data {args.output} --epochs 20")


if __name__ == "__main__":
    main()
