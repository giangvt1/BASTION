#!/usr/bin/env python3
"""
Visualize Semantic Analyzer predictions and compare with LLM.

This script helps understand how the semantic analyzer works and
compares its predictions with LLM outputs for validation.

Usage:
    python scripts/visualize_semantic_analyzer.py \
        --test-data test_samples.json \
        --compare-llm
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bastion.logger import get_logger

logger = get_logger(__name__)


def visualize_prediction(sample: dict, prediction: dict, llm_result: dict = None):
    """Pretty print a prediction with comparison."""
    print("\n" + "=" * 80)
    print("SAMPLE ANALYSIS")
    print("=" * 80)
    
    # Input
    print(f"\n📋 User: {sample.get('user', 'unknown')}")
    print(f"📋 Events: {len(sample.get('events', []))}")
    
    events = sample.get("events", [])[:5]
    print("\n📋 Event Sequence (first 5):")
    for i, event in enumerate(events, 1):
        event_name = event.get("eventName", "?")
        event_time = event.get("eventTime", "?")
        src_ip = event.get("sourceIPAddress", "?")
        error = event.get("errorCode", "")
        
        line = f"  {i}. {event_time} | {event_name} | IP: {src_ip}"
        if error:
            line += f" | ❌ {error}"
        print(line)
    
    # Semantic analyzer prediction
    print("\n🤖 SEMANTIC ANALYZER PREDICTION:")
    print(f"  Status: {prediction['status']}")
    print(f"  Confidence: {prediction['confidence_score']:.1%}")
    print(f"  Kill-chain: {', '.join(prediction['kill_chain_identified']) or 'None'}")
    print(f"  MITRE: {', '.join(prediction['mitre_tactics']) or 'None'}")
    print(f"  Reasoning: {prediction['reasoning_chain'][:200]}...")
    
    # Ground truth
    if "label" in sample:
        print("\n✅ GROUND TRUTH:")
        print(f"  Label: {sample['label']}")
        
        # Check if prediction matches
        match = prediction['status'] == sample['label']
        print(f"  Match: {'✓ CORRECT' if match else '✗ INCORRECT'}")
    
    # LLM comparison
    if llm_result:
        print("\n🧠 LLM PREDICTION (for comparison):")
        print(f"  Status: {llm_result.get('status', 'N/A')}")
        print(f"  Confidence: {llm_result.get('confidence_score', 0):.1%}")
        print(f"  Kill-chain: {', '.join(llm_result.get('kill_chain_identified', []))}")
        print(f"  MITRE: {', '.join(llm_result.get('mitre_tactics', []))}")
        
        # Agreement
        if prediction['status'] == llm_result.get('status'):
            print("  Agreement: ✓ MATCH")
        else:
            print("  Agreement: ✗ DISAGREE")
    
    print("=" * 80)


def compute_metrics(predictions: list[dict], ground_truth: list[dict]) -> dict:
    """Compute accuracy metrics."""
    correct = 0
    total = len(predictions)
    
    severity_correct = 0
    killchain_f1_scores = []
    mitre_f1_scores = []
    
    for pred, truth in zip(predictions, ground_truth):
        # Severity accuracy
        if pred["status"] == truth["label"]:
            correct += 1
            severity_correct += 1
        
        # Kill-chain F1 (multi-label)
        pred_kc = set(pred["kill_chain_identified"])
        true_kc = set(_decode_killchain(truth.get("killchain_labels", [])))
        
        if pred_kc or true_kc:
            precision = len(pred_kc & true_kc) / len(pred_kc) if pred_kc else 0
            recall = len(pred_kc & true_kc) / len(true_kc) if true_kc else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            killchain_f1_scores.append(f1)
        
        # MITRE F1 (multi-label)
        pred_mitre = set(pred["mitre_tactics"])
        true_mitre = set(_decode_mitre(truth.get("mitre_labels", [])))
        
        if pred_mitre or true_mitre:
            precision = len(pred_mitre & true_mitre) / len(pred_mitre) if pred_mitre else 0
            recall = len(pred_mitre & true_mitre) / len(true_mitre) if true_mitre else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            mitre_f1_scores.append(f1)
    
    return {
        "severity_accuracy": severity_correct / total if total > 0 else 0,
        "killchain_f1": sum(killchain_f1_scores) / len(killchain_f1_scores) if killchain_f1_scores else 0,
        "mitre_f1": sum(mitre_f1_scores) / len(mitre_f1_scores) if mitre_f1_scores else 0,
        "total_samples": total,
    }


def _decode_killchain(labels: list[int]) -> list[str]:
    """Decode binary vector to kill-chain stage names."""
    stages = [
        "Reconnaissance",
        "Initial Access",
        "Credential Access",
        "Privilege Escalation",
        "Lateral Movement",
        "Data Exfiltration",
        "Defense Evasion",
    ]
    return [stages[i] for i, label in enumerate(labels) if label == 1]


def _decode_mitre(labels: list[int]) -> list[str]:
    """Decode binary vector to MITRE tactic IDs."""
    tactics = [
        "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007",
        "TA0008", "TA0009", "TA0010", "TA0011", "TA0040", "TA0042", "TA0043",
    ]
    return [tactics[i] for i, label in enumerate(labels) if label == 1]


def main():
    parser = argparse.ArgumentParser(
        description="Visualize semantic analyzer predictions"
    )
    parser.add_argument(
        "--test-data",
        type=Path,
        required=True,
        help="Test data JSON file",
    )
    parser.add_argument(
        "--compare-llm",
        action="store_true",
        help="Compare with LLM predictions (requires running LLM)",
    )
    parser.add_argument(
        "--num-samples",
        type=int,
        default=5,
        help="Number of samples to visualize",
    )
    
    args = parser.parse_args()
    
    # Load test data
    with open(args.test_data, "r") as f:
        test_samples = json.load(f)
    
    if not test_samples:
        print("Error: No test samples found")
        sys.exit(1)
    
    print(f"Loaded {len(test_samples)} test samples")
    
    # Load semantic analyzer
    from bastion.models.semantic_analyzer import get_cloudtrail_analyzer
    
    analyzer = get_cloudtrail_analyzer()
    
    # Run predictions
    predictions = []
    
    for i, sample in enumerate(test_samples[:args.num_samples]):
        print(f"\n\nProcessing sample {i+1}/{min(args.num_samples, len(test_samples))}...")
        
        prediction = analyzer.analyze_sequence(
            events=sample.get("events", []),
            user=sample.get("user", ""),
            context="",
        )
        
        predictions.append(prediction)
        
        # Visualize
        llm_result = None
        if args.compare_llm:
            # TODO: Run LLM for comparison
            pass
        
        visualize_prediction(sample, prediction, llm_result)
    
    # Compute overall metrics
    if all("label" in s for s in test_samples[:args.num_samples]):
        print("\n\n" + "=" * 80)
        print("OVERALL METRICS")
        print("=" * 80)
        
        metrics = compute_metrics(
            predictions,
            test_samples[:args.num_samples],
        )
        
        print(f"\nSeverity Accuracy: {metrics['severity_accuracy']:.1%}")
        print(f"Kill-chain F1 Score: {metrics['killchain_f1']:.1%}")
        print(f"MITRE F1 Score: {metrics['mitre_f1']:.1%}")
        print(f"Total Samples: {metrics['total_samples']}")
        print("=" * 80)


if __name__ == "__main__":
    main()
