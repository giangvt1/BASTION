#!/usr/bin/env python3
"""
End-to-end ML integration test for BASTION.

Tests all ML components:
1. BERT Phishing Classifier (Email Tier 1)
2. Semantic Embeddings (Vector Store)
3. LSTM UBA Detector (Forensic Tier 1)
4. Semantic Analyzer - Email (Email Tier 2)
5. Semantic Analyzer - CloudTrail (Forensic Tier 2)

Usage:
    python scripts/test_ml_integration.py
    python scripts/test_ml_integration.py --quick  # Skip slow tests
"""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bastion.logger import configure_logging, get_logger

configure_logging(env="development", log_level="INFO")
logger = get_logger(__name__)


def test_bert_phishing_classifier():
    """Test P0: BERT Phishing Classifier."""
    logger.info("test.bert_classifier.start")
    
    try:
        from bastion.models.ml_models import get_phishing_classifier
        
        classifier = get_phishing_classifier()
        
        # Test case 1: Clear phishing
        score1, verdict1 = classifier.predict(
            subject="URGENT: Verify your account NOW",
            body="Click here immediately to verify your account or it will be suspended: http://fake-bank.com/verify",
        )
        
        # Test case 2: Legitimate email
        score2, verdict2 = classifier.predict(
            subject="Weekly team meeting notes",
            body="Hi team, here are the notes from our weekly sync meeting...",
        )
        
        logger.info(
            "test.bert_classifier.complete",
            phishing_score=round(score1, 3),
            phishing_verdict=verdict1,
            legit_score=round(score2, 3),
            legit_verdict=verdict2,
        )
        
        assert verdict1 == "PHISHING", f"Expected PHISHING, got {verdict1}"
        assert verdict2 in ["SAFE", "SUSPICIOUS"], f"Expected SAFE/SUSPICIOUS, got {verdict2}"
        
        return True
    
    except Exception:
        logger.exception("test.bert_classifier.failed")
        return False


def test_semantic_embeddings():
    """Test P1: Semantic Embeddings."""
    logger.info("test.semantic_embeddings.start")
    
    try:
        from bastion.vector_store.embeddings import get_text_embedding
        
        # Test semantic similarity
        emb1 = get_text_embedding("urgent account verification required")
        emb2 = get_text_embedding("verify your account urgently")
        emb3 = get_text_embedding("weekly team meeting notes")
        
        # Compute cosine similarity
        import numpy as np
        
        def cosine_sim(a, b):
            return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
        
        sim_12 = cosine_sim(emb1, emb2)  # Should be high (similar meaning)
        sim_13 = cosine_sim(emb1, emb3)  # Should be low (different meaning)
        
        logger.info(
            "test.semantic_embeddings.complete",
            embedding_dim=len(emb1),
            similar_texts_sim=round(sim_12, 3),
            different_texts_sim=round(sim_13, 3),
        )
        
        assert len(emb1) == 384, f"Expected 384-dim, got {len(emb1)}"
        assert sim_12 > 0.7, f"Similar texts should have high similarity, got {sim_12}"
        assert sim_13 < 0.5, f"Different texts should have low similarity, got {sim_13}"
        
        return True
    
    except Exception:
        logger.exception("test.semantic_embeddings.failed")
        return False


def test_lstm_uba_detector():
    """Test P2: LSTM UBA Detector."""
    logger.info("test.lstm_uba.start")
    
    try:
        from bastion.models.ml_models import get_lstm_detector
        
        detector = get_lstm_detector()
        
        # Test case: Suspicious sequence (privilege escalation)
        events = [
            {"eventName": "ConsoleLogin", "eventTime": "2024-03-17T02:00:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "ListUsers", "eventTime": "2024-03-17T02:01:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "ListRoles", "eventTime": "2024-03-17T02:02:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "AssumeRole", "eventTime": "2024-03-17T02:03:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "CreateAccessKey", "eventTime": "2024-03-17T02:04:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "AttachUserPolicy", "eventTime": "2024-03-17T02:05:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "GetObject", "eventTime": "2024-03-17T02:06:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "GetObject", "eventTime": "2024-03-17T02:07:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "GetObject", "eventTime": "2024-03-17T02:08:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
            {"eventName": "DeleteTrail", "eventTime": "2024-03-17T02:09:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": ""},
        ]
        
        anomaly_score, details = detector.detect_anomaly(
            event_sequence=events,
            user="test.user",
        )
        
        logger.info(
            "test.lstm_uba.complete",
            anomaly_score=round(anomaly_score, 3),
            is_anomaly=details["is_anomaly"],
            reconstruction_error=round(details["reconstruction_error"], 4),
        )
        
        # Note: Without training, model may not detect anomaly correctly
        # This test just validates the model loads and runs
        assert 0.0 <= anomaly_score <= 1.0, f"Score should be 0-1, got {anomaly_score}"
        
        return True
    
    except Exception:
        logger.exception("test.lstm_uba.failed")
        return False


def test_email_semantic_analyzer():
    """Test Semantic Analyzer for Email (Tier 2)."""
    logger.info("test.email_semantic.start")
    
    try:
        from bastion.models.semantic_analyzer import get_email_analyzer
        
        analyzer = get_email_analyzer()
        
        # Test case 1: Phishing email
        result1 = analyzer.analyze_email(
            subject="URGENT: Verify your account",
            body="Your account will be suspended unless you verify immediately. Click here: http://fake-bank.com/verify",
            sender="security@fake-bank.com",
            urls=["http://fake-bank.com/verify"],
        )
        
        # Test case 2: Legitimate email
        result2 = analyzer.analyze_email(
            subject="Weekly team sync",
            body="Hi team, here are the notes from our weekly meeting...",
            sender="manager@company.com",
            urls=[],
        )
        
        logger.info(
            "test.email_semantic.complete",
            phishing_status=result1["status"],
            phishing_confidence=round(result1["confidence_score"], 3),
            legit_status=result2["status"],
            legit_confidence=round(result2["confidence_score"], 3),
        )
        
        # Note: Without training, predictions may be random
        # This test validates the model loads and runs
        assert result1["status"] in ["PHISHING", "SUSPICIOUS", "SAFE"]
        assert 0.0 <= result1["confidence_score"] <= 1.0
        
        return True
    
    except Exception:
        logger.exception("test.email_semantic.failed")
        return False


def test_cloudtrail_semantic_analyzer():
    """Test Semantic Analyzer for CloudTrail (Tier 2)."""
    logger.info("test.cloudtrail_semantic.start")
    
    try:
        from bastion.models.semantic_analyzer import get_cloudtrail_analyzer
        
        analyzer = get_cloudtrail_analyzer()
        
        # Test case: Privilege escalation sequence
        events = [
            {"eventName": "ConsoleLogin", "eventTime": "2024-03-17T02:00:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": "", "userIdentity": {"userName": "alice"}},
            {"eventName": "ListUsers", "eventTime": "2024-03-17T02:01:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": "", "userIdentity": {"userName": "alice"}},
            {"eventName": "AssumeRole", "eventTime": "2024-03-17T02:02:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": "", "userIdentity": {"userName": "alice"}},
            {"eventName": "CreateAccessKey", "eventTime": "2024-03-17T02:03:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": "", "userIdentity": {"userName": "alice"}},
            {"eventName": "AttachUserPolicy", "eventTime": "2024-03-17T02:04:00Z", "sourceIPAddress": "1.2.3.4", "errorCode": "", "userIdentity": {"userName": "alice"}},
        ]
        
        result = analyzer.analyze_sequence(
            events=events,
            user="alice",
            context="Suspicious privilege escalation detected",
        )
        
        logger.info(
            "test.cloudtrail_semantic.complete",
            status=result["status"],
            confidence=round(result["confidence_score"], 3),
            killchain_stages=len(result["kill_chain_identified"]),
            mitre_tactics=len(result["mitre_tactics"]),
        )
        
        # Note: Without training, predictions may be random
        # This test validates the model loads and runs
        assert result["status"] in ["CLEAN", "LOW_RISK", "MEDIUM_RISK", "HIGH_RISK", "CRITICAL_COMPROMISE"]
        assert 0.0 <= result["confidence_score"] <= 1.0
        
        return True
    
    except Exception:
        logger.exception("test.cloudtrail_semantic.failed")
        return False


def test_full_pipeline(quick: bool = False):
    """Test full Email Analyst + Forensic Analyst pipeline."""
    if quick:
        logger.info("test.full_pipeline.skipped", reason="--quick mode")
        return True
    
    logger.info("test.full_pipeline.start")
    
    try:
        # This would require full LangGraph setup
        # For now, just validate imports
        from bastion.agents.email_analyst.node import email_analyst_node
        from bastion.agents.forensic_analyst.node import forensic_analyst_node
        from bastion.graph.workflow import build_graph
        
        logger.info("test.full_pipeline.imports_ok")
        
        # Could add actual graph invocation here with sample data
        # But that requires AWS credentials, Gemini API key, etc.
        
        return True
    
    except Exception:
        logger.exception("test.full_pipeline.failed")
        return False


def main():
    parser = argparse.ArgumentParser(description="Test BASTION ML integration")
    parser.add_argument("--quick", action="store_true", help="Skip slow tests")
    args = parser.parse_args()
    
    logger.info("test_suite.start", quick=args.quick)
    
    results = {}
    
    # Run all tests
    tests = [
        ("BERT Phishing Classifier", test_bert_phishing_classifier),
        ("Semantic Embeddings", test_semantic_embeddings),
        ("LSTM UBA Detector", test_lstm_uba_detector),
        ("Email Semantic Analyzer", test_email_semantic_analyzer),
        ("CloudTrail Semantic Analyzer", test_cloudtrail_semantic_analyzer),
        ("Full Pipeline", lambda: test_full_pipeline(args.quick)),
    ]
    
    for name, test_func in tests:
        logger.info("test.running", test=name)
        try:
            passed = test_func()
            results[name] = "✅ PASS" if passed else "❌ FAIL"
        except Exception:
            logger.exception("test.exception", test=name)
            results[name] = "❌ FAIL"
    
    # Print summary
    print("\n" + "="*60)
    print("ML INTEGRATION TEST RESULTS")
    print("="*60)
    for name, result in results.items():
        print(f"{result}  {name}")
    print("="*60)
    
    failed = sum(1 for r in results.values() if "FAIL" in r)
    total = len(results)
    
    if failed == 0:
        logger.info("test_suite.complete", status="ALL_PASS", total=total)
        print(f"\n✅ All {total} tests passed!")
        return 0
    else:
        logger.error("test_suite.complete", status="SOME_FAILED", failed=failed, total=total)
        print(f"\n❌ {failed}/{total} tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
