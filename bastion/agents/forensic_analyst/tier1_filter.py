"""
Tier 1 Anomaly Detection Filter for Forensic Analyst.

Combines multiple detection methods:
1. Rule-based checks for known suspicious CloudTrail events
2. Isolation Forest for statistical anomaly detection
3. LSTM Autoencoder for temporal User Behavior Analytics (UBA)

The hybrid approach captures both known attack patterns and novel anomalies.
"""

from __future__ import annotations

import os
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

from bastion.agents.forensic_analyst.models import Tier1AnomalyResult
from bastion.logger import get_logger

logger = get_logger(__name__)

# Feature flag for LSTM UBA detector
USE_LSTM_UBA = os.getenv("BASTION_USE_LSTM_UBA", "true").lower() == "true"


def _sanitize_ip(ip: str) -> str:
    """Sanitize and pad truncated IPs from dataset (e.g. '253.112' -> '10.0.253.112')."""
    if not ip or not isinstance(ip, str) or ip == "nan":
        return "0.0.0.0"
    
    parts = ip.split('.')
    # If already a valid IPv4, return as is
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ip
        
    # Handle truncated IPs from the kaggle/dec12 dataset (usually 2 octets)
    if len(parts) == 2 and all(p.isdigit() for p in parts):
        return f"10.0.{parts[0]}.{parts[1]}"
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        return f"10.{parts[0]}.{parts[1]}.{parts[2]}"
        
    return ip


# ── Suspicious CloudTrail event names ───────────────────────────────────

_HIGH_RISK_EVENTS = {
    "AssumeRole", "CreateUser", "CreateAccessKey", "AttachUserPolicy",
    "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreateLoginProfile", "UpdateLoginProfile", "DeleteTrail",
    "StopLogging", "UpdateTrail", "PutEventSelectors",
    "DisableKey", "ScheduleKeyDeletion",
    "AuthorizeSecurityGroupIngress", "CreateSecurityGroup",
    "DeleteFlowLogs", "DeleteBucket", "PutBucketPolicy",
}

_RECON_EVENTS = {
    "ListBuckets", "ListUsers", "ListRoles", "ListAccessKeys",
    "DescribeInstances", "DescribeSecurityGroups", "GetBucketAcl",
    "ListAttachedUserPolicies", "ListGroupsForUser",
    "GetAccountAuthorizationDetails",
}

_DATA_ACCESS_EVENTS = {
    "GetObject", "PutObject", "CopyObject", "SelectObjectContent",
}


def run_anomaly_filter(context_logs: dict, user: str = "") -> Tier1AnomalyResult:
    """Run Tier 1 hybrid anomaly detection on CloudTrail log context.

    Combines three detection methods:
    1. Rule-based checks (high-risk APIs, recon bursts, access denied)
    2. Isolation Forest (statistical anomaly detection)
    3. LSTM Autoencoder (temporal UBA, user-specific baselines)

    Args:
        context_logs: Dict containing 'Records' key with CloudTrail events.
        user: Username to focus analysis on.

    Returns:
        Tier1AnomalyResult with triage decision.
    """
    log = logger.bind(component="tier1_anomaly_filter")
    records = context_logs.get("Records", [])

    if not records:
        log.info("tier1_forensic.no_records")
        return Tier1AnomalyResult(decision="NORMAL")

    # ── Extract username if not provided ────────────────────────────────
    if not user:
        for rec in records:
            identity = rec.get("userIdentity", {})
            if isinstance(identity, dict):
                user = str(identity.get("userName", "") or identity.get("principalId", "") or "")
            else:
                user = str(identity) if identity else ""
            if user:
                break

    # ── 1. Rule-based checks ────────────────────────────────────────────
    rule_matches: list[str] = []
    flagged_events: list[dict] = []
    source_ips: set[str] = set()

    for rec in records:
        event_name = str(rec.get("eventName", "") or "")
        src_ip = _sanitize_ip(str(rec.get("sourceIPAddress", "") or ""))
        error_code = str(rec.get("errorCode", "") or "")
        event_time = str(rec.get("eventTime", "") or "")

        if src_ip:
            source_ips.add(src_ip)

        if event_name in _HIGH_RISK_EVENTS:
            rule_matches.append(f"high_risk_api:{event_name}")
            flagged_events.append({
                "eventName": event_name,
                "eventTime": event_time,
                "sourceIP": src_ip,
                "reason": "High-risk API call",
            })

        if error_code == "AccessDenied":
            rule_matches.append(f"access_denied:{event_name}")
            flagged_events.append({
                "eventName": event_name,
                "eventTime": event_time,
                "sourceIP": src_ip,
                "reason": "Access denied (possible probing)",
            })

        # ── VPC Flow Log specific rules ──────────────────────────────────
        event_source = str(rec.get("eventSource", "") or "")
        vpc_flow = rec.get("_vpc_flow_log", {})

        if event_source == "vpc-flow-logs.amazonaws.com" or vpc_flow:
            action = vpc_flow.get("action", "") if vpc_flow else ""
            attack_label = vpc_flow.get("mapped_attack_label", "") if vpc_flow else ""

            # REJECT events from external IPs are suspicious, never NORMAL
            if action == "REJECT" or "REJECT" in event_name:
                rule_matches.append(f"vpc_flow_reject:{src_ip}")
                flagged_events.append({
                    "eventName": event_name,
                    "eventTime": event_time,
                    "sourceIP": src_ip,
                    "eventSource": event_source,
                    "reason": f"Rejected network connection from {src_ip}",
                })

            # Heuristic attack labels add additional suspicion
            if attack_label and attack_label != "unknown_network_event":
                rule_matches.append(f"vpc_flow_suspicious_label:{attack_label}")
                flagged_events.append({
                    "eventName": event_name,
                    "eventTime": event_time,
                    "sourceIP": src_ip,
                    "eventSource": event_source,
                    "reason": f"Heuristic label: {attack_label} (not confirmed, upstream tag)",
                })

        recon_count = sum(
            1 for r in records if r.get("eventName") in _RECON_EVENTS
        )
        if recon_count >= 3 and f"recon_burst:{recon_count}" not in rule_matches:
            rule_matches.append(f"recon_burst:{recon_count}")

    # ── 2. Isolation Forest anomaly detection ───────────────────────────
    iforest_score = _run_isolation_forest(records)

    if iforest_score > 0.5:
        rule_matches.append(f"isolation_forest_anomaly:{iforest_score:.2f}")

    # ── 3. LSTM UBA anomaly detection ───────────────────────────────────
    lstm_score = 0.0
    lstm_details = {}
    
    if USE_LSTM_UBA:
        try:
            from bastion.models.ml_models import get_lstm_detector
            
            detector = get_lstm_detector()
            lstm_score, lstm_details = detector.detect_anomaly(records, user)
            
            log.info(
                "tier1_forensic.lstm_uba",
                user=user,
                lstm_score=round(lstm_score, 3),
                is_anomaly=lstm_details.get("is_anomaly", False),
                reconstruction_error=round(lstm_details.get("reconstruction_error", 0.0), 4),
            )
            
            if lstm_details.get("is_anomaly"):
                rule_matches.append(f"lstm_uba_anomaly:{lstm_score:.2f}")
        except Exception:
            log.warning("tier1_forensic.lstm_uba_failed", exc_info=True)
            # Continue with other detection methods

    # ── 4. Compute combined anomaly score ───────────────────────────────
    # Weighted combination of all detection methods
    combined_score = 0.0
    
    # Rule-based: up to 0.4
    rule_score = min(len(rule_matches) * 0.1, 0.4)
    combined_score += rule_score
    
    # Isolation Forest: up to 0.3
    combined_score += min(iforest_score * 0.3, 0.3)
    
    # LSTM UBA: up to 0.3
    if USE_LSTM_UBA:
        combined_score += min(lstm_score * 0.3, 0.3)
    
    combined_score = min(combined_score, 1.0)

    # ── 5. Decision ─────────────────────────────────────────────────────
    decision = "ANOMALY" if rule_matches else "NORMAL"

    log.info(
        "tier1_forensic.result",
        decision=decision,
        rule_matches=len(rule_matches),
        flagged_events=len(flagged_events),
        iforest_score=round(iforest_score, 3),
        lstm_score=round(lstm_score, 3) if USE_LSTM_UBA else None,
        combined_score=round(combined_score, 3),
        source_ips=list(source_ips),
        lstm_enabled=USE_LSTM_UBA,
    )

    return Tier1AnomalyResult(
        decision=decision,
        anomaly_score=combined_score,
        flagged_events=flagged_events,
        rule_matches=rule_matches,
        user=user,
        source_ips=list(source_ips),
    )


# Cached Isolation Forest model -- survives across Lambda warm invocations.
# Created once at module level, re-fitted per batch (fit is fast for small N).
# For production with a pre-trained model, load from S3/EFS via joblib here.
_CACHED_IFOREST: IsolationForest | None = None


def _get_iforest() -> IsolationForest:
    """Return a cached IsolationForest instance (created once per container)."""
    global _CACHED_IFOREST
    if _CACHED_IFOREST is None:
        _CACHED_IFOREST = IsolationForest(
            n_estimators=50,
            contamination=0.3,
            random_state=42,
        )
    return _CACHED_IFOREST


def _extract_features(records: list[dict]) -> np.ndarray:
    """Extract numeric feature matrix from CloudTrail records.

    Features: hour-of-day, is_high_risk, is_recon, has_error, unique_ip_index.
    """
    features: list[list[float]] = []
    ip_set: dict[str, int] = {}

    for rec in records:
        event_name = rec.get("eventName", "")
        event_time_str = rec.get("eventTime", "")
        src_ip = rec.get("sourceIPAddress", "")
        error_code = rec.get("errorCode", "")

        hour = 12.0
        try:
            dt = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
            hour = float(dt.hour + dt.minute / 60)
        except (ValueError, AttributeError):
            pass

        is_high_risk = 1.0 if event_name in _HIGH_RISK_EVENTS else 0.0
        is_recon = 1.0 if event_name in _RECON_EVENTS else 0.0
        has_error = 1.0 if error_code else 0.0

        if src_ip not in ip_set:
            ip_set[src_ip] = len(ip_set)
        ip_index = float(ip_set[src_ip])

        features.append([hour, is_high_risk, is_recon, has_error, ip_index])

    return np.array(features, dtype=np.float32)


def _run_isolation_forest(records: list[dict]) -> float:
    """Compute anomaly score using Isolation Forest on log features.

    The IsolationForest instance is cached at module level to avoid
    re-allocation overhead on Lambda warm starts. The model is re-fitted
    per batch since each context window is unique.
    """
    if len(records) < 3:
        return 0.0

    X = _extract_features(records)

    try:
        clf = _get_iforest()
        clf.fit(X)
        scores = clf.decision_function(X)
        min_score = float(np.min(scores))
        return max(0.0, -min_score)
    except Exception:
        logger.warning("tier1_forensic.isolation_forest_failed")
        return 0.0
