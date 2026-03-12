"""
Tier 1 Anomaly Detection Filter for Forensic Analyst.

Programmatic, no LLM. Combines:
1. Rule-based checks for known suspicious CloudTrail events
2. Isolation Forest for statistical anomaly detection on log features
"""

from __future__ import annotations

from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

from bastion.agents.forensic_analyst.models import Tier1AnomalyResult
from bastion.logger import get_logger

logger = get_logger(__name__)


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
    """Run Tier 1 anomaly detection on CloudTrail log context.

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
            user = identity.get("userName", "") or identity.get("principalId", "")
            if user:
                break

    # ── Rule-based checks ───────────────────────────────────────────────
    rule_matches: list[str] = []
    flagged_events: list[dict] = []
    source_ips: set[str] = set()

    for rec in records:
        event_name = rec.get("eventName", "")
        src_ip = rec.get("sourceIPAddress", "")
        error_code = rec.get("errorCode", "")
        event_time = rec.get("eventTime", "")

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

        recon_count = sum(
            1 for r in records if r.get("eventName") in _RECON_EVENTS
        )
        if recon_count >= 3 and f"recon_burst:{recon_count}" not in rule_matches:
            rule_matches.append(f"recon_burst:{recon_count}")

    # ── Isolation Forest anomaly detection ──────────────────────────────
    anomaly_score = _run_isolation_forest(records)

    if anomaly_score > 0.5:
        rule_matches.append(f"isolation_forest_anomaly:{anomaly_score:.2f}")

    # ── Decision ────────────────────────────────────────────────────────
    decision = "ANOMALY" if rule_matches else "NORMAL"

    log.info(
        "tier1_forensic.result",
        decision=decision,
        rule_matches=len(rule_matches),
        flagged_events=len(flagged_events),
        anomaly_score=round(anomaly_score, 3),
        source_ips=list(source_ips),
    )

    return Tier1AnomalyResult(
        decision=decision,
        anomaly_score=anomaly_score,
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
