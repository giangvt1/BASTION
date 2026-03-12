"""
Tier 1 Filter Lambda Handler.

First Lambda in the 2-Lambda pipeline:
  EventBridge -> [THIS] Tier 1 Filter + PII Scrub -> SQS -> Analysis Lambda

Responsibilities:
1. Receive raw events from EventBridge
2. Run lightweight static filters (rule-based, no LLM)
3. Drop noise (~99% of benign events)
4. Scrub PII from suspicious events
5. Push surviving events to SQS for deep analysis
"""

from __future__ import annotations

import json
from typing import Any

from bastion.config import config
from bastion.logger import configure_logging, get_logger
from bastion.services.eventbridge import parse_eventbridge_event
from bastion.services.pii_scrubber import scrub_event_payload
from bastion.tools.aws_helpers import get_boto3_client

configure_logging(env=config.environment, log_level=config.log_level)
logger = get_logger(__name__)

# CloudTrail API names that always warrant investigation
HIGH_RISK_EVENTS = frozenset({
    "ConsoleLogin", "AssumeRole", "AssumeRoleWithSAML",
    "AssumeRoleWithWebIdentity", "GetFederationToken",
    "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
    "PutUserPolicy", "AttachUserPolicy", "AttachRolePolicy",
    "CreateRole", "PutRolePolicy",
    "StopLogging", "DeleteTrail", "UpdateTrail",
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RunInstances", "CreateFunction20150331",
    "PutBucketPolicy", "PutBucketAcl",
    "DeleteBucket", "DeleteObject",
})

# Reconnaissance API names (suspicious in bursts)
RECON_EVENTS = frozenset({
    "ListBuckets", "ListUsers", "ListRoles", "ListAccessKeys",
    "GetBucketAcl", "GetBucketPolicy", "DescribeInstances",
    "DescribeSecurityGroups", "ListFunctions20150331",
})


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda handler: EventBridge -> Tier 1 filter -> SQS.

    Args:
        event: Raw EventBridge event.
        context: AWS Lambda context.

    Returns:
        Dict indicating whether event was forwarded or dropped.
    """
    log = logger.bind(handler="tier1_filter")
    log.info("tier1.received", source=event.get("source"))

    try:
        parsed = parse_eventbridge_event(event)
        event_type = parsed.get("event_type", "unknown")
        detail = parsed.get("detail", {})

        is_suspicious = False
        reasons: list[str] = []

        if event_type == "email":
            is_suspicious = True
            reasons.append("email_upload_always_suspicious")

        elif event_type == "cloudtrail":
            is_suspicious, reasons = _filter_cloudtrail(detail)

        elif event_type == "s3_upload":
            is_suspicious = True
            reasons.append("unknown_s3_upload")

        else:
            log.info("tier1.unknown_type_dropped", event_type=event_type)
            return {"action": "dropped", "reason": "unknown_event_type"}

        if not is_suspicious:
            log.info("tier1.clean_dropped", event_type=event_type)
            return {"action": "dropped", "reason": "clean"}

        # Scrub PII before forwarding
        scrubbed = scrub_event_payload(parsed)

        # Push to SQS
        queue_url = config.sqs_queue_url
        if not queue_url:
            log.error("tier1.no_sqs_queue_url")
            return {"action": "error", "reason": "sqs_queue_url_not_configured"}

        sqs = get_boto3_client("sqs")
        sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(scrubbed, default=str),
            MessageAttributes={
                "event_type": {
                    "DataType": "String",
                    "StringValue": event_type,
                },
                "filter_reasons": {
                    "DataType": "String",
                    "StringValue": ",".join(reasons),
                },
            },
        )

        log.info(
            "tier1.forwarded_to_sqs",
            event_type=event_type,
            reasons=reasons,
        )
        return {"action": "forwarded", "event_type": event_type, "reasons": reasons}

    except Exception:
        log.exception("tier1.error")
        return {"action": "error", "reason": "internal_error"}


def _filter_cloudtrail(detail: dict) -> tuple[bool, list[str]]:
    """Apply lightweight rule-based filter to a CloudTrail event.

    Returns (is_suspicious, list_of_reasons).
    """
    reasons: list[str] = []
    records = detail.get("Records", detail.get("context_logs", {}).get("Records", []))

    if not records and "eventName" in detail:
        records = [detail]

    for record in records:
        event_name = record.get("eventName", "")
        error_code = record.get("errorCode", "")

        if event_name in HIGH_RISK_EVENTS:
            reasons.append(f"high_risk_api:{event_name}")

        if event_name in RECON_EVENTS:
            reasons.append(f"recon_api:{event_name}")

        if error_code in ("AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess"):
            reasons.append(f"access_denied:{event_name}")

    return bool(reasons), reasons
