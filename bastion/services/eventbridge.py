"""
Amazon EventBridge integration for the Trigger Layer.

Handles event parsing and validation from EventBridge triggers.
"""

from __future__ import annotations

from typing import Any

from bastion.logger import get_logger

logger = get_logger(__name__)


def parse_eventbridge_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Parse and validate an EventBridge event into BASTION's internal format.

    Args:
        event: Raw EventBridge event dict.

    Returns:
        Normalized event dict with keys: event_type, source, detail, s3_key, etc.
    """
    log = logger.bind(service="eventbridge")
    log.info(
        "eventbridge.parse",
        source=event.get("source"),
        detail_type=event.get("detail-type"),
    )

    detail = event.get("detail", {})
    source = event.get("source", "")

    # Determine event type from source
    if "s3" in source.lower():
        event_type = _classify_s3_event(detail)
    elif "cloudtrail" in source.lower():
        event_type = "cloudtrail"
    else:
        event_type = "unknown"

    parsed = {
        "event_type": event_type,
        "source": source,
        "detail": detail,
        "raw_event": event,
    }

    # Extract S3 key if present
    s3_key = _extract_s3_key(detail)
    if s3_key:
        parsed["s3_key"] = s3_key

    log.info("eventbridge.parsed", event_type=event_type, has_s3_key=bool(s3_key))
    return parsed


def _classify_s3_event(detail: dict) -> str:
    """Classify an S3 event based on the uploaded file extension."""
    s3_key = _extract_s3_key(detail)
    if not s3_key:
        return "s3_upload"

    if s3_key.endswith(".eml"):
        return "email"
    elif s3_key.endswith(".json"):
        return "cloudtrail"
    else:
        return "s3_upload"


def _extract_s3_key(detail: dict) -> str | None:
    """Extract S3 object key from event detail."""
    try:
        return detail["requestParameters"]["key"]
    except (KeyError, TypeError):
        pass
    try:
        return detail["object"]["key"]
    except (KeyError, TypeError):
        pass
    return None
