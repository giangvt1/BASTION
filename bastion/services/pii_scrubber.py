"""
PII Scrubber for BASTION.

Masks personally identifiable information (PII) and sensitive data
before it reaches LLM agents. Required for PCI-DSS compliance in
banking environments.

Supported PII types:
- Credit card numbers (Visa, MasterCard, Amex, etc.)
- Social Security Numbers (SSN)
- Email addresses
- Phone numbers (US/international formats)
- AWS access keys (AKIA...)
- AWS account IDs (12-digit, context-aware)
- Internal/private IP addresses (RFC 1918)
"""

from __future__ import annotations

import copy
import re
from typing import Any

from bastion.logger import get_logger

logger = get_logger(__name__)

# ── Pattern definitions ──────────────────────────────────────────────

_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "credit_card",
        re.compile(
            r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"
        ),
        "[CARD_REDACTED]",
    ),
    (
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "[SSN_REDACTED]",
    ),
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "[AWS_KEY_REDACTED]",
    ),
    (
        "aws_secret_key",
        re.compile(r"(?<=['\"\s=:])[A-Za-z0-9/+=]{40}(?=['\"\s,}]|$)"),
        "[AWS_SECRET_REDACTED]",
    ),
    (
        "email",
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        "[EMAIL_REDACTED]",
    ),
    (
        "phone",
        re.compile(
            r"(?<!\d)"
            r"(?:\+?\d{1,3}[\s\-]?)?"
            r"(?:\(?\d{2,4}\)?[\s\-]?)?"
            r"\d{3,4}[\s\-]?\d{4}"
            r"(?!\d)"
        ),
        "[PHONE_REDACTED]",
    ),
    (
        "internal_ip",
        re.compile(
            r"\b(?:"
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r")\b"
        ),
        "[INTERNAL_IP_REDACTED]",
    ),
    (
        "aws_account_id",
        re.compile(
            r"(?:account[_\-\s]?(?:id)?|arn:aws)[:\s\"']*(\d{12})\b"
        ),
        "[ACCT_REDACTED]",
    ),
]

# Fields that should never be scrubbed (structural/routing keys)
_SKIP_KEYS = frozenset({
    "event_type", "source", "detail-type", "version", "region",
    "eventName", "eventSource", "eventCategory", "eventType",
    "readOnly", "managementEvent",
})


def scrub_text(text: str) -> str:
    """Apply all PII patterns to a single string.

    Args:
        text: Raw text that may contain PII.

    Returns:
        Text with PII replaced by redaction tokens.
    """
    result = text
    for name, pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def scrub_event_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Deep-walk an event payload dict and scrub all string values.

    Creates a deep copy so the original payload is not mutated.
    Structural keys (event_type, eventName, etc.) are preserved.

    Args:
        payload: Raw event payload dict.

    Returns:
        A new dict with PII-scrubbed string values.
    """
    scrubbed = copy.deepcopy(payload)
    count = _scrub_recursive(scrubbed, depth=0)
    if count > 0:
        logger.info("pii_scrubber.scrubbed", redactions=count)
    return scrubbed


def _scrub_recursive(obj: Any, depth: int = 0, parent_key: str = "") -> int:
    """Walk a nested structure in-place, scrubbing string values.

    Returns the total number of redactions applied.
    """
    if depth > 20:
        return 0

    count = 0

    if isinstance(obj, dict):
        for key in obj:
            if key in _SKIP_KEYS:
                continue
            val = obj[key]
            if isinstance(val, str):
                scrubbed = scrub_text(val)
                if scrubbed != val:
                    obj[key] = scrubbed
                    count += 1
            elif isinstance(val, (dict, list)):
                count += _scrub_recursive(val, depth + 1, parent_key=key)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str):
                scrubbed = scrub_text(item)
                if scrubbed != item:
                    obj[i] = scrubbed
                    count += 1
            elif isinstance(item, (dict, list)):
                count += _scrub_recursive(item, depth + 1, parent_key=parent_key)

    return count
