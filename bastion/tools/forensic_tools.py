"""
Legacy forensic analysis tools.

The main forensic tools (cloudtrail_query_tool, mitre_attack_vector_tool,
shared_state_lookup_tool) now live in bastion.agents.forensic_analyst.tools.

This module retains basic CloudTrail parsing utilities used across the system.
"""

from __future__ import annotations

import json
from typing import Any

from bastion.logger import get_logger

logger = get_logger(__name__)


def parse_cloudtrail_records(
    data: dict | str,
    target_error_code: str | None = None,
) -> list[dict[str, Any]]:
    """Parse CloudTrail JSON into a list of records, optionally filtering by error code.

    Args:
        data: CloudTrail JSON as a dict or JSON string.
        target_error_code: If set, only return records with this errorCode.

    Returns:
        List of CloudTrail record dicts.
    """
    if isinstance(data, str):
        data = json.loads(data)

    records = data.get("Records", [])

    if target_error_code:
        records = [r for r in records if r.get("errorCode") == target_error_code]

    logger.info("forensic_tools.parsed_records", total=len(records))
    return records
