"""
Amazon DynamoDB service for storing analysis results and reports.
"""

from __future__ import annotations

from typing import Any

from bastion.config import config
from bastion.logger import get_logger
from bastion.tools.aws_helpers import get_boto3_resource

logger = get_logger(__name__)

_table = None


def _get_table():
    """Lazy-init the DynamoDB table resource."""
    global _table
    if _table is None:
        dynamodb = get_boto3_resource("dynamodb")
        _table = dynamodb.Table(config.dynamodb_table)
    return _table


def save_report(report_id: str, report_data: dict[str, Any]) -> None:
    """
    Save an analysis report to DynamoDB.

    Args:
        report_id: Unique identifier for the report.
        report_data: Full report data including findings, risk score, etc.
    """
    log = logger.bind(service="dynamodb")
    log.info("dynamodb.save_report", report_id=report_id)

    try:
        table = _get_table()
        table.put_item(
            Item={
                "report_id": report_id,
                **report_data,
            }
        )
        log.info("dynamodb.save_report.success", report_id=report_id)
    except Exception:
        log.exception("dynamodb.save_report.error", report_id=report_id)
        raise


def get_report(report_id: str) -> dict[str, Any] | None:
    """
    Retrieve an analysis report from DynamoDB.

    Args:
        report_id: Unique identifier for the report.

    Returns:
        Report data dict or None if not found.
    """
    log = logger.bind(service="dynamodb")
    log.info("dynamodb.get_report", report_id=report_id)

    try:
        table = _get_table()
        response = table.get_item(Key={"report_id": report_id})
        item = response.get("Item")
        if item:
            log.info("dynamodb.get_report.found", report_id=report_id)
        else:
            log.info("dynamodb.get_report.not_found", report_id=report_id)
        return item
    except Exception:
        log.exception("dynamodb.get_report.error", report_id=report_id)
        raise


def list_reports(limit: int = 50) -> list[dict[str, Any]]:
    """
    List recent analysis reports.

    Args:
        limit: Maximum number of reports to return.

    Returns:
        List of report items.
    """
    log = logger.bind(service="dynamodb")
    log.info("dynamodb.list_reports", limit=limit)

    try:
        table = _get_table()
        response = table.scan(Limit=limit)
        items = response.get("Items", [])
        log.info("dynamodb.list_reports.done", count=len(items))
        return items
    except Exception:
        log.exception("dynamodb.list_reports.error")
        raise
