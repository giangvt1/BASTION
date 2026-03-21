"""
Amazon Athena service for querying CloudTrail logs.

Provides SQL query execution against CloudTrail logs stored in S3.
Falls back to direct CloudTrail API lookup when Athena is unavailable.
"""

from __future__ import annotations

import json
import time
from typing import Any

from bastion.config import config
from bastion.logger import get_logger
from bastion.tools.aws_helpers import get_boto3_client

logger = get_logger(__name__)

POLL_INTERVAL_SECONDS = 2
DEFAULT_MAX_WAIT_SECONDS = 60


def query_cloudtrail_athena(
    sql: str,
    database: str | None = None,
    output_location: str | None = None,
    max_wait_seconds: int = DEFAULT_MAX_WAIT_SECONDS,
) -> list[dict[str, Any]]:
    """Execute an Athena SQL query against CloudTrail logs.

    Args:
        sql: SQL query string.
        database: Athena database name (defaults to config).
        output_location: S3 path for query results (defaults to config).
        max_wait_seconds: Maximum time to wait for query completion.
            After this, returns a timeout message instead of crashing,
            so the LLM agent can decide to retry or use a different tool.

    Returns:
        List of result rows as dicts. On timeout, returns a single-item
        list with a ``_timeout`` marker so the agent can handle gracefully.
    """
    log = logger.bind(service="athena")
    resolved_db = database or config.athena_database
    resolved_output = output_location or config.athena_output_bucket
    max_polls = max(1, max_wait_seconds // POLL_INTERVAL_SECONDS)

    log.info(
        "athena.start_query",
        database=resolved_db,
        sql_length=len(sql),
        max_wait_seconds=max_wait_seconds,
    )

    client = get_boto3_client("athena")

    try:
        response = client.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={"Database": resolved_db},
            ResultConfiguration={"OutputLocation": resolved_output},
        )
        query_id = response["QueryExecutionId"]
        log.info("athena.query_started", query_id=query_id)

        elapsed = 0.0
        for attempt in range(max_polls):
            status_resp = client.get_query_execution(QueryExecutionId=query_id)
            state = status_resp["QueryExecution"]["Status"]["State"]

            if state == "SUCCEEDED":
                break
            elif state in ("FAILED", "CANCELLED"):
                reason = status_resp["QueryExecution"]["Status"].get(
                    "StateChangeReason", "Unknown"
                )
                log.error("athena.query_failed", state=state, reason=reason)
                return [{"error": f"Athena query {state}: {reason}. Hint: local environments may miss a data lake, try fallback mechanisms."}]

            time.sleep(POLL_INTERVAL_SECONDS)
            elapsed += POLL_INTERVAL_SECONDS
        else:
            log.warning(
                "athena.query_timeout",
                query_id=query_id,
                elapsed_seconds=elapsed,
                max_wait_seconds=max_wait_seconds,
            )
            return [{
                "_timeout": True,
                "message": (
                    f"Athena query still running after {max_wait_seconds}s. "
                    f"Query ID: {query_id}. Try a narrower time range or "
                    f"use the CloudTrail direct lookup tool instead."
                ),
            }]

        # Fetch results
        result_resp = client.get_query_results(QueryExecutionId=query_id)
        rows = result_resp.get("ResultSet", {}).get("Rows", [])

        if not rows:
            return []

        # First row is headers
        headers = [col.get("VarCharValue", "") for col in rows[0].get("Data", [])]
        results = []
        for row in rows[1:]:
            values = [col.get("VarCharValue", "") for col in row.get("Data", [])]
            results.append(dict(zip(headers, values)))

        log.info("athena.query_complete", rows_returned=len(results))
        return results

    except Exception:
        log.exception("athena.query_error")
        raise


def query_cloudtrail_direct(
    username: str | None = None,
    event_name: str | None = None,
    time_range_hours: int = 24,
    max_results: int = 50,
) -> list[dict[str, Any]]:
    """Query CloudTrail directly via the LookupEvents API.

    Fallback when Athena is unavailable. More limited than SQL queries.

    Args:
        username: Filter by IAM username.
        event_name: Filter by CloudTrail event name.
        time_range_hours: How far back to search.
        max_results: Maximum events to return.

    Returns:
        List of CloudTrail event dicts.
    """
    log = logger.bind(service="cloudtrail")
    log.info(
        "cloudtrail.lookup",
        username=username,
        event_name=event_name,
        hours=time_range_hours,
    )

    from datetime import datetime, timedelta, timezone

    client = get_boto3_client("cloudtrail")
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)

    lookup_attributes = []
    if username:
        lookup_attributes.append({"AttributeKey": "Username", "AttributeValue": username})
    if event_name:
        lookup_attributes.append({"AttributeKey": "EventName", "AttributeValue": event_name})

    try:
        kwargs: dict[str, Any] = {
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": max_results,
        }
        if lookup_attributes:
            kwargs["LookupAttributes"] = lookup_attributes

        response = client.lookup_events(**kwargs)
        events = []
        for event in response.get("Events", []):
            cloud_trail_event = event.get("CloudTrailEvent", "{}")
            try:
                events.append(json.loads(cloud_trail_event))
            except json.JSONDecodeError:
                events.append({"raw": cloud_trail_event})

        log.info("cloudtrail.lookup_complete", events_returned=len(events))
        return events

    except Exception:
        log.exception("cloudtrail.lookup_error")
        raise
