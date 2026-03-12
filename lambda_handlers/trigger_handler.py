"""
Analysis Lambda Handler (Tier 2).

Second Lambda in the 2-Lambda pipeline:
  EventBridge -> Tier 1 Filter -> SQS -> [THIS] LangGraph Analysis

Consumes pre-filtered, PII-scrubbed events from the SQS queue
and runs the full LangGraph multi-agent workflow.

Also supports direct EventBridge invocation for backwards compatibility.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from bastion.config import config
from bastion.graph.workflow import build_graph
from bastion.logger import configure_logging, get_logger
from bastion.services.dynamodb import save_report
from bastion.services.pii_scrubber import scrub_event_payload

configure_logging(env=config.environment, log_level=config.log_level)
logger = get_logger(__name__)

TIMEOUT_BUFFER_MS = 120_000  # 2 minutes buffer before Lambda hard-kills


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda handler: consumes events from SQS or direct EventBridge.

    SQS batch mode: processes each record in event["Records"].
    Direct mode (legacy): treats the entire event as a single EventBridge event.
    """
    log = logger.bind(handler="analysis")

    if "Records" in event:
        return _handle_sqs_batch(event, context, log)
    else:
        return _handle_direct_event(event, context, log)


def _handle_sqs_batch(
    event: dict[str, Any],
    context: Any,
    log: Any,
) -> dict[str, Any]:
    """Process a batch of SQS messages, each containing a pre-filtered event."""
    records = event.get("Records", [])
    log.info("analysis.sqs_batch", record_count=len(records))

    results = []
    for record in records:
        remaining = _get_remaining_ms(context)
        if remaining is not None and remaining < TIMEOUT_BUFFER_MS:
            log.warning(
                "analysis.timeout_approaching",
                remaining_ms=remaining,
                processed=len(results),
                total=len(records),
            )
            break

        try:
            body = json.loads(record.get("body", "{}"))
            result = _run_analysis(body, context, log)
            results.append(result)
        except Exception:
            log.exception("analysis.sqs_record_error", message_id=record.get("messageId"))
            results.append({"status": "error", "message_id": record.get("messageId")})

    return {"statusCode": 200, "processed": len(results), "results": results}


def _handle_direct_event(
    event: dict[str, Any],
    context: Any,
    log: Any,
) -> dict[str, Any]:
    """Legacy path: direct EventBridge invocation (no SQS)."""
    from bastion.services.eventbridge import parse_eventbridge_event

    log.info("analysis.direct_event", source=event.get("source"))

    parsed = parse_eventbridge_event(event)
    parsed = scrub_event_payload(parsed)

    return _run_analysis(parsed, context, log)


def _run_analysis(
    parsed_event: dict[str, Any],
    context: Any,
    log: Any,
) -> dict[str, Any]:
    """Run the LangGraph multi-agent workflow on a single event."""
    report_id = str(uuid.uuid4())
    log = log.bind(report_id=report_id)
    log.info("analysis.start", event_type=parsed_event.get("event_type"))

    try:
        graph = build_graph()
        initial_state = {
            "event_payload": parsed_event,
            "event_type": parsed_event.get("event_type", "unknown"),
            "messages": [],
            "next_agent": "",
            "findings": [],
            "iocs": [],
            "iteration_count": 0,
            "error_logs": [],
            "risk_score": None,
            "final_report": None,
            "report_id": report_id,
        }

        remaining = _get_remaining_ms(context)
        if remaining is not None and remaining < TIMEOUT_BUFFER_MS:
            log.warning("analysis.insufficient_time", remaining_ms=remaining)
            _save_partial(report_id, initial_state, "timeout_before_start")
            return {
                "report_id": report_id,
                "status": "timeout_partial",
            }

        result = graph.invoke(initial_state)

        save_report(report_id, {
            "event_type": result.get("event_type"),
            "risk_score": str(result.get("risk_score", 0)),
            "final_report": result.get("final_report", ""),
            "findings_count": len(result.get("findings", [])),
            "findings": result.get("findings", []),
            "error_logs": result.get("error_logs", []),
            "status": "completed",
        })

        log.info(
            "analysis.complete",
            risk_score=result.get("risk_score"),
            findings_count=len(result.get("findings", [])),
        )

        return {
            "report_id": report_id,
            "status": "completed",
            "risk_score": result.get("risk_score"),
            "findings_count": len(result.get("findings", [])),
        }

    except Exception:
        log.exception("analysis.error")
        _save_partial(report_id, {}, "error")
        return {
            "report_id": report_id,
            "status": "error",
        }


def _save_partial(report_id: str, state: dict, reason: str) -> None:
    """Save a partial/failed report to DynamoDB for later inspection."""
    try:
        save_report(report_id, {
            "event_type": state.get("event_type", "unknown"),
            "risk_score": "0",
            "final_report": "",
            "findings_count": len(state.get("findings", [])),
            "findings": state.get("findings", []),
            "error_logs": state.get("error_logs", []),
            "status": f"partial_{reason}",
        })
    except Exception:
        logger.exception("analysis.save_partial_failed", report_id=report_id)


def _get_remaining_ms(context: Any) -> int | None:
    """Get remaining Lambda execution time in milliseconds, or None if unavailable."""
    if context is None:
        return None
    try:
        return context.get_remaining_time_in_millis()
    except (AttributeError, TypeError):
        return None
