"""
Lambda Trigger Handler.

Entry point for EventBridge → LangGraph workflow invocation.
Deployed as an AWS Lambda function.
"""

from __future__ import annotations

import uuid
from typing import Any

from bastion.config import config
from bastion.graph.workflow import build_graph
from bastion.logger import configure_logging, get_logger
from bastion.services.dynamodb import save_report
from bastion.services.eventbridge import parse_eventbridge_event

# Configure logging on cold start
configure_logging(env=config.environment, log_level=config.log_level)
logger = get_logger(__name__)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda handler: receives EventBridge events, runs the
    LangGraph multi-agent analysis workflow, and stores results.

    Args:
        event: EventBridge event payload.
        context: AWS Lambda context object.

    Returns:
        Dict with report_id and status.
    """
    report_id = str(uuid.uuid4())
    log = logger.bind(report_id=report_id)

    log.info("lambda.trigger.start", event_source=event.get("source"))

    try:
        # Parse EventBridge event
        parsed_event = parse_eventbridge_event(event)

        # Build and invoke graph
        graph = build_graph()
        initial_state = {
            "event_payload": parsed_event,
            "event_type": parsed_event["event_type"],
            "messages": [],
            "next_agent": "",
            "findings": [],
            "iocs": [],
            "iteration_count": 0,
            "risk_score": None,
            "final_report": None,
            "report_id": report_id,
        }

        log.info("lambda.trigger.invoking_graph", event_type=parsed_event["event_type"])
        result = graph.invoke(initial_state)

        # Save results to DynamoDB
        save_report(report_id, {
            "event_type": result.get("event_type"),
            "risk_score": str(result.get("risk_score", 0)),  # DynamoDB doesn't support float
            "final_report": result.get("final_report", ""),
            "findings_count": len(result.get("findings", [])),
            "findings": result.get("findings", []),
            "status": "completed",
        })

        log.info(
            "lambda.trigger.complete",
            risk_score=result.get("risk_score"),
            findings_count=len(result.get("findings", [])),
        )

        return {
            "statusCode": 200,
            "body": {
                "report_id": report_id,
                "status": "completed",
                "risk_score": result.get("risk_score"),
                "findings_count": len(result.get("findings", [])),
            },
        }

    except Exception:
        log.exception("lambda.trigger.error")
        return {
            "statusCode": 500,
            "body": {
                "report_id": report_id,
                "status": "error",
                "message": "Internal analysis error. Check CloudWatch logs.",
            },
        }
