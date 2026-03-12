"""
Lambda API Handler.

Entry point for API Gateway → query analysis results from DynamoDB.
Deployed as an AWS Lambda function.
"""

from __future__ import annotations

import json
from typing import Any

from bastion.config import config
from bastion.logger import configure_logging, get_logger
from bastion.services.dynamodb import get_report, list_reports

# Configure logging on cold start
configure_logging(env=config.environment, log_level=config.log_level)
logger = get_logger(__name__)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda handler for API Gateway requests.

    Supports:
    - GET /reports          → list recent reports
    - GET /reports/{id}     → get a specific report

    Args:
        event: API Gateway proxy event.
        context: AWS Lambda context object.

    Returns:
        API Gateway proxy response.
    """
    log = logger.bind(handler="api")
    http_method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    path_params = event.get("pathParameters") or {}

    log.info("lambda.api.request", method=http_method, path=path)

    try:
        report_id = path_params.get("id")

        if report_id:
            # GET /reports/{id}
            report = get_report(report_id)
            if report:
                return _response(200, report)
            else:
                return _response(404, {"error": "Report not found", "report_id": report_id})
        else:
            # GET /reports
            reports = list_reports(limit=50)
            return _response(200, {"reports": reports, "count": len(reports)})

    except Exception:
        log.exception("lambda.api.error")
        return _response(500, {"error": "Internal server error"})


def _response(status_code: int, body: Any) -> dict:
    """Build an API Gateway proxy response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }
