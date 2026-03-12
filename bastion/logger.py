"""
BASTION Logging & Observability.

Uses structlog + rich for:
- Structured key-value logs (easy filtering by agent, event_id, severity)
- Beautiful stacktraces with syntax highlighting (Rich traceback)
- JSON output for production (CloudWatch / ELK / Datadog compatible)
- Context binding (bind agent_name, event_id once → auto-included in all logs)
"""

import logging
import sys

import structlog
from rich.traceback import install as install_rich_traceback


# ═══════════════════════════════════════════════════════════════════════
#  Rich Traceback — beautiful stacktraces for all uncaught exceptions
# ═══════════════════════════════════════════════════════════════════════
install_rich_traceback(
    show_locals=True,
    width=120,
    extra_lines=3,
    theme="monokai",
)


def configure_logging(
    env: str = "development",
    log_level: str = "DEBUG",
) -> None:
    """
    Configure structlog for the entire BASTION system.

    Args:
        env: "development" for rich console output, "production" for JSON.
        log_level: Standard Python log level string (DEBUG, INFO, WARNING, etc.)
    """
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if env == "production":
        # Production: JSON lines for CloudWatch / log aggregators
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        # Development: Rich console with colors and pretty exceptions
        renderer = structlog.dev.ConsoleRenderer(
            colors=True,
            exception_formatter=structlog.dev.rich_traceback,
        )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging for boto3 and other third-party libraries
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.DEBUG),
    )

    # Suppress noisy boto3/botocore logs unless WARNING+
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Create a logger with context binding support.

    Usage::

        logger = get_logger(__name__)
        logger.info("event.name", key1="value1", key2="value2")

        # Bind context for a session — auto-included in all subsequent logs
        log = logger.bind(event_id="abc-123", agent="supervisor")
        log.info("processing")  # includes event_id + agent automatically

    Args:
        name: Logger name, typically ``__name__``.

    Returns:
        A structlog BoundLogger instance.
    """
    return structlog.get_logger(name)
