"""
BASTION centralized configuration.

All settings are loaded from environment variables with sensible defaults.
Use a .env file for local development (loaded via python-dotenv).
"""

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


@dataclass
class BastionConfig:
    """Centralized configuration for the BASTION system."""

    # ── AWS General ──
    aws_region: str = field(
        default_factory=lambda: os.getenv("AWS_REGION", "us-east-1")
    )

    # ── S3 (Input Layer) ──
    s3_bucket: str = field(
        default_factory=lambda: os.getenv("BASTION_S3_BUCKET", "bastion-data-lake")
    )

    # ── DynamoDB (Storage Layer) ──
    dynamodb_table: str = field(
        default_factory=lambda: os.getenv("BASTION_DYNAMODB_TABLE", "bastion-results")
    )

    # ── Gemini (LLM) ──
    gemini_api_key: str = field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "")
    )
    gemini_model: str = field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    )
    gemini_max_tokens: int = field(
        default_factory=lambda: int(os.getenv("GEMINI_MAX_TOKENS", "8192"))
    )
    gemini_temperature: float = field(
        default_factory=lambda: float(os.getenv("GEMINI_TEMPERATURE", "0.1"))
    )
    gemini_base_url: str = field(
        default_factory=lambda: os.getenv("GEMINI_BASE_URL", "")
    )

    # ── FAISS (Pre-built index loading from S3) ──
    faiss_index_s3_prefix: str = field(
        default_factory=lambda: os.getenv("FAISS_INDEX_S3_PREFIX", "")
    )

    # ── SQS (Buffer Queue between Tier 1 filter and LangGraph core) ──
    sqs_queue_url: str = field(
        default_factory=lambda: os.getenv("BASTION_SQS_QUEUE_URL", "")
    )

    # ── Athena (Forensic queries) ──
    athena_database: str = field(
        default_factory=lambda: os.getenv("ATHENA_DATABASE", "bastion_cloudtrail")
    )
    athena_output_bucket: str = field(
        default_factory=lambda: os.getenv(
            "ATHENA_OUTPUT_BUCKET", "s3://bastion-athena-results/"
        )
    )

    # ── Logging ──
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "DEBUG")
    )
    environment: str = field(
        default_factory=lambda: os.getenv("ENVIRONMENT", "development")
    )


# Singleton config instance
config = BastionConfig()
