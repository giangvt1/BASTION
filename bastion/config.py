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

    # ── Amazon Bedrock (LLM) ──
    bedrock_model_id: str = field(
        default_factory=lambda: os.getenv(
            "BEDROCK_MODEL_ID",
            "anthropic.claude-3-sonnet-20240229-v1:0",
        )
    )
    bedrock_max_tokens: int = field(
        default_factory=lambda: int(os.getenv("BEDROCK_MAX_TOKENS", "4096"))
    )
    bedrock_temperature: float = field(
        default_factory=lambda: float(os.getenv("BEDROCK_TEMPERATURE", "0.1"))
    )

    # ── VectorDB ──
    vectordb_provider: str = field(
        default_factory=lambda: os.getenv("VECTORDB_PROVIDER", "pinecone")
    )
    pinecone_api_key: str = field(
        default_factory=lambda: os.getenv("PINECONE_API_KEY", "")
    )
    pinecone_index: str = field(
        default_factory=lambda: os.getenv("PINECONE_INDEX", "bastion-threats")
    )

    # ── Logging ──
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "DEBUG")
    )
    environment: str = field(
        default_factory=lambda: os.getenv("ENVIRONMENT", "development")
    )


# Singleton config instance — import this throughout the project
config = BastionConfig()
