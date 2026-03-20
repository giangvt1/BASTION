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

    # ── Pinecone (Vector Store) ──
    pinecone_api_key: str = field(
        default_factory=lambda: os.getenv("PINECONE_API_KEY", "")
    )
    pinecone_index_name: str = field(
        default_factory=lambda: os.getenv("PINECONE_INDEX_NAME", "bastion-vectors")
    )
    pinecone_cloud: str = field(
        default_factory=lambda: os.getenv("PINECONE_CLOUD", "aws")
    )
    pinecone_region: str = field(
        default_factory=lambda: os.getenv("PINECONE_REGION", "us-east-1")
    )
    pinecone_dimension: int = field(
        default_factory=lambda: int(os.getenv("PINECONE_DIMENSION", "384"))
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

    # ── ML Models (Feature Flags) ──
    use_ml_classifier: bool = field(
        default_factory=lambda: os.getenv("BASTION_USE_ML_CLASSIFIER", "true").lower() == "true"
    )
    use_semantic_embeddings: bool = field(
        default_factory=lambda: os.getenv("BASTION_USE_SEMANTIC_EMBEDDINGS", "true").lower() == "true"
    )
    use_lstm_uba: bool = field(
        default_factory=lambda: os.getenv("BASTION_USE_LSTM_UBA", "true").lower() == "true"
    )
    use_semantic_analyzer: bool = field(
        default_factory=lambda: os.getenv("BASTION_USE_SEMANTIC_ANALYZER", "false").lower() == "true"
    )
    semantic_analyzer_threshold: float = field(
        default_factory=lambda: float(os.getenv("BASTION_SEMANTIC_ANALYZER_THRESHOLD", "0.8"))
    )
    # Note: semantic_analyzer replaces LLM in Tier 2 (experimental, requires training)

    # ── Logging ──
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "DEBUG")
    )
    environment: str = field(
        default_factory=lambda: os.getenv("ENVIRONMENT", "development")
    )


# Singleton config instance
config = BastionConfig()
