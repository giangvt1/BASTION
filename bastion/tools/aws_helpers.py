"""
AWS helper utilities.

Common boto3 wrapper functions used across multiple tools and services.
"""

from __future__ import annotations

import boto3
from botocore.config import Config as BotoConfig

from bastion.config import config
from bastion.logger import get_logger

logger = get_logger(__name__)

# Shared boto3 config with retries
_boto_config = BotoConfig(
    region_name=config.aws_region,
    retries={"max_attempts": 3, "mode": "adaptive"},
)


def get_boto3_client(service_name: str):
    """
    Create a boto3 client with standard BASTION configuration.

    Args:
        service_name: AWS service name (e.g., "s3", "dynamodb", "bedrock-runtime").

    Returns:
        A configured boto3 client.
    """
    logger.debug("aws_helpers.create_client", service=service_name)
    return boto3.client(service_name, config=_boto_config)


def get_boto3_resource(service_name: str):
    """
    Create a boto3 resource with standard BASTION configuration.

    Args:
        service_name: AWS service name (e.g., "dynamodb").

    Returns:
        A configured boto3 resource.
    """
    logger.debug("aws_helpers.create_resource", service=service_name)
    return boto3.resource(service_name, config=_boto_config)
