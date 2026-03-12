"""
Amazon S3 service for the Input Layer.

Handles retrieval of suspicious files (.eml, .json) from the data lake.
"""

from __future__ import annotations

from bastion.config import config
from bastion.logger import get_logger
from bastion.tools.aws_helpers import get_boto3_client

logger = get_logger(__name__)

_s3_client = None


def _get_client():
    """Lazy-init S3 client."""
    global _s3_client
    if _s3_client is None:
        _s3_client = get_boto3_client("s3")
    return _s3_client


def get_object(key: str, bucket: str | None = None) -> bytes:
    """
    Retrieve an object from S3.

    Args:
        key: S3 object key.
        bucket: Override bucket name (defaults to config).

    Returns:
        Raw bytes of the S3 object.
    """
    resolved_bucket = bucket or config.s3_bucket
    log = logger.bind(service="s3")
    log.info("s3.get_object", bucket=resolved_bucket, key=key)

    try:
        client = _get_client()
        response = client.get_object(Bucket=resolved_bucket, Key=key)
        data = response["Body"].read()
        log.info("s3.get_object.success", size_bytes=len(data))
        return data
    except Exception:
        log.exception("s3.get_object.error", bucket=resolved_bucket, key=key)
        raise


def list_objects(prefix: str, bucket: str | None = None) -> list[str]:
    """
    List object keys under a prefix.

    Args:
        prefix: S3 key prefix to list.
        bucket: Override bucket name (defaults to config).

    Returns:
        List of S3 object keys.
    """
    resolved_bucket = bucket or config.s3_bucket
    log = logger.bind(service="s3")
    log.info("s3.list_objects", bucket=resolved_bucket, prefix=prefix)

    try:
        client = _get_client()
        response = client.list_objects_v2(
            Bucket=resolved_bucket,
            Prefix=prefix,
        )
        keys = [obj["Key"] for obj in response.get("Contents", [])]
        log.info("s3.list_objects.done", count=len(keys))
        return keys
    except Exception:
        log.exception("s3.list_objects.error", bucket=resolved_bucket, prefix=prefix)
        raise
