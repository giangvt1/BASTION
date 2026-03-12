"""
Amazon Bedrock LLM client.

Provides a unified interface to invoke foundation models (Claude, LLaMA 3)
via boto3's bedrock-runtime API.
"""

from __future__ import annotations

import json
from typing import Any

from bastion.config import config
from bastion.logger import get_logger
from bastion.tools.aws_helpers import get_boto3_client

logger = get_logger(__name__)

_bedrock_client = None


def _get_client():
    """Lazy-init the Bedrock Runtime client."""
    global _bedrock_client
    if _bedrock_client is None:
        _bedrock_client = get_boto3_client("bedrock-runtime")
    return _bedrock_client


def invoke_llm(
    system_prompt: str,
    user_message: str,
    model_id: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> str:
    """
    Invoke an LLM on Amazon Bedrock.

    Uses the Converse API for model-agnostic invocation.

    Args:
        system_prompt: System-level instructions for the model.
        user_message: The user/context message to process.
        model_id: Override model ID (defaults to config).
        max_tokens: Override max tokens (defaults to config).
        temperature: Override temperature (defaults to config).

    Returns:
        The model's text response.

    Raises:
        Exception: On Bedrock API errors (logged with full context).
    """
    log = logger.bind(service="bedrock")
    resolved_model = model_id or config.bedrock_model_id
    resolved_max_tokens = max_tokens or config.bedrock_max_tokens
    resolved_temperature = temperature if temperature is not None else config.bedrock_temperature

    log.info(
        "bedrock.invoke",
        model=resolved_model,
        system_prompt_length=len(system_prompt),
        user_message_length=len(user_message),
    )

    try:
        client = _get_client()
        response = client.converse(
            modelId=resolved_model,
            system=[{"text": system_prompt}],
            messages=[
                {
                    "role": "user",
                    "content": [{"text": user_message}],
                }
            ],
            inferenceConfig={
                "maxTokens": resolved_max_tokens,
                "temperature": resolved_temperature,
            },
        )

        # Extract text from response
        output_message = response.get("output", {}).get("message", {})
        content_blocks = output_message.get("content", [])
        result_text = ""
        for block in content_blocks:
            if "text" in block:
                result_text += block["text"]

        # Log usage stats
        usage = response.get("usage", {})
        log.info(
            "bedrock.response",
            input_tokens=usage.get("inputTokens"),
            output_tokens=usage.get("outputTokens"),
            response_length=len(result_text),
            stop_reason=response.get("stopReason"),
        )

        return result_text

    except Exception:
        log.exception("bedrock.invoke_error", model=resolved_model)
        raise
