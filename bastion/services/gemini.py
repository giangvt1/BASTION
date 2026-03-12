"""
Gemini LLM service for BASTION.

Provides two interfaces:
- call_gemini(): raw text generation for simple prompts
- get_chat_model(): LangChain ChatGoogleGenerativeAI for ReAct tool-calling
"""

from __future__ import annotations

import json
from typing import Any

import requests
from langchain_google_genai import ChatGoogleGenerativeAI

from bastion.config import config
from bastion.logger import get_logger

logger = get_logger(__name__)

_chat_model: ChatGoogleGenerativeAI | None = None


def get_chat_model(
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> ChatGoogleGenerativeAI:
    """Return a LangChain ChatGoogleGenerativeAI instance for tool-calling.

    This model supports ``.bind_tools()`` and is used by ReAct agents.
    The instance is cached for reuse across calls.
    """
    global _chat_model

    resolved_temp = temperature if temperature is not None else config.gemini_temperature
    resolved_max = max_tokens or config.gemini_max_tokens

    if _chat_model is None:
        log = logger.bind(service="gemini")
        log.info(
            "gemini.init_chat_model",
            model=config.gemini_model,
            temperature=resolved_temp,
        )
        _chat_model = ChatGoogleGenerativeAI(
            model=config.gemini_model,
            google_api_key=config.gemini_api_key,
            temperature=resolved_temp,
            max_output_tokens=resolved_max,
        )

    return _chat_model


def call_gemini(
    prompt: str,
    system_prompt: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> str:
    """Send a prompt to Gemini and return the text response.

    Uses REST if ``GEMINI_BASE_URL`` is configured, otherwise the
    LangChain chat model.

    Args:
        prompt: The user message / analysis request.
        system_prompt: Optional system-level instructions.
        max_tokens: Override max output tokens.
        temperature: Override sampling temperature.

    Returns:
        The model's text response.

    Raises:
        RuntimeError: On API errors.
    """
    log = logger.bind(service="gemini")
    resolved_max = max_tokens or config.gemini_max_tokens
    resolved_temp = temperature if temperature is not None else config.gemini_temperature

    base_url = config.gemini_base_url

    if base_url:
        return _call_via_rest(
            prompt, system_prompt, base_url, resolved_max, resolved_temp, log
        )

    return _call_via_langchain(prompt, system_prompt, resolved_max, resolved_temp, log)


def _call_via_rest(
    prompt: str,
    system_prompt: str | None,
    base_url: str,
    max_tokens: int,
    temperature: float,
    log: Any,
) -> str:
    """Call Gemini through a custom REST proxy endpoint."""
    url = f"{base_url.rstrip('/')}/models/{config.gemini_model}:generateContent"

    contents: list[dict] = []
    if system_prompt:
        contents.append({"role": "user", "parts": [{"text": system_prompt}]})
        contents.append({"role": "model", "parts": [{"text": "Understood."}]})
    contents.append({"role": "user", "parts": [{"text": prompt}]})

    payload = {
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": temperature,
        },
    }

    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": config.gemini_api_key,
    }

    log.info("gemini.rest_call", url=url, prompt_length=len(prompt))
    resp = requests.post(url, json=payload, headers=headers, timeout=120)
    resp.raise_for_status()

    data = resp.json()
    try:
        text = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise RuntimeError(
            f"Unexpected Gemini response: {json.dumps(data, indent=2)[:500]}"
        ) from exc

    log.info("gemini.rest_response", response_length=len(text))
    return text


def _call_via_langchain(
    prompt: str,
    system_prompt: str | None,
    max_tokens: int,
    temperature: float,
    log: Any,
) -> str:
    """Call Gemini through the LangChain ChatGoogleGenerativeAI wrapper."""
    from langchain_core.messages import HumanMessage, SystemMessage

    model = get_chat_model(temperature=temperature, max_tokens=max_tokens)

    messages: list = []
    if system_prompt:
        messages.append(SystemMessage(content=system_prompt))
    messages.append(HumanMessage(content=prompt))

    log.info("gemini.langchain_call", prompt_length=len(prompt))
    response = model.invoke(messages)
    text = response.content

    log.info("gemini.langchain_response", response_length=len(text))
    return text
