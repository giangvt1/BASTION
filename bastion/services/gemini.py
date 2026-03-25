"""
Gemini LLM service for BASTION.

Provides two interfaces:
- call_gemini(): raw text generation for simple prompts
- get_chat_model(): LangChain ChatGoogleGenerativeAI for ReAct tool-calling

Includes:
- Retry with exponential backoff (max 3 retries)
- LLM rate limiting (max 12 calls/min to stay under Gemini free tier)
"""

from __future__ import annotations

import json
import time
from collections import deque
from typing import Any

import requests
from langchain_google_genai import ChatGoogleGenerativeAI

from bastion.config import config
from bastion.logger import get_logger

logger = get_logger(__name__)

_chat_model: ChatGoogleGenerativeAI | None = None

# ── LLM Rate Limiter ──
_LLM_MAX_CALLS_PER_MINUTE = 12  # Gemini free tier = 15 RPM, leave 3 headroom
_LLM_MAX_RETRIES = 3
_LLM_RETRY_BACKOFF_BASE = 1.0  # seconds: 1s → 2s → 4s
_llm_call_log: deque = deque()


def _wait_for_rate_limit() -> None:
    """Block until we're under the LLM rate limit."""
    now = time.time()
    cutoff = now - 60
    while _llm_call_log and _llm_call_log[0] < cutoff:
        _llm_call_log.popleft()

    if len(_llm_call_log) >= _LLM_MAX_CALLS_PER_MINUTE:
        wait_time = _llm_call_log[0] + 60 - now + 0.1
        log = logger.bind(service="gemini")
        log.warning(
            "gemini.rate_limit_wait",
            calls_in_window=len(_llm_call_log),
            wait_seconds=round(wait_time, 1),
        )
        time.sleep(max(0, wait_time))

    _llm_call_log.append(time.time())


def _is_retryable(exc: Exception) -> bool:
    """Check if an exception is worth retrying."""
    if isinstance(exc, requests.exceptions.HTTPError):
        status = exc.response.status_code if exc.response is not None else 0
        return status in (429, 500, 502, 503)
    if isinstance(exc, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)):
        return True
    err_msg = str(exc).lower()
    return any(kw in err_msg for kw in ("429", "resource exhausted", "quota", "rate limit", "timeout"))


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
    """Send a prompt to Gemini with retry + rate limiting.

    - Retries up to 3 times with exponential backoff (1s → 2s → 4s)
    - Rate-limited to 12 calls/minute
    """
    log = logger.bind(service="gemini")
    resolved_max = max_tokens or config.gemini_max_tokens
    resolved_temp = temperature if temperature is not None else config.gemini_temperature

    base_url = config.gemini_base_url

    last_exc: Exception | None = None
    for attempt in range(_LLM_MAX_RETRIES + 1):
        # Rate limit gate
        _wait_for_rate_limit()

        try:
            if base_url:
                return _call_via_rest(
                    prompt, system_prompt, base_url, resolved_max, resolved_temp, log
                )
            return _call_via_langchain(prompt, system_prompt, resolved_max, resolved_temp, log)
        except Exception as exc:
            last_exc = exc
            if attempt < _LLM_MAX_RETRIES and _is_retryable(exc):
                wait = _LLM_RETRY_BACKOFF_BASE * (2 ** attempt)
                log.warning(
                    "gemini.retry",
                    attempt=attempt + 1,
                    max_retries=_LLM_MAX_RETRIES,
                    wait_seconds=wait,
                    error=str(exc)[:200],
                )
                time.sleep(wait)
            else:
                break

    raise RuntimeError(
        f"Gemini call failed after {_LLM_MAX_RETRIES} retries: {last_exc}"
    ) from last_exc


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
