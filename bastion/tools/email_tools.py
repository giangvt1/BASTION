"""
Email analysis tools.

Provides functions for extracting IOCs from .eml files:
- URLs, domains, IP addresses
- Header analysis (SPF, DKIM, DMARC)
- Attachment inspection

These can be used as LangChain tools or called directly by agents.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_core.tools import tool

from bastion.logger import get_logger

logger = get_logger(__name__)

# Common regex patterns
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)
DOMAIN_PATTERN = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}",
)
IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)


@tool
def extract_urls(text: str) -> list[str]:
    """Extract all URLs from the given text content."""
    logger.debug("email_tools.extract_urls", text_length=len(text))
    urls = URL_PATTERN.findall(text)
    logger.info("email_tools.extract_urls.done", count=len(urls))
    return list(set(urls))


@tool
def extract_domains(text: str) -> list[str]:
    """Extract all domain names from the given text content."""
    logger.debug("email_tools.extract_domains", text_length=len(text))
    domains = DOMAIN_PATTERN.findall(text)
    logger.info("email_tools.extract_domains.done", count=len(domains))
    return list(set(domains))


@tool
def extract_ips(text: str) -> list[str]:
    """Extract all IPv4 addresses from the given text content."""
    logger.debug("email_tools.extract_ips", text_length=len(text))
    ips = IP_PATTERN.findall(text)
    logger.info("email_tools.extract_ips.done", count=len(ips))
    return list(set(ips))


def parse_eml_file(raw_bytes: bytes) -> dict[str, Any]:
    """
    Parse a raw .eml file into structured components.

    Returns:
        Dict with keys: headers, body, attachments, metadata
    """
    # TODO: Implement full .eml parsing using mail-parser
    logger.info("email_tools.parse_eml", size_bytes=len(raw_bytes))
    return {
        "headers": {},
        "body": "",
        "attachments": [],
        "metadata": {},
    }
