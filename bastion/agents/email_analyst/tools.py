"""
ReAct tools for the Email Analyst Agent.

These are ``@tool`` decorated functions that the LLM can invoke
during the Thought-Action-Observation loop. Each tool performs
a specific analysis task and returns structured results.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

import numpy as np
import tldextract
from langchain_core.tools import tool

from bastion.logger import get_logger
from bastion.vector_store.embeddings import get_email_embedding
from bastion.vector_store.faiss_client import search_index

logger = get_logger(__name__)

# ── URL regex ───────────────────────────────────────────────────────────

_URL_RE = re.compile(r"https?://[^\s\"'<>\]\)]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ── Known suspicious TLDs ──────────────────────────────────────────────

_SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "pw", "buzz", "club",
    "work", "icu", "cam", "rest", "surf", "monster",
}

# ── Common bank brand names for typo-squatting detection ────────────────

_BRAND_NAMES = {
    "chase", "wellsfargo", "bankofamerica", "citibank", "paypal",
    "amazon", "microsoft", "apple", "google", "facebook", "netflix",
}


@tool
def extract_eml_components(eml_content: str) -> dict[str, Any]:
    """Parse raw .eml email content into structured components.

    Extracts headers (From, To, Subject, Date, Message-ID, X-Mailer),
    body text, and metadata for further analysis.

    Args:
        eml_content: The raw text content of the .eml file.

    Returns:
        Dict with keys: headers, body_text, sender, subject, metadata.
    """
    log = logger.bind(tool="extract_eml_components")
    log.info("tool.extracting_eml", content_length=len(eml_content))

    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False

    for line in eml_content.split("\n"):
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue
            if ":" in line and not line.startswith(" ") and not line.startswith("\t"):
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
        else:
            body_lines.append(line)

    body_text = "\n".join(body_lines).strip()
    sender = headers.get("From", "")
    subject = headers.get("Subject", "")

    result = {
        "headers": headers,
        "body_text": body_text,
        "sender": sender,
        "subject": subject,
        "metadata": {
            "message_id": headers.get("Message-ID", ""),
            "date": headers.get("Date", ""),
            "x_mailer": headers.get("X-Mailer", ""),
            "content_type": headers.get("Content-Type", ""),
            "mime_version": headers.get("MIME-Version", ""),
        },
    }

    log.info(
        "tool.eml_extracted",
        sender=sender,
        subject=subject[:80],
        body_length=len(body_text),
        header_count=len(headers),
    )
    return result


@tool
def extract_network_entities(text: str) -> dict[str, list[str]]:
    """Extract all URLs, domains, and IP addresses from text content.

    Uses regex patterns and tldextract for robust domain extraction.

    Args:
        text: The text content to scan for network entities.

    Returns:
        Dict with keys: urls, domains, ips (each a deduplicated list).
    """
    log = logger.bind(tool="extract_network_entities")

    urls = list(set(_URL_RE.findall(text)))

    domains: list[str] = []
    seen_domains: set[str] = set()
    for url in urls:
        try:
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                full = f"{ext.domain}.{ext.suffix}".lower()
                if full not in seen_domains:
                    seen_domains.add(full)
                    domains.append(full)
        except Exception:
            try:
                hostname = urlparse(url).hostname
                if hostname and hostname not in seen_domains:
                    seen_domains.add(hostname)
                    domains.append(hostname.lower())
            except Exception:
                continue

    ips = list(set(_IP_RE.findall(text)))

    log.info(
        "tool.entities_extracted",
        urls=len(urls),
        domains=len(domains),
        ips=len(ips),
    )

    return {"urls": urls, "domains": domains, "ips": ips}


@tool
def vector_similarity_search(query_text: str) -> list[dict]:
    """Search the phishing email corpus for similar historical emails using FAISS.

    Computes an embedding for the query text and finds the top-5 most similar
    emails in the historical phishing database (RAG retrieval step).

    Args:
        query_text: Email subject + body to compare against the corpus.

    Returns:
        List of similar emails with similarity scores and phishing/legit labels.
    """
    log = logger.bind(tool="vector_similarity_search")
    log.info("tool.faiss_search", query_length=len(query_text))

    from bastion.vector_store.corpus_loader import get_phishing_index

    try:
        index, labels, texts = get_phishing_index()
        query_vec = np.array(
            get_email_embedding(query_text[:80], query_text), dtype=np.float32
        )
        results = search_index(index, query_vec, k=5, labels=labels)

        enriched = []
        for r in results:
            entry = {
                "rank": len(enriched) + 1,
                "label": r.get("label", "unknown"),
                "distance": round(r["distance"], 4),
                "similarity": round(max(0, 1 - r["distance"] / 4), 4),
            }
            idx = r.get("id", -1)
            if 0 <= idx < len(texts):
                entry["text_preview"] = texts[idx][:200]
            enriched.append(entry)

        phishing_matches = sum(1 for e in enriched if e["label"] == "phishing")
        log.info(
            "tool.faiss_results",
            total_results=len(enriched),
            phishing_matches=phishing_matches,
        )
        return enriched

    except Exception as exc:
        log.exception("tool.faiss_search_error")
        return [{"error": str(exc)}]


@tool
def analyze_url_structure(url: str) -> dict[str, Any]:
    """Analyze a URL for phishing indicators.

    Detects typo-squatting, homoglyph attacks, suspicious TLDs,
    long subdomain chains, and brand impersonation attempts.

    Args:
        url: The URL to analyze.

    Returns:
        Dict with is_suspicious flag, detected techniques, and analysis details.
    """
    log = logger.bind(tool="analyze_url_structure")
    log.info("tool.analyzing_url", url=url[:100])

    techniques: list[str] = []
    details: list[str] = []

    try:
        ext = tldextract.extract(url)
        parsed = urlparse(url)

        # Check for suspicious TLD
        if ext.suffix.lower() in _SUSPICIOUS_TLDS:
            techniques.append("suspicious_tld")
            details.append(f"TLD '.{ext.suffix}' is commonly used in phishing")

        # Check for long subdomain chain (>2 levels suggests spoofing)
        subdomains = ext.subdomain.split(".") if ext.subdomain else []
        if len(subdomains) > 2:
            techniques.append("long_subdomain_chain")
            details.append(
                f"Unusually deep subdomain chain: {ext.subdomain}.{ext.domain}.{ext.suffix}"
            )

        # Check for brand name in subdomain (typo-squatting / brand impersonation)
        full_domain = f"{ext.subdomain}.{ext.domain}".lower()
        for brand in _BRAND_NAMES:
            if brand in full_domain and brand != ext.domain.lower():
                techniques.append("brand_impersonation")
                details.append(
                    f"Brand '{brand}' appears in subdomain but registered domain is '{ext.domain}.{ext.suffix}'"
                )
                break

        # Check for IP address in URL (direct IP hosting)
        if parsed.hostname and _IP_RE.match(parsed.hostname):
            techniques.append("ip_based_url")
            details.append(f"URL uses raw IP address: {parsed.hostname}")

        # Check for excessive path length or encoded characters
        if parsed.path and len(parsed.path) > 100:
            techniques.append("obfuscated_path")
            details.append("Excessively long URL path may hide true destination")

        # Check for @ symbol in URL (credential-based redirect)
        if "@" in url:
            techniques.append("credential_redirect")
            details.append("URL contains '@' which can mask the true destination")

        # Check for hyphens in domain (common typo-squatting technique)
        if ext.domain.count("-") >= 2:
            techniques.append("hyphen_squatting")
            details.append(
                f"Domain '{ext.domain}' uses multiple hyphens (common phishing pattern)"
            )

    except Exception as exc:
        log.exception("tool.url_analysis_error")
        return {"url": url, "error": str(exc), "is_suspicious": False, "techniques": []}

    is_suspicious = len(techniques) > 0

    log.info(
        "tool.url_analyzed",
        url=url[:60],
        is_suspicious=is_suspicious,
        techniques=techniques,
    )

    return {
        "url": url,
        "is_suspicious": is_suspicious,
        "techniques": techniques,
        "details": details,
        "domain_info": {
            "registered_domain": f"{ext.domain}.{ext.suffix}",
            "subdomain": ext.subdomain,
            "tld": ext.suffix,
        },
    }
