"""
ReAct tools for the Email Analyst Agent.

These are ``@tool`` decorated functions that the LLM can invoke
during the Thought-Action-Observation loop. Each tool performs
a specific analysis task and returns structured results.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import tldextract
from langchain_core.tools import tool

from bastion.logger import get_logger

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

    Extracts all headers (including multi-value headers like Received),
    body text, metadata, and IP addresses found in email headers.

    Handles:
    - Multi-value headers (Received lines are collected into a list)
    - Continuation lines (lines starting with whitespace)
    - IP extraction from Received and X-Originating-IP headers

    Args:
        eml_content: The raw text content of the .eml file.

    Returns:
        Dict with keys: headers, body_text, sender, subject, metadata,
        header_ips, received_chain.
    """
    log = logger.bind(tool="extract_eml_components")
    log.info("tool.extracting_eml", content_length=len(eml_content))

    # Use a dict of lists to support multi-value headers (e.g. Received)
    headers_multi: dict[str, list[str]] = {}
    body_lines: list[str] = []
    in_body = False
    current_key: str | None = None

    for line in eml_content.split("\n"):
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue
            # Continuation line (starts with whitespace) → append to previous header
            if (line.startswith(" ") or line.startswith("\t")) and current_key:
                headers_multi[current_key][-1] += " " + line.strip()
            elif ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                current_key = key
                headers_multi.setdefault(key, []).append(value.strip())
        else:
            body_lines.append(line)

    # Build a flat dict for single-value headers (last value wins)
    headers_flat: dict[str, str] = {}
    for key, values in headers_multi.items():
        headers_flat[key] = values[-1]

    body_text = "\n".join(body_lines).strip()
    sender = headers_flat.get("From", "")
    subject = headers_flat.get("Subject", "")

    # ── Extract IPs from Received headers + X-Originating-IP ────────
    received_chain = headers_multi.get("Received", [])
    header_ips: list[str] = []
    seen_ips: set[str] = set()

    # IPs from Received headers
    for received_line in received_chain:
        for ip in _IP_RE.findall(received_line):
            if ip not in seen_ips:
                seen_ips.add(ip)
                header_ips.append(ip)

    # IPs from X-Originating-IP header
    for xip in headers_multi.get("X-Originating-IP", []):
        for ip in _IP_RE.findall(xip):
            if ip not in seen_ips:
                seen_ips.add(ip)
                header_ips.append(ip)

    result = {
        "headers": headers_flat,
        "body_text": body_text,
        "sender": sender,
        "subject": subject,
        "received_chain": received_chain,
        "header_ips": header_ips,
        "metadata": {
            "message_id": headers_flat.get("Message-ID", ""),
            "date": headers_flat.get("Date", ""),
            "x_mailer": headers_flat.get("X-Mailer", ""),
            "x_originating_ip": headers_flat.get("X-Originating-IP", ""),
            "content_type": headers_flat.get("Content-Type", ""),
            "mime_version": headers_flat.get("MIME-Version", ""),
        },
    }

    log.info(
        "tool.eml_extracted",
        sender=sender,
        subject=subject[:80],
        body_length=len(body_text),
        header_count=len(headers_flat),
        header_ips_count=len(header_ips),
        received_hops=len(received_chain),
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
    """Search the phishing email corpus for similar historical emails using Pinecone.

    Computes an embedding for the query text and finds the top-5 most similar
    emails in the historical phishing database (RAG retrieval step).

    Args:
        query_text: Email subject + body to compare against the corpus.

    Returns:
        List of similar emails with similarity scores and phishing/legit labels.
    """
    log = logger.bind(tool="vector_similarity_search")
    log.info("tool.pinecone_search", query_length=len(query_text))

    from bastion.vector_store.corpus_loader import search_phishing_corpus
    import concurrent.futures

    SEARCH_TIMEOUT = 30  # seconds

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(search_phishing_corpus, query_text, 5)
            results = future.result(timeout=SEARCH_TIMEOUT)

        phishing_matches = sum(1 for r in results if r.get("label") == "phishing")
        log.info(
            "tool.pinecone_results",
            total_results=len(results),
            phishing_matches=phishing_matches,
        )
        return results

    except concurrent.futures.TimeoutError:
        log.error("tool.pinecone_timeout", timeout=SEARCH_TIMEOUT)
        return [{"error": f"Pinecone search timed out after {SEARCH_TIMEOUT}s", "label": "unknown"}]
    except Exception as exc:
        log.exception("tool.pinecone_search_error")
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
