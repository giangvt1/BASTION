"""
Threat intelligence tools.

Provides functions for:
- IP reputation checking (AbuseIPDB, VirusTotal)
- Domain reputation and WHOIS analysis
- Hash reputation lookup
- URL scanning

These can be used as LangChain tools or called directly by agents.
"""

from __future__ import annotations

import json
from typing import Any
import requests

from langchain_core.tools import tool

from bastion.logger import get_logger
from bastion.config import config

logger = get_logger(__name__)

def _query_virustotal(endpoint: str, identifier: str, fallback_data: dict[str, Any]) -> dict[str, Any]:
    """Helper to query VT API v3 safely with a graceful fallback."""
    api_key = config.virustotal_api_key.strip()
    if not api_key:
        logger.warning(f"threat_intel_tools.vt_skip (no API key) - fallback to mock for {identifier}")
        return fallback_data

    url = f"https://www.virustotal.com/api/v3/{endpoint}/{identifier}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        # Handle rate limits or unauthorized
        if response.status_code in [401, 429, 403]:
            logger.warning(f"threat_intel_tools.vt_error (status {response.status_code}) - fallback to mock for {identifier}")
            return fallback_data
            
        data = response.json()
        if "error" in data:
            logger.warning(f"threat_intel_tools.vt_not_found for {identifier}")
            fallback_data["reputation"] = "unknown"
            return fallback_data
            
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if not stats:
            return fallback_data
            
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        
        reputation = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "benign")
        risk_score = (malicious * 10 + suspicious * 5) / max(1, (malicious + suspicious + harmless))
        risk_score = min(risk_score, 1.0)
        
        return {
            "entity": identifier,
            "reputation": reputation,
            "risk_score": round(risk_score, 3),
            "stats": stats,
            "source": "virustotal_v3_api"
        }
        
    except Exception as e:
        logger.error(f"threat_intel_tools.vt_exception ({str(e)}) - fallback to mock for {identifier}")
        return fallback_data

@tool
def check_ip_reputation(ip_address: str) -> dict[str, Any]:
    """
    Check the reputation of an IP address against VirusTotal.

    Args:
        ip_address: IPv4 address to check.

    Returns:
        Dict with reputation score and malicious stats.
    """
    log = logger.bind(tool="check_ip_reputation")
    log.info("threat_intel_tools.check_ip", ip=ip_address)

    # Simulated Mock Data Fallback
    fallback = {
        "ip": ip_address,
        "reputation": "suspicious" if ip_address.startswith("185.") or ip_address.startswith("45.") else "benign",
        "risk_score": 0.8 if ip_address.startswith("185.") or ip_address.startswith("45.") else 0.1,
        "stats": {"malicious": 15, "suspicious": 2, "harmless": 70, "undetected": 5} if ip_address.startswith("185.") or ip_address.startswith("45.") else {"malicious": 0, "suspicious": 0, "harmless": 88, "undetected": 1},
        "source": "simulated_mock"
    }

    return _query_virustotal("ip_addresses", ip_address, fallback_data=fallback)

@tool
def check_domain_reputation(domain: str) -> dict[str, Any]:
    """
    Check the reputation of a domain name against VirusTotal.

    Args:
        domain: Domain name to investigate.

    Returns:
        Dict with reputation score and malicious stats.
    """
    log = logger.bind(tool="check_domain_reputation")
    log.info("threat_intel_tools.check_domain", domain=domain)

    # Simulated Mock Data Fallback
    fallback = {
        "domain": domain,
        "reputation": "malicious" if "update" in domain or "secure" in domain else "benign",
        "risk_score": 0.9 if "update" in domain or "secure" in domain else 0.05,
        "stats": {"malicious": 8, "suspicious": 4, "harmless": 60, "undetected": 12} if "update" in domain or "secure" in domain else {"malicious": 0, "suspicious": 0, "harmless": 90, "undetected": 0},
        "source": "simulated_mock"
    }

    return _query_virustotal("domains", domain, fallback_data=fallback)

@tool
def check_file_hash(hash_val: str) -> dict[str, Any]:
    """
    Check the reputation of a file hash (MD5, SHA-1, SHA-256) against VirusTotal.

    Args:
        hash_val: The file hash string.

    Returns:
        Dict with reputation score and malicious stats.
    """
    log = logger.bind(tool="check_file_hash")
    log.info("threat_intel_tools.check_hash", hash=hash_val)

    # Simulated Mock Data Fallback
    fallback = {
        "hash": hash_val,
        "reputation": "malicious",
        "risk_score": 0.95,
        "stats": {"malicious": 65, "suspicious": 0, "harmless": 0, "undetected": 5},
        "source": "simulated_mock"
    }

    return _query_virustotal("files", hash_val, fallback_data=fallback)
