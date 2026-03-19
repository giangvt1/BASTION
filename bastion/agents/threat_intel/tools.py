"""
ReAct tools for the Threat Intelligence Agent.

These ``@tool`` decorated functions allow the LLM to enrich IOCs
with reputation data, geolocation, WHOIS, and abuse reports.

All tools implement graceful fallbacks when external API keys are
unavailable (demo/thesis mode) -- returning heuristic-based results
instead of failing.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

import tldextract
from langchain_core.tools import tool

from bastion.logger import get_logger

logger = get_logger(__name__)

# ── Known-malicious patterns for heuristic fallback ────────────────────

_KNOWN_TOR_PREFIXES = {
    "185.220.", "185.129.", "176.10.", "198.98.", "195.176.",
    "62.210.", "51.15.", "163.172.", "212.47.", "151.115.",
}

_HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "pw", "buzz", "club",
    "work", "icu", "cam", "rest", "surf", "monster", "loan",
}

_KNOWN_MALICIOUS_PATTERNS = [
    re.compile(r"(bank|paypal|chase|wells.?fargo|citi|secure.?login)", re.IGNORECASE),
    re.compile(r"(phishing|malware|exploit|ransomware|c2|command.?control)", re.IGNORECASE),
]

_WHITELIST_DOMAINS = {
    "google.com", "microsoft.com", "amazon.com", "apple.com",
    "cloudflare.com", "amazonaws.com", "azure.com", "github.com",
    "office.com", "outlook.com", "live.com", "facebook.com",
    "twitter.com", "linkedin.com", "akamai.com", "fastly.com",
}

_HIGH_RISK_COUNTRIES = {
    "RU", "CN", "KP", "IR", "NG", "RO", "UA", "BY",
}

_RFC1918_RE = re.compile(
    r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
)


@tool
def virustotal_lookup(ioc_value: str, ioc_type: str = "auto") -> dict[str, Any]:
    """Look up an IOC (IP, domain, URL, or file hash) on VirusTotal.

    Returns detection ratio, malicious engine count, community reputation,
    and any associated tags. Falls back to heuristic analysis when the
    VirusTotal API key is not configured.

    Args:
        ioc_value: The IOC to check (IP address, domain, URL, or hash).
        ioc_type: Type hint -- 'ip', 'domain', 'url', 'hash', or 'auto'.

    Returns:
        Dict with reputation data: malicious_count, total_engines,
        detection_ratio, community_score, tags, and risk_level.
    """
    log = logger.bind(tool="virustotal_lookup")
    log.info("tool.vt_lookup", ioc_value=ioc_value[:100], ioc_type=ioc_type)

    # Try real VirusTotal API
    try:
        from bastion.config import config
        api_key = getattr(config, "virustotal_api_key", "") or ""
        if api_key:
            return _vt_api_call(ioc_value, ioc_type, api_key, log)
    except Exception:
        pass

    # Fallback: heuristic-based reputation
    log.info("tool.vt_fallback_heuristic", reason="no_api_key")
    return _vt_heuristic(ioc_value, ioc_type)


def _vt_api_call(
    ioc_value: str, ioc_type: str, api_key: str, log: Any,
) -> dict[str, Any]:
    """Real VirusTotal API v3 call."""
    import requests

    headers = {"x-apikey": api_key}

    if ioc_type in ("ip", "auto") and re.match(r"^\d+\.\d+\.\d+\.\d+$", ioc_value):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif ioc_type in ("domain", "auto") and "." in ioc_value and not ioc_value.startswith("http"):
        url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
    elif ioc_type in ("hash", "auto") and re.match(r"^[a-fA-F0-9]{32,64}$", ioc_value):
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else:
        url_id = hashlib.sha256(ioc_value.encode()).hexdigest()
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json().get("data", {}).get("attributes", {})

    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) or 1

    risk = "BENIGN"
    if malicious >= 5:
        risk = "CRITICAL"
    elif malicious >= 3:
        risk = "HIGH"
    elif malicious >= 1:
        risk = "MEDIUM"

    log.info("tool.vt_api_result", malicious=malicious, total=total, risk=risk)

    return {
        "source": "VirusTotal",
        "ioc_value": ioc_value,
        "malicious_count": malicious,
        "total_engines": total,
        "detection_ratio": f"{malicious}/{total}",
        "community_score": data.get("reputation", 0),
        "tags": data.get("tags", []),
        "risk_level": risk,
    }


def _vt_heuristic(ioc_value: str, ioc_type: str) -> dict[str, Any]:
    """Heuristic-based reputation when no API key available."""
    risk_score = 0
    flags: list[str] = []

    # IP checks
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ioc_value):
        if _RFC1918_RE.match(ioc_value):
            return {
                "source": "heuristic",
                "ioc_value": ioc_value,
                "risk_level": "BENIGN",
                "flags": ["internal_ip"],
                "note": "RFC 1918 private IP -- not externally routable.",
            }
        for prefix in _KNOWN_TOR_PREFIXES:
            if ioc_value.startswith(prefix):
                risk_score += 40
                flags.append("known_tor_exit_prefix")
                break
    else:
        # Domain checks
        ext = tldextract.extract(ioc_value)
        full_domain = f"{ext.domain}.{ext.suffix}".lower()

        if full_domain in _WHITELIST_DOMAINS:
            return {
                "source": "heuristic",
                "ioc_value": ioc_value,
                "risk_level": "BENIGN",
                "flags": ["whitelisted_domain"],
                "note": f"Domain '{full_domain}' is whitelisted.",
            }

        if ext.suffix.lower() in _HIGH_RISK_TLDS:
            risk_score += 25
            flags.append(f"high_risk_tld:.{ext.suffix}")

        for pat in _KNOWN_MALICIOUS_PATTERNS:
            if pat.search(ioc_value):
                risk_score += 30
                flags.append("brand_impersonation_pattern")
                break

        if ext.domain.count("-") >= 2:
            risk_score += 15
            flags.append("multi_hyphen_domain")

    risk = "BENIGN"
    if risk_score >= 50:
        risk = "HIGH"
    elif risk_score >= 30:
        risk = "MEDIUM"
    elif risk_score >= 10:
        risk = "LOW"

    return {
        "source": "heuristic",
        "ioc_value": ioc_value,
        "malicious_count": 0,
        "total_engines": 0,
        "detection_ratio": "N/A (heuristic)",
        "risk_level": risk,
        "risk_score": risk_score,
        "flags": flags,
        "note": "Heuristic analysis -- VirusTotal API key not configured.",
    }


@tool
def abuseipdb_check(ip_address: str) -> dict[str, Any]:
    """Check an IP address against the AbuseIPDB database.

    Returns abuse confidence score, total reports, country, ISP,
    and usage type. Falls back to heuristic analysis when the
    AbuseIPDB API key is not configured.

    Args:
        ip_address: The IP address to check (IPv4).

    Returns:
        Dict with abuse data: abuse_confidence_score, total_reports,
        country_code, isp, usage_type, is_tor, risk_level.
    """
    log = logger.bind(tool="abuseipdb_check")
    log.info("tool.abuseipdb_check", ip=ip_address)

    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_address):
        return {"error": f"Invalid IP format: {ip_address}", "risk_level": "UNKNOWN"}

    if _RFC1918_RE.match(ip_address):
        return {
            "source": "static",
            "ip_address": ip_address,
            "risk_level": "BENIGN",
            "note": "RFC 1918 private IP -- internal network.",
        }

    # Try real AbuseIPDB API
    try:
        from bastion.config import config
        api_key = getattr(config, "abuseipdb_api_key", "") or ""
        if api_key:
            return _abuseipdb_api_call(ip_address, api_key, log)
    except Exception:
        pass

    # Fallback: heuristic
    log.info("tool.abuseipdb_fallback", reason="no_api_key")
    return _abuseipdb_heuristic(ip_address)


def _abuseipdb_api_call(
    ip_address: str, api_key: str, log: Any,
) -> dict[str, Any]:
    """Real AbuseIPDB API call."""
    import requests

    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""},
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})

    score = data.get("abuseConfidenceScore", 0)
    risk = "BENIGN"
    if score >= 80:
        risk = "CRITICAL"
    elif score >= 50:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    elif score > 0:
        risk = "LOW"

    log.info("tool.abuseipdb_result", score=score, risk=risk)

    return {
        "source": "AbuseIPDB",
        "ip_address": ip_address,
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports", 0),
        "country_code": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "usage_type": data.get("usageType", ""),
        "is_tor": data.get("isTor", False),
        "domain": data.get("domain", ""),
        "risk_level": risk,
    }


def _abuseipdb_heuristic(ip_address: str) -> dict[str, Any]:
    """Heuristic abuse assessment when no API key available."""
    risk_score = 0
    flags: list[str] = []

    is_tor = False
    for prefix in _KNOWN_TOR_PREFIXES:
        if ip_address.startswith(prefix):
            is_tor = True
            risk_score += 50
            flags.append("known_tor_exit_prefix")
            break

    # Simulate country heuristic based on IP ranges
    octets = ip_address.split(".")
    first_octet = int(octets[0]) if octets else 0

    # Very rough geo heuristic for demo
    estimated_country = "US"
    if first_octet in range(176, 186):
        estimated_country = "RU"
        risk_score += 15
        flags.append("high_risk_geo_range")
    elif first_octet in range(36, 42):
        estimated_country = "CN"
        risk_score += 15
        flags.append("high_risk_geo_range")

    risk = "BENIGN"
    if risk_score >= 50:
        risk = "HIGH"
    elif risk_score >= 20:
        risk = "MEDIUM"
    elif risk_score > 0:
        risk = "LOW"

    return {
        "source": "heuristic",
        "ip_address": ip_address,
        "abuse_confidence_score": min(risk_score, 100),
        "total_reports": 0,
        "country_code": estimated_country,
        "isp": "unknown",
        "usage_type": "unknown",
        "is_tor": is_tor,
        "risk_level": risk,
        "flags": flags,
        "note": "Heuristic analysis -- AbuseIPDB API key not configured.",
    }


@tool
def whois_domain_lookup(domain: str) -> dict[str, Any]:
    """Perform WHOIS lookup on a domain to check registration details.

    Returns domain age, registrar, registration/expiration dates,
    and privacy protection status. Newly registered domains (< 30 days)
    are flagged as high risk. Falls back to TLD-based heuristic analysis
    when WHOIS data is unavailable.

    Args:
        domain: The domain name to look up (e.g. 'example.com').

    Returns:
        Dict with WHOIS data: domain_age_days, registrar, creation_date,
        expiration_date, privacy_protected, risk_level.
    """
    log = logger.bind(tool="whois_domain_lookup")
    log.info("tool.whois_lookup", domain=domain)

    ext = tldextract.extract(domain)
    registered = f"{ext.domain}.{ext.suffix}".lower()

    if registered in _WHITELIST_DOMAINS:
        return {
            "source": "whitelist",
            "domain": registered,
            "risk_level": "BENIGN",
            "domain_age_days": 9999,
            "note": f"'{registered}' is a well-known legitimate domain.",
        }

    # Try python-whois library
    try:
        import whois as python_whois  # type: ignore[import-untyped]

        w = python_whois.whois(registered)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        age_days = -1
        if creation:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                from datetime import timezone as tz
                creation = creation.replace(tzinfo=tz.utc)
            age_days = (now - creation).days

        privacy = bool(w.get("privacy") or "privacy" in str(w.get("registrar", "")).lower())

        risk = "BENIGN"
        flags = []
        if 0 <= age_days < 30:
            risk = "CRITICAL"
            flags.append("newly_registered_<30d")
        elif 0 <= age_days < 90:
            risk = "HIGH"
            flags.append("recently_registered_<90d")
        elif 0 <= age_days < 365:
            risk = "MEDIUM"
            flags.append("young_domain_<1y")

        if privacy:
            flags.append("privacy_protected")
            if risk in ("BENIGN", "LOW"):
                risk = "LOW"

        log.info("tool.whois_result", age_days=age_days, risk=risk)

        return {
            "source": "WHOIS",
            "domain": registered,
            "registrar": str(w.registrar or "unknown"),
            "creation_date": str(creation or "unknown"),
            "expiration_date": str(w.expiration_date or "unknown"),
            "domain_age_days": age_days,
            "privacy_protected": privacy,
            "name_servers": w.name_servers[:5] if w.name_servers else [],
            "risk_level": risk,
            "flags": flags,
        }

    except Exception as exc:
        log.warning("tool.whois_fallback", error=str(exc)[:200])

    # Fallback: TLD-based heuristic
    return _whois_heuristic(registered, ext)


def _whois_heuristic(registered: str, ext: Any) -> dict[str, Any]:
    """Heuristic WHOIS assessment based on TLD and domain patterns."""
    risk = "UNKNOWN"
    flags: list[str] = []

    if ext.suffix.lower() in _HIGH_RISK_TLDS:
        risk = "MEDIUM"
        flags.append(f"high_risk_tld:.{ext.suffix}")

    for pat in _KNOWN_MALICIOUS_PATTERNS:
        if pat.search(registered):
            risk = "HIGH"
            flags.append("brand_impersonation_pattern")
            break

    if ext.domain.count("-") >= 2:
        flags.append("multi_hyphen_domain")
        if risk in ("UNKNOWN", "BENIGN"):
            risk = "LOW"

    return {
        "source": "heuristic",
        "domain": registered,
        "registrar": "unknown",
        "creation_date": "unknown",
        "domain_age_days": -1,
        "privacy_protected": False,
        "risk_level": risk,
        "flags": flags,
        "note": "WHOIS lookup failed -- using TLD/pattern heuristic.",
    }


@tool
def ip_geolocation(ip_address: str) -> dict[str, Any]:
    """Get geolocation, ASN, and ISP information for an IP address.

    Detects Tor exit nodes, VPN/proxy usage, and high-risk geographic
    origins. Falls back to heuristic analysis when external GeoIP
    services are unavailable.

    Args:
        ip_address: The IP address to geolocate (IPv4).

    Returns:
        Dict with geo data: country_code, country_name, city, asn,
        isp, is_tor, is_vpn, is_proxy, risk_level.
    """
    log = logger.bind(tool="ip_geolocation")
    log.info("tool.geoip_lookup", ip=ip_address)

    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_address):
        return {"error": f"Invalid IP format: {ip_address}", "risk_level": "UNKNOWN"}

    if _RFC1918_RE.match(ip_address):
        return {
            "source": "static",
            "ip_address": ip_address,
            "country_code": "INTERNAL",
            "country_name": "Private Network",
            "is_tor": False,
            "is_vpn": False,
            "is_proxy": False,
            "risk_level": "BENIGN",
            "note": "RFC 1918 private IP.",
        }

    # Try ip-api.com (free, no key required, 45 req/min)
    try:
        import requests

        resp = requests.get(
            f"http://ip-api.com/json/{ip_address}",
            params={"fields": "status,country,countryCode,city,isp,org,as,proxy,hosting,query"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("countryCode", "")
                is_tor = any(ip_address.startswith(p) for p in _KNOWN_TOR_PREFIXES)
                is_proxy = data.get("proxy", False)
                is_hosting = data.get("hosting", False)

                risk = "BENIGN"
                flags = []
                if is_tor:
                    risk = "HIGH"
                    flags.append("tor_exit_node")
                if is_proxy:
                    risk = max(risk, "MEDIUM", key=lambda x: ["BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x))
                    flags.append("proxy_detected")
                if country in _HIGH_RISK_COUNTRIES:
                    risk = max(risk, "MEDIUM", key=lambda x: ["BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x))
                    flags.append(f"high_risk_country:{country}")
                if is_hosting:
                    flags.append("hosting_provider")

                log.info("tool.geoip_result", country=country, risk=risk)

                return {
                    "source": "ip-api.com",
                    "ip_address": ip_address,
                    "country_code": country,
                    "country_name": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                    "is_tor": is_tor,
                    "is_vpn": False,
                    "is_proxy": is_proxy,
                    "is_hosting": is_hosting,
                    "risk_level": risk,
                    "flags": flags,
                }

    except Exception as exc:
        log.warning("tool.geoip_api_error", error=str(exc)[:200])

    # Fallback: heuristic geolocation
    log.info("tool.geoip_fallback_heuristic")
    return _geoip_heuristic(ip_address)


def _geoip_heuristic(ip_address: str) -> dict[str, Any]:
    """Heuristic geolocation when external services are unavailable."""
    is_tor = any(ip_address.startswith(p) for p in _KNOWN_TOR_PREFIXES)

    flags = []
    risk = "UNKNOWN"
    if is_tor:
        risk = "HIGH"
        flags.append("known_tor_exit_prefix")

    return {
        "source": "heuristic",
        "ip_address": ip_address,
        "country_code": "unknown",
        "country_name": "unknown",
        "city": "unknown",
        "isp": "unknown",
        "asn": "unknown",
        "is_tor": is_tor,
        "is_vpn": False,
        "is_proxy": False,
        "risk_level": risk,
        "flags": flags,
        "note": "GeoIP service unavailable -- limited heuristic analysis.",
    }
