"""
Tier 1 Static IOC Filter for the Threat Intelligence Agent.

Programmatic, no LLM. Performs fast pre-filtering of IOCs to:
- Remove known-benign IOCs (internal IPs, whitelisted domains)
- Deduplicate IOCs by (type, value)
- Assign preliminary risk indicators
- Skip Tier 2 entirely if no suspicious IOCs remain
"""

from __future__ import annotations

import re

from bastion.agents.threat_intel.models import Tier1IOCFilterResult
from bastion.logger import get_logger

logger = get_logger(__name__)


# ── RFC 1918 / Loopback / Link-local ────────────────────────────────────

_BENIGN_IP_RE = re.compile(
    r"^("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"          # 10.0.0.0/8
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"  # 172.16.0.0/12
    r"|192\.168\.\d{1,3}\.\d{1,3}"             # 192.168.0.0/16
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"        # 127.0.0.0/8
    r"|169\.254\.\d{1,3}\.\d{1,3}"             # Link-local
    r"|0\.0\.0\.0"                              # Unspecified
    r")$"
)


# ── Whitelisted domains (well-known legitimate services) ────────────────

_WHITELIST_DOMAINS = {
    # Major tech
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "microsoft.com", "office.com", "outlook.com", "live.com",
    "windows.net", "azure.com", "bing.com",
    "amazon.com", "amazonaws.com", "aws.amazon.com",
    "apple.com", "icloud.com",
    "github.com", "gitlab.com",
    "cloudflare.com", "akamai.com", "fastly.com",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    # Major banks (legitimate)
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "paypal.com", "stripe.com",
}

# Match parent domains: if IOC domain ends with any of these
_WHITELIST_SUFFIXES = {f".{d}" for d in _WHITELIST_DOMAINS} | _WHITELIST_DOMAINS


# ── Quick risk heuristics ──────────────────────────────────────────────

_HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "pw", "buzz", "club",
    "work", "icu", "cam", "rest", "surf", "monster", "loan",
}

_KNOWN_TOR_PREFIXES = {
    "185.220.", "185.129.", "176.10.", "198.98.", "195.176.",
    "62.210.", "51.15.", "163.172.", "212.47.", "151.115.",
}

_BRAND_IMPERSONATION_RE = re.compile(
    r"(bank|paypal|chase|wells.?fargo|citi|secure.?login|verify.?account)",
    re.IGNORECASE,
)


def run_ioc_filter(iocs: list[dict]) -> Tier1IOCFilterResult:
    """Run Tier 1 static filter on a list of IOCs.

    Filters out known-benign IOCs, deduplicates, and assigns preliminary
    risk indicators. Returns ``SKIP`` if no suspicious IOCs remain.

    Args:
        iocs: List of IOC dicts from ``BastionState["iocs"]``, each with
              keys: ``ioc_type``, ``value``, ``source_agent``, ``context``.

    Returns:
        ``Tier1IOCFilterResult`` with the triage decision and filtered IOC list.
    """
    log = logger.bind(component="tier1_ioc_filter")
    log.info("tier1.start", total_iocs=len(iocs))

    if not iocs:
        log.info("tier1.empty_ioc_list")
        return Tier1IOCFilterResult(
            decision="SKIP",
            static_risk_score=0,
        )

    seen: set[tuple[str, str]] = set()
    filtered: list[dict] = []
    skipped: list[dict] = []
    risk_indicators: list[str] = []
    risk_score = 0

    for ioc in iocs:
        ioc_type = ioc.get("ioc_type", "unknown").lower()
        value = ioc.get("value", "").strip()

        if not value:
            continue

        # Deduplicate
        key = (ioc_type, value.lower())
        if key in seen:
            continue
        seen.add(key)

        # ── IP checks ──
        if ioc_type == "ip":
            if _BENIGN_IP_RE.match(value):
                skipped.append({**ioc, "_skip_reason": "internal_ip"})
                continue

            # Tor exit heuristic
            for prefix in _KNOWN_TOR_PREFIXES:
                if value.startswith(prefix):
                    risk_indicators.append(f"tor_exit_prefix:{value}")
                    risk_score += 20
                    break

            filtered.append(ioc)
            risk_score += 5

        # ── Domain checks ──
        elif ioc_type == "domain":
            value_lower = value.lower()

            # Whitelist check
            is_whitelisted = False
            for suffix in _WHITELIST_SUFFIXES:
                if value_lower == suffix or value_lower.endswith(f".{suffix}"):
                    is_whitelisted = True
                    break
            if value_lower in _WHITELIST_DOMAINS:
                is_whitelisted = True

            if is_whitelisted:
                skipped.append({**ioc, "_skip_reason": "whitelisted_domain"})
                continue

            # Risk heuristics
            import tldextract
            ext = tldextract.extract(value)
            if ext.suffix.lower() in _HIGH_RISK_TLDS:
                risk_indicators.append(f"high_risk_tld:{value}")
                risk_score += 15

            if _BRAND_IMPERSONATION_RE.search(value):
                risk_indicators.append(f"brand_impersonation:{value}")
                risk_score += 20

            filtered.append(ioc)
            risk_score += 5

        # ── URL checks ──
        elif ioc_type == "url":
            import tldextract
            ext = tldextract.extract(value)
            full_domain = f"{ext.domain}.{ext.suffix}".lower()

            if full_domain in _WHITELIST_DOMAINS:
                skipped.append({**ioc, "_skip_reason": "whitelisted_url_domain"})
                continue

            if ext.suffix.lower() in _HIGH_RISK_TLDS:
                risk_indicators.append(f"high_risk_url_tld:{value[:80]}")
                risk_score += 15

            filtered.append(ioc)
            risk_score += 5

        # ── Hash / Email / Other ──
        else:
            filtered.append(ioc)
            risk_score += 3

    risk_score = min(risk_score, 100)
    decision = "ANALYZE" if filtered else "SKIP"

    log.info(
        "tier1.result",
        decision=decision,
        filtered=len(filtered),
        skipped=len(skipped),
        risk_score=risk_score,
        indicators=len(risk_indicators),
    )

    return Tier1IOCFilterResult(
        decision=decision,
        filtered_iocs=filtered,
        skipped_iocs=skipped,
        static_risk_indicators=risk_indicators,
        static_risk_score=risk_score,
    )
