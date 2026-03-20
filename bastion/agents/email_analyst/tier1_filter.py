"""
Tier 1 Hybrid Filter for Email Analyst.

Combines rule-based detection with ML-based classification:
1. Fast regex rules for known patterns
2. BERT-based phishing classifier for semantic understanding
3. URL extraction and domain analysis

This hybrid approach reduces false positives while maintaining speed.
"""

from __future__ import annotations

import os
import re

from bastion.agents.email_analyst.models import Tier1FilterResult
from bastion.logger import get_logger

logger = get_logger(__name__)

# Feature flag for ML classifier (can be disabled via env var)
USE_ML_CLASSIFIER = os.getenv("BASTION_USE_ML_CLASSIFIER", "true").lower() == "true"


# ── Regex phishing rules (ported from email-agent) ──────────────────────

_PHISHING_RULES: list[tuple[str, re.Pattern]] = [
    (
        "urgent_action_required",
        re.compile(
            r"\b(urgent|immediate\s+action|act\s+now|action\s+required)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verify_account",
        re.compile(
            r"\b(verify\s+your\s+(account|identity)|confirm\s+your\s+(identity|account))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "password_reset",
        re.compile(
            r"\b(reset\s+your\s+password|change\s+your\s+password|password\s+expir)",
            re.IGNORECASE,
        ),
    ),
    (
        "suspended_account",
        re.compile(
            r"\b(account\s+(suspended|locked|disabled|compromised|permanently))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "click_link",
        re.compile(
            r"\b(click\s+(here|this\s+link|below|the\s+secure\s+link)|follow\s+this\s+link)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_login_page",
        re.compile(
            r"\b(login|log\s+in|sign\s+in)\s+(to\s+your|page|portal)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "financial_threat",
        re.compile(
            r"\b(bank\s+account|credit\s+card|payment\s+(declined|failed)|"
            r"unauthorized\s+transaction|wire\s+transfer)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "reward_lure",
        re.compile(
            r"\b(you\s+have\s+won|congratulations|claim\s+your\s+(prize|reward|refund))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "personal_info_request",
        re.compile(
            r"\b(social\s+security|ssn|date\s+of\s+birth|mother.?s\s+maiden|"
            r"routing\s+number|account\s+number)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "attachment_lure",
        re.compile(
            r"\b(see\s+attached|open\s+the\s+attachment|download\s+the\s+file)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "time_pressure",
        re.compile(
            r"\b(within\s+\d+\s+hours?|expires?\s+(today|soon|immediately)|final\s+warning)\b",
            re.IGNORECASE,
        ),
    ),
]


# ── Known-bad domain patterns ──────────────────────────────────────────

_SUSPICIOUS_DOMAIN_PATTERNS: list[re.Pattern] = [
    re.compile(r"secure-.*login", re.IGNORECASE),
    re.compile(r"(bank|paypal|chase|wells\s?fargo).*\.(xyz|top|tk|ml|ga|cf|pw)", re.IGNORECASE),
    re.compile(r"\d{4,}.*\.(com|net|org)", re.IGNORECASE),
    re.compile(r"[a-z]+-[a-z]+-[a-z]+\.(com|net)", re.IGNORECASE),
]


# ── Regex patterns for entity extraction ────────────────────────────────

_URL_RE = re.compile(r"https?://[^\s\"'<>\]\)]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)


def run_static_filter(
    subject: str,
    body: str,
    sender: str = "",
    raw_eml: str = "",
) -> Tier1FilterResult:
    """Run Tier 1 hybrid analysis on email content.

    Combines rule-based detection with ML classification for improved accuracy.
    Returns a ``Tier1FilterResult`` with the triage decision.

    Args:
        subject: Email subject line.
        body: Email body text.
        sender: Sender email address.
        raw_eml: Raw .eml content (optional). If provided, IPs are
                 extracted from Received and X-Originating-IP headers.
    """
    log = logger.bind(component="tier1_filter")
    combined_text = f"{subject} {body}"

    # 1. Run ML-based phishing classifier (if enabled)
    ml_score = 0.0
    ml_verdict = "UNKNOWN"
    
    if USE_ML_CLASSIFIER:
        try:
            from bastion.models.ml_models import get_phishing_classifier
            
            classifier = get_phishing_classifier()
            ml_score, ml_verdict = classifier.predict(subject, body)
            
            log.info(
                "tier1.ml_classifier",
                ml_score=round(ml_score, 3),
                ml_verdict=ml_verdict,
            )
        except Exception:
            log.warning("tier1.ml_classifier_failed", exc_info=True)
            # Continue with rule-based detection on ML failure

    # 2. Run regex phishing rules
    matched_rules: list[str] = []
    for rule_name, pattern in _PHISHING_RULES:
        if pattern.search(combined_text):
            matched_rules.append(rule_name)

    # 3. Extract network entities from body
    urls = list(set(_URL_RE.findall(combined_text)))
    ips = list(set(_IP_RE.findall(combined_text)))
    domains = list(set(_DOMAIN_RE.findall(combined_text)))

    # 4. Extract IPs from email headers (Received, X-Originating-IP)
    header_ips: list[str] = []
    if raw_eml:
        header_ips = _extract_header_ips(raw_eml)
        if header_ips:
            log.info("tier1.header_ips_found", count=len(header_ips), ips=header_ips)

    # 5. Check domains against suspicious patterns
    for domain in domains:
        for pat in _SUSPICIOUS_DOMAIN_PATTERNS:
            if pat.search(domain):
                matched_rules.append(f"suspicious_domain:{domain}")
                break

    # 6. Check sender domain
    if sender:
        sender_domain = sender.split("@")[-1] if "@" in sender else sender
        for pat in _SUSPICIOUS_DOMAIN_PATTERNS:
            if pat.search(sender_domain):
                matched_rules.append(f"suspicious_sender:{sender_domain}")
                break

    # 7. Compute hybrid risk score (combines ML + rules)
    score = 0
    
    # ML score contributes up to 60 points
    if USE_ML_CLASSIFIER and ml_score > 0:
        score += int(ml_score * 60)
        if ml_verdict == "PHISHING":
            matched_rules.append(f"ml_phishing:{ml_score:.2f}")
        elif ml_verdict == "SUSPICIOUS":
            matched_rules.append(f"ml_suspicious:{ml_score:.2f}")
    
    # Rule-based score contributes up to 40 points
    score += min(len(matched_rules) * 5, 20)
    score += min(len(urls) * 3, 10)
    score += min(len(ips) * 2, 5)
    score += min(len(header_ips) * 2, 5)
    score = min(score, 100)

    # Decision logic: ML verdict takes priority if confident
    if USE_ML_CLASSIFIER and ml_score >= 0.7:
        decision = "SUSPICIOUS"  # High ML confidence = escalate to Tier 2
    elif USE_ML_CLASSIFIER and ml_score < 0.3 and len(matched_rules) <= 2:
        decision = "CLEAN"  # Low ML score + few rules = likely clean
    elif matched_rules:
        decision = "SUSPICIOUS"
    else:
        decision = "CLEAN"

    log.info(
        "tier1.result",
        decision=decision,
        rules_matched=len(matched_rules),
        urls_found=len(urls),
        header_ips_found=len(header_ips),
        risk_score=score,
        ml_enabled=USE_ML_CLASSIFIER,
        ml_score=round(ml_score, 3) if USE_ML_CLASSIFIER else None,
    )

    return Tier1FilterResult(
        decision=decision,
        matched_rules=matched_rules,
        extracted_urls=urls,
        extracted_domains=domains,
        extracted_ips=ips,
        header_ips=header_ips,
        static_risk_score=score,
    )


def _extract_header_ips(raw_eml: str) -> list[str]:
    """Extract IP addresses from Received and X-Originating-IP headers.

    Parses only the header section of the .eml (lines before the first
    blank line) and extracts IPs from relevant headers.
    """
    header_ips: list[str] = []
    seen: set[str] = set()
    current_key = ""
    current_value = ""

    for line in raw_eml.split("\n"):
        stripped = line.strip()
        # Blank line = end of headers
        if stripped == "":
            break
        # Continuation line
        if line.startswith(" ") or line.startswith("\t"):
            current_value += " " + stripped
        elif ":" in line:
            # Process the previous header
            if current_key in ("Received", "X-Originating-IP"):
                for ip in _IP_RE.findall(current_value):
                    if ip not in seen:
                        seen.add(ip)
                        header_ips.append(ip)
            key, _, value = line.partition(":")
            current_key = key.strip()
            current_value = value.strip()

    # Process the last header
    if current_key in ("Received", "X-Originating-IP"):
        for ip in _IP_RE.findall(current_value):
            if ip not in seen:
                seen.add(ip)
                header_ips.append(ip)

    return header_ips

