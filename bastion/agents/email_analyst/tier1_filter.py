"""
Tier 1 Static Filter for Email Analyst.

Programmatic, no LLM. Runs fast regex rules, blacklist checks, and
URL extraction to triage emails before escalating to the ReAct agent.
"""

from __future__ import annotations

import re

from bastion.agents.email_analyst.models import Tier1FilterResult
from bastion.logger import get_logger

logger = get_logger(__name__)


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
) -> Tier1FilterResult:
    """Run Tier 1 static analysis on email content.

    Returns a ``Tier1FilterResult`` with the triage decision.
    If no rules match, the email is considered CLEAN and Tier 2 is skipped.
    """
    log = logger.bind(component="tier1_filter")
    combined_text = f"{subject} {body}"

    # 1. Run regex phishing rules
    matched_rules: list[str] = []
    for rule_name, pattern in _PHISHING_RULES:
        if pattern.search(combined_text):
            matched_rules.append(rule_name)

    # 2. Extract network entities
    urls = list(set(_URL_RE.findall(combined_text)))
    ips = list(set(_IP_RE.findall(combined_text)))
    domains = list(set(_DOMAIN_RE.findall(combined_text)))

    # 3. Check domains against suspicious patterns
    for domain in domains:
        for pat in _SUSPICIOUS_DOMAIN_PATTERNS:
            if pat.search(domain):
                matched_rules.append(f"suspicious_domain:{domain}")
                break

    # 4. Check sender domain
    if sender:
        sender_domain = sender.split("@")[-1] if "@" in sender else sender
        for pat in _SUSPICIOUS_DOMAIN_PATTERNS:
            if pat.search(sender_domain):
                matched_rules.append(f"suspicious_sender:{sender_domain}")
                break

    # 5. Compute preliminary risk score
    score = 0
    score += min(len(matched_rules) * 8, 50)
    score += min(len(urls) * 5, 20)
    score += min(len(ips) * 3, 15)
    score = min(score, 100)

    decision = "SUSPICIOUS" if matched_rules else "CLEAN"

    log.info(
        "tier1.result",
        decision=decision,
        rules_matched=len(matched_rules),
        urls_found=len(urls),
        risk_score=score,
    )

    return Tier1FilterResult(
        decision=decision,
        matched_rules=matched_rules,
        extracted_urls=urls,
        extracted_domains=domains,
        extracted_ips=ips,
        static_risk_score=score,
    )
