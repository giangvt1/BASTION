"""
Corpus loader -- populates and queries Pinecone for phishing emails and MITRE ATT&CK patterns.

Two namespaces inside one Pinecone index:
- ``phishing``: historical phishing/legit emails for email similarity RAG
- ``mitre``: attack technique descriptions for forensic pattern matching

Loading flow:
1. Check if the namespace already has data (``namespace_count > 0``)
2. If empty, load from CSV (or built-in fallback) and upsert to Pinecone
3. Query via ``search_phishing_corpus()`` / ``search_mitre_corpus()``
"""

from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

from bastion.logger import get_logger
from bastion.vector_store.embeddings import get_email_embedding, get_text_embedding
from bastion.vector_store.pinecone_client import (
    namespace_count,
    query_vectors,
    upsert_vectors,
)

logger = get_logger(__name__)

csv.field_size_limit(sys.maxsize)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_PHISHING_DIR = _DATA_DIR / "phishing_corpus"
_MITRE_DIR = _DATA_DIR / "mitre_attack_corpus"

MAX_SAMPLES = 400
RANDOM_SEED = 42

NS_PHISHING = "phishing"
NS_MITRE = "mitre"

_phishing_ready = False
_mitre_ready = False


# ── Built-in fallback: Phishing corpus ──────────────────────────────────

_FALLBACK_PHISHING: list[tuple[str, str, str]] = [
    (
        "Urgent: Verify your account immediately",
        "Dear customer, your account has been compromised. "
        "Click here to verify: https://fakebank-login.com/verify",
        "phishing",
    ),
    (
        "Your password will expire in 24 hours",
        "Please reset your password immediately at "
        "https://secure-reset.phish.net/reset to avoid account lockout.",
        "phishing",
    ),
    (
        "Congratulations! You have won $1,000,000",
        "Claim your prize now by providing your social security number "
        "and bank account details at https://prize-claim.scam.org/win",
        "phishing",
    ),
    (
        "Invoice #12345 attached",
        "Please see the attached invoice for your recent purchase. "
        "Download the file and review the payment details.",
        "phishing",
    ),
    (
        "Account suspended - action required",
        "Your account has been suspended due to suspicious activity. "
        "Log in to your portal at https://suspended-acct.fake.co/login",
        "phishing",
    ),
    (
        "Weekly team standup notes",
        "Hi team, here are the notes from today's standup. "
        "We discussed the roadmap and upcoming milestones.",
        "legit",
    ),
    (
        "Your order has been shipped",
        "Your order #98765 has been shipped via FedEx. "
        "Track your package at https://www.fedex.com/track?id=98765",
        "legit",
    ),
    (
        "Meeting rescheduled to Thursday",
        "Hi, the project review meeting has been moved to Thursday "
        "at 3 PM. Please update your calendars.",
        "legit",
    ),
    (
        "Monthly newsletter - March 2025",
        "Welcome to our monthly newsletter. This month we cover "
        "new product updates and community highlights.",
        "legit",
    ),
    (
        "Re: Quarterly budget review",
        "Attached is the updated budget spreadsheet for Q1. "
        "Let me know if you have any questions.",
        "legit",
    ),
]


# ── Built-in fallback: MITRE ATT&CK corpus ─────────────────────────────

_FALLBACK_MITRE: list[tuple[str, str, str]] = [
    ("TA0001", "T1566 - Phishing",
     "Adversaries send phishing messages to gain access to victim systems via "
     "spearphishing attachment, link, or service."),
    ("TA0001", "T1078 - Valid Accounts",
     "Adversaries obtain and abuse credentials of existing accounts for initial "
     "access, persistence, privilege escalation, or defense evasion."),
    ("TA0004", "T1548 - Abuse Elevation Control Mechanism",
     "Adversaries bypass UAC, sudo, setuid, or similar mechanisms to escalate "
     "privileges on a system."),
    ("TA0004", "T1134 - Access Token Manipulation",
     "Adversaries modify access tokens to operate under a different user or "
     "system security context via token impersonation or theft."),
    ("TA0006", "T1110 - Brute Force",
     "Adversaries use brute force techniques to attempt access when passwords "
     "are unknown, including password spraying and credential stuffing."),
    ("TA0006", "T1558 - Steal or Forge Kerberos Tickets",
     "Adversaries attempt to subvert Kerberos authentication by stealing or "
     "forging Kerberos tickets for lateral movement."),
    ("TA0008", "T1021 - Remote Services",
     "Adversaries log into remote services such as SSH, RDP, or VNC using "
     "valid accounts to move laterally within the network."),
    ("TA0005", "T1070 - Indicator Removal",
     "Adversaries delete or modify artifacts generated on a host system "
     "including logs and captured files to cover their tracks."),
    ("TA0003", "T1053 - Scheduled Task/Job",
     "Adversaries abuse task scheduling functionality to execute malicious "
     "code at system startup or on a scheduled basis for persistence."),
    ("TA0010", "T1041 - Exfiltration Over C2 Channel",
     "Adversaries steal data by exfiltrating it over an existing command "
     "and control channel using the same protocol as C2 communications."),
    ("TA0004", "T1098 - Account Manipulation",
     "Adversaries manipulate accounts to maintain access including modifying "
     "credentials, permissions, or adding SSH authorized keys."),
    ("TA0002", "T1059 - Command and Scripting Interpreter",
     "Adversaries abuse command and script interpreters such as PowerShell, "
     "Bash, Python, or Windows Command Shell to execute commands."),
    ("TA0007", "T1087 - Account Discovery",
     "Adversaries attempt to get a listing of accounts on a system or within "
     "an environment including cloud accounts and email accounts."),
    ("TA0009", "T1530 - Data from Cloud Storage",
     "Adversaries access data from cloud storage such as AWS S3 buckets, "
     "Azure Blobs, or GCP Storage to collect sensitive information."),
    ("TA0040", "T1485 - Data Destruction",
     "Adversaries destroy data and files on specific systems or in large "
     "numbers on a network to interrupt availability to systems."),
]


# ── CSV loaders ─────────────────────────────────────────────────────────

def _load_phishing_csv(path: Path) -> list[tuple[str, str, str]]:
    """Load a CSV with at least subject, body, label columns."""
    emails: list[tuple[str, str, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols = reader.fieldnames or []
        for row in reader:
            if "subject" in cols and "body" in cols:
                subject = (row.get("subject") or "").strip()
                body = (row.get("body") or "").strip()
            elif "text_combined" in cols:
                text = (row.get("text_combined") or "").strip()
                subject = text[:80]
                body = text[:500]
            else:
                continue
            label_raw = (row.get("label") or "0").strip().lower()
            label = "phishing" if label_raw in ("1", "phishing", "spam") else "legit"
            if body and len(body) > 10:
                emails.append((subject, body[:500], label))
    return emails


def _load_phishing_dataset() -> list[tuple[str, str, str]]:
    """Load phishing corpus from data dir, falling back to built-in samples."""
    if _PHISHING_DIR.is_dir():
        all_emails: list[tuple[str, str, str]] = []
        for csv_file in sorted(_PHISHING_DIR.glob("*.csv")):
            try:
                loaded = _load_phishing_csv(csv_file)
                logger.info("corpus.phishing_loaded", file=csv_file.name, count=len(loaded))
                all_emails.extend(loaded)
            except Exception as exc:
                logger.warning("corpus.phishing_load_error", file=csv_file.name, error=str(exc))
        if all_emails:
            rng = random.Random(RANDOM_SEED)
            rng.shuffle(all_emails)
            return all_emails[:MAX_SAMPLES]

    logger.info("corpus.phishing_using_fallback", count=len(_FALLBACK_PHISHING))
    return _FALLBACK_PHISHING


def _load_mitre_csv(path: Path) -> list[tuple[str, str, str]]:
    """Load CSV with columns: tactic_id, technique, description."""
    patterns: list[tuple[str, str, str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            tactic = (row.get("tactic_id") or "").strip()
            technique = (row.get("technique") or "").strip()
            description = (row.get("description") or "").strip()
            if technique and description:
                patterns.append((tactic, technique, description))
    return patterns


def _load_mitre_dataset() -> list[tuple[str, str, str]]:
    """Load MITRE corpus from data dir, falling back to built-in samples."""
    if _MITRE_DIR.is_dir():
        all_patterns: list[tuple[str, str, str]] = []
        for csv_file in sorted(_MITRE_DIR.glob("*.csv")):
            try:
                loaded = _load_mitre_csv(csv_file)
                logger.info("corpus.mitre_loaded", file=csv_file.name, count=len(loaded))
                all_patterns.extend(loaded)
            except Exception as exc:
                logger.warning("corpus.mitre_load_error", file=csv_file.name, error=str(exc))
        if all_patterns:
            return all_patterns

    logger.info("corpus.mitre_using_fallback", count=len(_FALLBACK_MITRE))
    return _FALLBACK_MITRE


# ── Ensure namespaces are populated ─────────────────────────────────────

def _ensure_phishing_populated() -> None:
    """Upsert the phishing corpus into Pinecone if the namespace is empty."""
    global _phishing_ready
    if _phishing_ready:
        return

    count = namespace_count(NS_PHISHING)
    if count > 0:
        logger.info("corpus.phishing_already_populated", count=count)
        _phishing_ready = True
        return

    dataset = _load_phishing_dataset()
    logger.info("corpus.populating_phishing", samples=len(dataset))

    ids: list[str] = []
    vectors: list[list[float]] = []
    metadata: list[dict] = []

    for i, (subject, body, label) in enumerate(dataset):
        vec = get_email_embedding(subject, body)
        ids.append(f"phish-{i:04d}")
        vectors.append(vec)
        metadata.append({
            "label": label,
            "text": f"[{label}] {subject} | {body[:200]}",
        })

    upsert_vectors(NS_PHISHING, ids, vectors, metadata)
    _phishing_ready = True
    logger.info("corpus.phishing_populated", total=len(ids))


def _ensure_mitre_populated() -> None:
    """Upsert the MITRE ATT&CK corpus into Pinecone if the namespace is empty."""
    global _mitre_ready
    if _mitre_ready:
        return

    count = namespace_count(NS_MITRE)
    if count > 0:
        logger.info("corpus.mitre_already_populated", count=count)
        _mitre_ready = True
        return

    dataset = _load_mitre_dataset()
    logger.info("corpus.populating_mitre", samples=len(dataset))

    ids: list[str] = []
    vectors: list[list[float]] = []
    metadata: list[dict] = []

    for i, (tactic, technique, description) in enumerate(dataset):
        vec = get_text_embedding(f"{technique} {description}")
        ids.append(f"mitre-{i:04d}")
        vectors.append(vec)
        metadata.append({
            "label": f"{tactic}|{technique}",
            "text": description,
        })

    upsert_vectors(NS_MITRE, ids, vectors, metadata)
    _mitre_ready = True
    logger.info("corpus.mitre_populated", total=len(ids))


# ── Public query helpers ────────────────────────────────────────────────

def search_phishing_corpus(query_text: str, k: int = 5) -> list[dict]:
    """Search the phishing email corpus for similar historical emails.

    Ensures the Pinecone namespace is populated before querying.

    Args:
        query_text: Email subject + body to compare.
        k: Number of results.

    Returns:
        List of dicts with: rank, label, score, text_preview.
    """
    _ensure_phishing_populated()
    query_vec = get_email_embedding(query_text[:80], query_text)
    raw_results = query_vectors(NS_PHISHING, query_vec, k=k)

    enriched: list[dict] = []
    for r in raw_results:
        enriched.append({
            "rank": len(enriched) + 1,
            "label": r["label"],
            "score": round(r["score"], 4),
            "text_preview": r.get("text", "")[:200],
        })
    return enriched


def search_mitre_corpus(behavior_description: str, k: int = 5) -> list[dict]:
    """Search MITRE ATT&CK patterns for matching attack techniques.

    Ensures the Pinecone namespace is populated before querying.

    Args:
        behavior_description: Natural language description of observed behavior.
        k: Number of results.

    Returns:
        List of dicts with: rank, tactic_id, technique, score, description.
    """
    _ensure_mitre_populated()
    query_vec = get_text_embedding(behavior_description)
    raw_results = query_vectors(NS_MITRE, query_vec, k=k)

    enriched: list[dict] = []
    for r in raw_results:
        label = r.get("label", "")
        tactic_id, _, technique = label.partition("|")
        enriched.append({
            "rank": len(enriched) + 1,
            "tactic_id": tactic_id.strip(),
            "technique": technique.strip(),
            "score": round(r["score"], 4),
            "description": r.get("text", "")[:300],
        })
    return enriched
