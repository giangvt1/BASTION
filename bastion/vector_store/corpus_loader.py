"""
Corpus loader -- builds FAISS indices for phishing emails and MITRE ATT&CK patterns.

Two singleton indices:
- Phishing corpus: historical phishing/legit emails for email similarity RAG
- MITRE ATT&CK corpus: attack technique descriptions for forensic pattern matching

Loading priority (fastest first):
1. Pre-built index from S3 (production -- FAISS_INDEX_S3_PREFIX configured)
2. Pre-built index from local cache (.bastion_cache/ or /tmp/faiss_cache)
3. Build from CSV data at runtime (development fallback)

After a runtime build, the index is saved locally so subsequent warm starts
skip the rebuild.
"""

from __future__ import annotations

import csv
import random
import sys
from pathlib import Path
from typing import Tuple

import numpy as np

from bastion.logger import get_logger
from bastion.vector_store.embeddings import get_text_embedding, get_email_embedding
from bastion.vector_store.faiss_client import (
    build_index,
    load_index,
    load_index_from_s3,
    save_index,
)

logger = get_logger(__name__)

csv.field_size_limit(sys.maxsize)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_PHISHING_DIR = _DATA_DIR / "phishing_corpus"
_MITRE_DIR = _DATA_DIR / "mitre_attack_corpus"

_LOCAL_CACHE_DIR = Path("/tmp/faiss_cache") if Path("/tmp").exists() else (
    Path(__file__).resolve().parent.parent.parent / ".bastion_cache"
)

MAX_SAMPLES = 400
RANDOM_SEED = 42


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


# ── Phishing corpus loader ──────────────────────────────────────────────

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


# ── MITRE ATT&CK corpus loader ─────────────────────────────────────────

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


# ── Singleton indices ───────────────────────────────────────────────────

_phishing_index = None
_phishing_labels: list[str] = []
_phishing_texts: list[str] = []

_mitre_index = None
_mitre_labels: list[str] = []
_mitre_texts: list[str] = []


def _try_load_prebuilt(name: str) -> tuple | None:
    """Try to load a pre-built FAISS index from S3 or local cache."""
    from bastion.config import config

    s3_prefix = getattr(config, "faiss_index_s3_prefix", "")
    if s3_prefix:
        result = load_index_from_s3(
            bucket=config.s3_bucket,
            s3_prefix=s3_prefix,
            name=name,
            local_dir=str(_LOCAL_CACHE_DIR),
        )
        if result is not None:
            return result

    result = load_index(_LOCAL_CACHE_DIR, name)
    if result is not None:
        return result

    return None


def get_phishing_index() -> Tuple:
    """Return (faiss_index, labels, texts) for the phishing corpus.

    Loading priority:
    1. Pre-built from S3/local cache (< 100ms)
    2. Build from CSV at runtime (saves to cache for next warm start)
    """
    global _phishing_index, _phishing_labels, _phishing_texts

    if _phishing_index is not None:
        return _phishing_index, _phishing_labels, _phishing_texts

    prebuilt = _try_load_prebuilt("phishing")
    if prebuilt is not None:
        _phishing_index, _phishing_labels = prebuilt
        _phishing_texts = _phishing_labels  # labels contain "[label] subject | body"
        logger.info("corpus.phishing_loaded_prebuilt", entries=_phishing_index.ntotal)
        return _phishing_index, _phishing_labels, _phishing_texts

    dataset = _load_phishing_dataset()
    logger.info("corpus.building_phishing_index", samples=len(dataset))

    embeddings, labels, texts = [], [], []
    for subject, body, label in dataset:
        vec = get_email_embedding(subject, body)
        embeddings.append(vec)
        labels.append(label)
        texts.append(f"[{label}] {subject} | {body[:200]}")

    matrix = np.array(embeddings, dtype=np.float32)
    _phishing_index = build_index(matrix)
    _phishing_labels = labels
    _phishing_texts = texts

    try:
        save_index(_phishing_index, _phishing_texts, _LOCAL_CACHE_DIR, "phishing")
    except Exception:
        logger.warning("corpus.phishing_save_cache_failed")

    logger.info("corpus.phishing_index_ready", entries=_phishing_index.ntotal)
    return _phishing_index, _phishing_labels, _phishing_texts


def get_mitre_index() -> Tuple:
    """Return (faiss_index, labels, texts) for the MITRE ATT&CK corpus.

    Loading priority:
    1. Pre-built from S3/local cache (< 100ms)
    2. Build from CSV at runtime (saves to cache for next warm start)
    """
    global _mitre_index, _mitre_labels, _mitre_texts

    if _mitre_index is not None:
        return _mitre_index, _mitre_labels, _mitre_texts

    prebuilt = _try_load_prebuilt("mitre")
    if prebuilt is not None:
        _mitre_index, _mitre_labels = prebuilt
        _mitre_texts = _mitre_labels
        logger.info("corpus.mitre_loaded_prebuilt", entries=_mitre_index.ntotal)
        return _mitre_index, _mitre_labels, _mitre_texts

    dataset = _load_mitre_dataset()
    logger.info("corpus.building_mitre_index", samples=len(dataset))

    embeddings, labels, texts = [], [], []
    for tactic, technique, description in dataset:
        vec = get_text_embedding(f"{technique} {description}")
        embeddings.append(vec)
        labels.append(f"{tactic}|{technique}")
        texts.append(description)

    matrix = np.array(embeddings, dtype=np.float32)
    _mitre_index = build_index(matrix)
    _mitre_labels = labels
    _mitre_texts = texts

    try:
        save_index(_mitre_index, _mitre_texts, _LOCAL_CACHE_DIR, "mitre")
    except Exception:
        logger.warning("corpus.mitre_save_cache_failed")

    logger.info("corpus.mitre_index_ready", entries=_mitre_index.ntotal)
    return _mitre_index, _mitre_labels, _mitre_texts
