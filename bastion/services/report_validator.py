"""
Report Claim Validator — Deterministic Post-Processing Policy Gate.

Runs after LLM synthesis to catch compliance failures that prompt
engineering alone cannot guarantee. Each check is deterministic,
testable, and auditable.

Flow: Draft Report → validate() → auto-fix simple violations → return sanitized report + violation log
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bastion.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Violation:
    """A single policy violation found in the report."""
    category: str           # e.g. "evidence_wording", "datasource_fidelity"
    severity: str           # "ERROR" or "WARNING"
    message: str            # Human-readable description
    line_context: str       # The offending text snippet
    auto_fix: tuple[str, str] | None = None  # (old, new) replacement pair


@dataclass
class ValidationResult:
    """Result of running all validators on a report."""
    violations: list[Violation] = field(default_factory=list)
    report: str = ""        # The (possibly auto-fixed) report text
    auto_fixed: int = 0     # Number of auto-fixed violations

    @property
    def has_errors(self) -> bool:
        return any(v.severity == "ERROR" for v in self.violations if v.auto_fix is None)

    @property
    def summary(self) -> str:
        errors = sum(1 for v in self.violations if v.severity == "ERROR")
        warnings = sum(1 for v in self.violations if v.severity == "WARNING")
        return f"{errors} errors, {warnings} warnings, {self.auto_fixed} auto-fixed"


# ── Deprecated MITRE ATT&CK IDs ────────────────────────────────────────

_DEPRECATED_ATTACK_IDS = {
    "T1192": "T1566.002",  # Spearphishing Link
    "T1193": "T1566.001",  # Spearphishing Attachment
    "T1194": "T1566.003",  # Spearphishing via Service
    "T1064": "T1059",      # Scripting → Command and Scripting Interpreter
    "T1015": "T1546.008",  # Accessibility Features
    "T1060": "T1547.001",  # Registry Run Keys
    "T1050": "T1543.003",  # New Service
    "T1031": "T1543.003",  # Modify Existing Service
    "T1085": "T1218.011",  # Rundll32
}

# ── Datasource capability boundaries ───────────────────────────────────

_VPCFLOW_FORBIDDEN_TERMS = [
    (r"\bConsoleLogin\b", "ConsoleLogin (requires CloudTrail)"),
    (r"\bAssumeRole\b", "AssumeRole (requires CloudTrail)"),
    (r"\bFederatedLogin\b", "FederatedLogin (requires CloudTrail)"),
    (r"\bauthentication failure\b", "authentication failure (requires CloudTrail)"),
    (r"\buser identity\b", "user identity (requires CloudTrail)"),
    (r"\bcredential.{0,10}brute.?force\b", "credential brute-force (requires CloudTrail)"),
    (r"\bGetObject\b", "GetObject (requires CloudTrail)"),
    (r"\bPutObject\b", "PutObject (requires CloudTrail)"),
]

_EMAIL_FORBIDDEN_TERMS = [
    (r"\buser clicked\b", "user clicked (no click evidence in email telemetry)"),
    (r"\bpayload was executed\b", "payload executed (no execution evidence in email telemetry)"),
    (r"\bmalware was downloaded\b", "malware downloaded (no download evidence in email telemetry)"),
    (r"\buser submitted credentials\b", "user submitted credentials (no form evidence)"),
]

# ── Evidence wording: terms that require specific evidence ─────────────

_HEURISTIC_FORBIDDEN_PATTERNS = [
    # (pattern, replacement) — auto-fixable
    (r"(?i)\bassessed as malicious by Threat Intel\b", "contextually suspicious based on heuristic analysis"),
    (r"(?i)\bconfirmed malicious\b", "contextually suspicious"),
    (r"(?i)\bconfirmed as malicious\b", "contextually suspicious"),
    (r"(?i)\bmalicious by Threat Intel\b", "contextually suspicious based on heuristic analysis"),
    (r"(?i)\bassessed as malicious\b", "contextually suspicious"),
    (r"(?i)\bindicate[s]? malicious activity\b", "indicate suspicious activity correlated with phishing campaign"),
    (r"(?i)\bindicate[s]? active malicious\b", "indicate suspicious activity"),
    (r"(?i)\bactive malicious activity\b", "suspicious activity"),
    (r"(?i)\bmalicious payload\b", "suspicious payload (purpose unknown from available data)"),
    (r"(?i)\blikely leads to a malicious\b", "assessed as suspicious, purpose unknown from available data"),
    (r"(?i)\bexplicitly labeled\b", "heuristically labeled"),
]

_REJECT_FORBIDDEN_PATTERNS = [
    # Terms that imply successful execution — wrong for REJECT events
    (r"(?i)\bnetwork exploitation\b", "blocked suspicious network activity"),
    (r"(?i)\battempted.*exploitation\b", "blocked suspicious connection attempt"),
    (r"(?i)\bsuccessful access\b", ""),  # Flag for removal
    (r"(?i)\bsuccessful compromise\b(?!\s+was not)", ""),  # Unless negated
    (r"(?i)\battempted to exploit a vulnerability\b", "attempted to connect to internal assets (blocked)"),
    (r"(?i)\bexploiting\b", "targeting"),
]

_UNSUPPORTED_INTENT_TERMS = [
    # These require specific evidence types
    (r"(?i)\bcredential harvesting\b", "evidence of login form, POST endpoint, or credential capture"),
    (r"(?i)\bdata exfiltration\b", "evidence of data volume anomaly or outbound transfer"),
    (r"(?i)\bmalware delivery\b", "evidence of download, executable, or payload"),
]

# ── Sigma field name mappings per datasource ───────────────────────────

_SIGMA_FIELD_FIXES = {
    "vpcflow": {
        "src_addr": "srcaddr",
        "dst_addr": "dstaddr",
        "src_port": "srcport",
        "dst_port": "dstport",
        "src_ip": "srcaddr",
        "dst_ip": "dstaddr",
        "source_ip": "srcaddr",
        "dest_ip": "dstaddr",
        "source_port": "srcport",
        "dest_port": "dstport",
    },
}

# Allowed fields per datasource (for fabricated field detection)
_SIGMA_ALLOWED_FIELDS = {
    "vpcflow": {
        "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
        "action", "packets", "bytes", "start", "end",
        "account_id", "interface_id", "log_status", "version",
    },
    "cloudtrail": {
        "eventName", "eventSource", "eventTime", "sourceIPAddress",
        "userIdentity.type", "userIdentity.userName", "userIdentity.arn",
        "errorCode", "errorMessage", "requestParameters", "responseElements",
        "awsRegion", "recipientAccountId", "userAgent",
    },
}

_SIGMA_LOGSOURCE_MAP = {
    "vpcflow": {"product": "aws", "service": "vpcflow"},
    "cloudtrail": {"product": "aws", "service": "cloudtrail"},
}

# MITRE techniques that require specific evidence
_TECHNIQUE_EVIDENCE_REQUIREMENTS = {
    "T1071": "Application Layer Protocol (C2) — requires evidence of established C2 channel or beaconing",
    "T1041": "Exfiltration Over C2 Channel — requires evidence of data transfer",
    "T1059": "Command and Scripting Interpreter — requires evidence of command execution",
    "T1078": "Valid Accounts — requires evidence of credential use",
    "T1027": "Obfuscated Files — requires evidence of encoded/obfuscated content",
}


# ═══════════════════════════════════════════════════════════════════════
# VALIDATORS
# ═══════════════════════════════════════════════════════════════════════


def _check_evidence_wording(
    report: str,
    enrichment_status: str,
    datasources: list[str],
) -> list[Violation]:
    """Check 1: Evidence wording — catch overclaims."""
    violations = []

    # If enrichment is heuristic-only, flag "malicious" assertions
    if enrichment_status in ("HEURISTIC_ONLY", "NOT_PERFORMED"):
        for pattern, replacement in _HEURISTIC_FORBIDDEN_PATTERNS:
            for match in re.finditer(pattern, report):
                violations.append(Violation(
                    category="evidence_wording",
                    severity="ERROR",
                    message=f"'{match.group()}' used with {enrichment_status} enrichment — must qualify",
                    line_context=match.group(),
                    auto_fix=(match.group(), replacement),
                ))

    # If datasource has VPC flow with REJECT, flag exploitation terms
    has_vpcflow = "vpcflow" in datasources
    if has_vpcflow:
        for pattern, replacement in _REJECT_FORBIDDEN_PATTERNS:
            for match in re.finditer(pattern, report):
                violations.append(Violation(
                    category="evidence_wording",
                    severity="ERROR",
                    message=f"'{match.group()}' implies successful execution — inconsistent with REJECT events",
                    line_context=match.group(),
                    auto_fix=(match.group(), replacement) if replacement else None,
                ))

    return violations


def _check_datasource_fidelity(
    report: str,
    datasources: list[str],
) -> list[Violation]:
    """Check 2: Datasource fidelity — catch cross-datasource claims."""
    violations = []

    # Pure VPC flow — no auth/identity claims allowed
    has_only_vpcflow = datasources == ["vpcflow"] or (
        set(datasources) - {"email"} == {"vpcflow"}
    )
    if has_only_vpcflow or "vpcflow" in datasources:
        for pattern, desc in _VPCFLOW_FORBIDDEN_TERMS:
            for match in re.finditer(pattern, report, re.IGNORECASE):
                violations.append(Violation(
                    category="datasource_fidelity",
                    severity="ERROR",
                    message=f"Report claims '{desc}' but datasource is VPC Flow Logs only",
                    line_context=match.group(),
                ))

    # Email-only — no click/execution claims
    if "email" in datasources:
        for pattern, desc in _EMAIL_FORBIDDEN_TERMS:
            for match in re.finditer(pattern, report, re.IGNORECASE):
                violations.append(Violation(
                    category="datasource_fidelity",
                    severity="ERROR",
                    message=f"Report claims '{desc}'",
                    line_context=match.group(),
                ))

    return violations


def _check_threat_intel_consistency(
    report: str,
    enrichment_status: str,
) -> list[Violation]:
    """Check 3: Threat intel consistency — heuristic data shown as API."""
    violations = []

    if enrichment_status in ("HEURISTIC_ONLY", "NOT_PERFORMED"):
        # Instead of replacing individual VT/AbuseIPDB patterns (creates ugly repetition),
        # do a smart full-line cleanup of the IOC table Threat Intel Rep column.

        # Pattern: find IOC table rows and clean the last column (Threat Intel Rep)
        # IOC table format: | Type | Value | Context | Threat Intel Rep |
        ioc_table_rows = re.finditer(
            r"(\|[^|]+\|[^|]+\|[^|]+\|)([^|\n]+)\|?",
            report,
        )
        for match in ioc_table_rows:
            rep_cell = match.group(2).strip()
            # Skip header/separator rows
            if rep_cell.startswith("---") or rep_cell == "Threat Intel Rep":
                continue

            # Check if this cell has fake API numbers mixed with heuristic text
            has_fake_vt = bool(re.search(r"VT:\s*\d+/\d+", rep_cell))
            has_fake_abuse = bool(re.search(r"AbuseIPDB:\s*\d+", rep_cell))
            has_heuristic = "heuristic" in rep_cell.lower()

            if has_fake_vt or has_fake_abuse:
                # Extract useful context (brand impersonation, risk level, etc.)
                useful_context = []
                if "brand impersonation" in rep_cell.lower():
                    useful_context.append("brand impersonation pattern detected")
                if "failed WHOIS" in rep_cell or "WHOIS failed" in rep_cell:
                    useful_context.append("WHOIS lookup failed")
                risk_match = re.search(r"labeled\s+(HIGH|CRITICAL|MEDIUM)\s+risk", rep_cell, re.IGNORECASE)
                if risk_match:
                    useful_context.append(f"heuristic risk: {risk_match.group(1)}")
                geo_match = re.search(r"IP Geolocation:\s*([^.;|]+)", rep_cell)
                if geo_match:
                    useful_context.append(f"Geo: {geo_match.group(1).strip()}")

                # Build clean replacement
                if useful_context:
                    clean_rep = f"Heuristic Only; {'; '.join(useful_context)}"
                else:
                    clean_rep = "Heuristic Only"

                violations.append(Violation(
                    category="threat_intel_consistency",
                    severity="ERROR",
                    message=f"IOC rep cell shows fake API numbers with {enrichment_status} enrichment",
                    line_context=rep_cell[:100],
                    auto_fix=(rep_cell, clean_rep),
                ))

            elif not has_heuristic and rep_cell != "Not Enriched" and rep_cell.strip():
                # Check for other suspicious patterns
                if re.search(r"(BENIGN|Clean|Malicious)", rep_cell, re.IGNORECASE):
                    violations.append(Violation(
                        category="threat_intel_consistency",
                        severity="WARNING",
                        message=f"IOC rep cell uses API-style labels but enrichment is {enrichment_status}",
                        line_context=rep_cell[:100],
                    ))

    return violations


def _check_attack_hygiene(report: str) -> list[Violation]:
    """Check 4: ATT&CK hygiene — deprecated IDs, tactic IDs in wrong places."""
    violations = []

    # Find all technique IDs
    for match in re.finditer(r"\b(T\d{4}(?:\.\d{3})?)\b", report):
        tid = match.group(1)
        base_tid = tid.split(".")[0]
        if base_tid in _DEPRECATED_ATTACK_IDS:
            new_id = _DEPRECATED_ATTACK_IDS[base_tid]
            violations.append(Violation(
                category="attack_hygiene",
                severity="ERROR",
                message=f"Deprecated ATT&CK ID '{tid}' — should be '{new_id}'",
                line_context=match.group(),
                auto_fix=(tid, new_id),
            ))

    # Check Sigma tags section for tactic-only IDs (TA00xx without technique)
    sigma_section = _extract_section(report, "Detection Logic", "Containment")
    if sigma_section:
        for match in re.finditer(r"- (TA\d{4})\s*(?:#|$|\n)", sigma_section):
            violations.append(Violation(
                category="attack_hygiene",
                severity="WARNING",
                message=f"Sigma tag '{match.group(1)}' is a Tactic ID, not a Technique ID. Use T-prefixed technique IDs in Sigma tags.",
                line_context=match.group(1),
            ))

    # Check incorrect tactic descriptions
    tactic_map = {
        "TA0009": "Collection",
        "TA0005": "Defense Evasion",
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
    }
    for match in re.finditer(r"(TA\d{4})\s*[-–—]\s*(\w[\w\s]+)", report):
        tactic_id = match.group(1)
        claimed_name = match.group(2).strip()
        if tactic_id in tactic_map:
            correct_name = tactic_map[tactic_id]
            if correct_name.lower() not in claimed_name.lower():
                violations.append(Violation(
                    category="attack_hygiene",
                    severity="ERROR",
                    message=f"'{tactic_id}' is '{correct_name}', not '{claimed_name}'",
                    line_context=match.group(),
                ))

    return violations


def _check_sigma_consistency(
    report: str,
    datasources: list[str],
) -> list[Violation]:
    """Check 5: Sigma consistency — logsource, field names, fabricated fields."""
    violations = []

    sigma_section = _extract_section(report, "Detection Logic", "Containment")
    if not sigma_section:
        return violations

    # Check logsource matches datasource
    for ds in datasources:
        if ds in _SIGMA_LOGSOURCE_MAP:
            expected = _SIGMA_LOGSOURCE_MAP[ds]
            if expected["service"] not in sigma_section.lower():
                violations.append(Violation(
                    category="sigma_consistency",
                    severity="WARNING",
                    message=f"Sigma logsource should include service: {expected['service']} for {ds} datasource",
                    line_context="logsource section",
                ))

    # Check field names — auto-fix wrong names
    for ds, fixes in _SIGMA_FIELD_FIXES.items():
        if ds in datasources:
            for wrong, correct in fixes.items():
                if wrong in sigma_section:
                    violations.append(Violation(
                        category="sigma_consistency",
                        severity="ERROR",
                        message=f"Sigma field '{wrong}' should be '{correct}' for {ds}",
                        line_context=wrong,
                        auto_fix=(wrong, correct),
                    ))

    # Check for fabricated fields not in schema
    for ds in datasources:
        if ds in _SIGMA_ALLOWED_FIELDS:
            allowed = _SIGMA_ALLOWED_FIELDS[ds]
            # Collect known wrong names (already handled by field fix above)
            known_wrong_names = set(_SIGMA_FIELD_FIXES.get(ds, {}).keys())
            # Extract field names from detection section (key: value patterns in YAML)
            detection_block = _extract_section(sigma_section, "detection", "level") or sigma_section
            for match in re.finditer(r"^\s{2,}(\w+):", detection_block, re.MULTILINE):
                field_name = match.group(1)
                # Skip YAML structural keys
                if field_name in ("selection", "condition", "filter", "detection",
                                  "logsource", "product", "service", "title",
                                  "status", "description", "author", "date",
                                  "level", "tags", "falsepositives", "id", "fields"):
                    continue
                # Skip fields already handled by field name fixes
                if field_name in known_wrong_names:
                    continue
                if field_name not in allowed:
                    violations.append(Violation(
                        category="sigma_consistency",
                        severity="ERROR",
                        message=f"Sigma field '{field_name}' does not exist in {ds} schema. Valid fields: {', '.join(sorted(allowed)[:8])}...",
                        line_context=match.group(),
                    ))

    # Check T1566 sub-technique correctness
    if "attack.t1566.001" in sigma_section.lower():
        # T1566.001 = Attachment, T1566.002 = Link
        # If we see URL IOCs in the report, it should be .002
        if re.search(r"http[s]?://", report):
            violations.append(Violation(
                category="sigma_consistency",
                severity="ERROR",
                message="Sigma tag 'attack.t1566.001' (Attachment) but evidence shows URL-based phishing — should be 'attack.t1566.002' (Spearphishing Link)",
                line_context="attack.t1566.001",
                auto_fix=("attack.t1566.001", "attack.t1566.002"),
            ))

    # Check for unsupported techniques
    for match in re.finditer(r"attack\.(t\d{4}(?:\.\d{3})?)", sigma_section, re.IGNORECASE):
        tid = match.group(1).upper()
        base_tid = tid.split(".")[0]
        if base_tid in _TECHNIQUE_EVIDENCE_REQUIREMENTS:
            desc = _TECHNIQUE_EVIDENCE_REQUIREMENTS[base_tid]
            # Check if there's evidence for this technique anywhere in the report
            # For now, flag C2/exfil/exec techniques when we only have email+vpcflow REJECT
            has_only_reject = "vpcflow" in datasources and not re.search(r"action.*ACCEPT", report, re.IGNORECASE)
            if has_only_reject:
                violations.append(Violation(
                    category="sigma_consistency",
                    severity="ERROR",
                    message=f"Sigma tag '{match.group()}' requires {desc} — no supporting evidence in REJECT-only VPC flow data",
                    line_context=match.group(),
                ))

    return violations


def _check_ioc_preservation(report: str) -> list[Violation]:
    """Check 6: IOC preservation — no redaction of indicators."""
    violations = []

    redaction_patterns = [
        (r"\[EMAIL_REDACTED\]", "email address was redacted — IOCs must not be redacted"),
        (r"\[IP_REDACTED\]", "IP address was redacted — IOCs must not be redacted"),
        (r"\[DOMAIN_REDACTED\]", "domain was redacted — IOCs must not be redacted"),
        (r"\[URL_REDACTED\]", "URL was redacted — IOCs must not be redacted"),
    ]
    for pattern, msg in redaction_patterns:
        for match in re.finditer(pattern, report):
            violations.append(Violation(
                category="ioc_preservation",
                severity="ERROR",
                message=msg,
                line_context=match.group(),
            ))

    return violations


def _check_assertion_level(
    report: str,
    datasources: list[str],
) -> list[Violation]:
    """Check 7: Assertion level — catch unsupported intent claims."""
    violations = []

    for pattern, required_evidence in _UNSUPPORTED_INTENT_TERMS:
        for match in re.finditer(pattern, report):
            # Check if it's qualified (preceded by "assessed", "likely", "suggests", etc.)
            # Look at 100 chars before the match
            start = max(0, match.start() - 100)
            context_before = report[start:match.start()].lower()
            qualifiers = ["assessed", "likely", "suggests", "consistent with",
                          "possibly", "may indicate", "purpose.*unknown"]
            is_qualified = any(re.search(q, context_before) for q in qualifiers)

            if not is_qualified:
                violations.append(Violation(
                    category="assertion_level",
                    severity="WARNING",
                    message=f"'{match.group()}' used without qualifier — requires {required_evidence}",
                    line_context=match.group(),
                ))

    return violations


# ═══════════════════════════════════════════════════════════════════════
# MAIN VALIDATOR
# ═══════════════════════════════════════════════════════════════════════


def validate_report(
    report: str,
    datasources: list[str],
    enrichment_status: str,
) -> ValidationResult:
    """Run all validators on a draft report.

    Args:
        report: The LLM-generated report text.
        datasources: List of actual datasource types (e.g., ["email", "vpcflow"]).
        enrichment_status: One of "ENRICHED_API", "ENRICHED", "HEURISTIC_ONLY", "NOT_PERFORMED".

    Returns:
        ValidationResult with violations and auto-fixed report.
    """
    log = logger.bind(component="report_validator")

    all_violations: list[Violation] = []

    # Run all checks
    all_violations.extend(_check_evidence_wording(report, enrichment_status, datasources))
    all_violations.extend(_check_datasource_fidelity(report, datasources))
    all_violations.extend(_check_threat_intel_consistency(report, enrichment_status))
    all_violations.extend(_check_attack_hygiene(report))
    all_violations.extend(_check_sigma_consistency(report, datasources))
    all_violations.extend(_check_ioc_preservation(report))
    all_violations.extend(_check_assertion_level(report, datasources))

    # Auto-fix where possible
    fixed_report = report
    auto_fixed_count = 0

    for v in all_violations:
        if v.auto_fix and v.auto_fix[0] in fixed_report:
            old, new = v.auto_fix
            fixed_report = fixed_report.replace(old, new, 1)
            auto_fixed_count += 1

    # Log results
    log.info(
        "report_validator.complete",
        total_violations=len(all_violations),
        errors=sum(1 for v in all_violations if v.severity == "ERROR"),
        warnings=sum(1 for v in all_violations if v.severity == "WARNING"),
        auto_fixed=auto_fixed_count,
        categories=list({v.category for v in all_violations}),
    )

    for v in all_violations:
        log_fn = log.error if v.severity == "ERROR" else log.warning
        log_fn(
            "report_validator.violation",
            category=v.category,
            message=v.message,
            context=v.line_context[:100],
            has_fix=v.auto_fix is not None,
        )

    return ValidationResult(
        violations=all_violations,
        report=fixed_report,
        auto_fixed=auto_fixed_count,
    )


def format_violations_for_repair(violations: list[Violation]) -> str:
    """Format unfixed violations as repair instructions for a second LLM pass."""
    unfixed = [v for v in violations if v.auto_fix is None and v.severity == "ERROR"]
    if not unfixed:
        return ""

    lines = ["The following policy violations were found in your report. Fix each one:\n"]
    for i, v in enumerate(unfixed, 1):
        lines.append(f"{i}. [{v.category}] {v.message}")
        lines.append(f"   Context: \"{v.line_context[:150]}\"")
        lines.append("")

    return "\n".join(lines)


# ── Helpers ─────────────────────────────────────────────────────────────

def _extract_section(text: str, start_heading: str, end_heading: str) -> str | None:
    """Extract text between two markdown headings."""
    pattern = rf"#+\s*\d*\.?\s*{re.escape(start_heading)}(.*?)(?=#+\s*\d*\.?\s*{re.escape(end_heading)}|\Z)"
    match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else None
