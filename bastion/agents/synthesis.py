"""
Synthesis Agent.

Receives all findings and IOCs gathered by other agents,
and calls Gemini to synthesize a final executive summary report.

Evidence discipline: reports must separate observed facts from assessed
inferences, use real timestamps, match Sigma to actual datasource, and
never hallucinate enrichment data.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from langchain_core.messages import AIMessage

from bastion.logger import get_logger
from bastion.models.state import BastionState

logger = get_logger(__name__)

SYNTHESIS_SYSTEM_PROMPT = """\
You are an elite Lead Incident Responder of the BASTION Autonomous SOC.
Your job is to read all findings, IOCs, and forensic results collected by your sub-agents,
and synthesize them into a highly professional, structured Executive Markdown Report.

## EVIDENCE DISCIPLINE — MANDATORY RULES

1. **Observed vs Assessed**: Every claim MUST be traceable to a specific field in the input data.
   - "Observed" = directly present in the data (log field, email header, network flow, API event).
   - "Assessed" = your inference based on observed data. Always qualify with "likely", "suggests", "consistent with".
   - NEVER present an assessment as an observed fact.
   - Test: "which field in the input proves this sentence?" If you cannot answer, delete the sentence or downgrade to weak inference.

2. **Timestamp**: Use ONLY the INCIDENT_WINDOW provided in the metadata below. Do NOT invent dates.

3. **Datasource fidelity**: 
   - Only make claims that the actual datasource type can support:
     * VPC Flow Logs → connection attempts, src/dst IPs, ports, protocols, accept/reject. CANNOT prove authentication, API calls, user identity.
     * CloudTrail → API calls, user identity, auth events, resource access. CANNOT prove network-layer connections.
     * Email → sender, subject, body, headers, URLs. CANNOT prove whether a URL was clicked or payload executed.
   - Rejected/blocked events = "rejected connection attempts" or "blocked suspicious activity". NEVER "exploitation" (exploitation requires successful execution, which rejection disproves).
   - If correlated events exist across datasources (e.g., same IP in email and network logs), acknowledge the correlation explicitly.

4. **Threat Intel transparency**:
   - If enrichment_source is "api": show real API results (e.g., "VT: 5/94 Malicious")
   - If enrichment_source is "heuristic": write "Heuristic Analysis Only"
   - If enrichment_source is "skip" or IOC is a private IP: write "Skipped (Internal IP)"
   - If enrichment was NOT performed: write "Not Enriched"
   - NEVER fabricate reputation numbers from heuristic data.
   - IOC Context: use "contextually suspicious" not "MALICIOUS" unless real API data confirms maliciousness.

5. **Sigma rule**:
   - Logsource MUST match ACTUAL_DATASOURCES from metadata.
   - Prefer pattern-based behavioral detection over IOC-centric rules. IOC rules catch one attacker; behavioral rules catch the technique.
   - If no suitable Sigma logsource exists for the data type, write "Not applicable for [datasource type]".

6. **Scope honesty**: 
   - Say "No evidence of X is present in the provided dataset" instead of "X has not been confirmed".
   - Heuristic labels (mapped_attack_label, risk_score) are upstream tags, NOT confirmed evidence. Qualify as "labeled as" not "confirmed as".
   - Do NOT claim a URL is "malicious" as fact. Say "suspicious URL" or qualify as assessed inference.
   - Do NOT claim specific attack intent (e.g., "credential harvesting", "data exfiltration") without supporting evidence (login form, download, POST endpoint, data volume anomaly, etc.).

7. **IOC preservation**: Show full IOC values (IPs, domains, email addresses, hashes, URLs). These are indicators, not PII. Do NOT redact them.

8. **MITRE ATT&CK taxonomy**:
   - Use ONLY current, non-deprecated technique IDs.
   - Deprecated IDs to avoid: T1192→T1566.002, T1193→T1566.001, T1194→T1566.003, T1064→T1059, T1015→T1546.008.
   - Match technique to what the evidence actually shows, not what you infer the attacker intended.

## REPORT STRUCTURE

# 🛡️ BASTION Security Incident Report
**Incident Window:** INCIDENT_WINDOW_PLACEHOLDER | **Verdict:** [CRITICAL COMPROMISE / HIGH RISK / MEDIUM RISK / FALSE POSITIVE]

## 1. Executive Summary
[2-3 sentences. State ONLY what is directly supported by evidence from the input data.]

## 2. Attack Scenario (Kill Chain)
For each stage, clearly separate observed facts from assessed inferences.
Only include stages that have at least observed evidence OR correlated data from another stage:
- **[Stage Name]:** 
  - *Observed:* [what the data directly shows, citing datasource type]
  - *Assessed:* [your inference, always qualified]

## 3. Indicators of Compromise (IOCs)
| Indicator Type | Value | Context | Threat Intel Rep |
|---|---|---|---|
[Show full IOC values. Context = where the IOC was found, not assertion of maliciousness.]

## 4. Detection Logic (Sigma Rule)
[Logsource must match actual datasource. Prefer behavioral patterns.]
[If no suitable Sigma logsource exists, state "Not applicable" with reason.]
```yaml
title: ...
logsource:
   product: [must match actual data]
   service: [must match actual data]
detection:
   ...
tags:
   - [current MITRE ATT&CK IDs only]
```

## 5. Containment & Remediation
[3-4 concrete, actionable steps based on observed evidence only.]
"""


def _extract_incident_timestamp(state: BastionState) -> tuple[str, str]:
    """Extract the real incident timestamp from event data."""
    timestamps = []

    payload = state.get("event_payload", {})
    detail = payload.get("detail", {})

    if isinstance(detail, dict):
        # From email Date header (in raw_eml)
        raw_eml = detail.get("raw_eml", "")
        date_match = re.search(r"Date:\s*(.+?)(?:\n|$)", raw_eml)
        if date_match:
            timestamps.append(date_match.group(1).strip())

        # From network events
        for evt in detail.get("aws_network_events", []):
            ts = evt.get("cloudwatch_timestamp", "")
            if ts:
                timestamps.append(ts)

        # From email_event Date field
        email_event = detail.get("email_event", {})
        if isinstance(email_event, dict):
            email_date = email_event.get("Date", "")
            if email_date and email_date not in timestamps:
                timestamps.append(email_date)

    elif isinstance(detail, list):
        for record in detail:
            if isinstance(record, dict):
                for key in ("eventTime", "timestamp", "cloudwatch_timestamp"):
                    ts = record.get(key, "")
                    if ts:
                        timestamps.append(ts)

    if timestamps:
        timestamps.sort()
        earliest = timestamps[0]
        latest = timestamps[-1]
        if earliest == latest:
            return earliest, earliest
        return earliest, latest

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return now, now


def _detect_datasource_types(state: BastionState) -> list[str]:
    """Detect what types of data sources are present in the input."""
    sources = []
    payload = state.get("event_payload", {})
    detail = payload.get("detail", {})

    if isinstance(detail, dict):
        if detail.get("raw_eml"):
            sources.append("email")
        if detail.get("email_event"):
            if "email" not in sources:
                sources.append("email")
        if detail.get("aws_network_events"):
            sources.append("vpcflow")

    # Check findings for datasource tags
    for f in state.get("findings", []):
        ds = f.get("datasource", "")
        if ds and ds not in sources:
            sources.append(ds)

    event_type = state.get("event_type", "")
    if event_type == "cloudtrail" and "cloudtrail" not in sources:
        sources.append("cloudtrail")
    elif event_type == "email" and "email" not in sources:
        sources.append("email")

    return sources or ["unknown"]


def _check_enrichment_status(state: BastionState) -> str:
    """Check if threat intel enrichment was actually performed."""
    findings = state.get("findings", [])
    threat_findings = [f for f in findings if f.get("agent") == "threat_intel"]

    if not threat_findings:
        return "NOT_PERFORMED"

    # Check if any enrichment has actual data
    for f in threat_findings:
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            enrichments = evidence.get("ioc_enrichments", [])
            if enrichments:
                # Check enrichment source
                for e in enrichments:
                    if isinstance(e, dict):
                        src = e.get("enrichment_source", "")
                        if src == "api":
                            return "ENRICHED_API"
                        if e.get("virustotal") or e.get("abuseipdb"):
                            return "ENRICHED"
        return "HEURISTIC_ONLY"

    return "NOT_PERFORMED"


def synthesis_node(state: BastionState) -> dict:
    """Synthesis node for LangGraph."""
    log = logger.bind(agent="synthesis", event_type=state.get("event_type"))
    log.info("synthesis.start")
    ts_now = datetime.now(timezone.utc).isoformat()

    findings = state.get("findings", [])
    iocs = state.get("iocs", [])

    if not findings and not iocs:
        return {
            "final_report": "No significant findings or anomalies detected during analysis.",
            "messages": [AIMessage(content="[Synthesis] No findings to report.")],
            "pipeline_logs": [{"node": "synthesis", "action": "Analysis complete", "detail": "No significant findings or IOCs detected. Event appears benign.", "ts": ts_now}],
        }

    # Extract real metadata from state
    ts_earliest, ts_latest = _extract_incident_timestamp(state)
    if ts_earliest == ts_latest:
        incident_window = ts_earliest
    else:
        incident_window = f"{ts_earliest} – {ts_latest}"
    datasource_types = _detect_datasource_types(state)
    enrichment_status = _check_enrichment_status(state)

    log.info(
        "synthesis.metadata",
        incident_window=incident_window,
        datasources=datasource_types,
        enrichment=enrichment_status,
    )

    try:
        # Build context with real metadata injected
        metadata_block = (
            f"=== INCIDENT METADATA (use these values, do NOT invent) ===\n"
            f"INCIDENT_WINDOW: {incident_window}\n"
            f"ACTUAL_DATASOURCES: {', '.join(datasource_types)}\n"
            f"ENRICHMENT_STATUS: {enrichment_status}\n"
            f"TOTAL_FINDINGS: {len(findings)}\n"
            f"TOTAL_IOCS: {len(iocs)}\n"
            f"=== END METADATA ===\n\n"
        )

        user_message = (
            f"{metadata_block}"
            f"Please synthesize the following security findings into a final report:\n\n"
            f"Findings: {findings}\n\n"
            f"IOCs: {iocs}"
        )

        from bastion.services.gemini import call_gemini

        final_report = call_gemini(
            prompt=user_message,
            system_prompt=SYNTHESIS_SYSTEM_PROMPT,
        )

        # Post-process: inject real incident window (in case LLM ignored our instruction)
        final_report = final_report.replace(
            "INCIDENT_WINDOW_PLACEHOLDER", incident_window
        )

        # ── Claim Validator: deterministic policy gate ──────────────────
        from bastion.services.report_validator import (
            validate_report,
            format_violations_for_repair,
        )

        validation = validate_report(
            report=final_report,
            datasources=datasource_types,
            enrichment_status=enrichment_status,
        )
        final_report = validation.report  # Apply auto-fixes

        log.info(
            "synthesis.validation",
            total_violations=len(validation.violations),
            auto_fixed=validation.auto_fixed,
            has_remaining_errors=validation.has_errors,
        )

        # If unfixed ERROR violations remain, do one repair pass
        if validation.has_errors:
            repair_instructions = format_violations_for_repair(validation.violations)
            if repair_instructions:
                log.info("synthesis.repair_pass", unfixed_errors=repair_instructions.count("\n"))
                repair_prompt = (
                    f"Your draft report has the following policy violations. "
                    f"Rewrite the report fixing ONLY these issues. "
                    f"Keep everything else exactly the same.\n\n"
                    f"{repair_instructions}\n\n"
                    f"=== DRAFT REPORT ===\n{final_report}"
                )
                final_report = call_gemini(
                    prompt=repair_prompt,
                    system_prompt=SYNTHESIS_SYSTEM_PROMPT,
                )
                # Re-inject incident window after repair
                final_report = final_report.replace(
                    "INCIDENT_WINDOW_PLACEHOLDER", incident_window
                )
                # Re-validate (log only, no further repair)
                repair_validation = validate_report(
                    report=final_report,
                    datasources=datasource_types,
                    enrichment_status=enrichment_status,
                )
                final_report = repair_validation.report
                log.info(
                    "synthesis.repair_validation",
                    remaining_violations=len(repair_validation.violations),
                    remaining_errors=sum(1 for v in repair_validation.violations if v.severity == "ERROR"),
                )

        log.info("synthesis.complete", report_length=len(final_report))

        # Calculate risk score
        score = 0.0
        for f in findings:
            sev = str(f.get("severity", "LOW")).upper()
            if sev == "CRITICAL": score += 0.4
            elif sev == "HIGH": score += 0.25
            elif sev == "MEDIUM": score += 0.15
            elif sev == "LOW": score += 0.08
            elif sev == "INFO": score += 0.05
            else: score += 0.1

        ioc_bonus = min(0.2, len(iocs) * 0.03)
        score += ioc_bonus

        if findings and score < 0.15:
            score = 0.15

        risk_score = min(1.0, score)

    except Exception:
        log.exception("synthesis.error")
        final_report = "Error generating final synthesis report."
        risk_score = 0.5

    return {
        "final_report": final_report,
        "risk_score": risk_score,
        "messages": [AIMessage(content="[Synthesis] Final report generated successfully.")],
        "pipeline_logs": [
            {"node": "synthesis", "action": "Generating executive report", "detail": f"Synthesizing {len(findings)} findings and {len(iocs)} IOCs | Datasources: {', '.join(datasource_types)} | Enrichment: {enrichment_status}", "ts": ts_now},
            {"node": "synthesis", "action": "Risk score computed", "detail": f"Final risk score: {(risk_score*100):.0f}% — Report length: {len(final_report)} chars", "ts": ts_now},
        ],
    }
