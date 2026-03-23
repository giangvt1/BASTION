"""
Threat Intelligence Agent -- LangGraph node.

Hybrid 2-Tier architecture:
  Tier 1: Programmatic IOC pre-filter (no LLM) -> triage
  Tier 2: ReAct agentic workflow (LLM + 4 tools) -> deep enrichment + self-reflection
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, HumanMessage

from bastion.agents.threat_intel.models import ThreatIntelOutput
from bastion.agents.threat_intel.prompts import (
    SELF_REFLECTION_PROMPT_TEMPLATE,
    THREAT_INTEL_SYSTEM_PROMPT,
)
from bastion.agents.threat_intel.tier1_filter import run_ioc_filter
from bastion.agents.threat_intel.tools import (
    abuseipdb_check,
    ip_geolocation,
    virustotal_lookup,
    whois_domain_lookup,
)
from bastion.logger import get_logger
from bastion.models.state import BastionState

logger = get_logger(__name__)

REACT_TOOLS = [
    virustotal_lookup,
    abuseipdb_check,
    whois_domain_lookup,
    ip_geolocation,
]

MAX_REACT_STEPS = 15


def threat_intel_node(state: BastionState) -> dict:
    """LangGraph node for the Threat Intelligence Agent.

    Flow:
    1. Collect IOCs from shared state
    2. Run Tier 1 static IOC filter
       -> SKIP: return BENIGN immediately (no LLM cost)
    3. Run Tier 2 ReAct agent with tools
    4. Run self-reflection check
    5. Return enriched findings + IOCs to shared state
    """
    log = logger.bind(agent="threat_intel", event_type=state.get("event_type"))
    log.info("threat_intel.start")

    now = datetime.now(timezone.utc).isoformat()
    iocs = state.get("iocs", [])
    existing_findings = state.get("findings", [])

    log.info("threat_intel.iocs_received", ioc_count=len(iocs))

    # ── Tier 1: Static IOC Filter ───────────────────────────────────────
    tier1_result = run_ioc_filter(iocs)

    if tier1_result.decision == "SKIP":
        log.info(
            "threat_intel.tier1_skip",
            skipped=len(tier1_result.skipped_iocs),
        )
        return _build_skip_response(tier1_result, now)

    log.info(
        "threat_intel.tier1_analyze",
        filtered_iocs=len(tier1_result.filtered_iocs),
        risk_score=tier1_result.static_risk_score,
        escalating_to_tier2=True,
    )

    # ── Tier 2: ReAct Agent ─────────────────────────────────────────────
    try:
        analysis = _run_react_agent(
            tier1_result, existing_findings, log,
        )
    except Exception:
        log.exception("threat_intel.react_error")
        analysis = _build_fallback_analysis(tier1_result)

    # ── Self-Reflection ─────────────────────────────────────────────────
    try:
        analysis = _run_self_reflection(
            analysis, tier1_result, existing_findings, log,
        )
    except Exception:
        log.exception("threat_intel.reflection_error")

    # ── Build state updates ─────────────────────────────────────────────
    return _build_response(analysis, tier1_result, now)


# ── Tier 2: ReAct Agent ────────────────────────────────────────────────

def _run_react_agent(
    tier1_result,
    existing_findings: list[dict],
    log,
) -> ThreatIntelOutput:
    """Run the ReAct threat intelligence enrichment agent."""
    from langgraph.prebuilt import create_react_agent

    from bastion.services.gemini import get_chat_model

    model = get_chat_model()

    react_agent = create_react_agent(
        model,
        REACT_TOOLS,
        prompt=THREAT_INTEL_SYSTEM_PROMPT,
    )

    # Build IOC summary for the agent
    ioc_lines = []
    for ioc in tier1_result.filtered_iocs:
        ioc_lines.append(
            f"  - [{ioc.get('ioc_type')}] {ioc.get('value')} "
            f"(from {ioc.get('source_agent', 'unknown')}: {ioc.get('context', '')})"
        )
    ioc_summary = "\n".join(ioc_lines)

    # Include findings from other agents for context
    findings_context = ""
    if existing_findings:
        finding_lines = [
            f"  - [{f.get('severity')}] {f.get('agent')}: {f.get('description', '')[:100]}"
            for f in existing_findings[:5]
        ]
        findings_context = f"\n\nFindings from other agents:\n" + "\n".join(finding_lines)

    # Include static risk indicators
    indicator_context = ""
    if tier1_result.static_risk_indicators:
        indicator_context = (
            f"\n\nTier 1 static risk indicators:\n"
            + "\n".join(f"  - {ind}" for ind in tier1_result.static_risk_indicators)
        )

    task_message = (
        f"Assess the following IOCs for threat intelligence.\n\n"
        f"IOCs to analyze ({len(tier1_result.filtered_iocs)}):\n"
        f"{ioc_summary}"
        f"{indicator_context}"
        f"{findings_context}\n\n"
        f"Use the available tools to enrich each IOC with reputation data, "
        f"geolocation, and WHOIS information. Then provide your final "
        f"threat assessment as a JSON object."
    )

    log.info(
        "threat_intel.react_start",
        ioc_count=len(tier1_result.filtered_iocs),
    )

    result = react_agent.invoke(
        {"messages": [HumanMessage(content=task_message)]},
        config={"recursion_limit": MAX_REACT_STEPS},
    )

    # Parse the final message from the agent
    messages = result.get("messages", [])
    final_text = ""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content and not msg.tool_calls:
            final_text = msg.content
            break

    log.info("threat_intel.react_complete", response_length=len(final_text))

    return _parse_analysis_output(final_text, tier1_result)


def _parse_analysis_output(text: str, tier1_result) -> ThreatIntelOutput:
    """Extract ThreatIntelOutput from the agent's final response."""
    try:
        json_str = _extract_json(text)
        if json_str:
            data = json.loads(json_str)
            return ThreatIntelOutput(
                status=data.get("status", "SUSPICIOUS"),
                confidence_score=float(data.get("confidence_score", 0.7)),
                ioc_enrichments=data.get("ioc_enrichments", []),
                mitre_tactics=data.get("mitre_tactics", []),
                threat_actor_attribution=data.get("threat_actor_attribution", ""),
                recommended_action=data.get("recommended_action", ""),
                reasoning_chain=data.get("reasoning_chain", text[:500]),
            )
    except (json.JSONDecodeError, ValueError, KeyError):
        pass

    return _build_fallback_analysis(tier1_result)


def _extract_json(text) -> str | None:
    """Extract the first JSON object from text."""
    import re
    if isinstance(text, list):
        if text and isinstance(text[0], dict) and "text" in text[0]:
            text = text[0]["text"]
        else:
            text = str(text)
    elif not isinstance(text, str):
        text = str(text)
        
    # Try markdown json blocks first
    match = re.search(r"```(?:json)?\s*\n?(.*?)\s*\n?```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # Try finding the first '{' and last '}'
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        return text[start_idx:end_idx+1]
        
    return None


# ── Self-Reflection ─────────────────────────────────────────────────────

def _run_self_reflection(
    analysis: ThreatIntelOutput,
    tier1_result,
    existing_findings: list[dict],
    log,
) -> ThreatIntelOutput:
    """Run a self-reflection check to reduce false positives."""
    if analysis.status == "BENIGN":
        return analysis

    from bastion.services.gemini import call_gemini

    ioc_lines = []
    for ioc in tier1_result.filtered_iocs[:10]:
        ioc_lines.append(f"  - [{ioc.get('ioc_type')}] {ioc.get('value')}")
    ioc_summary = "\n".join(ioc_lines)

    findings_lines = [
        f"  - [{f.get('severity')}] {f.get('agent')}: {f.get('description', '')[:80]}"
        for f in existing_findings[:3]
    ]
    agent_context = "\n".join(findings_lines) if findings_lines else "No prior findings."

    prompt = SELF_REFLECTION_PROMPT_TEMPLATE.format(
        verdict=analysis.status,
        confidence=analysis.confidence_score,
        reasoning=analysis.reasoning_chain[:1000],
        ioc_summary=ioc_summary,
        agent_context=agent_context,
    )

    log.info("threat_intel.self_reflection_start")
    response = call_gemini(prompt)
    log.info("threat_intel.self_reflection_complete", response_length=len(response))

    try:
        json_str = _extract_json(response)
        if json_str:
            data = json.loads(json_str)
            if data.get("reflection_decision") == "REVISED":
                log.info(
                    "threat_intel.verdict_revised",
                    old_verdict=analysis.status,
                    new_verdict=data.get("revised_verdict"),
                )
                return ThreatIntelOutput(
                    status=data.get("revised_verdict", analysis.status),
                    confidence_score=float(
                        data.get("revised_confidence", analysis.confidence_score)
                    ),
                    ioc_enrichments=analysis.ioc_enrichments,
                    mitre_tactics=analysis.mitre_tactics,
                    threat_actor_attribution=analysis.threat_actor_attribution,
                    recommended_action=analysis.recommended_action,
                    reasoning_chain=(
                        f"{analysis.reasoning_chain}\n\n"
                        f"[Self-Reflection] {data.get('reflection_reasoning', '')}"
                    ),
                )
    except (json.JSONDecodeError, ValueError, KeyError):
        log.warning("threat_intel.reflection_parse_failed")

    return analysis


# ── Response builders ───────────────────────────────────────────────────

def _build_skip_response(tier1_result, timestamp: str) -> dict:
    """Build a BENIGN response when Tier 1 finds only benign IOCs."""
    skipped_desc = ", ".join(
        f"{s.get('value')} ({s.get('_skip_reason', '?')})"
        for s in tier1_result.skipped_iocs[:5]
    )

    return {
        "findings": [
            {
                "agent": "threat_intel",
                "finding_type": "ioc_assessment",
                "severity": "INFO",
                "evidence": {"tier1_result": tier1_result.model_dump()},
                "mitre_tactic": "",
                "description": (
                    f"Tier 1 IOC filter: SKIP. All IOCs are benign/whitelisted. "
                    f"Skipped: {skipped_desc or 'none'}."
                ),
                "timestamp": timestamp,
            }
        ],
        "iocs": [],
        "messages": [
            AIMessage(
                content=(
                    f"[Threat Intel] Tier 1 filter: SKIP. "
                    f"All {len(tier1_result.skipped_iocs)} IOCs are benign/whitelisted."
                )
            )
        ],
        "pipeline_logs": [{
            "node": "threat_intel",
            "action": "Analysis Skipped",
            "detail": f"All {len(tier1_result.skipped_iocs)} IOCs are benign/whitelisted.",
            "ts": timestamp
        }],
    }


def _build_response(
    analysis: ThreatIntelOutput,
    tier1_result,
    timestamp: str,
) -> dict:
    """Build the full state update from a completed threat intel analysis."""
    severity_map = {
        "MALICIOUS": "CRITICAL",
        "SUSPICIOUS": "HIGH",
        "BENIGN": "LOW",
        "UNKNOWN": "MEDIUM",
    }

    findings = [
        {
            "agent": "threat_intel",
            "finding_type": "ioc_assessment",
            "severity": severity_map.get(analysis.status, "MEDIUM"),
            "evidence": {
                "status": analysis.status,
                "confidence_score": analysis.confidence_score,
                "ioc_enrichments": [e.model_dump() if hasattr(e, "model_dump") else e
                                    for e in analysis.ioc_enrichments],
                "mitre_tactics": analysis.mitre_tactics,
                "threat_actor": analysis.threat_actor_attribution,
                "tier1_risk_score": tier1_result.static_risk_score,
                "tier1_indicators": tier1_result.static_risk_indicators,
            },
            "mitre_tactic": ", ".join(analysis.mitre_tactics) if analysis.mitre_tactics else "",
            "description": analysis.reasoning_chain[:500],
            "timestamp": timestamp,
        }
    ]

    # Enriched IOCs -- re-emit with threat intel context
    enriched_iocs = []
    for ioc in tier1_result.filtered_iocs:
        enriched_iocs.append({
            "ioc_type": ioc.get("ioc_type", "unknown"),
            "value": ioc.get("value", ""),
            "source_agent": "threat_intel",
            "context": (
                f"Enriched by Threat Intel: {analysis.status} "
                f"(confidence: {analysis.confidence_score:.0%})"
            ),
        })

    summary = (
        f"[Threat Intel] Verdict: {analysis.status} "
        f"(confidence: {analysis.confidence_score:.0%}). "
        f"IOCs analyzed: {len(tier1_result.filtered_iocs)}. "
        f"MITRE: {', '.join(analysis.mitre_tactics) or 'N/A'}. "
        f"Action: {analysis.recommended_action[:100] or 'N/A'}."
    )

    if analysis.threat_actor_attribution:
        summary += f" Attribution: {analysis.threat_actor_attribution}."

    return {
        "findings": findings,
        "iocs": enriched_iocs,
        "messages": [AIMessage(content=summary)],
        "pipeline_logs": [{
            "node": "threat_intel",
            "action": f"Verdict: {analysis.status}",
            "detail": summary,
            "ts": timestamp
        }],
    }


def _build_fallback_analysis(tier1_result) -> ThreatIntelOutput:
    """Build a fallback analysis when the ReAct agent fails."""
    has_high_risk = any(
        "tor_exit" in ind or "brand_impersonation" in ind
        for ind in tier1_result.static_risk_indicators
    )
    status = "SUSPICIOUS" if has_high_risk else "UNKNOWN"

    return ThreatIntelOutput(
        status=status,
        confidence_score=0.3 + (tier1_result.static_risk_score / 200),
        ioc_enrichments=[],
        mitre_tactics=[],
        threat_actor_attribution="",
        recommended_action="Manual investigation required -- ReAct agent failed.",
        reasoning_chain=(
            f"Tier 1 flagged {len(tier1_result.static_risk_indicators)} indicators: "
            f"{', '.join(tier1_result.static_risk_indicators[:5])}. "
            f"Risk score: {tier1_result.static_risk_score}. "
            f"ReAct agent failed -- using rule-based fallback."
        ),
    )
