"""
Forensic Analyst Agent -- LangGraph node.

Hybrid 2-Tier architecture:
  Tier 1: Programmatic anomaly detection (rules + Isolation Forest)
  Tier 2: ReAct agentic workflow (LLM + tools) -> forensic investigation + Sigma rule
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, HumanMessage

from bastion.agents.forensic_analyst.models import ForensicAnalysisOutput
from bastion.agents.forensic_analyst.prompts import FORENSIC_ANALYST_SYSTEM_PROMPT
from bastion.agents.forensic_analyst.sigma_generator import generate_sigma_rule
from bastion.agents.forensic_analyst.tier1_filter import run_anomaly_filter
from bastion.agents.forensic_analyst.tools import (
    cloudtrail_query_tool,
    mitre_attack_vector_tool,
    shared_state_lookup_tool,
)
from bastion.logger import get_logger
from bastion.models.state import BastionState

logger = get_logger(__name__)

REACT_TOOLS = [
    cloudtrail_query_tool,
    mitre_attack_vector_tool,
    shared_state_lookup_tool,
]

MAX_REACT_STEPS = 15


def forensic_analyst_node(state: BastionState) -> dict:
    """LangGraph node for the Forensic Analyst Agent.

    Flow:
    1. Extract log context from event_payload
    2. Run Tier 1 anomaly detection
       -> NORMAL: return LOW_RISK immediately
    3. Run Tier 2 ReAct agent with tools
    4. Generate Sigma detection rule
    5. Return findings + IOCs to shared state
    """
    log = logger.bind(agent="forensic_analyst", event_type=state.get("event_type"))
    log.info("forensic_analyst.start")

    event_payload = state.get("event_payload", {})
    now = datetime.now(timezone.utc).isoformat()

    # ── Extract log context from payload ────────────────────────────────
    context_data = _extract_log_context(event_payload)
    context_logs = context_data.get("context_logs", {})
    user = context_data.get("user", "")
    anomaly_trigger = context_data.get("anomaly_trigger", "")

    log.info(
        "forensic_analyst.context_extracted",
        user=user,
        record_count=len(context_logs.get("Records", [])),
        trigger=anomaly_trigger[:100],
    )

    # ── Tier 1: Anomaly Detection ───────────────────────────────────────
    tier1_result = run_anomaly_filter(context_logs, user)

    if tier1_result.decision == "NORMAL":
        log.info("forensic_analyst.tier1_normal", anomaly_score=tier1_result.anomaly_score)
        return _build_clean_response(tier1_result, now)

    log.info(
        "forensic_analyst.tier1_anomaly",
        rule_matches=tier1_result.rule_matches,
        anomaly_score=tier1_result.anomaly_score,
        escalating_to_tier2=True,
    )

    # ── Tier 2: ReAct Agent ─────────────────────────────────────────────
    try:
        analysis = _run_react_agent(
            context_logs, user, anomaly_trigger, tier1_result, state, log
        )
    except Exception:
        log.exception("forensic_analyst.react_error")
        analysis = _build_fallback_analysis(tier1_result)

    # ── Sigma Rule Generation ───────────────────────────────────────────
    try:
        sigma_rule = generate_sigma_rule(
            analysis,
            flagged_events=tier1_result.flagged_events,
            source_ips=tier1_result.source_ips,
            user=user,
        )
        analysis.generated_sigma_rule = sigma_rule
        log.info("forensic_analyst.sigma_generated", rule_length=len(sigma_rule))
    except Exception:
        log.exception("forensic_analyst.sigma_error")

    # ── Build state updates ─────────────────────────────────────────────
    return _build_response(analysis, tier1_result, now)


# ── Helper: extract log context from various payload formats ────────────

def _extract_log_context(payload: dict) -> dict:
    """Extract forensic context from different event payload structures."""
    detail = payload.get("detail", payload)

    context_logs = detail.get("context_logs", {})
    if not context_logs and "Records" in detail:
        context_logs = {"Records": detail["Records"]}

    user = detail.get("user", "")
    anomaly_trigger = detail.get("anomaly_trigger", "")

    # Try to extract user from records if not provided
    if not user and context_logs.get("Records"):
        for rec in context_logs["Records"]:
            identity = rec.get("userIdentity", {})
            user = identity.get("userName", "")
            if user:
                break

    return {
        "context_logs": context_logs,
        "user": user,
        "anomaly_trigger": anomaly_trigger,
    }


# ── Tier 2: ReAct Agent ────────────────────────────────────────────────

def _run_react_agent(
    context_logs: dict,
    user: str,
    anomaly_trigger: str,
    tier1_result,
    state: BastionState,
    log,
) -> ForensicAnalysisOutput:
    """Run the ReAct forensic investigation agent.
    
    Can use either:
    1. Semantic Analyzer (DL model) - fast, cheap, no LLM calls
    2. LLM ReAct agent (Gemini) - flexible, expensive
    
    Semantic analyzer is preferred when available and trained.
    """
    from bastion.config import config
    
    # Try semantic analyzer first if enabled
    if config.use_semantic_analyzer:
        try:
            from bastion.models.semantic_analyzer import get_cloudtrail_analyzer
            
            analyzer = get_cloudtrail_analyzer()
            
            log.info("forensic_analyst.using_semantic_analyzer", user=user)
            
            result = analyzer.analyze_sequence(
                events=context_logs.get("Records", []),
                user=user,
                context=anomaly_trigger,
            )
            
            confidence = result["confidence_score"]
            threshold = config.semantic_analyzer_threshold
            
            log.info(
                "forensic_analyst.semantic_complete",
                status=result["status"],
                confidence=confidence,
                threshold=threshold,
                will_fallback=confidence < threshold,
            )
            
            # Use semantic result if confidence is high
            if confidence >= threshold:
                log.info("forensic_analyst.semantic_accepted", confidence=confidence)
                
                return ForensicAnalysisOutput(
                    status=result["status"],
                    confidence_score=result["confidence_score"],
                    kill_chain_identified=result["kill_chain_identified"],
                    mitre_tactics=result["mitre_tactics"],
                    recommended_action=_generate_recommendation(result["status"]),
                    reasoning_chain=result["reasoning_chain"],
                )
            else:
                log.info(
                    "forensic_analyst.semantic_low_confidence",
                    confidence=confidence,
                    threshold=threshold,
                    falling_back_to_llm=True,
                )
        
        except Exception:
            log.warning(
                "forensic_analyst.semantic_error",
                message="Semantic analyzer failed, falling back to LLM ReAct",
                exc_info=True,
            )
            # Fall through to LLM ReAct agent
    
    # Use LLM ReAct agent (original implementation)
    from langgraph.prebuilt import create_react_agent

    from bastion.services.gemini import get_chat_model

    model = get_chat_model()

    react_agent = create_react_agent(
        model,
        REACT_TOOLS,
        messages_modifier=FORENSIC_ANALYST_SYSTEM_PROMPT,
    )

    # Build context for the agent
    records_summary = _summarize_records(context_logs.get("Records", []))
    existing_iocs = state.get("iocs", [])
    existing_findings = state.get("findings", [])

    ioc_context = ""
    if existing_iocs:
        ioc_lines = [
            f"  - [{ioc.get('ioc_type')}] {ioc.get('value')} (from {ioc.get('source_agent')})"
            for ioc in existing_iocs[:10]
        ]
        ioc_context = f"\n\nIOCs from other agents:\n" + "\n".join(ioc_lines)

    findings_context = ""
    if existing_findings:
        finding_lines = [
            f"  - [{f.get('severity')}] {f.get('agent')}: {f.get('description', '')[:100]}"
            for f in existing_findings[:5]
        ]
        findings_context = f"\n\nFindings from other agents:\n" + "\n".join(finding_lines)

    task_message = (
        f"Investigate the following security anomaly.\n\n"
        f"User: {user}\n"
        f"Anomaly Trigger: {anomaly_trigger}\n\n"
        f"Tier 1 anomaly filter flagged these rules: {tier1_result.rule_matches}\n"
        f"Anomaly score: {tier1_result.anomaly_score:.3f}\n"
        f"Source IPs: {tier1_result.source_ips}\n\n"
        f"Context CloudTrail Logs ({len(context_logs.get('Records', []))} events):\n"
        f"{records_summary}"
        f"{ioc_context}"
        f"{findings_context}\n\n"
        f"Use the available tools to conduct a thorough forensic investigation, "
        f"then provide your final analysis as a JSON object."
    )

    log.info("forensic_analyst.react_start", user=user, record_count=len(context_logs.get("Records", [])))

    result = react_agent.invoke(
        {"messages": [HumanMessage(content=task_message)]},
        config={"recursion_limit": MAX_REACT_STEPS},
    )

    # Parse the final message
    messages = result.get("messages", [])
    final_text = ""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content and not msg.tool_calls:
            final_text = msg.content
            break

    log.info("forensic_analyst.react_complete", response_length=len(final_text))

    return _parse_analysis_output(final_text, tier1_result)


def _generate_recommendation(status: str) -> str:
    """Generate recommended action based on status."""
    recommendations = {
        "CRITICAL_COMPROMISE": "IMMEDIATE ACTION: Revoke all credentials, isolate affected resources, initiate incident response.",
        "HIGH_RISK": "Revoke suspicious credentials, review access logs, enable MFA if not present.",
        "MEDIUM_RISK": "Monitor user activity closely, review permissions, consider additional authentication.",
        "LOW_RISK": "Log for review, no immediate action required.",
        "CLEAN": "No action required. Continue normal monitoring.",
    }
    return recommendations.get(status, "Manual investigation required.")


def _summarize_records(records: list[dict]) -> str:
    """Create a concise text summary of CloudTrail records for the agent."""
    if not records:
        return "No CloudTrail records provided.\n"

    lines = []
    for i, rec in enumerate(records[:20], 1):
        event_name = rec.get("eventName", "?")
        event_time = rec.get("eventTime", "?")
        src_ip = rec.get("sourceIPAddress", "?")
        error = rec.get("errorCode", "")
        identity = rec.get("userIdentity", {})
        user = identity.get("userName", identity.get("principalId", "?"))

        line = f"  [{i}] {event_time} | {event_name} | User: {user} | IP: {src_ip}"
        if error:
            line += f" | ERROR: {error}"

        # Add request details for sensitive events
        params = rec.get("requestParameters", {})
        if params and event_name in ("AssumeRole", "GetObject", "PutObject"):
            line += f" | Params: {json.dumps(params)[:150]}"

        lines.append(line)

    if len(records) > 20:
        lines.append(f"  ... and {len(records) - 20} more events")

    return "\n".join(lines) + "\n"


def _parse_analysis_output(text: str, tier1_result) -> ForensicAnalysisOutput:
    """Extract ForensicAnalysisOutput from the agent's final response."""
    try:
        json_str = _extract_json(text)
        if json_str:
            data = json.loads(json_str)
            return ForensicAnalysisOutput(
                status=data.get("status", "HIGH_RISK"),
                confidence_score=float(data.get("confidence_score", 0.7)),
                kill_chain_identified=data.get("kill_chain_identified", []),
                mitre_tactics=data.get("mitre_tactics", []),
                recommended_action=data.get("recommended_action", ""),
                reasoning_chain=data.get("reasoning_chain", text[:500]),
            )
    except (json.JSONDecodeError, ValueError, KeyError):
        pass

    return _build_fallback_analysis(tier1_result)


def _extract_json(text: str) -> str | None:
    """Extract the first JSON object from text."""
    import re
    match = re.search(r"```(?:json)?\s*\n?({.*?})\s*\n?```", text, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r"\{[^{}]*\"status\"[^{}]*\}", text, re.DOTALL)
    if match:
        return match.group(0)
    return None


# ── Response builders ───────────────────────────────────────────────────

def _build_clean_response(tier1_result, timestamp: str) -> dict:
    """Build a LOW_RISK response when Tier 1 detects no anomalies."""
    return {
        "findings": [
            {
                "agent": "forensic_analyst",
                "finding_type": "log_analysis",
                "severity": "INFO",
                "evidence": {"tier1_result": tier1_result.model_dump()},
                "mitre_tactic": "",
                "description": "Tier 1 anomaly filter: NORMAL. No suspicious patterns detected.",
                "timestamp": timestamp,
            }
        ],
        "iocs": [],
        "messages": [
            AIMessage(content="[Forensic Analyst] Tier 1 filter: NORMAL. No anomalies detected.")
        ],
    }


def _build_response(
    analysis: ForensicAnalysisOutput,
    tier1_result,
    timestamp: str,
) -> dict:
    """Build the full state update from a completed forensic analysis."""
    severity_map = {
        "CRITICAL_COMPROMISE": "CRITICAL",
        "HIGH_RISK": "HIGH",
        "MEDIUM_RISK": "MEDIUM",
        "LOW_RISK": "LOW",
        "CLEAN": "INFO",
    }

    sigma_note = ""
    if analysis.generated_sigma_rule:
        sigma_note = f" Sigma rule generated ({len(analysis.generated_sigma_rule)} chars)."

    findings = [
        {
            "agent": "forensic_analyst",
            "finding_type": "forensic_investigation",
            "severity": severity_map.get(analysis.status, "HIGH"),
            "evidence": {
                "status": analysis.status,
                "confidence_score": analysis.confidence_score,
                "kill_chain": analysis.kill_chain_identified,
                "mitre_tactics": analysis.mitre_tactics,
                "recommended_action": analysis.recommended_action,
                "tier1_rule_matches": tier1_result.rule_matches,
                "tier1_anomaly_score": tier1_result.anomaly_score,
                "has_sigma_rule": bool(analysis.generated_sigma_rule),
            },
            "mitre_tactic": ", ".join(analysis.mitre_tactics) if analysis.mitre_tactics else "",
            "description": analysis.reasoning_chain[:500],
            "timestamp": timestamp,
        }
    ]

    # IOCs from source IPs
    iocs = []
    for ip in tier1_result.source_ips:
        iocs.append({
            "ioc_type": "ip",
            "value": ip,
            "source_agent": "forensic_analyst",
            "context": f"Source IP in {analysis.status} forensic investigation",
        })

    kill_chain_str = " -> ".join(analysis.kill_chain_identified) if analysis.kill_chain_identified else "N/A"
    summary = (
        f"[Forensic Analyst] Verdict: {analysis.status} "
        f"(confidence: {analysis.confidence_score:.0%}). "
        f"Kill-chain: {kill_chain_str}. "
        f"MITRE: {', '.join(analysis.mitre_tactics)}. "
        f"Action: {analysis.recommended_action[:100]}.{sigma_note}"
    )

    return {
        "findings": findings,
        "iocs": iocs,
        "messages": [AIMessage(content=summary)],
    }


def _build_fallback_analysis(tier1_result) -> ForensicAnalysisOutput:
    """Build a fallback analysis when ReAct agent fails."""
    # Determine severity from rule matches
    has_high_risk = any("high_risk_api" in r for r in tier1_result.rule_matches)
    status = "HIGH_RISK" if has_high_risk else "MEDIUM_RISK"

    return ForensicAnalysisOutput(
        status=status,
        confidence_score=0.4 + (tier1_result.anomaly_score / 5),
        kill_chain_identified=[],
        mitre_tactics=[],
        recommended_action="Manual investigation required -- ReAct agent failed.",
        reasoning_chain=(
            f"Tier 1 flagged {len(tier1_result.rule_matches)} rules: "
            f"{', '.join(tier1_result.rule_matches[:5])}. "
            f"Anomaly score: {tier1_result.anomaly_score:.3f}. "
            f"ReAct agent failed -- using rule-based fallback."
        ),
    )
