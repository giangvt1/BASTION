"""
Email Analyst Agent -- LangGraph node.

Hybrid 2-Tier architecture:
  Tier 1: Programmatic static filter (no LLM) -> triage
  Tier 2: ReAct agentic workflow (LLM + tools) -> deep analysis + self-reflection
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from bastion.agents.email_analyst.models import EmailAnalysisOutput
from bastion.agents.email_analyst.prompts import (
    EMAIL_ANALYST_SYSTEM_PROMPT,
    SELF_REFLECTION_PROMPT_TEMPLATE,
)
from bastion.agents.email_analyst.tier1_filter import run_static_filter
from bastion.agents.email_analyst.tools import (
    analyze_url_structure,
    extract_eml_components,
    extract_network_entities,
    vector_similarity_search,
)
from bastion.logger import get_logger
from bastion.models.state import BastionState

logger = get_logger(__name__)

REACT_TOOLS = [
    extract_eml_components,
    extract_network_entities,
    vector_similarity_search,
    analyze_url_structure,
]

MAX_REACT_STEPS = 12


def email_analyst_node(state: BastionState) -> dict:
    """LangGraph node for the Email Analyst Agent.

    Flow:
    1. Extract email data from event_payload
    2. Run Tier 1 static filter
       -> CLEAN: return SAFE immediately (no LLM cost)
    3. Run Tier 2 ReAct agent with tools
    4. Run self-reflection check
    5. Return findings + IOCs to shared state
    """
    log = logger.bind(agent="email_analyst", event_type=state.get("event_type"))
    log.info("email_analyst.start")

    event_payload = state.get("event_payload", {})
    now = datetime.now(timezone.utc).isoformat()

    # ── Extract email content from payload ──────────────────────────────
    email_content = _extract_email_content(event_payload)
    subject = email_content.get("subject", "")
    body = email_content.get("body", "")
    sender = email_content.get("sender", "")
    raw_eml = email_content.get("raw_eml", "")

    log.info(
        "email_analyst.content_extracted",
        subject=subject[:80],
        body_length=len(body),
        has_raw_eml=bool(raw_eml),
    )

    # ── Tier 1: Static Filter ───────────────────────────────────────────
    tier1_result = run_static_filter(subject, body, sender, raw_eml=raw_eml)

    if tier1_result.decision == "CLEAN":
        log.info("email_analyst.tier1_clean", static_score=tier1_result.static_risk_score)
        return _build_safe_response(tier1_result, now)

    log.info(
        "email_analyst.tier1_suspicious",
        matched_rules=tier1_result.matched_rules,
        escalating_to_tier2=True,
    )

    # ── Tier 2: ReAct Agent ─────────────────────────────────────────────
    try:
        analysis = _run_react_agent(raw_eml or body, subject, sender, tier1_result, log)
    except Exception:
        log.exception("email_analyst.react_error")
        analysis = _build_fallback_analysis(tier1_result)

    # ── Self-Reflection ─────────────────────────────────────────────────
    try:
        analysis = _run_self_reflection(analysis, sender, subject, log)
    except Exception:
        log.exception("email_analyst.reflection_error")

    # ── Build state updates ─────────────────────────────────────────────
    return _build_response(analysis, tier1_result, now)


# ── Helper: extract email content from various payload formats ──────────

def _extract_email_content(payload: dict) -> dict:
    """Extract email fields from different event payload formats."""
    detail = payload.get("detail", payload)

    raw_eml = detail.get("raw_eml", "") or detail.get("eml_content", "")
    subject = detail.get("subject", "")
    body = detail.get("body", "") or detail.get("body_text", "")
    sender = detail.get("sender", "") or detail.get("from", "")

    # If we have raw .eml but no parsed fields, extract from eml
    if raw_eml and not subject:
        for line in raw_eml.split("\n"):
            if line.lower().startswith("subject:"):
                subject = line.split(":", 1)[1].strip()
            elif line.lower().startswith("from:"):
                sender = line.split(":", 1)[1].strip()
            elif line.strip() == "":
                body = raw_eml[raw_eml.index(line) + 1:].strip()
                break

    return {
        "subject": subject,
        "body": body,
        "sender": sender,
        "raw_eml": raw_eml,
    }


# ── Tier 2: ReAct Agent ────────────────────────────────────────────────

def _run_react_agent(
    content: str,
    subject: str,
    sender: str,
    tier1_result,
    log,
) -> EmailAnalysisOutput:
    """Run the ReAct agent loop using LangGraph's create_react_agent."""
    from langgraph.prebuilt import create_react_agent

    from bastion.services.gemini import get_chat_model

    model = get_chat_model()

    react_agent = create_react_agent(
        model,
        REACT_TOOLS,
        state_modifier=EMAIL_ANALYST_SYSTEM_PROMPT,
    )

    task_message = (
        f"Analyze this email for phishing indicators.\n\n"
        f"Sender: {sender}\n"
        f"Subject: {subject}\n\n"
        f"Tier 1 static filter already flagged these rules: {tier1_result.matched_rules}\n"
        f"Pre-extracted URLs: {tier1_result.extracted_urls}\n\n"
        f"Email content:\n{content[:4000]}\n\n"
        f"Use the available tools to perform a thorough analysis, then provide "
        f"your final verdict as a JSON object."
    )

    log.info("email_analyst.react_start", content_length=len(content))

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

    log.info("email_analyst.react_complete", response_length=len(final_text))

    return _parse_analysis_output(final_text, tier1_result)


def _parse_analysis_output(text: str, tier1_result) -> EmailAnalysisOutput:
    """Extract EmailAnalysisOutput from the agent's final response."""
    try:
        json_match = _extract_json(text)
        if json_match:
            data = json.loads(json_match)
            return EmailAnalysisOutput(
                status=data.get("status", "SUSPICIOUS"),
                confidence_score=float(data.get("confidence_score", 0.7)),
                mitre_tactic=data.get("mitre_tactic", "TA0001 - Initial Access"),
                iocs_extracted=data.get("iocs_extracted", {
                    "urls": tier1_result.extracted_urls,
                    "domains": tier1_result.extracted_domains,
                    "ips": tier1_result.extracted_ips,
                    "sender_emails": [],
                }),
                reasoning_chain=data.get("reasoning_chain", text[:500]),
            )
    except (json.JSONDecodeError, ValueError, KeyError):
        pass

    return _build_fallback_analysis(tier1_result)


def _extract_json(text: str) -> str | None:
    """Extract the first JSON object from text (handles markdown code blocks)."""
    import re
    # Try ```json ... ``` blocks first
    match = re.search(r"```(?:json)?\s*\n?({.*?})\s*\n?```", text, re.DOTALL)
    if match:
        return match.group(1)
    # Try raw JSON
    match = re.search(r"\{[^{}]*\"status\"[^{}]*\}", text, re.DOTALL)
    if match:
        return match.group(0)
    return None


# ── Self-Reflection ─────────────────────────────────────────────────────

def _run_self_reflection(
    analysis: EmailAnalysisOutput,
    sender: str,
    subject: str,
    log,
) -> EmailAnalysisOutput:
    """Run a self-reflection check to reduce false positives."""
    if analysis.status == "SAFE":
        return analysis

    from bastion.services.gemini import call_gemini

    prompt = SELF_REFLECTION_PROMPT_TEMPLATE.format(
        verdict=analysis.status,
        confidence=analysis.confidence_score,
        reasoning=analysis.reasoning_chain[:1000],
        sender=sender,
        subject=subject,
    )

    log.info("email_analyst.self_reflection_start")
    response = call_gemini(prompt)
    log.info("email_analyst.self_reflection_complete", response_length=len(response))

    try:
        json_str = _extract_json(response)
        if json_str:
            data = json.loads(json_str)
            if data.get("reflection_decision") == "REVISED":
                log.info(
                    "email_analyst.verdict_revised",
                    old_verdict=analysis.status,
                    new_verdict=data.get("revised_verdict"),
                )
                return EmailAnalysisOutput(
                    status=data.get("revised_verdict", analysis.status),
                    confidence_score=float(data.get("revised_confidence", analysis.confidence_score)),
                    mitre_tactic=analysis.mitre_tactic,
                    iocs_extracted=analysis.iocs_extracted,
                    reasoning_chain=(
                        f"{analysis.reasoning_chain}\n\n"
                        f"[Self-Reflection] {data.get('reflection_reasoning', '')}"
                    ),
                )
    except (json.JSONDecodeError, ValueError, KeyError):
        log.warning("email_analyst.reflection_parse_failed")

    return analysis


# ── Response builders ───────────────────────────────────────────────────

def _build_safe_response(tier1_result, timestamp: str) -> dict:
    """Build a SAFE response when Tier 1 finds no suspicious indicators."""
    return {
        "findings": [
            {
                "agent": "email_analyst",
                "finding_type": "email_classification",
                "severity": "INFO",
                "evidence": {"tier1_result": tier1_result.model_dump()},
                "mitre_tactic": "",
                "description": "Email passed Tier 1 static filter -- classified as SAFE.",
                "timestamp": timestamp,
            }
        ],
        "iocs": [],
        "messages": [
            AIMessage(content="[Email Analyst] Tier 1 filter: CLEAN. No phishing indicators.")
        ],
    }


def _build_response(
    analysis: EmailAnalysisOutput,
    tier1_result,
    timestamp: str,
) -> dict:
    """Build the full state update from a completed analysis."""
    severity_map = {"PHISHING": "CRITICAL", "SUSPICIOUS": "HIGH", "SAFE": "LOW"}

    findings = [
        {
            "agent": "email_analyst",
            "finding_type": "email_classification",
            "severity": severity_map.get(analysis.status, "MEDIUM"),
            "evidence": {
                "status": analysis.status,
                "confidence_score": analysis.confidence_score,
                "tier1_matched_rules": tier1_result.matched_rules,
                "iocs": analysis.iocs_extracted,
            },
            "mitre_tactic": analysis.mitre_tactic,
            "description": analysis.reasoning_chain[:500],
            "timestamp": timestamp,
        }
    ]

    iocs = []
    for url in analysis.iocs_extracted.get("urls", []):
        iocs.append({
            "ioc_type": "url",
            "value": url,
            "source_agent": "email_analyst",
            "context": f"Extracted from {analysis.status} email",
        })
    for domain in analysis.iocs_extracted.get("domains", []):
        iocs.append({
            "ioc_type": "domain",
            "value": domain,
            "source_agent": "email_analyst",
            "context": f"Extracted from {analysis.status} email",
        })
    for ip in analysis.iocs_extracted.get("ips", []):
        iocs.append({
            "ioc_type": "ip",
            "value": ip,
            "source_agent": "email_analyst",
            "context": f"Extracted from {analysis.status} email body",
        })
    for ip in analysis.iocs_extracted.get("header_ips", []):
        iocs.append({
            "ioc_type": "ip",
            "value": ip,
            "source_agent": "email_analyst",
            "context": f"Extracted from email headers (Received/X-Originating-IP)",
        })

    summary = (
        f"[Email Analyst] Verdict: {analysis.status} "
        f"(confidence: {analysis.confidence_score:.0%}). "
        f"IOCs: {len(iocs)} extracted. "
        f"MITRE: {analysis.mitre_tactic}"
    )

    return {
        "findings": findings,
        "iocs": iocs,
        "messages": [AIMessage(content=summary)],
    }


def _build_fallback_analysis(tier1_result) -> EmailAnalysisOutput:
    """Build a fallback analysis when ReAct agent fails."""
    return EmailAnalysisOutput(
        status="SUSPICIOUS",
        confidence_score=0.5 + (tier1_result.static_risk_score / 200),
        mitre_tactic="TA0001 - Initial Access",
        iocs_extracted={
            "urls": tier1_result.extracted_urls,
            "domains": tier1_result.extracted_domains,
            "ips": tier1_result.extracted_ips,
            "header_ips": tier1_result.header_ips,
            "sender_emails": [],
        },
        reasoning_chain=(
            f"Tier 1 flagged {len(tier1_result.matched_rules)} rules: "
            f"{', '.join(tier1_result.matched_rules)}. "
            f"Header IPs: {tier1_result.header_ips}. "
            f"ReAct agent failed -- using rule-based fallback."
        ),
    )
