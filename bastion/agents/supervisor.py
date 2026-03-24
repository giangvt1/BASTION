"""
Supervisor Agent -- the "SOC Lead" of the BASTION system.

Responsibilities:
- Evaluate incoming alerts and current state
- Make dynamic routing decisions (delegate to sub-agents)
- Synthesize final report when sufficient evidence is gathered
- Does NOT directly use tools; only reads state and reasons

The Supervisor operates in a loop:
  1. Read event_payload + current findings from state
  2. Call Gemini LLM to decide next action
  3. Return routing decision: DELEGATE_EMAIL | DELEGATE_FORENSIC | DELEGATE_THREAT | SYNTHESIZE
"""

from __future__ import annotations

from langchain_core.messages import AIMessage

from bastion.logger import get_logger
from bastion.models.state import BastionState

logger = get_logger(__name__)

MAX_ITERATIONS = 10

SUPERVISOR_SYSTEM_PROMPT = """\
You are the Supervisor Agent of BASTION, a banking security threat detection system.
You act as the SOC Lead, coordinating specialized sub-agents to analyze security events.

Your role:
1. Evaluate the incoming security event and any findings gathered so far.
2. Decide which specialist agent to delegate to next, or synthesize a final report.

Available agents:
- DELEGATE_EMAIL: Email Analyst -- analyzes .eml files for phishing/social engineering
- DELEGATE_FORENSIC: Forensic Analyst -- queries CloudTrail logs, analyzes VPC Flow Logs, searches VectorDB for attack patterns
- DELEGATE_THREAT: Threat Intel -- scans IOC reputation, checks domain age, assesses risk levels

Rules:
- Delegate to agents based on the event type and what evidence is still needed.
- If sufficient evidence has been gathered, respond with SYNTHESIZE.
- Always respond with exactly one of: DELEGATE_EMAIL, DELEGATE_FORENSIC, DELEGATE_THREAT, SYNTHESIZE.
- Consider correlating findings across multiple agents for multi-vector attacks.
- IMPORTANT: For correlated events that contain BOTH email AND network/VPC Flow Log data,
  you MUST delegate to BOTH Email Analyst AND Forensic Analyst (one at a time) before synthesizing.
  After Email Analyst completes, delegate to Forensic Analyst to analyze the network events.
"""


def supervisor_node(state: BastionState) -> dict:
    """Supervisor node for LangGraph.

    Uses deterministic hard-rule routing to guarantee all relevant agents
    are called exactly once in order: Email → Forensic → Threat → Synthesize.
    LLM is only used as fallback for non-standard flows.
    """
    from datetime import datetime, timezone

    log = logger.bind(agent="supervisor", event_type=state.get("event_type"))
    iteration = state.get("iteration_count", 0)
    ts = datetime.now(timezone.utc).isoformat()

    log.info(
        "supervisor.evaluating",
        iteration=iteration,
        findings_count=len(state.get("findings", [])),
        iocs_count=len(state.get("iocs", [])),
    )

    if iteration >= MAX_ITERATIONS:
        log.warning("supervisor.max_iterations_reached", max=MAX_ITERATIONS)
        return {
            "next_agent": "SYNTHESIZE",
            "iteration_count": iteration + 1,
            "pipeline_logs": [{"node": "supervisor", "action": "Max iterations reached", "detail": f"Forced SYNTHESIZE after {MAX_ITERATIONS} iterations", "ts": ts}],
        }

    # ── Track which agents have already produced findings ──
    findings = state.get("findings", [])
    agents_with_findings = {f.get("agent", "") for f in findings}
    
    email_done = "email_analyst" in agents_with_findings
    forensic_done = "forensic_analyst" in agents_with_findings
    threat_done = "threat_intel" in agents_with_findings
    
    # Also check messages for agents that returned CLEAN/SKIP/NORMAL (no findings)
    messages = state.get("messages", [])
    for msg in messages:
        content = getattr(msg, "content", "") if hasattr(msg, "content") else str(msg)
        if "[Email Analyst]" in content:
            email_done = True
        if "[Forensic Analyst]" in content:
            forensic_done = True
        if "[Threat Intel]" in content:
            threat_done = True

    # Check for correlated network events
    event_payload = state.get("event_payload", {})
    detail = event_payload.get("detail", {})
    has_network_events = bool(detail.get("aws_network_events", [])) if isinstance(detail, dict) else False

    log.info(
        "supervisor.agent_status",
        email_done=email_done,
        forensic_done=forensic_done,
        threat_done=threat_done,
        has_network_events=has_network_events,
    )

    # ── Deterministic Pipeline Routing ──
    # Step 1: Email first (for email events)
    if not email_done and state.get("event_type") == "email":
        decision = "DELEGATE_EMAIL"
        reason = "Email event detected — delegating to Email Analyst first"
    
    # Step 2: Forensic next (if network events exist OR event is cloudtrail)
    elif not forensic_done and (has_network_events or state.get("event_type") in ("cloudtrail", "syslog")):
        decision = "DELEGATE_FORENSIC"
        reason = "Network events/logs detected — delegating to Forensic Analyst"
    
    # Step 3: Threat Intel (if there are IOCs to analyze)
    elif not threat_done and len(state.get("iocs", [])) > 0:
        decision = "DELEGATE_THREAT"
        reason = f"IOCs available ({len(state.get('iocs', []))}) — delegating to Threat Intel"
    
    # Step 4: All agents done → Synthesize
    elif email_done or forensic_done or threat_done:
        decision = "SYNTHESIZE"
        reason = f"All required agents completed (E:{email_done} F:{forensic_done} T:{threat_done}) — generating final report"
    
    # Fallback: use LLM for edge cases
    else:
        decision = _llm_routing_fallback(state, log, ts)
        reason = "Non-standard flow — using LLM routing"

    log.info("supervisor.decision", decision=decision, reason=reason)

    return {
        "next_agent": decision,
        "iteration_count": iteration + 1,
        "messages": [AIMessage(content=f"[Supervisor] Routing -> {decision}")],
        "pipeline_logs": [
            {"node": "supervisor", "action": "Evaluating state", "detail": f"Iteration {iteration}: E:{email_done} F:{forensic_done} T:{threat_done} | {len(findings)} findings, {len(state.get('iocs', []))} IOCs", "ts": ts},
            {"node": "supervisor", "action": f"Routing → {decision}", "detail": reason, "ts": ts},
        ],
    }


def _llm_routing_fallback(state: BastionState, log, ts: str) -> str:
    """LLM-based routing fallback for non-standard flows."""
    context_parts = [
        f"Event Type: {state.get('event_type', 'unknown')}",
        f"Iteration: {state.get('iteration_count', 0)}",
        f"Findings: {len(state.get('findings', []))}",
        f"IOCs: {len(state.get('iocs', []))}",
    ]
    user_message = "\n".join(context_parts)
    user_message += (
        "\n\nDecide the next action. Respond with exactly one of: "
        "DELEGATE_EMAIL, DELEGATE_FORENSIC, DELEGATE_THREAT, SYNTHESIZE."
    )

    try:
        from bastion.services.gemini import call_gemini
        llm_response = call_gemini(
            prompt=user_message,
            system_prompt=SUPERVISOR_SYSTEM_PROMPT,
        )
        return _parse_routing_decision(llm_response)
    except Exception:
        log.exception("supervisor.llm_error")
        return "SYNTHESIZE"


def _parse_routing_decision(llm_response: str) -> str:
    """Extract a valid routing decision from LLM response text."""
    valid_decisions = {
        "DELEGATE_EMAIL",
        "DELEGATE_FORENSIC",
        "DELEGATE_THREAT",
        "SYNTHESIZE",
    }
    response_upper = llm_response.strip().upper()

    for decision in valid_decisions:
        if decision in response_upper:
            return decision

    logger.warning(
        "supervisor.unparseable_decision",
        raw_response=llm_response[:200],
    )
    return "SYNTHESIZE"
