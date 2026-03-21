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
- DELEGATE_FORENSIC: Forensic Analyst -- queries CloudTrail logs, searches VectorDB for attack patterns
- DELEGATE_THREAT: Threat Intel -- scans IOC reputation, checks domain age, assesses risk levels

Rules:
- Delegate to agents based on the event type and what evidence is still needed.
- If sufficient evidence has been gathered, respond with SYNTHESIZE.
- Always respond with exactly one of: DELEGATE_EMAIL, DELEGATE_FORENSIC, DELEGATE_THREAT, SYNTHESIZE.
- Consider correlating findings across multiple agents for multi-vector attacks.
"""


def supervisor_node(state: BastionState) -> dict:
    """Supervisor node for LangGraph.

    Reads current state, invokes Gemini LLM for routing decision,
    and returns the next_agent field.
    """
    log = logger.bind(agent="supervisor", event_type=state.get("event_type"))
    iteration = state.get("iteration_count", 0)

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
        }

    # Build context message for LLM
    context_parts = [
        f"Event Type: {state.get('event_type', 'unknown')}",
        f"Iteration: {iteration}",
        f"Current Findings ({len(state.get('findings', []))}):",
    ]
    for f in state.get("findings", []):
        context_parts.append(
            f"  - [{f.get('severity')}] {f.get('agent')}: {f.get('description', '')}"
        )

    context_parts.append(f"\nIOCs ({len(state.get('iocs', []))}):")
    for ioc in state.get("iocs", []):
        context_parts.append(
            f"  - [{ioc.get('ioc_type')}] {ioc.get('value')} (from {ioc.get('source_agent')})"
        )

    error_logs = state.get("error_logs", [])
    if error_logs:
        context_parts.append(f"\nAgent Errors ({len(error_logs)}):")
        for err in error_logs[-5:]:
            context_parts.append(f"  - {err}")
        context_parts.append(
            "NOTE: Do NOT re-delegate to an agent that has already failed. "
            "If all relevant agents have errored, respond with SYNTHESIZE."
        )

    user_message = "\n".join(context_parts)
    user_message += (
        "\n\nDecide the next action. Respond with exactly one of: "
        "DELEGATE_EMAIL, DELEGATE_FORENSIC, DELEGATE_THREAT, SYNTHESIZE.\n"
        "IMPORTANT: Do NOT delegate to an agent you have already delegated to in previous iterations unless new evidence specifically requires it. If you have already called DELEGATE_THREAT and it found 0 findings, do NOT call it again, just SYNTHESIZE."
    )

    try:
        from bastion.services.gemini import call_gemini

        llm_response = call_gemini(
            prompt=user_message,
            system_prompt=SUPERVISOR_SYSTEM_PROMPT,
        )
        decision = _parse_routing_decision(llm_response)
        log.info("supervisor.decision", decision=decision)

    except Exception:
        log.exception("supervisor.llm_error")
        decision = "SYNTHESIZE"

    return {
        "next_agent": decision,
        "iteration_count": iteration + 1,
        "messages": [AIMessage(content=f"[Supervisor] Routing -> {decision}")],
    }


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
