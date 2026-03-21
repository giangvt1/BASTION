"""
Synthesis Agent.

Receives all findings and IOCs gathered by other agents,
and calls Gemini to synthesize a final executive summary report.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage

from bastion.logger import get_logger
from bastion.models.state import BastionState

logger = get_logger(__name__)

SYNTHESIS_SYSTEM_PROMPT = """\
You are the Executive Synthesis Agent of BASTION, a banking security system.
Your job is to read all findings and IOCs collected by various sub-agents
and synthesize them into a concise, professional Executive Report.

Include:
- Overall Verdict (e.g. "Confirmed Phishing", "False Positive", "High-Risk Anomaly")
- Key Indicators of Compromise
- Affected Entities/Users
- Recommended Actions

Format: Plain text or Markdown. Keep it under 250 words.
"""

def synthesis_node(state: BastionState) -> dict:
    """Synthesis node for LangGraph."""
    log = logger.bind(agent="synthesis", event_type=state.get("event_type"))
    log.info("synthesis.start")

    findings = state.get("findings", [])
    iocs = state.get("iocs", [])

    if not findings and not iocs:
        return {
            "final_report": "No significant findings or anomalies detected during analysis.",
            "messages": [AIMessage(content="[Synthesis] No findings to report.")],
            "pipeline_logs": [{"node": "synthesis", "action": "Analysis complete", "detail": "No significant findings or IOCs detected. Event appears benign.", "ts": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}],
        }

    try:
        user_message = (
            f"Please synthesize the following security findings into a final report:\n\n"
            f"Findings: {findings}\n\n"
            f"IOCs: {iocs}"
        )

        from bastion.services.gemini import call_gemini

        final_report = call_gemini(
            prompt=user_message,
            system_prompt=SYNTHESIS_SYSTEM_PROMPT,
        )

        log.info("synthesis.complete", report_length=len(final_report))

        # Calculate a rough risk score based on severities
        score = 0.0
        for f in findings:
            sev = str(f.get("severity", "LOW")).upper()
            if sev == "CRITICAL": score += 0.4
            elif sev == "HIGH": score += 0.25
            elif sev == "MEDIUM": score += 0.15
            elif sev == "LOW": score += 0.08
            elif sev == "INFO": score += 0.05
            else: score += 0.1  # Unknown severity gets moderate score
        
        # Add bonus score for IOCs discovered
        ioc_bonus = min(0.2, len(iocs) * 0.03)
        score += ioc_bonus
        
        # Ensure at least a base risk when findings exist
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
            {"node": "synthesis", "action": "Generating executive report", "detail": f"Synthesizing {len(findings)} findings and {len(iocs)} IOCs into executive summary via Gemini LLM", "ts": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()},
            {"node": "synthesis", "action": "Risk score computed", "detail": f"Final risk score: {(risk_score*100):.0f}% — Report length: {len(final_report)} chars", "ts": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()},
        ],
    }
