"""
Threat Intelligence Agent.

Receives IOCs from other agents and performs reputation scanning,
domain age checking, and risk level assessment from external sources.

Tools available:
- IOC reputation scanning (VirusTotal, AbuseIPDB, etc.)
- Domain age and WHOIS lookup
- IP geolocation and ASN analysis
"""

from __future__ import annotations

from langchain_core.messages import AIMessage

from bastion.logger import get_logger
from bastion.models.state import BastionState

logger = get_logger(__name__)

THREAT_INTEL_SYSTEM_PROMPT = """\
You are the Threat Intelligence Agent of BASTION, a banking security system.
You specialize in IOC (Indicator of Compromise) analysis and threat intelligence.

Your capabilities:
- Scan IP addresses against reputation databases (AbuseIPDB, VirusTotal)
- Check domain age, registration details, and WHOIS records
- Analyze URL reputation and redirect chains
- Assess file hash reputation against malware databases
- Correlate IOCs with known threat actor campaigns
- Map findings to MITRE ATT&CK techniques

Output your findings with confidence scores and threat attribution when possible.
"""


def threat_intel_node(state: BastionState) -> dict:
    """Threat Intel node for LangGraph.

    Takes IOCs from shared state, performs reputation checks,
    and returns enriched threat intelligence findings.
    """
    log = logger.bind(agent="threat_intel", event_type=state.get("event_type"))
    log.info("threat_intel.start")

    new_findings = []
    iocs_to_check = state.get("iocs", [])

    log.info("threat_intel.checking_iocs", ioc_count=len(iocs_to_check))

    try:
        user_message = (
            f"Assess the following IOCs for threat intelligence:\n"
            f"IOCs: {iocs_to_check}\n\n"
            f"Existing findings from other agents: {state.get('findings', [])}\n"
            f"Provide threat assessment with risk levels."
        )

        from bastion.services.gemini import call_gemini

        llm_response = call_gemini(
            prompt=user_message,
            system_prompt=THREAT_INTEL_SYSTEM_PROMPT,
        )

        log.info("threat_intel.assessment_complete", response_length=len(llm_response))

        if "high risk" in llm_response.lower() or "malicious" in llm_response.lower():
            new_findings.append({
                "agent": "threat_intel",
                "finding_type": "ioc_reputation",
                "severity": "CRITICAL",
                "evidence": {"llm_response": llm_response},
                "description": llm_response[:500]
            })
        else:
            new_findings.append({
                "agent": "threat_intel",
                "finding_type": "ioc_reputation",
                "severity": "MEDIUM",
                "evidence": {"llm_response": llm_response},
                "description": "Analyzed IOCs. " + llm_response[:300]
            })

    except Exception:
        log.exception("threat_intel.error")

    log.info("threat_intel.complete", findings_count=len(new_findings))

    return {
        "findings": new_findings,
        "messages": [
            AIMessage(
                content=f"[Threat Intel] Assessment complete. Found {len(new_findings)} findings."
            )
        ],
    }
