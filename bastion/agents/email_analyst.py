"""
Email Analyst Agent.

Specializes in semantic analysis of .eml files to identify
phishing and social engineering attacks.

Tools available:
- Extract domains, URLs, IPs from email content
- Parse email headers for spoofing indicators
- Analyze email body sentiment/intent

Detailed analysis logic will be implemented in a later phase.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage

from bastion.logger import get_logger
from bastion.models.state import BastionState
from bastion.services.bedrock import invoke_llm

logger = get_logger(__name__)

EMAIL_ANALYST_SYSTEM_PROMPT = """\
You are the Email Analyst Agent of BASTION, a banking security system.
You specialize in analyzing email files (.eml) to detect phishing and social engineering attacks.

Your capabilities:
- Parse email headers to detect spoofing (SPF, DKIM, DMARC failures)
- Extract and analyze embedded URLs, domains, and IP addresses
- Perform sentiment analysis on email body to detect urgency/fear tactics
- Identify suspicious attachments and embedded content
- Map findings to MITRE ATT&CK techniques (e.g., T1566.001 Spearphishing Attachment)

Output your findings as structured analysis with severity levels.
"""


def email_analyst_node(state: BastionState) -> dict:
    """
    Email Analyst node for LangGraph.

    Analyzes email-related data from the event payload, extracts IOCs,
    and returns findings.
    """
    log = logger.bind(agent="email_analyst", event_type=state.get("event_type"))
    log.info("email_analyst.start")

    new_findings = []
    new_iocs = []

    try:
        # TODO: Implement detailed email analysis logic
        # 1. Retrieve .eml file from S3 (via event_payload)
        # 2. Parse headers, extract URLs/domains/IPs using email_tools
        # 3. Call Bedrock LLM for semantic analysis
        # 4. Produce findings and IOCs

        event_payload = state.get("event_payload", {})

        # Placeholder: invoke LLM for analysis reasoning
        user_message = (
            f"Analyze this security event for email-related threats:\n"
            f"{event_payload}\n\n"
            f"Existing IOCs: {state.get('iocs', [])}\n"
            f"Provide your analysis."
        )

        llm_response = invoke_llm(
            system_prompt=EMAIL_ANALYST_SYSTEM_PROMPT,
            user_message=user_message,
        )

        log.info("email_analyst.analysis_complete", response_length=len(llm_response))

        # TODO: Parse LLM response into structured findings and IOCs

    except Exception:
        log.exception("email_analyst.error")

    log.info(
        "email_analyst.complete",
        findings_count=len(new_findings),
        iocs_count=len(new_iocs),
    )

    return {
        "findings": new_findings,
        "iocs": new_iocs,
        "messages": [AIMessage(content=f"[Email Analyst] Analysis complete. Found {len(new_findings)} findings.")],
    }
