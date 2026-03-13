"""
Pydantic output models for the Email Analyst Agent.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class EmailAnalysisOutput(BaseModel):
    """Structured output from the Email Analyst Agent."""

    status: Literal["PHISHING", "SUSPICIOUS", "SAFE"] = Field(
        description="Classification verdict for the analysed email."
    )
    confidence_score: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in the verdict (0.0 = uncertain, 1.0 = certain)."
    )
    mitre_tactic: str = Field(
        default="",
        description="Primary MITRE ATT&CK tactic ID, e.g. 'TA0001 - Initial Access'."
    )
    iocs_extracted: dict = Field(
        default_factory=lambda: {"urls": [], "domains": [], "ips": [], "sender_emails": []},
        description="IOCs extracted from the email content."
    )
    reasoning_chain: str = Field(
        default="",
        description="Human-readable explanation of why this verdict was reached."
    )


class Tier1FilterResult(BaseModel):
    """Result from the Tier 1 static filter."""

    decision: Literal["CLEAN", "SUSPICIOUS"] = Field(
        description="Whether the email passed or failed the static filter."
    )
    matched_rules: list[str] = Field(
        default_factory=list,
        description="Names of static rules that matched."
    )
    extracted_urls: list[str] = Field(default_factory=list)
    extracted_domains: list[str] = Field(default_factory=list)
    extracted_ips: list[str] = Field(default_factory=list)
    header_ips: list[str] = Field(
        default_factory=list,
        description="IP addresses extracted from email headers (Received, X-Originating-IP).",
    )
    static_risk_score: int = Field(
        default=0, ge=0, le=100,
        description="Preliminary risk score from static analysis (0-100)."
    )
