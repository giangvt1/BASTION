"""
Pydantic output models for the Threat Intelligence Agent.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class IOCEnrichment(BaseModel):
    """Enrichment result for a single IOC."""

    ioc_type: str = Field(description="Type of IOC: ip, domain, url, hash, email.")
    value: str = Field(description="The IOC value.")
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "BENIGN", "UNKNOWN"] = Field(
        default="UNKNOWN",
        description="Risk classification for this IOC.",
    )
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="Confidence in the risk assessment (0.0-1.0).",
    )
    enrichment_sources: list[str] = Field(
        default_factory=list,
        description="Sources used for enrichment (e.g. 'VirusTotal', 'AbuseIPDB').",
    )
    details: dict = Field(
        default_factory=dict,
        description="Detailed enrichment data from external sources.",
    )


class ThreatIntelOutput(BaseModel):
    """Structured output from the Threat Intelligence Agent."""

    status: Literal["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN"] = Field(
        description="Overall threat verdict for the IOC set.",
    )
    confidence_score: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in the overall verdict (0.0-1.0).",
    )
    ioc_enrichments: list[IOCEnrichment] = Field(
        default_factory=list,
        description="Per-IOC enrichment results.",
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactic IDs correlated with the IOCs.",
    )
    threat_actor_attribution: str = Field(
        default="",
        description="Suspected threat actor or campaign name, if identifiable.",
    )
    recommended_action: str = Field(
        default="",
        description="Recommended response action for the SOC team.",
    )
    reasoning_chain: str = Field(
        default="",
        description="Step-by-step explanation of the threat assessment.",
    )


class Tier1IOCFilterResult(BaseModel):
    """Result from the Tier 1 static IOC filter."""

    decision: Literal["SKIP", "ANALYZE"] = Field(
        description="SKIP = no suspicious IOCs remain; ANALYZE = proceed to Tier 2.",
    )
    filtered_iocs: list[dict] = Field(
        default_factory=list,
        description="IOCs that passed the filter and need deep analysis.",
    )
    skipped_iocs: list[dict] = Field(
        default_factory=list,
        description="IOCs removed as benign/whitelisted.",
    )
    static_risk_indicators: list[str] = Field(
        default_factory=list,
        description="Quick risk flags from static analysis.",
    )
    static_risk_score: int = Field(
        default=0, ge=0, le=100,
        description="Preliminary risk score from static filter (0-100).",
    )
