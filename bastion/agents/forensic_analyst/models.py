"""
Pydantic output models for the Forensic Analyst Agent.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ForensicAnalysisOutput(BaseModel):
    """Structured output from the Forensic Analyst Agent."""

    status: Literal[
        "CRITICAL_COMPROMISE", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "CLEAN"
    ] = Field(description="Severity classification of the forensic analysis.")

    confidence_score: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in the assessment (0.0-1.0)."
    )
    kill_chain_identified: list[str] = Field(
        default_factory=list,
        description="Attack kill-chain stages identified (e.g. 'Initial Access', 'Privilege Escalation')."
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactic IDs (e.g. 'TA0001', 'TA0004')."
    )
    recommended_action: str = Field(
        default="",
        description="Immediate remediation recommendation."
    )
    generated_sigma_rule: str | None = Field(
        default=None,
        description="Auto-generated Sigma detection rule YAML."
    )
    reasoning_chain: str = Field(
        default="",
        description="Step-by-step forensic reasoning narrative."
    )


class Tier1AnomalyResult(BaseModel):
    """Result from the Tier 1 anomaly detection filter."""

    decision: Literal["NORMAL", "ANOMALY"] = Field(
        description="Whether the logs show anomalous behaviour."
    )
    anomaly_score: float = Field(
        default=0.0,
        description="Anomaly score from the detection model (higher = more anomalous)."
    )
    flagged_events: list[dict] = Field(
        default_factory=list,
        description="Log events that triggered the anomaly detection."
    )
    rule_matches: list[str] = Field(
        default_factory=list,
        description="Static rules that matched."
    )
    user: str = Field(default="")
    source_ips: list[str] = Field(default_factory=list)
