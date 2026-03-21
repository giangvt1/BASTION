"""
BASTION Shared State Schema.

Defines the TypedDict used as LangGraph's shared state.
All agents read from and write to this unified state object.
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages


class Finding(TypedDict):
    """A single finding produced by any agent."""

    agent: str            # e.g. "email_analyst", "forensic_analyst"
    finding_type: str     # e.g. "phishing_indicator", "privilege_escalation"
    severity: str         # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    evidence: dict        # Structured evidence data
    mitre_tactic: str     # MITRE ATT&CK tactic ID, e.g. "T1566.001"
    description: str      # Human-readable description
    timestamp: str        # ISO 8601


class IOC(TypedDict):
    """An Indicator of Compromise shared between agents."""

    ioc_type: str         # "ip" | "domain" | "hash" | "url" | "email"
    value: str            # The actual IOC value
    source_agent: str     # Agent that discovered this IOC
    context: str          # Why this IOC is suspicious


class BastionState(TypedDict):
    """
    Shared state object for the entire LangGraph workflow.

    This state flows through all nodes (Supervisor, sub-agents).
    Each node reads what it needs and returns partial updates.
    LangGraph merges updates using the annotated reducers.

    Uses ``operator.add`` (C-level list concatenation) as the reducer
    for all list fields -- this is LangGraph standard practice and
    ensures sub-agent results are **appended**, never overwritten.
    """

    # ── Input ──
    event_payload: dict                                # Raw event from EventBridge
    event_type: str                                    # "email" | "cloudtrail" | "s3_upload"

    # ── Agent Communication (LangGraph messages) ──
    messages: Annotated[list[BaseMessage], add_messages]

    # ── Routing ──
    next_agent: str                                    # Supervisor's routing decision

    # ── Findings (each agent appends) ──
    findings: Annotated[list[Finding], operator.add]

    # ── IOCs (shared pool across agents) ──
    iocs: Annotated[list[IOC], operator.add]

    # ── Iteration tracking ──
    iteration_count: int                               # Guard against infinite loops

    # ── Error tracking (agents append errors here) ──
    error_logs: Annotated[list[str], operator.add]

    # ── Pipeline activity logs for visualization ──
    pipeline_logs: Annotated[list[dict], operator.add]  # {node, action, detail, ts}

    # ── Final Output ──
    risk_score: Optional[float]                        # 0.0 – 1.0
    final_report: Optional[str]                        # Synthesized narrative report
    report_id: Optional[str]                           # DynamoDB key
