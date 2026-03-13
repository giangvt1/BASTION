"""
BASTION LangGraph Workflow Definition.

Assembles the StateGraph with:
- Supervisor node (entry point, routing, synthesis)
- Sub-agent nodes (Email, Forensic, Threat Intel)
- Conditional edges for dynamic routing
- Loop-back edges from sub-agents to Supervisor
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from bastion.agents.email_analyst import email_analyst_node
from bastion.agents.forensic_analyst import forensic_analyst_node
from bastion.agents.supervisor import supervisor_node
from bastion.agents.threat_intel import threat_intel_node
from bastion.logger import get_logger
from bastion.models.state import BastionState

logger = get_logger(__name__)


def route_from_supervisor(state: BastionState) -> str:
    """
    Conditional edge function: reads the Supervisor's routing decision
    and returns the target node name.
    """
    next_agent = state.get("next_agent", "SYNTHESIZE")
    logger.debug("graph.routing", next_agent=next_agent)
    return next_agent


def build_graph() -> StateGraph:
    """
    Build and compile the BASTION LangGraph StateGraph.

    Graph topology::

        START → supervisor ──┬── DELEGATE_EMAIL    → email_analyst    ──┐
                             ├── DELEGATE_FORENSIC → forensic_analyst ──┤
                             ├── DELEGATE_THREAT   → threat_intel     ──┤
                             └── SYNTHESIZE        → END                │
                                                                        │
                             ◄──────────── (loop back) ─────────────────┘

    Returns:
        A compiled LangGraph graph ready to be invoked.
    """
    logger.info("graph.building")

    graph = StateGraph(BastionState)

    # ── Register Nodes ──
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("email_analyst", email_analyst_node)
    graph.add_node("forensic_analyst", forensic_analyst_node)
    graph.add_node("threat_intel", threat_intel_node)

    # ── Entry Point ──
    graph.set_entry_point("supervisor")

    # ── Conditional Routing from Supervisor ──
    graph.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "DELEGATE_EMAIL": "email_analyst",
            "DELEGATE_FORENSIC": "forensic_analyst",
            "DELEGATE_THREAT": "threat_intel",
            "SYNTHESIZE": END,
        },
    )

    # ── Sub-agents loop back to Supervisor ──
    graph.add_edge("email_analyst", "supervisor")
    graph.add_edge("forensic_analyst", "supervisor")
    graph.add_edge("threat_intel", "supervisor")

    compiled = graph.compile()
    logger.info("graph.compiled", recursion_limit=25)

    return compiled
