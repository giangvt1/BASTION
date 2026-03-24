"""
ReAct tools for the Forensic Analyst Agent.

These ``@tool`` functions allow the LLM to query CloudTrail logs,
search MITRE ATT&CK patterns, and look up user baselines.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool

from bastion.logger import get_logger

logger = get_logger(__name__)


@tool
def cloudtrail_query_tool(
    query_description: str,
    username: str = "",
    event_name: str = "",
    time_range_hours: int = 24,
) -> list[dict[str, Any]]:
    """Query AWS CloudTrail logs for specific events.

    Attempts Athena SQL query first, falls back to direct CloudTrail API.
    The LLM should describe what it's looking for, and optionally provide
    a username or event name filter.

    Args:
        query_description: Natural language description of what to search for.
        username: Filter by IAM username (e.g. 'alice.johnson').
        event_name: Filter by specific CloudTrail event name (e.g. 'AssumeRole').
        time_range_hours: How far back to search (default 24 hours).

    Returns:
        List of matching CloudTrail event records.
    """
    log = logger.bind(tool="cloudtrail_query")
    log.info(
        "tool.cloudtrail_query",
        description=query_description[:100],
        username=username,
        event_name=event_name,
    )

    # Try Athena SQL query first
    try:
        from bastion.services.athena import query_cloudtrail_athena

        where_clauses = []
        if username:
            where_clauses.append(f"useridentityusername = '{username}'")
        if event_name:
            where_clauses.append(f"eventname = '{event_name}'")

        where_str = " AND ".join(where_clauses) if where_clauses else "1=1"

        sql = (
            f"SELECT eventtime, eventname, eventsource, sourceipaddress, "
            f"errorcode, errormessage, useridentityusername "
            f"FROM cloudtrail_logs "
            f"WHERE {where_str} "
            f"ORDER BY eventtime DESC "
            f"LIMIT 50"
        )

        results = query_cloudtrail_athena(sql)
        log.info("tool.cloudtrail_athena_results", count=len(results))
        return results

    except Exception as athena_err:
        log.warning("tool.cloudtrail_athena_fallback", error=str(athena_err)[:200])

    # Fallback to direct CloudTrail API
    try:
        from bastion.services.athena import query_cloudtrail_direct

        results = query_cloudtrail_direct(
            username=username or None,
            event_name=event_name or None,
            time_range_hours=time_range_hours,
        )
        log.info("tool.cloudtrail_direct_results", count=len(results))
        return results

    except Exception:
        log.exception("tool.cloudtrail_query_failed")
        return [{"error": "Both Athena and CloudTrail API queries failed."}]


@tool
def mitre_attack_vector_tool(behavior_description: str) -> list[dict[str, Any]]:
    """Search MITRE ATT&CK patterns database for matching attack techniques.

    Uses Pinecone vector similarity to find the closest MITRE ATT&CK techniques
    that match the described behavior. This is the forensic RAG component.

    Args:
        behavior_description: Natural language description of the observed
            behavior (e.g. 'User called AssumeRole after clicking phishing link').

    Returns:
        List of matching MITRE ATT&CK techniques with tactic IDs and similarity scores.
    """
    log = logger.bind(tool="mitre_attack_vector")
    log.info("tool.mitre_search", query_length=len(behavior_description))

    try:
        from bastion.vector_store.corpus_loader import search_mitre_corpus
        import concurrent.futures

        SEARCH_TIMEOUT = 30  # seconds
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(search_mitre_corpus, behavior_description, 5)
            results = future.result(timeout=SEARCH_TIMEOUT)
        log.info("tool.mitre_results", count=len(results))
        return results

    except concurrent.futures.TimeoutError:
        log.error("tool.mitre_timeout", timeout=30)
        return [{"error": "MITRE search timed out", "tactic_id": "", "technique": ""}]
    except Exception as exc:
        log.exception("tool.mitre_search_error")
        return [{"error": str(exc)}]


@tool
def shared_state_lookup_tool(user_id: str) -> dict[str, Any]:
    """Look up a user's historical baseline from DynamoDB.

    Retrieves the user's typical behavior profile including normal login times,
    common API calls, usual source IPs, and team membership. This helps
    determine if observed behavior is anomalous for this specific user.

    Args:
        user_id: The IAM username or user identifier to look up.

    Returns:
        Dict with user baseline data: typical_hours, common_apis, usual_ips, team, etc.
    """
    log = logger.bind(tool="shared_state_lookup")
    log.info("tool.user_baseline_lookup", user_id=user_id)

    try:
        from bastion.services.dynamodb import get_report

        # Attempt to retrieve user baseline from DynamoDB
        baseline = get_report(f"baseline:{user_id}")
        if baseline:
            log.info("tool.baseline_found", user_id=user_id)
            return baseline

    except Exception as exc:
        log.warning("tool.baseline_dynamodb_error", error=str(exc)[:200])

    # Return default baseline when no historical data is available
    log.info("tool.baseline_not_found", user_id=user_id)
    return {
        "user_id": user_id,
        "baseline_available": False,
        "typical_login_hours": "08:00-18:00 local time (assumed)",
        "common_apis": ["s3:GetObject", "s3:PutObject", "sts:GetCallerIdentity"],
        "usual_source_ips": [],
        "team": "unknown",
        "mfa_enabled": "unknown",
        "last_activity": "unknown",
        "note": (
            "No historical baseline found for this user. "
            "Any privileged API calls should be treated with higher suspicion."
        ),
    }
