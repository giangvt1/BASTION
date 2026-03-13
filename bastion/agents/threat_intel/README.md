# Threat Intelligence Agent

> **Banking Agentic Security Threat Intelligence & Orchestration Network**
>
> Sub-agent chuyên enrichment IOCs và đánh giá mức độ đe dọa

---

## Kiến trúc: Hybrid 2-Tier

```
           IOCs from BastionState
                    │
                    ▼
         ┌─────────────────────┐
         │  Tier 1: Static     │  No LLM
         │  IOC Filter         │
         │  - Whitelist check  │
         │  - Deduplicate      │
         │  - Risk heuristics  │
         └────────┬────────────┘
                  │
          SKIP?───┼───ANALYZE
          │       │
    Return BENIGN │
                  ▼
         ┌─────────────────────┐
         │  Tier 2: ReAct      │  LLM + Tools
         │  Agent (Gemini)     │
         │  - VirusTotal       │
         │  - AbuseIPDB        │
         │  - WHOIS            │
         │  - IP Geolocation   │
         └────────┬────────────┘
                  │
                  ▼
         ┌─────────────────────┐
         │  Self-Reflection    │  LLM
         │  (false-positive    │
         │   reduction)        │
         └────────┬────────────┘
                  │
                  ▼
         Return findings + enriched IOCs
```

---

## Cấu trúc file

```
bastion/agents/threat_intel/
├── __init__.py          # Export threat_intel_node
├── node.py              # LangGraph node (Tier 1 -> Tier 2 -> Reflection)
├── models.py            # ThreatIntelOutput, IOCEnrichment, Tier1IOCFilterResult
├── prompts.py           # System prompt + self-reflection template
├── tools.py             # 4 @tool functions (VT, AbuseIPDB, WHOIS, GeoIP)
├── tier1_filter.py      # Static IOC pre-filter (no LLM)
└── README.md            # (file này)
```

---

## Tools

| Tool | Chức năng | Fallback |
|------|-----------|----------|
| `virustotal_lookup` | IP/Domain/Hash/URL reputation | Heuristic (TLD, patterns) |
| `abuseipdb_check` | IP abuse reports, country, ISP | Tor prefix check, geo heuristic |
| `whois_domain_lookup` | Domain age, registrar, privacy | TLD-based risk scoring |
| `ip_geolocation` | Country, ASN, Tor/VPN/Proxy | ip-api.com → heuristic fallback |

> **Note**: Tất cả tools đều fallback graceful khi không có API key -- phù hợp cho demo/thesis.

---

## Input

```python
state["iocs"] = [
    {"ioc_type": "ip", "value": "185.220.101.45", "source_agent": "forensic_analyst", "context": "Foreign IP"},
    {"ioc_type": "domain", "value": "secure-login.xyz", "source_agent": "email_analyst", "context": "Phishing URL"},
]
```

## Output

```python
{
    "findings": [{
        "agent": "threat_intel",
        "finding_type": "ioc_assessment",
        "severity": "CRITICAL",
        "evidence": {
            "status": "MALICIOUS",
            "confidence_score": 0.92,
            "ioc_enrichments": [...],
            "mitre_tactics": ["TA0011", "TA0001"],
            "threat_actor": "APT28",
        },
        ...
    }],
    "iocs": [...],  # Enriched IOCs
    "messages": [AIMessage(content="[Threat Intel] Verdict: MALICIOUS ...")]
}
```

---

## Dependencies

- `bastion.services.gemini` (call_gemini, get_chat_model)
- `bastion.models.state` (BastionState)
- `langchain_core.tools` (@tool)
- `langgraph.prebuilt` (create_react_agent)
- `tldextract` (domain parsing)
- `requests` (external API calls)
- Optional: `python-whois` (WHOIS lookup)
