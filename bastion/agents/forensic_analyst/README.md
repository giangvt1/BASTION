# Forensic Analyst Agent

> **Banking Agentic Security Threat Intelligence & Orchestration Network**
>
> Sub-agent chuyên điều tra log hệ thống và phát hiện tấn công APT

---

## Mục tiêu

Đóng vai trò **chuyên gia phân tích Log (SOC Analyst)**, tự động:
- Xây dựng câu truy vấn SQL để hunt hành vi bất thường trong CloudTrail
- Đối chiếu với MITRE ATT&CK framework
- Xác định kill-chain và đề xuất remediation
- Tự động sinh Sigma detection rules cho SIEM

---

## Kiến trúc: Hybrid 2-Tier

```
                    ┌──────────────────────────────┐
                    │  forensic_analyst_node()      │
                    │  (LangGraph Node)             │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │  TIER 1: Anomaly Detection    │
                    │  (Rules + Isolation Forest)    │
                    └──────────────┬───────────────┘
                         │                  │
                      NORMAL            ANOMALY
                         │                  │
                    Return LOW_RISK  ┌──────▼─────────┐
                    immediately      │ TIER 2: ReAct   │
                                     │ (Gemini LLM +   │
                                     │  Tool-calling)   │
                                     └──────┬─────────┘
                                            │
                                     ┌──────▼─────────┐
                                     │ Sigma Generator  │
                                     │ (Auto YAML rule) │
                                     └──────┬─────────┘
                                            │
                                ForensicAnalysisOutput
```

### Tier 1 -- Anomaly Detection (`tier1_filter.py`)

- **Rule-based checks**: Phát hiện high-risk APIs (AssumeRole, StopLogging, CreateAccessKey...), AccessDenied probing, reconnaissance bursts
- **Isolation Forest** (scikit-learn): ML anomaly detection trên log features:
  - Hour-of-day (login lúc 2AM?)
  - Is high-risk API?
  - Is reconnaissance API?
  - Has error code?
  - Unique IP index
- Nếu **0 rule matched + anomaly score thấp** → NORMAL → skip Tier 2
- Nếu **có rule match hoặc anomaly cao** → ANOMALY → chuyển Tier 2

### Tier 2 -- ReAct Forensic Investigation (`node.py`)

Sử dụng `create_react_agent` với Gemini LLM. Agent follow Chain-of-Thought:

1. **Analyze**: Đọc context logs, identify WHO/WHAT/WHEN/WHERE
2. **Baseline Check**: Gọi `shared_state_lookup_tool` để check user history
3. **Extended Investigation**: Gọi `cloudtrail_query_tool` để query thêm log 24h
4. **MITRE Mapping**: Gọi `mitre_attack_vector_tool` để classify attack pattern
5. **Synthesis**: Build kill-chain + verdict + recommendation

### Sigma Rule Generator (`sigma_generator.py`)

Sau khi ReAct hoàn thành, tự động sinh **Sigma YAML rule** cho SIEM:
- Event names từ flagged events
- Source IPs từ investigation
- MITRE tactic tags
- Level mapping (CRITICAL → critical, HIGH → high, ...)

---

## Cấu trúc thư mục

```
forensic_analyst/
├── __init__.py          # Export forensic_analyst_node
├── node.py              # Main LangGraph node (Tier 1 → Tier 2 → Sigma)
├── tier1_filter.py      # Rule-based + Isolation Forest anomaly detection
├── tools.py             # 3 @tool functions cho ReAct agent
├── prompts.py           # CoT system prompt for forensic reasoning
├── sigma_generator.py   # Auto-generate Sigma/YARA rules
├── models.py            # ForensicAnalysisOutput, Tier1AnomalyResult (Pydantic)
└── README.md            # File này
```

---

## Tools (ReAct)

| Tool | Chức năng | Input | Output |
|------|-----------|-------|--------|
| `cloudtrail_query_tool` | Query CloudTrail via Athena SQL (primary) hoặc direct API (fallback) | `query_description`, `username`, `event_name`, `time_range_hours` | `list[dict]` (CloudTrail events) |
| `mitre_attack_vector_tool` | Pinecone RAG search MITRE ATT&CK patterns | `behavior_description: str` | `list[dict]` (top-5 matching techniques) |
| `shared_state_lookup_tool` | Lookup user baseline từ DynamoDB | `user_id: str` | `dict` (typical_hours, common_apis, usual_ips, team) |

---

## Output Schema

```json
{
  "status": "CRITICAL_COMPROMISE",
  "confidence_score": 0.95,
  "kill_chain_identified": [
    "Initial Access (Email)",
    "Credential Access",
    "Privilege Escalation (AssumeRole)"
  ],
  "mitre_tactics": ["TA0001", "TA0006", "TA0004"],
  "recommended_action": "Revoke IAM Role immediately. Isolate affected resources.",
  "generated_sigma_rule": "title: Detect Suspicious AssumeRole at 2AM...",
  "reasoning_chain": "User alice.johnson logged in at 2:01 AM from foreign IP 185.220.101.45 without MFA. Proceeded to ListBuckets, ListUsers (recon), then AssumeRole to AdminFullAccess. Accessed credit card data bucket. Attempted to StopLogging (denied). Kill-chain matches Privilege Escalation pattern in MITRE ATT&CK."
}
```

---

## Input từ Supervisor (qua BastionState)

```python
state["event_payload"]["detail"] = {
    "user": "alice.johnson",
    "anomaly_trigger": "Unusual API calls at 2AM from foreign IP",
    "context_logs": {
        "Records": [
            {"eventName": "ConsoleLogin", "sourceIPAddress": "185.220.101.45", ...},
            {"eventName": "AssumeRole", ...},
            ...
        ]
    }
}
state["event_type"] = "cloudtrail"
```

---

## Dependencies

- `langchain-google-genai` (Gemini cho ReAct tool-calling)
- `langgraph` (create_react_agent)
- `scikit-learn` (Isolation Forest)
- `pinecone` (MITRE ATT&CK vector search via Pinecone cloud)
- `boto3` (Athena + CloudTrail + DynamoDB)
- `pydantic` (structured output models)

---

## PII Compliance

Data da duoc **PII-scrubbed** truoc khi toi agent nay:
- `tier1_filter_handler.py` scrub truoc khi push SQS
- `trigger_handler.py` scrub fallback cho direct invocation
- `run_local.py` scrub sample events

Agent **khong bao gio thay** so the tin dung, SSN, email that, hay IP noi bo.
Chi thay cac token nhu `[CARD_REDACTED]`, `[EMAIL_REDACTED]`, `[INTERNAL_IP_REDACTED]`.

---

## Test local

```bash
python scripts/run_local.py --forensic
```
