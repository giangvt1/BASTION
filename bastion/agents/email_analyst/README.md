# Email Analyst Agent

> **Banking Agentic Security Threat Intelligence & Orchestration Network**
>
> Sub-agent chuyên phân tích email phishing / social engineering

---

## Mục tiêu

Phân tích ngữ nghĩa (semantic analysis) các file `.eml` nghi ngờ để phát hiện **Phishing** hoặc **Social Engineering**, tự động trích xuất IOCs (Indicators of Compromise) và báo cáo về cho Supervisor Agent.

---

## Kiến trúc: Hybrid 2-Tier

```
                    ┌──────────────────────────────┐
                    │     email_analyst_node()      │
                    │     (LangGraph Node)          │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │   TIER 1: Static Filter       │
                    │   (Regex, Blacklist, No LLM)   │
                    └──────────────┬───────────────┘
                         │                  │
                      CLEAN            SUSPICIOUS
                         │                  │
                    Return SAFE     ┌───────▼────────┐
                    immediately     │ TIER 2: ReAct  │
                                    │ (Gemini LLM +  │
                                    │  Tool-calling)  │
                                    └───────┬────────┘
                                            │
                                    ┌───────▼────────┐
                                    │ Self-Reflection │
                                    │ (Anti-halluc.)  │
                                    └───────┬────────┘
                                            │
                                  EmailAnalysisOutput
```

### Tier 1 -- Static Filter (`tier1_filter.py`)

- **Không dùng LLM**, chạy cực nhanh, tiết kiệm chi phí
- 11 regex rules phát hiện phishing (urgency, verify_account, financial_threat, ...)
- Domain blacklist patterns (typo-squatting domains)
- Trích xuất URLs, IPs, domains bằng regex
- Nếu **0 rule matched** → CLEAN → trả SAFE ngay, skip Tier 2
- Nếu **>=1 rule matched** → SUSPICIOUS → chuyển sang Tier 2

### Tier 2 -- ReAct Agentic Workflow (`node.py`)

Sử dụng `langgraph.prebuilt.create_react_agent` với Gemini LLM.
Agent tự quyết định gọi tool nào theo vòng lặp **Thought → Action → Observation**:

1. **Thought**: Cần đọc nội dung email → gọi `extract_eml_components`
2. **Action**: Trích xuất URLs, domains → gọi `extract_network_entities`
3. **Action**: So sánh với DB phishing → gọi `vector_similarity_search` (Pinecone RAG)
4. **Action**: Phân tích URL cấu trúc → gọi `analyze_url_structure`
5. **Final**: Tổng hợp evidence → JSON verdict

### Self-Reflection

Sau khi ReAct agent đưa ra verdict, một LLM call thứ hai hỏi:
> "Liệu đây có phải email thông báo bảo mật thật từ IT nội bộ không?"

Nếu tự kiểm tra phát hiện false positive → **REVISED** verdict.

---

## Cấu trúc thư mục

```
email_analyst/
├── __init__.py          # Export email_analyst_node
├── node.py              # Main LangGraph node (Tier 1 → Tier 2 → Self-Reflection)
├── tier1_filter.py      # Static regex rules + blacklist + entity extraction
├── tools.py             # 4 @tool functions cho ReAct agent
├── prompts.py           # System prompt + Self-Reflection prompt template
├── models.py            # EmailAnalysisOutput, Tier1FilterResult (Pydantic)
└── README.md            # File này
```

---

## Tools (ReAct)

| Tool | Chức năng | Input | Output |
|------|-----------|-------|--------|
| `extract_eml_components` | Parse raw .eml → headers, body, metadata | `eml_content: str` | `dict` (headers, body_text, sender, subject, metadata) |
| `extract_network_entities` | Regex + tldextract → URLs, domains, IPs | `text: str` | `dict` (urls, domains, ips) |
| `vector_similarity_search` | Pinecone RAG search phishing corpus | `query_text: str` | `list[dict]` (top-5 similar emails + labels) |
| `analyze_url_structure` | Detect typo-squatting, brand impersonation | `url: str` | `dict` (is_suspicious, techniques, domain_info) |

---

## Output Schema

```json
{
  "status": "PHISHING",
  "confidence_score": 0.98,
  "mitre_tactic": "TA0001 - Initial Access",
  "iocs_extracted": {
    "urls": ["https://chase-bank.secure-login.com/verify"],
    "domains": ["secure-login.com"],
    "ips": [],
    "sender_emails": ["security-alerts@chase-bank.secure-login.com"]
  },
  "reasoning_chain": "Email uses urgency tactics, URL is typo-squatting Chase brand, content matches 95% with known phishing campaign in Pinecone corpus."
}
```

---

## Input từ Supervisor (qua BastionState)

```python
state["event_payload"]["detail"] = {
    "raw_eml": "From: ...\nTo: ...\nSubject: ...\n\nBody...",
    "s3_key": "emails/suspicious_01.eml",          # optional
    "subject": "URGENT: Your account...",            # optional (parsed from eml)
    "body": "Dear customer...",                      # optional
    "sender": "phisher@fake.com",                    # optional
}
state["event_type"] = "email"
```

---

## Dependencies

- `langchain-google-genai` (Gemini cho ReAct tool-calling)
- `langgraph` (create_react_agent)
- `tldextract` (domain extraction)
- `pinecone` (vector similarity search via Pinecone cloud)
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
python scripts/run_local.py --email
```
