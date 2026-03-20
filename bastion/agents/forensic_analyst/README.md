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

### Tier 1 -- Hybrid Anomaly Detection (`tier1_filter.py`) ✨ ENHANCED

**Multi-layered Detection**:

1. **Rule-based checks**: Phát hiện high-risk APIs (AssumeRole, StopLogging, CreateAccessKey...), AccessDenied probing, reconnaissance bursts

2. **Isolation Forest** (scikit-learn): Statistical anomaly detection trên log features:
   - Hour-of-day (login lúc 2AM?)
   - Is high-risk API?
   - Is reconnaissance API?
   - Has error code?
   - Unique IP index

3. **NEW: LSTM Autoencoder** (User Behavior Analytics):
   - Học baseline behavior của từng user
   - Phát hiện temporal anomalies (sequence patterns)
   - Features: hour, day_of_week, API types, IP entropy, event_name_hash
   - Reconstruction error → anomaly score
   - Phát hiện slow-burn attacks (tấn công kéo dài)

**Hybrid Scoring**:
```python
combined_score = (
    rule_score * 0.4 +        # Rule-based: up to 0.4
    iforest_score * 0.3 +     # Isolation Forest: up to 0.3
    lstm_score * 0.3          # LSTM UBA: up to 0.3
)
```

**Decision Logic**:
- Nếu **0 rule matched + combined_score < 0.5** → NORMAL → skip Tier 2
- Nếu **có rule match hoặc combined_score ≥ 0.5** → ANOMALY → chuyển Tier 2

**Feature Flag**:
```bash
BASTION_USE_LSTM_UBA=true  # default: true
```

Nếu LSTM model chưa train hoặc fail → tự động fallback về Isolation Forest only.

### Tier 2 -- Hybrid: Semantic Analyzer + ReAct Agent (`node.py`) ✨ ENHANCED

**Hybrid Strategy**: Semantic Analyzer (DL) → LLM fallback

#### Option A: Semantic Analyzer (Preferred)

**When**: `BASTION_USE_SEMANTIC_ANALYZER=true` AND confidence ≥ threshold (default 0.8)

**Model**: BERT-based CloudTrail classifier
- Input: CloudTrail event sequence + user + context
- Output: Attack severity + kill-chain stages + MITRE tactics + confidence
- Inference: ~100-200ms
- Cost: ~$0.0001 per analysis

**Benefits**:
- 95% cost reduction vs LLM
- 10-20x faster (100-200ms vs 2-5 seconds)
- Privacy: no data sent to external API
- Deterministic outputs

**Tradeoffs**:
- Requires training data (500-1000+ labeled sequences)
- Less flexible than LLM (cannot reason about novel attacks)
- Cannot use tools dynamically (Athena queries, MITRE search)

#### Option B: ReAct Agent (LLM + Tools)

**When**: Semantic analyzer disabled OR confidence < threshold

Sử dụng `create_react_agent` với Gemini LLM. Agent follow Chain-of-Thought:

1. **Analyze**: Đọc context logs, identify WHO/WHAT/WHEN/WHERE
2. **Baseline Check**: Gọi `shared_state_lookup_tool` để check user history
3. **Extended Investigation**: Gọi `cloudtrail_query_tool` để query thêm log 24h
4. **MITRE Mapping**: Gọi `mitre_attack_vector_tool` để classify attack pattern
5. **Synthesis**: Build kill-chain + verdict + recommendation

**Decision Flow**:
```
Tier 1 ANOMALY → Semantic Analyzer
                 ├─ confidence ≥ 0.8 → Use semantic result (fast)
                 └─ confidence < 0.8 → Fallback to LLM ReAct (accurate)
```

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
- **NEW**: `torch` (LSTM Autoencoder for UBA)

---

## ML Models

### 1. Isolation Forest (Tier 1)
- **Already implemented** in code
- Unsupervised anomaly detection
- Features: hour, is_high_risk, is_recon, has_error, ip_index
- Fast: <10ms per batch

### 2. LSTM Autoencoder (Tier 1) ✨ NEW
- **Location**: `bastion/models/ml_models.py` → `LSTMAnomalyDetector`
- **Architecture**: Encoder-Decoder LSTM
- **Input**: Sequence of 10 CloudTrail events
- **Features per event**: 8 dimensions
  - hour_of_day (0-1 normalized)
  - day_of_week (0-1 normalized)
  - is_high_risk_api (0/1)
  - is_recon_api (0/1)
  - is_data_access (0/1)
  - has_error (0/1)
  - source_ip_entropy (0-1)
  - event_name_hash (0-1)
- **Output**: Reconstruction error (MSE)
- **Anomaly threshold**: MSE > 0.05 (configurable)

### Training LSTM Model

**Step 1: Generate synthetic training data**
```bash
python scripts/generate_synthetic_cloudtrail.py \
    --output synthetic_logs.json \
    --events 5000 \
    --users 10 \
    --anomaly-ratio 0.05
```

**Step 2: Train LSTM autoencoder**
```bash
python scripts/train_lstm_uba.py \
    --data synthetic_logs.json \
    --epochs 50 \
    --batch-size 32 \
    --learning-rate 0.001
```

Model saved to: `~/.cache/bastion/models/lstm_uba_autoencoder.pth`

**Step 3: Enable in production**
```bash
# .env
BASTION_USE_LSTM_UBA=true
```

### Using Pre-trained Model

If you have historical CloudTrail logs:
```bash
# Use real logs for training
python scripts/train_lstm_uba.py \
    --data /path/to/cloudtrail_logs.json \
    --epochs 100 \
    --validation-split 0.2
```

Recommended: At least 1000+ events for meaningful training.

---

## Configuration

```bash
# .env file
BASTION_USE_LSTM_UBA=true                    # Enable LSTM UBA detector (Tier 1)
BASTION_USE_SEMANTIC_ANALYZER=true           # Enable semantic analyzer (Tier 2)
BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8      # Confidence threshold for semantic analyzer
```

**Important**: 
- LSTM model requires training first (see above)
- Semantic analyzer requires training on LLM outputs (see `SEMANTIC_ANALYZER.md`)
- If models not found → automatic fallback to Isolation Forest (Tier 1) + LLM ReAct (Tier 2)
- No crashes or blocking errors

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
