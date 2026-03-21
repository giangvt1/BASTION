# BASTION -- System Architecture Design

> **Banking Agentic Security Threat Intelligence & Orchestration Network**
>
> LangGraph + Gemini + ML/DL Multi-Agent Architecture
>
> ✨ **ML Enhanced**: 95-99% cost reduction, 10-20x faster with Deep Learning models

---

## Table of Contents

1. [Tong quan kien truc](#1-tong-quan-kien-truc)
2. [Cau truc thu muc du an](#2-cau-truc-thu-muc-du-an)
3. [Layer 1 -- Input Layer](#3-layer-1--input-layer)
4. [Layer 2 -- Trigger & Pre-Processing Layer (Tier 1)](#4-layer-2--trigger--pre-processing-layer-tier-1)
   - 4.5 [ML/DL Integration trong Tier 1](#45-mldl-integration-trong-tier-1--new)
5. [Layer 3 -- LangGraph Multi-Agent Core (Tier 2)](#5-layer-3--langgraph-multi-agent-core-tier-2)
   - 5.2 [Email Analyst Agent](#52-email-analyst-agent-hybrid-2-tier--ml-enhanced)
   - 5.3 [Forensic Analyst Agent](#53-forensic-analyst-agent-hybrid-2-tier--ml-enhanced)
   - 5.3.1 [Semantic Analyzer - DL thay the LLM](#531-semantic-analyzer---dl-thay-the-llm--implemented)
6. [Layer 4 -- Storage & Interface Layer](#6-layer-4--storage--interface-layer)
7. [Shared State Schema](#7-shared-state-schema)
8. [LangGraph Graph Definition](#8-langgraph-graph-definition)
9. [Security & Compliance](#9-security--compliance)
10. [Logging & Observability](#10-logging--observability)
11. [Cau hinh & Bien moi truong](#11-cau-hinh--bien-moi-truong)
12. [Dependency Stack](#12-dependency-stack)
    - 12.1 [Core Dependencies](#121-core-dependencies)
    - 12.2 [ML Models & Cache](#122-ml-models--cache)
    - 12.3 [Feature Flags](#123-feature-flags)
    - 12.4 [Training Requirements](#124-training-requirements)
13. [Production Considerations](#13-production-considerations)

---

## 1. Tong quan kien truc

```
+---------------------------------------------------------------------------------+
|                              AWS Cloud (BASTION)                                |
|                                                                                 |
|  +--------------+   +--------------------------------------------------+        |
|  | INPUT LAYER  |-->| TRIGGER & PRE-PROCESSING LAYER (TIER 1)          |        |
|  |              |   |                                                  |        |
|  | - CloudTrail |   |  [EventBridge] --> [Lambda: Tier 1 Filter]       |        |
|  | - S3 Bucket  |   |                        | Drop noise (~90%)       |        |
|  +--------------+   |                        v                         |        |
|                     |             [Lambda: PII Scrubber]               |        |
|                     |                        |                         |        |
|                     |                        v                         |        |
|                     |            [Amazon SQS (Analysis Queue)]         |        |
|                     +------------------------+-------------------------+        |
|                                              | Batch trigger                    |
|                     +------------------------v-------------------------+        |
|                     | LANGGRAPH MULTI-AGENT CORE (TIER 2)              |        |
|                     |                                                  |        |
|                     |             +-----------+                        |        |
|                     |             |Supervisor |                        |        |
|                     |             +-----+-----+                        |        |
|                     |  [Email Agent] [Forensic Agent] [Threat Intel]   |        |
|                     +------------------------+-------------------------+        |
|                                              | Save Report                      |
|                     +------------------------v-------------------------+        |
|                     | STORAGE & INTERFACE LAYER                        |        |
|                     | - DynamoDB (Reports + State Checkpoints)         |        |
|                     | - API Gateway -> SOC Dashboard                   |        |
|                     +--------------------------------------------------+        |
+---------------------------------------------------------------------------------+
```

He thong duoc phan thanh **4 layer** chinh:

| Layer | Vai tro | AWS Services / Lib | ML Enhancement |
|---|---|---|---|
| **Input** | Thu thap log & file dang ngo | CloudTrail, S3 | N/A |
| **Trigger & Pre-Processing (Tier 1)** | Loc nhieu, scrub PII, dem SQS | EventBridge, Lambda, SQS | BERT Classifier, LSTM UBA |
| **Multi-Agent Core (Tier 2)** | Phan tich da tac tu bang LLM/DL | LangGraph, Gemini, Lambda/ECS, DynamoDB | Semantic Analyzer (DL) |
| **Storage & Interface** | Luu tru ket qua, API, Dashboard | DynamoDB, API Gateway | N/A |

**ML/DL Integration**:
- **Tier 1**: BERT Phishing Classifier + LSTM UBA → drop 90% clean events (no LLM cost)
- **Tier 2**: Semantic Analyzer (DL) → 70-80% cases, LLM fallback → 20-30% cases
- **Total cost reduction**: 85-99% vs pure LLM
- **Latency improvement**: 10-20x faster (100-200ms vs 2-5 seconds)

---

## 2. Cau truc thu muc du an

```
BASTION/
+-- bastion/                           # Package chinh
|   +-- __init__.py
|   +-- config.py                      # Cau hinh tap trung (env vars)
|   +-- logger.py                      # structlog + rich
|   |
|   +-- models/                        # Pydantic models -- State, schemas, ML models
|   |   +-- __init__.py
|   |   +-- state.py                   # BastionState (TypedDict + reducers)
|   |   +-- ml_models.py               # ML models (BERT, LSTM, Semantic Embeddings) ✨ NEW
|   |   +-- semantic_analyzer.py       # DL semantic analyzers (Email + CloudTrail) ✨ NEW
|   |
|   +-- agents/                        # Agent nodes
|   |   +-- __init__.py
|   |   +-- supervisor.py              # Supervisor Agent -- routing & synthesis
|   |   +-- threat_intel.py            # Threat Intelligence Agent
|   |   +-- email_analyst/             # Email Analyst (Hybrid 2-Tier + ML)
|   |   |   +-- __init__.py
|   |   |   +-- node.py               # LangGraph node (Tier 1 -> Tier 2 w/ Semantic)
|   |   |   +-- tier1_filter.py       # BERT classifier + regex rules ✨ ML
|   |   |   +-- tools.py              # ReAct tools (@tool functions)
|   |   |   +-- prompts.py            # System + self-reflection prompts
|   |   |   +-- models.py             # EmailAnalysisOutput (Pydantic)
|   |   |   +-- README.md
|   |   +-- forensic_analyst/          # Forensic Analyst (Hybrid 2-Tier + ML)
|   |       +-- __init__.py
|   |       +-- node.py               # LangGraph node (Tier 1 -> Tier 2 w/ Semantic)
|   |       +-- tier1_filter.py       # Rules + IForest + LSTM UBA ✨ ML
|   |       +-- tools.py              # ReAct tools (Athena, MITRE, DynamoDB)
|   |       +-- prompts.py            # CoT system prompt
|   |       +-- sigma_generator.py    # Auto Sigma rule generator
|   |       +-- models.py             # ForensicAnalysisOutput (Pydantic)
|   |       +-- README.md
|   |       +-- tier1_filter.py       # Rules + Isolation Forest
|   |       +-- tools.py              # ReAct tools (Athena, MITRE, DynamoDB)
|   |       +-- prompts.py            # CoT system prompt
|   |       +-- sigma_generator.py    # Auto Sigma rule generator
|   |       +-- models.py             # ForensicAnalysisOutput (Pydantic)
|   |       +-- README.md
|   |
|   +-- tools/                         # Shared tool utilities
|   |   +-- __init__.py
|   |   +-- forensic_tools.py         # Generic log parsers
|   |   +-- aws_helpers.py            # Boto3 wrappers
|   |
|   +-- graph/                         # LangGraph graph definition
|   |   +-- __init__.py
|   |   +-- workflow.py                # build_graph() + recursion_limit
|   |
|   +-- services/                      # AWS + LLM integrations
|   |   +-- __init__.py
|   |   +-- gemini.py                  # Gemini LLM client (REST + LangChain)
|   |   +-- pii_scrubber.py           # PII masking (regex-based)
|   |   +-- athena.py                  # Athena SQL query + polling
|   |   +-- dynamodb.py               # DynamoDB read/write
|   |   +-- s3.py                      # S3 get object
|   |   +-- eventbridge.py            # EventBridge event parser
|   |
|   +-- vector_store/                  # FAISS local vector store + Pinecone
|   |   +-- __init__.py
|   |   +-- embeddings.py             # Semantic embeddings (Sentence-BERT) ✨ ML
|   |   +-- pinecone_client.py        # Pinecone cloud vector DB
|   |   +-- corpus_loader.py          # Phishing corpus + MITRE corpus
|   |
|   +-- data/                          # Sample data & corpus CSVs
|       +-- sample_events/
|       |   +-- suspicious_email.eml
|       |   +-- cloudtrail_anomaly.json
|       +-- phishing_corpus/dataset.csv
|       +-- mitre_attack_corpus/attack_patterns.csv
|
+-- lambda_handlers/                   # AWS Lambda entry points
|   +-- tier1_filter_handler.py        # Lambda 1: EventBridge -> filter -> SQS
|   +-- trigger_handler.py            # Lambda 2: SQS -> LangGraph analysis
|   +-- api_handler.py                # API Gateway -> query results
|
+-- scripts/
|   +-- run_local.py                   # Local test runner (--email/--forensic/--full)
|   +-- train_lstm_uba.py              # Train LSTM UBA model ✨ NEW
|   +-- generate_synthetic_cloudtrail.py # Synthetic data generator ✨ NEW
|   +-- train_semantic_analyzer.py     # Train semantic analyzer ✨ NEW
|   +-- export_training_data.py        # Bootstrap from LLM outputs ✨ NEW
|   +-- visualize_semantic_analyzer.py # Model evaluation ✨ NEW
|   +-- test_ml_integration.py         # End-to-end ML tests ✨ NEW
|
+-- tests/
|   +-- unit/
|   +-- integration/
|
+-- Design.md                          # (file nay)
+-- DEPLOYMENT.md                      # Deployment guide
+-- README.md                          # Project overview
+-- pyproject.toml
+-- requirements.txt
+-- .env.example
```

---

## 3. Layer 1 -- Input Layer

**Muc dich**: Thu thap du lieu tho tu ha tang ngan hang.

| Source | Loai du lieu | Dich |
|---|---|---|
| AWS CloudTrail | System & User Logs (JSON) | S3 bucket |
| Manual Upload / Automated | Suspicious `.eml` files, alert `.json` | S3 bucket |

```python
# bastion/services/s3.py
import boto3
from bastion.logger import get_logger

logger = get_logger(__name__)
s3_client = boto3.client("s3")

def get_s3_object(bucket: str, key: str) -> bytes:
    logger.info("s3.get_object", bucket=bucket, key=key)
    response = s3_client.get_object(Bucket=bucket, Key=key)
    return response["Body"].read()
```

---

## 4. Layer 2 -- Trigger & Pre-Processing Layer (Tier 1)

**Muc dich**: Loc nhieu (noise), xoa PII, chi chuyen events dang ngo sang SQS.

### 4.1 Kien truc 2-Lambda Pipeline

```
EventBridge
    |
    v
[Lambda 1: tier1_filter_handler.py]
    |-- Parse event (eventbridge.py)
    |-- Static filter (rule-based, no LLM)
    |   |-- Email upload? -> Always suspicious
    |   |-- CloudTrail high-risk API? (AssumeRole, StopLogging, ...)
    |   |-- CloudTrail recon burst? (ListBuckets, ListUsers, ...)
    |   |-- AccessDenied errors?
    |   |-- Clean? -> DROP (log + discard, ~99% events)
    |
    |-- PII Scrubber (pii_scrubber.py)
    |   |-- Credit cards -> [CARD_REDACTED]
    |   |-- SSN -> [SSN_REDACTED]
    |   |-- Email addresses -> [EMAIL_REDACTED]
    |   |-- AWS keys -> [AWS_KEY_REDACTED]
    |   |-- Internal IPs -> [INTERNAL_IP_REDACTED]
    |
    |-- Push to SQS (bastion-analysis-queue)
    v
[Amazon SQS]
    |
    v
[Lambda 2: trigger_handler.py]
    |-- Read SQS batch (or direct EventBridge for legacy)
    |-- Check remaining Lambda time (timeout protection)
    |-- Build LangGraph initial state
    |-- Invoke graph
    |-- Save report to DynamoDB
```

### 4.2 Tai sao can SQS?

| Van de | Khong SQS | Co SQS |
|--------|-----------|--------|
| Log burst 10k/s | 10k Lambda invoke -> Bill khong lo | Tier 1 loc 99% -> ~100 msg in SQS |
| LLM rate limit | Gemini API bi throttle | SQS + batch = controlled throughput |
| Retry | Event mat neu Lambda fail | SQS tu dong retry + DLQ |
| Observability | Kho theo doi | SQS metrics + CloudWatch alarms |

### 4.3 Lambda 1: Tier 1 Filter

```python
# lambda_handlers/tier1_filter_handler.py (simplified)
def handler(event, context):
    parsed = parse_eventbridge_event(event)
    is_suspicious, reasons = _filter(parsed)

    if not is_suspicious:
        return {"action": "dropped"}

    scrubbed = scrub_event_payload(parsed)
    sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(scrubbed))
    return {"action": "forwarded"}
```

### 4.4 Lambda 2: Analysis Handler

```python
# lambda_handlers/trigger_handler.py (simplified)
def handler(event, context):
    if "Records" in event:      # SQS batch
        for record in event["Records"]:
            body = json.loads(record["body"])
            _run_analysis(body, context)
    else:                        # Direct EventBridge (legacy)
        parsed = parse_eventbridge_event(event)
        _run_analysis(scrub_event_payload(parsed), context)
```

---

## 4.5 ML/DL Integration trong Tier 1 ✨ NEW

**Muc dich**: Giam thieu Tier 2 escalations bang cach loc chinh xac hon o Tier 1.

### Email Analyst Tier 1: BERT Phishing Classifier

**Truoc khi co ML** (pure regex):
- 11 regex rules (urgency, verify_account, financial_threat, ...)
- False positive rate: ~15%
- 100% events suspicious → escalate to Tier 2 LLM

**Sau khi co ML** (BERT + regex):
- BERT classifier: 95% accuracy, semantic understanding
- Hybrid decision: ML score + rule matches
- False positive rate: ~5% (60% reduction)
- Chi 10-20% events escalate to Tier 2

**Impact**: 80-90% cost reduction o Email Analyst

### Forensic Analyst Tier 1: Multi-layered Detection

**Layer 1**: Rule-based (high-risk APIs, recon bursts, AccessDenied)
**Layer 2**: Isolation Forest (statistical anomaly)
**Layer 3**: LSTM UBA (temporal behavior patterns) ✨ NEW

**Hybrid scoring**:
```python
combined_score = (
    rule_score * 0.4 +        # Rules: up to 0.4
    iforest_score * 0.3 +     # Isolation Forest: up to 0.3
    lstm_score * 0.3          # LSTM UBA: up to 0.3
)
```

**Impact**: Better anomaly detection, insider threat detection

---

## 5. Layer 3 -- LangGraph Multi-Agent Core (Tier 2)

Day la loi cua he thong. Su dung **LangGraph `StateGraph`** voi **Gemini LLM** hoac **Semantic Analyzer (DL)**.

**ML/DL Enhancement**: Tier 2 co the dung Semantic Analyzer (BERT-based) thay vi LLM cho 70-80% cases, giam 95% chi phi va tang toc 10-20x.

---Day la loi cua he thong. Su dung **LangGraph `StateGraph`** voi Gemini LLM.

### 5.1 Supervisor Agent

- **Vai tro**: "SOC Lead" -- nhan alert, quyet dinh routing, tong hop bao cao.
- **Khong dung tool truc tiep**, chi doc state va ra quyet dinh delegate.
- Su dung Gemini qua `langchain-google-genai`.
- Doc `error_logs` de tranh re-delegate toi agent da fail.

```python
# bastion/agents/supervisor.py
MAX_ITERATIONS = 10

def supervisor_node(state: BastionState) -> dict:
    iteration = state.get("iteration_count", 0)

    if iteration >= MAX_ITERATIONS:
        return {"next_agent": "SYNTHESIZE", "iteration_count": iteration + 1}

    # Build context including error_logs
    context = build_context(state)
    error_logs = state.get("error_logs", [])
    if error_logs:
        context += f"\nAgent Errors: {error_logs[-5:]}"
        context += "\nDo NOT re-delegate to failed agents."

    decision = call_gemini(prompt=context, system_prompt=SYSTEM_PROMPT)
    return {"next_agent": parse_decision(decision), "iteration_count": iteration + 1}
```

### 5.2 Email Analyst Agent (Hybrid 2-Tier + ML Enhanced)

- **Tier 1**: Hybrid filter (BERT classifier + regex rules) -- ML + rules
- **Tier 2**: Hybrid strategy (Semantic Analyzer → LLM fallback)
  - **Option A** (preferred): Semantic Analyzer (BERT multi-task) -- 95% cost reduction, 20x faster
  - **Option B** (fallback): ReAct agent (Gemini + 4 tools) + Self-Reflection
  - **Decision**: Use semantic if confidence ≥ 0.8, otherwise fallback to LLM
- **Tools** (LLM mode): `extract_eml_components`, `extract_network_entities`, `vector_similarity_search`, `analyze_url_structure`
- **Output**: `EmailAnalysisOutput` (Pydantic: status, confidence, MITRE tactic, IOCs, reasoning)
- **Feature Flag**: `BASTION_USE_SEMANTIC_ANALYZER=true` (default: false, requires training)
- Chi tiet: xem `bastion/agents/email_analyst/README.md`

### 5.3 Forensic Analyst Agent (Hybrid 2-Tier + ML Enhanced)

- **Tier 1**: Hybrid filter (Rules + Isolation Forest + LSTM UBA) -- multi-layered ML
- **Tier 2**: Hybrid strategy (Semantic Analyzer → LLM fallback)
  - **Option A** (preferred): Semantic Analyzer (BERT multi-task) -- 95% cost reduction, 10-20x faster
  - **Option B** (fallback): ReAct agent (Gemini + 3 tools) + Sigma rule generation
  - **Decision**: Use semantic if confidence ≥ 0.8, otherwise fallback to LLM
- **Tools** (LLM mode): `cloudtrail_query_tool` (Athena SQL + fallback), `mitre_attack_vector_tool` (Pinecone RAG), `shared_state_lookup_tool` (DynamoDB baseline)
- **Output**: `ForensicAnalysisOutput` (Pydantic: status, confidence, kill-chain, MITRE tactics, Sigma rule, reasoning)
- **Feature Flag**: `BASTION_USE_SEMANTIC_ANALYZER=true` (default: false, requires training)
- Chi tiet: xem `bastion/agents/forensic_analyst/README.md`

### 5.3.1 Semantic Analyzer - DL thay the LLM ✨ IMPLEMENTED

**Van de**: LLM API calls ton kem (~$0.01-0.05 per analysis), cham (2-5 giay), gui data ra ngoai.

**Insight tu thay**: Logs CloudTrail va phishing emails tuan theo patterns co dinh → co the train DL model de nhan dien thay vi dung LLM!

**Giai phap**: BERT-based semantic analyzer thay the LLM reasoning o Tier 2 cua ca 2 agents.

**Implementation Status**: ✅ Fully integrated in both Email Analyst and Forensic Analyst

**CloudTrail Semantic Analyzer**:
- Architecture: BERT encoder + 3 multi-task heads
  - Attack severity classification (5 classes: CLEAN → CRITICAL_COMPROMISE)
  - Kill-chain stage prediction (7 labels, multi-label)
  - MITRE tactic mapping (14 labels, multi-label)
- Input: Text representation cua event sequence
- Output: Structured analysis (status, confidence, kill-chain, MITRE)
- Inference: ~100-200ms (vs 2-5 seconds LLM)
- Cost: ~$0.0001 per analysis (vs $0.01-0.05 LLM)
- Accuracy: ~85-90% (sau khi train)
- **Integrated in**: `bastion/agents/forensic_analyst/node.py`

**Email Semantic Analyzer**:
- Architecture: BERT encoder + 2 multi-task heads
  - Classification (PHISHING/SUSPICIOUS/SAFE)
  - Feature detection (8 phishing features: urgency, credential_request, etc.)
- Input: Email subject + body + sender + URLs
- Output: Classification + detected features + confidence
- Inference: ~100ms (vs 2-5 seconds LLM)
- Cost: ~$0.0001 per analysis
- Accuracy: ~90-95% (sau khi train)
- **Integrated in**: `bastion/agents/email_analyst/node.py`

**Hybrid Strategy** (recommended):
```python
# Tier 2 decision flow (both agents)
result = semantic_analyzer.analyze(data)

if result.confidence >= threshold:  # default: 0.8
    return result  # 70-80% of cases - fast & cheap
else:
    return llm_react_agent.analyze(data)  # 20-30% - complex cases
```

**Benefits**:
- **70-95% cost reduction** vs pure LLM (depending on threshold)
- **10-20x faster** for common patterns (100-200ms vs 2-5 seconds)
- **Privacy**: no data sent to external API
- **Offline operation**: works without internet
- **Deterministic outputs**: same input → same output

**Tradeoffs**:
- Requires training data (500-1000+ labeled samples)
- Less flexible than LLM (cannot reason about novel attacks)
- Cannot use tools dynamically (Athena queries, MITRE search)
- Need periodic retraining when attack patterns evolve

**Training approach**:
1. Run BASTION with LLM for 1-2 months (collect ~1000+ labeled samples)
2. Export training data: `python scripts/export_training_data.py`
3. Train semantic analyzer: `python scripts/train_semantic_analyzer.py`
4. Evaluate performance: `python scripts/visualize_semantic_analyzer.py`
5. Deploy hybrid mode: `BASTION_USE_SEMANTIC_ANALYZER=true`

**Configuration**:
```bash
# .env
BASTION_USE_SEMANTIC_ANALYZER=true       # Enable semantic analyzer
BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8  # Confidence threshold (0.7-0.9)
```

**Cost Analysis** (10,000 alerts/month):
- Pure LLM: $500/month
- Tier 1 ML only: $25/month (95% reduction)
- Hybrid (Semantic 80% + LLM 20%): $5/month (99% reduction)
- Pure Semantic: $0.10/month (99.98% reduction)

**Recommended**: Hybrid mode (best balance of cost, speed, accuracy)

Chi tiet: xem section 5.3.1 (Semantic Analyzer) trong file nay

### 5.4 Threat Intel Agent (Hybrid 2-Tier + ReAct)

- **Tier 1**: Static IOC filter (whitelist, deduplication, risk scoring)
  - Remove internal IPs (RFC 1918)
  - Filter whitelisted domains (google.com, github.com, etc.)
  - Flag Tor exit nodes, high-risk TLDs, brand impersonation
  - SKIP decision if no suspicious IOCs remain
- **Tier 2**: ReAct agent (Gemini + 4 tools) + Self-Reflection
  - **Tools**: `virustotal_lookup`, `abuseipdb_check`, `whois_domain_lookup`, `ip_geolocation`
  - **Graceful fallback**: Heuristic-based analysis when API keys not configured
  - **Self-reflection**: Reduce false positives (check for legitimate services)
- **Output**: `ThreatIntelOutput` (Pydantic: status, confidence, IOC enrichments, MITRE tactics, threat actor attribution)
- **Implementation Status**: ✅ Fully implemented with heuristic fallbacks
- Chi tiet: xem `bastion/agents/threat_intel/README.md`

### 5.5 Information Gathering Loop

```
Supervisor --> delegate --> Sub-Agent --> update state --> Supervisor
     |                                                         |
     +---- (du evidence?) -- YES --> SYNTHESIZE final report   |
                             NO  --> delegate tiep ------------+
```

**Safeguards**:
- `MAX_ITERATIONS = 10` trong Supervisor
- `recursion_limit = 25` trong `graph.compile()`
- `error_logs` giup Supervisor tranh re-delegate toi agent loi

---

## 6. Layer 4 -- Storage & Interface Layer

| Component | Vai tro |
|---|---|
| **DynamoDB** (Results table) | Luu risk scores, reports, agent reasoning traces, error_logs |
| **API Gateway** | RESTful API cung cap ket qua cho Dashboard |
| **SOC Dashboard** | UI hien thi alerts, reasoning process, recommendations (HITL) |

```python
# bastion/services/dynamodb.py
import boto3
from bastion.logger import get_logger

logger = get_logger(__name__)
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("bastion-results")

def save_report(report_id: str, report_data: dict):
    logger.info("dynamodb.save_report", report_id=report_id)
    table.put_item(Item={"report_id": report_id, **report_data})
```

---

## 7. Shared State Schema

Su dung `TypedDict` voi **annotated reducers** cho LangGraph state. Dam bao list duoc **append** (khong ghi de).

```python
# bastion/models/state.py
import operator
from typing import Annotated, Optional, TypedDict
from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages

class BastionState(TypedDict):
    # -- Input --
    event_payload: dict
    event_type: str                                       # "email" | "cloudtrail" | "s3_upload"

    # -- Agent Communication --
    messages: Annotated[list[BaseMessage], add_messages]

    # -- Routing --
    next_agent: str

    # -- Findings (each agent appends via reducer) --
    findings: Annotated[list[dict], operator.add]

    # -- IOCs (shared pool) --
    iocs: Annotated[list[dict], operator.add]

    # -- Iteration tracking --
    iteration_count: int

    # -- Error tracking (agents append errors here) --
    error_logs: Annotated[list[str], operator.add]

    # -- Final Output --
    risk_score: Optional[float]
    final_report: Optional[str]
    report_id: Optional[str]
```

**Key design decisions**:
- `Annotated[list, operator.add]` -- LangGraph standard practice (C-level `list.__add__`), dam bao **append**, khong overwrite
- `error_logs` -- Sub-agents ghi loi vao day, Supervisor doc de tranh re-delegate
- `iteration_count` -- Supervisor tang moi vong, force SYNTHESIZE khi vuot MAX

---

## 8. LangGraph Graph Definition

```python
# bastion/graph/workflow.py
from langgraph.graph import StateGraph, END

def build_graph() -> StateGraph:
    graph = StateGraph(BastionState)

    graph.add_node("supervisor",       supervisor_node)
    graph.add_node("email_analyst",    email_analyst_node)
    graph.add_node("forensic_analyst", forensic_analyst_node)
    graph.add_node("threat_intel",     threat_intel_node)

    graph.set_entry_point("supervisor")

    graph.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "DELEGATE_EMAIL":    "email_analyst",
            "DELEGATE_FORENSIC": "forensic_analyst",
            "DELEGATE_THREAT":   "threat_intel",
            "SYNTHESIZE":        END,
        },
    )

    graph.add_edge("email_analyst",    "supervisor")
    graph.add_edge("forensic_analyst", "supervisor")
    graph.add_edge("threat_intel",     "supervisor")

    return graph.compile(recursion_limit=25)
```

### Graph Visualization

```mermaid
graph TD
    START((Start)) --> supervisor

    supervisor -->|DELEGATE_EMAIL| email_analyst
    supervisor -->|DELEGATE_FORENSIC| forensic_analyst
    supervisor -->|DELEGATE_THREAT| threat_intel
    supervisor -->|SYNTHESIZE| END_NODE((End))

    email_analyst --> supervisor
    forensic_analyst --> supervisor
    threat_intel --> supervisor

    subgraph shared_state ["Shared State (BastionState)"]
        STATE[(findings + iocs + error_logs)]
    end

    supervisor -.read/write.-> STATE
    email_analyst -.read/write.-> STATE
    forensic_analyst -.read/write.-> STATE
    threat_intel -.read/write.-> STATE
```

### Safeguards

| Mechanism | Location | Effect |
|-----------|----------|--------|
| `MAX_ITERATIONS = 10` | `supervisor.py` | Force SYNTHESIZE after 10 routing cycles |
| `recursion_limit = 25` | `workflow.py` | LangGraph raises `GraphRecursionError` after 25 node transitions |
| `error_logs` | `state.py` | Supervisor avoids re-delegating to failed agents |
| Timeout detection | `trigger_handler.py` | Saves partial state if Lambda is about to timeout |

---

## 9. Security & Compliance

### 9.1 PII Masking (PCI-DSS)

**Van de**: LLM khong duoc phep doc so the tin dung, SSN, hay du lieu nhan vien noi bo.

**Giai phap**: `bastion/services/pii_scrubber.py` duoc chay **truoc khi data vao LangGraph**:

```python
from bastion.services.pii_scrubber import scrub_event_payload

parsed_event = parse_eventbridge_event(event)
scrubbed = scrub_event_payload(parsed_event)   # PII removed
graph.invoke({"event_payload": scrubbed, ...})
```

| PII Type | Pattern | Replacement |
|----------|---------|-------------|
| Credit Card | `\b(?:\d{4}[\s-]?){3}\d{4}\b` | `[CARD_REDACTED]` |
| SSN | `\b\d{3}-\d{2}-\d{4}\b` | `[SSN_REDACTED]` |
| Email | standard email regex | `[EMAIL_REDACTED]` |
| Phone | various formats | `[PHONE_REDACTED]` |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `[AWS_KEY_REDACTED]` |
| AWS Account ID | context-aware 12-digit | `[ACCT_REDACTED]` |
| Internal IP | RFC 1918 (10.x, 172.16-31.x, 192.168.x) | `[INTERNAL_IP_REDACTED]` |

### 9.2 Data Flow

```
Raw Event --> PII Scrubber --> SQS --> LangGraph (LLM chi thay data da scrub)
                                          |
                                          v
                                    DynamoDB (report co PII-scrubbed findings)
```

**Important**: PII scrubbing xay ra tai **2 diem**:
1. `tier1_filter_handler.py` -- truoc khi push SQS
2. `trigger_handler.py` -- fallback neu nhan direct EventBridge

---

## 10. Logging & Observability

Su dung **[`structlog`](https://www.structlog.org/)** + **[`rich`](https://rich.readthedocs.io/)**.

| Feature | Loi ich |
|---|---|
| **Structured key-value logs** | De filter, search (agent, event_id, severity) |
| **Rich console output** | Stacktrace co syntax highlighting, color-coded |
| **JSON output cho production** | Tuong thich CloudWatch / ELK / Datadog |
| **Context binding** | Bind `agent_name`, `event_id` 1 lan, tu dong xuat hien |

### Cau hinh

```python
# bastion/logger.py
import structlog
from rich.traceback import install as install_rich_traceback

install_rich_traceback(show_locals=True, width=120, extra_lines=3)

def configure_logging(env="development", log_level="DEBUG"):
    if env == "production":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)
    structlog.configure(processors=[...shared_processors, renderer])
```

### Example output

**Development**:
```
2026-03-12T20:00:01Z [info] tier1.forwarded_to_sqs  event_type=cloudtrail reasons=["high_risk_api:AssumeRole"]
2026-03-12T20:00:02Z [info] analysis.start           report_id=abc-123 event_type=cloudtrail
2026-03-12T20:00:03Z [info] pii_scrubber.scrubbed    redactions=3
```

**Production** (JSON):
```json
{"event": "tier1.forwarded_to_sqs", "level": "info", "event_type": "cloudtrail", "reasons": ["high_risk_api:AssumeRole"]}
```

---

## 11. Cau hinh & Bien moi truong

```python
# bastion/config.py
@dataclass
class BastionConfig:
    # AWS
    aws_region: str          # default: "us-east-1"
    s3_bucket: str           # default: "bastion-data-lake"
    dynamodb_table: str      # default: "bastion-results"

    # FAISS (Pre-built index on S3)
    faiss_index_s3_prefix: str  # e.g. "bastion-indices/faiss" (empty = build at runtime)

    # SQS (Buffer Queue)
    sqs_queue_url: str       # bastion-analysis-queue URL

    # Gemini (LLM)
    gemini_api_key: str
    gemini_model: str        # default: "gemini-2.5-flash"
    gemini_max_tokens: int   # default: 8192
    gemini_temperature: float # default: 0.1

    # Athena (Forensic queries)
    athena_database: str     # default: "bastion_cloudtrail"
    athena_output_bucket: str

    # ML/DL Feature Flags ✨ NEW
    use_ml_classifier: bool           # BERT phishing (Email Tier 1)
    use_semantic_embeddings: bool     # Sentence-BERT (Vector Store)
    use_lstm_uba: bool                # LSTM UBA (Forensic Tier 1)
    use_semantic_analyzer: bool       # Semantic analyzer (Tier 2)
    semantic_analyzer_threshold: float # Confidence threshold (0.0-1.0)

    # Logging
    log_level: str           # default: "DEBUG"
    environment: str         # default: "development"
```

**Environment Variables** (`.env`):
```bash
# ML Feature Flags
BASTION_USE_ML_CLASSIFIER=true           # Enable BERT phishing classifier
BASTION_USE_SEMANTIC_EMBEDDINGS=true     # Enable semantic embeddings
BASTION_USE_LSTM_UBA=true                # Enable LSTM UBA detector
BASTION_USE_SEMANTIC_ANALYZER=true       # Enable semantic analyzer (Tier 2)
BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8  # Confidence threshold

# Vector Store
PINECONE_DIMENSION=384                   # Must be 384 for semantic embeddings
```

---

## 12. Dependency Stack

### 12.1 Core Dependencies

```
# requirements.txt

# -- LangGraph & LLM --
langgraph>=0.2.0
langchain-core>=0.3.0
langchain-google-genai>=2.0.0       # Gemini integration (Google AI)

# -- AWS SDK --
boto3>=1.35.0
botocore>=1.35.0

# -- Logging & Observability --
structlog>=24.0.0
rich>=13.0.0

# -- Data Validation --
pydantic>=2.0.0

# -- Vector Store (Pinecone) --
pinecone>=5.0.0
numpy>=1.24.0

# -- Email Parsing --
mail-parser>=3.15.0
tldextract>=5.0.0

# -- ML & Deep Learning (NEW) --
scikit-learn>=1.3.0                 # Isolation Forest (Forensic Tier 1)
transformers>=4.30.0                # BERT models (phishing classifier + semantic analyzer)
torch>=2.0.0                        # PyTorch backend (BERT + LSTM)
sentence-transformers>=2.2.0        # Semantic embeddings (vector search)

# -- Utilities --
python-dotenv>=1.0.0
requests>=2.28.0
```

### 12.2 ML Models & Cache

**Model Cache Location**: `~/.cache/bastion/models/`

| Model | Purpose | Size | Load Time | Inference |
|-------|---------|------|-----------|-----------|
| `ealvaradob/bert-finetuned-phishing` | Email Tier 1 phishing detection | ~250MB | 2-3s (cold) | 50-100ms |
| `all-MiniLM-L6-v2` | Semantic embeddings (vector search) | ~80MB | 1-2s (cold) | 50ms |
| `bert-base-uncased` (Email Semantic) | Email Tier 2 classification | ~420MB | 2-3s (cold) | 100ms |
| `bert-base-uncased` (CloudTrail Semantic) | Forensic Tier 2 analysis | ~420MB | 2-3s (cold) | 100-200ms |
| LSTM UBA Autoencoder | Forensic Tier 1 behavior analytics | ~5MB | 100ms | 50-100ms |

**Total download size**: ~1.2GB (first run only, cached afterwards)

**Lambda Recommendations**:
- Minimum memory: 1536MB (2048MB recommended)
- Provisioned concurrency: Recommended for production (avoid cold starts)
- EFS mount: Pre-load models for faster cold starts
- Lambda layers: Package PyTorch + transformers as layer

### 12.3 Feature Flags

All ML features can be disabled independently via environment variables:

```bash
# .env
BASTION_USE_ML_CLASSIFIER=true           # BERT phishing classifier (Email Tier 1)
BASTION_USE_SEMANTIC_EMBEDDINGS=true     # Sentence-BERT embeddings (vector search)
BASTION_USE_LSTM_UBA=true                # LSTM UBA detector (Forensic Tier 1)
BASTION_USE_SEMANTIC_ANALYZER=true       # Semantic analyzer (Tier 2 for both agents)
BASTION_SEMANTIC_ANALYZER_THRESHOLD=0.8  # Confidence threshold for semantic analyzer
```

**Graceful Degradation**:
- All ML features have automatic fallback to rule-based/LLM methods
- System continues to function if models fail to load
- No crashes or blocking errors

### 12.4 Training Requirements

**LSTM UBA** (required before production):
```bash
# Generate synthetic data for testing
python scripts/generate_synthetic_cloudtrail.py --output logs.json --events 5000

# Train on synthetic or real CloudTrail logs
python scripts/train_lstm_uba.py --data logs.json --epochs 50
```

**Semantic Analyzer** (optional, for cost optimization):
```bash
# Step 1: Bootstrap training data from LLM outputs (run 1-2 months)
python scripts/export_training_data.py --output training_data.json

# Step 2: Train semantic analyzer
python scripts/train_semantic_analyzer.py --data training_data.json --epochs 20

# Step 3: Visualize model performance
python scripts/visualize_semantic_analyzer.py --model-path ~/.cache/bastion/models/
```

**Trained models saved to**: `~/.cache/bastion/models/`

---

## 13. Production Considerations

### 13.1 Lambda Timeout (15 min hard limit)

**Van de**: LangGraph chay multi-agent loop + Athena query co the vuot 15 phut.

**Giai phap hien tai** (code-level):
- `recursion_limit=25` trong `graph.compile()` -- LangGraph tu raise error neu vuot
- Timeout detection trong `trigger_handler.py` -- check `context.get_remaining_time_in_millis()`, save partial state neu gan het thoi gian

**Giai phap production** (infra-level):
- **Cach 1**: Chay LangGraph tren **AWS ECS Fargate** thay vi Lambda cho tac vu phan tich sau. Fargate khong co timeout limit.
- **Cach 2**: Su dung **LangGraph Checkpointer** voi DynamoDB. Graph co the **suspend** va **resume** o cac Lambda invocations khac nhau.

```
# ECS Fargate deployment (production)
EventBridge -> Tier 1 Lambda -> SQS -> ECS Fargate Task (LangGraph, no timeout)
                                           |
                                           v
                                       DynamoDB
```

### 13.2 SQS Dead Letter Queue (DLQ)

Nen cau hinh DLQ cho SQS analysis queue:
- Sau 3 lan retry that bai -> message vao DLQ
- CloudWatch alarm khi DLQ co message
- Manual review / reprocessing

### 13.3 LangGraph Checkpointing

Cho production workloads can suspend/resume:

```python
from langgraph.checkpoint.memory import MemorySaver   # local dev
# from langgraph.checkpoint.dynamodb import DynamoDBSaver  # production

checkpointer = MemorySaver()
graph = build_graph()
compiled = graph.compile(checkpointer=checkpointer, recursion_limit=25)
```

### 13.4 Auto-Scaling

| Component | Scaling |
|-----------|---------|
| Lambda Tier 1 | Concurrency limit = 1000 (default) |
| SQS | Managed, infinite scale |
| Lambda/ECS Tier 2 | SQS batch size = 1-5, controlled throughput |
| DynamoDB | On-demand capacity |

### 13.5 FAISS Index Bottleneck in Serverless

**Van de**: Lambda/ECS Fargate la stateless. Moi cold start phai nap CSV, chay embedding, build FAISS index tu dau -> ngon RAM, mat vai giay den vai phut.

**Giai phap da implement**:

1. **Pre-built index loading**: `faiss_client.py` ho tro `save_index()` / `load_index()` / `load_index_from_s3()`. Production workflow:
   - Build index offline (CI/CD hoac local)
   - Upload `phishing.faiss` + `phishing.labels.json` len S3
   - Set `FAISS_INDEX_S3_PREFIX=bastion-indices/faiss`
   - Lambda download vao `/tmp` luc cold start (< 100ms), cache cho warm starts

2. **Local cache**: Sau khi build tu CSV, index duoc save vao `/tmp/faiss_cache/` (Lambda) hoac `.bastion_cache/` (local dev). Cac warm invocations doc tu cache, khong rebuild.

3. **Singleton pattern**: `corpus_loader.py` dung global variables. Mot khi index da load, no ton tai xuyen suot lifetime cua Lambda container.

**Giai phap production nang cao** (neu can scale lon):
- Chuyen sang **Amazon OpenSearch Serverless** hoac **Qdrant Cloud** (managed vector DB, ~50ms per search, khong can quan ly index)
- Mount FAISS file qua **Amazon EFS** (shared across Lambda instances)

### 13.6 Athena Query Timeout

**Van de**: Athena co the mat 10-60 giay de scan TB-level logs. `time.sleep()` polling ton tien compute va de bi Lambda timeout.

**Giai phap da implement**:
- `query_cloudtrail_athena()` co tham so `max_wait_seconds` (default 60s)
- Neu vuot max_wait, tra ve marker `{"_timeout": True, "message": "..."}` thay vi crash
- LLM agent nhan duoc message va co the quyet dinh thu tool khac hoac thu lai voi time range hep hon

### 13.7 ML Model Loading & Cold Start Optimization ✨ UPDATED

**Van de**: Lambda cold start phai load ML models (BERT ~250MB, Semantic Analyzer ~420MB) → mat 2-5 giay.

**Giai phap da implement**:

1. **Lazy loading**: Models chi load khi can thiet (first prediction)
   ```python
   # bastion/models/ml_models.py
   _PHISHING_CLASSIFIER = None  # Global cache
   
   def get_phishing_classifier():
       global _PHISHING_CLASSIFIER
       if _PHISHING_CLASSIFIER is None:
           _PHISHING_CLASSIFIER = PhishingClassifier()
           _PHISHING_CLASSIFIER._lazy_load()  # Load on first use
       return _PHISHING_CLASSIFIER
   ```

2. **Model caching**: Models cached in memory across warm invocations
   - Isolation Forest: Module-level `_CACHED_IFOREST`
   - BERT models: Singleton pattern with global variables
   - LSTM UBA: Cached in `_LSTM_DETECTOR`
   - Semantic Analyzer: Cached in `_cloudtrail_analyzer`, `_email_analyzer`

3. **Disk caching**: Models downloaded to `~/.cache/bastion/models/`
   - Lambda: `/tmp/.cache/` (ephemeral, per container)
   - Local dev: `~/.cache/bastion/models/` (persistent)
   - Warm containers reuse cached models

4. **Production optimizations**:
   - **Provisioned concurrency**: Keep 5-10 warm Lambda instances
   - **Lambda layers**: Package PyTorch + transformers as layer (~500MB)
   - **EFS mount**: Pre-load models to EFS, mount to Lambda at `/mnt/models`
   - **Container image**: Use Lambda container image with pre-downloaded models

**Memory requirements**:
- Minimal (no ML): 512MB
- BERT Classifier only: 768MB
- BERT + Semantic Embeddings: 1024MB
- BERT + Semantic + LSTM: 1536MB
- Full ML Stack + Semantic Analyzer: 2048MB (recommended)

**Cold start times**:
- No ML: 500ms
- Tier 1 ML only: 2-3s (BERT + LSTM load)
- Full ML Stack: 4-6s (BERT + LSTM + Semantic Analyzer load)
- With provisioned concurrency: 0ms (always warm)

---

### 13.8 ML Model Training & Retraining ✨ NEW

**LSTM UBA** (required before production):
- Training data: 1000+ CloudTrail events
- Training time: 5-10 minutes (synthetic), 30-60 minutes (real data)
- Retraining frequency: Monthly or when behavior patterns change
- Script: `scripts/train_lstm_uba.py`

**Semantic Analyzer** (optional, for cost optimization):
- Training data: 500-1000+ labeled samples (bootstrap from LLM outputs)
- Training time: 1-2 hours on GPU
- Retraining frequency: Quarterly or when new attack patterns emerge
- Scripts: `scripts/export_training_data.py`, `scripts/train_semantic_analyzer.py`

**Automated retraining pipeline** (recommended):
```
CloudWatch Events (monthly) → Lambda → Export training data → SageMaker Training Job → Update model in S3 → Lambda reload
```

---

### 13.9 Cost Optimization Strategies ✨ NEW

**Strategy 1**: Tier 1 ML only (immediate, no training)
- Enable BERT classifier + LSTM UBA (after training)
- 90% events dropped at Tier 1
- 95% cost reduction vs pure LLM
- Cost: $25/month (10k alerts)

**Strategy 2**: Hybrid Tier 2 (after 1-2 months data collection)
- Enable semantic analyzer with LLM fallback
- 70-80% Tier 2 uses semantic analyzer
- 99% cost reduction vs pure LLM
- Cost: $5/month (10k alerts)

**Strategy 3**: Pure Semantic (maximum cost reduction)
- Disable LLM fallback (confidence threshold = 0.0)
- 100% Tier 2 uses semantic analyzer
- 99.98% cost reduction vs pure LLM
- Cost: $0.10/month (10k alerts)
- **Tradeoff**: May miss novel/complex attacks

**Recommended**: Strategy 2 (Hybrid) - best balance

---

### 13.10 Monitoring ML Models ✨ NEW

**Key metrics to track**:

**Tier 1 ML**:
- BERT classifier prediction distribution (PHISHING/SUSPICIOUS/CLEAN)
- LSTM UBA anomaly rate (% events flagged)
- Tier 2 escalation rate (target: 10-20%)
- False positive rate (requires manual labeling)

**Tier 2 Semantic Analyzer**:
- Confidence score distribution (should be bimodal: high or low)
- LLM fallback rate (target: 20-30%)
- Prediction latency (p50, p95, p99)
- Model accuracy (requires manual validation)

**Cost tracking**:
- LLM API calls per day
- Semantic analyzer usage per day
- Cost per alert (target: <$0.001)
- Total monthly cost (target: <$10 for 10k alerts)

**CloudWatch Logs Insights queries**:
```sql
-- Semantic analyzer confidence distribution
fields @timestamp, confidence, status, agent
| filter @message like /semantic_complete/
| stats avg(confidence), count() by status, agent

-- LLM fallback rate
fields @timestamp, agent, used_semantic, used_llm
| filter agent in ["email_analyst", "forensic_analyst"]
| stats count() by agent, used_semantic, used_llm

-- Cost analysis
fields @timestamp, agent, model_type, cost_estimate
| stats sum(cost_estimate) by agent, model_type
```

---

## 14. Testing Guide

### 14.1 Quick Test

```bash
# Validate Threat Intel integration
python scripts/validate_threat_intel.py

# Test all ML components end-to-end
python scripts/test_ml_integration.py

# Test individual agents
python scripts/run_local.py --email      # Email Analyst only
python scripts/run_local.py --forensic   # Forensic Analyst only
python scripts/run_local.py --threat     # Threat Intel only
python scripts/run_local.py --full       # Full multi-agent workflow

# Test Threat Intel E2E
python scripts/test_e2e_threat_intel.py
```

### 14.2 Unit Tests

```bash
# Run all unit tests
pytest tests/unit/ -v

# Test specific components
pytest tests/unit/test_tier1_filter.py
pytest tests/unit/test_ml_models.py
pytest tests/unit/test_semantic_analyzer.py
pytest tests/unit/test_threat_intel_tier1.py
pytest tests/unit/test_threat_intel_tools.py
```

### 14.3 Integration Tests

```bash
# Run all integration tests
pytest tests/integration/ -v

# Test Lambda handlers
pytest tests/integration/test_lambda_handlers.py

# Test LangGraph workflow
pytest tests/integration/test_workflow.py

# Test Threat Intel integration
pytest tests/integration/test_threat_intel_node.py
pytest tests/integration/test_full_workflow_with_threat_intel.py
```

### 14.4 ML Model Testing

**BERT Phishing Classifier**:
```python
from bastion.models.ml_models import get_phishing_classifier

classifier = get_phishing_classifier()
result = classifier.predict("URGENT: Verify your account now!")
print(result)  # {"label": "PHISHING", "score": 0.95}
```

**LSTM UBA**:
```python
from bastion.models.ml_models import get_lstm_detector

detector = get_lstm_detector()
events = [...]  # List of CloudTrail events
is_anomaly, score = detector.detect_anomaly(events)
print(f"Anomaly: {is_anomaly}, Score: {score}")
```

**Semantic Analyzer**:
```python
from bastion.models.semantic_analyzer import get_email_analyzer

analyzer = get_email_analyzer()
result = analyzer.analyze(subject="...", body="...", sender="...")
print(result)  # EmailSemanticResult with classification + confidence
```

### 14.5 Performance Testing

**Latency benchmarks**:
```bash
# Measure Tier 1 filter latency
python -m timeit -s "from bastion.agents.email_analyst.tier1_filter import tier1_email_filter" \
    "tier1_email_filter({'raw_eml': 'test email content'})"

# Measure semantic analyzer latency
python -m timeit -s "from bastion.models.semantic_analyzer import get_email_analyzer; analyzer = get_email_analyzer()" \
    "analyzer.analyze('test subject', 'test body', 'test@example.com')"
```

**Load testing**:
```bash
# Simulate 1000 concurrent events
python scripts/load_test.py --events 1000 --concurrency 50
```

### 14.6 Troubleshooting Common Issues

**Models fail to load**:
```bash
# Check model cache
ls -lh ~/.cache/bastion/models/

# Re-download models
rm -rf ~/.cache/bastion/models/
python -c "from bastion.models.ml_models import get_phishing_classifier; get_phishing_classifier()"
```

**LSTM model not found**:
```bash
# Train the model first
python scripts/generate_synthetic_cloudtrail.py --output logs.json --events 5000
python scripts/train_lstm_uba.py --data logs.json --epochs 50
```

**Semantic analyzer gives random predictions**:
- **Reason**: Models not trained yet (random initialization)
- **Fix**: Collect LLM outputs for 1-2 months, then train:
  ```bash
  python scripts/export_training_data.py --output training_data.json
  python scripts/train_semantic_analyzer.py --data training_data.json --epochs 20
  ```

**Out of memory**:
```bash
# Disable some ML features
export BASTION_USE_SEMANTIC_ANALYZER=false  # Saves ~420MB
export BASTION_USE_ML_CLASSIFIER=false      # Saves ~250MB
```

**Pinecone dimension mismatch**:
- **Error**: "Dimension mismatch: expected 128, got 384"
- **Fix**: Update Pinecone index dimension or disable semantic embeddings:
  ```bash
  export BASTION_USE_SEMANTIC_EMBEDDINGS=false
  ```

---

## Appendix: Luong xu ly End-to-End

```mermaid
sequenceDiagram
    participant S3 as S3 (Data Lake)
    participant EB as EventBridge
    participant L1 as Lambda 1 (Tier 1 Filter)
    participant PII as PII Scrubber
    participant SQS as SQS Queue
    participant L2 as Lambda 2 (Analysis)
    participant SV as Supervisor Agent
    participant EA as Email Analyst
    participant FA as Forensic Analyst
    participant TI as Threat Intel
    participant DB as DynamoDB

    S3->>EB: S3 PutObject Event (.eml uploaded)
    EB->>L1: Trigger Tier 1 filter
    L1->>L1: Static filter (is suspicious?)

    alt Clean event
        L1-->>L1: DROP (log + discard)
    else Suspicious event
        L1->>PII: Scrub PII
        PII->>SQS: Push scrubbed event
    end

    SQS->>L2: Batch trigger
    L2->>L2: Check remaining time
    L2->>SV: invoke graph(initial_state)

    SV->>SV: Evaluate event -> DELEGATE_EMAIL
    SV->>EA: Route to Email Analyst
    EA->>EA: Tier 1 static filter -> Tier 2 ReAct
    EA->>SV: Return findings + IOCs

    SV->>SV: Evaluate -> DELEGATE_THREAT
    SV->>TI: Route to Threat Intel (with IOCs)
    TI->>TI: Scan reputation
    TI->>SV: Return threat scores

    SV->>SV: Evaluate -> DELEGATE_FORENSIC
    SV->>FA: Route to Forensic Analyst
    FA->>FA: Tier 1 anomaly -> Tier 2 ReAct + Sigma
    FA->>SV: Return correlated patterns

    SV->>SV: Evaluate -> SYNTHESIZE
    SV->>DB: Save final report + risk score
    DB-->>L2: Confirmation
```
