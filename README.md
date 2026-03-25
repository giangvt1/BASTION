# BASTION

**B**ehavioral **A**nalysis & **S**ecurity **T**hreat **I**ntelligence **O**rchestration **N**ode

> Autonomous AI-Powered SOC Platform for Real-Time Incident Response

BASTION is a multi-agent AI security triage system that analyzes suspicious emails, cloud log artifacts, and correlated threat data to generate explainable incident reports, extracted indicators of compromise (IOCs), and actionable response recommendations — all in under 60 seconds.

---

## Problem Statement

- **Pain Point:** Alert fatigue. SOC analysts are drowning in false positives and spend an average of 30 minutes investigating a single alert by manually querying logs and OSINT tools.
- **Target Users:** Tier 1 and Tier 2 SOC Analysts, Incident Responders, Security Operations Teams.
- **Business Impact:** Reduces Mean Time To Respond (MTTR) from 30 minutes to under 1 minute, preventing critical threats from slipping through the noise and saving operational costs.

## Solution Overview

BASTION accepts suspicious security artifacts (`.eml`, `.csv`, `.json`) and correlated multi-source threat data. It preprocesses (PII scrubbing), routes through specialized LangGraph agents for parsing, indicator extraction, OSINT enrichment (VirusTotal + AbuseIPDB), contextual reasoning, and automated report generation — all saved securely in AWS DynamoDB and surfaced on a real-time React SOC Dashboard.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Format Ingestion** | `.eml` emails, `.csv` logs, `.json` CloudTrail events, correlated multi-source batches |
| **Live Threat Intelligence** | VirusTotal API v3 (IP/Domain/Hash) + AbuseIPDB API v2 (IP Abuse Scoring) with graceful fallback |
| **ML/DL Hybrid Detection** | BERT Phishing Classifier, LSTM Autoencoder UBA, Isolation Forest Anomaly Detection |
| **Multi-Agent Orchestration** | LangGraph Supervisor routing to Email Analyst, Forensic Analyst, Threat Intel agents |
| **Cloud Log Forensics** | Automated CloudTrail hunting via Serverless SQL (AWS Athena) |
| **Explainable Reports** | MITRE ATT&CK mapping, Kill Chain analysis, Sigma Rule auto-generation |
| **SOC Dashboard** | Real-time pipeline visualization, SOAR automation, analyst feedback loop (RLHF) |
| **Privacy-Preserving** | PII Scrubbing via Regex Anonymization before any LLM processing |

---

## System Architecture

```text
+────────────────────────────────────────────────────────────────+
│ Layer 1: INPUT                                                 │
│ CloudTrail Logs, S3 Uploads, Suspicious Emails, VPC Flow Logs  │
│ Formats: .eml, .csv, .json (correlated multi-source batches)   │
+────────────────────────────────────────────────────────────────+
                              │
                              ▼
+────────────────────────────────────────────────────────────────+
│ Layer 2: TIER 1 FILTERING (ML Enhanced, No LLM Cost)           │
│ ├─ BERT Phishing Classifier (DistilBERT, ~95% accuracy)        │
│ ├─ LSTM Autoencoder (User Behavior Analytics)                  │
│ ├─ Isolation Forest (Statistical Anomaly Detection)            │
│ ├─ Rule-Based Checks (Regex, Heuristics)                       │
│ └─ PII Scrubber → SQS Queue                                   │
+────────────────────────────────────────────────────────────────+
                              │
                              ▼
+────────────────────────────────────────────────────────────────+
│ Layer 3: TIER 2 MULTI-AGENT CORE (LangGraph + Gemini 2.5)     │
│                                                                │
│           +─────────────────────────────────+                  │
│           │ Supervisor (Routing + Synthesis) │                  │
│           +─────────────────────────────────+                  │
│                 │             │             │                   │
│           ┌─────────┐   ┌──────────┐   ┌──────────┐           │
│           │ Email   │   │ Forensic │   │ Threat   │           │
│           │ Analyst │   │ Analyst  │   │ Intel    │           │
│           └─────────┘   └──────────┘   └──────────┘           │
│                                             │                  │
│                              ┌──────────────┼──────────────┐   │
│                              │ VirusTotal   │ AbuseIPDB   │   │
│                              │ API v3       │ API v2      │   │
│                              └──────────────┴──────────────┘   │
│                                                                │
│ Semantic Analyzer (DL) → LLM Fallback (Hybrid Architecture)    │
+────────────────────────────────────────────────────────────────+
                              │
                              ▼
+────────────────────────────────────────────────────────────────+
│ Layer 4: STORAGE & INTERFACE                                   │
│ DynamoDB (Reports) + Pinecone (RAG) + React SOC Dashboard      │
+────────────────────────────────────────────────────────────────+
```

---

## Agent Workflow

| Agent | Responsibility | Input | Output |
|-------|----------------|-------|--------|
| **Supervisor** | Orchestrates routing and decides analysis path | Event type & agent findings | Delegated node or Synthesis |
| **Email Analyst** | Extracts structured fields & phishing indicators | Raw `.eml` artifact | Parsed IPs, Domains, URLs, Context |
| **Forensic Analyst** | Queries AWS Athena for historical evidence | Event contexts, IPs, Users | CloudTrail forensic timeline |
| **Threat Intel** | Correlates and enriches IOCs via OSINT | Suspicious IOCs | VT/AbuseIPDB reputation + MITRE tactics |
| **Synthesizer** | Produces explainable final executive report | Combined findings | Structured Markdown Report + Sigma Rule |

---

## ML / DL Models

| Model | Architecture | Purpose | Performance |
|-------|-------------|---------|-------------|
| **Phishing Classifier** | DistilBERT (fine-tuned) | Email phishing detection | ~95% accuracy, ~100ms inference |
| **Semantic Embedder** | Sentence-BERT (all-MiniLM-L6-v2) | Vector search in Pinecone | 384-dim embeddings, ~50ms |
| **LSTM UBA Detector** | LSTM Autoencoder | User Behavior Analytics | Temporal anomaly via reconstruction error |
| **CloudTrail Analyzer** | BERT + Multi-task Heads | Attack classification + MITRE mapping | 5-class severity + 14 MITRE tactics |
| **Email Analyzer** | BERT + Multi-task Heads | Email intent + feature extraction | 3-class + 8 phishing features |
| **Isolation Forest** | Unsupervised ML | Statistical anomaly on CloudTrail | Tier 1 pre-filter, no LLM cost |

> All models are **lazy-loaded** (singleton pattern) and operate in Tier 1 to filter ~90% of benign events **before** any LLM API call, dramatically reducing cost.

---

## Threat Intelligence Integration

| Source | API | Rate Limit | Data Provided | Fallback |
|--------|-----|-----------|---------------|----------|
| **VirusTotal** | v3 REST API | 4 req/min (free) | IP/Domain/Hash detection ratio, malicious engine count | Heuristic mock data |
| **AbuseIPDB** | v2 REST API | 1000 req/day (free) | IP abuse confidence score, country, ISP, Tor status | Heuristic mock data |

Both APIs use a **graceful fallback mechanism** — if the API key is missing, rate limits are hit (429), or network timeout occurs, the system seamlessly falls back to heuristic-based analysis without any pipeline failures.

---

## Technology Stack

- **Frontend:** React 19, Vite, TailwindCSS (real-time SOC Dashboard)
- **Backend:** Python 3.10+, FastAPI
- **AI Orchestration:** LangGraph, LangChain
- **LLMs:** Google Gemini 2.5 Flash
- **ML/DL:** PyTorch, Transformers (HuggingFace), Sentence-Transformers
- **Vector DB:** Pinecone
- **Cloud:** AWS Athena, DynamoDB, S3, Lambda, SQS, EventBridge
- **Threat Intel:** VirusTotal API v3, AbuseIPDB API v2

## AWS Services

| Service | Usage |
|---------|-------|
| **Amazon S3** | Stores uploaded artifacts and cold-storage logs |
| **AWS Athena** | Serverless SQL for deep forensic timeline construction |
| **AWS DynamoDB** | Stores structured analysis results and final reports |
| **AWS Lambda / SQS / EventBridge** | Production deployment targets (`/lambda_handlers`) |

---

## Repository Structure

```text
.
├── bastion/                 # 🔧 BACKEND — Python multi-agent pipeline
│   ├── agents/              #    AI agents (Supervisor, Email, Forensic, Threat Intel, Synthesis)
│   │   ├── supervisor/      #      Routing & orchestration logic
│   │   ├── email_analyst/   #      Tier 1 ML filter + Tier 2 ReAct agent
│   │   ├── forensic_analyst/#      CloudTrail forensics & anomaly detection
│   │   ├── threat_intel/    #      IOC enrichment (VirusTotal, AbuseIPDB, WHOIS)
│   │   └── synthesis.py     #      Report generation + evidence discipline prompt
│   ├── models/              #    ML/DL models (BERT, LSTM, Sentence-BERT)
│   ├── services/            #    AWS services (Athena, DynamoDB, S3) + Gemini + Report Validator
│   ├── graph/               #    LangGraph workflow definition
│   ├── vector_store/        #    Pinecone integration (embeddings, corpus loader)
│   └── data/                #    Phishing corpus + MITRE ATT&CK corpus
│
├── frontend/                # 🎨 FRONTEND — React SOC Dashboard
│   └── src/
│       ├── pages/           #    SOCDashboard, Orchestrator, Metrics
│       ├── components/      #    Header, Sidebar, GraphView, RightPanel
│       └── services/        #    API client (connects to backend)
│
├── scripts/                 # 🛠️ SCRIPTS — Server & training utilities
│   ├── api_server.py        #    FastAPI backend server (main entry point)
│   ├── run_local.py         #    Local CLI runner for testing
│   ├── train_*.py           #    ML model training scripts
│   └── test_*.py            #    Integration test scripts
│
├── lambda_handlers/         # ☁️ AWS LAMBDA — Production deployment handlers
├── dataset/                 # 📊 DATA — Test inputs + ML training datasets
├── notebooks/               # 📓 NOTEBOOKS — ML model training & evaluation
├── tests/                   # 🧪 TESTS — Unit + integration test suites
├── docs/                    # 📄 DOCS — System design & deployment guides
├── requirements.txt         #    Python dependencies
└── pyproject.toml           #    Project metadata & build config
```

---

## Prerequisites

- Python 3.10+
- Node.js 18+
- AWS Account configured (`aws configure`)
- Google Gemini API Key
- Pinecone API Key
- (Optional) VirusTotal API Key — [Get free key](https://www.virustotal.com/gui/join-us)
- (Optional) AbuseIPDB API Key — [Get free key](https://www.abuseipdb.com/register)

## Environment Variables

Create a `.env` file and configure:

```env
# LLM
GEMINI_API_KEY=your_key
GEMINI_MODEL=gemini-2.5-flash

# Vector Store
PINECONE_API_KEY=your_key
PINECONE_INDEX_NAME=bastion-vectors

# AWS
AWS_REGION=ap-southeast-2
ATHENA_DATABASE=bastion_cloudtrail
ATHENA_OUTPUT_BUCKET=s3://your-bucket/athena-results/
BASTION_DYNAMODB_TABLE=bastion-results

# Threat Intel (Optional - graceful fallback if missing)
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# Feature Flags
BASTION_USE_ML_CLASSIFIER=true
BASTION_USE_SEMANTIC_EMBEDDINGS=false
```

## Installation

```bash
# Backend
python -m venv .venv
source .venv/Scripts/activate   # Windows
pip install -r requirements.txt

# Frontend
cd frontend && npm install
```

## How to Run

```bash
# Terminal 1: Backend API
python scripts/api_server.py
# Or: run_api.bat

# Terminal 2: Frontend
cd frontend && npm run dev
```

- **SOC Dashboard:** `http://localhost:5173`
- **API Docs:** `http://localhost:8001/docs`

---

## Demo Scenarios

### Scenario 1: Phishing Email Analysis
- **Input:** Upload `.eml` file via Dashboard drag-and-drop
- **Flow:** Ingestion → PII Scrub → BERT Classifier → Email Analyst → Threat Intel (VT+AbuseIPDB) → Synthesis
- **Output:** Phishing tactics identified, malicious URLs/IPs extracted, VT detection ratios, risk assessment

### Scenario 2: Cloud Log Anomaly Investigation
- **Input:** Upload `.csv` CloudTrail logs
- **Flow:** Ingestion → Isolation Forest + LSTM UBA → Forensic Analyst (Athena SQL) → Threat Intel → Report
- **Output:** Kill Chain timeline, MITRE ATT&CK mapping, auto-generated Sigma detection rule

### Scenario 3: Correlated Multi-Source Batch (NEW)
- **Input:** Upload `dataset/a.json` (correlated email + VPC Flow Logs per IP)
- **Flow:** System detects correlated format → splits into individual tasks → processes sequentially
- **Output:** One report per correlated task, each analyzing phishing email + network activity together

---

## Results / Evaluation

| Metric | Value | Source |
|--------|-------|--------|
| **MTTR Reduction** | 30 min → **< 45 seconds** | End-to-end pipeline measurement |
| **Phishing Detection F1** | **88.8%** (threshold 0.7) | CEAS-08 dataset, 7,826 test emails |
| **Precision (weighted)** | **89.7%** | Notebook `bastion_ml_models.ipynb` |
| **Recall (weighted)** | **88.8%** | Notebook `bastion_ml_models.ipynb` |
| **LSTM Anomaly Ratio** | **22.6×** (attack vs normal) | Synthetic attack injection test |
| **LLM Cost Savings** | ~90% (Tier 1 filters benign events before API calls) | Architecture design |
| **Threat Intel** | Live VT + AbuseIPDB with heuristic fallback | Runtime measurement |

## Limitations and Risks

- **LLM Hallucinations:** Mitigated by forcing Forensic Agent to retrieve hard evidence from AWS Athena before Synthesis.
- **Rate Limiting:** VT free tier is 4 req/min. Mitigated by graceful fallback to heuristic analysis. AbuseIPDB allows 1000 req/day.
- **Production Architecture:** Local API Emulator for demo stability; `lambda_handlers` are ready for AWS deployment.

## AI/ML Notebooks

All custom ML/DL model training and evaluation is documented in a single notebook:

```
notebooks/
├── README.md
└── bastion_ml_models.ipynb    # Training & evaluation for all 3 models
```

| Model | Architecture | Task |
|-------|-------------|------|
| Phishing Classifier | Fine-tuned DistilBERT | Email phishing detection (Tier 1) |
| LSTM Anomaly Detector | LSTM Autoencoder | CloudTrail user behavior anomaly detection |
| Semantic Embedder | Sentence-BERT (all-MiniLM-L6-v2) | Vector search for RAG (Pinecone) |

> This project uses a hybrid architecture: **foundation models** (Gemini) handle reasoning and report generation via multi-agent orchestration, while **custom ML models** handle specialized classification tasks requiring deterministic, low-latency inference. The notebook above documents all custom-trained model components.

---

## Team

- Vu Truong Giang — Team Leader
- Nguyen Ngoc Sang — Team Member
- Le Ngoc Hai — Team Member
- Bui Hoang Viet — Team Member
- Dinh Thanh Tung — Team Member
