# Architecture Design: BASTION

This document provides a deep technical dive into the architecture, component design, and state management of the BASTION Autonomous SOC platform. It complements the `README.md` by explaining the "How" and "Why" behind the engineering decisions.

---

## 1. System Architecture (Cloud & Local Modality)

BASTION is designed with a **Decoupled Architecture**, allowing the core AI reasoning engine to be tested locally via an API emulator or deployed natively to an AWS Serverless environment.

### 1.1 Production Cloud Architecture (Target State)
The production deployment utilizes AWS Serverless components to ensure infinite scalability and zero idle costs:
1. **Amazon S3 / EventBridge:** Raw security logs and suspicious `.eml` files are dropped into an S3 bucket. This triggers an EventBridge notification.
2. **Lambda Tier 1 (Edge Filter):** A lightweight, fast-executing AWS Lambda function that parses the event, strips out PII (Regex/Anonymization), and applies a static heuristic filter.
3. **Amazon SQS:** Events that survive Tier 1 are pushed to a message queue, acting as a buffer to prevent API rate-limit exhaustion during DDoS or high-volume log bursts.
4. **Lambda Tier 2 (LangGraph Core):** Reads from SQS and instantiates the multi-agent AI State Machine.
5. **AWS Athena & Pinecone:** Memory retrieval layers used by the AI during investigation.
6. **Amazon DynamoDB:** Final structured JSON reports are saved here for dashboard consumption.

### 1.2 Local Emulator Architecture (Demo Mode)
To eliminate cloud deployment latency and network risks during demonstrations, the infrastructure is simulated locally:
- **FastAPI Server (`api_server.py`)** replaces EventBridge and SQS. It accepts file uploads via HTTP POST.
- The **Tier 1 PII Scrubber** is invoked synchronously.
- **LangGraph** execution is streamed in real-time via `BackgroundTasks` to a React UI (Vite) for high-observability visualization.
- **Data Persistence** remains live: The system still queries the actual AWS Athena staging data and saves the final result to the actual AWS DynamoDB instance.

---

## 2. Multi-Agent Orchestration (LangGraph)

BASTION moves beyond standard Retrieval-Augmented Generation (RAG) by employing a **Routing State Machine**. The core object passed between nodes is the `State` dict, ensuring execution history and intermediate findings are immutable and fully traceable.

### 2.1 The Supervisor (Orchestrator Node)
The Supervisor does not analyze data. Its sole purpose is **Decision Making**.
- **Input:** Current state (Event payload, List of findings, Iteration count).
- **Rule-Based Preemption:** To prevent LLM hallucination, hard-rules are evaluated first (e.g., if `event_type == 'email'`, it MUST route to `Email Analyst` on iteration 0).
- **LLM Routing:** Post-iteration 0, the Supervisor uses Google Gemini 2.5 to evaluate findings and decide the `next_agent`.
- **Termination:** Once satisfied or if `MAX_ITERATIONS` is reached, it routes to the `SYNTHESIZE` node.

### 2.2 Specialized Agents
1. **Email Analyst:** 
   - Uses `mail_parser_tool` and `extract_urls_tool`.
   - Focus: Extracts sender headers, DKIM/SPF statuses, and malicious phishing links.
2. **Threat Intel:** 
   - Uses `virustotal_api` and `alienvault_otx`.
   - Focus: Correlates extracted IPs/Domains against global malware databases.
3. **Forensic Analyst (The Hunter):** 
   - Uses `cloudtrail_query_tool`.
   - Focus: A unique agent that writes native Presto/SQL statements to query AWS Athena. It cross-references suspicious IPs against historical internal cloud activity (e.g., detecting `AssumeRole` or `ConsoleLogin` after a phishing click).

---

## 3. Data Strategy & Privacy

A critical component of enterprise security tools is their handling of sensitive data.

### 3.1 PII Scrubbing (Privacy-by-Design)
Before any data payload touches a third-party LLM (OpenAI/Gemini), it passes through `bastion.services.pii_scrubber`.
- Converts IP addresses to `[REDACTED_IP]`.
- Hashes or censors email addresses and Social Security Numbers.
- **Impact:** Ensures the organization remains compliant with GDPR/PCI-DSS standards while still allowing the AI to understand the structural context of the breach.

### 3.2 Data Lakehouse Tiering (Cost Optimization)
Querying millions of logs via Elasticsearch or Pinecone is cost-prohibitive.
- **Cold Storage:** The raw `.csv` and CloudTrail `.json` massive datasets reside in S3.
- **On-Demand Compute:** The `Forensic Analyst` agent only spins up an AWS Athena engine when hard evidence is needed. This costs pennies per query compared to thousands of dollars per month for always-on indexing clusters.
- **Hot Output:** Only the highly refined, synthesized output is stored in **DynamoDB**.

---

## 4. Threat Detection Lifecycle (Step-by-Step)

An example trace of how the state machine revolves during a phishing attack resolution:

1. **Trigger:** `POST /upload` (Payload: `.eml`).
2. **Tier 1:** Payload scrubbed. Event mapped to state. `iteration = 0`.
3. **Supervisor:** Detects payload is `email`. Bypasses LLM reasoning and forces route -> `DELEGATE_EMAIL`.
4. **Email Analyst:** LLM reads payload via tools. Extracts Domain `evil-phish.biz` and IP `192.168.1.100`. Returns array of `IOCs`. `iteration = 1`.
5. **Supervisor:** Reads new State. Sees 2 IOCs. Routes -> `DELEGATE_THREAT`.
6. **Threat Intel:** Queries VirusTotal. Finds `evil-phish.biz` has 15/90 malicious hits. `iteration = 2`.
7. **Supervisor:** Sees confirmed threat. Needs internal context. Routes -> `DELEGATE_FORENSIC`.
8. **Forensic Analyst:** Writes SQL: `SELECT eventname FROM cloudtrail_logs WHERE sourceipaddress = '192.168.1.100'`. Athena returns `ConsoleLogin (Success)`. `iteration = 3`.
9. **Supervisor:** Sees High Severity (Phishing IP successfully logged in). Routes -> `SYNTHESIZE`.
10. **Synthesizer:** Drafts final JSON report, marks `risk_score = 9.5`, generates mitigation steps. Saves to DynamoDB. Exits Graph.

---

## 5. Extensibility & Future Scaling

- **Adding New Agents:** Simply write a new Node class in `bastion/agents/` and register it in `workflow.py`. Add the node name to the Supervisor's system prompt list of acceptable return strings.
- **Replacing LLMs:** The system uses `BaseChatModel` from LangChain. Switching from Google Gemini to local Llama3 or Anthropic GPT-4o requires changing exactly one line of code in `bastion/config.py`.
- **Sigma Rules Integration:** Future updates will enable the `Forensic` agent or a dedicated `Detection Engineer` agent to automatically write `.yml` Sigma rules based on the synthesized attack vector, allowing immediate back-porting of defenses to the legacy SIEM.
