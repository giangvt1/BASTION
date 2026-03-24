import sys
import csv
import io
import json
from pathlib import Path
from fastapi import FastAPI, BackgroundTasks, UploadFile, File, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import uuid
from typing import Dict, Any

# Ensure the bastion package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bastion.config import config
from bastion.logger import configure_logging, get_logger
from bastion.services.pii_scrubber import scrub_event_payload
from run_local import load_email_event, load_forensic_event
from bastion.graph.workflow import build_graph

configure_logging(env=config.environment, log_level=config.log_level)
logger = get_logger(__name__)

# Suppress noisy python-multipart debug logging
import logging
logging.getLogger("multipart.multipart").setLevel(logging.WARNING)

app = FastAPI(title="BASTION Local API")

# Enable CORS for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for local testing instead of DynamoDB
reports_db: Dict[str, Any] = {}

# Initialize Graph
graph = build_graph()

def run_agent_task(report_id: str, event_type: str):
    try:
        event = load_email_event() if event_type == "email" else load_forensic_event()
        
        initial_state = {
            "event_payload": scrub_event_payload(event),
            "event_type": event.get("event_type", "unknown"),
            "messages": [],
            "next_agent": "",
            "findings": [],
            "iocs": [],
            "iteration_count": 0,
            "error_logs": [],
            "pipeline_logs": [{"node": "eventbridge", "action": "Event ingested", "detail": f"New {event.get('event_type', 'unknown')} event received via EventBridge", "ts": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}],
            "risk_score": 0.0,
            "final_report": "",
            "report_id": report_id,
        }
        
        logger.info(f"Running graph for report {report_id}")
        for current_state in graph.stream(initial_state, stream_mode="values"):
            safe_state = dict(current_state)
            if "messages" in safe_state:
                safe_state["messages"] = [{"role": getattr(m, "type", "unknown"), "content": getattr(m, "content", str(m))} for m in safe_state["messages"]]
            safe_state["status"] = "running"
            safe_state["report_id"] = report_id
            reports_db[report_id] = safe_state
            
        reports_db[report_id]["status"] = "completed"
        
        # Save final completed report to DynamoDB
        try:
            from bastion.services.dynamodb import save_report
            save_report(report_id, reports_db[report_id])
            logger.info("Saved final report to DynamoDB", report_id=report_id)
        except Exception as err:
            logger.error("Failed to save report to DynamoDB", report_id=report_id, error=str(err))

        logger.info(f"Finished graph for report {report_id}")
    except Exception as e:
        logger.exception("Graph execution failed")
        reports_db[report_id] = {"error": str(e), "status": "failed"}

@app.get("/reports")
async def get_reports():
    return {"reports": list(reports_db.values()), "count": len(reports_db)}

@app.get("/reports/{report_id}")
async def get_report(report_id: str):
    if report_id in reports_db:
        return reports_db[report_id]
    return {"error": "Report not found"}

@app.post("/trigger/{event_type}")
async def trigger_analysis(event_type: str, background_tasks: BackgroundTasks):
    if event_type not in ["email", "cloudtrail"]:
        return {"error": "Invalid event type. Use 'email' or 'cloudtrail'."}
        
    report_id = f"LOCAL-{str(uuid.uuid4())[:8].upper()}"
    # Seed the report DB to show it's running
    reports_db[report_id] = {
        "report_id": report_id,
        "event_type": event_type,
        "status": "running",
        "findings": [],
        "iocs": [],
        "error_logs": [],
        "pipeline_logs": [],
        "messages": [],
        "iteration_count": 0,
        "risk_score": 0.0,
        "final_report": ""
    }
    
    background_tasks.add_task(run_agent_task, report_id, event_type)
    return {"message": "Analysis triggered", "report_id": report_id}

def run_upload_task(report_id: str, event: dict):
    """Run the graph with a user-uploaded event."""
    try:
        initial_state = {
            "event_payload": scrub_event_payload(event),
            "event_type": event.get("event_type", "unknown"),
            "messages": [],
            "next_agent": "",
            "findings": [],
            "iocs": [],
            "iteration_count": 0,
            "error_logs": [],
            "pipeline_logs": [{"node": "eventbridge", "action": "File uploaded", "detail": f"Incident response file uploaded for {event.get('event_type', 'unknown')} analysis", "ts": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}],
            "risk_score": 0.0,
            "final_report": "",
            "report_id": report_id,
        }
        logger.info(f"Running graph for uploaded report {report_id}")
        for current_state in graph.stream(initial_state, stream_mode="values"):
            safe_state = dict(current_state)
            if "messages" in safe_state:
                safe_state["messages"] = [{"role": getattr(m, "type", "unknown"), "content": getattr(m, "content", str(m))} for m in safe_state["messages"]]
            safe_state["status"] = "running"
            safe_state["report_id"] = report_id
            reports_db[report_id] = safe_state
        reports_db[report_id]["status"] = "completed"

        # Save final completed report to DynamoDB
        try:
            from bastion.services.dynamodb import save_report
            save_report(report_id, reports_db[report_id])
            logger.info("Saved final uploaded report to DynamoDB", report_id=report_id)
        except Exception as err:
            logger.error("Failed to save uploaded report to DynamoDB", report_id=report_id, error=str(err))

        logger.info(f"Finished graph for uploaded report {report_id}")
    except Exception as e:
        logger.exception("Upload graph execution failed")
        reports_db[report_id] = {"error": str(e), "status": "failed"}

@app.post("/upload")
async def upload_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Upload a .eml, .json, or .csv file for Incident Response analysis."""
    filename = file.filename or "unknown"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    content = await file.read()
    text = content.decode("utf-8", errors="replace")

    if ext == "eml" or ext == "txt":
        event = {
            "event_type": "email",
            "source": "manual_upload",
            "detail": {"raw_eml": text, "s3_key": f"uploads/{filename}"},
        }
    elif ext == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON file"}

        # ── Detect correlated multi-source format (a.json style) ────────
        # Structure: [ { task_id, correlation_key, context_payload: { email_event, aws_network_events } }, ... ]
        # Also support single-object format: { task_id, context_payload: { ... } }
        if isinstance(data, dict) and "context_payload" in data:
            data = [data]  # Normalize single task to list
        if isinstance(data, list) and len(data) > 0 and "context_payload" in data[0]:
            # Build events for all tasks
            all_task_events = []
            for task in data:
                task_id = task.get("task_id", f"task-{uuid.uuid4().hex[:6]}")
                payload = task.get("context_payload", {})
                corr_ip = task.get("correlation_key", {}).get("ip_address", "")

                email_evt = payload.get("email_event", {})
                network_evts = payload.get("aws_network_events", [])

                # Build a raw_eml string from the email_event dict
                raw_eml_lines = []
                if email_evt:
                    raw_eml_lines.append(f"From: {email_evt.get('Sender', 'unknown')}")
                    raw_eml_lines.append(f"Return-Path: {email_evt.get('Return-Path', '')}")
                    raw_eml_lines.append(f"Subject: {email_evt.get('Subject', '')}")
                    raw_eml_lines.append(f"Date: {email_evt.get('Date', '')}")
                    if email_evt.get("X-Originating-IP"):
                        raw_eml_lines.append(f"X-Originating-IP: {email_evt['X-Originating-IP']}")
                    raw_eml_lines.append("")
                    raw_eml_lines.append(email_evt.get("Body", ""))
                raw_eml = "\n".join(raw_eml_lines)

                evt = {
                    "event_type": "email",
                    "source": "correlated_upload",
                    "detail": {
                        "raw_eml": raw_eml,
                        "s3_key": f"uploads/{filename}/{task_id}",
                        "correlation_ip": corr_ip,
                        "aws_network_events": network_evts,
                    },
                }
                all_task_events.append((task_id, evt))

            # Only run the FIRST task immediately so the frontend gets a single report_id to track
            first_task_id, first_event = all_task_events[0]
            primary_rid = f"IR-{str(uuid.uuid4())[:8].upper()}"
            reports_db[primary_rid] = {
                "report_id": primary_rid,
                "task_id": first_task_id,
                "event_type": first_event["event_type"],
                "status": "running",
                "findings": [], "iocs": [], "error_logs": [], "messages": [],
                "iteration_count": 0, "risk_score": 0.0, "final_report": "",
                "pipeline_logs": [{"node": "eventbridge", "action": f"Correlated batch: {len(all_task_events)} tasks", "detail": f"Processing task 1/{len(all_task_events)}: {first_task_id}", "ts": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}],
            }

            # Queue remaining tasks to run SEQUENTIALLY after primary completes
            def run_correlated_batch(primary_id, primary_evt, remaining):
                """Run primary task first, then remaining tasks one-by-one."""
                import time
                run_upload_task(primary_id, primary_evt)
                for tid, evt in remaining:
                    rid = f"IR-{str(uuid.uuid4())[:8].upper()}"
                    reports_db[rid] = {
                        "report_id": rid, "task_id": tid,
                        "event_type": evt["event_type"], "status": "running",
                        "findings": [], "iocs": [], "error_logs": [], "messages": [],
                        "iteration_count": 0, "risk_score": 0.0, "final_report": "",
                        "pipeline_logs": [],
                    }
                    run_upload_task(rid, evt)

            background_tasks.add_task(
                run_correlated_batch,
                primary_rid, first_event, all_task_events[1:]
            )

            return {
                "message": f"Correlated Incident Response triggered for {len(data)} tasks from {filename}",
                "report_id": primary_rid,
                "event_type": "email",
                "task_count": len(data),
            }

        # ── Fallback: treat as generic CloudTrail JSON ─────────────────
        event = {
            "event_type": "cloudtrail",
            "source": "manual_upload",
            "detail": data,
        }
    elif ext == "csv":
        import sys
        try:
            csv.field_size_limit(sys.maxsize)
        except OverflowError:
            csv.field_size_limit(2147483647)  # Fallback for Windows where maxsize might be too large for C long
            
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        if not rows:
            return {"error": "CSV file is empty"}
            
        first_row = {k: (str(v) if v else "") for k, v in rows[0].items()}
        # Detect if this is an email CSV or log CSV
        if any(k in first_row for k in ["sender", "body", "subject"]):
            raw_eml = f"From: {first_row.get('sender', 'unknown')}\nTo: {first_row.get('receiver', 'unknown')}\nSubject: {first_row.get('subject', '')}\n\n{first_row.get('body', '')}"
            event = {
                "event_type": "email",
                "source": "manual_upload",
                "detail": {"raw_eml": raw_eml, "s3_key": f"uploads/{filename}"},
            }
        else:
            # It's a log CSV. Process up to 100 rows to prevent LLM context limits
            limit = 100
            records = []
            for row in rows[:limit]:
                records.append({k: (str(v) if v else "") for k, v in row.items()})
                
            event_type = "cloudtrail" if any(k in first_row for k in ["awsRegion", "eventName", "eventSource"]) else "syslog"
            event = {
                "event_type": event_type,
                "source": "manual_upload",
                "detail": records if len(records) > 1 else records[0],
            }
    else:
        return {"error": f"Unsupported file type: .{ext}. Use .eml, .json, or .csv"}

    report_id = f"IR-{str(uuid.uuid4())[:8].upper()}"
    reports_db[report_id] = {
        "report_id": report_id,
        "event_type": event["event_type"],
        "status": "running",
        "findings": [], "iocs": [], "error_logs": [], "messages": [],
        "iteration_count": 0, "risk_score": 0.0, "final_report": "",
    }
    background_tasks.add_task(run_upload_task, report_id, event)
    return {"message": f"Incident Response triggered for {filename}", "report_id": report_id, "event_type": event["event_type"]}

@app.get("/stats")
async def get_stats():
    reports = list(reports_db.values())
    total = len(reports)
    all_findings = []
    all_iocs = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    agent_counts = {"email_analyst": 0, "forensic_analyst": 0, "threat_intel": 0}
    event_counts = {"email": 0, "cloudtrail": 0}
    mitre_counts = {}
    risk_scores = []

    for r in reports:
        findings = r.get("findings", [])
        all_findings.extend(findings)
        all_iocs.extend(r.get("iocs", []))
        event_counts[r.get("event_type", "email")] = event_counts.get(r.get("event_type", "email"), 0) + 1
        rs = r.get("risk_score", 0)
        if rs:
            risk_scores.append(float(rs))
        for f in findings:
            sev = str(f.get("severity", "low")).lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            agent = str(f.get("agent", ""))
            for key in agent_counts:
                if key in agent:
                    agent_counts[key] += 1
                    
            mitre = f.get("mitre_tactic", "")
            if mitre:
                for tactic in mitre.split(","):
                    t = tactic.strip()
                    if t and t != "N/A":
                        mitre_counts[t] = mitre_counts.get(t, 0) + 1

    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

    # Risk score histogram buckets: 0-20, 20-40, 40-60, 60-80, 80-100
    histogram = [0, 0, 0, 0, 0]
    for s in risk_scores:
        pct = s * 100 if s <= 1 else s
        idx = min(int(pct // 20), 4)
        histogram[idx] += 1

    recent = []
    for r in list(reports)[-10:]:
        recent.append({
            "report_id": r.get("report_id", ""),
            "status": r.get("status", ""),
            "event_type": r.get("event_type", ""),
            "risk_score": r.get("risk_score", 0),
            "finding_count": len(r.get("findings", [])),
        })

    return {
        "total_reports": total,
        "completed_reports": len([r for r in reports if r.get("status") == "completed"]),
        "failed_reports": len([r for r in reports if r.get("status") == "failed"]),
        "total_findings": len(all_findings),
        "total_iocs": len(all_iocs),
        "avg_risk_score": round(avg_risk, 4),
        "severity_breakdown": severity_counts,
        "agent_usage": agent_counts,
        "event_type_breakdown": event_counts,
        "mitre_tactics": mitre_counts,
        "risk_histogram": histogram,
        "recent_reports": recent,
    }

class FeedbackRequest(BaseModel):
    feedback_type: str
    notes: str = ""

@app.post("/reports/{report_id}/feedback")
async def submit_feedback(report_id: str, request: FeedbackRequest):
    """Analyst Feedback Loop for RLHF"""
    if report_id not in reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
        
    report = reports_db[report_id]
    report["analyst_feedback"] = {
        "type": request.feedback_type,
        "notes": request.notes,
        "timestamp": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()
    }
    report["rlhf_ready"] = True
    
    try:
        from bastion.services.dynamodb import save_report
        save_report(report_id, report)
    except Exception as e:
        logger.error(f"Failed to save feedback to DB: {e}")
        
    return {"message": f"Feedback '{request.feedback_type}' recorded successfully for API routing RLHF.", "status": "success"}

@app.post("/reports/{report_id}/push-sigma")
async def push_sigma(report_id: str):
    """Auto-push Sigma rules to SIEM"""
    if report_id not in reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report = reports_db[report_id]
    final_report = report.get("final_report", "")
    
    import re
    match = re.search(r"```yaml\s*\n(.*?)\n```", final_report, re.DOTALL)
    sigma_rule = match.group(1) if match else None
    
    if not sigma_rule:
        return {"message": "No Sigma Rule found in report to push.", "status": "skipped"}
        
    logger.info(f"Pushing Sigma rule to Enterprise SIEM for {report_id}")
    import asyncio
    await asyncio.sleep(1.5) # Simulate API latency
    
    report["sigma_pushed"] = True
    
    try:
        from bastion.services.dynamodb import save_report
        save_report(report_id, report)
    except Exception as e:
        logger.error(f"Failed to save sigma_pushed to DB: {e}")
        
    return {"message": "Sigma Rule successfully synced and active in SIEM.", "status": "success"}

if __name__ == "__main__":
    print("Starting BASTION Local API on port 8001...")
    uvicorn.run(app, host="127.0.0.1", port=8001)
