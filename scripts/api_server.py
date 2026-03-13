import sys
from pathlib import Path
from fastapi import FastAPI, BackgroundTasks
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
        "messages": [],
        "iteration_count": 0,
        "risk_score": 0.0,
        "final_report": ""
    }
    
    background_tasks.add_task(run_agent_task, report_id, event_type)
    return {"message": "Analysis triggered", "report_id": report_id}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
