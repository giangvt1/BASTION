import sys
import pandas as pd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_local import run_full_pipeline

def clean_record(d):
    """Sanitize pandas NaNs and cast all values to strings for downstream compatibility."""
    return {k: ("" if pd.isna(v) else str(v)) for k, v in d.items()}

def evaluate_mail():
    print("\n\n############################################################")
    print("   EVALUATING 1 EMAIL FROM THE NIGERIAN FRAUD DATASET")
    print("############################################################\n")
    df = pd.read_csv("dataset/mail/Nigerian_Fraud.csv", nrows=1, encoding="utf-8")
    record = clean_record(df.iloc[0].to_dict())
    
    # Rebuild raw EML from columns sender, receiver, subject, body
    raw_eml = f"From: {record.get('sender', 'unknown')}\nTo: {record.get('receiver', 'unknown')}\nSubject: {record.get('subject', 'unknown')}\n\n{record.get('body', '')}"
    
    event = {
        "event_type": "email",
        "source": "aws.s3",
        "detail": {
            "raw_eml": raw_eml,
            "s3_key": "emails/dataset_fraud_sample.eml"
        }
    }
    run_full_pipeline(event)

def evaluate_logs():
    print("\n\n############################################################")
    print("   EVALUATING 1 CLOUDTRAIL EVENT FROM THE LOGS DATASET")
    print("############################################################\n")
    # Using 18 features log dataset
    df = pd.read_csv("dataset/logs/dec12_18features.csv", nrows=1, encoding="utf-8")
    record = clean_record(df.iloc[0].to_dict())
    
    # Convert specific columns to native dict structure CloudTrail expects if possible,
    # or just supply raw columns. forensic_analyst is LLM so it will understand standard JSON.
    event = {
        "event_type": "cloudtrail",
        "source": "aws.cloudtrail",
        "detail": record
    }
    run_full_pipeline(event)

if __name__ == "__main__":
    evaluate_mail()
    evaluate_logs()
