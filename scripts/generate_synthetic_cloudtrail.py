#!/usr/bin/env python3
"""
Generate synthetic CloudTrail logs for LSTM UBA training.

Creates realistic CloudTrail event sequences with normal user behavior patterns
and optional anomalies for testing.

Usage:
    python scripts/generate_synthetic_cloudtrail.py --output synthetic_logs.json --events 5000
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path


def generate_normal_user_behavior(
    user: str,
    start_time: datetime,
    num_events: int = 100,
) -> list[dict]:
    """Generate normal CloudTrail events for a user."""
    
    # Normal user behavior patterns
    normal_apis = [
        "DescribeInstances",
        "ListBuckets",
        "GetObject",
        "PutObject",
        "DescribeSecurityGroups",
        "ListUsers",
        "GetBucketAcl",
        "DescribeVolumes",
        "DescribeSnapshots",
        "ListAccessKeys",
    ]
    
    # User typically works during business hours (9am-5pm)
    work_hours = list(range(9, 17))
    
    events = []
    current_time = start_time
    
    for i in range(num_events):
        # Advance time by 1-30 minutes
        current_time += timedelta(minutes=random.randint(1, 30))
        
        # Adjust to work hours (80% of the time)
        if random.random() < 0.8:
            current_time = current_time.replace(hour=random.choice(work_hours))
        
        event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(1000000000, 9999999999)}",
                "arn": f"arn:aws:iam::123456789012:user/{user}",
                "accountId": "123456789012",
                "userName": user,
            },
            "eventTime": current_time.isoformat() + "Z",
            "eventSource": random.choice(["ec2.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com"]),
            "eventName": random.choice(normal_apis),
            "awsRegion": "us-east-1",
            "sourceIPAddress": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
            "requestParameters": {},
            "responseElements": None,
            "requestID": f"{random.randint(10**15, 10**16-1):016x}",
            "eventID": f"{random.randint(10**31, 10**32-1):032x}",
            "readOnly": True,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
        }
        
        events.append(event)
    
    return events


def generate_anomalous_behavior(
    user: str,
    start_time: datetime,
    anomaly_type: str = "privilege_escalation",
) -> list[dict]:
    """Generate anomalous CloudTrail events."""
    
    anomaly_patterns = {
        "privilege_escalation": [
            "CreateUser",
            "CreateAccessKey",
            "AttachUserPolicy",
            "PutUserPolicy",
            "CreateLoginProfile",
        ],
        "data_exfiltration": [
            "GetObject",
            "GetObject",
            "GetObject",
            "ListBuckets",
            "GetBucketAcl",
            "GetObject",
            "GetObject",
        ],
        "reconnaissance": [
            "ListBuckets",
            "ListUsers",
            "ListRoles",
            "ListAccessKeys",
            "DescribeInstances",
            "DescribeSecurityGroups",
            "GetAccountAuthorizationDetails",
        ],
        "defense_evasion": [
            "StopLogging",
            "DeleteTrail",
            "PutEventSelectors",
            "UpdateTrail",
        ],
    }
    
    apis = anomaly_patterns.get(anomaly_type, anomaly_patterns["privilege_escalation"])
    
    events = []
    current_time = start_time
    
    # Anomalies often happen outside business hours
    current_time = current_time.replace(hour=random.choice([2, 3, 4, 22, 23]))
    
    # Suspicious IP (external)
    suspicious_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    for api in apis:
        # Rapid succession (1-5 minutes apart)
        current_time += timedelta(minutes=random.randint(1, 5))
        
        event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDA{random.randint(1000000000, 9999999999)}",
                "arn": f"arn:aws:iam::123456789012:user/{user}",
                "accountId": "123456789012",
                "userName": user,
            },
            "eventTime": current_time.isoformat() + "Z",
            "eventSource": random.choice(["iam.amazonaws.com", "cloudtrail.amazonaws.com", "s3.amazonaws.com"]),
            "eventName": api,
            "awsRegion": "us-east-1",
            "sourceIPAddress": suspicious_ip,
            "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
            "requestParameters": {},
            "responseElements": None,
            "requestID": f"{random.randint(10**15, 10**16-1):016x}",
            "eventID": f"{random.randint(10**31, 10**32-1):032x}",
            "readOnly": False,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
        }
        
        # Some events may fail (AccessDenied)
        if random.random() < 0.3:
            event["errorCode"] = "AccessDenied"
            event["errorMessage"] = "User is not authorized to perform this operation"
        
        events.append(event)
    
    return events


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic CloudTrail logs for LSTM UBA training"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("synthetic_cloudtrail_logs.json"),
        help="Output JSON file path",
    )
    parser.add_argument(
        "--events",
        type=int,
        default=5000,
        help="Total number of events to generate",
    )
    parser.add_argument(
        "--users",
        type=int,
        default=10,
        help="Number of unique users",
    )
    parser.add_argument(
        "--anomaly-ratio",
        type=float,
        default=0.05,
        help="Ratio of anomalous events (0.0-1.0)",
    )
    
    args = parser.parse_args()
    
    print(f"Generating {args.events} CloudTrail events...")
    print(f"Users: {args.users}")
    print(f"Anomaly ratio: {args.anomaly_ratio:.1%}")
    
    all_events = []
    start_time = datetime.now() - timedelta(days=30)
    
    # Generate events per user
    events_per_user = args.events // args.users
    anomalous_events_per_user = int(events_per_user * args.anomaly_ratio)
    normal_events_per_user = events_per_user - anomalous_events_per_user
    
    for i in range(args.users):
        user = f"user{i+1:02d}"
        
        # Generate normal behavior
        normal_events = generate_normal_user_behavior(
            user,
            start_time + timedelta(days=i),
            normal_events_per_user,
        )
        all_events.extend(normal_events)
        
        # Generate anomalous behavior (for some users)
        if anomalous_events_per_user > 0:
            anomaly_type = random.choice([
                "privilege_escalation",
                "data_exfiltration",
                "reconnaissance",
                "defense_evasion",
            ])
            anomalous_events = generate_anomalous_behavior(
                user,
                start_time + timedelta(days=i + 15),
                anomaly_type,
            )
            all_events.extend(anomalous_events[:anomalous_events_per_user])
    
    # Sort by time
    all_events.sort(key=lambda e: e["eventTime"])
    
    # Save to file
    output_data = {"Records": all_events}
    
    with open(args.output, "w") as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n✓ Generated {len(all_events)} events")
    print(f"✓ Saved to: {args.output}")
    print(f"✓ File size: {args.output.stat().st_size / 1024:.1f} KB")
    
    # Statistics
    normal_count = len([e for e in all_events if "errorCode" not in e])
    anomalous_count = len(all_events) - normal_count
    
    print(f"\nStatistics:")
    print(f"  Normal events: {normal_count} ({normal_count/len(all_events):.1%})")
    print(f"  Anomalous events: {anomalous_count} ({anomalous_count/len(all_events):.1%})")
    
    print(f"\nTo train LSTM UBA model:")
    print(f"  python scripts/train_lstm_uba.py --data {args.output} --epochs 50")


if __name__ == "__main__":
    main()
