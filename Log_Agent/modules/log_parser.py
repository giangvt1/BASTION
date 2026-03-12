import json

def parse_cloudtrail_logs(file_path: str, target_error_code: str = "AccessDenied"):
    """
    Reads a CloudTrail logs JSON file and filters records by errorCode.
    """
    filtered_records = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            records = data.get("Records", [])
            for record in records:
                if record.get("errorCode") == target_error_code:
                    filtered_records.append(record)
    except Exception as e:
        print(f"Error parsing log file: {e}")
    
    return filtered_records
