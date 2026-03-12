import os
from dotenv import load_dotenv
from modules.log_parser import parse_cloudtrail_logs
from modules.bedrock_client import BedrockAnalyzer
from modules.gemini_client import GeminiAnalyzer

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # We expect the user to have copied .env.example to .env and filled it out
    if not os.getenv("AWS_ACCESS_KEY_ID") or not os.getenv("AWS_SECRET_ACCESS_KEY"):
        print("Warning: AWS credentials not found in environment variables.")
        print("Make sure you have created a '.env' file based on '.env.example' with your AWS keys.")
        print("Proceeding anyway, as boto3 might find credentials in ~/.aws/credentials...\n")
    
    log_file_path = "CloudTRail.json"
    print(f"Parsing logs from {log_file_path} for 'AccessDenied' errors...")
    
    # 1. Parse Logs
    access_denied_logs = parse_cloudtrail_logs(log_file_path, "AccessDenied")
    
    if not access_denied_logs:
        print("No 'AccessDenied' logs found.")
        return
        
    print(f"Found {len(access_denied_logs)} 'AccessDenied' log(s). Sending to Amazon Bedrock for analysis...\n")
    
    # 2. Analyze with Bedrock
    analyzer = BedrockAnalyzer()
    analysis_result = analyzer.analyze_logs(access_denied_logs)
    
    # 3. Fallback to Gemini if Bedrock fails
    if analysis_result.startswith("Error invoking Bedrock model") or "AccessDeniedException" in analysis_result:
        print("Bedrock invocation failed or returned an error. Falling back to Gemini 2.5 Flash...\n")
        gemini_analyzer = GeminiAnalyzer()
        analysis_result = gemini_analyzer.analyze_logs(access_denied_logs)
    
    # 4. Print Result
    print("="*50)
    print("AI Analysis Result (Chain-of-Thought):")
    print("="*50)
    print(analysis_result)
    print("="*50)

if __name__ == "__main__":
    main()
