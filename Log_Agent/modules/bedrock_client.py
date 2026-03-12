import boto3
import json
from typing import List, Dict

class BedrockAnalyzer:
    def __init__(self):
        # boto3 will automatically pick up credentials from environment variables 
        # (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION)
        self.bedrock_runtime = boto3.client('bedrock-runtime')
        # We'll use Claude 3 Haiku for fast, cost-effective reasoning. 
        self.model_id = "anthropic.claude-3-haiku-20240307-v1:0"

    def analyze_logs(self, logs: List[Dict]) -> str:
        """
        Sends the filtered logs to Amazon Bedrock with a Chain-of-Thought prompt.
        """
        if not logs:
            return "No logs provided for analysis."

        logs_str = json.dumps(logs, indent=2)

        prompt = f"""You are a cloud security expert. Review the following AWS CloudTrail logs which have been filtered for 'AccessDenied' errors.

<logs>
{logs_str}
</logs>

Please analyze these logs step-by-step to understand the security incidents. Use the following Chain-of-Thought process:
1. Identify the principal (who) attempted the action.
2. Identify the action (what) they tried to perform.
3. Identify the resource or service (where) they tried to perform it.
4. Conclude why they might have been denied and what the potential security implication is.
5. Suggest a remediation step.

Provide your final analysis in a clear, structured format.
"""

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": prompt
                        }
                    ]
                }
            ]
        }

        try:
            response = self.bedrock_runtime.invoke_model(
                body=json.dumps(body),
                modelId=self.model_id,
                accept="application/json",
                contentType="application/json"
            )
            response_body = json.loads(response.get('body').read())
            return response_body.get('content')[0].get('text')
        except Exception as e:
            return f"Error invoking Bedrock model: {e}"
