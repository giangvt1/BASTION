import os
import json
from typing import List, Dict
from google import genai

class GeminiAnalyzer:
    def __init__(self):
        # The SDK will automatically pick up GEMINI_API_KEY from the environment
        self.api_key = os.getenv("GEMINI_API_KEY")
        if self.api_key:
            self.client = genai.Client()
        else:
            self.client = None
            
        self.model_id = "gemini-2.5-flash"

    def analyze_logs(self, logs: List[Dict]) -> str:
        """
        Sends the filtered logs to Gemini with a Chain-of-Thought prompt.
        """
        if not self.client:
            return "Error: GEMINI_API_KEY not found in environment variables."
            
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

        try:
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"Error invoking Gemini model: {e}"
