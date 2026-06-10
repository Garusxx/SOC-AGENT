import json
import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def analyze_log_with_ai(log_text: str, source: str = "manual") -> dict:
    if not log_text or not log_text.strip():
        return {
            "severity": "Low",
            "mitre": "Unknown",
            "classification": "Empty Input",
            "summary": "No log content was provided.",
            "indicators": [],
            "recommendations": ["Provide a valid log or alert for analysis."],
            "raw_log_explanation": "The input was empty.",
            "source": source,
            "received_chars": 0,
        }

    prompt = f"""
You are a SOC Tier 2 cybersecurity analyst.

Analyze the following security log or alert.

Rules:
- Do not invent facts.
- If evidence is weak, say so.
- Map activity to MITRE ATT&CK when possible.
- Return practical SOC recommendations.
- Explain what the raw log means in simple terms.

LOG SOURCE:
{source}

LOG:
{log_text[:12000]}
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
        text={
            "format": {
                "type": "json_schema",
                "name": "soc_log_analysis",
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "severity": {
                            "type": "string",
                            "enum": ["Low", "Medium", "High", "Critical"],
                        },
                        "mitre": {"type": "string"},
                        "classification": {"type": "string"},
                        "summary": {"type": "string"},
                        "indicators": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "recommendations": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "raw_log_explanation": {"type": "string"},
                    },
                    "required": [
                        "severity",
                        "mitre",
                        "classification",
                        "summary",
                        "indicators",
                        "recommendations",
                        "raw_log_explanation",
                    ],
                },
                "strict": True,
            }
        },
    )

    result = json.loads(response.output_text)
    result["source"] = source
    result["received_chars"] = len(log_text)

    return result