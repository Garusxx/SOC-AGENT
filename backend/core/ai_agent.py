import json
import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = None

api_key = os.getenv("OPENAI_API_KEY")

if api_key:
    client = OpenAI(api_key=api_key)


def analyze_log_with_ai(
    log_text: str,
    source: str = "manual",
    log_type: str = "generic",
    risk_score: int = 0,
    parser_indicators: list[str] | None = None,
) -> dict:
    if parser_indicators is None:
        parser_indicators = []

    if client is None:
        return {
            "severity": "Low",
            "mitre": "N/A",
            "classification": "AI Disabled",
            "summary": "OPENAI_API_KEY is not configured",
            "indicators": [],
            "recommendations": ["Configure OPENAI_API_KEY"],
            "raw_log_explanation": "AI backend unavailable",
            "source": source,
            "received_chars": len(log_text),
        }

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

    suggested_severity = "Low"

    if risk_score >= 90:
        suggested_severity = "Critical"
    elif risk_score >= 60:
        suggested_severity = "High"
    elif risk_score >= 30:
        suggested_severity = "Medium"

    prompt = f"""
You are a SOC Tier 2 cybersecurity analyst.

Analyze the following security log or alert.

Rules:
- Do not invent facts.
- If evidence is weak, say so.
- Map activity to MITRE ATT&CK when possible.
- Return practical SOC recommendations.
- Explain what the raw log means in simple terms.
- Consider the parser risk score and detected indicators, but do not blindly trust them.
- If PowerShell uses EncodedCommand or ExecutionPolicy Bypass, severity should usually be High unless strong benign context is present.
- If LSASS access, Mimikatz, credential dumping tools, or ProcDump are present, severity should usually be Critical.

LOG SOURCE:
{source}

LOG TYPE:
{log_type}

PARSER RISK SCORE:
{risk_score}

PARSER SUGGESTED SEVERITY:
{suggested_severity}

PARSER DETECTED INDICATORS:
{", ".join(parser_indicators) if parser_indicators else "None"}

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