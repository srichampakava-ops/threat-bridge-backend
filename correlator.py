import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(
    api_key=os.environ.get("GROQ_API_KEY")
)


def clean_json_response(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.replace("```json", "")
        text = text.replace("```", "")
        text = text.strip()
    return text


def correlate_findings(findings: list) -> dict:
    """
    Takes all findings from the report
    Analyzes them together as a group
    Returns correlation analysis
    """

    # Build a clean summary of all findings
    findings_summary = ""
    for i, f in enumerate(findings, 1):
        findings_summary += f"""
Finding {i}:
  Attack: {f.get("attack_name")}
  MITRE ID: {f.get("mitre_id")}
  MITRE Technique: {f.get("mitre_name")}
  MITRE Tactic: {f.get("mitre_tactic")}
  Severity: {f.get("severity")}
  Evidence: {", ".join(f.get("evidence_quotes", []))}
  Explanation: {f.get("explanation")}
"""

    prompt = f"""
You are an expert SOC Analyst and Threat Intelligence specialist
with 20 years of experience in attack correlation and campaign analysis.

Analyze ALL of the following security findings TOGETHER as a group.
Determine if they are part of a coordinated attack chain or separate incidents.

SECURITY FINDINGS:
{findings_summary}

Perform a deep correlation analysis and return ONLY this exact JSON:

{{
  "are_related": true,
  "confidence_percentage": 92,
  "relationship_explanation": "clear explanation of why these attacks are related or not",
  "attack_chain": [
    {{
      "step": 1,
      "mitre_id": "T1110",
      "attack_name": "Brute Force",
      "tactic": "Initial Access",
      "what_happened": "brief explanation of what happened at this step",
      "led_to_next": "explanation of how this led to the next attack"
    }}
  ],
  "attacker_goal": "clear explanation of what the attacker was trying to achieve",
  "attack_pattern": "name of the overall attack pattern e.g APT Campaign, Ransomware Preparation",
  "overall_risk_score": 9.2,
  "risk_explanation": "explanation of why this risk score was assigned",
  "timeline": [
    {{
      "time": "02:00 UTC",
      "mitre_id": "T1110",
      "event": "brief description of what happened"
    }}
  ],
  "priority_action": {{
    "mitre_id": "T1110",
    "attack_name": "Brute Force",
    "reason": "explanation of why this should be addressed first"
  }},
  "recommendations": [
    "specific actionable recommendation 1",
    "specific actionable recommendation 2",
    "specific actionable recommendation 3"
  ]
}}

IMPORTANT RULES:
- Base everything only on the findings provided
- Be specific and accurate not generic
- Timeline must use times from the evidence
- Risk score must be between 0 and 10
- Confidence must be between 0 and 100
- Return ONLY valid JSON nothing else
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=2000
        )

        response_text = clean_json_response(
            response.choices[0].message.content
        )

        result = json.loads(response_text)
        return result

    except json.JSONDecodeError:
        return {
            "are_related": False,
            "confidence_percentage": 0,
            "relationship_explanation": "Could not perform correlation analysis",
            "attack_chain": [],
            "attacker_goal": "Unknown",
            "attack_pattern": "Unknown",
            "overall_risk_score": 0,
            "risk_explanation": "Analysis failed",
            "timeline": [],
            "priority_action": {},
            "recommendations": []
        }

    except Exception as e:
        return {
            "are_related": False,
            "confidence_percentage": 0,
            "relationship_explanation": str(e),
            "attack_chain": [],
            "attacker_goal": "Unknown",
            "attack_pattern": "Unknown",
            "overall_risk_score": 0,
            "risk_explanation": "Analysis failed",
            "timeline": [],
            "priority_action": {},
            "recommendations": []
        }