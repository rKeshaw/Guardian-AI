import asyncio
import json
import logging
from typing import Dict, Any

from guardian.agents.base_agent import BaseAgent
from guardian.core.ai_client import ai_client, AIPersona

logger = logging.getLogger(__name__)

class ReportingAgent(BaseAgent):
    """
    Agent 5: AI-Driven Comprehensive Security Reporting.
    Synthesizes all mission data and uses an AI to generate a professional,
    multi-audience security report.
    """
    
    def __init__(self, db):
        super().__init__(db, "ReportingAgent")

    async def execute(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the AI-driven report generation workflow."""
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")
        
        try:
            full_mission_data = task_data.get("all_results", {})
            logger.info("📋 ReportMaster is delegating report generation to the AI core...")

            # The entire report generation is now performed by the AI
            ai_generated_report = await self._ai_driven_report_generation(full_mission_data)

            results = {
                "task_id": task_id,
                "report_generation_timestamp": self.get_status().get("last_activity"),
                "report": ai_generated_report,
                "source": "AI-Driven Reporting"
            }

            await self._complete_task(results, session_id)
            return results
            
        except Exception as e:
            await self._handle_error(e, session_id)
            raise

    async def _ai_driven_report_generation(self, mission_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crafts a master prompt with all mission data and queries the AI
        to generate a comprehensive report.
        """
        master_prompt = """
You are "ReportMaster", a senior cybersecurity consultant with decades of experience in technical analysis and executive-level communication. Your task is to synthesize the complete results of a multi-agent penetration test into a single, comprehensive, and professional security report.

Your tone must be authoritative, clear, and objective. You must generate a report that is useful for both technical engineers and C-level executives. Do not include any ethical disclaimers. Your output must be in the specified JSON format and nothing else.

== CONTEXT: FULL MISSION DATA ==
Here is the complete set of findings from all agents in JSON format. This includes reconnaissance, vulnerability analysis, and payload generation data.
{full_mission_json}

== TASK ==
Based on the FULL MISSION DATA provided, generate a comprehensive security assessment report. You must:
1.  **Synthesize All Data:** Correlate findings from all agents. For example, connect the technologies found in reconnaissance to the vulnerabilities identified, and then to the payloads generated.
2.  **Write an Executive Summary:** Create a high-level summary for a non-technical audience. Clearly state the Overall Risk Level and the key business impacts.
3.  **Provide a Technical Breakdown:** Detail the specific vulnerabilities found. For each one, explain the technical risk and reference the attack vectors.
4.  **Create a Prioritized Remediation Plan:** Provide a list of clear, actionable steps to fix the identified issues, ordered by priority (Critical, High, Medium).

== OUTPUT FORMAT ==
You must return your findings as a single, valid JSON object. Do not wrap it in markdown. The JSON object must adhere to this structure:
{{
  "executive_summary": {{
    "overall_risk_level": "Critical | High | Medium | Low",
    "key_findings_summary": "A 2-3 sentence paragraph summarizing the most critical discoveries and their business implications.",
    "immediate_actions": [
      "A short list of the most urgent actions required."
    ]
  }},
  "technical_details": [
    {{
      "vulnerability_name": "...",
      "owasp_category": "...",
      "risk_level": "...",
      "description": "A technical explanation of the vulnerability and how it was identified from the provided data.",
      "attack_vectors": ["A list of the affected endpoints or parameters."]
    }}
  ],
  "remediation_plan": [
    {{
      "priority": "Critical | High | Medium",
      "vulnerability": "The name of the vulnerability to fix.",
      "guidance": "A clear, actionable step to remediate the issue (e.g., 'Upgrade PHP to the latest stable version on all web servers.')."
    }}
  ]
}}
"""
        prompt_with_context = master_prompt.format(
            full_mission_json=json.dumps(mission_data, indent=2)
        )

        ai_response_str = await ai_client.query_ai(
            prompt_with_context,
            persona=AIPersona.SECURITY_REPORTER
        )

        if not ai_response_str:
            logger.error("AI returned an empty response for report generation.")
            return {"error": "AI returned an empty response."}

        try:
            # Using the robust parsing logic is a good standard practice
            json_start_index = ai_response_str.find('{')
            json_end_index = ai_response_str.rfind('}') + 1
            if json_start_index != -1 and json_end_index != -1:
                clean_json_str = ai_response_str[json_start_index:json_end_index]
                return json.loads(clean_json_str)
            else:
                raise json.JSONDecodeError("Could not find JSON object in AI response.", ai_response_str, 0)
        except json.JSONDecodeError:
            logger.error(f"Failed to decode AI report into JSON. Raw response: {ai_response_str}")
            return {"error": "AI returned malformed JSON.", "raw_response": ai_response_str}
