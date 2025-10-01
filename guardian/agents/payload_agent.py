import asyncio
import json
import logging
import os
from typing import Dict, Any, List

from guardian.agents.base_agent import BaseAgent
from guardian.core.ai_client import ai_client, AIPersona
from guardian.core.config import settings

logger = logging.getLogger(__name__)

class PayloadGenerationAgent(BaseAgent):
    """
    Agent 3: Retrieval-Augmented Payload Generation.
    Receives a knowledge base file reference from the VulnHunter agent
    and uses it to generate highly relevant payloads.
    """
    
    def __init__(self, db):
        super().__init__(db, "PayloadGenerationAgent")
        self.payloads_repo_path = settings.PAYLOADS_REPO_PATH
        # The static vulnerability_map is now obsolete and has been removed.

    def _retrieve_knowledge(self, knowledge_file: str) -> str:
        """
        Retrieves content from a specific file in the PayloadsAllTheThings repo.
        """
        if not knowledge_file:
            return "No specific knowledge file was provided."

        try:
            full_path = os.path.join(self.payloads_repo_path, "Methodology and Resources", knowledge_file)
            if not os.path.exists(full_path):
                 logger.warning(f"Could not find knowledge file: {knowledge_file}")
                 return f"Knowledge file '{knowledge_file}' not found."
            
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read(12000)
                logger.info(f"Successfully retrieved {len(content)} chars from {knowledge_file}.")
                return content
        except Exception as e:
            logger.error(f"Failed to retrieve knowledge from '{knowledge_file}': {e}")
            return "Failed to retrieve knowledge."

    async def execute(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the RAG payload generation workflow."""
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")
        
        try:
            vuln_report = task_data.get("vulnerability_data", {})
            recon_data = task_data.get("reconnaissance_data", {})
            final_payload_arsenal = []

            for vulnerability in vuln_report.get("vulnerabilities", []):
                vuln_name = vulnerability.get("vulnerability_name")
                # DYNAMIC DISPATCH: Get the knowledge file from the VulnHunter's output
                knowledge_file = vulnerability.get("knowledge_base_file")
                
                logger.info(f"⚔️ Crafting payloads for '{vuln_name}' using knowledge from '{knowledge_file}'...")
                
                retrieved_knowledge = self._retrieve_knowledge(knowledge_file)
                
                ai_generated_payloads = await self._ai_driven_payload_generation(
                    recon_data, vulnerability, retrieved_knowledge
                )
                
                if ai_generated_payloads and "error" not in ai_generated_payloads:
                    final_payload_arsenal.extend(ai_generated_payloads.get("payload_arsenal", []))

            results = {
                "task_id": task_id,
                "generation_timestamp": self.get_status().get("last_activity"),
                "payload_arsenal": final_payload_arsenal,
                "source": "AI-to-AI Dynamic RAG"
            }
            
            await self._complete_task(results, session_id)
            return results
            
        except Exception as e:
            await self._handle_error(e, session_id)
            raise

    async def _ai_driven_payload_generation(self, recon_data: dict, vulnerability: dict, knowledge: str) -> dict:
        """Sends the augmented prompt to the AI."""
        master_prompt = """
You are an expert exploit developer, "PayloadSmith". Your task is to craft payloads based on the context provided. Your output MUST be ONLY a valid JSON object.

== CONTEXT 1: RECONNAISSANCE REPORT (Target technologies and endpoints) ==
{recon_json}

== CONTEXT 2: VULNERABILITY ANALYSIS (The specific vulnerability to target) ==
{vuln_json}

== CONTEXT 3: AUTHORITATIVE KNOWLEDGE (Expert-curated data on this vulnerability type) ==
{retrieved_knowledge}

== TASK ==
Based on ALL THREE contexts above, generate a payload arsenal for the single vulnerability specified in CONTEXT 2.
1.  Your payloads MUST be consistent with the examples and descriptions in the AUTHORITATIVE KNOWLEDGE.
2.  Tailor the payloads to the specific `attack_vectors` and the technologies in the RECONNAISSANCE REPORT.
3.  Provide a variety of payloads (e.g., Basic, Obfuscated, WAF Bypass).

== OUTPUT FORMAT ==
Return ONLY a valid JSON object matching this structure:
{{
  "payload_arsenal": [
    {{
      "target_vulnerability": "{vuln_name}",
      "owasp_category": "{owasp_category}",
      "attack_vectors": {attack_vectors},
      "payloads": [
        {{
          "type": "...",
          "description": "...",
          "payload": "..."
        }}
      ]
    }}
  ]
}}
"""
        target_url = list(recon_data.get("reconnaissance_data", {}).keys())[0]
        target_recon_data = recon_data.get("reconnaissance_data", {}).get(target_url, {})
        
        prompt_with_context = master_prompt.format(
            recon_json=json.dumps(target_recon_data, indent=2),
            vuln_json=json.dumps(vulnerability, indent=2),
            retrieved_knowledge=knowledge,
            vuln_name=vulnerability.get("vulnerability_name"),
            owasp_category=vulnerability.get("owasp_category"),
            attack_vectors=json.dumps(vulnerability.get("attack_vectors", []))
        )

        ai_response_str = await ai_client.query_ai(prompt_with_context, persona=AIPersona.PAYLOAD_GENERATOR)
        
        if not ai_response_str: return {"error": "AI returned empty response"}
        try:
            return json.loads(ai_response_str)
        except json.JSONDecodeError:
            logger.error(f"RAG-based payload generation failed JSON parsing. Raw response: {ai_response_str}")
            return {"error": "AI returned malformed JSON.", "raw_response": ai_response_str}