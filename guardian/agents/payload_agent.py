"""
guardian/agents/payload_agent.py
"""

import json
import logging
from typing import Any

from pydantic import BaseModel, ValidationError

from guardian.agents.base_agent import BaseAgent
from guardian.core.ai_client import ai_client, AIPersona
from guardian.core.knowledge_index import (
    knowledge_index,
    parse_knowledge_file,
    estimate_tokens,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Response schema
# ──────────────────────────────────────────────────────────────────────────────

class PayloadItem(BaseModel):
    type: str
    description: str
    payload: str


class VulnPayloadSet(BaseModel):
    target_vulnerability: str
    owasp_category: str
    attack_vectors: list[str] = []
    payloads: list[PayloadItem]


class PayloadArsenalResponse(BaseModel):
    payload_arsenal: list[VulnPayloadSet]


# ──────────────────────────────────────────────────────────────────────────────
# Agent
# ──────────────────────────────────────────────────────────────────────────────

class PayloadGenerationAgent(BaseAgent):
    """
    Agent 3 — Retrieval-Augmented Payload Generation.

    For each vulnerability identified by VulnerabilityAnalysisAgent:
      1. Look up relevant knowledge files using the programmatic OWASP_TO_FILES
         table (via knowledge_index.files_for_vulnerability).
      2. Extract section-aware, token-budgeted content from each file.
      3. Build a prompt containing recon context + vuln details + retrieved
         knowledge and query the LLM for tailored payloads.
      4. Validate the response and retry with correction on failure.
    """

    # Per-vulnerability knowledge token budget
    KNOWLEDGE_TOKEN_BUDGET = 3500

    # Warn if full prompt exceeds this
    PROMPT_TOKEN_WARN = 6500

    # Max LLM retries per vulnerability
    MAX_RETRIES = 2

    def __init__(self, db) -> None:
        super().__init__(db, "PayloadGenerationAgent")
        # Ensure the index is built at agent init time
        knowledge_index.build()

    # ── Entry point ───────────────────────────

    async def execute(self, task_data: dict[str, Any]) -> dict[str, Any]:
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")

        try:
            # vulnerability_data arrives from the orchestrator as the full
            # vulnerability_analysis result dict
            vuln_data: dict[str, Any] = task_data.get("vulnerability_data", {})
            recon_data: dict[str, Any] = task_data.get("reconnaissance_data", {})

            # Support both shapes: direct list or nested under 'vulnerability_assessment'
            vulnerabilities: list[dict] = (
                vuln_data.get("vulnerabilities")
                or vuln_data.get("vulnerability_assessment", {}).get("vulnerabilities", [])
            )

            if not vulnerabilities:
                logger.warning("No vulnerabilities received — returning empty arsenal")
                results = {
                    "task_id": task_id,
                    "payload_arsenal": [],
                    "source": "AI-Driven RAG",
                }
                await self._complete_task(results, session_id)
                return results

            # Build a compact recon context (target tech + endpoints only)
            recon_context = self._build_recon_context(recon_data)

            # Generate payloads for each vulnerability
            arsenal: list[dict] = []
            for vuln in vulnerabilities:
                entry = await self._generate_for_vulnerability(vuln, recon_context)
                if entry:
                    arsenal.append(entry)

            results = {
                "task_id": task_id,
                "payload_arsenal": arsenal,
                "source": "AI-Driven RAG",
            }
            await self._complete_task(results, session_id)
            logger.info(
                "PayloadSmith complete session_id=%s vuln_count=%d arsenal_entries=%d",
                session_id, len(vulnerabilities), len(arsenal),
            )
            return results

        except Exception as exc:
            await self._handle_error(exc, session_id)
            raise

    # ── Per-vulnerability generation ──────────

    async def _generate_for_vulnerability(
        self,
        vuln: dict[str, Any],
        recon_context: dict[str, Any],
    ) -> dict[str, Any] | None:
        vuln_name = vuln.get("vulnerability_name", "Unknown")
        owasp_cat = vuln.get("owasp_category", "")

        logger.info(
            "PayloadSmith generating payloads vuln=%s category=%s",
            vuln_name, owasp_cat,
        )

        # ── Step 1: Retrieve knowledge (FIX 03 + 04) ──
        knowledge_text = self._retrieve_knowledge(owasp_cat, vuln_name)

        # ── Step 2: Build prompt (FIX 05 — section-aware content already applied) ──
        prompt = self._build_prompt(recon_context, vuln, knowledge_text)
        estimated = estimate_tokens(prompt)

        if estimated > self.PROMPT_TOKEN_WARN:
            logger.warning(
                "PayloadSmith prompt large tokens≈%d vuln=%s",
                estimated, vuln_name,
            )

        # ── Step 3: Query LLM with retry ──────────────
        last_error = "No attempts made"
        for attempt in range(1, self.MAX_RETRIES + 2):
            raw = await ai_client.query_ai(prompt, persona=AIPersona.PAYLOAD_GENERATOR)

            if not raw:
                last_error = "LLM returned empty response"
                logger.warning(
                    "PayloadSmith empty response attempt=%d vuln=%s",
                    attempt, vuln_name,
                )
                continue

            parsed, error = self._parse_and_validate(raw)
            if parsed is not None:
                entries = parsed.get("payload_arsenal", [])
                return entries[0] if entries else None

            last_error = error
            logger.warning(
                "PayloadSmith parse failed attempt=%d vuln=%s error=%s",
                attempt, vuln_name, error,
            )
            prompt = self._build_correction_prompt(raw, error, vuln_name, owasp_cat)

        logger.error(
            "PayloadSmith failed for vuln=%s after %d attempts: %s",
            vuln_name, self.MAX_RETRIES + 1, last_error,
        )
        return None

    # ── Knowledge retrieval (FIX 03 + 05) ────

    def _retrieve_knowledge(self, owasp_category: str, vuln_name: str) -> str:
        """
        1. Use knowledge_index.files_for_vulnerability() to look up files from
           the programmatic OWASP_TO_FILES table — no LLM filename selection.
        2. Extract section-aware, token-budgeted content from each file.
        3. Merge up to 3 files, each limited to KNOWLEDGE_TOKEN_BUDGET // 3 tokens.
        """
        file_paths = knowledge_index.files_for_vulnerability(owasp_category, vuln_name)

        if not file_paths:
            logger.warning(
                "No knowledge files found for vuln=%s category=%s — proceeding without RAG",
                vuln_name, owasp_category,
            )
            return "No authoritative knowledge available for this vulnerability type."

        per_file_budget = self.KNOWLEDGE_TOKEN_BUDGET // max(len(file_paths), 1)
        parts: list[str] = []

        for path in file_paths:
            from pathlib import Path
            filename = Path(path).name
            content = parse_knowledge_file(path, token_budget=per_file_budget)
            if content:
                parts.append(f"### Source: {filename}\n\n{content}")
                logger.debug(
                    "Knowledge retrieved file=%s tokens≈%d",
                    filename, estimate_tokens(content),
                )

        if not parts:
            return "Knowledge files found but content extraction returned empty results."

        return "\n\n---\n\n".join(parts)

    # ── Recon context builder ─────────────────

    def _build_recon_context(self, recon_data: dict[str, Any]) -> dict[str, Any]:
        """Extract a minimal recon context for the payload prompt."""
        context: dict[str, Any] = {}
        recon_map = recon_data.get("reconnaissance_data", {})

        for target_url, data in recon_map.items():
            if not isinstance(data, dict) or "error" in data:
                continue
            tech_names = [
                t.get("name") if isinstance(t, dict) else str(t)
                for tech_list in data.get("technologies", {}).values()
                for t in tech_list
            ]
            web = data.get("web_applications", {})
            context[target_url] = {
                "technologies": tech_names[:15],
                "open_ports": [
                    f"{p.get('port')}/{p.get('service')}"
                    for p in data.get("open_ports", [])[:10]
                ],
                "endpoints": web.get("endpoints", [])[:20],
                "forms": [
                    {
                        "action": f.get("action"),
                        "method": f.get("method"),
                        "inputs": [i.get("name") for i in f.get("inputs", []) if i.get("name")],
                    }
                    for f in web.get("forms", [])[:10]
                ],
            }

        return context

    # ── Prompt construction ───────────────────

    def _build_prompt(
        self,
        recon_context: dict[str, Any],
        vuln: dict[str, Any],
        knowledge: str,
    ) -> str:
        return f"""You are "PayloadSmith", an expert exploit developer specialising in \
web application vulnerabilities. Generate a focused payload arsenal for the vulnerability \
specified in CONTEXT 2, informed by the reconnaissance data and authoritative knowledge provided.

== CONTEXT 1: RECONNAISSANCE (target technologies and endpoints) ==
{json.dumps(recon_context, indent=2)}

== CONTEXT 2: VULNERABILITY TO TARGET ==
{json.dumps(vuln, indent=2)}

== CONTEXT 3: AUTHORITATIVE KNOWLEDGE ==
{knowledge}

== INSTRUCTIONS ==
1. Generate 4-8 payloads: include Basic, Encoded/Obfuscated, and WAF Bypass variants.
2. Tailor payloads to the specific technologies and endpoints in CONTEXT 1.
3. Base payload structure on examples from CONTEXT 3.
4. Each payload must be immediately usable — no placeholders except for injection points \
marked as <INJECT>.

== OUTPUT FORMAT ==
Return ONLY a valid JSON object — no markdown wrapper:
{{
  "payload_arsenal": [
    {{
      "target_vulnerability": "{vuln.get("vulnerability_name", "")}",
      "owasp_category": "{vuln.get("owasp_category", "")}",
      "attack_vectors": {json.dumps(vuln.get("attack_vectors", []))},
      "payloads": [
        {{
          "type": "Basic | Encoded | WAF Bypass | Time-Based | Error-Based",
          "description": "What this payload does and why it works",
          "payload": "actual payload string"
        }}
      ]
    }}
  ]
}}"""

    def _build_correction_prompt(
        self,
        bad_output: str,
        error: str,
        vuln_name: str,
        owasp_cat: str,
    ) -> str:
        return f"""Your previous response could not be validated. Error: {error}

Previous output (first 400 chars):
{bad_output[:400]}

Return ONLY a valid JSON object for {vuln_name} ({owasp_cat}):
{{
  "payload_arsenal": [
    {{
      "target_vulnerability": "{vuln_name}",
      "owasp_category": "{owasp_cat}",
      "attack_vectors": [],
      "payloads": [
        {{"type": "string", "description": "string", "payload": "string"}}
      ]
    }}
  ]
}}"""

    # ── Parse + validate ──────────────────────

    def _parse_and_validate(
        self, raw: str
    ) -> tuple[dict[str, Any] | None, str]:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start == -1 or end == 0:
            return None, "No JSON object found in response"

        try:
            data = json.loads(raw[start:end])
        except json.JSONDecodeError as exc:
            return None, f"JSON parse error: {exc}"

        try:
            validated = PayloadArsenalResponse.model_validate(data)
            return validated.model_dump(), ""
        except ValidationError as exc:
            return None, f"Schema validation error: {exc}"
