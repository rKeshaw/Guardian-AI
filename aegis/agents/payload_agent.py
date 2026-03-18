"""
aegis/agents/payload_agent.py
"""

import json
import logging
from typing import Any

from pydantic import BaseModel, ValidationError

from aegis.agents.base_agent import BaseAgent
from aegis.core.ai_client import ai_client, AIPersona, estimate_tokens

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
    Agent 3 — LLM-native payload generation.

    For each vulnerability identified by VulnerabilityAnalysisAgent:
      1. Build a rich, target-specific context from reconnaissance and
         vulnerability metadata.
      2. Prompt the LLM to reason about exploitation strategy and generate
         diverse payloads tailored to that context.
      3. Validate the response and retry with correction on failure.
    """

    # Warn if full prompt exceeds this
    PROMPT_TOKEN_WARN = 6500

    # Max LLM retries per vulnerability
    MAX_RETRIES = 2

    def __init__(self, db) -> None:
        super().__init__(db, "PayloadGenerationAgent")

    @staticmethod
    def _optional_str(value: Any) -> str | None:
        return str(value) if value is not None else None

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
                    "source": "AI-Driven Contextual Generation",
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
                "source": "AI-Driven Contextual Generation",
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

        # ── Step 1: Build contextual prompt ────────────
        prompt = self._build_prompt(recon_context, vuln)
        estimated = estimate_tokens(prompt)

        if estimated > self.PROMPT_TOKEN_WARN:
            logger.warning(
                "PayloadSmith prompt large tokens≈%d vuln=%s",
                estimated, vuln_name,
            )

        # ── Step 2: Query LLM with retry ──────────────
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

    # ── Recon context builder ─────────────────

    def _build_recon_context(self, recon_data: dict[str, Any]) -> dict[str, Any]:
        """Extract a minimal recon context for the payload prompt."""
        context: dict[str, Any] = {}
        recon_map = recon_data.get("reconnaissance_data", {})

        for target_url, data in recon_map.items():
            if not isinstance(data, dict) or "error" in data:
                continue
            tech_names: list[str] = []
            technologies_raw = data.get("technologies", {})
            if isinstance(technologies_raw, dict):
                for tech_list in technologies_raw.values():
                    if not isinstance(tech_list, list):
                        continue
                    for t in tech_list:
                        name = t.get("name") if isinstance(t, dict) else str(t)
                        if name and name not in tech_names:
                            tech_names.append(name)
            elif isinstance(technologies_raw, list):
                for t in technologies_raw:
                    name = t.get("name") if isinstance(t, dict) else str(t)
                    if name and name not in tech_names:
                        tech_names.append(name)

            forms = data.get("forms", [])
            endpoints = data.get("api_endpoints", [])
            if not forms or not endpoints:
                web = data.get("web_applications", {}) if isinstance(data.get("web_applications"), dict) else {}
                forms = forms or web.get("forms", [])
                endpoints = endpoints or web.get("endpoints", [])
            raw_signals = data.get("attack_surface_signals")
            attack_surface_signals = raw_signals if isinstance(raw_signals, list) else []
            waf_detected = data.get("waf_detected")
            backend_language = data.get("backend_language")
            database_hint = data.get("database_hint")
            framework = data.get("framework")
            context[target_url] = {
                "technologies": tech_names[:15],
                "waf_detected": self._optional_str(waf_detected),
                "backend_language": self._optional_str(backend_language),
                "database_hint": self._optional_str(database_hint),
                "framework": self._optional_str(framework),
                "attack_surface_signals": attack_surface_signals[:20],
                "open_ports": [
                    f"{p.get('port')}/{p.get('service')}" if isinstance(p, dict) else str(p)
                    for p in data.get("open_ports", [])[:10]
                ],
                "endpoints": endpoints[:20],
                "forms": [
                    {
                        "action": f.get("action"),
                        "method": f.get("method"),
                        "inputs": [i.get("name") for i in f.get("inputs", []) if i.get("name")],
                    }
                    for f in forms[:10]
                ],
            }

        return context

    # ── Prompt construction ───────────────────

    def _build_prompt(
        self,
        recon_context: dict[str, Any],
        vuln: dict[str, Any],
    ) -> str:
        owasp_category = str(vuln.get("owasp_category", ""))
        injection_point = (
            vuln.get("injection_point")
            if isinstance(vuln.get("injection_point"), dict)
            else {}
        )
        target_context = {
            "reconnaissance": recon_context,
            "vulnerability_name": vuln.get("vulnerability_name", ""),
            "owasp_category": owasp_category,
            "risk_level": vuln.get("risk_level", ""),
            "attack_vectors": vuln.get("attack_vectors", []),
            "injection_point": {
                "url": injection_point.get("url"),
                "method": injection_point.get("method"),
                "param_name": injection_point.get("param_name"),
                "param_type": injection_point.get("param_type"),
                "context_hint": injection_point.get("context_hint", ""),
            },
            "database_hint": vuln.get("database_hint"),
            "backend_language": vuln.get("backend_language"),
            "waf_detected": vuln.get("waf_detected"),
            "behavioral_signals": vuln.get("behavioral_signals", []),
        }
        exploitation_goal = self._success_criteria_for_category(owasp_category)
        return f"""You are "PayloadSmith", an expert exploit developer specialising in \
web application vulnerabilities. You are mid-engagement and must produce immediately testable payloads.

== TARGET CONTEXT ==
{json.dumps(target_context, indent=2)}

== EXPLOITATION SUCCESS CRITERIA ==
{exploitation_goal}

== INSTRUCTIONS ==
1. Think through likely backend behavior using the target context (technology stack, parameter handling, defensive controls, framework patterns) before deriving payload strings.
2. Generate 4-8 payloads with explicit diversity:
   - Canonical/basic payload
   - Encoded or obfuscated variants
   - WAF bypass variants when a WAF is detected
   - Technology-specific variants (e.g., DB/vendor/framework specific syntax when hints exist)
3. Every payload must be immediately usable and target the concrete injection point and attack vectors.
4. In each payload "description", include concise reasoning:
   - what this payload tests,
   - why it fits this target,
   - what response pattern would confirm exploitation.
5. Avoid generic placeholders except where an explicit injection marker is unavoidable.

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
          "description": "What this payload tests, why it matches this target, and confirmation signal",
          "payload": "actual payload string"
        }}
      ]
    }}
  ]
}}"""

    @staticmethod
    def _success_criteria_for_category(owasp_category: str) -> str:
        normalized = (owasp_category or "").strip().lower()
        if normalized.startswith("a03") or "injection" in normalized:
            return (
                "For injection-class vulnerabilities, success means measurable backend impact "
                "(e.g., SQL/database errors, differential responses, data extraction paths, or "
                "reliable timing side channels)."
            )
        if normalized.startswith("a01") or "access control" in normalized:
            return (
                "For broken access control, success means unauthorized data access or state changes "
                "across privilege boundaries."
            )
        if normalized.startswith("a07") or "authentication" in normalized:
            return (
                "For authentication failures, success means bypassing or weakening authentication/session "
                "controls to gain unauthorized access."
            )
        if normalized.startswith("a05") or "csrf" in normalized:
            return (
                "For CSRF or misconfiguration-style abuse, success means triggering an unintended state-changing "
                "action without a valid anti-CSRF/control token."
            )
        return (
            "Define success as observable, repeatable evidence that the target violates the stated OWASP category "
            "through unauthorized behavior, execution, disclosure, or control bypass."
        )

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
