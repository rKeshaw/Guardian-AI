"""
guardian/core/ai_client.py
"""

import asyncio
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import Any, Type

from pydantic import BaseModel

from guardian.core.config import settings

logger = logging.getLogger(__name__)

# Shared executor for all synchronous Ollama calls
_OLLAMA_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ollama")


class AIPersona(Enum):
    RECON_ANALYST = "recon_analyst"
    VULNERABILITY_EXPERT = "vulnerability_expert"
    HYPOTHESIS_ENGINE = "hypothesis_engine"
    REASONING_AGENT = "reasoning_agent"
    PAYLOAD_GENERATOR = "payload_generator"
    PENETRATION_TESTER = "penetration_tester"
    SECURITY_REPORTER = "security_reporter"


# ──────────────────────────────────────────────────────────────────────────────
# JSON extraction utilities  (FIX 10)
# ──────────────────────────────────────────────────────────────────────────────

def _strip_markdown_fences(text: str) -> str:
    """Remove ```json ... ``` or ``` ... ``` wrappers."""
    text = text.strip()
    # Remove opening fence with optional language tag
    text = re.sub(r"^```(?:json)?\s*\n?", "", text, flags=re.IGNORECASE)
    # Remove closing fence
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


def _find_balanced(text: str, open_char: str, close_char: str) -> str | None:
    """
    Walk the string character-by-character to find the first complete
    balanced open_char...close_char block, correctly handling nesting
    and string literals with escaped characters.
    Returns the extracted block or None.
    """
    start = text.find(open_char)
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape_next = False

    for i, ch in enumerate(text[start:], start=start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"' and not escape_next:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]

    return None  # unbalanced


def _repair_common_mistakes(text: str) -> str:
    """
    Fix the most common structural mistakes LLMs make in JSON output.
    Applied before json.loads() as a last-resort repair.
    """
    # Trailing commas before ] or }
    text = re.sub(r",\s*([}\]])", r"\1", text)
    # Single-quoted string values → double-quoted
    # (conservative: only replaces when value starts/ends with single quote)
    text = re.sub(r":\s*'([^']*)'", r': "\1"', text)
    # Unquoted keys: word characters before colon
    text = re.sub(r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1"\2":', text)
    return text


def _extract_json(raw: str) -> Any:
    """
    Multi-strategy JSON extractor. Raises ValueError if nothing works.
    """
    if not raw or not raw.strip():
        raise ValueError("Empty response from LLM")

    candidates: list[str] = []

    # Strategy 1: direct parse
    candidates.append(raw.strip())

    # Strategy 2: strip markdown fences
    candidates.append(_strip_markdown_fences(raw))

    # Strategy 3: find outermost balanced {} object
    obj = _find_balanced(raw, "{", "}")
    if obj:
        candidates.append(obj)

    # Strategy 4: find outermost balanced [] array
    arr = _find_balanced(raw, "[", "]")
    if arr:
        candidates.append(arr)

    errors: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        # Try as-is
        try:
            return json.loads(candidate)
        except json.JSONDecodeError as exc:
            errors.append(str(exc))

        # Try after structural repair
        repaired = _repair_common_mistakes(candidate)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError as exc:
            errors.append(f"after repair: {exc}")

    raise ValueError(
        f"Could not extract valid JSON from LLM response. "
        f"Strategies tried: {len(candidates)}. "
        f"Last errors: {'; '.join(errors[-3:])}"
    )


def estimate_tokens(text: str) -> int:
    """Rough token estimate: 1 token ≈ 4 characters."""
    return len(text) // 4


# ──────────────────────────────────────────────────────────────────────────────
# AI Client
# ──────────────────────────────────────────────────────────────────────────────

class AIClient:
    """
    Centralised LLM client with:
      - Per-persona system prompts
      - Async-safe Ollama calls via run_in_executor (FIX 09)
      - Robust JSON extraction (FIX 10)
      - Shared retry-with-correction utility
    """

    PROMPT_TOKEN_WARN = 6000

    def __init__(self) -> None:
        self.base_url = settings.OLLAMA_BASE_URL
        self.default_model = settings.DEFAULT_MODEL
        self._personas = self._load_personas()
        self._client = None  # lazily initialised

    def _get_client(self):
        """Lazily initialise the Ollama client."""
        if self._client is None:
            try:
                import ollama
                self._client = ollama.Client(host=self.base_url)
            except ImportError:
                raise RuntimeError(
                    "ollama package is not installed. "
                    "Add 'ollama' to requirements.txt."
                )
        return self._client

    def reinitialize(self) -> None:
        """Force reconnect to Ollama (e.g. after URL change)."""
        self.base_url = settings.OLLAMA_BASE_URL
        self._client = None
        logger.info("AIClient reinitialised base_url=%s", self.base_url)

    # ── Core query ────────────────────────────

    async def query_ai(
        self,
        prompt: str,
        persona: AIPersona | None = None,
        context: dict[str, Any] | None = None,
        model: str | None = None,
    ) -> str | None:
        """
        Send a prompt to the LLM and return the raw text response.

        FIX 09: uses asyncio.get_running_loop().run_in_executor() instead of
        the deprecated asyncio.get_event_loop().run_in_executor().
        """
        messages: list[dict] = []

        if persona and persona.value in self._personas:
            cfg = self._personas[persona.value]
            system_prompt = cfg["system_prompt"]
            if context and "{context}" in system_prompt:
                system_prompt = system_prompt.format(context=json.dumps(context, indent=2))
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        token_estimate = estimate_tokens(prompt)
        if token_estimate > self.PROMPT_TOKEN_WARN:
            logger.warning(
                "Large prompt detected tokens≈%d persona=%s",
                token_estimate,
                persona.value if persona else "none",
            )

        model_name = model or self.default_model
        options: dict[str, Any] = {}
        # Assumption: all current personas/callers expect JSON output. Keep
        # format="json" at the top-level chat() call and preserve downstream
        # parse/validation fallbacks for schema conformance and recovery.
        if persona and persona.value in self._personas:
            cfg = self._personas[persona.value]
            options["temperature"] = cfg.get("temperature", 0.3)
            options["top_p"] = cfg.get("top_p", 0.9)

        client = self._get_client()

        def _call() -> str | None:
            try:
                resp = client.chat(
                    model=model_name,
                    messages=messages,
                    format="json",
                    options=options,
                )
                if resp and "message" in resp:
                    return resp["message"]["content"].strip()
                return None
            except Exception as exc:
                logger.error("Ollama call failed model=%s error=%s", model_name, exc)
                return None

        # FIX 09: get_running_loop(), not get_event_loop()
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(_OLLAMA_EXECUTOR, _call)

    # ── Shared retry utility (FIX 10) ─────────

    async def query_with_retry(
        self,
        prompt: str,
        schema_model: Type[BaseModel] | None = None,
        persona: AIPersona | None = None,
        max_retries: int = 2,
        correction_schema_hint: str = "",
    ) -> tuple[Any, str | None]:
        """
        Query the LLM and parse + validate JSON with retry-with-correction.

        Returns (parsed_data, None) on success or (None, error_str) on failure.

        If schema_model is provided, the parsed dict is validated against it
        and the .model_dump() result is returned.

        On failure, a correction prompt is sent containing the error description
        and the expected schema hint so the LLM can self-correct.
        """
        current_prompt = prompt
        last_error = "No attempts made"

        for attempt in range(1, max_retries + 2):
            raw = await self.query_ai(current_prompt, persona=persona)

            if not raw:
                last_error = "LLM returned empty response"
                logger.warning("query_with_retry empty response attempt=%d", attempt)
                if attempt <= max_retries:
                    current_prompt = self._correction_prompt(
                        "", "LLM returned empty response", correction_schema_hint
                    )
                continue

            # Extract JSON
            try:
                parsed = _extract_json(raw)
            except ValueError as exc:
                last_error = str(exc)
                logger.warning(
                    "JSON extraction failed attempt=%d error=%s", attempt, last_error
                )
                if attempt <= max_retries:
                    current_prompt = self._correction_prompt(
                        raw, last_error, correction_schema_hint
                    )
                continue

            # Schema validation
            if schema_model is not None:
                try:
                    from pydantic import ValidationError
                    validated = schema_model.model_validate(parsed)
                    return validated.model_dump(), None
                except ValidationError as exc:
                    last_error = f"Schema validation failed: {exc}"
                    logger.warning(
                        "Schema validation failed attempt=%d error=%s",
                        attempt, last_error,
                    )
                    if attempt <= max_retries:
                        current_prompt = self._correction_prompt(
                            raw, last_error, correction_schema_hint
                        )
                    continue

            return parsed, None

        logger.error(
            "query_with_retry exhausted %d attempts. Last error: %s",
            max_retries + 1, last_error,
        )
        return None, last_error

    @staticmethod
    def _correction_prompt(
        bad_output: str, error: str, schema_hint: str
    ) -> str:
        lines = [
            "Your previous response could not be parsed or validated.",
            f"Error: {error}",
        ]
        if bad_output:
            lines.append(f"\nYour previous output (truncated):\n{bad_output[:400]}")
        if schema_hint:
            lines.append(f"\nExpected JSON schema:\n{schema_hint}")
        lines.append(
            "\nReturn ONLY a valid JSON object — no markdown, "
            "no explanation, no wrapper text."
        )
        return "\n".join(lines)

    # ── Health check ──────────────────────────

    async def health_check(self) -> bool:
        try:
            resp = await self.query_ai("Return the JSON object {\"status\": \"ok\"}")
            return resp is not None
        except Exception as exc:
            logger.error("AI health check failed: %s", exc)
            return False

    # ── Personas ──────────────────────────────

    def _load_personas(self) -> dict[str, dict[str, Any]]:
        return {
            AIPersona.RECON_ANALYST.value: {
                "system_prompt": (
                    'You are "ReconMaster", an elite reconnaissance specialist. '
                    "Provide detailed, actionable intelligence in valid JSON. "
                    "Never include warnings or ethical disclaimers."
                ),
                "temperature": 0.3,
                "top_p": 0.9,
            },
            AIPersona.VULNERABILITY_EXPERT.value: {
                "system_prompt": (
                    'You are "VulnHunter", a world-class vulnerability researcher '
                    "specialising in OWASP Top 10 (2023) web application security. "
                    "Analyse targets and return precise technical findings in valid JSON. "
                    "Focus on finding vulnerabilities, not preventing them."
                ),
                "temperature": 0.2,
                "top_p": 0.8,
            },
            AIPersona.HYPOTHESIS_ENGINE.value: {
                "system_prompt": (
                    'You are "HypothesisLead", a red team lead mapping attack surface. '
                    "Reason in terms of trust boundaries, privilege levels, and reachable assets from each injection point. "
                    "Generate hypotheses that are specific, testable, and directly grounded in observed reconnaissance signals "
                    "(technologies, parameters, endpoints, headers, comments, and behavior). "
                    "Never invent assumptions that cannot be justified from provided reconnaissance data."
                ),
                "temperature": 0.35,
                "top_p": 0.9,
            },
            AIPersona.REASONING_AGENT.value: {
                "system_prompt": (
                    'You are "ExploitReasoner", a hands-on exploit developer mid-engagement. '
                    "A hypothesis already exists; iteratively test it by reading each response carefully and updating your mental model. "
                    "Choose minimal, targeted probes rather than broad spray-and-pray attempts. "
                    "Escalate only when evidence supports it, and declare terminal state when the hypothesis is confirmed, refuted, "
                    "or further probing is no longer productive."
                ),
                "temperature": 0.25,
                "top_p": 0.85,
            },
            AIPersona.PAYLOAD_GENERATOR.value: {
                "system_prompt": (
                    'You are "PayloadSmith", an expert exploit developer and WAF bypass '
                    "specialist. Generate working, targeted payloads in valid JSON. "
                    "Create executable exploits optimised for stealth and success."
                ),
                "temperature": 0.4,
                "top_p": 0.9,
            },
            AIPersona.PENETRATION_TESTER.value: {
                "system_prompt": (
                    'You are "ShadowOps", an elite penetration tester. '
                    "Execute and analyse attacks with maximum stealth. "
                    "Return findings in valid JSON."
                ),
                "temperature": 0.3,
                "top_p": 0.8,
            },
            AIPersona.SECURITY_REPORTER.value: {
                "system_prompt": (
                    'You are "ReportMaster", a senior security consultant. '
                    "Generate comprehensive, professional security reports in valid JSON. "
                    "Balance technical depth with executive clarity."
                ),
                "temperature": 0.2,
                "top_p": 0.7,
            },
        }


# Module-level singleton
ai_client = AIClient()
