from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from pydantic import ValidationError

from guardian.core.ai_client import AIPersona, estimate_tokens
from guardian.core.graph.attack_graph import AttackGraph, Node, NodeType
from guardian.core.token_ledger import TokenLedger
from guardian.models.hypothesis import HypothesisSchema

logger = logging.getLogger(__name__)


_REQUIRED_FIELDS = {
    "hypothesis",
    "owasp_category",
    "owasp_impact",
    "evidence_for",
    "evidence_against",
    "entry_probe",
    "expected_if_vulnerable",
    "expected_if_not_vulnerable",
    "confidence",
    "injection_point",
}

_REQUIRED_INJECTION_POINT_FIELDS = {"url", "method", "param_name", "param_type"}


class HypothesisAgent:
    def __init__(self, db: Any, ai_client: Any) -> None:
        self.db = db
        self.ai_client = ai_client

    async def generate(
        self,
        target_model: dict,
        graph: AttackGraph,
        ledger: TokenLedger,
    ) -> list[Node]:
        prompt = self._build_generation_prompt(target_model)

        if not self._charge_ledger(ledger, "hypothesis_engine", prompt):
            logger.warning("Token budget exhausted before hypothesis generation.")
            return []

        persona = getattr(AIPersona, "HYPOTHESIS_ENGINE", AIPersona.VULNERABILITY_EXPERT)
        raw_first = await self.ai_client.query_with_retry(
            prompt,
            persona=persona,
            max_retries=2,
        )

        initial_payload = self._unpack_query_result(raw_first)
        if initial_payload is None:
            logger.warning("Hypothesis generation returned no payload.")
            return []

        hypotheses = self._extract_hypothesis_list(initial_payload)
        valid = self._validate_hypotheses(hypotheses)

        reviewed = await self._self_review(target_model, valid, ledger, persona)
        deduped = self._deduplicate(reviewed)

        nodes = [self._to_node(h) for h in deduped]
        nodes.sort(key=lambda n: n.confidence, reverse=True)

        for node in nodes:
            graph.add_node(node)

        return nodes

    def _build_generation_prompt(self, target_model: dict[str, Any]) -> str:
        technologies = target_model.get("technologies", [])
        injection_points = target_model.get("injection_points", [])
        attack_surface_signals = target_model.get("attack_surface_signals", target_model.get("interesting_signals", []))
        waf = target_model.get("waf_detected", target_model.get("waf", "not detected"))

        compact_model = {
            "technologies": technologies,
            "injection_points": injection_points,
            "attack_surface_signals": attack_surface_signals,
            "waf_detected": waf,
        }

        example = {
            "hypothesis": "The username field on /login is injectable via error-based SQLi",
            "owasp_category": "A03:2023",
            "owasp_impact": 9,
            "evidence_for": ["PHP detected", "MySQL error pattern possible", "login form found"],
            "evidence_against": ["no WAF detected"],
            "entry_probe": "'",
            "expected_if_vulnerable": "SQL syntax error visible in response body",
            "expected_if_not_vulnerable": "Generic login failed message, no SQL content",
            "confidence": 70,
            "injection_point": {
                "url": "http://target.com/login",
                "method": "POST",
                "param_name": "username",
                "param_type": "form",
                "context_hint": "login username field",
                "other_params": {"password": "test"}
            }
        }

        lines = [
            "Generate 5 to 15 penetration testing hypotheses as a JSON array.",
            "Return ONLY the JSON array. No markdown. No explanation before or after.",
            "Each element must have ALL of these keys exactly:",
            "hypothesis, owasp_category, owasp_impact, evidence_for, evidence_against,",
            "entry_probe, expected_if_vulnerable, expected_if_not_vulnerable, confidence, injection_point.",
            "injection_point must have: url, method, param_name, param_type, context_hint, other_params.",
            "owasp_category must match pattern A##:2023.",
            "confidence is integer 0-100. owasp_impact is integer 1-10.",
            "Every hypothesis must name a specific parameter from the target data below.",
            "",
            "Example of one valid element:",
            json.dumps(example, indent=2),
            "",
            "Target reconnaissance data:",
            json.dumps(compact_model, indent=2),
            "",
            "Return the JSON array now:",
        ]
        return "\\n".join(lines)

    async def _self_review(
        self,
        target_model: dict[str, Any],
        hypotheses: list[dict[str, Any]],
        ledger: TokenLedger,
        persona: AIPersona,
    ) -> list[dict[str, Any]]:
        technologies = target_model.get("technologies", [])
        review_prompt = (
            "Review this hypothesis list for a target with the following technologies: "
            f"{technologies}.\n"
            "Are there obvious high-impact hypotheses missing? Are any hypotheses redundant?\n"
            "Return a JSON object with keys 'missing' (list of new hypothesis dicts) "
            "and 'redundant' (list of hypothesis strings to remove by hypothesis text match).\n"
            f"Current list:\n{json.dumps(hypotheses, indent=2)}"
        )

        if not self._charge_ledger(ledger, "hypothesis_engine", review_prompt):
            logger.warning("Token budget exhausted before self-review pass.")
            return hypotheses

        raw_review = await self.ai_client.query_with_retry(
            review_prompt,
            persona=persona,
            max_retries=2,
        )
        review_payload = self._unpack_query_result(raw_review)
        if not isinstance(review_payload, dict):
            return hypotheses

        missing_raw = review_payload.get("missing", [])
        redundant_raw = review_payload.get("redundant", [])

        missing_valid = self._validate_hypotheses(missing_raw if isinstance(missing_raw, list) else [])
        redundant_set = {
            text.strip() for text in redundant_raw if isinstance(text, str) and text.strip()
        }

        merged = list(hypotheses) + missing_valid
        if redundant_set:
            merged = [h for h in merged if str(h.get("hypothesis", "")).strip() not in redundant_set]

        return merged

    def _extract_hypothesis_list(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            raw = payload.get("hypotheses", [])
            return raw if isinstance(raw, list) else []
        if isinstance(payload, list):
            return payload
        return []

    def _validate_hypotheses(self, raw_hypotheses: list[Any]) -> list[dict[str, Any]]:
        valid: list[dict[str, Any]] = []

        for idx, item in enumerate(raw_hypotheses):
            if not isinstance(item, dict):
                logger.warning("Skipping non-dict hypothesis at index=%d", idx)
                continue

            missing = _REQUIRED_FIELDS - set(item.keys())
            if missing:
                logger.warning("Skipping hypothesis missing fields=%s", sorted(missing))
                continue

            inj = item.get("injection_point")
            if not isinstance(inj, dict):
                logger.warning("Skipping hypothesis with non-dict injection_point")
                continue
            inj_missing = _REQUIRED_INJECTION_POINT_FIELDS - set(inj.keys())
            if inj_missing:
                logger.warning("Skipping hypothesis missing injection_point fields=%s", sorted(inj_missing))
                continue

            try:
                parsed = HypothesisSchema.model_validate(item)
            except ValidationError as exc:
                logger.warning("Skipping invalid hypothesis due to schema error: %s", exc)
                continue

            valid.append(parsed.model_dump())

        return valid

    def _deduplicate(self, hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: dict[tuple[str, str, str], dict[str, Any]] = {}

        for hyp in hypotheses:
            injection_point = hyp.get("injection_point", {})
            key = (
                str(injection_point.get("url", "")).strip().lower(),
                str(injection_point.get("param_name", "")).strip().lower(),
                str(hyp.get("owasp_category", "")).strip(),
            )
            existing = deduped.get(key)
            if existing is None or int(hyp.get("confidence", 0)) > int(existing.get("confidence", 0)):
                deduped[key] = hyp

        return list(deduped.values())

    def _to_node(self, hypothesis_dict: dict[str, Any]) -> Node:
        confidence = max(0, min(100, int(hypothesis_dict.get("confidence", 0)))) / 100.0
        token_est = estimate_tokens(json.dumps(hypothesis_dict, sort_keys=True))

        return Node(
            id=str(uuid.uuid4()),
            type=NodeType.HYPOTHESIS,
            content=hypothesis_dict.get("hypothesis", ""),
            depth=0,
            confidence=confidence,
            token_estimate=token_est,
            compressed_summary=hypothesis_dict,
        )

    def _charge_ledger(self, ledger: TokenLedger, component: str, prompt: str) -> bool:
        tokens = estimate_tokens(prompt)

        # Preferred signature in this codebase: charge(amount, component="...")
        try:
            return bool(ledger.charge(tokens, component=component))
        except TypeError:
            # Compatibility fallback for alternate signature: charge(component, amount)
            return bool(ledger.charge(component, tokens))

    @staticmethod
    def _unpack_query_result(raw_result: Any) -> Any | None:
        if raw_result is None:
            return None

        if isinstance(raw_result, tuple) and len(raw_result) == 2:
            parsed, err = raw_result
            if err:
                logger.warning("LLM query_with_retry returned error: %s", err)
                return None
            return parsed

        return raw_result
