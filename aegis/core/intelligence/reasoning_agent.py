from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from aegis.core.ai_client import AIPersona, estimate_tokens
from aegis.core.graph.attack_graph import AttackGraph, Edge, EdgeType, Node, NodeType
from aegis.core.intelligence.response_analyzer import ResponseAnalyzer
from aegis.core.intelligence.quality_monitor import QualityMonitor
from aegis.core.memory.conversation_memory import ConversationMemory
from aegis.core.config import settings
from aegis.core.probing.probe_executor import ProbeExecutor

logger = logging.getLogger(__name__)


_DEFAULTS: dict[str, Any] = {
    "observation": "",
    "updated_hypothesis": "",
    "confirmed_facts": [],
    "refuted_facts": [],
    "next_probe": "",
    "probe_rationale": "",
    "confidence": 0,
    "terminal": False,
    "exploitation_confirmed": False,
    "exploitation_evidence": None,
    "terminal_reason": None,
}

def _parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    if isinstance(value, int):
        return value != 0
    return default

class ReasoningAgent:
    def __init__(self, ai_client, comprehender, probe_executor, ledger) -> None:
        self.ai_client = ai_client
        self.comprehender = comprehender
        self.probe_executor = probe_executor
        self.ledger = ledger
        self._response_analyzer = ResponseAnalyzer()
        self._quality_monitor = QualityMonitor()
        self._pending_recovery_message: str | None = None

    async def explore(self, hypothesis_node: Node, target_model: dict, graph: AttackGraph) -> Node | None:
        memory = ConversationMemory(hypothesis_node.data.get("hypothesis", ""))

        injection_point_data = hypothesis_node.data.get("injection_point", {})
        injection_point = self._build_injection_point(injection_point_data)
        if injection_point is None:
            logger.warning("Invalid injection point for hypothesis=%s", hypothesis_node.id)
            return None

        current_probe = str(hypothesis_node.data.get("entry_probe", ""))
        max_turns = int(settings.MAX_TURNS_PER_HYPOTHESIS)

        baseline = await self.probe_executor.capture_baseline(injection_point)
        if getattr(baseline, "is_error", False):
            logger.warning("Baseline capture failed for hypothesis=%s", hypothesis_node.id)
            return None

        persona = AIPersona.REASONING_AGENT

        rag_context = ""
        if settings.ENABLE_RAG_PROBING:
            from aegis.core.intelligence.rag_helper import rag_helper

            rag_context = rag_helper.get_probe_context(
                owasp_category=str(hypothesis_node.data.get("owasp_category", "")),
                vuln_name=str(hypothesis_node.data.get("hypothesis", "")),
                token_budget=600,
            )
            if rag_context and not self._charge("reasoning_agent_rag", rag_context):
                logger.warning(
                    "Insufficient token budget for RAG context hypothesis=%s",
                    hypothesis_node.id,
                )
                rag_context = ""

        for turn in range(max_turns):
            if await self.comprehender.is_near_duplicate(current_probe, memory._tried_probes):
                duplicate_override = {
                    "role": "system_override",
                    "message": (
                        "Your last proposed probe is near-identical to a previous attempt. "
                        "Try a completely different angle or approach. State why your new probe is fundamentally different."
                    ),
                }
                re_prompt = self._build_probe_recovery_prompt(
                    hypothesis_node,
                    target_model,
                    memory,
                    turn,
                    max_turns,
                    duplicate_override,
                    self._pending_recovery_message or "",
                    rag_context=rag_context,
                )

                if not self._charge("reasoning_agent", re_prompt):
                    break

                retry_raw = await self.ai_client.query_with_retry(
                    re_prompt,
                    persona=persona,
                    max_retries=2,
                )
                llm_retry = self._normalize_llm_response(self._unpack_query_result(retry_raw))
                next_candidate = str(llm_retry.get("next_probe", ""))
                if not next_candidate:
                    current_probe = None
                    break
                if await self.comprehender.is_near_duplicate(next_candidate, memory._tried_probes):
                    current_probe = None
                    break
                current_probe = next_candidate

            if not current_probe:
                break

            probe_result = await self.probe_executor.fire(injection_point, current_probe)

            probe_node = Node(
                id=str(uuid.uuid4()),
                type=NodeType.PROBE,
                content=current_probe,
                data={"probe": current_probe, "turn": turn},
                depth=hypothesis_node.depth + 1,
            )
            graph.add_node(probe_node)
            graph.add_edge(Edge(source_id=hypothesis_node.id, target_id=probe_node.id, type=EdgeType.GENERATED))

            profile = self._response_analyzer.analyze(
                probe_result,
                self.probe_executor.get_baseline(injection_point),
            )

            observation_unit = await self.comprehender.compress_async(
                content=profile.new_content + str(profile.extracted_facts),
                content_type="injection_response",
                probe_sent=current_probe,
                ai_client=self.ai_client,
                token_ledger=self.ledger,
            )

            observation_node = Node(
                id=str(uuid.uuid4()),
                type=NodeType.OBSERVATION,
                content=getattr(observation_unit, "content", ""),
                data={
                    "turn": turn,
                    "facts": list(getattr(observation_unit, "irreducible_facts", [])),
                    "summary": getattr(observation_unit, "content", ""),
                    "status_code": profile.status_code,
                },
                token_estimate=getattr(observation_unit, "token_count", 0),
                depth=hypothesis_node.depth + 2,
            )
            graph.add_node(observation_node)
            graph.add_edge(Edge(source_id=probe_node.id, target_id=observation_node.id, type=EdgeType.RESPONDED))

            memory_string = memory.render_for_prompt(token_budget=3000)
            full_prompt = self._build_prompt(
                turn,
                max_turns,
                injection_point_data,
                target_model,
                hypothesis_node,
                memory_string,
                profile,
                self._pending_recovery_message or "",
                rag_context=rag_context,
            )

            if not self._charge("reasoning_agent", full_prompt):
                break

            raw = await self.ai_client.query_with_retry(
                full_prompt,
                persona=persona,
                max_retries=2,
            )
            llm_response = self._normalize_llm_response(self._unpack_query_result(raw))
            if llm_response is None:
                break

            overflow = memory.add_turn(current_probe, profile.to_prompt_dict(), observation_unit, llm_response)
            normalize_fn = getattr(self.comprehender, "_normalize_probe", None)
            normalized_probe = normalize_fn(current_probe) if callable(normalize_fn) else str(current_probe)
            logger.debug(
                "Probe diversity hypothesis=%s normalized=%r tried_count=%d semantic_normalized=%s",
                hypothesis_node.id,
                normalized_probe,
                len(memory._tried_probes),
                normalized_probe != current_probe,
            )
            if overflow:
                oldest = memory.oldest_working_turn()
                if oldest is not None:
                    compressed_unit = await self.comprehender.compress_episode(
                        turns=[oldest.get("llm_reasoning", {})],
                        confirmed_facts=memory.confirmed_facts,
                        ai_client=self.ai_client,
                        token_ledger=self.ledger,
                    )
                    memory.flush_oldest(compressed_unit)

            graph.update_node_confidence(hypothesis_node.id, float(llm_response.get("confidence", 0)) / 100.0)

            quality = self._quality_monitor.assess(memory, turn)
            if not quality.get("quality_ok", True) and quality.get("recovery_message"):
                self._pending_recovery_message = str(quality["recovery_message"])
            else:
                self._pending_recovery_message = None
        
            if bool(llm_response.get("terminal", False)):
                if bool(llm_response.get("exploitation_confirmed", False)):
                    return self._build_finding_node(hypothesis_node, memory, llm_response, graph)
                graph.resolve_hypothesis(hypothesis_node.id, NodeType.DEAD_END)
                return None

            current_probe = str(llm_response.get("next_probe", "") or "")
            if not current_probe:
                break

        logger.warning("Hypothesis exploration exhausted without terminal resolution node=%s", hypothesis_node.id)
        graph.resolve_hypothesis(hypothesis_node.id, NodeType.DEAD_END)
        return None

    def _build_prompt(
        self,
        turn: int,
        max_turns: int,
        injection_point: dict[str, Any],
        target_model: dict[str, Any],
        hypothesis_node: Node,
        memory_string: str,
        profile,
        quality_recovery_message: str,
        rag_context: str = "",
    ) -> str:
        rag_section = ""
        if rag_context:
            rag_section = (
                "ATTACK KNOWLEDGE CONTEXT:\n"
                f"{rag_context}\n\n"
                "Use the above payload patterns as inspiration for your next_probe "
                "when appropriate. Do not copy them verbatim — adapt them to the "
                "specific parameter and technology stack you are targeting.\n\n"
            )
        base = f'''PENETRATION TEST — Active Reasoning Session
Turn: {turn + 1} of {max_turns}

TARGET:
  URL: {injection_point.get("url", "")}
  Parameter: {injection_point.get("param_name", "")} ({injection_point.get("param_type", "")})
  Method: {injection_point.get("method", "")}
  Technologies: {target_model.get("technologies", [])}
  WAF: {target_model.get("waf_detected", "not detected")}
  Backend: {target_model.get("database_hint") or target_model.get("backend_language") or "unknown"}

ACTIVE HYPOTHESIS: {hypothesis_node.data.get("hypothesis", "")}
ATTACK CHAIN: {hypothesis_node.data.get("attack_chain", "initial hypothesis — no parent finding")}

{memory_string}

LATEST OBSERVATION:
{json.dumps(profile.to_prompt_dict(), indent=2)}

{rag_section}Respond with a JSON object containing exactly these keys:
{{
  "observation": "one sentence: what this response tells you",
  "updated_hypothesis": "your current precise model of the vulnerability",
  "confirmed_facts": ["list of new facts confirmed by this response"],
  "refuted_facts": ["list of beliefs this response disproves"],
  "next_probe": "the exact string to inject — nothing else, no explanation",
  "probe_rationale": "why this specific string tests your updated hypothesis",
  "confidence": integer 0-100,
  "terminal": false,
  "exploitation_confirmed": false,
  "exploitation_evidence": null,
  "terminal_reason": null
}}

Set terminal=true when: exploitation is confirmed with clear evidence,
or the hypothesis is definitively ruled out, or you have tried all
viable approaches. When terminal=true and exploitation_confirmed=true,
set exploitation_evidence to a dict with keys:
  proof_type: "error_based" | "boolean_based" | "time_based" | "reflected" | "rce" | "data_extracted"
  extracted_data: string of what was extracted (version, user, etc.)
  payload_used: the exact payload that confirmed exploitation
  severity: "critical" | "high" | "medium" | "low"'''
        note = self._pending_recovery_message or quality_recovery_message
        if note:
            base = base + "\n\nQUALITY RECOVERY NOTE:\n" + note
            self._pending_recovery_message = None
        return base

    def _build_probe_recovery_prompt(
        self,
        hypothesis_node: Node,
        target_model: dict[str, Any],
        memory: ConversationMemory,
        turn: int,
        max_turns: int,
        override_message: dict[str, str],
        quality_recovery_message: str,
        rag_context: str = "",
    ) -> str:
        fake_profile = type("Profile", (), {"to_prompt_dict": lambda _self: {"error": "duplicate_probe"}})()
        prompt = self._build_prompt(
            turn,
            max_turns,
            hypothesis_node.data.get("injection_point", {}),
            target_model,
            hypothesis_node,
            memory.render_for_prompt(token_budget=3000),
            fake_profile,
            quality_recovery_message,
            rag_context=rag_context,
        )
        return prompt + "\n\nSYSTEM OVERRIDE:\n" + json.dumps(override_message)

    def _build_finding_node(self, hypothesis_node: Node, memory: ConversationMemory, llm_response: dict[str, Any], graph: AttackGraph) -> Node | None:
        exploitation_evidence = llm_response.get("exploitation_evidence")

        VALID_PROOF_TYPES = {"error_based", "boolean_based", "time_based", "reflected", "rce", "data_extracted"}
        VALID_SEVERITIES = {"critical", "high", "medium", "low"}

        if not isinstance(exploitation_evidence, dict):
            graph.resolve_hypothesis(hypothesis_node.id, NodeType.DEAD_END)
            logger.warning(
                "Exploitation claimed but evidence is not a dict — rejecting finding hypothesis=%s",
                hypothesis_node.id,
            )
            return None

        proof_type = str(exploitation_evidence.get("proof_type", "")).strip().lower()
        severity = str(exploitation_evidence.get("severity", "")).strip().lower()
        payload_used = str(exploitation_evidence.get("payload_used", "")).strip()

        if proof_type not in VALID_PROOF_TYPES:
            graph.resolve_hypothesis(hypothesis_node.id, NodeType.DEAD_END)
            logger.warning("Invalid proof_type '%s' — rejecting finding", proof_type)
            return None

        if severity not in VALID_SEVERITIES:
            exploitation_evidence["severity"] = "medium"

        if not payload_used:
            graph.resolve_hypothesis(hypothesis_node.id, NodeType.DEAD_END)
            logger.warning(
                "Exploitation claimed but no payload_used — rejecting finding hypothesis=%s",
                hypothesis_node.id,
            )
            return None

        if not memory.confirmed_facts:
            graph.resolve_hypothesis(hypothesis_node.id, NodeType.DEAD_END)
            logger.warning(
                "Exploitation claimed but no confirmed_facts accumulated — rejecting finding hypothesis=%s",
                hypothesis_node.id,
            )
            return None

        finding = Node(
            id=str(uuid.uuid4()),
            type=NodeType.FINDING,
            content=hypothesis_node.data.get("hypothesis", ""),
            depth=hypothesis_node.depth + 1,
            confidence=float(llm_response.get("confidence", 0)) / 100.0,
            data={
                "hypothesis": hypothesis_node.data.get("hypothesis"),
                "owasp_category": hypothesis_node.data.get("owasp_category"),
                "owasp_impact": hypothesis_node.data.get("owasp_impact", 5),
                "exploitation_evidence": exploitation_evidence,
                "confirmed_facts": list(memory.confirmed_facts),
                "injection_point": hypothesis_node.data.get("injection_point"),
                "turn_count": memory.turn_count,
            },
        )
        graph.add_node(finding)
        graph.add_edge(Edge(source_id=hypothesis_node.id, target_id=finding.id, type=EdgeType.CONFIRMED))
        graph.resolve_hypothesis(hypothesis_node.id, NodeType.FINDING)
        return finding

    def _build_injection_point(self, injection_point_data: dict[str, Any]) -> Any | None:
        try:
            return ProbeExecutor.build_injection_point(injection_point_data)
        except ValueError as exc:
            logger.error("Invalid injection point payload: %s", exc)
            return None

    def _charge(self, component: str, prompt: str) -> bool:
        tokens = estimate_tokens(prompt)
        try:
            return bool(self.ledger.charge(tokens, component=component))
        except TypeError:
            return bool(self.ledger.charge(component, tokens))

    @staticmethod
    def _unpack_query_result(raw_result: Any) -> Any | None:
        if raw_result is None:
            return None
        if isinstance(raw_result, tuple) and len(raw_result) == 2:
            payload, err = raw_result
            if err:
                return None
            return payload
        return raw_result

    @staticmethod
    def _normalize_llm_response(payload: Any) -> dict[str, Any] | None:
        if payload is None:
            return None
        if not isinstance(payload, dict):
            return dict(_DEFAULTS)

        out = dict(_DEFAULTS)
        out.update(payload)

        if not isinstance(out.get("confirmed_facts"), list):
            out["confirmed_facts"] = []
        if not isinstance(out.get("refuted_facts"), list):
            out["refuted_facts"] = []

        out["confidence"] = max(0, min(100, int(out.get("confidence", 0))))
        out["terminal"] = _parse_bool(out.get("terminal", False), default=False)
        out["exploitation_confirmed"] = _parse_bool(out.get("exploitation_confirmed", False), default=False)

        for key in ["observation", "updated_hypothesis", "next_probe", "probe_rationale", "terminal_reason"]:
            val = out.get(key)
            out[key] = "" if val is None else str(val)

        return out
