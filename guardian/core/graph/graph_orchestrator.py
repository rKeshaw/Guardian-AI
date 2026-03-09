from __future__ import annotations

import json
import asyncio
import logging
from typing import Any

from guardian.core.ai_client import AIPersona, estimate_tokens
from guardian.core.config import settings
from guardian.core.graph.attack_graph import AttackGraph, Edge, EdgeType, Node, NodeType
from guardian.core.graph.priority_queue import HypothesisPriorityQueue
from guardian.core.token_ledger import TokenLedger

logger = logging.getLogger(__name__)

def _score_node(node: Node) -> float:
    impact = float(node.data.get("owasp_impact", 5)) / 10.0
    depth_decay = 1.0 / (1.0 + node.depth * 0.15)
    confidence = float(node.confidence)
    return confidence * 0.45 + impact * 0.40 + depth_decay * 0.15

class GraphOrchestrator:
    def __init__(self, ai_client, comprehender, db) -> None:
        self.ai_client = ai_client
        self.comprehender = comprehender
        self.db = db
        self._priority_queue: HypothesisPriorityQueue | None = None

    async def run(
        self,
        session_id: str,
        target_model: dict,
        graph: AttackGraph,
        probe_executor,
        ledger: TokenLedger,
    ) -> AttackGraph:
        from guardian.agents.hypothesis_agent import HypothesisAgent
        from guardian.core.intelligence.reasoning_agent import ReasoningAgent

        hypothesis_agent = HypothesisAgent(self.db, self.ai_client)
        reasoning_agent = ReasoningAgent(self.ai_client, self.comprehender, probe_executor, ledger)

        persisted_ids: set[str] = set()
        self._priority_queue = None

        while graph.frontier and not ledger.is_critical():
            max_graph_tokens = int(settings.MAX_GRAPH_TOKENS)
            compress_threshold = float(settings.GRAPH_COMPRESS_THRESHOLD)
            threshold_tokens = max_graph_tokens * compress_threshold
            if graph.token_cost() > threshold_tokens:
                await self._compress_graph(graph, ledger)

            hypothesis_node = self._select_next(graph)
            if hypothesis_node is None:
                break

            logger.info(
                "Exploring hypothesis id=%s confidence=%.2f owasp=%s",
                hypothesis_node.id,
                hypothesis_node.confidence,
                hypothesis_node.data.get("owasp_category"),
            )

            await self.db.upsert_node(graph.graph_id, hypothesis_node.to_dict())
            persisted_ids.add(hypothesis_node.id)

            remaining = ledger.remaining()
            score = _score_node(hypothesis_node)
            cap = int(remaining * 0.20)
            allocated = max(2000, min(int(remaining * 0.20 * score), cap if cap > 0 else 0))
            hypothesis_budget = ledger.allocate_sub_budget(allocated, "hypothesis_exploration")

            reasoning_agent.ledger = hypothesis_budget
            finding = await reasoning_agent.explore(hypothesis_node, target_model, graph)
            hypothesis_budget.release()

            if finding is not None:
                try:
                    graph.resolve_hypothesis(hypothesis_node.id, NodeType.FINDING)
                except Exception:
                    pass
                persisted_ids.discard(hypothesis_node.id)
                await self._expand_from_finding(
                    finding=finding,
                    graph=graph,
                    target_model=target_model,
                    ledger=ledger,
                    hypothesis_agent=hypothesis_agent,
                )
                persisted_ids.discard(finding.id)
                await self.db.upsert_node(graph.graph_id, finding.to_dict())
                persisted_ids.add(finding.id)
            elif hypothesis_node.id in graph.frontier:
                # Defensive fallback in case exploration returned without resolving state.
                try:
                    graph.resolve_hypothesis(hypothesis_node.id, NodeType.DEAD_END)
                except Exception:
                    pass
                persisted_ids.discard(hypothesis_node.id)

            for node_id, node in graph.nodes.items():
                if node_id not in persisted_ids:
                    await self.db.upsert_node(graph.graph_id, node.to_dict())
                    persisted_ids.add(node_id)

            if hasattr(self.db, "upsert_edge"):
                for edge in graph.edges:
                    try:
                        await self.db.upsert_edge(graph.graph_id, edge.as_dict())
                    except Exception:
                        break

            await self.db.upsert_graph_meta(
                graph.graph_id,
                {
                    "session_id": session_id,
                    "stats": graph.stats(),
                    "frontier_size": len(graph.frontier),
                },
            )
        logger.debug("Token budget: %s", ledger.render_breakdown())
        return graph

    def _select_next(self, graph: AttackGraph) -> Node | None:
        active = graph.get_active_hypotheses()
        if not active:
            return None

        queue_threshold = 50
        if len(active) >= queue_threshold:
            if self._priority_queue is None:
                self._priority_queue = HypothesisPriorityQueue(active)
            else:
                existing_ids = self._priority_queue._ids
                for node in active:
                    if node.id not in existing_ids:
                        self._priority_queue.push(node)

            active_ids = {node.id for node in active}
            while True:
                candidate = self._priority_queue.pop()
                if candidate is None:
                    return None
                if candidate.id in active_ids:
                    return candidate

        return max(active, key=_score_node)

    async def _expand_from_finding(
        self,
        finding: Node,
        graph: AttackGraph,
        target_model: dict,
        ledger: TokenLedger,
        hypothesis_agent,
    ) -> None:
        findings_summary = [f.data for f in graph.get_findings()]
        prompt = (
            "Confirmed finding:\n"
            f"{json.dumps(finding.data, indent=2)}\n\n"
            "Prior findings:\n"
            f"{json.dumps(findings_summary, indent=2)}\n\n"
            f"Target technologies: {target_model.get('technologies', [])}\n\n"
            "This vulnerability was confirmed. What new attack hypotheses does it unlock? "
            "Think like an attacker who just got a foothold — what can they now reach that was previously inaccessible? "
            "Each new hypothesis must: (1) logically depend on this specific finding, "
            "(2) represent a genuinely new attack path not already in the finding list, "
            "(3) include a concrete first probe. Return a JSON object with key 'new_hypotheses' "
            "containing a list of hypothesis dicts using the same schema as before."
        )

        if not self._charge(ledger, "graph_expansion", prompt):
            return

        persona = AIPersona.HYPOTHESIS_ENGINE
        raw = await self.ai_client.query_with_retry(prompt, persona=persona)
        payload = self._unpack_query_result(raw)
        if not isinstance(payload, dict):
            return

        raw_hypotheses = payload.get("new_hypotheses", [])
        if not isinstance(raw_hypotheses, list):
            return

        for item in raw_hypotheses:
            if not isinstance(item, dict):
                continue
            if not all(k in item for k in ("hypothesis", "entry_probe", "injection_point")):
                continue

            valid_list = hypothesis_agent._validate_hypotheses([item])
            if not valid_list:
                continue

            node = hypothesis_agent._to_node(valid_list[0])
            node.depth = finding.depth + 1
            node.data["attack_chain"] = f"spawned_from_finding:{finding.id}"
            graph.add_node(node)
            graph.add_edge(Edge(source_id=finding.id, target_id=node.id, type=EdgeType.SPAWNED))
            logger.info("Spawned new hypothesis from finding finding_id=%s hypothesis=%s", finding.id, node.content)

    async def _compress_graph(self, graph: AttackGraph, ledger: TokenLedger) -> None:
        max_graph_tokens = int(settings.MAX_GRAPH_TOKENS)
        compress_threshold = float(settings.GRAPH_COMPRESS_THRESHOLD)
        threshold_tokens = max_graph_tokens * compress_threshold
        target_cost = threshold_tokens * 0.5

        for idx, node in enumerate(graph.compressible_nodes()[:10], start=1):
            loop = asyncio.get_running_loop()
            unit = await loop.run_in_executor(
                None,
                self.comprehender.compress,
                json.dumps(node.data, sort_keys=True),
                node.type.value,
            )
            content = str(unit.get("content", ""))
            facts = list(unit.get("irreducible_facts", []))
            compressed_tokens = estimate_tokens(content)

            graph.mark_compressed(
                node.id,
                {
                    "compressed_summary": content,
                    "irreducible_facts": facts,
                },
                compressed_tokens,
            )

            if graph.token_cost() <= target_cost:
                break

            if idx >= 10:
                break

    @staticmethod
    def _charge(ledger: TokenLedger, component: str, prompt: str) -> bool:
        tokens = estimate_tokens(prompt)
        try:
            return bool(ledger.charge(tokens, component=component))
        except TypeError:
            return bool(ledger.charge(component, tokens))

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
