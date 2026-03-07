from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from guardian.core.graph.attack_graph import AttackGraph, Node, NodeType
from guardian.core.graph.graph_orchestrator import GraphOrchestrator
from guardian.core.token_ledger import TokenLedger


def _hypothesis_node(node_id: str, confidence: float = 0.6, impact: int = 5, depth: int = 0) -> Node:
    return Node(
        id=node_id,
        type=NodeType.HYPOTHESIS,
        content=f"hyp-{node_id}",
        confidence=confidence,
        depth=depth,
        data={
            "hypothesis": f"hypothesis {node_id}",
            "owasp_category": "A03:2023",
            "owasp_impact": impact,
            "entry_probe": "'",
            "injection_point": {
                "url": f"https://target.com/{node_id}",
                "method": "GET",
                "param_name": "q",
                "param_type": "query",
            },
        },
        token_estimate=200,
    )


def _finding_node(node_id: str = "finding-1") -> Node:
    return Node(
        id=node_id,
        type=NodeType.FINDING,
        content="finding",
        confidence=0.95,
        depth=1,
        data={
            "hypothesis": "confirmed hypothesis",
            "owasp_category": "A03:2023",
            "owasp_impact": 9,
            "injection_point": {
                "url": "https://target.com/search",
                "method": "GET",
                "param_name": "q",
                "param_type": "query",
            },
        },
    )


class DummyDB:
    def __init__(self) -> None:
        self.upsert_node = AsyncMock()
        self.upsert_graph_meta = AsyncMock()
        self.upsert_edge = AsyncMock()


@pytest.mark.anyio
async def test_single_hypothesis_finding_triggers_expansion(monkeypatch):
    db = DummyDB()
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(
        return_value=(
            {
                "new_hypotheses": [
                    {
                        "hypothesis": "post-exploitation 1",
                        "owasp_category": "A01:2023",
                        "owasp_impact": 8,
                        "evidence_for": ["finding evidence"],
                        "evidence_against": [],
                        "entry_probe": "../../etc/passwd",
                        "expected_if_vulnerable": "file contents",
                        "expected_if_not_vulnerable": "403",
                        "confidence": 70,
                        "injection_point": {
                            "url": "https://target.com/admin",
                            "method": "GET",
                            "param_name": "path",
                            "param_type": "query",
                        },
                    },
                    {
                        "hypothesis": "post-exploitation 2",
                        "owasp_category": "A05:2023",
                        "owasp_impact": 9,
                        "evidence_for": ["finding evidence"],
                        "evidence_against": [],
                        "entry_probe": "{{7*7}}",
                        "expected_if_vulnerable": "49",
                        "expected_if_not_vulnerable": "literal",
                        "confidence": 75,
                        "injection_point": {
                            "url": "https://target.com/render",
                            "method": "POST",
                            "param_name": "tpl",
                            "param_type": "form",
                        },
                    },
                ]
            },
            None,
        )
    )

    class FakeReasoningAgent:
        def __init__(self, *args, **kwargs):
            self.explore = AsyncMock(return_value=_finding_node())

    monkeypatch.setattr("guardian.core.intelligence.reasoning_agent.ReasoningAgent", FakeReasoningAgent)

    graph = AttackGraph()
    graph.add_node(_hypothesis_node("h1"))

    orchestrator = GraphOrchestrator(ai_client=ai_client, comprehender=SimpleNamespace(compress=lambda c, s: {"content": c, "irreducible_facts": []}), db=db)
    ledger = TokenLedger(total=100000)

    original_expand = orchestrator._expand_from_finding

    async def expand_once_then_stop(*args, **kwargs):
        await original_expand(*args, **kwargs)
        ledger.used = int(ledger.total * 0.95)

    orchestrator._expand_from_finding = expand_once_then_stop

    out = await orchestrator.run("s1", {"technologies": ["php"]}, graph, probe_executor=SimpleNamespace(), ledger=ledger)

    assert len(out.frontier) == 2
    assert len(out.get_findings()) >= 1


@pytest.mark.anyio
async def test_dead_end_not_expanded(monkeypatch):
    db = DummyDB()
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(return_value=None)

    class FakeReasoningAgent:
        def __init__(self, *args, **kwargs):
            self.explore = AsyncMock(return_value=None)

    monkeypatch.setattr("guardian.core.intelligence.reasoning_agent.ReasoningAgent", FakeReasoningAgent)

    graph = AttackGraph()
    graph.add_node(_hypothesis_node("h1"))

    orchestrator = GraphOrchestrator(ai_client=ai_client, comprehender=SimpleNamespace(compress=lambda c, s: {"content": c, "irreducible_facts": []}), db=db)
    await orchestrator.run("s1", {"technologies": ["php"]}, graph, probe_executor=SimpleNamespace(), ledger=TokenLedger(total=100000))

    ai_client.query_with_retry.assert_not_called()


@pytest.mark.anyio
async def test_critical_budget_stops_loop(monkeypatch):
    db = DummyDB()
    ai_client = SimpleNamespace()

    class FakeReasoningAgent:
        def __init__(self, *args, **kwargs):
            self.explore = AsyncMock(return_value=None)

    monkeypatch.setattr("guardian.core.intelligence.reasoning_agent.ReasoningAgent", FakeReasoningAgent)

    graph = AttackGraph()
    graph.add_node(_hypothesis_node("h1"))

    ledger = TokenLedger(total=100)
    assert ledger.charge(91) is True

    orchestrator = GraphOrchestrator(ai_client=ai_client, comprehender=SimpleNamespace(compress=lambda c, s: {"content": c, "irreducible_facts": []}), db=db)
    await orchestrator.run("s1", {}, graph, probe_executor=SimpleNamespace(), ledger=ledger)

    db.upsert_node.assert_not_called()


@pytest.mark.anyio
async def test_compression_triggered_at_threshold(monkeypatch):
    db = DummyDB()

    class FakeReasoningAgent:
        def __init__(self, *args, **kwargs):
            self.explore = AsyncMock(return_value=None)

    monkeypatch.setattr("guardian.core.intelligence.reasoning_agent.ReasoningAgent", FakeReasoningAgent)

    graph = AttackGraph()
    for i in range(12):
        graph.add_node(_hypothesis_node(f"h{i}"))
        graph.nodes[f"h{i}"].token_estimate = 2000

    orchestrator = GraphOrchestrator(
        ai_client=SimpleNamespace(),
        comprehender=SimpleNamespace(compress=lambda c, s: {"content": c[:50], "irreducible_facts": []}),
        db=db,
    )
    orchestrator._compress_graph = AsyncMock(side_effect=orchestrator._compress_graph)

    await orchestrator.run("s1", {}, graph, probe_executor=SimpleNamespace(), ledger=TokenLedger(total=100000))

    assert orchestrator._compress_graph.call_count >= 1


def test_select_next_prefers_high_impact():
    orchestrator = GraphOrchestrator(ai_client=SimpleNamespace(), comprehender=SimpleNamespace(), db=DummyDB())
    graph = AttackGraph()

    n1 = _hypothesis_node("a", confidence=0.4, impact=9)
    n2 = _hypothesis_node("b", confidence=0.9, impact=2)

    graph.add_node(n1)
    graph.add_node(n2)

    selected = orchestrator._select_next(graph)

    # score(a)=0.4*0.45 + 0.9*0.4 + 1*0.15 = 0.69
    # score(b)=0.9*0.45 + 0.2*0.4 + 1*0.15 = 0.635
    assert selected is not None
    assert selected.id == "a"


@pytest.mark.anyio
async def test_graph_persisted_after_exploration(monkeypatch):
    db = DummyDB()

    class FakeReasoningAgent:
        def __init__(self, *args, **kwargs):
            self.explore = AsyncMock(return_value=None)

    monkeypatch.setattr("guardian.core.intelligence.reasoning_agent.ReasoningAgent", FakeReasoningAgent)

    graph = AttackGraph()
    graph.add_node(_hypothesis_node("h1"))

    orchestrator = GraphOrchestrator(ai_client=SimpleNamespace(), comprehender=SimpleNamespace(compress=lambda c, s: {"content": c, "irreducible_facts": []}), db=db)
    await orchestrator.run("s1", {}, graph, probe_executor=SimpleNamespace(), ledger=TokenLedger(total=100000))

    assert db.upsert_node.call_count >= 1
    assert db.upsert_graph_meta.call_count >= 1
