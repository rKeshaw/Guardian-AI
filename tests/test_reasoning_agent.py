from __future__ import annotations

import difflib
import sys
import types
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from guardian.core.graph.attack_graph import AttackGraph, Node, NodeType
from guardian.core.intelligence.reasoning_agent import ReasoningAgent
from guardian.core.memory.semantic_unit import SemanticUnit
from guardian.core.token_ledger import TokenLedger


@dataclass
class ProbeResult:
    status_code: int = 200
    body: str = "ok"
    response_time_ms: float = 100.0
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None


class ProbeExecutorModuleDouble:
    @staticmethod
    def compute_delta(current: ProbeResult, baseline: ProbeResult | None) -> dict:
        base = baseline or ProbeResult(status_code=0, body="", response_time_ms=0)
        added_lines = [
            line[2:]
            for line in difflib.ndiff(base.body.splitlines(), current.body.splitlines())
            if line.startswith("+ ")
        ]
        return {
            "status_code": current.status_code,
            "status_changed": current.status_code != base.status_code,
            "baseline_status": base.status_code,
            "body_length": len(current.body),
            "length_delta": len(current.body) - len(base.body),
            "length_ratio": (len(current.body) / len(base.body)) if len(base.body) else 0.0,
            "response_time_ms": current.response_time_ms,
            "time_delta_ms": current.response_time_ms - base.response_time_ms,
            "new_content": "\n".join(added_lines),
            "new_headers": {k: v for k, v in current.headers.items() if k not in base.headers},
        }


# make import path used by ResponseAnalyzer available
probing_pkg = types.ModuleType("guardian.core.probing")
probe_module = types.ModuleType("guardian.core.probing.probe_executor")
probe_module.ProbeExecutor = ProbeExecutorModuleDouble
sys.modules["guardian.core.probing"] = probing_pkg
sys.modules["guardian.core.probing.probe_executor"] = probe_module


class ProbeExecutorRuntimeDouble:
    def __init__(self) -> None:
        self._baseline = ProbeResult(status_code=200, body="baseline", response_time_ms=100)
        self.capture_baseline = AsyncMock(return_value=self._baseline)
        self.fire = AsyncMock(return_value=ProbeResult(status_code=200, body="baseline\nYou have an error in your SQL syntax"))

    def get_baseline(self, injection_point):
        return self._baseline


def _make_hypothesis_node() -> Node:
    return Node(
        id="hyp-1",
        type=NodeType.HYPOTHESIS,
        content="sqli hyp",
        depth=0,
        confidence=0.6,
        data={
            "hypothesis": "The q parameter is SQL injectable",
            "owasp_category": "A03:2023",
            "owasp_impact": 9,
            "entry_probe": "'",
            "injection_point": {
                "url": "https://target.com/search",
                "method": "GET",
                "param_name": "q",
                "param_type": "query",
            },
        },
    )


def _make_comprehender(duplicate_always: bool = False):
    c = SimpleNamespace()
    c.is_near_duplicate = AsyncMock(side_effect=lambda probe, tried: duplicate_always or (probe in tried))

    async def compress_async(content, content_type, probe_sent, ai_client, token_ledger):
        unit = SemanticUnit.from_raw(content, content_type)
        unit.irreducible_facts = ["mysql_error"] if "SQL" in content or "sql" in content.lower() else []
        return unit

    c.compress_async = AsyncMock(side_effect=compress_async)
    c.compress_episode = AsyncMock(side_effect=lambda turns, confirmed_facts, ai_client, token_ledger: SemanticUnit.from_raw("episode", "episode"))
    return c


@pytest.mark.anyio
async def test_terminal_finding_creates_finding_node():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(return_value=({
        "terminal": True,
        "exploitation_confirmed": True,
        "confidence": 95,
        "next_probe": "",
        "exploitation_evidence": {"proof_type": "error_based"},
    }, None))

    agent = ReasoningAgent(ai_client, _make_comprehender(), ProbeExecutorRuntimeDouble(), TokenLedger(total=100000))
    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)

    finding = await agent.explore(hyp, {}, graph)

    assert finding is not None
    assert finding.type == NodeType.FINDING
    assert any(n.type == NodeType.FINDING for n in graph.nodes.values())


@pytest.mark.anyio
async def test_terminal_dead_end_returns_none():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(return_value=({
        "terminal": True,
        "exploitation_confirmed": False,
        "confidence": 10,
        "next_probe": "",
    }, None))

    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)
    agent = ReasoningAgent(ai_client, _make_comprehender(), ProbeExecutorRuntimeDouble(), TokenLedger(total=100000))

    out = await agent.explore(hyp, {}, graph)

    assert out is None
    assert graph.nodes[hyp.id].type == NodeType.DEAD_END


@pytest.mark.anyio
async def test_loop_continues_on_non_terminal():
    responses = [
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": "p2"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 30, "next_probe": "p3"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 40, "next_probe": "p4"}, None),
        ({"terminal": True, "exploitation_confirmed": True, "confidence": 90, "next_probe": "", "exploitation_evidence": {}}, None),
    ]
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(side_effect=responses)

    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)
    agent = ReasoningAgent(ai_client, _make_comprehender(), ProbeExecutorRuntimeDouble(), TokenLedger(total=100000))

    out = await agent.explore(hyp, {}, graph)

    assert out is not None
    assert ai_client.query_with_retry.call_count == 4


@pytest.mark.anyio
async def test_duplicate_probe_triggers_recovery():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(side_effect=[
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": "'"}, None),
        ({"next_probe": "'"}, None),
    ])

    probe_exec = ProbeExecutorRuntimeDouble()
    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)
    agent = ReasoningAgent(ai_client, _make_comprehender(), probe_exec, TokenLedger(total=100000))

    out = await agent.explore(hyp, {}, graph)

    assert out is None
    assert probe_exec.fire.call_count < 3


@pytest.mark.anyio
async def test_memory_overflow_triggers_episode_compression():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(side_effect=[
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": "p2"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": "p3"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": "p4"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": "p5"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": "p6"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": ""}, None),
    ])

    comprehender = _make_comprehender()
    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)
    agent = ReasoningAgent(ai_client, comprehender, ProbeExecutorRuntimeDouble(), TokenLedger(total=100000))

    await agent.explore(hyp, {}, graph)

    assert comprehender.compress_episode.call_count >= 1


@pytest.mark.anyio
async def test_graph_nodes_added_per_turn():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(side_effect=[
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": "p2"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 30, "next_probe": "p3"}, None),
        ({"terminal": False, "exploitation_confirmed": False, "confidence": 40, "next_probe": ""}, None),
    ])

    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)
    agent = ReasoningAgent(ai_client, _make_comprehender(), ProbeExecutorRuntimeDouble(), TokenLedger(total=100000))

    await agent.explore(hyp, {}, graph)

    probe_count = sum(1 for n in graph.nodes.values() if n.type == NodeType.PROBE)
    obs_count = sum(1 for n in graph.nodes.values() if n.type == NodeType.OBSERVATION)
    assert probe_count >= 3
    assert obs_count >= 3


@pytest.mark.anyio
async def test_budget_exhaustion_terminates_loop():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(return_value=({"terminal": False, "next_probe": "x"}, None))

    probe_exec = ProbeExecutorRuntimeDouble()
    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)
    agent = ReasoningAgent(ai_client, _make_comprehender(), probe_exec, TokenLedger(total=1))

    out = await agent.explore(hyp, {}, graph)

    assert out is None
    assert ai_client.query_with_retry.call_count == 0
