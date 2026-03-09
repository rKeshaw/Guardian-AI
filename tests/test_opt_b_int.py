from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from guardian.core.config import settings
from guardian.core.graph.attack_graph import AttackGraph, Node, NodeType
from guardian.core.intelligence.reasoning_agent import ReasoningAgent
from guardian.core.probing.probe_executor import ProbeResult
from guardian.core.token_ledger import TokenLedger


@dataclass
class ProbeExecutorRuntimeDouble:
    baseline: ProbeResult = field(
        default_factory=lambda: ProbeResult(
            status_code=200,
            body="baseline",
            headers={},
            response_time_ms=100.0,
            url_sent="https://target.com/search",
            method="GET",
            param_injected="q",
            probe_value="baseline",
            error=None,
        )
    )

    def __post_init__(self):
        self.capture_baseline = AsyncMock(return_value=self.baseline)
        self.fire = AsyncMock(
            return_value=ProbeResult(
                status_code=200,
                body="baseline\nSQL syntax error",
                headers={},
                response_time_ms=110.0,
                url_sent="https://target.com/search",
                method="GET",
                param_injected="q",
                probe_value="'",
                error=None,
            )
        )

    def get_baseline(self, injection_point):
        return self.baseline


def _make_comprehender():
    c = SimpleNamespace()
    c.is_near_duplicate = AsyncMock(return_value=False)
    c.compress_async = AsyncMock(
        return_value=SimpleNamespace(
            content="compressed obs",
            irreducible_facts=["sql_error"],
            token_count=10,
        )
    )
    c.compress_episode = AsyncMock(return_value=SimpleNamespace(content="episode", token_count=10))
    return c


def _make_hypothesis_node() -> Node:
    return Node(
        id="hyp-option-b",
        type=NodeType.HYPOTHESIS,
        content="SQLi hypothesis",
        data={
            "hypothesis": "SQL Injection in q",
            "owasp_category": "A03:2023",
            "entry_probe": "'",
            "injection_point": {
                "url": "https://target.com/search",
                "method": "GET",
                "param_name": "q",
                "param_type": "query",
            },
        },
    )


@pytest.mark.anyio
async def test_option_b_disabled_does_not_call_rag_helper(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", False)

    from guardian.core.intelligence import rag_helper as rag_module

    call_counter = {"count": 0}

    def _fake_rag(*args, **kwargs):
        call_counter["count"] += 1
        return "ignored"

    monkeypatch.setattr(rag_module.rag_helper, "get_probe_context", _fake_rag)

    prompts: list[str] = []

    async def _query(prompt, persona=None, max_retries=2):
        prompts.append(prompt)
        return ({"terminal": False, "exploitation_confirmed": False, "confidence": 20, "next_probe": ""}, None)

    ai_client = SimpleNamespace(query_with_retry=AsyncMock(side_effect=_query))
    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)

    agent = ReasoningAgent(ai_client, _make_comprehender(), ProbeExecutorRuntimeDouble(), TokenLedger(total=100000))
    await agent.explore(hyp, {}, graph)

    assert call_counter["count"] == 0
    assert prompts


@pytest.mark.anyio
async def test_option_b_enabled_includes_attack_knowledge_context_in_prompt(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", True)

    from guardian.core.intelligence import rag_helper as rag_module

    rag_text = "=== RELEVANT ATTACK KNOWLEDGE (from PayloadsAllTheThings) ===\nSQLi payloads\n=== END KNOWLEDGE CONTEXT ==="
    monkeypatch.setattr(rag_module.rag_helper, "get_probe_context", lambda *args, **kwargs: rag_text)

    captured_prompts: list[str] = []

    async def _query(prompt, persona=None, max_retries=2):
        captured_prompts.append(prompt)
        return ({"terminal": False, "exploitation_confirmed": False, "confidence": 30, "next_probe": ""}, None)

    ai_client = SimpleNamespace(query_with_retry=AsyncMock(side_effect=_query))
    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)

    agent = ReasoningAgent(ai_client, _make_comprehender(), ProbeExecutorRuntimeDouble(), TokenLedger(total=100000))
    await agent.explore(hyp, {}, graph)

    assert captured_prompts
    assert "ATTACK KNOWLEDGE CONTEXT" in captured_prompts[0]
    assert rag_text in captured_prompts[0]


@pytest.mark.anyio
async def test_option_b_enabled_with_empty_rag_context_keeps_prompt_without_rag_block(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", True)

    from guardian.core.intelligence import rag_helper as rag_module

    monkeypatch.setattr(rag_module.rag_helper, "get_probe_context", lambda *args, **kwargs: "")

    captured_prompts: list[str] = []

    async def _query(prompt, persona=None, max_retries=2):
        captured_prompts.append(prompt)
        return ({"terminal": False, "exploitation_confirmed": False, "confidence": 25, "next_probe": ""}, None)

    ai_client = SimpleNamespace(query_with_retry=AsyncMock(side_effect=_query))
    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)

    agent = ReasoningAgent(ai_client, _make_comprehender(), ProbeExecutorRuntimeDouble(), TokenLedger(total=100000))
    result = await agent.explore(hyp, {}, graph)

    assert result is None
    assert captured_prompts
    assert "ATTACK KNOWLEDGE CONTEXT" not in captured_prompts[0]


@pytest.mark.anyio
async def test_option_b_insufficient_ledger_budget_drops_rag_context_and_logs_warning(monkeypatch, caplog):
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", True)

    from guardian.core.intelligence import rag_helper as rag_module

    rag_text = "R" * 400
    monkeypatch.setattr(rag_module.rag_helper, "get_probe_context", lambda *args, **kwargs: rag_text)

    captured_prompts: list[str] = []

    async def _query(prompt, persona=None, max_retries=2):
        captured_prompts.append(prompt)
        return ({"terminal": False, "exploitation_confirmed": False, "confidence": 25, "next_probe": ""}, None)

    ai_client = SimpleNamespace(query_with_retry=AsyncMock(side_effect=_query))
    graph = AttackGraph()
    hyp = _make_hypothesis_node()
    graph.add_node(hyp)

    caplog.set_level("WARNING")
    agent = ReasoningAgent(ai_client, _make_comprehender(), ProbeExecutorRuntimeDouble(), TokenLedger(total=1))
    await agent.explore(hyp, {}, graph)

    assert ai_client.query_with_retry.call_count == 0
    assert any("Insufficient token budget for RAG context" in rec.message for rec in caplog.records)
