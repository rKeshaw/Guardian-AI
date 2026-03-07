from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from guardian.agents.hypothesis_agent import HypothesisAgent
from guardian.core.graph.attack_graph import AttackGraph, NodeType
from guardian.core.token_ledger import TokenLedger


def _valid_hypothesis(confidence: int = 72, text: str = "SQLi hypothesis") -> dict:
    return {
        "hypothesis": text,
        "owasp_category": "A03:2023",
        "owasp_impact": 9,
        "evidence_for": ["MySQL signature observed"],
        "evidence_against": ["WAF header present"],
        "entry_probe": "'",
        "expected_if_vulnerable": "SQL syntax error appears",
        "expected_if_not_vulnerable": "Normal response",
        "confidence": confidence,
        "injection_point": {
            "url": "https://target.com/search",
            "method": "GET",
            "param_name": "q",
            "param_type": "query",
            "context_hint": "search parameter",
            "other_params": {},
        },
    }


def _minimal_target_model() -> dict:
    return {
        "technologies": ["nginx", "php", "mysql"],
        "injection_points": [{"url": "https://target.com/search", "param_name": "q", "method": "GET"}],
        "interesting_signals": ["x-powered-by: php"],
        "waf": "modsecurity",
    }


@pytest.mark.anyio
async def test_valid_hypothesis_becomes_node():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(
        side_effect=[
            ({"hypotheses": [_valid_hypothesis()]}, None),
            ({"missing": [], "redundant": []}, None),
        ]
    )
    agent = HypothesisAgent(db=None, ai_client=ai_client)

    graph = AttackGraph()
    ledger = TokenLedger(total=10000)

    nodes = await agent.generate(_minimal_target_model(), graph, ledger)

    assert len(nodes) == 1
    assert nodes[0].type == NodeType.HYPOTHESIS


@pytest.mark.anyio
async def test_missing_field_hypothesis_skipped():
    bad = _valid_hypothesis()
    bad.pop("entry_probe")

    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(
        side_effect=[
            ({"hypotheses": [bad]}, None),
            ({"missing": [], "redundant": []}, None),
        ]
    )
    agent = HypothesisAgent(db=None, ai_client=ai_client)

    nodes = await agent.generate(_minimal_target_model(), AttackGraph(), TokenLedger(total=10000))

    assert nodes == []


@pytest.mark.anyio
async def test_duplicate_hypotheses_deduplicated():
    low = _valid_hypothesis(confidence=60, text="low conf")
    high = _valid_hypothesis(confidence=80, text="high conf")

    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(
        side_effect=[
            ({"hypotheses": [low, high]}, None),
            ({"missing": [], "redundant": []}, None),
        ]
    )
    agent = HypothesisAgent(db=None, ai_client=ai_client)

    nodes = await agent.generate(_minimal_target_model(), AttackGraph(), TokenLedger(total=10000))

    assert len(nodes) == 1
    assert nodes[0].confidence == 0.80


@pytest.mark.anyio
async def test_confidence_normalized_to_float():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(
        side_effect=[
            ({"hypotheses": [_valid_hypothesis(confidence=75)]}, None),
            ({"missing": [], "redundant": []}, None),
        ]
    )
    agent = HypothesisAgent(db=None, ai_client=ai_client)

    nodes = await agent.generate(_minimal_target_model(), AttackGraph(), TokenLedger(total=10000))

    assert len(nodes) == 1
    assert nodes[0].confidence == 0.75


@pytest.mark.anyio
async def test_budget_exhausted_returns_empty():
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(return_value=({"hypotheses": [_valid_hypothesis()]}, None))
    agent = HypothesisAgent(db=None, ai_client=ai_client)

    ledger = TokenLedger(total=1)
    nodes = await agent.generate(_minimal_target_model(), AttackGraph(), ledger)

    assert nodes == []
    ai_client.query_with_retry.assert_not_called()


@pytest.mark.anyio
async def test_nodes_sorted_by_confidence_descending():
    h40 = _valid_hypothesis(confidence=40, text="h40")
    h90 = _valid_hypothesis(confidence=90, text="h90")
    h60 = _valid_hypothesis(confidence=60, text="h60")

    # make keys unique so dedup does not collapse them
    h90["injection_point"]["param_name"] = "id"
    h60["injection_point"]["param_name"] = "name"

    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(
        side_effect=[
            ({"hypotheses": [h40, h90, h60]}, None),
            ({"missing": [], "redundant": []}, None),
        ]
    )
    agent = HypothesisAgent(db=None, ai_client=ai_client)

    nodes = await agent.generate(_minimal_target_model(), AttackGraph(), TokenLedger(total=10000))

    assert [n.confidence for n in nodes] == [0.90, 0.60, 0.40]
