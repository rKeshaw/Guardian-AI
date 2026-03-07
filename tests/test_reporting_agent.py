from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from guardian.agents.reporting_agent import ReportingAgent
from guardian.core.graph.attack_graph import AttackGraph, Edge, EdgeType, Node, NodeType
from guardian.core.token_ledger import TokenLedger


def _make_agent(ai_payload):
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(return_value=(ai_payload, None))
    return ReportingAgent(db=None, ai_client=ai_client)


@pytest.mark.anyio
async def test_empty_graph_produces_clean_report():
    graph = AttackGraph()
    agent = _make_agent({"risk_overview": "none", "key_findings": [], "business_impact": "low", "immediate_actions": []})

    report = await agent.generate(graph, {"reconnaissance": {"url": "https://target"}}, "s1", TokenLedger(total=10000))

    assert report["scan_metadata"]["total_findings"] == 0


def test_cvss_rce_vector_correct():
    agent = _make_agent({})
    vector, score = agent.compute_cvss(
        owasp_category="A03:2023",
        proof_type="rce",
        exploitation_confirmed=True,
        auth_required=False,
    )

    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert score == 10.0


def test_cvss_reflected_xss_vector_correct():
    agent = _make_agent({})
    vector, score = agent.compute_cvss(
        owasp_category="xss",
        proof_type="reflected",
        exploitation_confirmed=True,
        auth_required=False,
    )

    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
    assert score == pytest.approx(4.3, abs=0.1)


@pytest.mark.anyio
async def test_reasoning_chain_in_poc():
    graph = AttackGraph()
    h = Node(id="h1", type=NodeType.HYPOTHESIS, content="hyp", data={"hypothesis": "SQLi", "owasp_category": "A03:2023"})
    p = Node(id="p1", type=NodeType.PROBE, content="' OR 1=1--", data={"probe": "' OR 1=1--"})
    f = Node(
        id="f1",
        type=NodeType.FINDING,
        content="finding",
        data={
            "hypothesis": "SQLi",
            "owasp_category": "A03:2023",
            "exploitation_evidence": {"proof_type": "error_based", "severity": "high"},
            "confirmed_facts": ["mysql_error"],
            "injection_point": {"url": "https://t", "method": "GET", "param_name": "q", "param_type": "query"},
        },
    )
    graph.add_node(h)
    graph.add_node(p)
    graph.add_node(f)
    graph.add_edge(Edge(source_id="h1", target_id="p1", type=EdgeType.GENERATED))
    graph.add_edge(Edge(source_id="p1", target_id="f1", type=EdgeType.CONFIRMED))

    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(side_effect=[
        ({"risk_overview": "x", "key_findings": [], "business_impact": "x", "immediate_actions": []}, None),
        (None, "bad"),
    ])

    agent = ReportingAgent(db=None, ai_client=ai_client)
    report = await agent.generate(graph, {"reconnaissance": {"url": "https://target"}}, "s1", TokenLedger(total=10000))

    assert report["technical_findings"]
    poc = report["technical_findings"][0]["proof_of_concept"]
    assert "' OR 1=1--" in poc
