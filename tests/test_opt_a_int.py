from __future__ import annotations

import pytest

from guardian.core.config import settings
from guardian.core.database import Database
from guardian.core.graph.attack_graph import Node, NodeType
from guardian.core.orchestrator import CentralOrchestrator, ScanContext


@pytest.mark.anyio
async def test_option_a_disabled_returns_skipped_and_does_not_add_nodes(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-1", target_urls=["https://example.com"], config={})
    ctx.phase_results["reconnaissance"] = {
        "url": "https://example.com",
        "injection_points": [
            {
                "url": "https://example.com/search",
                "method": "GET",
                "param_name": "q",
                "param_type": "query",
                "context_hint": "search",
                "other_params": {},
            }
        ],
    }

    before = len(ctx.graph.nodes)
    result = await orchestrator._run_vulnerability_analysis(ctx)

    assert result["skipped"] is True
    assert len(ctx.graph.nodes) == before
    assert ctx.phase_results["vulnerability_analysis"]["skipped"] is True


@pytest.mark.anyio
async def test_option_a_seeds_two_hypotheses_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", True)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-2", target_urls=["https://example.com"], config={})
    ctx.phase_results["reconnaissance"] = {
        "url": "https://example.com",
        "injection_points": [
            {
                "url": "https://example.com/search",
                "method": "GET",
                "param_name": "q",
                "param_type": "query",
                "context_hint": "search",
                "other_params": {},
            },
            {
                "url": "https://example.com/login",
                "method": "POST",
                "param_name": "username",
                "param_type": "form",
                "context_hint": "login",
                "other_params": {},
            },
        ],
    }

    vuln_results = {
        "overall_risk_level": "High",
        "vulnerabilities": [
            {
                "vulnerability_name": "SQL Injection",
                "owasp_category": "A03:2023",
                "risk_level": "High",
                "attack_vectors": ["q parameter on /search endpoint"],
            },
            {
                "vulnerability_name": "Authentication Bypass",
                "owasp_category": "A07:2023",
                "risk_level": "Medium",
                "attack_vectors": ["username parameter on /login endpoint"],
            },
        ],
    }

    added = orchestrator._seed_hypotheses_from_vuln_analysis(ctx, vuln_results)

    assert added == 2
    seeded_nodes = [
        n
        for n in ctx.graph.nodes.values()
        if n.type == NodeType.HYPOTHESIS and n.data.get("seeded_by") == "vuln_analysis_agent"
    ]
    assert len(seeded_nodes) == 2


@pytest.mark.anyio
async def test_option_a_deduplicates_existing_hypothesis(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", True)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-3", target_urls=["https://example.com"], config={})

    injection_point = {
        "url": "https://example.com/search",
        "method": "GET",
        "param_name": "q",
        "param_type": "query",
        "context_hint": "search",
        "other_params": {},
    }
    ctx.phase_results["reconnaissance"] = {
        "url": "https://example.com",
        "injection_points": [injection_point],
    }

    existing = Node(
        id="existing-h",
        type=NodeType.HYPOTHESIS,
        content="Existing hypothesis",
        data={
            "hypothesis": "Existing hypothesis",
            "owasp_category": "A03:2023",
            "injection_point": injection_point,
        },
    )
    ctx.graph.add_node(existing)

    vuln_results = {
        "overall_risk_level": "High",
        "vulnerabilities": [
            {
                "vulnerability_name": "SQL Injection",
                "owasp_category": "A03:2023",
                "risk_level": "High",
                "attack_vectors": ["q parameter on /search endpoint"],
            }
        ],
    }

    added = orchestrator._seed_hypotheses_from_vuln_analysis(ctx, vuln_results)

    assert added == 0
    assert len(ctx.graph.nodes) == 1
