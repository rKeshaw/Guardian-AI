from __future__ import annotations

import uuid
from types import MethodType, SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from aegis.core.config import settings
from aegis.core.database import Database
from aegis.core.graph.attack_graph import AttackGraph, Node, NodeType
from aegis.core.orchestrator import CentralOrchestrator, ScanContext
from aegis.core.token_ledger import TokenLedger
from aegis.models.scan_session import ScanStatus


def _make_ctx(orchestrator: CentralOrchestrator) -> ScanContext:
    ctx = ScanContext(
        session_id=f"sess-{uuid.uuid4()}",
        target_urls=["https://example.com"],
        config={},
    )
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}
    return ctx


def _recon_payload(injection_points: list[dict] | None = None) -> dict:
    return {
        "url": "https://example.com",
        "domain": "example.com",
        "technologies": ["nginx"],
        "waf_detected": None,
        "backend_language": "python",
        "database_hint": "mysql",
        "framework": "fastapi",
        "injection_points": injection_points or [],
        "forms": [],
        "api_endpoints": [],
        "html_comments": [],
        "hardcoded_values": [],
        "interesting_paths": [],
        "open_ports": [],
        "attack_surface_signals": [],
        "page_classifications": {},
    }


@pytest.mark.anyio
async def test_tier2_all_flags_off_baseline_behavior_preserved(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orch = CentralOrchestrator(Database())
    ctx = _make_ctx(orch)

    async def _noop_save(self, _ctx):
        return None

    async def _fake_recon(self, _ctx):
        return _recon_payload()

    async def _fake_vuln(self, _ctx):
        return {"overall_risk_level": "Unknown", "vulnerabilities": [], "skipped": True}

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_graph(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _fake_active(self, _ctx):
        return {"skipped": True, "active_confirmation_results": []}

    async def _fake_report(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orch._save_session = MethodType(_noop_save, orch)
    orch._run_reconnaissance = MethodType(_fake_recon, orch)
    orch._run_vulnerability_analysis = MethodType(_fake_vuln, orch)
    orch._run_hypothesis_seeding = MethodType(_fake_seed, orch)
    orch._run_graph_exploration = MethodType(_fake_graph, orch)
    orch._run_active_confirmation = MethodType(_fake_active, orch)
    orch._run_reporting = MethodType(_fake_report, orch)

    await orch._execute_pipeline(ctx)

    assert all(phase in ctx.results for phase in orch.PIPELINE_PHASES)
    preview = orch._results_preview(ctx)
    assert preview["vulnerability_analysis"]["skipped"] is True
    assert preview["active_confirmation"]["skipped"] is True
    assert ctx.status == ScanStatus.COMPLETED


@pytest.mark.anyio
async def test_tier2_option_a_only_vuln_analysis_adds_hypotheses(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", True)
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orch = CentralOrchestrator(Database())
    ctx = _make_ctx(orch)
    ctx.phase_results["reconnaissance"] = _recon_payload(
        [
            {"url": "https://example.com/search", "method": "GET", "param_name": "q", "param_type": "query"},
            {"url": "https://example.com/login", "method": "POST", "param_name": "username", "param_type": "form"},
            {"url": "https://example.com/item", "method": "GET", "param_name": "id", "param_type": "query"},
        ]
    )
    ctx.phase_results["vulnerability_analysis"] = {
        "overall_risk_level": "High",
        "vulnerabilities": [
            {"vulnerability_name": "SQL Injection", "owasp_category": "A03:2023", "risk_level": "High", "attack_vectors": ["q parameter"]},
            {"vulnerability_name": "Auth Bypass", "owasp_category": "A07:2023", "risk_level": "Medium", "attack_vectors": ["username parameter"]},
            {"vulnerability_name": "SSRF", "owasp_category": "A10:2023", "risk_level": "Low", "attack_vectors": ["id parameter"]},
        ],
    }

    class _MockHypothesisAgent:
        def __init__(self, db, ai_client):
            pass

        async def generate(self, context, graph, ledger):
            return [
                Node(
                    id="h-1",
                    type=NodeType.HYPOTHESIS,
                    content="h1",
                    data={
                        "hypothesis": "existing one",
                        "owasp_category": "A03:2023",
                        "injection_point": {"url": "https://example.com/alpha", "param_name": "a"},
                    },
                ),
                Node(
                    id="h-2",
                    type=NodeType.HYPOTHESIS,
                    content="h2",
                    data={
                        "hypothesis": "existing two",
                        "owasp_category": "A05:2023",
                        "injection_point": {"url": "https://example.com/beta", "param_name": "b"},
                    },
                ),
            ]

    import aegis.agents.hypothesis_agent as hypothesis_module

    monkeypatch.setattr(hypothesis_module, "HypothesisAgent", _MockHypothesisAgent)

    result = await orch._run_hypothesis_seeding(ctx)

    hypotheses = [n for n in ctx.graph.nodes.values() if n.type == NodeType.HYPOTHESIS]
    assert len(hypotheses) > 2
    assert any(n.data.get("seeded_by") == "vuln_analysis_agent" for n in hypotheses)
    assert result["seeded_from_vuln_analysis"] >= 1


@pytest.mark.anyio
async def test_tier2_option_a_deduplication(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", True)

    orch = CentralOrchestrator(Database())
    ctx = _make_ctx(orch)
    ip = {"url": "https://example.com/search", "method": "GET", "param_name": "q", "param_type": "query"}

    ctx.phase_results["reconnaissance"] = _recon_payload([ip])
    ctx.phase_results["vulnerability_analysis"] = {
        "vulnerabilities": [
            {
                "vulnerability_name": "SQL Injection",
                "owasp_category": "A03:2023",
                "risk_level": "High",
                "attack_vectors": ["q parameter"],
            }
        ]
    }

    class _MockHypothesisAgent:
        def __init__(self, db, ai_client):
            pass

        async def generate(self, context, graph, ledger):
            return [
                Node(
                    id="existing",
                    type=NodeType.HYPOTHESIS,
                    content="existing",
                    data={
                        "hypothesis": "SQLi existing",
                        "owasp_category": "A03:2023",
                        "injection_point": ip,
                    },
                )
            ]

    import aegis.agents.hypothesis_agent as hypothesis_module

    monkeypatch.setattr(hypothesis_module, "HypothesisAgent", _MockHypothesisAgent)
    await orch._run_hypothesis_seeding(ctx)

    matches = [
        n
        for n in ctx.graph.nodes.values()
        if n.type == NodeType.HYPOTHESIS
        and n.data.get("owasp_category") == "A03:2023"
        and (n.data.get("injection_point") or {}).get("url") == ip["url"]
        and (n.data.get("injection_point") or {}).get("param_name") == ip["param_name"]
    ]
    assert len(matches) == 1


@pytest.mark.anyio
async def test_tier2_option_b_only_rag_context_appears_in_prompt(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", True)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    from aegis.core.intelligence.reasoning_agent import ReasoningAgent
    from aegis.core.intelligence import rag_helper as rag_module

    monkeypatch.setattr(rag_module.rag_helper, "get_probe_context", lambda *args, **kwargs: "MOCK_PAYLOAD_CONTEXT")

    prompts: list[str] = []

    async def _query(prompt, persona=None, max_retries=2):
        prompts.append(prompt)
        return ({"terminal": True, "exploitation_confirmed": False, "confidence": 20, "next_probe": ""}, None)

    ai_client = SimpleNamespace(query_with_retry=AsyncMock(side_effect=_query))
    comprehender = SimpleNamespace(
        is_near_duplicate=AsyncMock(return_value=False),
        compress_async=AsyncMock(return_value=SimpleNamespace(content="obs", irreducible_facts=[], token_count=10)),
        compress_episode=AsyncMock(return_value=SimpleNamespace(content="ep", token_count=10)),
    )
    probe_executor = SimpleNamespace(
        capture_baseline=AsyncMock(return_value=SimpleNamespace(is_error=False)),
        fire=AsyncMock(return_value=SimpleNamespace(status_code=200, body="ok", response_time_ms=100, headers={})),
        get_baseline=lambda _: None,
    )
    graph = AttackGraph()
    hyp = Node(
        id="hyp-rag",
        type=NodeType.HYPOTHESIS,
        content="",
        data={
            "hypothesis": "SQLi via q",
            "owasp_category": "A03:2023",
            "entry_probe": "'",
            "injection_point": {"url": "https://example.com/search", "method": "GET", "param_name": "q", "param_type": "query"},
        },
    )
    graph.add_node(hyp)

    agent = ReasoningAgent(ai_client, comprehender, probe_executor, TokenLedger(total=100000))
    await agent.explore(hyp, _recon_payload(), graph)

    assert prompts
    assert "MOCK_PAYLOAD_CONTEXT" in prompts[0]


@pytest.mark.anyio
async def test_tier2_option_c_only_confirmation_runs_per_finding(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", True)

    orch = CentralOrchestrator(Database())
    ctx = _make_ctx(orch)
    ctx.phase_results["reconnaissance"] = _recon_payload()

    f1 = Node(id="f1", type=NodeType.FINDING, content="", confidence=0.6, data={"hypothesis": "h1", "exploitation_evidence": {"payload_used": "p1"}, "injection_point": {"url": "https://e.com/a", "method": "GET", "param_name": "a", "param_type": "query"}})
    f2 = Node(id="f2", type=NodeType.FINDING, content="", confidence=0.6, data={"hypothesis": "h2", "exploitation_evidence": {"payload_used": "p2"}, "injection_point": {"url": "https://e.com/b", "method": "GET", "param_name": "b", "param_type": "query"}})
    ctx.graph.add_node(f1)
    ctx.graph.add_node(f2)

    import aiohttp
    from aegis.agents import penetration_agent as pen_module

    class _DummySession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(aiohttp, "ClientSession", _DummySession)

    calls = {"n": 0}

    async def _fake_confirm(self, finding_node, recon_data, session):
        calls["n"] += 1
        return {"finding_id": finding_node.id, "http_confirmed": True, "new_indicators": ["sql_error"]}

    monkeypatch.setattr(pen_module.PenetrationAgent, "confirm_finding", _fake_confirm)

    result = await orch._run_active_confirmation(ctx)

    assert calls["n"] == 2
    assert f1.data.get("http_confirmation") is not None
    assert f2.data.get("http_confirmation") is not None
    assert len(result["active_confirmation_results"]) == 2


@pytest.mark.anyio
async def test_tier2_all_flags_on_full_pipeline_completes(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", True)
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", True)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", True)

    orch = CentralOrchestrator(Database())
    ctx = _make_ctx(orch)

    async def _noop_save(self, _ctx):
        return None

    async def _fake_recon(self, _ctx):
        return _recon_payload([{"url": "https://example.com/search", "method": "GET", "param_name": "q", "param_type": "query"}])

    async def _fake_vuln(self, _ctx):
        return {"overall_risk_level": "Medium", "vulnerabilities": [{"vulnerability_name": "SQL Injection"}], "skipped": False}

    async def _fake_seed(self, _ctx):
        h = Node(id="h-main", type=NodeType.HYPOTHESIS, content="", data={"hypothesis": "h", "injection_point": {"url": "https://example.com/search", "param_name": "q"}, "owasp_category": "A03:2023"})
        _ctx.graph.add_node(h)
        return {"hypotheses_generated": 1, "seeded_from_vuln_analysis": 1}

    async def _fake_graph(self, _ctx):
        f = Node(id="f-main", type=NodeType.FINDING, content="", confidence=0.8, data={"hypothesis": "finding", "owasp_category": "A03:2023", "exploitation_evidence": {"payload_used": "'"}, "injection_point": {"url": "https://example.com/search", "method": "GET", "param_name": "q", "param_type": "query"}})
        _ctx.graph.add_node(f)
        return {"finding_count": 1, "graph_stats": _ctx.graph.stats()}

    async def _fake_active(self, _ctx):
        for n in _ctx.graph.get_findings():
            n.data["http_confirmation"] = {"http_confirmed": True, "new_indicators": ["sql_error"]}
        return {"skipped": False, "active_confirmation_results": [{"http_confirmed": True}], "confirmed_count": 1, "total_findings": 1}

    async def _fake_reporting(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [{"name": "f"}],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orch._save_session = MethodType(_noop_save, orch)
    orch._run_reconnaissance = MethodType(_fake_recon, orch)
    orch._run_vulnerability_analysis = MethodType(_fake_vuln, orch)
    orch._run_hypothesis_seeding = MethodType(_fake_seed, orch)
    orch._run_graph_exploration = MethodType(_fake_graph, orch)
    orch._run_active_confirmation = MethodType(_fake_active, orch)
    orch._run_reporting = MethodType(_fake_reporting, orch)

    await orch._execute_pipeline(ctx)

    assert ctx.status == ScanStatus.COMPLETED
    preview = orch._results_preview(ctx)
    assert all(preview[p]["completed"] for p in ["reconnaissance", "vulnerability_analysis", "hypothesis_seeding", "graph_exploration", "active_confirmation", "reporting"])
    assert preview["vulnerability_analysis"]["skipped"] is False
    assert preview["active_confirmation"]["skipped"] is False
    assert all("error" not in (ctx.results.get(phase) or {}) for phase in orch.PIPELINE_PHASES)


@pytest.mark.anyio
async def test_tier2_option_c_missing_payload_graceful_degradation(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", True)

    orch = CentralOrchestrator(Database())
    ctx = _make_ctx(orch)
    ctx.phase_results["reconnaissance"] = _recon_payload()

    finding = Node(
        id="f-no-payload",
        type=NodeType.FINDING,
        content="",
        data={
            "hypothesis": "no payload",
            "owasp_category": "A03:2023",
            "injection_point": {"url": "https://example.com/search", "method": "GET", "param_name": "q", "param_type": "query"},
            "exploitation_evidence": {},
        },
    )
    ctx.graph.add_node(finding)

    result = await orch._run_active_confirmation(ctx)

    assert result["active_confirmation_results"][0]["http_confirmed"] is False
    assert result["active_confirmation_results"][0]["reason"] == "no_payload_in_evidence"


@pytest.mark.anyio
async def test_tier2_option_b_empty_knowledge_index_no_crash(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", True)

    from aegis.core.intelligence.reasoning_agent import ReasoningAgent
    from aegis.core.intelligence import rag_helper as rag_module

    monkeypatch.setattr(rag_module.rag_helper, "get_probe_context", lambda *args, **kwargs: "")

    prompts: list[str] = []

    async def _query(prompt, persona=None, max_retries=2):
        prompts.append(prompt)
        return ({"terminal": True, "exploitation_confirmed": False, "confidence": 15, "next_probe": ""}, None)

    ai_client = SimpleNamespace(query_with_retry=AsyncMock(side_effect=_query))
    comprehender = SimpleNamespace(
        is_near_duplicate=AsyncMock(return_value=False),
        compress_async=AsyncMock(return_value=SimpleNamespace(content="obs", irreducible_facts=[], token_count=10)),
        compress_episode=AsyncMock(return_value=SimpleNamespace(content="ep", token_count=10)),
    )
    probe_executor = SimpleNamespace(
        capture_baseline=AsyncMock(return_value=SimpleNamespace(is_error=False)),
        fire=AsyncMock(return_value=SimpleNamespace(status_code=200, body="ok", response_time_ms=100, headers={})),
        get_baseline=lambda _: None,
    )
    graph = AttackGraph()
    hyp = Node(
        id="hyp-empty-rag",
        type=NodeType.HYPOTHESIS,
        content="",
        data={
            "hypothesis": "SQLi via q",
            "owasp_category": "A03:2023",
            "entry_probe": "'",
            "injection_point": {"url": "https://example.com/search", "method": "GET", "param_name": "q", "param_type": "query"},
        },
    )
    graph.add_node(hyp)

    agent = ReasoningAgent(ai_client, comprehender, probe_executor, TokenLedger(total=100000))
    result = await agent.explore(hyp, _recon_payload(), graph)

    assert result is None
    assert prompts
    assert "ATTACK KNOWLEDGE CONTEXT" not in prompts[0]
