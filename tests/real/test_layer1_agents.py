from __future__ import annotations

import uuid

import pytest

from aegis.agents.hypothesis_agent import HypothesisAgent
from aegis.agents.reconnaissance_agent import ReconnaissanceAgent
from aegis.agents.reporting_agent import ReportingAgent
from aegis.agents.vulnerability_agent import VulnerabilityAnalysisAgent
from aegis.core.ai_client import AIClient, AIPersona
from aegis.core.graph.attack_graph import AttackGraph, Node, NodeType
from aegis.core.graph.graph_orchestrator import GraphOrchestrator
from aegis.core.intelligence.comprehender import Comprehender
from aegis.core.intelligence.reasoning_agent import ReasoningAgent
from aegis.core.probing.probe_executor import ProbeExecutor
from aegis.core.token_ledger import TokenLedger

from .helpers import (
    assert_finding_references_vuln_type,
    assert_valid_graph_result,
    assert_valid_hypotheses,
    timed_call,
    with_llm_retry,
)


@pytest.mark.real_llm
@pytest.mark.anyio
async def test_vulnerability_analysis_identifies_sqli(test_db, dvwa_sqli_url, scan_auth_config, request):
    async def _run():
        recon = await timed_call(request.node.name, "ReconnaissanceAgent", lambda: ReconnaissanceAgent(test_db).run([dvwa_sqli_url], {"crawl_depth": 1, "auth": scan_auth_config}))
        payload = {
            "session_id": str(uuid.uuid4()),
            "reconnaissance_data": {"targets_analyzed": 1, "reconnaissance_data": {dvwa_sqli_url: recon.model_dump()}},
        }
        return await timed_call(request.node.name, "VulnerabilityAnalysisAgent", lambda: VulnerabilityAnalysisAgent(test_db).execute(payload))

    def _assert(result):
        vulns = result.get("vulnerabilities", [])
        assert vulns
        assert any(str(v.get("owasp_category", "")).upper().startswith("A03") or "sql" in str(v).lower() or "inject" in str(v).lower() for v in vulns)
        assert all(str(v.get("risk_level", "")).strip() for v in vulns)

    await with_llm_retry(_run, _assert, retries=3)


@pytest.mark.real_llm
@pytest.mark.anyio
async def test_vulnerability_analysis_identifies_xss(test_db, dvwa_xss_url, scan_auth_config, request):
    async def _run():
        recon = await timed_call(request.node.name, "ReconnaissanceAgent", lambda: ReconnaissanceAgent(test_db).run([dvwa_xss_url], {"crawl_depth": 1, "auth": scan_auth_config}))
        payload = {
            "session_id": str(uuid.uuid4()),
            "reconnaissance_data": {"targets_analyzed": 1, "reconnaissance_data": {dvwa_xss_url: recon.model_dump()}},
        }
        return await timed_call(request.node.name, "VulnerabilityAnalysisAgent", lambda: VulnerabilityAnalysisAgent(test_db).execute(payload))

    def _assert(result):
        vulns = result.get("vulnerabilities", [])
        assert vulns
        joined = " ".join(str(v).lower() for v in vulns)
        assert "xss" in joined or "cross-site" in joined or any(str(v.get("owasp_category", "")).upper() in {"A03:2023", "A07:2023"} for v in vulns)

    await with_llm_retry(_run, _assert, retries=3)


def _minimal_context(url: str, param: str, method: str = "GET", ptype: str = "query") -> dict:
    return {
        "url": url,
        "technologies": ["PHP", "MySQL"],
        "waf_detected": None,
        "injection_points": [{"url": url, "param_name": param, "param_type": ptype, "method": method}],
        "forms": [],
        "api_endpoints": [url],
        "attack_surface_signals": [],
    }


@pytest.mark.real_llm
@pytest.mark.anyio
async def test_hypothesis_agent_generates_sqli_hypothesis(test_db, dvwa_sqli_url, request):
    async def _run():
        graph = AttackGraph()
        return await timed_call(request.node.name, "HypothesisAgent", lambda: HypothesisAgent(test_db, AIClient()).generate(_minimal_context(dvwa_sqli_url, "id"), graph, TokenLedger(total=10000)))

    def _assert(nodes):
        assert isinstance(nodes, list) and len(nodes) >= 2
        assert_valid_hypotheses(nodes)
        joined = " ".join(str(n.data).lower() for n in nodes)
        assert ("'" in joined) or ("1=1" in joined) or ("sql" in joined) or ("inject" in joined)

    await with_llm_retry(_run, _assert, retries=3)


@pytest.mark.real_llm
@pytest.mark.anyio
async def test_hypothesis_agent_generates_xss_hypothesis(test_db, dvwa_xss_url, request):
    async def _run():
        graph = AttackGraph()
        return await timed_call(request.node.name, "HypothesisAgent", lambda: HypothesisAgent(test_db, AIClient()).generate(_minimal_context(dvwa_xss_url, "name"), graph, TokenLedger(total=10000)))

    def _assert(nodes):
        assert nodes
        joined = " ".join(str(n.data).lower() for n in nodes)
        assert "xss" in joined or "cross-site" in joined or "script" in joined or "<" in joined

    await with_llm_retry(_run, _assert, retries=3)


@pytest.mark.real_llm
@pytest.mark.anyio
async def test_hypothesis_agent_generates_cmdi_hypothesis(test_db, dvwa_exec_url, request):
    async def _run():
        graph = AttackGraph()
        return await timed_call(request.node.name, "HypothesisAgent", lambda: HypothesisAgent(test_db, AIClient()).generate(_minimal_context(dvwa_exec_url, "ip", method="POST", ptype="form"), graph, TokenLedger(total=10000)))

    def _assert(nodes):
        assert nodes
        joined = " ".join(str(n.data).lower() for n in nodes)
        assert ";" in joined or "|" in joined or "`" in joined or "command" in joined or "exec" in joined

    await with_llm_retry(_run, _assert, retries=3)


def _seed_hypothesis(url: str, param: str, probe: str) -> Node:
    return Node(
        id=str(uuid.uuid4()),
        type=NodeType.HYPOTHESIS,
        content="Seed hypothesis",
        confidence=0.8,
        data={
            "hypothesis": f"Potential issue via {param}",
            "entry_probe": probe,
            "injection_point": {"url": url, "param_name": param, "param_type": "query", "method": "GET"},
            "confidence": 80,
            "owasp_category": "A03:2023",
            "owasp_impact": 8,
        },
    )


@pytest.mark.real_llm
@pytest.mark.anyio
async def test_graph_orchestrator_explores_sqli_hypothesis(test_db, dvwa_sqli_url, dvwa_cookies, request):
    async def _run():
        graph = AttackGraph()
        graph.add_node(_seed_hypothesis(dvwa_sqli_url, "id", "1' AND '1'='1"))
        pe = await ProbeExecutor.create(cookies=dvwa_cookies)
        try:
            orch = GraphOrchestrator(AIClient(), Comprehender(), test_db)
            await timed_call(request.node.name, "GraphOrchestrator", lambda: orch.run(str(uuid.uuid4()), {"technologies": ["PHP", "MySQL"]}, graph, pe, TokenLedger(total=12000)))
            return graph
        finally:
            await pe.close()

    def _assert(graph: AttackGraph):
        assert len(graph.nodes) > 1
        types = {n.type for n in graph.nodes.values()}
        assert NodeType.PROBE in types or NodeType.OBSERVATION in types or NodeType.FINDING in types
        assert_valid_graph_result(graph.to_d3())

    await with_llm_retry(_run, _assert, retries=3)


@pytest.mark.real_llm
@pytest.mark.timeout(180)
@pytest.mark.anyio
async def test_graph_orchestrator_produces_finding_for_sqli(test_db, dvwa_sqli_url, dvwa_cookies, request):
    async def _run():
        graph = AttackGraph()
        graph.add_node(_seed_hypothesis(dvwa_sqli_url, "id", "1' AND '1'='1"))
        pe = await ProbeExecutor.create(cookies=dvwa_cookies)
        try:
            orch = GraphOrchestrator(AIClient(), Comprehender(), test_db)
            await timed_call(request.node.name, "GraphOrchestrator", lambda: orch.run(str(uuid.uuid4()), {"technologies": ["PHP", "MySQL"]}, graph, pe, TokenLedger(total=16000)))
            return graph
        finally:
            await pe.close()

    def _assert(graph: AttackGraph):
        findings = [n for n in graph.nodes.values() if n.type == NodeType.FINDING]
        assert findings
        joined = " ".join(str(f.data).lower() for f in findings)
        assert "sql" in joined or "inject" in joined or "id" in joined

    await with_llm_retry(_run, _assert, retries=3)


@pytest.mark.real_llm
@pytest.mark.anyio
async def test_graph_orchestrator_explores_xss_hypothesis(test_db, dvwa_xss_url, dvwa_cookies, request):
    async def _run():
        graph = AttackGraph()
        graph.add_node(_seed_hypothesis(dvwa_xss_url, "name", "<script>alert(1)</script>"))
        pe = await ProbeExecutor.create(cookies=dvwa_cookies)
        try:
            orch = GraphOrchestrator(AIClient(), Comprehender(), test_db)
            await timed_call(request.node.name, "GraphOrchestrator", lambda: orch.run(str(uuid.uuid4()), {"technologies": ["PHP"]}, graph, pe, TokenLedger(total=12000)))
            return graph
        finally:
            await pe.close()

    def _assert(graph: AttackGraph):
        assert len(graph.nodes) > 1
        assert any(n.type != NodeType.DEAD_END for n in graph.nodes.values())

    await with_llm_retry(_run, _assert, retries=3)


@pytest.mark.real_http
@pytest.mark.anyio
async def test_reasoning_agent_handles_string_boolean():
    payload = {"terminal": "false", "exploitation_confirmed": "false", "confidence": 60, "reasoning": "probing", "next_probe": "test"}
    out = ReasoningAgent._normalize_llm_response(payload)
    assert out is not None
    assert out["terminal"] is False
    assert out["exploitation_confirmed"] is False


@pytest.mark.real_http
@pytest.mark.anyio
async def test_ollama_format_parameter_placement(monkeypatch):
    captured = {}

    class _Client:
        def chat(self, **kwargs):
            captured.update(kwargs)
            return {"message": {"content": '{"status":"ok"}'}}

    client = AIClient()
    monkeypatch.setattr(client, "_get_client", lambda: _Client())
    out = await client.query_ai("return json", persona=AIPersona.VULNERABILITY_EXPERT)
    assert out
    assert captured.get("format") == "json"
    assert "format" not in captured.get("options", {})


@pytest.mark.real_llm
@pytest.mark.anyio
async def test_reporting_agent_generates_report(test_db, dvwa_sqli_url, request):
    async def _run():
        phase_results = {
            "reconnaissance": {"url": dvwa_sqli_url, "injection_points": [{"url": dvwa_sqli_url, "param_name": "id", "param_type": "query", "method": "GET"}], "technologies": ["PHP", "MySQL"]},
            "graph_exploration": {
                "findings": [
                    {
                        "node_id": "test_finding_1",
                        "type": "FINDING",
                        "content": "SQL injection confirmed in id parameter",
                        "data": {"confidence": 0.9, "owasp_category": "A03", "evidence": "Differential response confirmed"},
                    }
                ]
            },
        }
        graph = AttackGraph()
        graph.add_node(Node(id="f1", type=NodeType.FINDING, content="SQL injection confirmed", data={"hypothesis": "SQL injection", "owasp_category": "A03"}))
        return await timed_call(request.node.name, "ReportingAgent", lambda: ReportingAgent(test_db, AIClient()).generate(graph, phase_results, str(uuid.uuid4()), TokenLedger(total=10000)))

    def _assert(report):
        assert isinstance(report, dict)
        assert str(report.get("executive_summary", "")).strip()
        findings = report.get("technical_findings", [])
        assert isinstance(findings, list) and findings
        assert report.get("graph_summary") is not None

    await with_llm_retry(_run, _assert, retries=3)
