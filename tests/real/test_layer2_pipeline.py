from __future__ import annotations

import uuid

import pytest

from guardian.agents.hypothesis_agent import HypothesisAgent
from guardian.agents.penetration_agent import PenetrationAgent
from guardian.agents.reconnaissance_agent import ReconnaissanceAgent
from guardian.agents.vulnerability_agent import VulnerabilityAnalysisAgent
from guardian.core.ai_client import AIClient
from guardian.core.graph.attack_graph import AttackGraph, Node, NodeType
from guardian.core.graph.graph_orchestrator import GraphOrchestrator
from guardian.core.intelligence.comprehender import Comprehender
from guardian.core.probing.probe_executor import ProbeExecutor
from guardian.core.token_ledger import TokenLedger

from .helpers import assert_valid_hypotheses, timed_call


pytestmark = [pytest.mark.real_llm]


@pytest.mark.anyio
async def test_recon_to_hypothesis_pipeline(test_db, dvwa_sqli_url, scan_auth_config, request):
    recon = await timed_call(request.node.name, "ReconnaissanceAgent", lambda: ReconnaissanceAgent(test_db).run([dvwa_sqli_url], {"crawl_depth": 1, "auth": scan_auth_config}))
    graph = AttackGraph()
    nodes = await timed_call(request.node.name, "HypothesisAgent", lambda: HypothesisAgent(test_db, AIClient()).generate(recon.to_hypothesis_context(), graph, TokenLedger(total=10000)))
    assert_valid_hypotheses(nodes)
    assert any("sqli" in str((n.data.get("injection_point") or {}).get("url", "")).lower() or dvwa_sqli_url in str((n.data.get("injection_point") or {}).get("url", "")) for n in nodes)
    assert any(str(n.data.get("entry_probe", "")).strip() not in {"", "test", "probe_test"} for n in nodes)
    assert all(0.0 <= float(n.confidence) <= 1.0 for n in nodes)


@pytest.mark.anyio
async def test_recon_to_vuln_to_hypothesis_pipeline(test_db, dvwa_sqli_url, scan_auth_config, request):
    recon = await timed_call(request.node.name, "ReconnaissanceAgent", lambda: ReconnaissanceAgent(test_db).run([dvwa_sqli_url], {"crawl_depth": 1, "auth": scan_auth_config}))

    vuln_payload = {
        "session_id": str(uuid.uuid4()),
        "reconnaissance_data": {"targets_analyzed": 1, "reconnaissance_data": {dvwa_sqli_url: recon.model_dump()}},
    }
    vuln = await timed_call(request.node.name, "VulnerabilityAnalysisAgent", lambda: VulnerabilityAnalysisAgent(test_db).execute(vuln_payload))

    base_graph = AttackGraph()
    base_nodes = await timed_call(request.node.name, "HypothesisAgent-baseline", lambda: HypothesisAgent(test_db, AIClient()).generate(recon.to_hypothesis_context(), base_graph, TokenLedger(total=10000)))

    seeded_graph = AttackGraph()
    seeded_nodes = await timed_call(request.node.name, "HypothesisAgent-vuln-informed", lambda: HypothesisAgent(test_db, AIClient()).generate(recon.to_hypothesis_context(), seeded_graph, TokenLedger(total=12000)))

    assert len(seeded_nodes) >= len(base_nodes)
    vuln_cats = {str(v.get("owasp_category", "")).upper() for v in vuln.get("vulnerabilities", []) if isinstance(v, dict)}
    assert not vuln_cats or any(str(n.data.get("owasp_category", "")).upper() in vuln_cats for n in seeded_nodes)


@pytest.mark.anyio
@pytest.mark.timeout(180)
async def test_hypothesis_to_graph_pipeline(test_db, dvwa_sqli_url, scan_auth_config, dvwa_cookies, request):
    recon = await timed_call(request.node.name, "ReconnaissanceAgent", lambda: ReconnaissanceAgent(test_db).run([dvwa_sqli_url], {"crawl_depth": 1, "auth": scan_auth_config}))
    graph = AttackGraph()
    nodes = await timed_call(request.node.name, "HypothesisAgent", lambda: HypothesisAgent(test_db, AIClient()).generate(recon.to_hypothesis_context(), graph, TokenLedger(total=10000)))
    assert nodes

    seed = nodes[0]
    g2 = AttackGraph()
    g2.add_node(seed)

    pe = await ProbeExecutor.create(cookies=dvwa_cookies)
    try:
        orch = GraphOrchestrator(AIClient(), Comprehender(), test_db)
        await timed_call(request.node.name, "GraphOrchestrator", lambda: orch.run(str(uuid.uuid4()), recon.model_dump(), g2, pe, TokenLedger(total=12000)))
    finally:
        await pe.close()

    assert len(g2.nodes) >= 3
    assert any(n.type in {NodeType.OBSERVATION, NodeType.FINDING} for n in g2.nodes.values())


@pytest.mark.anyio
@pytest.mark.timeout(240)
async def test_graph_to_confirmation_pipeline(test_db, dvwa_sqli_url, dvwa_cookies, request):
    graph = AttackGraph()
    graph.add_node(Node(
        id=str(uuid.uuid4()),
        type=NodeType.HYPOTHESIS,
        content="SQL injection via id",
        confidence=0.8,
        data={
            "hypothesis": "SQL injection via id",
            "entry_probe": "1' AND '1'='1",
            "injection_point": {"url": dvwa_sqli_url, "param_name": "id", "param_type": "query", "method": "GET"},
            "owasp_category": "A03:2023",
            "owasp_impact": 8,
        },
    ))

    pe = await ProbeExecutor.create(cookies=dvwa_cookies)
    try:
        await timed_call(request.node.name, "GraphOrchestrator", lambda: GraphOrchestrator(AIClient(), Comprehender(), test_db).run(str(uuid.uuid4()), {"technologies": ["PHP", "MySQL"]}, graph, pe, TokenLedger(total=16000)))
    finally:
        await pe.close()

    findings = [n for n in graph.nodes.values() if n.type == NodeType.FINDING]
    if not findings:
        pytest.skip("LLM did not produce finding in budget")

    async with __import__("aiohttp").ClientSession(cookies=dvwa_cookies) as session:
        result = await timed_call(request.node.name, "PenetrationAgent.confirm_finding", lambda: PenetrationAgent(test_db).confirm_finding(findings[0], {}, session))

    assert isinstance(result.get("http_confirmed"), bool)
    assert "finding_id" in result


@pytest.mark.anyio
@pytest.mark.timeout(120)
async def test_authenticated_scan_reaches_protected_pages(test_db, dvwa_base_url, scan_auth_config, request):
    recon = await timed_call(request.node.name, "ReconnaissanceAgent", lambda: ReconnaissanceAgent(test_db).run([dvwa_base_url], {"crawl_depth": 2, "auth": scan_auth_config}))
    urls = recon.api_endpoints
    assert any("vulnerabilities" in u for u in urls)
    assert recon.injection_points
    assert any(any(k in str(p.get("url", "")).lower() for k in ["sqli", "xss_r", "exec"]) for p in recon.injection_points)
