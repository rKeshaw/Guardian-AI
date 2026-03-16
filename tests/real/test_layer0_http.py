from __future__ import annotations

import uuid

import aiohttp
import aiosqlite
import pytest

from aegis.agents.reconnaissance_agent import ReconnaissanceAgent
from aegis.core.database import Database
from aegis.core.graph.attack_graph import AttackGraph, Node, NodeType
from aegis.core.orchestrator import CentralOrchestrator, ScanContext
from aegis.core.probing.probe_executor import ProbeExecutor
from aegis.models.scan_session import ScanStatus

from .helpers import (
    assert_valid_injection_points,
    dvwa_confirm_cmdi,
    dvwa_confirm_sqli,
    dvwa_confirm_xss,
)


pytestmark = [pytest.mark.real_http]


@pytest.mark.anyio
async def test_dvwa_sqli_endpoint_live(dvwa_base_url, dvwa_cookies):
    async with aiohttp.ClientSession(cookies=dvwa_cookies) as session:
        async with session.get(f"{dvwa_base_url}/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"}) as r:
            body = await r.text(errors="replace")
    assert r.status == 200
    assert "First name" in body
    assert "admin" in body.lower()


@pytest.mark.anyio
async def test_dvwa_sqli_boolean_differential(dvwa_base_url, dvwa_cookies):
    async with aiohttp.ClientSession(cookies=dvwa_cookies) as session:
        assert await dvwa_confirm_sqli(session, dvwa_base_url)


@pytest.mark.anyio
async def test_dvwa_xss_reflection(dvwa_base_url, dvwa_cookies):
    async with aiohttp.ClientSession(cookies=dvwa_cookies) as session:
        assert await dvwa_confirm_xss(session, dvwa_base_url)


@pytest.mark.anyio
async def test_dvwa_cmdi_execution(dvwa_base_url, dvwa_cookies):
    async with aiohttp.ClientSession(cookies=dvwa_cookies) as session:
        ok = await dvwa_confirm_cmdi(session, dvwa_base_url)
    assert ok


@pytest.mark.anyio
async def test_dvwa_fi_local_inclusion(dvwa_fi_url, dvwa_cookies):
    async with aiohttp.ClientSession(cookies=dvwa_cookies) as session:
        async with session.get(dvwa_fi_url, params={"page": "../../dvwa/about.php"}) as r1:
            b1 = await r1.text(errors="replace")
        async with session.get(dvwa_fi_url, params={"page": "include.php"}) as r2:
            b2 = await r2.text(errors="replace")
    assert r1.status == 200
    assert b1 != b2


@pytest.mark.anyio
async def test_reconnaissance_agent_discovers_sqli_param(test_db, dvwa_sqli_url, scan_auth_config):
    agent = ReconnaissanceAgent(test_db)
    model = await agent.run([dvwa_sqli_url], {"crawl_depth": 1, "auth": scan_auth_config})
    points = model.model_dump().get("injection_points", [])
    assert_valid_injection_points(points)
    assert any(p.get("param_name") == "id" for p in points)
    assert any("sqli" in str(p.get("url", "")) for p in points)


@pytest.mark.anyio
async def test_reconnaissance_agent_discovers_xss_param(test_db, dvwa_xss_url, scan_auth_config):
    agent = ReconnaissanceAgent(test_db)
    model = await agent.run([dvwa_xss_url], {"crawl_depth": 1, "auth": scan_auth_config})
    points = model.model_dump().get("injection_points", [])
    assert_valid_injection_points(points)
    assert any(p.get("param_name") == "name" for p in points)


@pytest.mark.anyio
async def test_reconnaissance_agent_discovers_exec_param(test_db, dvwa_exec_url, scan_auth_config):
    agent = ReconnaissanceAgent(test_db)
    model = await agent.run([dvwa_exec_url], {"crawl_depth": 1, "auth": scan_auth_config})
    points = model.model_dump().get("injection_points", [])
    assert_valid_injection_points(points)
    assert any(p.get("param_name") == "ip" for p in points)
    assert any(p.get("method") == "POST" or p.get("param_type") == "form" for p in points)


@pytest.mark.anyio
async def test_probe_executor_sends_get_probe(dvwa_sqli_url, dvwa_cookies):
    pe = await ProbeExecutor.create(cookies=dvwa_cookies)
    try:
        point = ProbeExecutor.build_injection_point({
            "url": dvwa_sqli_url,
            "param_name": "id",
            "param_type": "query",
            "method": "GET",
            "other_params": {"Submit": "Submit"},
        })
        result = await pe.fire(point, "1")
        assert result.status_code == 200
        assert "First name" in result.body
    finally:
        await pe.close()


@pytest.mark.anyio
async def test_probe_executor_sends_post_probe(dvwa_exec_url, dvwa_cookies):
    pe = await ProbeExecutor.create(cookies=dvwa_cookies)
    try:
        point = ProbeExecutor.build_injection_point({
            "url": dvwa_exec_url,
            "param_name": "ip",
            "param_type": "form",
            "method": "POST",
            "other_params": {"Submit": "Submit"},
        })
        result = await pe.fire(point, "127.0.0.1")
        assert result.status_code == 200
        assert "ping" in result.body.lower() or "PING" in result.body
    finally:
        await pe.close()


@pytest.mark.anyio
async def test_probe_executor_sends_cookie_probe(dvwa_sqli_url, dvwa_cookies):
    pe = await ProbeExecutor.create(cookies=dvwa_cookies)
    try:
        point = ProbeExecutor.build_injection_point({
            "url": dvwa_sqli_url,
            "param_name": "security",
            "param_type": "cookie",
            "method": "GET",
            "other_params": {"id": "1", "Submit": "Submit"},
        })
        result = await pe.fire(point, "low")
        assert result.status_code == 200
        assert "security=low" not in result.url_sent
    finally:
        await pe.close()


@pytest.mark.anyio
async def test_db_upsert_node_no_duplicates(test_db: Database):
    gid, nid = "g-http", "n-http"
    await test_db.upsert_node(gid, {"id": nid, "type": "hypothesis", "content": "v1", "data": {}, "depth": 0, "confidence": 0.2, "token_estimate": 1})
    await test_db.upsert_node(gid, {"id": nid, "type": "hypothesis", "content": "v2", "data": {}, "depth": 0, "confidence": 0.3, "token_estimate": 1})
    async with aiosqlite.connect(test_db.db_path) as conn:
        async with conn.execute("SELECT COUNT(*), content FROM graph_nodes WHERE graph_id=? AND node_id=?", (gid, nid)) as cur:
            row = await cur.fetchone()
    assert row[0] == 1
    assert row[1] == "v2"


@pytest.mark.anyio
async def test_db_upsert_graph_meta_single_row(test_db: Database):
    gid = "g-http-meta"
    for i in range(3):
        await test_db.upsert_graph_meta(gid, {"session_id": "s", "stats": {"n": i}, "frontier_size": i})
    async with aiosqlite.connect(test_db.db_path) as conn:
        async with conn.execute("SELECT COUNT(*) FROM graph_meta WHERE graph_id=?", (gid,)) as cur:
            count = (await cur.fetchone())[0]
    assert count == 1


@pytest.mark.anyio
async def test_phase_failure_sets_error_status(test_db: Database):
    orch = CentralOrchestrator(test_db)
    ctx = ScanContext(session_id=str(uuid.uuid4()), target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orch.PIPELINE_PHASES}

    async def _boom(_ctx):
        raise RuntimeError("recon failed")

    orch._run_reconnaissance = _boom  # type: ignore[assignment]
    await orch._execute_pipeline(ctx)
    assert ctx.status == ScanStatus.ERROR
