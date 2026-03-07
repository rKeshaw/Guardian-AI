from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from guardian.api.main import app
from guardian.core.graph.attack_graph import AttackGraph, Edge, EdgeType, Node, NodeType


async def _client_with(main_module):
    async def _ok_init() -> bool:
        return True

    main_module.initialize_guardian_components = _ok_init
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.anyio
async def test_health_returns_200():
    import guardian.api.main as main_module

    main_module.orchestrator = SimpleNamespace(get_workflow_health=lambda: {"active_sessions": 0, "slots_available": 5})
    main_module.database = object()

    async with await _client_with(main_module) as client:
        r = await client.get("/api/v1/health")

    assert r.status_code == 200
    body = r.json()
    assert "status" in body


@pytest.mark.anyio
async def test_start_scan_returns_session_id():
    import guardian.api.main as main_module

    orch = SimpleNamespace(start_scan=AsyncMock(return_value="sess-123"))
    main_module.orchestrator = orch
    main_module.database = object()

    async with await _client_with(main_module) as client:
        r = await client.post("/api/v1/scan/start", json={"target_urls": ["https://example.com"], "config": {}})

    assert r.status_code == 202
    assert "session_id" in r.json()


@pytest.mark.anyio
async def test_start_scan_invalid_url_returns_422():
    import guardian.api.main as main_module

    main_module.orchestrator = SimpleNamespace(start_scan=AsyncMock(return_value="sess-123"))
    main_module.database = object()

    async with await _client_with(main_module) as client:
        r = await client.post("/api/v1/scan/start", json={"target_urls": ["not-a-url"], "config": {}})

    assert r.status_code == 422


@pytest.mark.anyio
async def test_start_scan_empty_urls_returns_422():
    import guardian.api.main as main_module

    main_module.orchestrator = SimpleNamespace(start_scan=AsyncMock(return_value="sess-123"))
    main_module.database = object()

    async with await _client_with(main_module) as client:
        r = await client.post("/api/v1/scan/start", json={"target_urls": [], "config": {}})

    assert r.status_code == 422


@pytest.mark.anyio
async def test_stop_scan_not_found_returns_404():
    import guardian.api.main as main_module

    orch = SimpleNamespace(stop_scan=AsyncMock(side_effect=KeyError("missing")))
    main_module.orchestrator = orch
    main_module.database = object()

    async with await _client_with(main_module) as client:
        r = await client.delete("/api/v1/scan/nonexistent")

    assert r.status_code == 404


@pytest.mark.anyio
async def test_graph_endpoint_returns_d3_structure():
    import guardian.api.main as main_module

    graph = AttackGraph(graph_id="g1")
    h = Node(id="h1", type=NodeType.HYPOTHESIS, content="hyp", data={"hypothesis": "hyp"})
    f = Node(id="f1", type=NodeType.FINDING, content="finding", data={"hypothesis": "finding"})
    graph.add_node(h)
    graph.add_node(f)
    graph.add_edge(Edge(source_id="h1", target_id="f1", type=EdgeType.CONFIRMED))

    orch = SimpleNamespace(get_session_graph=AsyncMock(return_value=graph))
    main_module.orchestrator = orch
    main_module.database = object()

    async with await _client_with(main_module) as client:
        r = await client.get("/api/v1/scan/sess-1/graph")

    assert r.status_code == 200
    body = r.json()
    assert "nodes" in body
    assert "links" in body


@pytest.mark.anyio
async def test_status_fallback_to_db():
    import guardian.api.main as main_module

    orch = SimpleNamespace(get_session_status=AsyncMock(side_effect=KeyError("evicted")))
    session_row = SimpleNamespace(
        status="completed",
        started_at=datetime(2024, 1, 1, 0, 0, 0),
        completed_at=datetime(2024, 1, 1, 0, 1, 0),
        error_message=None,
    )
    db = SimpleNamespace(get_session=AsyncMock(return_value=session_row))
    main_module.orchestrator = orch
    main_module.database = db

    async with await _client_with(main_module) as client:
        r = await client.get("/api/v1/scan/sess-1/status")

    assert r.status_code == 200
    body = r.json()
    assert body["session_id"] == "sess-1"
    assert body["status"] == "completed"
