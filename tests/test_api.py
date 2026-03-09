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

@pytest.mark.anyio
async def test_start_scan_requires_api_key_when_configured(monkeypatch):
    import guardian.api.main as main_module

    monkeypatch.setattr(main_module.settings, "API_KEY", "secret")
    monkeypatch.setattr(main_module, "validate_scan_target", lambda _u: None)

    orch = SimpleNamespace(start_scan=AsyncMock(return_value="sess-123"))
    main_module.orchestrator = orch
    main_module.database = object()

    async with await _client_with(main_module) as client:
        r = await client.post("/api/v1/scan/start", json={"target_urls": ["https://example.com"], "config": {}})

    assert r.status_code == 401


@pytest.mark.anyio
async def test_start_scan_allows_without_api_key_when_not_configured(monkeypatch):
    import guardian.api.main as main_module

    monkeypatch.setattr(main_module.settings, "API_KEY", "")
    monkeypatch.setattr(main_module, "validate_scan_target", lambda _u: None)

    orch = SimpleNamespace(start_scan=AsyncMock(return_value="sess-123"))
    main_module.orchestrator = orch
    main_module.database = object()

    async with await _client_with(main_module) as client:
        r = await client.post("/api/v1/scan/start", json={"target_urls": ["https://example.com"], "config": {}})

    assert r.status_code == 202


def test_validate_scan_target_denies_private_ip(monkeypatch):
    import guardian.api.main as main_module

    monkeypatch.setattr(main_module.settings, "SCAN_TARGET_ALLOW_EXTERNAL_ONLY", True)
    monkeypatch.setattr(main_module.settings, "SCAN_TARGET_DENY_CIDRS", "10.0.0.0/8,192.168.0.0/16")
    monkeypatch.setattr(main_module.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, None, ("192.168.1.1", 443))])

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        main_module.validate_scan_target("https://intranet.local")
    assert "denied network range" in str(exc.value)


def test_validate_scan_target_denies_metadata_ip(monkeypatch):
    import guardian.api.main as main_module

    monkeypatch.setattr(main_module.settings, "SCAN_TARGET_ALLOW_EXTERNAL_ONLY", True)
    monkeypatch.setattr(main_module.settings, "SCAN_TARGET_DENY_CIDRS", "169.254.0.0/16")
    monkeypatch.setattr(main_module.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, None, ("169.254.169.254", 443))])

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        main_module.validate_scan_target("https://metadata.local")
    assert "denied network range" in str(exc.value)


def test_validate_scan_target_allows_public_ip(monkeypatch):
    import guardian.api.main as main_module

    monkeypatch.setattr(main_module.settings, "SCAN_TARGET_ALLOW_EXTERNAL_ONLY", True)
    monkeypatch.setattr(main_module.settings, "SCAN_TARGET_DENY_CIDRS", "10.0.0.0/8")
    monkeypatch.setattr(main_module.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, None, ("93.184.216.34", 443))])

    main_module.validate_scan_target("https://example.com")


def test_validate_scan_target_dns_failure_allowed(monkeypatch):
    import guardian.api.main as main_module

    def _boom(*args, **kwargs):
        raise main_module.socket.gaierror("dns failure")

    monkeypatch.setattr(main_module.socket, "getaddrinfo", _boom)
    main_module.validate_scan_target("https://unknown.invalid")