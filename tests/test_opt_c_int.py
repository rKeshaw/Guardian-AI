from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from aegis.agents.penetration_agent import PenetrationAgent, TestResult as PenetrationTestResult
from aegis.core.config import settings
from aegis.core.database import Database
from aegis.core.graph.attack_graph import AttackGraph, Node, NodeType
from aegis.core.orchestrator import CentralOrchestrator, ScanContext


class _DummyClientSession:
    def __init__(self, *args, **kwargs):
        pass

    async def close(self):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _finding_node(with_payload: bool = True) -> Node:
    exploitation = {"payload_used": "' OR '1'='1", "proof_type": "boolean_based"} if with_payload else {}
    return Node(
        id="finding-1",
        type=NodeType.FINDING,
        content="SQLi finding",
        confidence=0.7,
        data={
            "hypothesis": "SQL Injection via q",
            "owasp_category": "A03:2023",
            "injection_point": {
                "url": "https://target.com/search",
                "method": "GET",
                "param_name": "q",
                "param_type": "query",
            },
            "exploitation_evidence": exploitation,
        },
    )


@pytest.mark.anyio
async def test_option_c_disabled_skips_and_does_not_call_confirm(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    called = {"count": 0}

    async def _fake_confirm(self, finding_node, recon_data, session):
        called["count"] += 1
        return {"http_confirmed": False}

    monkeypatch.setattr(PenetrationAgent, "confirm_finding", _fake_confirm)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-c1", target_urls=["https://target.com"], config={})
    ctx.graph.add_node(_finding_node(with_payload=True))
    ctx.phase_results["reconnaissance"] = {"url": "https://target.com"}

    result = await orchestrator._run_active_confirmation(ctx)

    assert result["skipped"] is True
    assert called["count"] == 0


@pytest.mark.anyio
async def test_option_c_enabled_calls_confirm_once_per_finding(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", True)

    import aiohttp

    monkeypatch.setattr(aiohttp, "ClientSession", _DummyClientSession)

    calls = {"count": 0}

    async def _fake_confirm(self, finding_node, recon_data, session):
        calls["count"] += 1
        return {"finding_id": finding_node.id, "http_confirmed": False, "new_indicators": []}

    monkeypatch.setattr(PenetrationAgent, "confirm_finding", _fake_confirm)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-c2", target_urls=["https://target.com"], config={})
    ctx.graph.add_node(_finding_node(with_payload=True))
    ctx.phase_results["reconnaissance"] = {"url": "https://target.com"}

    result = await orchestrator._run_active_confirmation(ctx)

    assert result["skipped"] is False
    assert calls["count"] == 1
    assert result["total_findings"] == 1


@pytest.mark.anyio
async def test_confirm_finding_true_updates_node_http_confirmation(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", True)

    import aiohttp

    monkeypatch.setattr(aiohttp, "ClientSession", _DummyClientSession)

    async def _fake_capture(self, point, session):
        return SimpleNamespace(status_code=200, body_length=100, response_time_ms=100.0, present_indicators=set())

    async def _fake_execute(self, point, payload, session):
        return PenetrationTestResult(
            exploitation_detected=True,
            status_code=500,
            response_time_ms=120.0,
            body_length=140,
            evidence={"response_snippet": "you have an error in your SQL syntax"},
        )

    def _fake_diff(self, test, baseline, category):
        return ["syntax error"]

    monkeypatch.setattr(PenetrationAgent, "_capture_baseline", _fake_capture)
    monkeypatch.setattr(PenetrationAgent, "_execute_payload", _fake_execute)
    monkeypatch.setattr(PenetrationAgent, "_differential_indicators", _fake_diff)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-c3", target_urls=["https://target.com"], config={})
    finding = _finding_node(with_payload=True)
    ctx.graph.add_node(finding)
    ctx.phase_results["reconnaissance"] = {"url": "https://target.com"}

    result = await orchestrator._run_active_confirmation(ctx)

    assert result["confirmed_count"] == 1
    assert finding.data.get("http_confirmation", {}).get("http_confirmed") is True


@pytest.mark.anyio
async def test_confirm_finding_without_payload_returns_expected_reason():
    agent = PenetrationAgent(Database())
    finding = _finding_node(with_payload=False)

    result = await agent.confirm_finding(finding, {}, _DummyClientSession())

    assert result["http_confirmed"] is False
    assert result["reason"] == "no_payload_in_evidence"

@pytest.mark.anyio
async def test_active_confirmation_passes_bearer_auth_header_to_session(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", True)

    captured = {"auth": None}

    class _DummyProbeExecutor:
        def __init__(self):
            self._session = SimpleNamespace(headers={})
            self.closed = False

        async def close(self):
            self.closed = True

    dummy = _DummyProbeExecutor()

    async def _create(auth_headers=None, cookies=None):
        if auth_headers:
            dummy._session.headers.update(auth_headers)
        return dummy

    async def _auth(self, auth, session):
        captured["auth"] = auth
        return True

    async def _fake_confirm(self, finding_node, recon_data, session):
        assert session.headers.get("Authorization") == "Bearer tok"
        return {"finding_id": finding_node.id, "http_confirmed": False, "new_indicators": []}

    import aegis.core.probing.probe_executor as pe_module

    class _PE:
        @classmethod
        async def create(cls, auth_headers=None, cookies=None):
            return await _create(auth_headers=auth_headers, cookies=cookies)

    monkeypatch.setattr(pe_module, "ProbeExecutor", _PE)
    monkeypatch.setattr("aegis.core.probing.session_manager.SessionManager.authenticate", _auth)
    monkeypatch.setattr(PenetrationAgent, "confirm_finding", _fake_confirm)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-c-auth", target_urls=["https://target.com"], config={"auth": {"type": "bearer", "bearer_token": "tok"}})
    ctx.graph.add_node(_finding_node(with_payload=True))
    ctx.phase_results["reconnaissance"] = {"url": "https://target.com"}

    await orchestrator._run_active_confirmation(ctx)

    assert captured["auth"]["bearer_token"] == "tok"


@pytest.mark.anyio
async def test_active_confirmation_runs_without_auth_config(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", True)

    class _DummyProbeExecutor:
        def __init__(self):
            self._session = SimpleNamespace(headers={})
        async def close(self):
            return None

    async def _create(auth_headers=None, cookies=None):
        return _DummyProbeExecutor()

    async def _auth(self, auth, session):
        return True

    async def _fake_confirm(self, finding_node, recon_data, session):
        return {"finding_id": finding_node.id, "http_confirmed": False, "new_indicators": []}

    import aegis.core.probing.probe_executor as pe_module

    class _PE:
        @classmethod
        async def create(cls, auth_headers=None, cookies=None):
            return await _create(auth_headers=auth_headers, cookies=cookies)

    monkeypatch.setattr(pe_module, "ProbeExecutor", _PE)
    monkeypatch.setattr("aegis.core.probing.session_manager.SessionManager.authenticate", _auth)
    monkeypatch.setattr(PenetrationAgent, "confirm_finding", _fake_confirm)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-c-no-auth", target_urls=["https://target.com"], config={})
    ctx.graph.add_node(_finding_node(with_payload=True))
    ctx.phase_results["reconnaissance"] = {"url": "https://target.com"}

    result = await orchestrator._run_active_confirmation(ctx)
    assert result["skipped"] is False


@pytest.mark.anyio
async def test_active_confirmation_closes_probe_executor_on_error(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", True)

    class _DummyProbeExecutor:
        def __init__(self):
            self._session = SimpleNamespace(headers={})
            self.closed = False
        async def close(self):
            self.closed = True

    dummy = _DummyProbeExecutor()

    async def _create(auth_headers=None, cookies=None):
        return dummy

    async def _auth(self, auth, session):
        return True

    async def _boom_confirm(self, finding_node, recon_data, session):
        raise RuntimeError("confirm failed")

    import aegis.core.probing.probe_executor as pe_module

    class _PE:
        @classmethod
        async def create(cls, auth_headers=None, cookies=None):
            return await _create(auth_headers=auth_headers, cookies=cookies)

    monkeypatch.setattr(pe_module, "ProbeExecutor", _PE)
    monkeypatch.setattr("aegis.core.probing.session_manager.SessionManager.authenticate", _auth)
    monkeypatch.setattr(PenetrationAgent, "confirm_finding", _boom_confirm)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-c-close", target_urls=["https://target.com"], config={})
    ctx.graph.add_node(_finding_node(with_payload=True))
    ctx.phase_results["reconnaissance"] = {"url": "https://target.com"}

    with pytest.raises(RuntimeError):
        await orchestrator._run_active_confirmation(ctx)
