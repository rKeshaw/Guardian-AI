from __future__ import annotations

from types import MethodType

import pytest

from guardian.core.config import settings
from guardian.core.database import Database
from guardian.core.orchestrator import CentralOrchestrator, ScanContext
from guardian.models.scan_session import ScanStatus


@pytest.mark.anyio
async def test_pipeline_graceful_degradation_all_flags_off(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_RAG_PROBING", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-int-1", target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}

    async def _noop_save(self, _ctx):
        return None

    async def _fake_recon(self, _ctx):
        return {"url": "https://example.com", "domain": "example.com", "injection_points": []}

    async def _fake_vuln(self, _ctx):
        return {
            "overall_risk_level": "Unknown",
            "vulnerabilities": [],
            "skipped": True,
        }

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_explore(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _fake_active(self, _ctx):
        return {"skipped": True, "active_confirmation_results": []}

    async def _fake_reporting(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    orchestrator._run_reconnaissance = MethodType(_fake_recon, orchestrator)
    orchestrator._run_vulnerability_analysis = MethodType(_fake_vuln, orchestrator)
    orchestrator._run_hypothesis_seeding = MethodType(_fake_seed, orchestrator)
    orchestrator._run_graph_exploration = MethodType(_fake_explore, orchestrator)
    orchestrator._run_active_confirmation = MethodType(_fake_active, orchestrator)
    orchestrator._run_reporting = MethodType(_fake_reporting, orchestrator)

    await orchestrator._execute_pipeline(ctx)

    assert all(phase in ctx.results for phase in orchestrator.PIPELINE_PHASES)
    assert ctx.results["vulnerability_analysis"]["skipped"] is True
    assert ctx.results["active_confirmation"]["skipped"] is True
    assert ctx.status == ScanStatus.COMPLETED


@pytest.mark.anyio
async def test_pipeline_sets_error_when_recon_phase_fails(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-int-recon-fail", target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}

    async def _noop_save(self, _ctx):
        return None

    async def _bad_recon(self, _ctx):
        raise RuntimeError("recon blew up")

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_explore(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _fake_reporting(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    orchestrator._run_reconnaissance = MethodType(_bad_recon, orchestrator)
    orchestrator._run_hypothesis_seeding = MethodType(_fake_seed, orchestrator)
    orchestrator._run_graph_exploration = MethodType(_fake_explore, orchestrator)
    orchestrator._run_reporting = MethodType(_fake_reporting, orchestrator)

    await orchestrator._execute_pipeline(ctx)

    assert ctx.status == ScanStatus.ERROR
    assert "reconnaissance" in (ctx.error_message or "")


@pytest.mark.anyio
async def test_pipeline_sets_error_when_vuln_phase_fails_if_enabled(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", True)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-int-vuln-fail", target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}

    async def _noop_save(self, _ctx):
        return None

    async def _fake_recon(self, _ctx):
        return {"url": "https://example.com", "domain": "example.com", "injection_points": []}

    async def _bad_vuln(self, _ctx):
        raise RuntimeError("vuln failed")

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_explore(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _fake_reporting(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    orchestrator._run_reconnaissance = MethodType(_fake_recon, orchestrator)
    orchestrator._run_vulnerability_analysis = MethodType(_bad_vuln, orchestrator)
    orchestrator._run_hypothesis_seeding = MethodType(_fake_seed, orchestrator)
    orchestrator._run_graph_exploration = MethodType(_fake_explore, orchestrator)
    orchestrator._run_reporting = MethodType(_fake_reporting, orchestrator)

    await orchestrator._execute_pipeline(ctx)

    assert ctx.status == ScanStatus.ERROR
    assert "vulnerability_analysis" in (ctx.error_message or "")


@pytest.mark.anyio
async def test_pipeline_remains_completed_when_active_confirmation_disabled(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-int-active-skip", target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}

    async def _noop_save(self, _ctx):
        return None

    async def _fake_recon(self, _ctx):
        return {"url": "https://example.com", "domain": "example.com", "injection_points": []}

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_explore(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _bad_active(self, _ctx):
        raise RuntimeError("should not be called when disabled")

    async def _fake_reporting(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    orchestrator._run_reconnaissance = MethodType(_fake_recon, orchestrator)
    orchestrator._run_hypothesis_seeding = MethodType(_fake_seed, orchestrator)
    orchestrator._run_graph_exploration = MethodType(_fake_explore, orchestrator)
    orchestrator._run_active_confirmation = MethodType(_bad_active, orchestrator)
    orchestrator._run_reporting = MethodType(_fake_reporting, orchestrator)

    await orchestrator._execute_pipeline(ctx)

    assert ctx.status == ScanStatus.COMPLETED
    assert ctx.results["active_confirmation"]["skipped"] is True

@pytest.mark.anyio
async def test_pipeline_sets_error_when_recon_phase_fails(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-int-recon-fail", target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}

    async def _noop_save(self, _ctx):
        return None

    async def _bad_recon(self, _ctx):
        raise RuntimeError("recon blew up")

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_explore(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _fake_reporting(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    orchestrator._run_reconnaissance = MethodType(_bad_recon, orchestrator)
    orchestrator._run_hypothesis_seeding = MethodType(_fake_seed, orchestrator)
    orchestrator._run_graph_exploration = MethodType(_fake_explore, orchestrator)
    orchestrator._run_reporting = MethodType(_fake_reporting, orchestrator)

    await orchestrator._execute_pipeline(ctx)

    assert ctx.status == ScanStatus.ERROR
    assert "reconnaissance" in (ctx.error_message or "")


@pytest.mark.anyio
async def test_pipeline_sets_error_when_vuln_phase_fails_if_enabled(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", True)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-int-vuln-fail", target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}

    async def _noop_save(self, _ctx):
        return None

    async def _fake_recon(self, _ctx):
        return {"url": "https://example.com", "domain": "example.com", "injection_points": []}

    async def _bad_vuln(self, _ctx):
        raise RuntimeError("vuln failed")

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_explore(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _fake_reporting(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    orchestrator._run_reconnaissance = MethodType(_fake_recon, orchestrator)
    orchestrator._run_vulnerability_analysis = MethodType(_bad_vuln, orchestrator)
    orchestrator._run_hypothesis_seeding = MethodType(_fake_seed, orchestrator)
    orchestrator._run_graph_exploration = MethodType(_fake_explore, orchestrator)
    orchestrator._run_reporting = MethodType(_fake_reporting, orchestrator)

    await orchestrator._execute_pipeline(ctx)

    assert ctx.status == ScanStatus.ERROR
    assert "vulnerability_analysis" in (ctx.error_message or "")


@pytest.mark.anyio
async def test_pipeline_remains_completed_when_active_confirmation_disabled(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-int-active-skip", target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}

    async def _noop_save(self, _ctx):
        return None

    async def _fake_recon(self, _ctx):
        return {"url": "https://example.com", "domain": "example.com", "injection_points": []}

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_explore(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _bad_active(self, _ctx):
        raise RuntimeError("should not be called when disabled")

    async def _fake_reporting(self, _ctx):
        return {
            "executive_summary": {},
            "technical_findings": [],
            "graph_summary": _ctx.graph.stats(),
            "scan_metadata": {},
            "generated_at": "now",
        }

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    orchestrator._run_reconnaissance = MethodType(_fake_recon, orchestrator)
    orchestrator._run_hypothesis_seeding = MethodType(_fake_seed, orchestrator)
    orchestrator._run_graph_exploration = MethodType(_fake_explore, orchestrator)
    orchestrator._run_active_confirmation = MethodType(_bad_active, orchestrator)
    orchestrator._run_reporting = MethodType(_fake_reporting, orchestrator)

    await orchestrator._execute_pipeline(ctx)

    assert ctx.status == ScanStatus.COMPLETED
    assert ctx.results["active_confirmation"]["skipped"] is True


@pytest.mark.anyio
async def test_max_concurrent_scans_setting_rejects_third_start(monkeypatch):
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 2)

    orchestrator = CentralOrchestrator(Database())

    async def _noop_save(self, _ctx):
        return None

    async def _noop_cleanup(self):
        return None

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    monkeypatch.setattr(orchestrator, "_ensure_cleanup_running", _noop_cleanup.__get__(orchestrator, type(orchestrator)))

    await orchestrator.start_scan(["https://a.example"], {})
    await orchestrator.start_scan(["https://b.example"], {})
    with pytest.raises(RuntimeError):
        await orchestrator.start_scan(["https://c.example"], {})


@pytest.mark.anyio
async def test_default_max_concurrent_scans_from_settings(monkeypatch):
    monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
    orchestrator = CentralOrchestrator(Database())
    assert orchestrator.MAX_CONCURRENT_SCANS == 3


@pytest.mark.anyio
async def test_pipeline_skips_payload_and_active_penetration_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_VULN_ANALYSIS_SEEDING", False)
    monkeypatch.setattr(settings, "ENABLE_PAYLOAD_GENERATION", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_PENETRATION", False)
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_CONFIRMATION", False)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-int-phases-skip", target_urls=["https://example.com"], config={})
    ctx.agents = {name: {"status": "pending"} for name in orchestrator.PIPELINE_PHASES}

    async def _noop_save(self, _ctx):
        return None

    async def _fake_recon(self, _ctx):
        return {"url": "https://example.com", "domain": "example.com", "injection_points": [], "forms": [], "api_endpoints": []}

    async def _fake_seed(self, _ctx):
        return {"hypotheses_generated": 0, "seeded_from_vuln_analysis": 0}

    async def _fake_explore(self, _ctx):
        return {"finding_count": 0, "graph_stats": _ctx.graph.stats()}

    async def _fake_reporting(self, _ctx):
        return {"executive_summary": {}, "technical_findings": [], "graph_summary": _ctx.graph.stats(), "scan_metadata": {}, "generated_at": "now"}

    orchestrator._save_session = MethodType(_noop_save, orchestrator)
    orchestrator._run_reconnaissance = MethodType(_fake_recon, orchestrator)
    orchestrator._run_hypothesis_seeding = MethodType(_fake_seed, orchestrator)
    orchestrator._run_graph_exploration = MethodType(_fake_explore, orchestrator)
    orchestrator._run_reporting = MethodType(_fake_reporting, orchestrator)

    await orchestrator._execute_pipeline(ctx)

    assert ctx.status == ScanStatus.COMPLETED
    assert ctx.results["payload_generation"]["skipped"] is True
    assert ctx.results["active_penetration"]["skipped"] is True


@pytest.mark.anyio
async def test_payload_generation_enabled_handles_empty_vuln_results(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_PAYLOAD_GENERATION", True)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-empty-vuln", target_urls=["https://example.com"], config={})
    ctx.phase_results["reconnaissance"] = {"url": "https://example.com"}
    ctx.phase_results["vulnerability_analysis"] = {"overall_risk_level": "Unknown", "vulnerabilities": []}

    class FakePayloadAgent:
        def __init__(self, _db):
            pass
        async def execute(self, task_data):
            assert task_data["vulnerability_data"]["vulnerabilities"] == []
            return {"payload_arsenal": [], "source": "AI-Driven RAG", "skipped": False}

    monkeypatch.setattr("guardian.agents.payload_agent.PayloadGenerationAgent", FakePayloadAgent)

    result = await orchestrator._run_payload_generation(ctx)
    assert result["payload_arsenal"] == []
    assert result["source"] == "AI-Driven RAG"


@pytest.mark.anyio
async def test_active_penetration_skips_on_empty_payload_arsenal(monkeypatch):
    monkeypatch.setattr(settings, "ENABLE_ACTIVE_PENETRATION", True)

    orchestrator = CentralOrchestrator(Database())
    ctx = ScanContext(session_id="sess-empty-arsenal", target_urls=["https://example.com"], config={})
    ctx.phase_results["payload_generation"] = {"payload_arsenal": [], "source": "AI-Driven RAG"}
    ctx.phase_results["reconnaissance"] = {"url": "https://example.com", "api_endpoints": [], "forms": []}

    result = await orchestrator._run_active_penetration(ctx)

    assert result["skipped"] is True
    assert result["reason"] == "empty_payload_arsenal"


def test_pipeline_phase_order_for_payload_and_penetration():
    phases = CentralOrchestrator.PIPELINE_PHASES
    assert phases.index("payload_generation") > phases.index("hypothesis_seeding")
    assert phases.index("active_penetration") > phases.index("payload_generation")