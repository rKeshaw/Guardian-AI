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
