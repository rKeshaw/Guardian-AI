from __future__ import annotations

import json
import time
import uuid

import aiosqlite
import pytest

from guardian.core.orchestrator import CentralOrchestrator
from guardian.core.graph.attack_graph import NodeType

from .helpers import assert_finding_references_vuln_type


@pytest.mark.integration
@pytest.mark.timeout(900)
@pytest.mark.anyio
async def test_full_pipeline_scan_dvwa_sqli(test_db, dvwa_sqli_url, scan_auth_config):
    orch = CentralOrchestrator(test_db)

    session_id = await orch.start_scan(
        [dvwa_sqli_url],
        {
            "auth": scan_auth_config,
            "max_hypotheses": 3,
            "max_turns_per_hypothesis": 6,
            "enable_vuln_analysis": True,
            "enable_active_confirmation": True,
        },
    )

    deadline = time.monotonic() + 900
    final = None
    while time.monotonic() < deadline:
        st = await orch.get_session_status(session_id)
        if st["status"] in {"completed", "error"}:
            final = st
            break
        await __import__("asyncio").sleep(10)

    assert final is not None, "scan did not reach terminal state within timeout"
    assert final["status"] == "completed"

    ctx = orch._get_context(session_id)
    report = ctx.phase_results.get("reporting", {})
    graph = ctx.graph

    try:
        with open("/tmp/guardian_test_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        with open("/tmp/guardian_test_graph.json", "w", encoding="utf-8") as f:
            json.dump(graph.to_d3(), f, indent=2, default=str)
    finally:
        pass

    recon = ctx.phase_results.get("reconnaissance", {})
    assert any(p.get("param_name") == "id" for p in recon.get("injection_points", []))

    hyp_nodes = [n for n in graph.nodes.values() if n.type == NodeType.HYPOTHESIS]
    assert hyp_nodes or ctx.phase_results.get("hypothesis_seeding", {}).get("hypotheses_generated", 0) > 0

    assert len(graph.nodes) >= 3
    assert report
    assert str(report.get("executive_summary", "")).strip()

    findings = report.get("technical_findings", [])
    assert findings
    assert_finding_references_vuln_type(findings, ["sql", "inject", "id"])

    async with aiosqlite.connect(test_db.db_path) as conn:
        async with conn.execute("SELECT graph_id, node_id, COUNT(*) FROM graph_nodes GROUP BY graph_id, node_id HAVING COUNT(*) > 1") as cur:
            dupes = await cur.fetchall()
        async with conn.execute("SELECT graph_id, COUNT(*) FROM graph_meta GROUP BY graph_id HAVING COUNT(*) > 1") as cur:
            meta_dupes = await cur.fetchall()

    assert not dupes
    assert not meta_dupes
