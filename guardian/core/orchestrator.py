"""guardian/core/orchestrator.py"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from guardian.core.config import settings
from guardian.core.database import Database
from guardian.core.graph.attack_graph import AttackGraph
from guardian.core.token_ledger import TokenLedger
from guardian.models.scan_session import ScanSession, ScanStatus

logger = logging.getLogger(__name__)


class OrchestratorStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"


@dataclass
class ScanContext:
    session_id: str
    target_urls: list[str]
    config: dict[str, Any]
    status: ScanStatus = ScanStatus.INITIALIZING
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    error_message: str | None = None

    results: dict[str, Any] = field(default_factory=dict)
    phase_results: dict[str, Any] = field(default_factory=dict)
    agent_metrics: dict[str, Any] = field(default_factory=dict)
    agents: dict[str, Any] = field(default_factory=dict)

    graph: AttackGraph = field(default_factory=AttackGraph)
    ledger: TokenLedger = field(default_factory=lambda: TokenLedger(total=getattr(settings, "MAX_GRAPH_TOKENS", 20000) * 2))

    pipeline_task: asyncio.Task | None = field(default=None, repr=False)
    event_queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=256), repr=False)

    def is_terminal(self) -> bool:
        return self.status in (ScanStatus.COMPLETED, ScanStatus.ERROR)

    def age_seconds(self) -> float:
        ref = self.completed_at or self.started_at
        return (datetime.utcnow() - ref).total_seconds()


class CentralOrchestrator:
    MAX_CONCURRENT_SCANS: int = 5
    SESSION_TTL_SECONDS: int = 3600
    PIPELINE_PHASES: tuple[str, ...] = (
        "reconnaissance",
        "hypothesis_seeding",
        "graph_exploration",
        "reporting",
    )

    def __init__(self, db: Database) -> None:
        self.db = db
        self._registry: dict[str, ScanContext] = {}
        self._semaphore = asyncio.BoundedSemaphore(self.MAX_CONCURRENT_SCANS)
        self._cleanup_task: asyncio.Task | None = asyncio.create_task(self._cleanup_loop())
        self._status = OrchestratorStatus.IDLE

    async def start_scan(self, target_urls: list[str], scan_config: dict[str, Any]) -> str:
        if not self._semaphore._value:  # type: ignore[attr-defined]
            raise RuntimeError(
                f"Maximum concurrent scan limit ({self.MAX_CONCURRENT_SCANS}) reached. "
                "Wait for an active scan to complete before starting a new one."
            )

        session_id = str(uuid.uuid4())
        ctx = ScanContext(session_id=session_id, target_urls=target_urls, config=scan_config)
        ctx.agents = {name: {"status": "pending"} for name in self.PIPELINE_PHASES}
        self._registry[session_id] = ctx

        await self._save_session(ctx)
        ctx.pipeline_task = asyncio.create_task(self._run_pipeline_with_semaphore(ctx), name=f"pipeline-{session_id}")

        self._status = OrchestratorStatus.RUNNING
        return session_id

    async def get_session_status(self, session_id: str) -> dict[str, Any]:
        ctx = self._get_context(session_id)
        return {
            "session_id": session_id,
            "status": ctx.status.value if isinstance(ctx.status, Enum) else str(ctx.status),
            "progress": self._calculate_progress(ctx),
            "started_at": ctx.started_at.isoformat() if ctx.started_at else None,
            "completed_at": ctx.completed_at.isoformat() if ctx.completed_at else None,
            "error_message": ctx.error_message,
            "agent_status": ctx.agents,
            "results_preview": self._results_preview(ctx),
            "performance_metrics": ctx.agent_metrics,
        }

    async def stop_scan(self, session_id: str) -> None:
        ctx = self._get_context(session_id)
        if ctx.pipeline_task and not ctx.pipeline_task.done():
            ctx.pipeline_task.cancel()
            try:
                await ctx.pipeline_task
            except asyncio.CancelledError:
                pass
        ctx.status = ScanStatus.ERROR
        ctx.error_message = "Scan stopped by operator request."
        ctx.completed_at = datetime.utcnow()
        await self._save_session(ctx)

    async def get_agent_results(self, session_id: str, agent_name: str) -> list[dict[str, Any]]:
        return await self.db.get_results(session_id, agent_name)

    async def get_session_graph(self, session_id: str) -> AttackGraph:
        ctx = self._get_context(session_id)
        return ctx.graph

    def get_workflow_health(self) -> dict[str, Any]:
        active = sum(1 for ctx in self._registry.values() if not ctx.is_terminal())
        return {
            "orchestrator_status": self._status.value,
            "active_sessions": active,
            "total_sessions_in_memory": len(self._registry),
            "max_concurrent_scans": self.MAX_CONCURRENT_SCANS,
            "slots_available": self._semaphore._value,  # type: ignore[attr-defined]
            "last_checked": datetime.utcnow().isoformat(),
        }

    async def _run_pipeline_with_semaphore(self, ctx: ScanContext) -> None:
        async with self._semaphore:
            await self._execute_pipeline(ctx)

    async def _execute_pipeline(self, ctx: ScanContext) -> None:
        ctx.status = ScanStatus.RUNNING
        await self._save_session(ctx)

        try:
            await self._run_phase(ctx, "reconnaissance", {})
            await self._run_phase(ctx, "hypothesis_seeding", {})
            await self._run_phase(ctx, "graph_exploration", {})
            await self._run_phase(ctx, "reporting", {})

            ctx.status = ScanStatus.COMPLETED
            ctx.completed_at = datetime.utcnow()
            await self._save_session(ctx)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            ctx.status = ScanStatus.ERROR
            ctx.error_message = str(exc)
            ctx.completed_at = datetime.utcnow()
            await self._save_session(ctx)

    async def _run_phase(self, ctx: ScanContext, phase_name: str, task_data: dict[str, Any]) -> dict[str, Any]:
        t0 = datetime.utcnow()
        ctx.agents[phase_name] = {"status": "running"}
        try:
            if phase_name == "reconnaissance":
                result = await self._run_reconnaissance(ctx)
            elif phase_name == "hypothesis_seeding":
                result = await self._run_hypothesis_seeding(ctx)
            elif phase_name == "graph_exploration":
                result = await self._run_graph_exploration(ctx)
            elif phase_name == "reporting":
                result = await self._run_reporting(ctx)
            else:
                raise ValueError(f"Unknown phase: {phase_name}")

            duration = (datetime.utcnow() - t0).total_seconds()
            ctx.results[phase_name] = result
            ctx.phase_results[phase_name] = result
            ctx.agent_metrics[phase_name] = {"execution_time_s": round(duration, 2), "success": True}
            ctx.agents[phase_name] = {"status": "completed"}
            return result
        except Exception as exc:
            duration = (datetime.utcnow() - t0).total_seconds()
            ctx.agent_metrics[phase_name] = {
                "execution_time_s": round(duration, 2),
                "success": False,
                "error": str(exc),
            }
            ctx.agents[phase_name] = {"status": "failed", "error": str(exc)}
            logger.error("Phase failed phase=%s session_id=%s error=%s", phase_name, ctx.session_id, exc)
            return {}

    async def _run_reconnaissance(self, ctx: ScanContext) -> dict[str, Any]:
        from guardian.agents.reconnaissance_agent import ReconnaissanceAgent

        agent = ReconnaissanceAgent(self.db)
        target_model = await agent.run(ctx.target_urls, ctx.config)
        ctx.phase_results["reconnaissance"] = target_model.model_dump()
        return target_model.model_dump()

    async def _run_hypothesis_seeding(self, ctx: ScanContext) -> dict[str, Any]:
        from guardian.agents.hypothesis_agent import HypothesisAgent
        from guardian.core.ai_client import ai_client
        from guardian.models.target_model import TargetModel

        agent = HypothesisAgent(self.db, ai_client)
        target_model_dict = ctx.phase_results.get("reconnaissance", {})
        target_model = TargetModel(**target_model_dict)

        nodes = await agent.generate(target_model.to_hypothesis_context(), ctx.graph, ctx.ledger)
        for node in nodes:
            ctx.graph.add_node(node)
            if hasattr(self.db, "upsert_node"):
                await self.db.upsert_node(ctx.graph.graph_id, node.to_dict())

        result = {"hypotheses_generated": len(nodes)}
        ctx.phase_results["hypothesis_seeding"] = result
        return result

    async def _run_graph_exploration(self, ctx: ScanContext) -> dict[str, Any]:
        from guardian.core.ai_client import ai_client
        from guardian.core.graph.graph_orchestrator import GraphOrchestrator
        from guardian.core.intelligence.comprehender import Comprehender

        auth = ctx.config.get("auth", {})
        auth_headers = None
        if auth.get("type") == "bearer":
            auth_headers = {"Authorization": f"Bearer {auth.get('bearer_token', '')}"}

        cookies = auth.get("cookies") if isinstance(auth.get("cookies"), dict) else None

        try:
            from guardian.core.probing.probe_executor import ProbeExecutor
        except Exception as exc:
            logger.warning("ProbeExecutor unavailable: %s", exc)
            return {"findings": 0, "error": "probe_executor_unavailable"}

        probe_executor = await ProbeExecutor.create(auth_headers=auth_headers, cookies=cookies)

        from guardian.core.probing.session_manager import SessionManager

        auth_ok = await SessionManager().authenticate(auth, getattr(probe_executor, "_session", None)) if getattr(probe_executor, "_session", None) is not None else True
        if not auth_ok:
            logger.warning("Authentication failed for session_id=%s", ctx.session_id)

        try:
            orch = GraphOrchestrator(ai_client, Comprehender(), self.db)
            await orch.run(
                ctx.session_id,
                ctx.phase_results.get("reconnaissance", {}),
                ctx.graph,
                probe_executor,
                ctx.ledger,
            )
        finally:
            await probe_executor.close()

        finding_count = len(ctx.graph.get_findings())
        result = {"finding_count": finding_count, "graph_stats": ctx.graph.stats()}
        ctx.phase_results["graph_exploration"] = result
        return result

    async def _run_reporting(self, ctx: ScanContext) -> dict[str, Any]:
        from guardian.agents.reporting_agent import ReportingAgent
        from guardian.core.ai_client import ai_client

        agent = ReportingAgent(self.db, ai_client)
        report = await agent.generate(ctx.graph, ctx.phase_results, ctx.session_id, ctx.ledger)
        ctx.phase_results["reporting"] = report
        await self.db.save_agent_result(ctx.session_id, "reporting", report)
        return report

    def _get_context(self, session_id: str) -> ScanContext:
        ctx = self._registry.get(session_id)
        if ctx is None:
            raise KeyError(
                f"Session '{session_id}' not found in memory. "
                "It may have been evicted after TTL expiry — query the database directly."
            )
        return ctx

    async def _save_session(self, ctx: ScanContext) -> None:
        session = ScanSession(
            session_id=ctx.session_id,
            target_urls=ctx.target_urls,
            config=ctx.config,
            status=ctx.status,
            started_at=ctx.started_at,
            completed_at=ctx.completed_at,
            error_message=ctx.error_message,
            results_summary=self._results_preview(ctx),
        )
        try:
            await self.db.save_session(session)
        except Exception as exc:
            logger.warning("Could not persist session session_id=%s error=%s", ctx.session_id, exc)

    def _calculate_progress(self, ctx: ScanContext) -> dict[str, Any]:
        phases = list(self.PIPELINE_PHASES)
        completed = [p for p in phases if p in ctx.results]
        pct = (len(completed) / len(phases) * 100.0) if phases else 0.0
        if ctx.status == ScanStatus.COMPLETED:
            pct = 100.0
        return {
            "overall": round(pct, 1),
            "phases": {p: (100.0 if p in ctx.results else 0.0) for p in phases},
        }

    def _results_preview(self, ctx: ScanContext) -> dict[str, Any]:
        recon = ctx.results.get("reconnaissance", {})
        seed = ctx.results.get("hypothesis_seeding", {})
        explore = ctx.results.get("graph_exploration", {})
        report = ctx.results.get("reporting", {})
        return {
            "reconnaissance": {
                "completed": "reconnaissance" in ctx.results,
                "domain": recon.get("domain"),
                "injection_points": len(recon.get("injection_points", [])),
            },
            "hypothesis_seeding": {
                "completed": "hypothesis_seeding" in ctx.results,
                "hypotheses_generated": seed.get("hypotheses_generated", 0),
            },
            "graph_exploration": {
                "completed": "graph_exploration" in ctx.results,
                "finding_count": explore.get("finding_count", 0),
            },
            "reporting": {
                "completed": "reporting" in ctx.results,
                "report_available": bool(report),
            },
        }

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(300)
            try:
                self._evict_expired_sessions()
            except Exception as exc:
                logger.warning("Session cleanup error: %s", exc)

    def _evict_expired_sessions(self) -> None:
        cutoff = self.SESSION_TTL_SECONDS
        to_evict = [
            sid
            for sid, ctx in self._registry.items()
            if ctx.is_terminal() and ctx.age_seconds() > cutoff
        ]
        for sid in to_evict:
            del self._registry[sid]