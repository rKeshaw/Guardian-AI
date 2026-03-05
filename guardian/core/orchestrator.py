"""
guardian/core/orchestrator.py
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from guardian.core.config import settings
from guardian.core.database import Database
from guardian.models.scan_session import ScanSession, ScanStatus

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Orchestrator-level status (not per-session)
# ──────────────────────────────────────────────
class OrchestratorStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"


# ──────────────────────────────────────────────
# Per-session state container
# ──────────────────────────────────────────────
@dataclass
class ScanContext:
    """
    Owns all mutable state for a single scan session.
    Never shared between sessions.
    """
    session_id: str
    target_urls: list[str]
    config: dict[str, Any]
    status: ScanStatus = ScanStatus.INITIALIZING
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    error_message: str | None = None

    # Results keyed by phase name
    results: dict[str, Any] = field(default_factory=dict)

    # Per-agent execution metrics
    agent_metrics: dict[str, Any] = field(default_factory=dict)

    # Agent instances — fresh per session, never reused
    agents: dict[str, Any] = field(default_factory=dict)

    # Asyncio task running the pipeline
    pipeline_task: asyncio.Task | None = field(default=None, repr=False)

    # Event bus for WebSocket / streaming (enhancement hook)
    event_queue: asyncio.Queue = field(
        default_factory=lambda: asyncio.Queue(maxsize=256),
        repr=False,
    )

    def is_terminal(self) -> bool:
        return self.status in (ScanStatus.COMPLETED, ScanStatus.ERROR)

    def age_seconds(self) -> float:
        ref = self.completed_at or self.started_at
        return (datetime.utcnow() - ref).total_seconds()


# ──────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────
class CentralOrchestrator:
    """
    Session-isolated multi-agent orchestrator.

    Public surface:
        start_scan(target_urls, config) -> session_id
        get_session_status(session_id)  -> dict
        stop_scan(session_id)
        get_agent_results(session_id, agent_name) -> list
        get_workflow_health() -> dict
    """

    # Maximum concurrent active scans
    MAX_CONCURRENT_SCANS: int = 5

    # Evict completed/errored sessions after this many seconds
    SESSION_TTL_SECONDS: int = 3600  # 1 hour

    def __init__(self, db: Database) -> None:
        self.db = db
        self._registry: dict[str, ScanContext] = {}
        self._semaphore = asyncio.BoundedSemaphore(self.MAX_CONCURRENT_SCANS)
        self._cleanup_task: asyncio.Task | None = None
        self._status = OrchestratorStatus.IDLE

        # Start the background TTL cleanup loop
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("CentralOrchestrator initialised (max_concurrent=%d)", self.MAX_CONCURRENT_SCANS)

    # ── Public API ────────────────────────────

    async def start_scan(
        self,
        target_urls: list[str],
        scan_config: dict[str, Any],
    ) -> str:
        """
        Create a new isolated ScanContext and launch the pipeline.
        Returns the session_id immediately; the pipeline runs in the background.
        Raises RuntimeError if the concurrent-session limit is reached.
        """
        # Non-blocking acquire — raise immediately if at capacity
        if not self._semaphore._value:  # type: ignore[attr-defined]
            raise RuntimeError(
                f"Maximum concurrent scan limit ({self.MAX_CONCURRENT_SCANS}) reached. "
                "Wait for an active scan to complete before starting a new one."
            )

        session_id = str(uuid.uuid4())
        ctx = ScanContext(
            session_id=session_id,
            target_urls=target_urls,
            config=scan_config,
        )
        ctx.agents = self._build_agents(ctx)
        self._registry[session_id] = ctx

        # Persist the initial session record
        await self._save_session(ctx)

        # Launch the pipeline as a background task; semaphore is held for its lifetime
        ctx.pipeline_task = asyncio.create_task(
            self._run_pipeline_with_semaphore(ctx),
            name=f"pipeline-{session_id}",
        )

        self._status = OrchestratorStatus.RUNNING
        logger.info("Scan started session_id=%s targets=%s", session_id, target_urls)
        return session_id

    async def get_session_status(self, session_id: str) -> dict[str, Any]:
        """
        Return a serialisable status dict for the given session.
        Raises KeyError if the session is not in the in-memory registry
        (e.g. evicted after TTL); in that case the caller should fall back
        to the database.
        """
        ctx = self._get_context(session_id)

        return {
            "session_id": session_id,
            "status": ctx.status.value if isinstance(ctx.status, Enum) else str(ctx.status),
            "progress": self._calculate_progress(ctx),
            "started_at": ctx.started_at.isoformat() if ctx.started_at else None,
            "completed_at": ctx.completed_at.isoformat() if ctx.completed_at else None,
            "error_message": ctx.error_message,
            "agent_status": {
                name: agent.get_status()
                for name, agent in ctx.agents.items()
            },
            "results_preview": self._results_preview(ctx),
            "performance_metrics": ctx.agent_metrics,
        }

    async def stop_scan(self, session_id: str) -> None:
        """Cancel the pipeline task for a session and mark it stopped."""
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
        for agent in ctx.agents.values():
            await agent.cleanup()
        logger.info("Scan stopped session_id=%s", session_id)

    async def get_agent_results(
        self, session_id: str, agent_name: str
    ) -> list[dict[str, Any]]:
        """Retrieve persisted agent results from the database."""
        return await self.db.get_results(session_id, agent_name)

    def get_workflow_health(self) -> dict[str, Any]:
        active = sum(
            1 for ctx in self._registry.values() if not ctx.is_terminal()
        )
        return {
            "orchestrator_status": self._status.value,
            "active_sessions": active,
            "total_sessions_in_memory": len(self._registry),
            "max_concurrent_scans": self.MAX_CONCURRENT_SCANS,
            "slots_available": self._semaphore._value,  # type: ignore[attr-defined]
            "last_checked": datetime.utcnow().isoformat(),
        }

    # ── Internal pipeline ─────────────────────

    def _build_agents(self, ctx: ScanContext) -> dict[str, Any]:
        """
        Instantiate all five agents fresh for this session.
        No agent instance is ever shared between sessions.
        """
        from guardian.agents.reconnaissance_agent import ReconnaissanceAgent
        from guardian.agents.vulnerability_agent import VulnerabilityAnalysisAgent
        from guardian.agents.payload_agent import PayloadGenerationAgent
        from guardian.agents.penetration_agent import PenetrationAgent
        from guardian.agents.reporting_agent import ReportingAgent

        return {
            "reconnaissance":       ReconnaissanceAgent(self.db),
            "vulnerability_analysis": VulnerabilityAnalysisAgent(self.db),
            "payload_generation":   PayloadGenerationAgent(self.db),
            "penetration":          PenetrationAgent(self.db),
            "reporting":            ReportingAgent(self.db),
        }

    async def _run_pipeline_with_semaphore(self, ctx: ScanContext) -> None:
        """Acquire the semaphore, run the pipeline, release on exit."""
        async with self._semaphore:
            await self._execute_pipeline(ctx)

    async def _execute_pipeline(self, ctx: ScanContext) -> None:
        """
        Execute the five-agent pipeline for a single session.

        Each phase is wrapped individually so that a failure in one phase
        stores partial results and continues where possible, rather than
        aborting everything.  If a phase fails its output is an empty dict
        and the next phase receives whatever was accumulated so far.
        """
        ctx.status = ScanStatus.RUNNING
        await self._save_session(ctx)
        await self._emit(ctx, "pipeline.started", {"targets": ctx.target_urls})

        try:
            # ── Phase 1: Reconnaissance ──────────────────────────
            recon_results = await self._run_phase(
                ctx,
                phase_name="reconnaissance",
                task_data={
                    "targets": ctx.target_urls,
                    "config": ctx.config.get("reconnaissance", {}),
                    "session_id": ctx.session_id,
                },
            )

            # ── Phase 2: Vulnerability Analysis ─────────────────
            vuln_results = await self._run_phase(
                ctx,
                phase_name="vulnerability_analysis",
                task_data={
                    "reconnaissance_data": recon_results,
                    "config": ctx.config.get("vulnerability_analysis", {}),
                    "session_id": ctx.session_id,
                },
            )

            # ── Phase 3: Payload Generation ──────────────────────
            payload_results = await self._run_phase(
                ctx,
                phase_name="payload_generation",
                task_data={
                    "vulnerability_data": vuln_results.get(
                        "vulnerability_assessment", vuln_results
                    ),
                    "reconnaissance_data": recon_results,
                    "config": ctx.config.get("payload_generation", {}),
                    "session_id": ctx.session_id,
                },
            )

            # ── Phase 4: Penetration Testing ─────────────────────
            penetration_results = await self._run_phase(
                ctx,
                phase_name="penetration",
                task_data={
                    "payloads": payload_results,
                    "targets": recon_results,
                    "vulnerabilities": vuln_results,
                    "config": ctx.config.get("penetration", {}),
                    "session_id": ctx.session_id,
                },
            )

            # ── Phase 5: Reporting ───────────────────────────────
            await self._run_phase(
                ctx,
                phase_name="reporting",
                task_data={
                    "all_results": ctx.results,
                    "session_id": ctx.session_id,
                    "config": ctx.config.get("reporting", {}),
                },
            )

            # ── Completion ───────────────────────────────────────
            ctx.status = ScanStatus.COMPLETED
            ctx.completed_at = datetime.utcnow()
            await self._save_session(ctx)
            await self._emit(ctx, "pipeline.completed", self._results_preview(ctx))
            logger.info(
                "Pipeline completed session_id=%s duration_s=%.1f",
                ctx.session_id,
                (ctx.completed_at - ctx.started_at).total_seconds(),
            )

        except asyncio.CancelledError:
            logger.warning("Pipeline cancelled session_id=%s", ctx.session_id)
            raise

        except Exception as exc:
            ctx.status = ScanStatus.ERROR
            ctx.error_message = str(exc)
            ctx.completed_at = datetime.utcnow()
            await self._save_session(ctx)
            await self._emit(ctx, "pipeline.error", {"error": str(exc)})
            logger.exception("Pipeline failed session_id=%s", ctx.session_id)

    async def _run_phase(
        self,
        ctx: ScanContext,
        phase_name: str,
        task_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Execute a single pipeline phase with:
          - Timing metrics
          - Per-phase error isolation (failure returns {} and logs, does not raise)
          - Result checkpointing to ctx.results
          - Event emission for real-time progress
        """
        agent = ctx.agents[phase_name]
        logger.info("Phase starting phase=%s session_id=%s", phase_name, ctx.session_id)
        await self._emit(ctx, f"phase.started", {"phase": phase_name})
        t0 = datetime.utcnow()

        try:
            result = await agent.execute(task_data)
            duration = (datetime.utcnow() - t0).total_seconds()
            ctx.results[phase_name] = result
            ctx.agent_metrics[phase_name] = {
                "execution_time_s": round(duration, 2),
                "success": True,
            }
            logger.info(
                "Phase completed phase=%s session_id=%s duration_s=%.1f",
                phase_name, ctx.session_id, duration,
            )
            await self._emit(ctx, "phase.completed", {
                "phase": phase_name,
                "duration_s": round(duration, 2),
            })
            return result

        except Exception as exc:
            duration = (datetime.utcnow() - t0).total_seconds()
            ctx.agent_metrics[phase_name] = {
                "execution_time_s": round(duration, 2),
                "success": False,
                "error": str(exc),
            }
            logger.error(
                "Phase failed phase=%s session_id=%s error=%s",
                phase_name, ctx.session_id, exc,
            )
            await self._emit(ctx, "phase.failed", {
                "phase": phase_name,
                "error": str(exc),
            })
            # Return empty dict so downstream phases receive a safe value
            return {}

    # ── Helpers ───────────────────────────────

    def _get_context(self, session_id: str) -> ScanContext:
        ctx = self._registry.get(session_id)
        if ctx is None:
            raise KeyError(
                f"Session '{session_id}' not found in memory. "
                "It may have been evicted after TTL expiry — query the database directly."
            )
        return ctx

    async def _save_session(self, ctx: ScanContext) -> None:
        """Persist the session record to the database."""
        session = ScanSession(
            session_id=ctx.session_id,
            target_urls=ctx.target_urls,
            config=ctx.config,
            status=ctx.status,
            started_at=ctx.started_at,
            completed_at=ctx.completed_at,
            error_message=ctx.error_message,
        )
        try:
            await self.db.save_session(session)
        except Exception as exc:
            logger.warning(
                "Could not persist session session_id=%s error=%s",
                ctx.session_id, exc,
            )

    async def _emit(
        self, ctx: ScanContext, event: str, data: dict[str, Any]
    ) -> None:
        """
        Push an event onto the session's event queue for WebSocket streaming.
        Non-blocking: if the queue is full the event is dropped with a warning.
        """
        payload = {
            "event": event,
            "session_id": ctx.session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data,
        }
        try:
            ctx.event_queue.put_nowait(payload)
        except asyncio.QueueFull:
            logger.warning(
                "Event queue full — dropping event event=%s session_id=%s",
                event, ctx.session_id,
            )

    def _calculate_progress(self, ctx: ScanContext) -> dict[str, Any]:
        """Return overall and per-phase progress as percentages."""
        phases = list(ctx.agents.keys())
        completed = [p for p in phases if p in ctx.results]
        pct = (len(completed) / len(phases) * 100.0) if phases else 0.0

        if ctx.status == ScanStatus.COMPLETED:
            pct = 100.0

        return {
            "overall": round(pct, 1),
            "phases": {
                p: (100.0 if p in ctx.results else 0.0)
                for p in phases
            },
        }

    def _results_preview(self, ctx: ScanContext) -> dict[str, Any]:
        """Lightweight summary of current results — safe to return in status calls."""
        recon = ctx.results.get("reconnaissance", {})
        vuln = ctx.results.get("vulnerability_analysis", {})
        payload = ctx.results.get("payload_generation", {})
        pentest = ctx.results.get("penetration", {})
        report = ctx.results.get("reporting", {})

        return {
            "reconnaissance": {
                "completed": "reconnaissance" in ctx.results,
                "targets_analyzed": recon.get("targets_analyzed", 0),
            },
            "vulnerability_analysis": {
                "completed": "vulnerability_analysis" in ctx.results,
                "vulnerabilities_found": len(
                    vuln.get("vulnerability_assessment", {}).get("vulnerabilities", [])
                ),
            },
            "payload_generation": {
                "completed": "payload_generation" in ctx.results,
                "payload_entries": len(payload.get("payload_arsenal", [])),
            },
            "penetration": {
                "completed": "penetration" in ctx.results,
                "successful_exploits": sum(
                    len(t.get("successful_exploits", []))
                    for t in pentest.get("penetration_results", {}).values()
                ),
            },
            "reporting": {
                "completed": "reporting" in ctx.results,
                "report_available": bool(report.get("report")),
            },
        }

    # ── Background TTL cleanup ────────────────

    async def _cleanup_loop(self) -> None:
        """
        Runs every 5 minutes. Evicts sessions that are in a terminal state
        (COMPLETED or ERROR) and older than SESSION_TTL_SECONDS.
        This prevents the in-memory registry from growing without bound on
        long-running deployments.
        """
        while True:
            await asyncio.sleep(300)  # 5 minutes
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
            logger.debug("Evicted expired session session_id=%s", sid)
        if to_evict:
            logger.info(
                "TTL cleanup evicted %d session(s). Registry size=%d",
                len(to_evict),
                len(self._registry),
            )
