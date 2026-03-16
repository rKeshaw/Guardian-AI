"""guardian/core/orchestrator.py"""

from __future__ import annotations

import json
import asyncio
import logging
import random
import ssl
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from guardian.core.config import settings
from guardian.core.database import Database
from guardian.core.graph.attack_graph import AttackGraph, Node, NodeType
from guardian.core.token_ledger import TokenLedger
from guardian.core.pipeline_contracts import (
    GraphExplorationPhaseOutput,
    HypothesisPhaseOutput,
    PayloadPhaseOutput,
    PenetrationPhaseOutput,
    ReconPhaseOutput,
    ReportPhaseOutput,
    ScanPhaseResults,
    VulnAnalysisPhaseOutput,
)
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
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    error_message: str | None = None

    results: dict[str, Any] = field(default_factory=dict)
    phase_results: dict[str, Any] = field(default_factory=dict)
    typed_phase_results: ScanPhaseResults = field(default_factory=ScanPhaseResults)
    agent_metrics: dict[str, Any] = field(default_factory=dict)
    agents: dict[str, Any] = field(default_factory=dict)
    pipeline_degraded: bool = False
    failed_phases: list[str] = field(default_factory=list)

    graph: AttackGraph = field(default_factory=AttackGraph)
    ledger: TokenLedger = field(default_factory=lambda: TokenLedger(total=settings.MAX_GRAPH_TOKENS * 2))

    pipeline_task: asyncio.Task | None = field(default=None, repr=False)
    event_queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=256), repr=False)

    def is_terminal(self) -> bool:
        return self.status in (ScanStatus.COMPLETED, ScanStatus.ERROR)

    def age_seconds(self) -> float:
        ref = self.completed_at or self.started_at
        return (datetime.now(timezone.utc) - ref).total_seconds()


class CentralOrchestrator:
    SESSION_TTL_SECONDS: int = 3600
    PIPELINE_PHASES: tuple[str, ...] = (
        "reconnaissance",
        "vulnerability_analysis",
        "hypothesis_seeding",
        "payload_generation",
        "active_penetration",
        "graph_exploration",
        "active_confirmation",
        "reporting",
    )
    PHASE_WEIGHTS: dict[str, float] = {
        "reconnaissance": 15.0,
        "vulnerability_analysis": 10.0,
        "hypothesis_seeding": 10.0,
        "payload_generation": 5.0,
        "active_penetration": 10.0,
        "graph_exploration": 35.0,
        "active_confirmation": 10.0,
        "reporting": 10.0,
    }

    def __init__(self, db: Database) -> None:
        self.db = db
        self._registry: dict[str, ScanContext] = {}
        self.MAX_CONCURRENT_SCANS = int(settings.MAX_CONCURRENT_SCANS)
        self._semaphore = asyncio.BoundedSemaphore(self.MAX_CONCURRENT_SCANS)
        self._cleanup_task: asyncio.Task | None = None
        self._active_scans: int = 0
        self._capacity_lock = asyncio.Lock()
        self._status = OrchestratorStatus.IDLE

    async def start_scan(self, target_urls: list[str], scan_config: dict[str, Any]) -> str:
        await self._ensure_cleanup_running()

        async with self._capacity_lock:
            if self._active_scans >= self.MAX_CONCURRENT_SCANS:
                raise RuntimeError(
                    f"Maximum concurrent scan limit ({self.MAX_CONCURRENT_SCANS}) reached. "
                    "Wait for an active scan to complete before starting a new one."
                )
            self._active_scans += 1

        session_id = str(uuid.uuid4())
        ctx = ScanContext(session_id=session_id, target_urls=target_urls, config=scan_config)
        ctx.agents = {name: {"status": "pending"} for name in self.PIPELINE_PHASES}
        self._registry[session_id] = ctx

        await self._save_session(ctx)
        try:
            ctx.pipeline_task = asyncio.create_task(self._run_pipeline_with_semaphore(ctx), name=f"pipeline-{session_id}")
        except Exception:
            async with self._capacity_lock:
                self._active_scans = max(0, self._active_scans - 1)
            raise

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
        ctx.completed_at = datetime.now(timezone.utc)
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
            "slots_available": max(0, self.MAX_CONCURRENT_SCANS - self._active_scans),
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }

    async def _run_pipeline_with_semaphore(self, ctx: ScanContext) -> None:
        try:
            async with self._semaphore:
                await self._execute_pipeline(ctx)
        finally:
            async with self._capacity_lock:
                self._active_scans = max(0, self._active_scans - 1)

    async def _execute_pipeline(self, ctx: ScanContext) -> None:
        ctx.status = ScanStatus.RUNNING
        await self._save_session(ctx)

        try:
            await self._run_phase(ctx, "reconnaissance")
            recon_result = ctx.phase_results.get("reconnaissance", {})
            if "reconnaissance" not in ctx.failed_phases and not recon_result.get("url") and not recon_result.get("domain"):
                ctx.status = ScanStatus.ERROR
                ctx.error_message = "Reconnaissance phase produced empty result — aborting pipeline."
                ctx.completed_at = datetime.now(timezone.utc)
                await self._save_session(ctx)
                self._publish(ctx, {"event": "scan_error", "session_id": ctx.session_id, "error": ctx.error_message})
                return
            deterministic_findings = await self._run_deterministic_checks(ctx)
            ctx.phase_results["deterministic_findings"] = deterministic_findings
            ctx.results["deterministic_findings"] = deterministic_findings
            await self._run_phase(ctx, "vulnerability_analysis")
            await self._run_phase(ctx, "hypothesis_seeding")
            await self._run_phase(ctx, "payload_generation")
            await self._run_phase(ctx, "active_penetration")
            await self._run_phase(ctx, "graph_exploration")
            await self._run_phase(ctx, "active_confirmation")
            await self._run_phase(ctx, "reporting")

            failed_required = [
                phase for phase in ctx.failed_phases
                if self._is_required_phase(phase)
            ]
            if failed_required:
                ctx.status = ScanStatus.ERROR
                ctx.error_message = (
                    "Pipeline degraded: required phase(s) failed: "
                    + ", ".join(sorted(set(failed_required)))
                )
            else:
                ctx.status = ScanStatus.COMPLETED
            ctx.completed_at = datetime.now(timezone.utc)
            await self._save_session(ctx)
            self._publish(ctx, {"event": "scan_complete", "session_id": ctx.session_id})

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            ctx.status = ScanStatus.ERROR
            ctx.error_message = str(exc)
            ctx.completed_at = datetime.now(timezone.utc)
            await self._save_session(ctx)
            self._publish(ctx, {"event": "scan_error", "session_id": ctx.session_id, "error": str(exc)})

    def _is_required_phase(self, phase_name: str) -> bool:
        if phase_name == "vulnerability_analysis":
            return bool(settings.ENABLE_VULN_ANALYSIS_SEEDING)
        if phase_name == "active_confirmation":
            return bool(settings.ENABLE_ACTIVE_CONFIRMATION)
        if phase_name == "payload_generation":
            return bool(settings.ENABLE_PAYLOAD_GENERATION)
        if phase_name == "active_penetration":
            return bool(settings.ENABLE_ACTIVE_PENETRATION)
        return phase_name in {"reconnaissance", "hypothesis_seeding", "graph_exploration", "reporting"}

    async def _run_phase(self, ctx: ScanContext, phase_name: str) -> dict[str, Any]:
        t0 = datetime.now(timezone.utc)
        ctx.agents[phase_name] = {"status": "running"}
        self._publish(ctx, {"event": "phase_start", "phase": phase_name})

        if phase_name == "vulnerability_analysis" and not settings.ENABLE_VULN_ANALYSIS_SEEDING:
            result = VulnAnalysisPhaseOutput(
                overall_risk_level="Unknown",
                vulnerabilities=[],
                skipped=True,
            ).model_dump()
            ctx.results[phase_name] = result
            ctx.phase_results[phase_name] = result
            self._record_typed_phase_result(ctx, phase_name, result)
            duration = (datetime.now(timezone.utc) - t0).total_seconds()
            ctx.agent_metrics[phase_name] = {
                "execution_time_s": round(duration, 2),
                "success": True,
                "skipped": True,
            }
            ctx.agents[phase_name] = {"status": "completed", "skipped": True}
            self._publish(
                ctx,
                {
                    "event": "phase_complete",
                    "phase": phase_name,
                    "data": {"duration_s": round(duration, 2), "skipped": True},
                },
            )
            return result

        if phase_name == "active_confirmation" and not settings.ENABLE_ACTIVE_CONFIRMATION:
            result = {"skipped": True, "active_confirmation_results": []}
            ctx.results[phase_name] = result
            ctx.phase_results[phase_name] = result
            self._record_typed_phase_result(ctx, phase_name, result)
            duration = (datetime.now(timezone.utc) - t0).total_seconds()
            ctx.agent_metrics[phase_name] = {
                "execution_time_s": round(duration, 2),
                "success": True,
                "skipped": True,
            }
            ctx.agents[phase_name] = {"status": "completed", "skipped": True}
            self._publish(
                ctx,
                {
                    "event": "phase_complete",
                    "phase": phase_name,
                    "data": {"duration_s": round(duration, 2), "skipped": True},
                },
            )
            return result

        if phase_name == "payload_generation" and not settings.ENABLE_PAYLOAD_GENERATION:
            result = {"payload_arsenal": [], "source": "disabled", "skipped": True}
            ctx.results[phase_name] = result
            ctx.phase_results[phase_name] = result
            self._record_typed_phase_result(ctx, phase_name, result)
            duration = (datetime.now(timezone.utc) - t0).total_seconds()
            ctx.agent_metrics[phase_name] = {
                "execution_time_s": round(duration, 2),
                "success": True,
                "skipped": True,
            }
            ctx.agents[phase_name] = {"status": "completed", "skipped": True}
            self._publish(
                ctx,
                {
                    "event": "phase_complete",
                    "phase": phase_name,
                    "data": {"duration_s": round(duration, 2), "skipped": True},
                },
            )
            return result

        if phase_name == "active_penetration" and not settings.ENABLE_ACTIVE_PENETRATION:
            result = {"penetration_results": {}, "evidence_package": {}, "successful_exploits": [], "skipped": True}
            ctx.results[phase_name] = result
            ctx.phase_results[phase_name] = result
            self._record_typed_phase_result(ctx, phase_name, result)
            duration = (datetime.now(timezone.utc) - t0).total_seconds()
            ctx.agent_metrics[phase_name] = {
                "execution_time_s": round(duration, 2),
                "success": True,
                "skipped": True,
            }
            ctx.agents[phase_name] = {"status": "completed", "skipped": True}
            self._publish(
                ctx,
                {
                    "event": "phase_complete",
                    "phase": phase_name,
                    "data": {"duration_s": round(duration, 2), "skipped": True},
                },
            )
            return result
        
        try:
            if phase_name == "reconnaissance":
                result = await self._run_reconnaissance(ctx)
            elif phase_name == "vulnerability_analysis":
                result = await self._run_vulnerability_analysis(ctx)
            elif phase_name == "hypothesis_seeding":
                result = await self._run_hypothesis_seeding(ctx)
            elif phase_name == "payload_generation":
                result = await self._run_payload_generation(ctx)
            elif phase_name == "active_penetration":
                result = await self._run_active_penetration(ctx)
            elif phase_name == "graph_exploration":
                result = await self._run_graph_exploration(ctx)
            elif phase_name == "active_confirmation":
                result = await self._run_active_confirmation(ctx)
            elif phase_name == "reporting":
                result = await self._run_reporting(ctx)
            else:
                raise ValueError(f"Unknown phase: {phase_name}")

            duration = (datetime.now(timezone.utc) - t0).total_seconds()
            ctx.results[phase_name] = result
            ctx.phase_results[phase_name] = result
            self._record_typed_phase_result(ctx, phase_name, result)
            ctx.agent_metrics[phase_name] = {"execution_time_s": round(duration, 2), "success": True}
            ctx.agents[phase_name] = {"status": "completed"}
            self._publish(
                ctx,
                {
                    "event": "phase_complete",
                    "phase": phase_name,
                    "data": {
                        "duration_s": round(duration, 2),
                        "skipped": bool(result.get("skipped", False)),
                    },
                },
            )
            return result
        except Exception as exc:
            duration = (datetime.now(timezone.utc) - t0).total_seconds()
            ctx.agent_metrics[phase_name] = {
                "execution_time_s": round(duration, 2),
                "success": False,
                "error": str(exc),
            }
            ctx.pipeline_degraded = True
            if phase_name not in ctx.failed_phases:
                ctx.failed_phases.append(phase_name)
            ctx.agents[phase_name] = {"status": "failed", "error": str(exc)}
            logger.error("Phase failed phase=%s session_id=%s error=%s", phase_name, ctx.session_id, exc)
            self._publish(ctx, {"event": "phase_error", "phase": phase_name, "data": {"error": str(exc)}})
            return {}

    async def _run_reconnaissance(self, ctx: ScanContext) -> dict[str, Any]:
        from guardian.agents.reconnaissance_agent import ReconnaissanceAgent

        agent = ReconnaissanceAgent(self.db)
        target_model = await agent.run(ctx.target_urls, ctx.config)
        ctx.phase_results["reconnaissance"] = target_model.model_dump()
        return target_model.model_dump()
    
    async def _run_vulnerability_analysis(self, ctx: ScanContext) -> dict[str, Any]:
        if not settings.ENABLE_VULN_ANALYSIS_SEEDING:
            logger.info("Option A disabled; skipping vulnerability analysis phase")
            result = VulnAnalysisPhaseOutput(
                overall_risk_level="Unknown",
                vulnerabilities=[],
                skipped=True,
            ).model_dump()
            ctx.phase_results["vulnerability_analysis"] = result
            return result

        from guardian.agents.vulnerability_agent import VulnerabilityAnalysisAgent

        recon_output = ctx.phase_results.get("reconnaissance", {})
        target_url = recon_output.get("url", "unknown_target")
        task_data = {
            "session_id": ctx.session_id,
            "reconnaissance_data": {
                "targets_analyzed": 1,
                "reconnaissance_data": {
                    target_url: recon_output,
                },
            },
        }

        result = await VulnerabilityAnalysisAgent(self.db).execute(task_data)
        normalized = {
            "overall_risk_level": result.get("overall_risk_level", "Unknown"),
            "vulnerabilities": result.get("vulnerabilities", []),
            "error": result.get("error"),
            "skipped": False,
            **result,
        }
        ctx.phase_results["vulnerability_analysis"] = normalized
        return normalized

    def _seed_hypotheses_from_vuln_analysis(self, ctx: ScanContext, vuln_results: dict[str, Any]) -> int:
        vulnerabilities = vuln_results.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            return 0

        recon = ctx.phase_results.get("reconnaissance", {})
        injection_points = recon.get("injection_points", [])
        if not isinstance(injection_points, list) or not injection_points:
            return 0

        impact_by_risk = {"critical": 9, "high": 7, "medium": 5, "low": 3}
        confidence_by_risk = {"critical": 80, "high": 65, "medium": 45, "low": 25}

        existing_keys: set[tuple[str, str, str]] = set()
        for node in ctx.graph.nodes.values():
            if node.type != NodeType.HYPOTHESIS:
                continue

            payload = node.data if isinstance(node.data, dict) else {}
            ip = payload.get("injection_point", {}) if isinstance(payload.get("injection_point", {}), dict) else {}
            key = (
                str(ip.get("url", "")),
                str(ip.get("param_name", "")),
                str(payload.get("owasp_category", "A03:2023")),
            )
            if key[0] and key[1]:
                existing_keys.add(key)

        seeded = 0
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            vulnerability_name = str(vulnerability.get("vulnerability_name", "Potential vulnerability")).strip() or "Potential vulnerability"
            risk_level = str(vulnerability.get("risk_level", "Low"))
            risk_key = risk_level.strip().lower()
            impact = impact_by_risk.get(risk_key, 3)
            confidence = confidence_by_risk.get(risk_key, 25)

            owasp_raw = str(vulnerability.get("owasp_category", "A03:2023")).strip().upper()
            owasp_category = owasp_raw if owasp_raw.startswith("A") and ":" in owasp_raw else "A03:2023"

            vectors = vulnerability.get("attack_vectors", [])
            attack_vectors = vectors if isinstance(vectors, list) and vectors else ["default attack vector"]

            for attack_vector in attack_vectors:
                vector_text = str(attack_vector)
                vector_lower = vector_text.lower()

                matched_ip: dict[str, Any] | None = None
                for ip in injection_points:
                    if not isinstance(ip, dict):
                        continue
                    url = str(ip.get("url", "")).lower()
                    param = str(ip.get("param_name", "")).lower()
                    if (url and (url in vector_lower or vector_lower in url)) or (
                        param and (param in vector_lower or vector_lower in param)
                    ):
                        matched_ip = ip
                        break

                if matched_ip is None:
                    first_ip = injection_points[0]
                    matched_ip = first_ip if isinstance(first_ip, dict) else {}

                dedup_key = (
                    str(matched_ip.get("url", "")),
                    str(matched_ip.get("param_name", "")),
                    owasp_category,
                )
                if dedup_key in existing_keys or not dedup_key[0] or not dedup_key[1]:
                    continue

                entry_probe = self._select_entry_probe(owasp_category, matched_ip, vulnerability_name)

                hypothesis = {
                    "hypothesis": f"{vulnerability_name} via {vector_text}",
                    "owasp_category": owasp_category,
                    "owasp_impact": impact,
                    "evidence_for": [f"VulnerabilityAnalysisAgent identified {vulnerability_name}"],
                    "evidence_against": [],
                    "entry_probe": entry_probe,
                    "expected_if_vulnerable": "Anomalous response pattern",
                    "expected_if_not_vulnerable": "Normal response",
                    "confidence": confidence,
                    "injection_point": matched_ip,
                    "source": "vuln_analysis",
                    "seeded_by": "vuln_analysis_agent",
                }

                node = Node(
                    id=str(uuid.uuid4()),
                    type=NodeType.HYPOTHESIS,
                    content=f"[VulnAnalysis] {hypothesis['hypothesis']}",
                    data=hypothesis,
                    confidence=max(0.01, min(1.0, confidence / 100.0)),
                    token_estimate=max(1, len(json.dumps(hypothesis)) // 4),
                )
                ctx.graph.add_node(node)
                existing_keys.add(dedup_key)
                seeded += 1

        return seeded

    @staticmethod
    def _select_entry_probe(owasp_category: str, injection_point: dict[str, Any], vulnerability_name: str) -> str:
        param_name = str(injection_point.get("param_name", "")).lower()
        param_type = str(injection_point.get("param_type", "query")).lower()
        cat = owasp_category.upper()
        vuln_lower = vulnerability_name.lower()

        if cat.startswith("A03"):
            if "email" in param_name or "mail" in param_name:
                return "test@test.com'"
            if "id" in param_name or "num" in param_name or "page" in param_name:
                return "1 AND 1=2"
            if "template" in vuln_lower or "ssti" in vuln_lower:
                return "{{7*7}}"
            if "xml" in vuln_lower or "xxe" in vuln_lower:
                return "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>"
            if "command" in vuln_lower or "rce" in vuln_lower:
                return ";id"
            if param_type == "json":
                return '{"$gt": ""}'
            return "'"

        if cat.startswith("A07"):
            if "token" in param_name or "jwt" in param_name:
                return "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
            if param_type == "json":
                return '{"username": "admin", "password": {"$ne": ""}}'
            return "' OR '1'='1"

        if cat.startswith("A10"):
            return "http://169.254.169.254/latest/meta-data/"

        if cat.startswith("A01"):
            if "file" in param_name or "path" in param_name or "dir" in param_name:
                return "../../../../etc/passwd"
            return "../../../etc/passwd"

        if cat.startswith("A02") or cat.startswith("A05"):
            return "true"

        return "probe_test_" + param_name[:8] if param_name else "probe_test"
    
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

        seeded_from_vuln = 0
        if settings.ENABLE_VULN_ANALYSIS_SEEDING and ctx.phase_results.get("vulnerability_analysis") is not None:
            seeded_from_vuln = self._seed_hypotheses_from_vuln_analysis(ctx, ctx.phase_results.get("vulnerability_analysis", {}))

        result = {
            "hypotheses_generated": len(nodes) + seeded_from_vuln,
            "seeded_from_vuln_analysis": seeded_from_vuln,
        }
        ctx.phase_results["hypothesis_seeding"] = result
        return result
    
    async def _run_payload_generation(self, ctx: ScanContext) -> dict[str, Any]:
        if not settings.ENABLE_PAYLOAD_GENERATION:
            return {"payload_arsenal": [], "source": "disabled", "skipped": True}

        from guardian.agents.payload_agent import PayloadGenerationAgent

        vuln_data = ctx.phase_results.get("vulnerability_analysis", {})
        recon_output = ctx.phase_results.get("reconnaissance", {})
        target_url = recon_output.get("url", "unknown_target")
        task_data = {
            "session_id": ctx.session_id,
            "vulnerability_data": vuln_data,
            "reconnaissance_data": {
                "targets_analyzed": 1,
                "reconnaissance_data": {
                    target_url: recon_output,
                },
            },
        }
        result = await PayloadGenerationAgent(self.db).execute(task_data)
        ctx.phase_results["payload_generation"] = result
        return result

    async def _run_active_penetration(self, ctx: ScanContext) -> dict[str, Any]:
        if not settings.ENABLE_ACTIVE_PENETRATION:
            return {"penetration_results": {}, "evidence_package": {}, "successful_exploits": [], "skipped": True}

        from guardian.agents.penetration_agent import PenetrationAgent

        payload_data = ctx.phase_results.get("payload_generation", {})
        payload_arsenal = payload_data.get("payload_arsenal", []) if isinstance(payload_data, dict) else []
        if not payload_arsenal:
            return {
                "penetration_results": {},
                "evidence_package": {},
                "successful_exploits": [],
                "skipped": True,
                "reason": "empty_payload_arsenal",
            }

        recon_output = ctx.phase_results.get("reconnaissance", {})
        target_url = recon_output.get("url", "unknown_target")
        task_data = {
            "session_id": ctx.session_id,
            "payloads": payload_data,
            "targets": {
                "reconnaissance_data": {
                    target_url: {
                        "web_applications": {
                            "endpoints": recon_output.get("api_endpoints", []),
                            "forms": recon_output.get("forms", []),
                        }
                    }
                }
            },
        }
        result = await PenetrationAgent(self.db).execute(task_data)
        successful_exploits: list[dict[str, Any]] = []
        if isinstance(result.get("penetration_results"), dict):
            for _target, target_result in result["penetration_results"].items():
                if isinstance(target_result, dict):
                    successful_exploits.extend(target_result.get("successful_exploits", []))
        result["successful_exploits"] = successful_exploits
        ctx.phase_results["active_penetration"] = result
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
                event_queue=ctx.event_queue,
            )
        finally:
            await probe_executor.close()

        finding_count = len(ctx.graph.get_findings())
        result = {"finding_count": finding_count, "graph_stats": ctx.graph.stats()}
        ctx.phase_results["graph_exploration"] = result
        return result

    async def _run_deterministic_checks(self, ctx: ScanContext) -> list[dict]:
        recon = ctx.phase_results.get("reconnaissance", {})
        findings = []

        interesting_paths = recon.get("interesting_paths", [])
        signals = recon.get("attack_surface_signals", [])

        if any("/.git/HEAD" in p for p in interesting_paths):
            findings.append({
                "vulnerability_name": "Git Repository Exposure",
                "owasp_category": "A05:2023",
                "risk_level": "High",
                "cwe": "CWE-538",
                "deterministic": True,
                "evidence": "/.git/HEAD returned HTTP 200 — source code may be accessible",
                "remediation": "Block public access to .git directory via web server configuration",
            })

        if any("/.env" in p for p in interesting_paths):
            findings.append({
                "vulnerability_name": "Environment File Exposure",
                "owasp_category": "A05:2023",
                "risk_level": "Critical",
                "cwe": "CWE-540",
                "deterministic": True,
                "evidence": "/.env returned HTTP 200 — credentials and configuration may be exposed",
                "remediation": "Block public access to .env files. Move secrets to a secrets manager.",
            })

        if any("/actuator" in p for p in interesting_paths):
            findings.append({
                "vulnerability_name": "Spring Boot Actuator Exposure",
                "owasp_category": "A05:2023",
                "risk_level": "High",
                "cwe": "CWE-200",
                "deterministic": True,
                "evidence": "/actuator endpoint returned HTTP 200 — internal application state exposed",
                "remediation": "Disable or restrict actuator endpoints. Apply Spring Security to actuator routes.",
            })

        target_url = recon.get("url", "")
        if target_url.startswith("https://"):
            if any("Missing HSTS" in s for s in signals):
                findings.append({
                    "vulnerability_name": "Missing HTTP Strict Transport Security",
                    "owasp_category": "A02:2023",
                    "risk_level": "Medium",
                    "cwe": "CWE-319",
                    "deterministic": True,
                    "evidence": "HTTPS endpoint does not return Strict-Transport-Security header",
                    "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                })

        if any("Allow-Credentials:true" in s for s in signals):
            findings.append({
                "vulnerability_name": "CORS Misconfiguration with Credentials",
                "owasp_category": "A05:2023",
                "risk_level": "Critical",
                "cwe": "CWE-942",
                "deterministic": True,
                "evidence": "Server reflects arbitrary Origin with Access-Control-Allow-Credentials: true",
                "remediation": "Never combine wildcard or reflected origins with Allow-Credentials: true. Maintain an explicit origin allowlist.",
            })

        return findings

    async def _run_reporting(self, ctx: ScanContext) -> dict[str, Any]:
        from guardian.agents.reporting_agent import ReportingAgent
        from guardian.core.ai_client import ai_client

        agent = ReportingAgent(self.db, ai_client)
        report = await agent.generate(
            ctx.graph,
            ctx.phase_results,
            ctx.session_id,
            ctx.ledger,
            deterministic_findings=ctx.phase_results.get("deterministic_findings", []),
        )
        ctx.phase_results["reporting"] = report
        await self.db.save_agent_result(ctx.session_id, "reporting", report)
        return report
    
    async def _run_active_confirmation(self, ctx: ScanContext) -> dict[str, Any]:
        if not settings.ENABLE_ACTIVE_CONFIRMATION:
            logger.info("Option C disabled; skipping active confirmation phase")
            return {"skipped": True, "active_confirmation_results": []}

        findings = ctx.graph.get_findings()
        if not findings:
            return {
                "skipped": False,
                "active_confirmation_results": [],
                "reason": "no_findings_to_confirm",
            }

        from guardian.agents.penetration_agent import PenetrationAgent
        from guardian.core.probing.probe_executor import ProbeExecutor
        from guardian.core.probing.session_manager import SessionManager

        recon_data = ctx.phase_results.get("reconnaissance", {})
        ssl_context = False if not settings.VERIFY_SSL else ssl.create_default_context()
        auth = ctx.config.get("auth", {})
        auth_headers = None
        if auth.get("type") == "bearer":
            auth_headers = {"Authorization": f"Bearer {auth.get('bearer_token', '')}"}
        cookies = auth.get("cookies") if isinstance(auth.get("cookies"), dict) else None

        probe_executor = None
        if hasattr(ProbeExecutor, "create"):
            probe_executor = await ProbeExecutor.create(auth_headers=auth_headers, cookies=cookies)
        else:
            import aiohttp

            headers = {"User-Agent": random.choice(settings.USER_AGENTS)}
            if auth_headers:
                headers.update(auth_headers)
            session = aiohttp.ClientSession(headers=headers)
            if cookies:
                session.cookie_jar.update_cookies(cookies)

            class _SessionWrapper:
                def __init__(self, sess):
                    self._session = sess
                async def close(self):
                    close_fn = getattr(self._session, "close", None)
                    if close_fn is None:
                        return
                    out = close_fn()
                    if asyncio.iscoroutine(out):
                        await out

            probe_executor = _SessionWrapper(session)

        auth_ok = await SessionManager().authenticate(auth, getattr(probe_executor, "_session", None)) if getattr(probe_executor, "_session", None) is not None else True
        if not auth_ok:
            logger.warning("Authentication failed for active confirmation session_id=%s", ctx.session_id)

        agent = PenetrationAgent(self.db)
        results: list[dict[str, Any]] = []

        try:
            session = getattr(probe_executor, "_session", None)
            if session is None:
                raise RuntimeError("probe_executor_session_unavailable")
            for finding in findings:
                result = await agent.confirm_finding(finding, recon_data, session)
                results.append(result)

                finding.data["http_confirmation"] = result
                if result.get("http_confirmed"):
                    ctx.graph.update_node_confidence(
                        finding.id,
                        min(1.0, finding.confidence + 0.1),
                    )

                await asyncio.sleep(random.uniform(settings.PROBE_DELAY_MIN, settings.PROBE_DELAY_MAX))
        finally:
            await probe_executor.close()

        if ctx.typed_phase_results.graph_exploration:
            ctx.typed_phase_results.graph_exploration.active_confirmation_results = results

        if isinstance(ctx.phase_results.get("graph_exploration"), dict):
            ctx.phase_results["graph_exploration"]["active_confirmation_results"] = results
        if isinstance(ctx.results.get("graph_exploration"), dict):
            ctx.results["graph_exploration"]["active_confirmation_results"] = results

        confirmed_count = sum(1 for r in results if r.get("http_confirmed"))
        logger.info(
            "Active confirmation: %d/%d findings HTTP-confirmed",
            confirmed_count,
            len(findings),
        )

        return {
            "skipped": False,
            "active_confirmation_results": results,
            "confirmed_count": confirmed_count,
            "total_findings": len(findings),
        }


    def _record_typed_phase_result(self, ctx: ScanContext, phase_name: str, result: dict[str, Any]) -> None:
        if phase_name == "reconnaissance":
            data = {
                "url": result.get("url", ""),
                "domain": result.get("domain", ""),
                "technologies": result.get("technologies", []),
                "waf_detected": result.get("waf_detected"),
                "backend_language": result.get("backend_language"),
                "database_hint": result.get("database_hint"),
                "framework": result.get("framework"),
                "injection_points": result.get("injection_points", []),
                "forms": result.get("forms", []),
                "api_endpoints": result.get("api_endpoints", []),
                "html_comments": result.get("html_comments", []),
                "hardcoded_values": result.get("hardcoded_values", []),
                "interesting_paths": result.get("interesting_paths", []),
                "open_ports": result.get("open_ports", []),
                "attack_surface_signals": result.get("attack_surface_signals", []),
                "page_classifications": result.get("page_classifications", {}),
            }
            ctx.typed_phase_results.reconnaissance = ReconPhaseOutput.model_validate(data)
        elif phase_name == "vulnerability_analysis":
            data = {
                "overall_risk_level": result.get("overall_risk_level", "Unknown"),
                "vulnerabilities": result.get("vulnerabilities", []),
                "error": result.get("error"),
                "skipped": bool(result.get("skipped", False)),
                **result,
            }
            ctx.typed_phase_results.vulnerability_analysis = VulnAnalysisPhaseOutput.model_validate(data)
        elif phase_name == "hypothesis_seeding":
            data = {
                "hypotheses_generated": int(result.get("hypotheses_generated", 0)),
                "seeded_from_vuln_analysis": int(result.get("seeded_from_vuln_analysis", 0)),
                **result,
            }
            ctx.typed_phase_results.hypothesis_seeding = HypothesisPhaseOutput.model_validate(data)
        elif phase_name == "payload_generation":
            data = {
                "payload_arsenal": result.get("payload_arsenal", []),
                "source": result.get("source", ""),
                "skipped": bool(result.get("skipped", False)),
                **result,
            }
            ctx.typed_phase_results.payload_generation = PayloadPhaseOutput.model_validate(data)
        elif phase_name == "active_penetration":
            data = {
                "penetration_results": result.get("penetration_results", {}),
                "evidence_package": result.get("evidence_package", {}),
                "successful_exploits": result.get("successful_exploits", []),
                "skipped": bool(result.get("skipped", False)),
                **result,
            }
            ctx.typed_phase_results.active_penetration = PenetrationPhaseOutput.model_validate(data)
        elif phase_name == "graph_exploration":
            data = {
                "finding_count": int(result.get("finding_count", result.get("findings", 0))),
                "graph_stats": result.get("graph_stats", {}),
                "active_confirmation_results": result.get("active_confirmation_results", []),
                **result,
            }
            ctx.typed_phase_results.graph_exploration = GraphExplorationPhaseOutput.model_validate(data)
        elif phase_name == "reporting":
            data = {
                "executive_summary": result.get("executive_summary", {}),
                "technical_findings": result.get("technical_findings", []),
                "graph_summary": result.get("graph_summary", {}),
                "scan_metadata": result.get("scan_metadata", {}),
                "generated_at": result.get("generated_at", ""),
                **result,
            }
            ctx.typed_phase_results.reporting = ReportPhaseOutput.model_validate(data)

    def _publish(self, ctx: ScanContext, event: dict) -> None:
        try:
            ctx.event_queue.put_nowait({**event, "timestamp": datetime.now(timezone.utc).isoformat()})
        except asyncio.QueueFull:
            pass

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
        total_weight = sum(self.PHASE_WEIGHTS.get(p, 0.0) for p in phases) or 100.0

        def _is_phase_done(phase_name: str) -> bool:
            if phase_name in ctx.results:
                return True
            phase_result = ctx.phase_results.get(phase_name)
            return isinstance(phase_result, dict) and bool(phase_result.get("skipped", False))

        completed_weight = sum(self.PHASE_WEIGHTS.get(p, 0.0) for p in phases if _is_phase_done(p))
        pct = (completed_weight / total_weight) * 100.0
        if ctx.status == ScanStatus.COMPLETED:
            pct = 100.0
        return {
            "overall": round(pct, 1),
            "phases": {
                p: (100.0 if _is_phase_done(p) else 0.0)
                for p in phases
            },
            "deterministic_findings_count": len(ctx.phase_results.get("deterministic_findings", []))
            if isinstance(ctx.phase_results.get("deterministic_findings", []), list)
            else 0,
        }

    def _results_preview(self, ctx: ScanContext) -> dict[str, Any]:
        recon = ctx.results.get("reconnaissance", {})
        vuln = ctx.results.get("vulnerability_analysis", {})
        seed = ctx.results.get("hypothesis_seeding", {})
        payload = ctx.results.get("payload_generation", {})
        active_pentest = ctx.results.get("active_penetration", {})
        explore = ctx.results.get("graph_exploration", {})
        active_confirm = ctx.results.get("active_confirmation", {})
        report = ctx.results.get("reporting", {})
        deterministic = ctx.results.get("deterministic_findings", [])
        return {
            "reconnaissance": {
                "completed": "reconnaissance" in ctx.results,
                "domain": recon.get("domain"),
                "injection_points": len(recon.get("injection_points", [])),
            },
            "deterministic_findings": {
                "completed": "deterministic_findings" in ctx.results,
                "deterministic_findings_count": len(deterministic) if isinstance(deterministic, list) else 0,
            },
            "vulnerability_analysis": {
                "completed": "vulnerability_analysis" in ctx.results,
                "skipped": vuln.get("skipped", False),
                "vulnerability_count": len(vuln.get("vulnerabilities", [])) if isinstance(vuln.get("vulnerabilities", []), list) else 0,
                "overall_risk": vuln.get("overall_risk_level", "N/A"),
            },
            "hypothesis_seeding": {
                "completed": "hypothesis_seeding" in ctx.results,
                "hypotheses_generated": seed.get("hypotheses_generated", 0),
            },
            "payload_generation": {
                "completed": "payload_generation" in ctx.results,
                "skipped": payload.get("skipped", False),
                "payload_count": len(payload.get("payload_arsenal", [])) if isinstance(payload.get("payload_arsenal", []), list) else 0,
            },
            "active_penetration": {
                "completed": "active_penetration" in ctx.results,
                "skipped": active_pentest.get("skipped", False),
                "successful_exploits": len(active_pentest.get("successful_exploits", [])) if isinstance(active_pentest.get("successful_exploits", []), list) else 0,
            },
            "graph_exploration": {
                "completed": "graph_exploration" in ctx.results,
                "finding_count": explore.get("finding_count", 0),
            },
            "active_confirmation": {
                "completed": "active_confirmation" in ctx.results,
                "skipped": active_confirm.get("skipped", False),
                "confirmed_count": active_confirm.get("confirmed_count", 0),
                "total_findings": active_confirm.get("total_findings", 0),
            },
            "reporting": {
                "completed": "reporting" in ctx.results,
                "report_available": bool(report),
            },
        }

    async def _ensure_cleanup_running(self) -> None:
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop(), name="guardian-session-cleanup")

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
