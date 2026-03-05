"""
guardian/api/main.py
"""

import asyncio
import logging
import os
import traceback
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)
logger.info("Guardian AI starting up …")

app = FastAPI(
    title="Guardian AI — Multi-Agent Penetration Testing System",
    description="Advanced AI-powered penetration testing with 5 specialised agents covering OWASP Top 10 (2023)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Globals ────────────────────────────────────
database = None
orchestrator = None
startup_error: str | None = None
env_warnings: list[str] = []


# ── Pydantic models ────────────────────────────
class ScanRequest(BaseModel):
    target_urls: List[str]
    config: Optional[Dict[str, Any]] = {}


class ScanResponse(BaseModel):
    session_id: str
    status: str
    message: str


class ScanStatus(BaseModel):
    session_id: str
    status: str
    progress: float
    started_at: Optional[str]
    completed_at: Optional[str]
    error_message: Optional[str] = None
    results: Optional[Dict[str, Any]] = None


# ── Startup ────────────────────────────────────
async def _wait_for_ollama(max_attempts: int = 5) -> bool:
    """Retry Ollama health check with exponential backoff."""
    from guardian.core.ai_client import ai_client
    delay = 5.0
    for attempt in range(1, max_attempts + 1):
        try:
            ok = await ai_client.health_check()
            if ok:
                logger.info("Ollama is reachable (attempt %d)", attempt)
                return True
        except Exception as exc:
            logger.warning("Ollama not ready (attempt %d/%d): %s", attempt, max_attempts, exc)
        if attempt < max_attempts:
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)
    return False


async def initialize_guardian_components() -> bool:
    global database, orchestrator, startup_error, env_warnings

    try:
        from guardian.core.config import settings
        env_warnings = settings.validate_environment()
        for w in env_warnings:
            logger.warning("Config warning: %s", w)

        from guardian.core.database import Database
        database = Database()

        from guardian.core.orchestrator import CentralOrchestrator
        orchestrator = CentralOrchestrator(database)

        ollama_ok = await _wait_for_ollama()
        if not ollama_ok:
            logger.error("Ollama unreachable after retries — LLM phases will fail")
            env_warnings.append("Ollama LLM service is not reachable. AI-powered phases will fail.")

        logger.info("Guardian AI components initialised successfully")
        return True

    except Exception as exc:
        startup_error = str(exc)
        logger.error("Startup failed: %s\n%s", exc, traceback.format_exc())
        return False


# ── Routes ─────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    port = os.environ.get("GUARDIAN_PORT", "8888")
    return f"""<!DOCTYPE html>
<html>
<head><title>Guardian AI</title>
<style>
  body{{font-family:Arial,sans-serif;background:#0f0f1a;color:#e0e0e0;padding:20px}}
  h1{{color:#4fc3f7}} a{{color:#4fc3f7}}
  .card{{background:#1e1e30;border-radius:8px;padding:20px;margin:12px 0;border:1px solid #333}}
</style>
</head>
<body>
<h1>&#128737; Guardian AI</h1>
<div class="card"><b>Status:</b> Running on port {port}<br>
<a href="/docs">API Docs</a> &nbsp;|&nbsp; <a href="/api/v1/health">Health</a></div>
</body></html>"""


@app.post("/api/v1/scan/start", response_model=ScanResponse, status_code=202)
async def start_scan(scan_request: ScanRequest):
    if not orchestrator:
        raise HTTPException(503, detail=f"Orchestrator unavailable. {startup_error or ''}")
    if not scan_request.target_urls:
        raise HTTPException(400, detail="target_urls must not be empty.")

    try:
        session_id = await orchestrator.start_scan(
            scan_request.target_urls,
            scan_request.config or {},
        )
    except RuntimeError as exc:
        # Concurrent session limit exceeded
        raise HTTPException(429, detail=str(exc))

    return ScanResponse(
        session_id=session_id,
        status="started",
        message=f"Assessment initiated. session_id={session_id}",
    )


@app.get("/api/v1/scan/{session_id}/status")
async def get_scan_status(session_id: str):
    if not orchestrator:
        raise HTTPException(503, detail="Orchestrator unavailable.")

    try:
        status_data = await orchestrator.get_session_status(session_id)
    except KeyError:
        # Session evicted from memory after TTL — fall back to database
        if not database:
            raise HTTPException(404, detail="Session not found.")
        session = await database.get_session(session_id)
        if not session:
            raise HTTPException(404, detail=f"Session '{session_id}' not found.")
        status_data = {
            "session_id": session_id,
            "status": session.status.value if hasattr(session.status, "value") else str(session.status),
            "progress": {"overall": 100.0 if session.status in ("completed", "error") else 0.0},
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "error_message": session.error_message,
            "results_preview": {},
        }

    return JSONResponse(content={
        "session_id": status_data["session_id"],
        "status": status_data["status"],
        "progress": status_data.get("progress", {}).get("overall", 0),
        "started_at": status_data.get("started_at"),
        "completed_at": status_data.get("completed_at"),
        "error_message": status_data.get("error_message"),
        "results": status_data.get("results_preview", {}),
    })


@app.get("/api/v1/scan/{session_id}/results")
async def get_scan_results(session_id: str):
    if not database:
        raise HTTPException(503, detail="Database unavailable.")
    results = await database.get_results(session_id)
    if not results:
        raise HTTPException(404, detail="Results not found. Scan may still be in progress.")
    return JSONResponse(content={"session_id": session_id, "results": results})


@app.delete("/api/v1/scan/{session_id}")
async def stop_scan(session_id: str):
    if not orchestrator:
        raise HTTPException(503, detail="Orchestrator unavailable.")
    try:
        await orchestrator.stop_scan(session_id)
    except KeyError:
        raise HTTPException(404, detail=f"Session '{session_id}' not found.")
    return {"message": f"Scan {session_id} stopped."}


@app.get("/api/v1/health")
async def health_check():
    port = os.environ.get("GUARDIAN_PORT", "8888")
    health = orchestrator.get_workflow_health() if orchestrator else {}
    return {
        "status": "operational" if orchestrator and database else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "port": port,
        "components": {
            "database": "available" if database else "unavailable",
            "orchestrator": "available" if orchestrator else "unavailable",
            "active_sessions": health.get("active_sessions", 0),
            "available_slots": health.get("slots_available", 0),
        },
        "environment_warnings": env_warnings,
        "startup_error": startup_error,
    }


# ── Lifecycle ──────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("Guardian AI initialising …")
    await initialize_guardian_components()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("GUARDIAN_PORT", "8888")))
