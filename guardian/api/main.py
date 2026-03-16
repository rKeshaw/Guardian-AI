"""
guardian/api/main.py
"""

import asyncio
import json
import logging
import os
import traceback
import socket
import ipaddress
from datetime import datetime, timezone

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, AnyHttpUrl, Field
from typing import Any, Dict, List, Optional

from guardian.api.graph_viz import build_graph_response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)
logger.info("Guardian AI starting up …")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info("Guardian AI initialising …")
    await initialize_guardian_components()
    yield

app = FastAPI(
    title="Guardian AI — Multi-Agent Penetration Testing System",
    description="Advanced AI-powered penetration testing with 5 specialised agents covering OWASP Top 10 (2023)",
    version="1.0.0",
    lifespan=lifespan,
)

static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

from guardian.core.config import settings

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Globals ────────────────────────────────────

def verify_api_key(x_api_key: str = Header(default="")) -> None:
    key = settings.API_KEY
    if settings.REQUIRE_API_KEY and not key:
        raise HTTPException(status_code=503, detail="API key auth is required but API_KEY is not configured")
    if key and x_api_key != key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _denied_networks() -> list[ipaddress._BaseNetwork]:
    cidrs = [c.strip() for c in str(settings.SCAN_TARGET_DENY_CIDRS or "").split(",") if c.strip()]
    out: list[ipaddress._BaseNetwork] = []
    for cidr in cidrs:
        try:
            out.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("Invalid SCAN_TARGET_DENY_CIDRS entry ignored: %s", cidr)
    return out


def validate_scan_target(url: str) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return

    denied = _denied_networks()
    try:
        infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return
    except Exception:
        return

    for info in infos:
        sockaddr = info[4]
        ip_raw = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else ""
        try:
            ip_obj = ipaddress.ip_address(ip_raw)
        except ValueError:
            continue

        if any(ip_obj in net for net in denied):
            raise HTTPException(status_code=400, detail="Target is in a denied network range")

        if settings.SCAN_TARGET_ALLOW_EXTERNAL_ONLY:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                raise HTTPException(status_code=400, detail="Target is in a denied network range")
            if getattr(ip_obj, "is_reserved", False) or getattr(ip_obj, "is_unspecified", False):
                raise HTTPException(status_code=400, detail="Target is in a denied network range")
            
database = None
orchestrator = None
startup_error: str | None = None
env_warnings: list[str] = []


# ── Pydantic models ────────────────────────────
class ScanRequest(BaseModel):
    target_urls: List[AnyHttpUrl] = Field(min_length=1)
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
        await database.initialize()

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
    index_path = os.path.join(os.path.dirname(__file__), "..", "static", "index.html")
    if os.path.exists(index_path):
        with open(index_path, encoding="utf-8") as f:
            return f.read()

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


@app.post("/api/v1/scan/start", response_model=ScanResponse, status_code=202, dependencies=[Depends(verify_api_key)])
async def start_scan(scan_request: ScanRequest):
    if not orchestrator:
        raise HTTPException(503, detail=f"Orchestrator unavailable. {startup_error or ''}")
    target_urls = [str(url) for url in scan_request.target_urls]
    for target in target_urls:
        validate_scan_target(target)

    try:
        session_id = await orchestrator.start_scan(
            target_urls,
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


@app.get("/api/v1/scan/{session_id}/status", dependencies=[Depends(verify_api_key)])
async def get_scan_status(session_id: str):
    from guardian.core.config import settings
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
        "progress_detail": status_data.get("progress", {}),
        "active_options": {
            "vuln_analysis_seeding": settings.ENABLE_VULN_ANALYSIS_SEEDING,
            "rag_probing": settings.ENABLE_RAG_PROBING,
            "active_confirmation": settings.ENABLE_ACTIVE_CONFIRMATION,
        },
        "started_at": status_data.get("started_at"),
        "completed_at": status_data.get("completed_at"),
        "error_message": status_data.get("error_message"),
        "results": status_data.get("results_preview", {}),
    })

@app.get("/api/v1/scan/{session_id}/graph", dependencies=[Depends(verify_api_key)])
async def get_scan_graph(session_id: str):
    if not orchestrator:
        raise HTTPException(503, detail="Orchestrator unavailable.")

    try:
        if hasattr(orchestrator, "get_session_graph"):
            graph = await orchestrator.get_session_graph(session_id)
        else:
            graph = orchestrator._get_context(session_id).graph
    except KeyError:
        raise HTTPException(404, detail=f"Session '{session_id}' not found.")

    return JSONResponse(content=build_graph_response(graph))

@app.get("/api/v1/scan/{session_id}/results", dependencies=[Depends(verify_api_key)])
async def get_scan_results(session_id: str):
    if not database:
        raise HTTPException(503, detail="Database unavailable.")
    results = await database.get_results(session_id)
    if not results:
        raise HTTPException(404, detail="Results not found. Scan may still be in progress.")
    return JSONResponse(content={"session_id": session_id, "results": results})


@app.get("/api/v1/scan/{session_id}/report/json", dependencies=[Depends(verify_api_key)])
async def export_report_json(session_id: str):
    if not database:
        raise HTTPException(503, detail="Database unavailable.")
    results = await database.get_results(session_id)
    if not results:
        raise HTTPException(404, detail="Results not found")
    return JSONResponse(content={"session_id": session_id, "results": results})


@app.get("/api/v1/scan/{session_id}/report/html", dependencies=[Depends(verify_api_key)])
async def export_report_html(session_id: str):
    if not database:
        raise HTTPException(503, detail="Database unavailable.")
    results = await database.get_results(session_id)
    if not results:
        raise HTTPException(404, detail="Results not found")
    from guardian.core.report_renderer import render_html_report

    html_content = render_html_report(session_id, results)
    return HTMLResponse(content=html_content)


@app.get("/api/v1/scan/{session_id}/report/markdown", dependencies=[Depends(verify_api_key)])
async def export_report_markdown(session_id: str):
    if not database:
        raise HTTPException(503, detail="Database unavailable.")
    results = await database.get_results(session_id)
    if not results:
        raise HTTPException(404, detail="Results not found")
    from guardian.core.report_renderer import render_markdown_report

    md_content = render_markdown_report(session_id, results)
    return PlainTextResponse(content=md_content, media_type="text/markdown")


@app.websocket("/ws/scan/{session_id}")
async def scan_websocket(websocket: WebSocket, session_id: str, api_key: str = ""):
    if settings.REQUIRE_API_KEY and settings.API_KEY and api_key != settings.API_KEY:
        await websocket.close(code=1008)
        return

    if not orchestrator:
        await websocket.close(code=1008)
        return

    ctx = orchestrator._registry.get(session_id)
    if not ctx:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    try:
        while True:
            try:
                event = await asyncio.wait_for(ctx.event_queue.get(), timeout=30.0)
                await websocket.send_json(event)
                if event.get("event") in ("scan_complete", "scan_error"):
                    break
            except asyncio.TimeoutError:
                await websocket.send_json(
                    {"event": "heartbeat", "timestamp": datetime.now(timezone.utc).isoformat()}
                )
    except WebSocketDisconnect:
        pass


@app.get("/api/v1/scan/{session_id}/stream")
async def scan_sse(session_id: str, request: Request):
    if not orchestrator:
        raise HTTPException(503, detail="Orchestrator unavailable.")

    ctx = orchestrator._registry.get(session_id)
    if not ctx:
        raise HTTPException(404, detail=f"Session '{session_id}' not found.")

    async def _event_stream():
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(ctx.event_queue.get(), timeout=30.0)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("event") in ("scan_complete", "scan_error"):
                    break
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"

    return StreamingResponse(_event_stream(), media_type="text/event-stream")


@app.delete("/api/v1/scan/{session_id}", dependencies=[Depends(verify_api_key)])
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "port": port,
        "components": {
            "database": "available" if database else "unavailable",
            "orchestrator": "available" if orchestrator else "unavailable",
            "active_sessions": health.get("active_sessions", 0),
            "available_slots": health.get("slots_available", 0),
        },
        "feature_flags": {
            "vuln_analysis_seeding": settings.ENABLE_VULN_ANALYSIS_SEEDING,
            "rag_probing": settings.ENABLE_RAG_PROBING,
            "active_confirmation": settings.ENABLE_ACTIVE_CONFIRMATION,
            "payload_generation": settings.ENABLE_PAYLOAD_GENERATION,
            "active_penetration": settings.ENABLE_ACTIVE_PENETRATION,
        },
        "execution_profile": settings.SCAN_EXECUTION_PROFILE,
        "ai_provider": settings.AI_PROVIDER,
        "environment_warnings": env_warnings,
        "startup_error": startup_error,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("GUARDIAN_PORT", "8888")))
