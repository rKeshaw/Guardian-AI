"""
guardian/core/database.py
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

from guardian.core.config import settings
from guardian.models.scan_session import ScanSession, ScanStatus

logger = logging.getLogger(__name__)


class Database:
    def __init__(self) -> None:
        db_path = settings.get_db_path()
        # Ensure the parent directory exists (absolute path guaranteed by config)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        logger.info("Database path: %s", db_path)

    # ── Schema initialisation ─────────────────

    async def initialize(self) -> None:
        """Create all tables if they do not exist."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    session_id      TEXT PRIMARY KEY,
                    target_urls     TEXT NOT NULL DEFAULT '[]',
                    config          TEXT NOT NULL DEFAULT '{}',
                    status          TEXT NOT NULL DEFAULT 'initializing',
                    started_at      TEXT,
                    completed_at    TEXT,
                    error_message   TEXT,
                    results_summary TEXT
                );

                CREATE TABLE IF NOT EXISTS agent_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    agent_name  TEXT NOT NULL,
                    results     TEXT NOT NULL DEFAULT '{}',
                    created_at  TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(session_id)
                );

                CREATE TABLE IF NOT EXISTS agent_tasks (
                    task_id       TEXT PRIMARY KEY,
                    session_id    TEXT NOT NULL,
                    agent_name    TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    input_summary TEXT,
                    created_at    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_errors (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    agent_name  TEXT NOT NULL,
                    error       TEXT NOT NULL,
                    created_at  TEXT NOT NULL
                );
                                   
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    graph_id            TEXT NOT NULL,
                    node_id             TEXT NOT NULL,
                    node_type           TEXT NOT NULL,
                    content             TEXT,
                    data                TEXT NOT NULL DEFAULT '{}',
                    depth               INTEGER DEFAULT 0,
                    confidence          REAL DEFAULT 0.5,
                    token_estimate      INTEGER DEFAULT 0,
                    compressed_summary  TEXT,
                    compressed_tokens   INTEGER,
                    updated_at          TEXT NOT NULL,
                    PRIMARY KEY (graph_id, node_id)
                );

                CREATE TABLE IF NOT EXISTS graph_edges (
                    graph_id    TEXT NOT NULL,
                    source_id   TEXT NOT NULL,
                    target_id   TEXT NOT NULL,
                    edge_type   TEXT NOT NULL,
                    PRIMARY KEY (graph_id, source_id, target_id, edge_type)
                );

                CREATE TABLE IF NOT EXISTS graph_meta (
                    graph_id        TEXT NOT NULL PRIMARY KEY,
                    session_id      TEXT,
                    stats           TEXT NOT NULL DEFAULT '{}',
                    frontier_size   INTEGER DEFAULT 0,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_agent_results_session
                    ON agent_results(session_id);
                CREATE INDEX IF NOT EXISTS idx_agent_tasks_session
                    ON agent_tasks(session_id);
            """)
            await db.commit()
        logger.info("Database schema initialised")

    # ── Session persistence ───────────────────

    async def save_session(self, session: ScanSession) -> None:
        """
        Persist a ScanSession to the database.

        FIX 16: Because use_enum_values=True is set in ScanSession.model_config,
        session.status is already a plain string — no isinstance(Enum) check needed.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO scan_sessions
                    (session_id, target_urls, config, status,
                     started_at, completed_at, error_message, results_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    status          = excluded.status,
                    completed_at    = excluded.completed_at,
                    error_message   = excluded.error_message,
                    results_summary = excluded.results_summary
            """, (
                session.session_id,
                json.dumps(session.target_urls),
                json.dumps(session.config),
                session.status,          # already a string — no unwrapping needed
                session.started_at.isoformat() if session.started_at else None,
                session.completed_at.isoformat() if session.completed_at else None,
                session.error_message,
                json.dumps(session.results_summary) if session.results_summary else None,
            ))
            await db.commit()

    async def get_session(self, session_id: str) -> ScanSession | None:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM scan_sessions WHERE session_id = ?", (session_id,)
            ) as cursor:
                row = await cursor.fetchone()

        if row is None:
            return None
        return ScanSession.from_db_row(dict(row))

    async def list_sessions(
        self,
        limit: int = 50,
        status_filter: ScanStatus | None = None,
    ) -> list[ScanSession]:
        query = "SELECT * FROM scan_sessions"
        params: list[Any] = []

        if status_filter is not None:
            # status_filter may be ScanStatus enum or plain string
            status_val = (
                status_filter.value
                if isinstance(status_filter, ScanStatus)
                else str(status_filter)
            )
            query += " WHERE status = ?"
            params.append(status_val)

        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()

        return [ScanSession.from_db_row(dict(row)) for row in rows]

    # ── Agent results ─────────────────────────

    async def save_agent_results(
        self, session_id: str, agent_name: str, results: dict[str, Any]
    ) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO agent_results (session_id, agent_name, results, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                session_id,
                agent_name,
                json.dumps(results, default=str),
                datetime.utcnow().isoformat(),
            ))
            await db.commit()

    async def get_results(
        self, session_id: str, agent_name: str | None = None
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM agent_results WHERE session_id = ?"
        params: list[Any] = [session_id]
        if agent_name:
            query += " AND agent_name = ?"
            params.append(agent_name)
        query += " ORDER BY created_at ASC"

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()

        out = []
        for row in rows:
            r = dict(row)
            try:
                r["results"] = json.loads(r["results"])
            except (ValueError, TypeError):
                pass
            out.append(r)
        return out

    # ── Agent task lifecycle ──────────────────

    async def save_agent_task(self, task: dict[str, Any]) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR IGNORE INTO agent_tasks
                    (task_id, session_id, agent_name, status, input_summary, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                task["task_id"],
                task["session_id"],
                task["agent_name"],
                task["status"],
                json.dumps(task.get("input_summary", {})),
                datetime.utcnow().isoformat(),
            ))
            await db.commit()

    async def save_agent_error(
        self, session_id: str, agent_name: str, error: str
    ) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO agent_errors (session_id, agent_name, error, created_at)
                VALUES (?, ?, ?, ?)
            """, (session_id, agent_name, error, datetime.utcnow().isoformat()))
            await db.commit()

    async def save_agent_result(self, session_id: str, agent_name: str, results: dict[str, Any]) -> None:
        await self.save_agent_results(session_id, agent_name, results)

    async def upsert_node(self, graph_id: str, node: dict[str, Any]) -> None:
        # Schema guaranteed by Database.initialize() called at startup.
        now = datetime.utcnow().isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO graph_nodes
                    (graph_id, node_id, node_type, content, data, depth, confidence,
                     token_estimate, compressed_summary, compressed_tokens, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    graph_id,
                    str(node.get("id", "")),
                    str(node.get("type", "")),
                    str(node.get("content", "")),
                    json.dumps(node.get("data", {}), default=str),
                    int(node.get("depth", 0)),
                    float(node.get("confidence", 0.5)),
                    int(node.get("token_estimate", 0)),
                    json.dumps(node.get("compressed_summary"), default=str) if node.get("compressed_summary") is not None else None,
                    int(node.get("compressed_tokens")) if node.get("compressed_tokens") is not None else None,
                    now,
                ),
            )
            await db.commit()

    async def upsert_graph_meta(self, graph_id: str, meta: dict[str, Any]) -> None:
        # Schema guaranteed by Database.initialize() called at startup.
        now = datetime.utcnow().isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO graph_meta
                    (graph_id, session_id, stats, frontier_size, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    graph_id,
                    str(meta.get("session_id", "")) if meta.get("session_id") is not None else None,
                    json.dumps(meta.get("stats", {}), default=str),
                    int(meta.get("frontier_size", 0)),
                    now,
                ),
            )
            await db.commit()

    async def upsert_edge(self, graph_id: str, edge: dict[str, Any]) -> None:
        # Schema guaranteed by Database.initialize() called at startup.
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR IGNORE INTO graph_edges
                    (graph_id, source_id, target_id, edge_type)
                VALUES (?, ?, ?, ?)
                """,
                (
                    graph_id,
                    str(edge.get("source_id", "")),
                    str(edge.get("target_id", "")),
                    str(edge.get("type", "")),
                ),
            )
            await db.commit()
    # ── Health / statistics ───────────────────

    async def get_statistics(self) -> dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM scan_sessions") as cur:
                total = (await cur.fetchone())[0]
            async with db.execute(
                "SELECT COUNT(*) FROM scan_sessions WHERE status = 'completed'"
            ) as cur:
                completed = (await cur.fetchone())[0]
            async with db.execute(
                "SELECT COUNT(*) FROM scan_sessions WHERE status = 'error'"
            ) as cur:
                errors = (await cur.fetchone())[0]

        return {
            "total_sessions": total,
            "completed_sessions": completed,
            "error_sessions": errors,
            "active_sessions": total - completed - errors,
        }
