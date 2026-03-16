from __future__ import annotations

import json

import aiosqlite
import pytest

from aegis.core.config import settings
from aegis.core.database import Database


@pytest.mark.anyio
async def test_upsert_node_replaces_existing_row(tmp_path, monkeypatch):
    db_file = tmp_path / "graph_nodes.db"
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite:///{db_file}")

    db = Database()
    await db.initialize()

    await db.upsert_node("g1", {"id": "n1", "type": "hypothesis", "content": "v1", "data": {"a": 1}, "depth": 0, "confidence": 0.1, "token_estimate": 10})
    await db.upsert_node("g1", {"id": "n1", "type": "hypothesis", "content": "v2", "data": {"a": 2}, "depth": 1, "confidence": 0.9, "token_estimate": 20})

    async with aiosqlite.connect(db.db_path) as conn:
        async with conn.execute("SELECT COUNT(*), content, data, depth FROM graph_nodes WHERE graph_id=? AND node_id=?", ("g1", "n1")) as cur:
            row = await cur.fetchone()

    assert row[0] == 1
    assert row[1] == "v2"
    assert json.loads(row[2])["a"] == 2
    assert row[3] == 1


@pytest.mark.anyio
async def test_upsert_edge_is_idempotent(tmp_path, monkeypatch):
    db_file = tmp_path / "graph_edges.db"
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite:///{db_file}")

    db = Database()
    await db.initialize()

    edge = {"source_id": "a", "target_id": "b", "type": "generated"}
    await db.upsert_edge("g1", edge)
    await db.upsert_edge("g1", edge)

    async with aiosqlite.connect(db.db_path) as conn:
        async with conn.execute("SELECT COUNT(*) FROM graph_edges WHERE graph_id=?", ("g1",)) as cur:
            count = (await cur.fetchone())[0]

    assert count == 1


@pytest.mark.anyio
async def test_upsert_graph_meta_replaces_existing_row(tmp_path, monkeypatch):
    db_file = tmp_path / "graph_meta.db"
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite:///{db_file}")

    db = Database()
    await db.initialize()

    await db.upsert_graph_meta("g1", {"session_id": "s1", "stats": {"node_count": 1}, "frontier_size": 1})
    await db.upsert_graph_meta("g1", {"session_id": "s1", "stats": {"node_count": 2}, "frontier_size": 0})

    async with aiosqlite.connect(db.db_path) as conn:
        async with conn.execute("SELECT COUNT(*), stats, frontier_size FROM graph_meta WHERE graph_id=?", ("g1",)) as cur:
            row = await cur.fetchone()

    assert row[0] == 1
    assert json.loads(row[1])["node_count"] == 2
    assert row[2] == 0


@pytest.mark.anyio
async def test_graph_nodes_row_count_matches_unique_nodes(tmp_path, monkeypatch):
    db_file = tmp_path / "graph_nodes_unique.db"
    monkeypatch.setattr(settings, "DATABASE_URL", f"sqlite:///{db_file}")

    db = Database()
    await db.initialize()

    for _ in range(5):
        await db.upsert_node("g1", {"id": "n1", "type": "hypothesis", "content": "v", "data": {}, "depth": 0, "confidence": 0.5, "token_estimate": 1})
    await db.upsert_node("g1", {"id": "n2", "type": "hypothesis", "content": "v", "data": {}, "depth": 0, "confidence": 0.5, "token_estimate": 1})

    async with aiosqlite.connect(db.db_path) as conn:
        async with conn.execute("SELECT COUNT(*) FROM graph_nodes WHERE graph_id=?", ("g1",)) as cur:
            count = (await cur.fetchone())[0]

    assert count == 2
