from aegis.core.intelligence.quality_monitor import QualityMonitor
from aegis.core.memory.conversation_memory import ConversationMemory
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


def _turn(probe: str, obs: str, conf: float, next_probe: str | None = None) -> dict:
    return {
        "probe": probe,
        "observation": {"content": obs},
        "llm_reasoning": {"confirmed_facts": [], "next_probe": next_probe or probe},
        "confidence_after": conf,
    }


def test_no_issues_fresh_memory():
    monitor = QualityMonitor()
    memory = ConversationMemory()

    q = monitor.assess(memory, 2)
    assert q["quality_ok"] is True
    assert q["issues"] == []


def test_confidence_flat_low_triggers_recovery():
    monitor = QualityMonitor()
    memory = ConversationMemory()
    for i in range(4):
        memory.add_turn(_turn(f"p{i}", f"obs{i}", 0.2))

    q = monitor.assess(memory, 4)
    assert q["quality_ok"] is False
    assert q["recovery_message"]


def test_repetitive_observations_detected():
    monitor = QualityMonitor()
    memory = ConversationMemory()
    for i in range(3):
        memory.add_turn(_turn(f"p{i}", "The response was the same as before", 0.5))

    q = monitor.assess(memory, 3)
    assert any("repetitive" in i.lower() for i in q["issues"])


def test_no_facts_after_six_turns():
    monitor = QualityMonitor()
    memory = ConversationMemory()
    for i in range(6):
        memory.add_turn(_turn(f"p{i}", f"obs{i}", 0.4))

    q = monitor.assess(memory, 6)
    assert any("No facts confirmed after 6 turns" == i for i in q["issues"])


def test_long_probe_flagged():
    monitor = QualityMonitor()
    memory = ConversationMemory()
    long_probe = "A" * 600
    memory.add_turn(_turn("p1", "obs", 0.5, next_probe=long_probe))

    q = monitor.assess(memory, 1)
    assert any("Probe too long" == i for i in q["issues"])


@pytest.mark.anyio
async def test_judge_finding_confirmed():
    monitor = QualityMonitor()
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(return_value=({
        "verdict": "confirmed",
        "confidence_adjustment": 0.1,
        "reasoning": "SQL error signature + payload evidence.",
    }, None))
    ledger = SimpleNamespace(charge=lambda *args, **kwargs: True)
    finding = {
        "hypothesis": "SQL injection",
        "exploitation_evidence": {"payload_used": "'"},
        "confirmed_facts": ["mysql_error"],
        "owasp_category": "A03:2023",
    }
    out = await monitor.judge_finding(finding, ai_client, ledger)
    assert out["verdict"] == "confirmed"
    assert out["confidence_adjustment"] > 0


@pytest.mark.anyio
async def test_judge_finding_invalid_payload_defaults_uncertain():
    monitor = QualityMonitor()
    ai_client = SimpleNamespace()
    ai_client.query_with_retry = AsyncMock(return_value=("not-json", None))
    ledger = SimpleNamespace(charge=lambda *args, **kwargs: True)
    out = await monitor.judge_finding({}, ai_client, ledger)
    assert out["verdict"] == "uncertain"
