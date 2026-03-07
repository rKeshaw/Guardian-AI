from guardian.core.memory.conversation_memory import ConversationMemory


def _turn(i: int, probe: str, obs: str, confidence: float) -> dict:
    return {
        "probe": probe,
        "observation": {"content": obs},
        "llm_reasoning": {"confirmed_facts": [f"fact_{i}"]},
        "confidence_after": confidence,
    }


def test_confirmed_facts_never_lost():
    memory = ConversationMemory()

    for i in range(6):
        memory.add_turn(_turn(i, f"probe_{i}", f"obs_{i}", 0.5))

    for i in range(6):
        assert f"fact_{i}" in memory.confirmed_facts


def test_already_tried_exact_match():
    memory = ConversationMemory()
    memory.add_turn(_turn(1, "' OR 1=1--", "obs", 0.5))

    assert memory.already_tried("' OR 1=1--") is True
    assert memory.already_tried("' OR 1=1-- -") is False


def test_render_within_token_budget():
    memory = ConversationMemory()
    for i in range(4):
        memory.add_turn(_turn(i, f"probe_{i}", "x" * 2000, 0.5))

    rendered = memory.render_for_prompt(token_budget=500)

    assert len(rendered) <= 2000


def test_render_facts_appear_even_with_tiny_budget():
    memory = ConversationMemory()
    for i in range(4):
        memory.add_turn(_turn(i, f"probe_{i}", "x" * 2000, 0.5))

    rendered = memory.render_for_prompt(token_budget=50)

    assert "fact_" in rendered


def test_confidence_trend_rising():
    memory = ConversationMemory()
    memory.add_turn(_turn(1, "p1", "obs", 0.3))
    memory.add_turn(_turn(2, "p2", "obs", 0.5))
    memory.add_turn(_turn(3, "p3", "obs", 0.7))

    assert memory.confidence_trend == "rising"


def test_confidence_trend_flat():
    memory = ConversationMemory()
    memory.add_turn(_turn(1, "p1", "obs", 0.5))
    memory.add_turn(_turn(2, "p2", "obs", 0.48))
    memory.add_turn(_turn(3, "p3", "obs", 0.52))

    assert memory.confidence_trend == "flat"


def test_flush_oldest_moves_to_episodic():
    memory = ConversationMemory()
    for i in range(5):
        memory.add_turn(_turn(i, f"probe_{i}", f"obs_{i}", 0.5))

    compressed_unit = {"content": "compressed"}
    memory.flush_oldest(compressed_unit)

    assert len(memory._working) == 4
    assert len(memory._episodes) == 1
