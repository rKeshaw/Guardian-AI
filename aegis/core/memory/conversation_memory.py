from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean
from typing import Any

from aegis.core.config import settings


@dataclass
class ConversationMemory:
    seed_hypothesis: str = ""
    _working: list[dict[str, Any]] = field(default_factory=list)
    _episodes: list[Any] = field(default_factory=list)
    confirmed_facts: set[str] = field(default_factory=set)
    _tried: set[str] = field(default_factory=set)

    @property
    def _tried_probes(self) -> set[str]:
        return self._tried

    @property
    def turn_count(self) -> int:
        return len(self._working) + len(self._episodes)
    
    @property
    def _WORKING_MEMORY_LIMIT(self) -> int:
        return int(settings.WORKING_MEMORY_LIMIT)

    @property
    def recent_confidences(self) -> list[float]:
        vals = [
            float(t.get("confidence_after"))
            for t in self._working
            if isinstance(t.get("confidence_after"), (float, int))
        ]
        return vals

    def add_turn(self, *args: Any) -> bool:
        if len(args) == 1 and isinstance(args[0], dict):
            turn = args[0]
        elif len(args) == 4:
            probe, profile_prompt, observation_unit, llm_response = args
            turn = {
                "probe": probe,
                "observation": {
                    "content": getattr(observation_unit, "content", ""),
                    "facts": list(getattr(observation_unit, "irreducible_facts", [])),
                    "profile": profile_prompt,
                },
                "llm_reasoning": llm_response,
                "confidence_after": float(llm_response.get("confidence", 0)) / 100.0,
            }
        else:
            raise TypeError("add_turn expects either a turn dict or (probe, profile, observation_unit, llm_response)")

        self._working.append(turn)

        probe = turn.get("probe")
        if isinstance(probe, str) and probe:
            self._tried.add(probe)

        llm_reasoning = turn.get("llm_reasoning", {})
        for fact in llm_reasoning.get("confirmed_facts", []):
            if isinstance(fact, str) and fact:
                self.confirmed_facts.add(fact)

        obs = turn.get("observation", {})
        for fact in obs.get("facts", []):
            if isinstance(fact, str) and fact:
                self.confirmed_facts.add(fact)

        return len(self._working) > self._WORKING_MEMORY_LIMIT

    def oldest_working_turn(self) -> dict[str, Any] | None:
        return self._working[0] if self._working else None

    def already_tried(self, probe: str) -> bool:
        return probe in self._tried

    def render_for_prompt(self, token_budget: int) -> str:
        char_budget = max(token_budget * 4, 0)

        fact_lines = [f"- {fact}" for fact in sorted(self.confirmed_facts)]
        fact_section = "Confirmed facts:\n" + "\n".join(fact_lines) if fact_lines else ""

        remaining = max(char_budget - len(fact_section), 0)

        working_parts: list[str] = []
        for turn in reversed(self._working):
            snippet = (
                f"Probe: {turn.get('probe', '')}\n"
                f"Obs: {turn.get('observation', {}).get('content', '')}\n"
            )
            if len("\n".join(working_parts)) + len(snippet) > remaining:
                break
            working_parts.append(snippet)

        body = "\n".join(reversed(working_parts)).strip()
        rendered = "\n\n".join(s for s in [fact_section, body] if s)
        return rendered[:char_budget]

    @property
    def confidence_trend(self) -> str:
        vals = self.recent_confidences
        if len(vals) < 2:
            return "flat"
        delta = vals[-1] - vals[0]
        if delta > 0.1:
            return "rising"
        if delta < -0.1:
            return "falling"
        if mean(abs(vals[i] - vals[i - 1]) for i in range(1, len(vals))) <= 0.05:
            return "flat"
        return "flat"

    def flush_oldest(self, compressed_unit: Any) -> None:
        if len(self._working) > self._WORKING_MEMORY_LIMIT:
            self._working.pop(0)
        self._episodes.append(compressed_unit)
