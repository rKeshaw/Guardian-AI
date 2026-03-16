from __future__ import annotations

from difflib import SequenceMatcher

from aegis.core.memory.conversation_memory import ConversationMemory


class QualityMonitor:
    def assess(self, memory: ConversationMemory, turn: int) -> dict:
        issues: list[str] = []
        recovery_message: str | None = None

        confidences = memory.recent_confidences

        # Check 1 — Confidence stuck low
        if turn >= 4 and confidences:
            if all(c < 0.25 for c in confidences) and memory.confidence_trend == "flat":
                issues.append("Confidence flat at low levels for 4+ turns")
                recovery_message = (
                    "Your confidence has been consistently low. Either this injection point is not vulnerable "
                    "(set terminal=true, exploitation_confirmed=false) or you need a completely different attack angle. "
                    "Do not vary the same technique — pivot entirely."
                )

        # Check 2 — Repetitive observations
        obs_texts = [
            str(t.get("observation", {}).get("content", ""))
            for t in memory._working[-3:]
            if isinstance(t.get("observation", {}), dict)
        ]
        if len(obs_texts) == 3 and all(obs_texts):
            s01 = SequenceMatcher(None, obs_texts[0], obs_texts[1]).ratio()
            s02 = SequenceMatcher(None, obs_texts[0], obs_texts[2]).ratio()
            s12 = SequenceMatcher(None, obs_texts[1], obs_texts[2]).ratio()
            if s01 > 0.85 and s02 > 0.85 and s12 > 0.85:
                issues.append("Observations are repetitive — not learning from responses")
                recovery_message = (
                    "Your last three observations are nearly identical, suggesting you are not changing your approach "
                    "based on what you see. Look more carefully at the response differences and try something fundamentally different."
                )

        # Check 3 — Empty confirmed facts after many turns
        if turn >= 6 and len(memory.confirmed_facts) == 0:
            issues.append("No facts confirmed after 6 turns")
            recovery_message = (
                "You have been testing for 6 turns without confirming any facts about the target. This suggests either "
                "the parameter is not injectable or your probes are being blocked. Try a diagnostic probe to understand "
                "the application's behavior: send a long random string and observe how the application handles unexpected input."
            )

        # Check 4 — Probe quality
        last_probe = None
        if memory._working:
            last_turn = memory._working[-1]
            llm_reason = last_turn.get("llm_reasoning", {}) if isinstance(last_turn, dict) else {}
            last_probe = llm_reason.get("next_probe") if isinstance(llm_reason, dict) else None
            if not last_probe:
                last_probe = last_turn.get("probe") if isinstance(last_turn, dict) else None

        if isinstance(last_probe, str) and len(last_probe) > 500:
            issues.append("Probe too long")
            recovery_message = (
                "Your last probe was over 500 characters. Effective probes are precise and short. "
                "Identify the minimal string that tests your hypothesis."
            )

        return {
            "quality_ok": len(issues) == 0,
            "issues": issues,
            "recovery_message": recovery_message,
        }
