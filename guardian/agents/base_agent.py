"""
guardian/agents/base_agent.py

Shared base class for all five pipeline agents.
"""

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import Executor
from typing import Any

from guardian.core.ai_client import estimate_tokens

logger = logging.getLogger(__name__)


class PromptTooLargeError(RuntimeError):
    """Raised when a prompt exceeds the hard token limit."""
    pass


class BaseAgent(ABC):
    # Warn at 6,000 tokens (Mistral context is 8,192; leaves ~2k for response)
    PROMPT_WARN_TOKENS: int = 6_000
    # Hard stop at 7,500 — anything above risks silent truncation
    PROMPT_HARD_LIMIT: int = 7_500

    def __init__(self, db, agent_name: str) -> None:
        self.db = db
        self.agent_name = agent_name
        self._status: str = "idle"
        self._current_task_id: str | None = None
        self.logger = logging.getLogger(f"guardian.agents.{agent_name}")

    # ── Abstract interface ────────────────────

    @abstractmethod
    async def execute(self, task_data: dict[str, Any]) -> dict[str, Any]:
        """Run the agent's main logic and return a results dict."""
        ...

    # ── Status ────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "status": self._status,
            "current_task_id": self._current_task_id,
        }

    # ── Lifecycle helpers ─────────────────────

    async def _start_task(self, task_data: dict[str, Any]) -> str:
        task_id = str(uuid.uuid4())
        self._current_task_id = task_id
        self._status = "running"
        self.logger.debug("Task started task_id=%s", task_id)

        if self.db:
            try:
                await self.db.save_agent_task({
                    "task_id": task_id,
                    "agent_name": self.agent_name,
                    "session_id": task_data.get("session_id", "unknown"),
                    "status": "running",
                    "input_summary": {
                        k: (str(v)[:120] if isinstance(v, str) else type(v).__name__)
                        for k, v in task_data.items()
                        if k != "config"
                    },
                })
            except Exception as exc:
                self.logger.debug("Could not persist task start: %s", exc)

        return task_id

    async def _complete_task(
        self, results: dict[str, Any], session_id: str
    ) -> None:
        self._status = "completed"
        self.logger.debug(
            "Task completed task_id=%s session_id=%s",
            self._current_task_id, session_id,
        )

        if self.db:
            try:
                await self.db.save_agent_results(
                    session_id=session_id,
                    agent_name=self.agent_name,
                    results=results,
                )
            except Exception as exc:
                self.logger.debug("Could not persist task results: %s", exc)

        self._current_task_id = None

    async def _handle_error(self, exc: Exception, session_id: str) -> None:
        self._status = "error"
        self.logger.error(
            "Agent error agent=%s session_id=%s error=%s",
            self.agent_name, session_id, exc,
        )

        if self.db:
            try:
                await self.db.save_agent_error(
                    session_id=session_id,
                    agent_name=self.agent_name,
                    error=str(exc),
                )
            except Exception as db_exc:
                self.logger.debug("Could not persist error: %s", db_exc)

        self._current_task_id = None

    async def cleanup(self) -> None:
        """Called by orchestrator on scan stop. Override in agents with
        open resources (e.g. aiohttp sessions)."""
        self._status = "idle"
        self._current_task_id = None

    # ── Token budget guard (FIX 11) ───────────

    def _check_prompt_tokens(
        self,
        prompt: str,
        context_label: str = "",
    ) -> int:
        """
        Estimate prompt token count and enforce the budget.

        Logs a WARNING above PROMPT_WARN_TOKENS.
        Raises PromptTooLargeError above PROMPT_HARD_LIMIT.

        Returns the estimated token count so callers can log it.
        """
        tokens = estimate_tokens(prompt)
        label = f"[{context_label}] " if context_label else ""

        if tokens > self.PROMPT_HARD_LIMIT:
            msg = (
                f"{label}Prompt exceeds hard token limit "
                f"({tokens} > {self.PROMPT_HARD_LIMIT}). "
                "Refusing to send — truncate input data before querying the LLM."
            )
            self.logger.error(msg)
            raise PromptTooLargeError(msg)

        if tokens > self.PROMPT_WARN_TOKENS:
            self.logger.warning(
                "%sLarge prompt tokens≈%d (warn threshold=%d). "
                "Risk of context window truncation.",
                label, tokens, self.PROMPT_WARN_TOKENS,
            )

        return tokens

    # ── Async executor helper (FIX 09) ────────

    @staticmethod
    async def run_in_executor(executor: Executor | None, fn, *args) -> Any:
        """
        Run a blocking callable in an executor using get_running_loop().
        Replaces all uses of asyncio.get_event_loop().run_in_executor()
        throughout the codebase.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(executor, fn, *args)
