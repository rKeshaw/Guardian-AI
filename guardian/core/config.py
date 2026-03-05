"""
guardian/core/config.py
"""

import os
from pathlib import Path
from typing import List, Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings

# Anchor: directory containing this file → .../guardian/core/
_HERE = Path(__file__).resolve().parent
# Project root: two levels up from guardian/core/
_PROJECT_ROOT = _HERE.parent.parent


class Settings(BaseSettings):
    # ── Database ──────────────────────────────
    DATABASE_URL: str = "sqlite:///./data/guardian.db"

    # ── Redis ─────────────────────────────────
    REDIS_URL: str = "redis://redis:6379"

    # ── AI / Ollama ───────────────────────────
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    DEFAULT_MODEL: str = "mistral:latest"

    # ── API ───────────────────────────────────
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "guardian-ai-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ── Agent concurrency ─────────────────────
    MAX_CONCURRENT_AGENTS: int = 5
    AGENT_TIMEOUT: int = 300

    # ── Reconnaissance ────────────────────────
    CRAWL_DEPTH: int = 3

    # ── SSL / TLS ─────────────────────────────
    # Single source of truth for SSL verification across all HTTP clients.
    # Set VERIFY_SSL=false in the environment ONLY when targeting hosts with
    # self-signed certificates you accept the risk for.
    VERIFY_SSL: bool = True
    # Optional path to a custom CA bundle (PEM file) for private/internal CAs.
    # If unset and VERIFY_SSL=True, the system CA store is used.
    CA_BUNDLE_PATH: Optional[str] = None

    # ── Stealth / user agents ─────────────────
    STEALTH_MODE: bool = True
    USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]

    # ── Knowledge base (PayloadsAllTheThings) ─
    # Default assumes the volume mount defined in docker-compose.yml.
    # Resolved to an absolute path by the validator below.
    PAYLOADS_REPO_PATH: str = "/PayloadsAllTheThings"

    # ── Rate limiting ─────────────────────────
    REQUESTS_PER_SECOND: float = 1.0
    BURST_SIZE: int = 5

    # ── Logging ───────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

    # ─────────────────────────────────────────
    # Path resolution validator
    # ─────────────────────────────────────────
    @model_validator(mode="after")
    def resolve_paths(self) -> "Settings":
        """
        Convert any relative paths to absolute paths anchored at the project
        root.  This ensures the application behaves identically regardless of
        the process working directory — in tests, in Docker, or run locally.
        """
        # DATABASE_URL: strip the SQLite URI prefix, resolve, reattach
        db_path = self.DATABASE_URL.replace("sqlite:///", "")
        resolved_db = Path(db_path) if Path(db_path).is_absolute() else (_PROJECT_ROOT / db_path)
        resolved_db.parent.mkdir(parents=True, exist_ok=True)
        self.DATABASE_URL = f"sqlite:///{resolved_db}"

        # PAYLOADS_REPO_PATH
        p = Path(self.PAYLOADS_REPO_PATH)
        if not p.is_absolute():
            p = _PROJECT_ROOT / p
        self.PAYLOADS_REPO_PATH = str(p)

        # CA_BUNDLE_PATH: resolve if set
        if self.CA_BUNDLE_PATH:
            ca = Path(self.CA_BUNDLE_PATH)
            if not ca.is_absolute():
                ca = _PROJECT_ROOT / ca
            self.CA_BUNDLE_PATH = str(ca)

        return self

    def get_db_path(self) -> str:
        """Return the raw filesystem path (no sqlite:/// prefix)."""
        return self.DATABASE_URL.replace("sqlite:///", "")

    def validate_environment(self) -> list[str]:
        """
        Return a list of warning strings for any environment problems detected.
        Called at application startup and surfaced in /api/v1/health.
        """
        warnings: list[str] = []

        payloads_path = Path(self.PAYLOADS_REPO_PATH)
        if not payloads_path.exists():
            warnings.append(
                f"PAYLOADS_REPO_PATH does not exist: {self.PAYLOADS_REPO_PATH}. "
                "Payload generation will fall back to non-RAG mode."
            )
        elif not any(payloads_path.rglob("*.md")):
            warnings.append(
                f"PAYLOADS_REPO_PATH exists but contains no .md files: {self.PAYLOADS_REPO_PATH}. "
                "Knowledge index will be empty — check the volume mount."
            )

        if self.CA_BUNDLE_PATH and not Path(self.CA_BUNDLE_PATH).exists():
            warnings.append(
                f"CA_BUNDLE_PATH is set but file does not exist: {self.CA_BUNDLE_PATH}"
            )

        if not self.VERIFY_SSL:
            warnings.append(
                "SSL verification is disabled (VERIFY_SSL=False). "
                "Reconnaissance traffic is vulnerable to MITM attacks."
            )

        db_dir = Path(self.get_db_path()).parent
        if not os.access(db_dir, os.W_OK):
            warnings.append(f"Database directory is not writable: {db_dir}")

        return warnings

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global singleton — import this everywhere
settings = Settings()