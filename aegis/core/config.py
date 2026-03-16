"""
aegis/core/config.py
"""

import os
import logging
from pathlib import Path
from typing import List, Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Anchor: directory containing this file → .../aegis/core/
_HERE = Path(__file__).resolve().parent
# Project root: two levels up from aegis/core/
_PROJECT_ROOT = _HERE.parent.parent

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    # ── Database ──────────────────────────────
    DATABASE_URL: str = "sqlite:///./data/aegis.db"

    # ── AI / Ollama ───────────────────────────
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    DEFAULT_MODEL: str = "mixtral:latest"
    # Backward-compatibility alias for existing deployments using OLLAMA_MODEL.
    # If set, resolve_paths() maps it to DEFAULT_MODEL.
    OLLAMA_MODEL: str | None = None
    OLLAMA_MODEL_FAST: str = "llama3:latest"
    AI_PROVIDER: str = "ollama"
    AI_FALLBACK_PROVIDER: str = "none"
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"

    # ── Pipeline / graph / reasoning controls ─
    MAX_GRAPH_TOKENS: int = 50000
    GRAPH_COMPRESS_THRESHOLD: float = 0.8
    MAX_TURNS_PER_HYPOTHESIS: int = 6
    MAX_CONCURRENT_SCANS: int = 3

    # ── Probe execution pacing ────────────────
    PROBE_DELAY_MIN: float = 0.5
    PROBE_DELAY_MAX: float = 1.5

    # ── Memory controls ───────────────────────
    WORKING_MEMORY_LIMIT: int = 4

    # ── Integration Feature Flags ─────────────
    # Tier 2 integrations are opt-in and default OFF to preserve current behavior.
    ENABLE_VULN_ANALYSIS_SEEDING: bool = True
    ENABLE_RAG_PROBING: bool = True
    ENABLE_ACTIVE_CONFIRMATION: bool = True
    ENABLE_PAYLOAD_GENERATION: bool = True
    ENABLE_ACTIVE_PENETRATION: bool = True
    ENABLE_LLM_JUDGE: bool = True
    SCAN_EXECUTION_PROFILE: str = "aggressive"  # legacy | safe | balanced | aggressive

    # ── Reserved / currently unused — planned for future features ─
    # Kept for backward compatibility with existing deployments/.env files.

    # ── Redis ─────────────────────────────────
    REDIS_URL: str = "redis://redis:6379"
    NVD_API_KEY: str = ""

    # ── API ───────────────────────────────────
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "aegis-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    API_KEY: str = ""
    REQUIRE_API_KEY: bool = False
    SCAN_TARGET_DENY_CIDRS: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fc00::/7"
    SCAN_TARGET_ALLOW_EXTERNAL_ONLY: bool = True
    CORS_ALLOW_ORIGINS: List[str] = ["*"]

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

        # Backward compatibility: accept legacy OLLAMA_MODEL env var and
        # map it to DEFAULT_MODEL used by AIClient.
        if self.OLLAMA_MODEL:
            self.DEFAULT_MODEL = self.OLLAMA_MODEL

        self._apply_scan_profile()

        return self
    
    def _apply_scan_profile(self) -> None:
        profile = str(self.SCAN_EXECUTION_PROFILE or "legacy").strip().lower()
        if profile == "legacy":
            return
        if profile == "safe":
            self.ENABLE_VULN_ANALYSIS_SEEDING = True
            self.ENABLE_PAYLOAD_GENERATION = False
            self.ENABLE_ACTIVE_PENETRATION = False
            self.ENABLE_ACTIVE_CONFIRMATION = False
            return
        if profile == "balanced":
            self.ENABLE_VULN_ANALYSIS_SEEDING = True
            self.ENABLE_PAYLOAD_GENERATION = True
            self.ENABLE_ACTIVE_PENETRATION = False
            self.ENABLE_ACTIVE_CONFIRMATION = False
            return
        if profile == "aggressive":
            self.ENABLE_VULN_ANALYSIS_SEEDING = True
            self.ENABLE_PAYLOAD_GENERATION = True
            self.ENABLE_ACTIVE_PENETRATION = True
            self.ENABLE_ACTIVE_CONFIRMATION = True
            return
        logger.warning("Unknown SCAN_EXECUTION_PROFILE '%s'; using legacy behavior", profile)

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

        if self.REQUIRE_API_KEY and not self.API_KEY:
            warnings.append("REQUIRE_API_KEY is true but API_KEY is empty; all API requests will be rejected.")

        if self.AI_PROVIDER.lower() == "openai" and not self.OPENAI_API_KEY:
            warnings.append("AI_PROVIDER=openai but OPENAI_API_KEY is empty; requests will fail unless fallback provider is configured.")

        if self.PROBE_DELAY_MIN >= self.PROBE_DELAY_MAX:
            warnings.append(
                "Probe delay configuration is invalid: "
                "PROBE_DELAY_MIN must be less than PROBE_DELAY_MAX."
            )

        if self.ENABLE_VULN_ANALYSIS_SEEDING:
            logger.info("Integration feature flag enabled: ENABLE_VULN_ANALYSIS_SEEDING")
        if self.ENABLE_RAG_PROBING:
            logger.info("Integration feature flag enabled: ENABLE_RAG_PROBING")
        if self.ENABLE_ACTIVE_CONFIRMATION:
            logger.info("Integration feature flag enabled: ENABLE_ACTIVE_CONFIRMATION")
        if self.ENABLE_PAYLOAD_GENERATION:
            logger.info("Integration feature flag enabled: ENABLE_PAYLOAD_GENERATION")
        if self.ENABLE_ACTIVE_PENETRATION:
            logger.info("Integration feature flag enabled: ENABLE_ACTIVE_PENETRATION")

        db_dir = Path(self.get_db_path()).parent
        if not os.access(db_dir, os.W_OK):
            warnings.append(f"Database directory is not writable: {db_dir}")

        return warnings

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


# Global singleton — import this everywhere
settings = Settings()
