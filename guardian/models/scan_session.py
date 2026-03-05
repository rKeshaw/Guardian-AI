"""
guardian/models/scan_session.py
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScanStatus(str, Enum):
    INITIALIZING  = "initializing"
    RUNNING       = "running"
    COMPLETED     = "completed"
    ERROR         = "error"
    CANCELLED     = "cancelled"


class ScanSession(BaseModel):
    # FIX 16: Pydantic v2 config — replaces inner class Config
    model_config = ConfigDict(
        use_enum_values=True,    # stores enum as its string value
        populate_by_name=True,   # allows field_name and alias interchangeably
    )

    session_id: str
    target_urls: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    status: ScanStatus = ScanStatus.INITIALIZING

    # Timestamps
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Optional fields
    error_message: str | None = None
    results_summary: dict[str, Any] | None = None

    @classmethod
    def from_db_row(cls, row: dict[str, Any]) -> "ScanSession":
        """
        Construct a ScanSession from a raw database row dict.
        Handles type coercions (e.g. JSON strings for list/dict fields).
        """
        import json as _json

        data = dict(row)

        # Deserialise JSON-encoded list/dict columns from SQLite TEXT
        for field_name in ("target_urls", "config", "results_summary"):
            val = data.get(field_name)
            if isinstance(val, str):
                try:
                    data[field_name] = _json.loads(val)
                except (ValueError, TypeError):
                    pass

        # Parse datetime strings
        for dt_field in ("started_at", "completed_at"):
            val = data.get(dt_field)
            if isinstance(val, str):
                try:
                    data[dt_field] = datetime.fromisoformat(val)
                except (ValueError, TypeError):
                    data[dt_field] = None

        return cls.model_validate(data)
