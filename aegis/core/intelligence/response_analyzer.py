from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.core.intelligence.comprehender import Comprehender


@dataclass
class ResponseProfile:
    status_code: int
    status_changed: bool
    baseline_status: int
    body_length: int
    length_delta: int
    length_ratio: float
    response_time_ms: float
    time_delta_ms: float
    new_content: str
    new_headers: dict[str, str]
    error: str | None
    extracted_facts: list[str] = field(default_factory=list)
    time_anomaly: bool = False

    def to_prompt_dict(self) -> dict[str, Any]:
        return {
            "status": self.status_code,
            "status_changed": self.status_changed,
            "baseline_status": self.baseline_status,
            "length_delta": self.length_delta,
            "length_ratio": round(self.length_ratio, 2),
            "time_delta_ms": round(self.time_delta_ms, 1),
            "time_anomaly": self.time_anomaly,
            "new_content_preview": self.new_content[:500],
            "extracted_facts": self.extracted_facts,
            "error": self.error,
        }


class ResponseAnalyzer:
    def __init__(self) -> None:
        self._comprehender = Comprehender()

    def analyze(self, current: Any, baseline: Any | None, threshold_ms: float = 4000.0) -> ResponseProfile:
        if getattr(current, "is_error", False):
            return ResponseProfile(
                status_code=0,
                status_changed=False,
                baseline_status=0,
                body_length=0,
                length_delta=0,
                length_ratio=0.0,
                response_time_ms=0.0,
                time_delta_ms=0.0,
                new_content="",
                new_headers={},
                error=getattr(current, "error", None),
                extracted_facts=[],
                
            )

        from aegis.core.probing.probe_executor import ProbeExecutor

        delta = ProbeExecutor.compute_delta(current, baseline)
        profile = ResponseProfile(
            status_code=int(delta.get("status_code", 0)),
            status_changed=bool(delta.get("status_changed", False)),
            baseline_status=int(delta.get("baseline_status", 0)),
            body_length=int(delta.get("body_length", 0)),
            length_delta=int(delta.get("length_delta", 0)),
            length_ratio=float(delta.get("length_ratio", 0.0)),
            response_time_ms=float(delta.get("response_time_ms", 0.0)),
            time_delta_ms=float(delta.get("time_delta_ms", 0.0)),
            new_content=str(delta.get("new_content", ""))[:3000],
            new_headers={str(k): str(v) for k, v in dict(delta.get("new_headers", {})).items()},
            error=getattr(current, "error", None),
            time_anomaly=float(delta.get("time_delta_ms", 0.0)) > float(threshold_ms),
        )
        profile.extracted_facts = self._comprehender._extract_facts(
            f"{profile.new_content} {profile.new_headers}"
        )
        return profile
