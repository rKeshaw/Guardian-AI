from __future__ import annotations

import json
from pydantic import BaseModel, Field

from guardian.core.ai_client import estimate_tokens


class TargetModel(BaseModel):
    url: str
    domain: str
    technologies: list[str] = Field(default_factory=list)
    waf_detected: str | None = None
    backend_language: str | None = None
    database_hint: str | None = None
    framework: str | None = None
    injection_points: list[dict] = Field(default_factory=list)
    forms: list[dict] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)
    html_comments: list[str] = Field(default_factory=list)
    hardcoded_values: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    open_ports: list[dict] = Field(default_factory=list)
    attack_surface_signals: list[str] = Field(default_factory=list)
    page_classifications: dict[str, str] = Field(default_factory=dict)

    def to_hypothesis_context(self) -> dict:
        ctx = {
            "url": self.url,
            "domain": self.domain,
            "technologies": self.technologies[:20],
            "waf_detected": self.waf_detected,
            "backend_language": self.backend_language,
            "database_hint": self.database_hint,
            "framework": self.framework,
            "injection_points": self.injection_points[:30],
            "api_endpoints": self.api_endpoints[:30],
            "html_comments": self.html_comments[:10],
            "hardcoded_values": self.hardcoded_values[:20],
            "interesting_paths": self.interesting_paths[:20],
            "open_ports": self.open_ports[:20],
            "attack_surface_signals": self.attack_surface_signals[:15],
        }

        list_keys = [
            "injection_points",
            "attack_surface_signals",
            "api_endpoints",
            "hardcoded_values",
            "interesting_paths",
            "technologies",
            "open_ports",
            "html_comments",
        ]

        def _token_len() -> int:
            return estimate_tokens(json.dumps(ctx, ensure_ascii=False))

        while _token_len() >= 2000:
            longest_key = max(
                list_keys,
                key=lambda k: len(ctx.get(k, [])) if isinstance(ctx.get(k), list) else 0,
            )
            arr = ctx.get(longest_key, [])
            if not isinstance(arr, list) or not arr:
                break
            arr.pop()
            ctx[longest_key] = arr

        return ctx
