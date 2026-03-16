from __future__ import annotations

import json
import logging
from pydantic import BaseModel, Field

from aegis.core.ai_client import estimate_tokens

logger = logging.getLogger(__name__)

class TargetModel(BaseModel):
    url: str
    domain: str
    technologies: list[str] = Field(default_factory=list)
    waf_detected: str | None = None
    backend_language: str | None = None
    database_hint: str | None = None
    framework: str | None = None
    injection_points: list[dict] = Field(default_factory=list)
    graphql_schema: dict = Field(default_factory=dict)
    forms: list[dict] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)
    html_comments: list[str] = Field(default_factory=list)
    hardcoded_values: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    open_ports: list[dict] = Field(default_factory=list)
    subdomains: list[dict] = Field(default_factory=list)
    subdomain_takeover_risk: str | None = None
    cve_correlations: list[dict] = Field(default_factory=list)
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
            "graphql_schema": self.graphql_schema,
            "api_endpoints": self.api_endpoints[:30],
            "html_comments": self.html_comments[:10],
            "hardcoded_values": self.hardcoded_values[:20],
            "interesting_paths": self.interesting_paths[:20],
            "open_ports": self.open_ports[:20],
            "subdomains": self.subdomains[:20],
            "subdomain_takeover_risk": self.subdomain_takeover_risk,
            "cve_correlations": self.cve_correlations[:20],
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
            "subdomains",
            "html_comments",
        ]

        def _token_len() -> int:
            return estimate_tokens(json.dumps(ctx, ensure_ascii=False))

        previous_tokens = _token_len()
        stagnant_iterations = 0
        for _ in range(500):
            if previous_tokens < 2000:
                break
            longest_key = max(
                list_keys,
                key=lambda k: len(ctx.get(k, [])) if isinstance(ctx.get(k), list) else 0,
            )
            arr = ctx.get(longest_key, [])
            if isinstance(arr, list) and arr:
                arr.pop()
                ctx[longest_key] = arr
            else:
                string_trim_order = ["framework", "database_hint", "backend_language", "waf_detected"]
                trimmed_string = False
                for key in string_trim_order:
                    value = ctx.get(key)
                    if isinstance(value, str) and value:
                        if len(value) > 32:
                            ctx[key] = value[:32]
                        else:
                            ctx[key] = None
                        trimmed_string = True
                        break

                if not trimmed_string:
                    url_value = str(ctx.get("url", ""))
                    if url_value:
                        from urllib.parse import urlparse

                        parsed = urlparse(url_value)
                        ctx["url"] = parsed.netloc or parsed.path or url_value[:128]
                    else:
                        break

            current_tokens = _token_len()
            if current_tokens >= previous_tokens:
                stagnant_iterations += 1
            else:
                stagnant_iterations = 0

            if stagnant_iterations >= 50:
                logger.error("Failed to reduce hypothesis context tokens after iterative trimming")
                break
            previous_tokens = current_tokens

        if _token_len() >= 2000:
            url_value = str(ctx.get("url", ""))
            if url_value:
                max_chars = 512
                while estimate_tokens(json.dumps(ctx, ensure_ascii=False)) >= 2000 and max_chars > 16:
                    ctx["url"] = url_value[:max_chars]
                    max_chars //= 2

        return ctx
