from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

import aiohttp

from aegis.core.config import settings

logger = logging.getLogger(__name__)


class CVECorrelator:
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self) -> None:
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self._last_request_ts = 0.0

    def _extract_tech_versions(self, tech_stack: list[str], headers: dict) -> list[tuple[str, str]]:
        discovered: set[tuple[str, str]] = set()
        for tech in tech_stack:
            value = str(tech or "").strip()
            m = re.search(r"([a-zA-Z0-9._-]+)[/ ](\d+(?:\.\d+){1,3})", value)
            if m:
                discovered.add((m.group(1).lower(), m.group(2)))

        header_values = " ".join([str(v) for v in (headers or {}).values()])
        for m in re.finditer(r"([A-Za-z][A-Za-z0-9._-]{1,30})[/ ](\d+(?:\.\d+){1,3})", header_values):
            discovered.add((m.group(1).lower(), m.group(2)))

        key_headers = {
            "server": r"([A-Za-z0-9._-]+)/(\d+(?:\.\d+){1,3})",
            "x-powered-by": r"([A-Za-z0-9._ -]+)/? ?(\d+(?:\.\d+){1,3})",
            "x-aspnet-version": r"(\d+(?:\.\d+){1,3})",
        }
        header_map = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        for hk, pattern in key_headers.items():
            val = header_map.get(hk)
            if not val:
                continue
            m = re.search(pattern, val, re.I)
            if not m:
                continue
            if hk == "x-aspnet-version":
                discovered.add(("asp.net", m.group(1)))
            else:
                discovered.add((m.group(1).strip().lower(), m.group(2)))
        return sorted(discovered)

    async def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request_ts
        min_interval = 1 / 3.0
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_ts = time.monotonic()

    async def _query_nvd(self, session: aiohttp.ClientSession, tech: str, version: str) -> list[dict[str, Any]]:
        cache_key = f"{tech}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        await self._rate_limit()
        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY
        params = {
            "keywordSearch": f"{tech} {version}",
            "cvssV3Severity": "HIGH,CRITICAL",
            "resultsPerPage": "5",
        }
        try:
            async with session.get(self.NVD_API, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                payload = await resp.json(content_type=None)
        except Exception as exc:
            logger.debug("nvd_lookup_failed tech=%s version=%s error=%s", tech, version, exc)
            self._cache[cache_key] = []
            return []

        vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        out: list[dict[str, Any]] = []
        for item in vulns[:5]:
            cve = (item or {}).get("cve", {})
            cve_id = cve.get("id")
            desc = ""
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score = None
            metrics = cve.get("metrics", {}) or {}
            v31 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
            if v31 and isinstance(v31, list):
                score = ((v31[0] or {}).get("cvssData") or {}).get("baseScore")
            out.append({
                "cve_id": cve_id,
                "description": desc,
                "cvss_score": score,
                "tech": tech,
                "version": version,
            })

        self._cache[cache_key] = out
        return out

    async def correlate(self, tech_stack: list[str], headers: dict) -> list[dict]:
        tech_versions = self._extract_tech_versions(tech_stack, headers)
        if not tech_versions:
            return []
        results: list[dict] = []
        async with aiohttp.ClientSession() as session:
            for tech, version in tech_versions:
                results.extend(await self._query_nvd(session, tech, version))
        return results
