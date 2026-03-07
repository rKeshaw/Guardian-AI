"""
guardian/agents/penetration_agent.py
"""

import asyncio
import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import aiohttp
from pydantic import BaseModel, Field

from guardian.agents.base_agent import BaseAgent
from guardian.core.ai_client import ai_client, AIPersona
from guardian.core.config import settings

logger = logging.getLogger(__name__)

# OWASP category base impact weights for scoring
_OWASP_IMPACT_WEIGHT: dict[str, int] = {
    "A01:2023": 8,   # Broken Access Control
    "A02:2023": 7,   # Cryptographic Failures
    "A03:2023": 9,   # Injection
    "A04:2023": 5,   # Insecure Design
    "A05:2023": 6,   # Security Misconfiguration
    "A06:2023": 5,   # Vulnerable Components
    "A07:2023": 8,   # Auth Failures
    "A08:2023": 7,   # Integrity Failures
    "A09:2023": 4,   # Logging Failures
    "A10:2023": 7,   # SSRF
}

_SUCCESS_INDICATORS: dict[str, list[str]] = {
    "A01:2023": ["admin", "root:", "uid=0", "unauthorized", "/etc/passwd"],
    "A02:2023": ["-----BEGIN", "private key", "encryption key"],
    "A03:2023": [
        "syntax error", "mysql_fetch", "ora-", "you have an error in your sql",
        "sqlite_version", "information_schema", "pg_sleep", "sleep(", "benchmark(",
    ],
    "A05:2023": ["directory listing", "index of /", "phpinfo()", "server-status"],
    "A07:2023": ["login successful", "welcome back", "authentication bypassed"],
    "A08:2023": ["deserialization error", "unserialize("],
    "A10:2023": ["169.254.169.254", "localhost", "127.0.0.1", "internal service"],
}


# ──────────────────────────────────────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class InjectionPoint:
    url: str          # Always absolute
    method: str       # GET | POST
    param_name: str
    source: str       # "form" | "query"


@dataclass
class Baseline:
    status_code: int
    body_length: int
    response_time_ms: float
    present_indicators: set[str] = field(default_factory=set)


@dataclass
class TestResult:
    exploitation_detected: bool = False
    status_code: int = -1
    response_time_ms: float = 0.0
    body_length: int = 0
    new_indicators: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# Agent
# ──────────────────────────────────────────────────────────────────────────────

class PenetrationAgent(BaseAgent):
    """
    Agent 4 — Stealthy Penetration Testing Execution.

    For each vulnerability in the payload arsenal:
      1. Discover injection points (all URLs absolutized at discovery time).
      2. Capture a baseline response per injection point.
      3. Test payloads, comparing each response against its baseline.
      4. Record only indicators that are NEW relative to the baseline.
    """

    def __init__(self, db) -> None:
        super().__init__(db, "PenetrationAgent")
        self._user_agents: list[str] = settings.USER_AGENTS
        self._stealth_delay_range: tuple[float, float] = (0.5, 1.5)

    # ── Entry point ───────────────────────────

    async def execute(self, task_data: dict[str, Any]) -> dict[str, Any]:
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")

        try:
            payloads_data: dict[str, Any] = task_data.get("payloads", {})
            recon_data: dict[str, Any] = task_data.get("targets", {})

            recon_map = recon_data.get("reconnaissance_data", {})
            if not recon_map:
                raise ValueError("Reconnaissance data is empty for penetration test.")

            target_url = next(iter(recon_map))
            target_recon = recon_map[target_url]
            payload_arsenal: list[dict] = payloads_data.get("payload_arsenal", [])

            results: dict[str, Any] = {
                "task_id": task_id,
                "penetration_results": {},
            }

            target_results = await self._execute_target_penetration(
                target_url, payload_arsenal, target_recon
            )
            results["penetration_results"][target_url] = target_results
            results["evidence_package"] = self._build_evidence_package(results)

            await self._complete_task(results, session_id)
            exploit_count = len(target_results.get("successful_exploits", []))
            logger.info(
                "ShadowOps complete session_id=%s successful_exploits=%d",
                session_id, exploit_count,
            )
            return results

        except Exception as exc:
            await self._handle_error(exc, session_id)
            raise

    # ── Target execution ──────────────────────

    async def _execute_target_penetration(
        self,
        target_url: str,
        payload_arsenal: list[dict],
        recon_data: dict[str, Any],
    ) -> dict[str, Any]:
        logger.info("ShadowOps executing pentest target=%s", target_url)

        injection_points = self._discover_injection_points(target_url, recon_data)

        if not injection_points:
            logger.warning("No injection points found for %s — skipping active tests", target_url)
            return {
                "target_url": target_url,
                "status": "skipped",
                "reason": "No injectable parameters discovered",
            }

        results: dict[str, Any] = {
            "target_url": target_url,
            "vulnerabilities_tested": len(payload_arsenal),
            "injection_points_discovered": len(injection_points),
            "vulnerability_results": {},
            "successful_exploits": [],
            "failed_attempts": [],
            "stealth_metrics": {"requests_made": 0, "detection_probability": 0.0},
        }

        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=20, connect=8)
        headers = {"User-Agent": random.choice(self._user_agents)}

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers
        ) as session:
            # Capture baselines for all injection points first
            baselines = await self._capture_all_baselines(injection_points, session)

            for vuln_payload_set in payload_arsenal:
                vuln_name = vuln_payload_set.get("target_vulnerability", "Unknown")
                logger.info("Testing vuln=%s on %s", vuln_name, target_url)

                vuln_result = await self._test_vulnerability(
                    vuln_payload_set, injection_points, baselines, session
                )
                results["vulnerability_results"][vuln_name] = vuln_result
                results["stealth_metrics"]["requests_made"] += vuln_result.get("requests_made", 0)

                if vuln_result.get("exploitation_successful"):
                    results["successful_exploits"].append({
                        "vulnerability": vuln_name,
                        "owasp_category": vuln_payload_set.get("owasp_category"),
                        "successful_payload": vuln_result.get("successful_payload"),
                        "evidence": vuln_result.get("evidence"),
                        "impact_level": vuln_result.get("impact_level"),
                    })
                else:
                    results["failed_attempts"].append({
                        "vulnerability": vuln_name,
                        "payloads_tried": len(vuln_result.get("tested_payloads", [])),
                    })

                await self._stealth_delay()

        results["stealth_metrics"]["detection_probability"] = (
            self._calculate_detection_probability(
                results["stealth_metrics"]["requests_made"]
            )
        )
        return results

    # ── Injection point discovery (FIX 06) ────

    def _discover_injection_points(
        self, target_url: str, recon_data: dict[str, Any]
    ) -> list[InjectionPoint]:
        """
        Build the list of injection points.
        All URLs are absolutized here using urljoin(page_url, action).
        Executors receive only absolute URLs — session._base_url is never used.
        """
        points: list[InjectionPoint] = []
        seen: set[tuple] = set()
        web = recon_data.get("web_applications", {})

        # From URL query parameters discovered during crawl
        for endpoint in web.get("endpoints", []):
            parsed = urlparse(endpoint)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in params:
                key = (base, "GET", param)
                if key not in seen:
                    seen.add(key)
                    points.append(InjectionPoint(
                        url=base, method="GET", param_name=param, source="query"
                    ))

        # From HTML forms
        for form in web.get("forms", []):
            raw_action = form.get("action") or target_url
            # FIX 06: absolutize at discovery time
            abs_action = (
                raw_action
                if raw_action.startswith(("http://", "https://"))
                else urljoin(target_url, raw_action)
            )
            method = form.get("method", "GET").upper()

            for inp in form.get("inputs", []):
                param = inp.get("name", "")
                if not param:
                    continue
                key = (abs_action, method, param)
                if key not in seen:
                    seen.add(key)
                    points.append(InjectionPoint(
                        url=abs_action, method=method,
                        param_name=param, source="form"
                    ))

        logger.info(
            "Injection points discovered: %d (forms=%d, query=%d)",
            len(points),
            sum(1 for p in points if p.source == "form"),
            sum(1 for p in points if p.source == "query"),
        )
        return points

    # ── Baseline capture (FIX 07) ─────────────

    async def _capture_all_baselines(
        self,
        points: list[InjectionPoint],
        session: aiohttp.ClientSession,
    ) -> dict[tuple, Baseline]:
        """
        Capture a baseline response for each injection point using a benign probe value.
        Runs all baseline captures concurrently (semaphore-gated).
        """
        sem = asyncio.Semaphore(5)
        results: dict[tuple, Baseline] = {}

        async def capture_one(pt: InjectionPoint) -> None:
            key = (pt.url, pt.method, pt.param_name)
            async with sem:
                baseline = await self._capture_baseline(pt, session)
            results[key] = baseline

        await asyncio.gather(
            *[capture_one(pt) for pt in points],
            return_exceptions=True,
        )
        return results

    async def _capture_baseline(
        self, point: InjectionPoint, session: aiohttp.ClientSession
    ) -> Baseline:
        """Send a known-benign probe and record the normal response profile."""
        benign_value = "guardian_baseline_probe_1234"
        t0 = time.monotonic()
        try:
            if point.method == "POST":
                async with session.post(
                    point.url, data={point.param_name: benign_value}
                ) as resp:
                    body = await resp.text(errors="replace")
                    status = resp.status
            else:
                async with session.get(
                    point.url, params={point.param_name: benign_value}
                ) as resp:
                    body = await resp.text(errors="replace")
                    status = resp.status
        except Exception as exc:
            logger.debug("Baseline capture failed url=%s param=%s: %s", point.url, point.param_name, exc)
            return Baseline(status_code=0, body_length=0, response_time_ms=9999.0)

        elapsed_ms = (time.monotonic() - t0) * 1000
        body_lower = body.lower()

        # Record which indicators are already present in the normal response
        present: set[str] = set()
        for indicators in _SUCCESS_INDICATORS.values():
            for ind in indicators:
                if ind.lower() in body_lower:
                    present.add(ind)

        return Baseline(
            status_code=status,
            body_length=len(body),
            response_time_ms=elapsed_ms,
            present_indicators=present,
        )

    # ── Vulnerability testing ─────────────────

    async def _test_vulnerability(
        self,
        vuln_payload_set: dict[str, Any],
        injection_points: list[InjectionPoint],
        baselines: dict[tuple, Baseline],
        session: aiohttp.ClientSession,
    ) -> dict[str, Any]:
        owasp_cat = vuln_payload_set.get("owasp_category", "")
        vuln_name = vuln_payload_set.get("target_vulnerability", "Unknown")
        payloads: list[dict] = vuln_payload_set.get("payloads", [])

        result: dict[str, Any] = {
            "vulnerability_name": vuln_name,
            "owasp_category": owasp_cat,
            "tested_payloads": [],
            "exploitation_successful": False,
            "successful_payload": None,
            "evidence": {},
            "impact_level": "None",
            "requests_made": 0,
        }

        for point in injection_points:
            pt_key = (point.url, point.method, point.param_name)
            baseline = baselines.get(pt_key)

            for payload_obj in payloads:
                payload_str = payload_obj.get("payload", "")
                if not payload_str:
                    continue

                test = await self._execute_payload(point, payload_str, session)
                result["requests_made"] += 1

                result["tested_payloads"].append({
                    "injection_point": f"{point.method} {point.url} [{point.param_name}]",
                    "payload": payload_str,
                    "status_code": test.status_code,
                })

                # FIX 07: check new indicators against baseline
                new_indicators = self._differential_indicators(
                    test, baseline, owasp_cat
                )

                if new_indicators:
                    result["exploitation_successful"] = True
                    result["successful_payload"] = payload_str
                    result["evidence"] = test.evidence
                    result["impact_level"] = self._assess_impact_level(
                        owasp_cat, new_indicators, test, baseline
                    )
                    logger.info(
                        "EXPLOIT CONFIRMED vuln=%s url=%s param=%s indicators=%s",
                        vuln_name, point.url, point.param_name, new_indicators,
                    )
                    return result

                await self._stealth_delay()

        return result

    async def _execute_payload(
        self,
        point: InjectionPoint,
        payload: str,
        session: aiohttp.ClientSession,
    ) -> TestResult:
        """
        Execute a single payload against an injection point.
        point.url is always absolute (guaranteed by _discover_injection_points).
        """
        t0 = time.monotonic()
        result = TestResult()

        try:
            if point.method == "POST":
                async with session.post(
                    point.url, data={point.param_name: payload}
                ) as resp:
                    body = await resp.text(errors="replace")
                    result.status_code = resp.status
            else:
                async with session.get(
                    point.url, params={point.param_name: payload}
                ) as resp:
                    body = await resp.text(errors="replace")
                    result.status_code = resp.status

            result.response_time_ms = (time.monotonic() - t0) * 1000
            result.body_length = len(body)
            result.evidence = {
                "response_snippet": body[:800],
                "status_code": result.status_code,
                "response_time_ms": round(result.response_time_ms, 1),
                "injection_point": f"{point.method} {point.url} [{point.param_name}]",
                "payload": payload,
            }

        except Exception as exc:
            result.response_time_ms = (time.monotonic() - t0) * 1000
            result.evidence = {"error": str(exc)}
            logger.debug("Payload execution error url=%s: %s", point.url, exc)

        return result

    # ── Differential analysis (FIX 07) ────────

    def _differential_indicators(
        self,
        test: TestResult,
        baseline: Baseline | None,
        owasp_category: str,
    ) -> list[str]:
        """
        Return only indicators that are NEW relative to the baseline.
        Also checks status code deviation and time-based detection.
        """
        if not test.evidence.get("response_snippet"):
            return []

        body_lower = test.evidence["response_snippet"].lower()
        category_indicators = _SUCCESS_INDICATORS.get(owasp_category, [])
        new: list[str] = []

        for ind in category_indicators:
            if ind.lower() in body_lower:
                # Only flag if absent from baseline
                if baseline is None or ind not in baseline.present_indicators:
                    new.append(ind)

        # Status code deviation: 200 on a normally-403/404 endpoint
        if baseline and baseline.status_code in (403, 404, 401):
            if test.status_code == 200:
                new.append(f"status_code_bypass:{baseline.status_code}→200")

        # Body length explosion: >50% larger than baseline (possible data dump)
        if baseline and baseline.body_length > 0:
            ratio = test.body_length / baseline.body_length
            if ratio > 1.5:
                new.append(f"body_length_increase:{ratio:.1f}x")

        # Time-based detection: response >4s slower than baseline
        if baseline and baseline.response_time_ms > 0:
            time_delta = test.response_time_ms - baseline.response_time_ms
            if time_delta > 4000:
                new.append(f"time_based_delay:{time_delta:.0f}ms")

        return new

    def _assess_impact_level(
        self,
        owasp_category: str,
        new_indicators: list[str],
        test: TestResult,
        baseline: Baseline | None,
    ) -> str:
        """
        Score based on OWASP category weight and evidence strength.
        Replaces the previous hardcoded return "High".
        """
        base_weight = _OWASP_IMPACT_WEIGHT.get(owasp_category, 5)
        evidence_bonus = min(len(new_indicators), 3)  # up to +3
        score = base_weight + evidence_bonus

        # Extra weight for authentication bypass or status code jump
        if any("status_code_bypass" in ind for ind in new_indicators):
            score += 2
        if any("body_length_increase" in ind for ind in new_indicators):
            score += 1

        if score >= 11:
            return "Critical"
        elif score >= 8:
            return "High"
        elif score >= 5:
            return "Medium"
        else:
            return "Low"

    # ── Stealth + metrics ─────────────────────

    async def _stealth_delay(self) -> None:
        lo, hi = self._stealth_delay_range
        await asyncio.sleep(random.uniform(lo, hi))

    def _calculate_detection_probability(self, requests_made: int) -> float:
        return round(min(0.95, requests_made * 0.008), 3)

    def _build_evidence_package(self, results: dict[str, Any]) -> dict[str, Any]:
        pen = results.get("penetration_results", {})
        total_exploits = sum(
            len(t.get("successful_exploits", [])) for t in pen.values()
        )
        return {
            "total_successful_exploits": total_exploits,
            "overall_risk": (
                "Critical" if total_exploits >= 3 else
                "High" if total_exploits >= 2 else
                "Medium" if total_exploits >= 1 else
                "Low"
            ),
        }
