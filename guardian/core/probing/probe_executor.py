"""
guardian/core/probing/probe_executor.py
"""

import asyncio
import logging
import random
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from guardian.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class InjectionPoint:
    url: str
    method: str
    param_name: str
    param_type: str
    context_hint: str = ""
    other_params: dict = field(default_factory=dict)


@dataclass
class ProbeResult:
    status_code: int
    body: str
    headers: dict
    response_time_ms: float
    url_sent: str
    method: str
    param_injected: str
    probe_value: str
    error: str | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def _build_ssl_context():
    if not settings.VERIFY_SSL:
        return False
    return ssl.create_default_context()


class ProbeExecutor:
    def __init__(self, session: aiohttp.ClientSession, baseline_cache=None):
        self._session = session
        self._baseline_cache: dict[str, ProbeResult] = baseline_cache or {}

    @classmethod
    async def create(cls, auth_headers=None, auth_cookies=None, cookies=None) -> "ProbeExecutor":
        ssl_ctx = _build_ssl_context()
        connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=10, limit_per_host=4)
        headers = {
            "User-Agent": random.choice(settings.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if auth_headers:
            headers.update(auth_headers)
        session = aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=25, connect=8),
        )
        combined_cookies = {}
        if auth_cookies:
            combined_cookies.update(auth_cookies)
        if cookies:
            combined_cookies.update(cookies)
        if combined_cookies:
            session.cookie_jar.update_cookies(combined_cookies)
        return cls(session)

    async def close(self):
        close_fn = getattr(self._session, "close", None)
        if close_fn is None:
            return
        out = close_fn()
        if asyncio.iscoroutine(out):
            await out

    @classmethod
    def build_injection_point(cls, data: dict) -> InjectionPoint:
        raw = data or {}

        url = str(raw.get("url", "")).strip()
        if not url:
            raise ValueError("InjectionPoint.url is required")

        param_name = str(raw.get("param_name", "")).strip()
        if not param_name:
            raise ValueError("InjectionPoint.param_name is required")

        method = str(raw.get("method", "GET")).upper().strip() or "GET"
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
        if method not in allowed_methods:
            logger.warning("Invalid injection point method '%s'; defaulting to GET", method)
            method = "GET"

        param_type = str(raw.get("param_type", "query")).lower().strip() or "query"
        allowed_param_types = {"query", "form", "json", "header", "cookie"}
        if param_type not in allowed_param_types:
            logger.warning("Invalid injection point param_type '%s'; defaulting to query", param_type)
            param_type = "query"

        other_params = raw.get("other_params", {})
        if not isinstance(other_params, dict):
            other_params = {}

        return InjectionPoint(
            url=url,
            method=method,
            param_name=param_name,
            param_type=param_type,
            context_hint=str(raw.get("context_hint", "")),
            other_params=other_params,
        )


    @staticmethod
    def _generate_baseline_probe(param_name: str, param_type: str) -> str:
        rand = uuid.uuid4().hex[:8]
        safe_rand = ''.join(ch for ch in rand if ch.isalnum())

        if param_type == "header":
            quality_digit = next((ch for ch in safe_rand if ch.isdigit()), "9")
            return f"en-US,en;q=0.{quality_digit}"

        if param_type in {"form", "json"}:
            digits = ''.join(ch for ch in safe_rand if ch.isdigit())[:4].ljust(4, "0")
            return f"John{digits}"

        # Default query/cookie style: 8-12 safe alphanumeric chars
        return safe_rand[:10]

    async def capture_baseline(self, point: InjectionPoint) -> ProbeResult:
        cache_key = f"{point.method}:{point.url}:{point.param_name}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]
        benign_value = self._generate_baseline_probe(point.param_name, point.param_type)
        result = await self.fire(point, benign_value)
        self._baseline_cache[cache_key] = result
        return result

    def get_baseline(self, point: InjectionPoint) -> ProbeResult | None:
        cache_key = f"{point.method}:{point.url}:{point.param_name}"
        return self._baseline_cache.get(cache_key)

    async def fire(self, point: InjectionPoint, probe_value: str) -> ProbeResult:
        delay = random.uniform(settings.PROBE_DELAY_MIN, settings.PROBE_DELAY_MAX)
        await asyncio.sleep(delay)
        self._session.headers.update({"User-Agent": random.choice(settings.USER_AGENTS)})
        t0 = time.monotonic()
        try:
            result = await self._execute(point, probe_value)
        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            return ProbeResult(
                status_code=0, body="", headers={},
                response_time_ms=elapsed, url_sent=point.url,
                method=point.method, param_injected=point.param_name,
                probe_value=probe_value, error=str(exc),
            )
        result.response_time_ms = (time.monotonic() - t0) * 1000
        return result

    async def _execute(self, point: InjectionPoint, probe_value: str) -> ProbeResult:
        method = point.method.upper()
        if point.param_type == "json":
            payload = dict(point.other_params)
            payload[point.param_name] = probe_value
            async with self._session.request(method, point.url, json=payload) as resp:
                body = await resp.text(errors="replace")
                return self._make_result(resp, body, point, probe_value)
        elif point.param_type == "header":
            headers = {point.param_name: probe_value}
            async with self._session.request(method, point.url, headers=headers) as resp:
                body = await resp.text(errors="replace")
                return self._make_result(resp, body, point, probe_value)
        elif point.param_type == "cookie":
            cookies = {point.param_name: probe_value}
            async with self._session.request(method, point.url, cookies=cookies) as resp:
                body = await resp.text(errors="replace")
                return self._make_result(resp, body, point, probe_value)
        elif method == "POST":
            data = dict(point.other_params)
            data[point.param_name] = probe_value
            async with self._session.post(point.url, data=data) as resp:
                body = await resp.text(errors="replace")
                return self._make_result(resp, body, point, probe_value)
        else:
            params = dict(point.other_params)
            params[point.param_name] = probe_value
            async with self._session.get(point.url, params=params) as resp:
                body = await resp.text(errors="replace")
                return self._make_result(resp, body, point, probe_value)

    @staticmethod
    def _make_result(resp, body, point, probe_value) -> ProbeResult:
        return ProbeResult(
            status_code=resp.status,
            body=body,
            headers={k.lower(): v for k, v in resp.headers.items()},
            response_time_ms=0.0,
            url_sent=str(resp.url),
            method=point.method,
            param_injected=point.param_name,
            probe_value=probe_value,
        )

    @staticmethod
    def compute_delta(current: "ProbeResult", baseline: "ProbeResult | None") -> dict[str, Any]:
        if baseline is None:
            return {
                "status_code": current.status_code,
                "body_length": len(current.body),
                "response_time_ms": round(current.response_time_ms, 1),
                "status_changed": False,
                "length_delta": 0,
                "time_delta_ms": 0,
                "new_content": current.body[:2000],
                "new_headers": {},
            }
        import difflib
        baseline_lines = baseline.body.splitlines()
        current_lines = current.body.splitlines()
        diff = difflib.unified_diff(baseline_lines, current_lines, lineterm="")
        additions = [l[1:] for l in diff if l.startswith("+") and not l.startswith("+++")]
        new_content = "\n".join(additions)[:2000]
        new_headers = {
            k: v for k, v in current.headers.items()
            if k not in baseline.headers or baseline.headers[k] != v
        }
        return {
            "status_code": current.status_code,
            "status_changed": current.status_code != baseline.status_code,
            "baseline_status": baseline.status_code,
            "body_length": len(current.body),
            "length_delta": len(current.body) - len(baseline.body),
            "length_ratio": len(current.body) / max(len(baseline.body), 1),
            "response_time_ms": round(current.response_time_ms, 1),
            "time_delta_ms": round(current.response_time_ms - baseline.response_time_ms, 1),
            "new_content": new_content,
            "new_headers": new_headers,
        }