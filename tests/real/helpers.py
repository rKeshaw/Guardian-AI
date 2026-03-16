from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Callable, Awaitable

import aiohttp

_TIMING_FILE = Path("/tmp/aegis_test_timing.log")


def log_timing(test_name: str, agent_name: str, elapsed_seconds: float) -> None:
    _TIMING_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _TIMING_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{test_name},{agent_name},{elapsed_seconds:.3f}\n")


async def timed_call(test_name: str, agent_name: str, fn: Callable[[], Awaitable[Any]]) -> Any:
    t0 = time.monotonic()
    out = await fn()
    log_timing(test_name, agent_name, time.monotonic() - t0)
    return out


async def with_llm_retry(coro_factory: Callable[[], Awaitable[Any]], assertion_fn: Callable[[Any], None], retries: int = 3):
    for attempt in range(retries):
        result = await coro_factory()
        try:
            assertion_fn(result)
            return result
        except AssertionError:
            if attempt == retries - 1:
                raise


def assert_valid_injection_points(points: list) -> None:
    assert isinstance(points, list) and points
    assert any(
        isinstance(p, dict)
        and str(p.get("url", "")).strip()
        and str(p.get("param_name", "")).strip()
        and str(p.get("param_type", "")).strip()
        for p in points
    )


def assert_valid_hypotheses(hypotheses: list) -> None:
    assert isinstance(hypotheses, list) and hypotheses
    for h in hypotheses:
        if hasattr(h, "data"):
            data = h.data
            description = data.get("hypothesis", "")
            entry_probe = data.get("entry_probe", "")
            target_url = (data.get("injection_point") or {}).get("url", "")
            confidence = float(getattr(h, "confidence", 0.0))
            owasp = str(data.get("owasp_category", ""))
        else:
            description = h.get("description", "")
            entry_probe = h.get("entry_probe", "")
            target_url = h.get("target_url", "")
            confidence = float(h.get("confidence", 0.0))
            owasp = str(h.get("owasp_category", ""))

        assert isinstance(description, str) and description
        assert isinstance(entry_probe, str) and entry_probe
        assert isinstance(target_url, str) and target_url
        assert 0.0 <= confidence <= 1.0
        assert owasp.upper().startswith("A0") or owasp.upper().startswith("A")


def assert_valid_graph_result(graph_result: dict) -> None:
    nodes = graph_result.get("nodes", [])
    assert isinstance(nodes, list) and nodes
    node_types = {str(n.get("type", "")).upper() for n in nodes if isinstance(n, dict)}
    assert any(t in node_types for t in {"FINDING", "HYPOTHESIS"})
    assert any(t != "DEAD_END" for t in node_types)


def assert_finding_references_vuln_type(findings: list, vuln_keywords: list[str]) -> None:
    lowered = [k.lower() for k in vuln_keywords]
    joined = []
    for f in findings:
        if isinstance(f, dict):
            joined.append((str(f.get("description", "")) + " " + str(f.get("evidence", "")) + " " + str(f)).lower())
        else:
            joined.append(str(f).lower())
    assert any(any(k in s for k in lowered) for s in joined)


def assert_json_parseable(text: str) -> dict:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    parsed = json.loads(cleaned)
    assert isinstance(parsed, dict)
    return parsed


async def dvwa_confirm_sqli(session: aiohttp.ClientSession, base_url: str) -> bool:
    p_true = "1' AND '1'='1"
    p_false = "1' AND '1'='2"
    async with session.get(f"{base_url}/vulnerabilities/sqli/", params={"id": p_true, "Submit": "Submit"}) as r1:
        b1 = await r1.text(errors="replace")
    async with session.get(f"{base_url}/vulnerabilities/sqli/", params={"id": p_false, "Submit": "Submit"}) as r2:
        b2 = await r2.text(errors="replace")
    return ("First name" in b1) and ("First name" not in b2 or len(b2) < len(b1))


async def dvwa_confirm_xss(session: aiohttp.ClientSession, base_url: str) -> bool:
    payload = "<script>alert(1)</script>"
    async with session.get(f"{base_url}/vulnerabilities/xss_r/", params={"name": payload}) as r:
        body = await r.text(errors="replace")
    return payload in body


async def dvwa_confirm_cmdi(session: aiohttp.ClientSession, base_url: str) -> bool:
    payload = "127.0.0.1;id"
    async with session.post(f"{base_url}/vulnerabilities/exec/", data={"ip": payload, "Submit": "Submit"}) as r:
        body = await r.text(errors="replace")
    return "uid=" in body
