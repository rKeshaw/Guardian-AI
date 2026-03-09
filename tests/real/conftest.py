from __future__ import annotations

import os
import re
import socket
from typing import AsyncGenerator

import aiohttp
import pytest

from guardian.core.config import settings
from guardian.core.database import Database

import pytest

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

_DVWA_USER = "admin"
_DVWA_PASS = "password"


def _is_reachable(url: str, timeout_s: float = 3.0) -> bool:
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not host:
            return False
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except Exception:
        return False



async def dvwa_login(base_url: str) -> dict:
    """
    Returns dict with keys: phpsessid, security
    suitable for use as cookies= in aiohttp requests
    and as Cookie header value in Guardian scan config.
    """
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # 1) Login page (get token)
        async with session.get(f"{base_url}/login.php") as resp:
            html = await resp.text(errors="replace")
        m = re.search(r'name="user_token"\s+value="([^"]+)"', html)
        if not m:
            raise RuntimeError("Could not extract DVWA login user_token")
        login_token = m.group(1)

        # 2) Submit credentials
        payload = {
            "username": _DVWA_USER,
            "password": _DVWA_PASS,
            "Login": "Login",
            "user_token": login_token,
        }
        async with session.post(f"{base_url}/login.php", data=payload, allow_redirects=True) as resp:
            body = await resp.text(errors="replace")
        if "Login failed" in body:
            raise RuntimeError("DVWA login failed with configured credentials")

        # 3) Set security low (csrf aware)
        async with session.get(f"{base_url}/security.php") as resp:
            sec_html = await resp.text(errors="replace")
        m2 = re.search(r'name="user_token"\s+value="([^"]+)"', sec_html)
        if not m2:
            raise RuntimeError("Could not extract DVWA security user_token")

        sec_payload = {
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": m2.group(1),
        }
        async with session.post(f"{base_url}/security.php", data=sec_payload, allow_redirects=True) as _:
            pass

        cookies = {c.key: c.value for c in session.cookie_jar}
        phpsessid = cookies.get("PHPSESSID")
        if not phpsessid:
            raise RuntimeError("DVWA login did not produce PHPSESSID cookie")

        return {"PHPSESSID": phpsessid, "security": "low"}




@pytest.fixture(scope="session", autouse=True)
def _ensure_dvwa_reachable(dvwa_base_url: str):
    if not _is_reachable(dvwa_base_url):
        pytest.skip(f"DVWA not reachable at {dvwa_base_url}")

@pytest.fixture(scope="session")
def dvwa_base_url() -> str:
    return os.getenv("DVWA_BASE_URL", "http://guardian-dvwa:80")


@pytest.fixture(scope="session")
def ollama_base_url() -> str:
    return os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")


@pytest.fixture(scope="session")
async def dvwa_cookies(dvwa_base_url: str) -> dict:
    try:
        return await dvwa_login(dvwa_base_url)
    except Exception as exc:
        pytest.fail(f"DVWA login bootstrap failed: {exc}")


@pytest.fixture(scope="session", autouse=True)
def guardian_settings(ollama_base_url: str):
    settings.OLLAMA_BASE_URL = ollama_base_url
    # settings.OLLAMA_MODEL = "mistral:latest"
    settings.DEFAULT_MODEL = "mistral:latest"
    # settings.OLLAMA_MODEL_FAST = "mistral:latest"
    settings.DATABASE_URL = "sqlite:////tmp/guardian_test.db"
    settings.VERIFY_SSL = False
    # settings.MAX_GRAPH_TOKENS = 10000
    # settings.ENABLE_ACTIVE_CONFIRMATION = True
    # settings.ENABLE_VULN_ANALYSIS_SEEDING = True
    # settings.PROBE_DELAY_MIN = 0.0
    # settings.PROBE_DELAY_MAX = 0.1

    # settings.MAX_CONCURRENT_SCANS = 3
    # settings.ENABLE_PAYLOAD_GENERATION = True
    # settings.ENABLE_ACTIVE_PENETRATION = True

    # Ensure probe delay settings are what ProbeExecutor should consume.
    # if settings.PROBE_DELAY_MIN != 0.0 or settings.PROBE_DELAY_MAX != 0.1:
    #     settings.PROBE_DELAY_MIN = 0.0
    #     settings.PROBE_DELAY_MAX = 0.1

    return settings


@pytest.fixture(scope="session")
async def test_db(guardian_settings) -> AsyncGenerator[Database, None]:
    db = Database()
    await db.initialize()

    import aiosqlite

    async with aiosqlite.connect(db.db_path) as conn:
        for table in [
            "scan_sessions",
            "agent_results",
            "agent_tasks",
            "agent_errors",
            "graph_nodes",
            "graph_edges",
            "graph_meta",
        ]:
            await conn.execute(f"DELETE FROM {table}")
        await conn.commit()

    yield db


@pytest.fixture(scope="function")
def dvwa_sqli_url(dvwa_base_url: str) -> str:
    return f"{dvwa_base_url}/vulnerabilities/sqli/"


@pytest.fixture(scope="function")
def dvwa_xss_url(dvwa_base_url: str) -> str:
    return f"{dvwa_base_url}/vulnerabilities/xss_r/"


@pytest.fixture(scope="function")
def dvwa_exec_url(dvwa_base_url: str) -> str:
    return f"{dvwa_base_url}/vulnerabilities/exec/"


@pytest.fixture(scope="function")
def dvwa_fi_url(dvwa_base_url: str) -> str:
    return f"{dvwa_base_url}/vulnerabilities/fi/"


@pytest.fixture(scope="function")
def scan_auth_config(dvwa_base_url: str, dvwa_cookies: dict) -> dict:
    cookie_header = "; ".join([f"{k}={v}" for k, v in dvwa_cookies.items()])
    return {
        "type": "form",
        "login_url": f"{dvwa_base_url}/login.php",
        "credentials": {"username": "admin", "password": "password"},
        "username_field": "username",
        "password_field": "password",
        "submit_field": "Login",
        "extra_cookies": {"security": "low"},
        "cookies": dvwa_cookies,
        "cookie_header": cookie_header,
    }


def pytest_collection_modifyitems(config, items):
    ollama_ok = _is_reachable(os.getenv("OLLAMA_BASE_URL", "http://ollama:11434"))
    if ollama_ok:
        return

    skip_llm = pytest.mark.skip(reason=f"Ollama not reachable at {os.getenv('OLLAMA_BASE_URL', 'http://ollama:11434')}")
    for item in items:
        if "real_llm" in item.keywords or "integration" in item.keywords:
            item.add_marker(skip_llm)
