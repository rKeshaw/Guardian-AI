from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from guardian.agents.reconnaissance_agent import ReconnaissanceAgent
from guardian.core.ai_client import estimate_tokens
from guardian.models.target_model import TargetModel


@dataclass
class FakeResponse:
    status: int = 200
    headers: dict[str, str] | None = None
    body: str = ""
    json_data: dict | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self, errors: str | None = None):
        return self.body

    async def json(self, content_type=None):
        if self.json_data is not None:
            return self.json_data
        return json.loads(self.body or "{}")


class FakeSession:
    def __init__(self, routes: dict[tuple[str, str], FakeResponse]):
        self.routes = routes

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, url, **kwargs):
        return self.routes.get(("GET", url), FakeResponse(status=404, body=""))

    def head(self, url, **kwargs):
        return self.routes.get(("HEAD", url), FakeResponse(status=404, body=""))


class FakeClientSessionFactory:
    def __init__(self, routes):
        self.routes = routes

    def __call__(self, *args, **kwargs):
        return FakeSession(self.routes)


def _base_routes(url: str) -> dict[tuple[str, str], FakeResponse]:
    return {
        ("GET", url): FakeResponse(status=200, headers={"server": "nginx"}, body="<html><body>ok</body></html>"),
        ("HEAD", f"{url}/swagger.json"): FakeResponse(status=404),
    }


@pytest.mark.anyio
async def test_waf_detected_from_header(monkeypatch):
    url = "https://example.com"
    routes = _base_routes(url)
    routes[("GET", url)] = FakeResponse(status=200, headers={"cf-ray": "abc123"}, body="home")

    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.ClientSession", FakeClientSessionFactory(routes))
    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.TCPConnector", lambda *a, **k: None)

    agent = ReconnaissanceAgent(db=None)
    model = await agent.run([url], {"crawl_depth": 0})

    assert model.waf_detected == "cloudflare"


@pytest.mark.anyio
async def test_technology_detected_from_body(monkeypatch):
    url = "https://example.com"
    routes = _base_routes(url)
    routes[("GET", url)] = FakeResponse(status=200, headers={"server": "nginx"}, body="<div>wp-content/themes</div>")

    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.ClientSession", FakeClientSessionFactory(routes))
    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.TCPConnector", lambda *a, **k: None)

    agent = ReconnaissanceAgent(db=None)
    model = await agent.run([url], {"crawl_depth": 0})

    assert "wordpress" in model.technologies


@pytest.mark.anyio
async def test_html_comment_extracted(monkeypatch):
    url = "https://example.com"
    html = "<html><body><!-- admin password: changeme123 --><a href='/x'>x</a></body></html>"
    routes = _base_routes(url)
    routes[("GET", url)] = FakeResponse(status=200, headers={"server": "nginx"}, body=html)
    routes[("GET", f"{url}/x")] = FakeResponse(status=200, headers={"server": "nginx"}, body="<html></html>")

    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.ClientSession", FakeClientSessionFactory(routes))
    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.TCPConnector", lambda *a, **k: None)

    agent = ReconnaissanceAgent(db=None)
    model = await agent.run([url], {"crawl_depth": 1})

    assert any("admin password: changeme123" in c for c in model.html_comments)


@pytest.mark.anyio
async def test_openapi_endpoints_extracted(monkeypatch):
    url = "https://example.com"
    spec = {"openapi": "3.0.0", "paths": {"/users/{id}": {"get": {"parameters": [{"name": "id"}]}}}}
    routes = _base_routes(url)
    routes[("HEAD", f"{url}/swagger.json")] = FakeResponse(status=200)
    routes[("GET", f"{url}/swagger.json")] = FakeResponse(status=200, json_data=spec)

    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.ClientSession", FakeClientSessionFactory(routes))
    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.TCPConnector", lambda *a, **k: None)

    agent = ReconnaissanceAgent(db=None)
    model = await agent.run([url], {"crawl_depth": 0})

    assert "/users/{id}" in model.api_endpoints


@pytest.mark.anyio
async def test_port_scan_failure_returns_empty(monkeypatch):
    url = "https://example.com"
    routes = _base_routes(url)

    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.ClientSession", FakeClientSessionFactory(routes))
    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.TCPConnector", lambda *a, **k: None)

    def boom(*args, **kwargs):
        raise RuntimeError("nmap unavailable")

    monkeypatch.setattr("guardian.agents.reconnaissance_agent.subprocess.run", boom)

    agent = ReconnaissanceAgent(db=None)
    model = await agent.run([url], {"crawl_depth": 0})

    assert model.open_ports == []


def test_to_hypothesis_context_token_limit():
    model = TargetModel(
        url="https://example.com",
        domain="example.com",
        technologies=[f"tech{i}" for i in range(50)],
        waf_detected=None,
        backend_language=None,
        database_hint=None,
        framework=None,
        injection_points=[{"url": "https://example.com/x", "method": "GET", "param_name": f"p{i}", "param_type": "query"} for i in range(100)],
        forms=[],
        api_endpoints=[f"/api/v1/{i}" for i in range(100)],
        html_comments=["comment " + ("x" * 500) for _ in range(50)],
        hardcoded_values=["secret" + str(i) for i in range(50)],
        interesting_paths=[f"/p/{i}" for i in range(50)],
        open_ports=[{"port": i, "service": "http", "banner": ""} for i in range(1, 101)],
        attack_surface_signals=["signal " + ("y" * 300) for _ in range(60)],
        page_classifications={},
    )

    ctx = model.to_hypothesis_context()
    assert estimate_tokens(json.dumps(ctx)) < 2000


@pytest.mark.anyio
async def test_js_fetch_endpoint_extracted(monkeypatch):
    url = "https://example.com"
    html = "<html><head><script src='/static/app.js'></script></head><body></body></html>"
    js = "const x = fetch('/api/v2/admin/users');"
    routes = _base_routes(url)
    routes[("GET", url)] = FakeResponse(status=200, headers={"server": "nginx"}, body=html)
    routes[("GET", f"{url}/static/app.js")] = FakeResponse(status=200, headers={}, body=js)

    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.ClientSession", FakeClientSessionFactory(routes))
    monkeypatch.setattr("guardian.agents.reconnaissance_agent.aiohttp.TCPConnector", lambda *a, **k: None)

    agent = ReconnaissanceAgent(db=None)
    model = await agent.run([url], {"crawl_depth": 0})

    assert "/api/v2/admin/users" in model.api_endpoints
