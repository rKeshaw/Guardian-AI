from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

if "guardian.core.probing" in sys.modules and not hasattr(sys.modules["guardian.core.probing"], "__path__"):
    module_path = Path(__file__).resolve().parents[1] / "guardian" / "core" / "probing" / "session_manager.py"
    spec = importlib.util.spec_from_file_location("session_manager_for_tests", module_path)
    _mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(_mod)
    SessionManager = _mod.SessionManager
else:
    from guardian.core.probing.session_manager import SessionManager


class _Resp:
    def __init__(self, body: str):
        self._body = body

    async def text(self, errors: str = "replace") -> str:
        return self._body


class _Ctx:
    def __init__(self, body: str):
        self._resp = _Resp(body)

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Session:
    def __init__(self, get_body: str = "", post_body: str = "") -> None:
        self.headers = {}
        self._get_body = get_body
        self._post_body = post_body

    def get(self, *args, **kwargs):
        return _Ctx(self._get_body)

    def post(self, *args, **kwargs):
        return _Ctx(self._post_body)


@pytest.mark.anyio
async def test_bearer_sets_header():
    sm = SessionManager()
    session = _Session()

    ok = await sm.authenticate({"type": "bearer", "bearer_token": "abc"}, session)

    assert ok is True
    assert session.headers["Authorization"] == "Bearer abc"


@pytest.mark.anyio
async def test_form_auth_posts_credentials():
    sm = SessionManager()
    login_page = (
        '<html><body><form action="/login" method="post">'
        '<input type="hidden" name="csrf" value="tok123"/>'
        '<input name="username"/><input name="password"/>'
        "</form></body></html>"
    )
    session = _Session(get_body=login_page, post_body="welcome dashboard")

    ok = await sm.authenticate(
        {
            "type": "form",
            "login_url": "https://example.test/auth",
            "credentials": {"username": "alice", "password": "secret"},
            "success_indicator": "dashboard",
        },
        session,
    )

    assert ok is True


@pytest.mark.anyio
async def test_form_auth_fails_without_indicator():
    sm = SessionManager()
    login_page = (
        '<html><body><form action="/login" method="post">'
        '<input type="hidden" name="csrf" value="tok123"/>'
        "</form></body></html>"
    )
    session = _Session(get_body=login_page, post_body="invalid credentials")

    ok = await sm.authenticate(
        {
            "type": "form",
            "login_url": "https://example.test/auth",
            "credentials": {"username": "alice", "password": "wrong"},
            "success_indicator": "dashboard",
        },
        session,
    )

    assert ok is False


@pytest.mark.anyio
async def test_none_returns_true():
    sm = SessionManager()
    session = _Session()

    ok = await sm.authenticate({"type": "none"}, session)

    assert ok is True


@pytest.mark.anyio
async def test_exception_returns_false():
    sm = SessionManager()

    class _BrokenSession(SimpleNamespace):
        def __init__(self):
            super().__init__(headers={})

        def get(self, *args, **kwargs):
            raise RuntimeError("boom")

    session = _BrokenSession()

    ok = await sm.authenticate(
        {
            "type": "form",
            "login_url": "https://example.test/auth",
            "credentials": {"username": "alice", "password": "secret"},
            "success_indicator": "dashboard",
        },
        session,
    )

    assert ok is False
