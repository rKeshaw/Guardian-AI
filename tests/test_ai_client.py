from __future__ import annotations

from types import SimpleNamespace

import pytest

from guardian.core.ai_client import AIClient, AIPersona


@pytest.mark.anyio
async def test_query_ai_calls_chat_with_top_level_json_format(monkeypatch):
    captured: dict = {}

    def _chat(**kwargs):
        captured.update(kwargs)
        return {"message": {"content": '{"ok": true}'}}

    client = AIClient()
    monkeypatch.setattr(client, "_get_client", lambda: SimpleNamespace(chat=_chat))

    out = await client.query_ai("return json", persona=AIPersona.VULNERABILITY_EXPERT)

    assert out == '{"ok": true}'
    assert captured.get("format") == "json"
    assert "options" in captured
    assert "format" not in captured["options"]


@pytest.mark.anyio
async def test_query_ai_options_include_persona_runtime_params_without_format(monkeypatch):
    captured: dict = {}

    def _chat(**kwargs):
        captured.update(kwargs)
        return {"message": {"content": '{"status": "ok"}'}}

    client = AIClient()
    monkeypatch.setattr(client, "_get_client", lambda: SimpleNamespace(chat=_chat))

    await client.query_ai("return json", persona=AIPersona.PAYLOAD_GENERATOR)

    options = captured.get("options", {})
    assert "temperature" in options
    assert "top_p" in options
    assert "format" not in options
