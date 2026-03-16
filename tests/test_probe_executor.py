from aegis.core.probing.probe_executor import ProbeExecutor, InjectionPoint
import pytest

def test_generate_baseline_probe_unique_values():
    probes = [ProbeExecutor._generate_baseline_probe("q", "query") for _ in range(5)]
    assert len(set(probes)) == 5


def test_generate_baseline_probe_no_sql_keywords():
    sql_keywords = ["SELECT", "UNION", "OR ", "AND ", "DROP"]
    probes = [ProbeExecutor._generate_baseline_probe("name", "form") for _ in range(5)]
    for probe in probes:
        upper = probe.upper()
        for keyword in sql_keywords:
            assert keyword not in upper

class _Resp:
    status = 200
    headers = {}
    url = "https://example.com"

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self, errors="replace"):
        return "ok"


class _Session:
    def __init__(self):
        self.called = {}

    def request(self, method, url, **kwargs):
        self.called = {"method": method, "url": url, **kwargs}
        return _Resp()


@pytest.mark.anyio
async def test_execute_cookie_param_uses_cookies_kwarg():
    session = _Session()
    executor = ProbeExecutor(session)
    point = InjectionPoint(
        url="https://example.com/profile",
        method="GET",
        param_name="sessionid",
        param_type="cookie",
        context_hint="cookie test",
        other_params={},
    )

    await executor._execute(point, "abc123")

    assert session.called.get("cookies") == {"sessionid": "abc123"}
    assert "params" not in session.called
    assert "data" not in session.called