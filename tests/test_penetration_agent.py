from guardian.agents.penetration_agent import Baseline, PenetrationAgent, TestResult as PentestResult


def test_differential_indicators_does_not_flag_admin_nav_text():
    agent = PenetrationAgent(None)
    baseline = Baseline(
        status_code=200,
        body_length=120,
        response_time_ms=120.0,
        present_indicators=set(),
    )
    test = PentestResult(
        status_code=200,
        response_time_ms=125.0,
        body_length=150,
        evidence={"response_snippet": "<nav><a href='/admin'>admin</a></nav>"},
    )

    indicators = agent._differential_indicators(test, baseline, "A01:2023")

    assert "admin" not in indicators


def test_differential_indicators_flags_specific_sql_syntax_error():
    agent = PenetrationAgent(None)
    baseline = Baseline(
        status_code=200,
        body_length=100,
        response_time_ms=110.0,
        present_indicators=set(),
    )
    test = PentestResult(
        status_code=200,
        response_time_ms=130.0,
        body_length=220,
        evidence={
            "response_snippet": "Warning: You have an error in your SQL syntax near '1'' at line 1"
        },
    )

    indicators = agent._differential_indicators(test, baseline, "A03:2023")

    assert any("you have an error in your sql syntax" in i.lower() for i in indicators)
