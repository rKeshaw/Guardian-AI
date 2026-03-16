from aegis.agents.penetration_agent import Baseline, PenetrationAgent, TestResult as PentestResult


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

def test_discover_injection_points_extracts_path_template_param():
    agent = PenetrationAgent(None)
    points = agent._discover_injection_points(
        "https://example.com",
        {
            "web_applications": {
                "endpoints": ["https://example.com/api/users/{id}"],
                "forms": [],
            }
        },
    )

    assert any(p.param_name == "id" and p.method == "GET" for p in points)


def test_build_evidence_package_contains_manifest_and_hash():
    agent = PenetrationAgent(None)
    results = {
        "penetration_results": {
            "https://example.com": {
                "successful_exploits": [
                    {
                        "vulnerability": "SQL Injection",
                        "owasp_category": "A03:2023",
                        "successful_payload": "' OR '1'='1",
                        "impact_level": "High",
                    }
                ]
            }
        }
    }

    evidence = agent._build_evidence_package(results)

    assert evidence["total_successful_exploits"] == 1
    assert evidence["overall_risk"] in {"Medium", "High", "Critical"}
    assert evidence["schema_version"] == "1.1"
    assert len(evidence["exploit_manifest"]) == 1
    assert len(evidence["evidence_hash_sha256"]) == 64