from aegis.agents.payload_agent import PayloadGenerationAgent
from aegis.agents.penetration_agent import PenetrationAgent
from aegis.agents.vulnerability_agent import VulnerabilityAnalysisAgent


def test_vulnerability_summary_supports_flat_recon_shape():
    agent = VulnerabilityAnalysisAgent(None)
    recon = {
        "targets_analyzed": 1,
        "reconnaissance_data": {
            "https://example.com": {
                "url": "https://example.com",
                "technologies": ["nginx", "php"],
                "open_ports": [{"port": 443, "service": "https"}, "80/http"],
                "forms": [{"inputs": [{"name": "q"}, {"name": "id"}]}],
                "api_endpoints": ["https://example.com/api/users"],
                "subdomains": [{"subdomain": "dev.example.com"}],
                "subdomain_takeover_risk": "Low Risk",
            }
        },
    }

    summary = agent._build_recon_summary(recon)

    assert summary["total_targets"] == 1
    target = summary["targets"][0]
    assert target["technologies"] == ["nginx", "php"]
    assert "443/https" in target["open_ports"]
    assert target["endpoint_count"] == 1
    assert target["form_count"] == 1


def test_payload_context_supports_flat_recon_shape():
    agent = PayloadGenerationAgent(None)
    recon = {
        "reconnaissance_data": {
            "https://example.com": {
                "technologies": ["django", "postgresql"],
                "open_ports": [{"port": 443, "service": "https"}],
                "forms": [{"action": "/search", "method": "GET", "inputs": [{"name": "q"}]}],
                "api_endpoints": ["https://example.com/api/search"],
            }
        }
    }

    out = agent._build_recon_context(recon)

    assert "https://example.com" in out
    assert out["https://example.com"]["technologies"] == ["django", "postgresql"]
    assert out["https://example.com"]["endpoints"] == ["https://example.com/api/search"]


def test_penetration_discovery_supports_flat_recon_shape():
    agent = PenetrationAgent(None)
    points = agent._discover_injection_points(
        "https://example.com",
        {
            "injection_points": [
                {
                    "url": "https://example.com/search",
                    "method": "GET",
                    "param_name": "q",
                    "param_type": "query",
                }
            ],
            "forms": [
                {
                    "action": "/login",
                    "method": "POST",
                    "inputs": [{"name": "username"}],
                }
            ],
            "api_endpoints": ["https://example.com/api/users/{id}"],
        },
    )

    keys = {(p.url, p.method, p.param_name) for p in points}
    assert ("https://example.com/search", "GET", "q") in keys
    assert ("https://example.com/login", "POST", "username") in keys
    assert ("https://example.com/api/users/", "GET", "id") in keys
