from guardian.core.intelligence.comprehender import Comprehender


def _facts(comp):
    return comp.get("irreducible_facts", []) if isinstance(comp, dict) else getattr(comp, "irreducible_facts", [])


def _content(comp):
    return comp.get("content", "") if isinstance(comp, dict) else getattr(comp, "content", "")


def test_mysql_error_extracted():
    comprehender = Comprehender()
    out = comprehender.compress("You have an error in your SQL syntax near '1'' at line 1", "injection_response")
    facts = _facts(out)
    assert any("mysql_error" in f for f in facts)


def test_uid_output_extracted():
    comprehender = Comprehender()
    out = comprehender.compress("uid=0(root) gid=0(root) groups=0(root)", "injection_response")
    facts = _facts(out)
    assert any("uid_output" in f for f in facts)


def test_unix_path_extracted():
    comprehender = Comprehender()
    out = comprehender.compress("Fatal error in /var/www/html/index.php on line 42", "injection_response")
    facts = _facts(out)
    assert any("unix_path" in f for f in facts)
    assert any("/var/www/html/index.php" in f for f in facts)


def test_reflection_detected():
    comprehender = Comprehender()
    probe = "<script>alert(1)</script>"
    out = comprehender.compress(f"Results for: {probe}", "injection_response", probe_sent=probe)
    facts = _facts(out)
    assert any("reflection" in f for f in facts)


def test_html_boilerplate_stripped():
    comprehender = Comprehender()
    html = (
        "<html><body><nav>menu</nav>"
        + ("A" * 2600)
        + "<div>Invalid query</div>"
        + ("B" * 300)
        + "<footer>foot</footer></body></html>"
    )
    out = comprehender.compress(html, "injection_response")
    content = _content(out)
    assert len(content) < 500
    assert "Invalid query" in content


def test_jwt_token_extracted():
    comprehender = Comprehender()
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123"
    out = comprehender.compress(f"Authorization token leaked: {token}", "injection_response")
    facts = _facts(out)
    assert any("jwt_token" in f for f in facts)


def test_normalize_probe_url_encoding():
    comprehender = Comprehender()
    assert comprehender._normalize_probe("' OR 1%3D1--") == comprehender._normalize_probe("' OR 1=1--")


def test_normalize_probe_case_insensitive():
    comprehender = Comprehender()
    assert comprehender._normalize_probe("' OR 1=1--") == comprehender._normalize_probe("' or 1=1--")


def test_near_duplicate_sync_exact():
    comprehender = Comprehender()
    tried = {comprehender._normalize_probe("' OR 1=1--")}
    candidate = comprehender._normalize_probe("' OR 1=1--")
    assert candidate in tried
