from guardian.core.memory.semantic_unit import SemanticUnit


def test_entropy_empty_string():
    unit = SemanticUnit.from_raw("", "test")
    assert unit.entropy == 0.0


def test_entropy_high_for_code():
    raw = "SELECT * FROM users WHERE id=1; <script>alert(1)</script> ../../etc/passwd UNION%20SELECT%201,2,3" * 2
    unit = SemanticUnit.from_raw(raw[:200], "test")
    assert unit.entropy > 0.6


def test_entropy_low_for_repetition():
    unit = SemanticUnit.from_raw("a" * 200, "test")
    assert unit.entropy < 0.2


def test_token_count_approximation():
    unit = SemanticUnit.from_raw("x" * 400, "test")
    assert unit.token_count == 100


def test_compression_ratio_when_not_compressed():
    unit = SemanticUnit.from_raw("hello world", "test")
    assert unit.compression_ratio == 1.0


def test_compression_ratio_when_compressed():
    unit = SemanticUnit.from_raw("short", "test")
    unit.compressed_from = "x" * 100
    assert unit.compression_ratio < 0.1


def test_prompt_repr_facts_first():
    unit = SemanticUnit.from_raw("summary text", "test")
    unit.irreducible_facts = ["mysql_error: ...", "unix_path: /etc"]

    rendered = unit.prompt_repr()

    assert rendered.find("mysql_error: ...") < rendered.find("summary text")
    assert rendered.find("unix_path: /etc") < rendered.find("summary text")


def test_is_high_entropy():
    high = SemanticUnit.from_raw("high", "test")
    high.entropy = 0.8
    low = SemanticUnit.from_raw("low", "test")
    low.entropy = 0.4

    assert high.is_high_entropy is True
    assert low.is_high_entropy is False
