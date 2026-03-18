from aegis.core.config import Settings


def test_default_model_prefers_reasoning_model(tmp_path):
    s = Settings(DATABASE_URL=f"sqlite:///{tmp_path / 'default.db'}")
    assert s.DEFAULT_MODEL == "deepseek-r1:32b"


def test_ollama_model_alias_overrides_default_model(tmp_path):
    s = Settings(
        DATABASE_URL=f"sqlite:///{tmp_path / 'alias.db'}",
        OLLAMA_MODEL="custom-model:latest",
    )
    assert s.DEFAULT_MODEL == "custom-model:latest"


def test_balanced_profile_enables_vuln_and_payload_only(tmp_path):
    s = Settings(
        DATABASE_URL=f"sqlite:///{tmp_path / 'aegis.db'}",
        SCAN_EXECUTION_PROFILE="balanced",
    )

    assert s.ENABLE_VULN_ANALYSIS_SEEDING is True
    assert s.ENABLE_PAYLOAD_GENERATION is True
    assert s.ENABLE_ACTIVE_PENETRATION is False
    assert s.ENABLE_ACTIVE_CONFIRMATION is False


def test_aggressive_profile_enables_active_stages(tmp_path):
    s = Settings(
        DATABASE_URL=f"sqlite:///{tmp_path / 'aegis2.db'}",
        SCAN_EXECUTION_PROFILE="aggressive",
    )

    assert s.ENABLE_VULN_ANALYSIS_SEEDING is True
    assert s.ENABLE_PAYLOAD_GENERATION is True
    assert s.ENABLE_ACTIVE_PENETRATION is True
    assert s.ENABLE_ACTIVE_CONFIRMATION is True
