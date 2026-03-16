from aegis.core.config import Settings


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
