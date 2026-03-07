from guardian.core.token_ledger import TokenLedger


def test_charge_within_budget():
    ledger = TokenLedger(total=1000)
    assert ledger.charge(300) is True
    assert ledger.remaining() == 700


def test_charge_exhausts_budget():
    ledger = TokenLedger(total=100)
    assert ledger.charge(90) is True
    assert ledger.charge(20) is False
    assert ledger.remaining() == 10


def test_utilization_calculation():
    ledger = TokenLedger(total=1000)
    ledger.charge(750)
    assert ledger.utilization() == 0.75


def test_is_critical_threshold():
    ledger = TokenLedger(total=1000)
    ledger.charge(910)
    assert ledger.is_critical() is True

    fresh = TokenLedger(total=1000)
    assert fresh.is_critical() is False


def test_snapshot_by_component():
    ledger = TokenLedger(total=1000)
    ledger.charge(100, component="recon")
    ledger.charge(200, component="comprehender")

    assert ledger.snapshot()["by_component"] == {"recon": 100, "comprehender": 200}
