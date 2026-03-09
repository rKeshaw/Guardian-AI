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

def test_allocate_sub_budget_total():
    ledger = TokenLedger(total=1000)
    sub = ledger.allocate_sub_budget(500, component="hypothesis_1")

    assert sub.total == 500


def test_sub_budget_charge_updates_parent():
    ledger = TokenLedger(total=5000)
    ledger.charge(1000, component="recon")
    sub = ledger.allocate_sub_budget(2000, component="hypothesis_1")

    assert sub.charge(500, component="turn_1") is True
    assert ledger.used == 1500


def test_sub_budget_exhaustion_blocks_charge_with_parent_remaining():
    ledger = TokenLedger(total=5000)
    sub = ledger.allocate_sub_budget(500, component="hypothesis_1")

    assert sub.charge(500, component="turn_1") is True
    assert sub.charge(1, component="turn_2") is False
    assert ledger.remaining() > 0


def test_sub_budget_release_returns_unused_to_parent():
    ledger = TokenLedger(total=10000)
    ledger.charge(1000, component="recon")
    sub = ledger.allocate_sub_budget(2000, component="hypothesis_1")

    assert sub.charge(500, component="turn_1") is True
    sub.release()

    assert ledger.used == 1000