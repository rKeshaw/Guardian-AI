from guardian.core.probing.probe_executor import ProbeExecutor


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
