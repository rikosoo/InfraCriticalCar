import pytest

from capm.architecture import build_graph
from capm.controls import Portfolio, SCENARIOS
from capm.risk import ACTOR_PROFILES, SimulationConfig, simulate


@pytest.fixture(scope="module")
def graph():
    return build_graph()


def test_simulation_is_deterministic_for_a_seed(graph):
    cfg = SimulationConfig(trials=800, seed=7)
    a = simulate(graph, SCENARIOS["S0"], "S0", cfg)
    b = simulate(graph, SCENARIOS["S0"], "S0", cfg)
    assert a.ale == pytest.approx(b.ale)
    assert a.p_any_impact == pytest.approx(b.p_any_impact)


def test_probabilities_are_well_formed(graph):
    res = simulate(graph, SCENARIOS["S0"], "S0", SimulationConfig(trials=800))
    assert 0.0 <= res.p_any_impact <= 1.0
    assert 0.0 <= res.p_contained <= 1.0
    assert res.p_any_impact + res.p_contained <= 1.0 + 1e-9
    for value in res.p_impact.values():
        assert 0.0 <= value <= 1.0
    assert res.mean_loss >= 0.0 and res.ale >= 0.0


def test_full_programme_dominates_the_baseline(graph):
    cfg = SimulationConfig(trials=4000)
    base = simulate(graph, SCENARIOS["S0"], "S0", cfg)
    hardened = simulate(graph, SCENARIOS["S5"], "S5", cfg)
    assert hardened.ale < base.ale
    assert hardened.p_impact["imp_prod_stop"] < base.p_impact["imp_prod_stop"]


def test_ale_scales_linearly_with_campaign_frequency(graph):
    one = simulate(graph, SCENARIOS["S0"], "S0", SimulationConfig(trials=1500, frequency=1.0))
    two = simulate(graph, SCENARIOS["S0"], "S0", SimulationConfig(trials=1500, frequency=2.0))
    assert two.ale == pytest.approx(2.0 * one.ale, rel=1e-6)


def test_unknown_profile_is_rejected(graph):
    with pytest.raises(KeyError):
        simulate(graph, SCENARIOS["S0"], "S0", SimulationConfig(trials=10, profile="nope"))


def test_profiles_drive_different_consequences(graph):
    cfg_r = SimulationConfig(trials=4000, profile="ransomware")
    cfg_e = SimulationConfig(trials=4000, profile="espionage")
    r = simulate(graph, SCENARIOS["S0"], "S0", cfg_r)
    e = simulate(graph, SCENARIOS["S0"], "S0", cfg_e)
    assert r.p_impact["imp_prod_stop"] > e.p_impact["imp_prod_stop"]
    assert e.p_impact["imp_ip"] > r.p_impact["imp_ip"]
    assert set(ACTOR_PROFILES) == {"ransomware", "espionage", "sabotage"}


def test_recovery_controls_shorten_downtime(graph):
    cfg = SimulationConfig(trials=4000)
    without = simulate(graph, Portfolio(()), "none", cfg)
    with_backup = simulate(graph, Portfolio(("C08", "C17")), "recovery", cfg)
    assert with_backup.mean_downtime_h < without.mean_downtime_h


def test_simulation_is_reproducible_across_processes(graph):
    """Guards against set-iteration order leaking the per-process hash seed."""
    import json
    import subprocess
    import sys

    code = (
        "from capm.architecture import build_graph;"
        "from capm.controls import SCENARIOS;"
        "from capm.risk import simulate, SimulationConfig;"
        "import json;"
        "r=simulate(build_graph(), SCENARIOS['S0'], 'S0', SimulationConfig(trials=1500));"
        "print(json.dumps([r.ale, r.p_any_impact]))"
    )
    outs = []
    for seed in ("0", "12345"):
        env = {"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"}
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                              text=True, env=env, cwd=".")
        assert proc.returncode == 0, proc.stderr
        outs.append(json.loads(proc.stdout.strip().splitlines()[-1]))
    assert outs[0] == outs[1]
