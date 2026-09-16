import pytest

from capm.controls import CONTROLS, Portfolio, SCENARIOS, coverage_table
from capm.model import Edge


def test_control_catalogue_is_well_formed():
    for cid, c in CONTROLS.items():
        assert cid == c.id
        assert 0.0 <= c.m <= 1.0 and 0.0 <= c.u <= 1.0 and 0.0 <= c.recovery <= 1.0
        assert c.cost > 0
        assert c.iec62443 and c.csf


def test_portfolio_rejects_unknown_controls():
    with pytest.raises(KeyError):
        Portfolio(("C99",))


def test_combined_controls_compose_multiplicatively():
    edge = Edge("a", "b", "T1", 0.8, 0.1, 2.0, controls=("C01", "C12"))
    pf = Portfolio(("C01", "C12"))
    m, u = pf(edge)
    expected_m = 1 - (1 - CONTROLS["C01"].m) * (1 - CONTROLS["C12"].m)
    expected_u = 1 - (1 - CONTROLS["C01"].u) * (1 - CONTROLS["C12"].u)
    assert m == pytest.approx(expected_m)
    assert u == pytest.approx(expected_u)


def test_inapplicable_controls_have_no_effect():
    edge = Edge("a", "b", "T1", 0.8, 0.1, 2.0, controls=("C09",))
    assert Portfolio(("C01",))(edge) == (0.0, 0.0)


def test_recovery_factor_and_cost():
    pf = Portfolio(("C08", "C17"))
    expected = (1 - CONTROLS["C08"].recovery) * (1 - CONTROLS["C17"].recovery)
    assert pf.recovery_factor() == pytest.approx(expected)
    assert pf.cost() == CONTROLS["C08"].cost + CONTROLS["C17"].cost
    assert Portfolio(()).recovery_factor() == pytest.approx(1.0)


def test_scenarios_are_disjointly_defined_and_full_covers_all():
    assert set(SCENARIOS["S5"].active) == set(CONTROLS)
    assert SCENARIOS["S0"].active == ()
    for key in ("S1", "S2", "S3", "S4"):
        assert SCENARIOS[key].active


def test_standards_mapping_table_covers_every_control():
    assert len(coverage_table()) == len(CONTROLS)


def test_cli_subcommands_run(capsys):
    from capm.cli import main

    assert main(["graph"]) == 0
    assert main(["paths", "-k", "3"]) == 0
    assert main(["risk", "--trials", "200"]) == 0
    assert main(["corpus"]) == 0
    assert main(["controls"]) == 0
    out = capsys.readouterr().out
    assert "imp_prod_stop" in out or "Production stoppage" in out
