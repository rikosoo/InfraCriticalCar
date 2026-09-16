import pytest

from capm.architecture import build_graph
from capm.incidents import (analyse_corpus, leave_one_out_report, load_incidents, realise)


@pytest.fixture(scope="module")
def graph():
    return build_graph()


def test_corpus_loads_and_is_well_formed(graph):
    incidents = load_incidents()
    assert len(incidents) >= 20
    for inc in incidents:
        assert inc.sources, f"{inc.id} has no source"
        assert 2015 <= inc.year <= 2026
        assert inc.primary_impact in graph.impacts
        assert inc.confidence in {"high", "medium", "low", "disputed", "attempted", "partial"}
        for node in inc.node_path:
            assert node in graph.assets, f"{inc.id} references unknown asset {node}"
        assert inc.node_path[0] in graph.entry_points


def test_every_reconstruction_is_a_model_path(graph):
    for inc in load_incidents():
        path, err = realise(graph, inc.node_path)
        assert path is not None, f"{inc.id}: {err}"
        assert path.target == inc.primary_impact
        assert 0.0 < path.likelihood() <= 1.0


def test_corpus_report_statistics(graph):
    report = analyse_corpus(graph)
    assert report.coverage == pytest.approx(1.0)
    assert 0.0 <= report.supply_chain_share <= 1.0
    assert 0.0 <= report.availability_share <= 1.0
    assert report.per_impact["imp_prod_stop"] >= 10


def test_leave_one_out_ablation_reports_fractions():
    report = leave_one_out_report()
    assert 0.0 <= report["score"] <= 1.0
    assert 0.0 <= report["score_internal"] <= 1.0
    assert report["score_internal"] >= report["score"]
    assert report["total"] == len(load_incidents())


def test_unknown_node_is_reported_not_raised(graph):
    path, err = realise(graph, ("ext_actor", "does_not_exist"))
    assert path is None and "unknown asset" in err
