import pytest

from capm.architecture import build_graph
from capm.controls import Portfolio, SCENARIOS
from capm.paths import (choke_points, enumerate_paths, k_best_paths, purdue_depth,
                        rank_paths, zone_transitions)


@pytest.fixture(scope="module")
def graph():
    return build_graph()


def test_best_path_is_the_global_optimum(graph):
    best = k_best_paths(graph, "ext_actor", "imp_prod_stop", 1)[0]
    brute = max((p for p in enumerate_paths(graph, "ext_actor", ["imp_prod_stop"], max_length=12)),
                key=lambda p: p.likelihood())
    assert best.likelihood() == pytest.approx(brute.likelihood(), rel=1e-9)


def test_k_best_paths_are_distinct_ordered_and_loop_free(graph):
    paths = k_best_paths(graph, "ext_actor", "imp_prod_stop", 12)
    assert len(paths) == 12
    likelihoods = [p.likelihood() for p in paths]
    assert all(a >= b - 1e-12 for a, b in zip(likelihoods, likelihoods[1:]))
    assert len({p.nodes for p in paths}) == len(paths)
    for p in paths:
        assert len(set(p.nodes)) == len(p.nodes)


def test_controls_never_increase_path_likelihood(graph):
    paths = k_best_paths(graph, "ext_actor", "imp_prod_stop", 8)
    hardened = SCENARIOS["S5"]
    for p in paths:
        assert p.likelihood(hardened) <= p.likelihood() + 1e-12


def test_adding_a_control_is_monotone(graph):
    path = k_best_paths(graph, "ext_actor", "imp_prod_stop", 1)[0]
    small = Portfolio(("C14",))
    bigger = small.with_control("C17")
    assert path.likelihood(bigger) <= path.likelihood(small) + 1e-12


def test_enumeration_respects_length_bound_and_terminality(graph):
    paths = enumerate_paths(graph, "ext_actor", max_length=6)
    assert paths
    for p in paths:
        assert p.length <= 6
        assert graph.assets[p.target].is_impact
        for node in p.nodes[:-1]:
            assert not graph.assets[node].is_impact


def test_choke_point_shares_are_bounded(graph):
    scored = rank_paths(enumerate_paths(graph, "ext_actor", max_length=10))
    nodes, edges = choke_points(scored, graph)
    assert nodes and edges
    for _, share, count in nodes:
        assert 0.0 <= share <= 1.0 and count >= 1
    assert all(n[0] != "ext_actor" for n in nodes)


def test_metrics_helpers(graph):
    path = k_best_paths(graph, "ext_actor", "imp_prod_stop", 1)[0]
    assert 0 <= zone_transitions(path, graph) <= path.length
    assert 0 <= purdue_depth(path, graph) <= 5
