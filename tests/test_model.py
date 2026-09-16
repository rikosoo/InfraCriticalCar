import math

import pytest

from capm.architecture import build_graph
from capm.model import Asset, AttackGraph, Edge, Path, Zone


def test_zone_validation():
    with pytest.raises(ValueError):
        Zone("Z", "bad plane", 4, "quantum", 2)
    with pytest.raises(ValueError):
        Zone("Z", "bad purdue", 9, "it", 2)
    with pytest.raises(ValueError):
        Zone("Z", "bad sl", 4, "it", 7)


def test_edge_parameter_ranges():
    with pytest.raises(ValueError):
        Edge("a", "b", "T1", 0.0, 0.1, 1.0)
    with pytest.raises(ValueError):
        Edge("a", "b", "T1", 0.5, 1.0, 1.0)
    with pytest.raises(ValueError):
        Edge("a", "b", "T1", 0.5, 0.1, 0.0)


def test_effective_applies_controls_monotonically():
    e = Edge("a", "b", "T1", 0.6, 0.2, 4.0)
    p0, d0 = e.effective()
    p1, d1 = e.effective(mitigation=0.5, uplift=0.5)
    assert p0 == pytest.approx(0.6)
    assert d0 == pytest.approx(0.2)
    assert p1 < p0
    assert d1 > d0
    assert 0.0 < p1 <= 1.0 and 0.0 <= d1 < 1.0


def test_impact_nodes_are_terminal():
    g = build_graph()
    for impact in g.impacts:
        assert not g.out_edges(impact)


def test_graph_is_structurally_valid():
    g = build_graph()
    assert g.validate() == []
    assert g.summary()["edges"] == len(g.edges)


def test_path_likelihood_matches_product():
    g = build_graph()
    e1 = g.out_edges("ext_actor")[0]
    path = Path((e1,))
    assert path.likelihood() == pytest.approx(e1.p * (1 - e1.delta))
    assert path.length == 1
    assert path.nodes == (e1.src, e1.dst)


def test_every_edge_control_and_technique_is_defined():
    from capm.controls import CONTROLS

    g = build_graph()
    for e in g.edges:
        assert e.technique in g.techniques
        for c in e.controls:
            assert c in CONTROLS


def test_every_edge_evidence_id_exists_in_corpus():
    from capm.incidents import load_incidents

    known = {i.id for i in load_incidents()}
    for e in build_graph().edges:
        for ev in e.evidence:
            assert ev in known, f"{e.src}->{e.dst} cites unknown incident {ev}"
