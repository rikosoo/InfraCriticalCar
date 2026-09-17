import math

import pytest

from capm.architecture import build_graph
from capm.evaluation import (build_baselines, format_interval, kendall_tau_b,
                             percentile_positions, score_ranking, wilcoxon_signed_rank,
                             wilson_interval)
from capm.incidents import load_incidents, realise
from capm.paths import enumerate_paths


def test_wilson_interval_matches_published_values():
    # 2 of 20: the normal approximation would run below zero, Wilson does not
    p, lo, hi = wilson_interval(2, 20)
    assert p == pytest.approx(0.10)
    assert lo == pytest.approx(0.0279, abs=5e-4)
    assert hi == pytest.approx(0.3010, abs=5e-4)
    # 11 of 20
    _, lo, hi = wilson_interval(11, 20)
    assert lo == pytest.approx(0.3421, abs=5e-4)
    assert hi == pytest.approx(0.7418, abs=5e-4)


def test_wilson_interval_is_bounded_and_ordered():
    for successes in range(0, 21):
        p, lo, hi = wilson_interval(successes, 20)
        assert 0.0 <= lo <= p <= hi <= 1.0


def test_wilson_interval_rejects_impossible_counts():
    with pytest.raises(ValueError):
        wilson_interval(5, 0)
    with pytest.raises(ValueError):
        wilson_interval(21, 20)


def test_format_interval_is_latex_safe():
    text = format_interval(8, 20)
    assert "40" in text and "CI" in text and "\\%" in text


def test_kendall_tau_known_values():
    assert kendall_tau_b([1, 2, 3, 4], [1, 2, 3, 4]) == pytest.approx(1.0)
    assert kendall_tau_b([1, 2, 3, 4], [4, 3, 2, 1]) == pytest.approx(-1.0)
    # two discordant pairs out of ten
    assert kendall_tau_b([1, 2, 3, 4, 5], [2, 1, 4, 3, 5]) == pytest.approx(0.6)


def test_kendall_tau_handles_ties():
    assert kendall_tau_b([1, 1, 2], [3, 3, 4]) == pytest.approx(1.0)
    with pytest.raises(ValueError):
        kendall_tau_b([1], [1])


def test_wilcoxon_identical_samples_is_not_significant():
    out = wilcoxon_signed_rank([1, 2, 3], [1, 2, 3])
    assert out["n"] == 0 and out["p_value"] == 1.0


def test_wilcoxon_is_symmetric_and_bounded():
    a = [5, 3, 8, 9, 2, 7, 6]
    b = [1, 4, 2, 3, 5, 1, 2]
    ab = wilcoxon_signed_rank(a, b)
    ba = wilcoxon_signed_rank(b, a)
    assert ab["p_value"] == pytest.approx(ba["p_value"])
    assert ab["effect"] == pytest.approx(-ba["effect"])
    assert 0.0 <= ab["p_value"] <= 1.0


def test_wilcoxon_detects_a_consistent_shift():
    a = list(range(1, 13))
    b = [x + 5 for x in a]
    out = wilcoxon_signed_rank(a, b)
    assert out["p_value"] < 0.001
    assert out["effect"] == pytest.approx(-1.0)


def test_wilcoxon_exact_distribution_small_case():
    # n = 3 with no ties: W+ can be 0..6, each of the 8 sign patterns equally
    # likely, so the smallest attainable two-sided p is 2/8
    out = wilcoxon_signed_rank([1.0, 2.0, 3.0], [0.0, 0.0, 0.0])
    assert out["p_value"] == pytest.approx(0.25)


def test_wilcoxon_rejects_unequal_lengths():
    with pytest.raises(ValueError):
        wilcoxon_signed_rank([1, 2], [1])


def test_baselines_are_distinct_orderings():
    graph = build_graph()
    paths = enumerate_paths(graph, "ext_actor", max_length=10)
    capm = [p.likelihood() for p in paths]
    for base in build_baselines(graph):
        scores = [base.score(p) for p in paths]
        assert len(scores) == len(paths)
        tau = kendall_tau_b(capm, scores)
        assert -1.0 <= tau <= 1.0
        assert not all(s == scores[0] for s in scores), f"{base.id} is constant"


def test_percentiles_are_within_range_and_capm_leads():
    graph = build_graph()
    paths = enumerate_paths(graph, "ext_actor", max_length=12)
    targets = [t for t in (realise(graph, i.node_path)[0] for i in load_incidents()) if t]
    capm_pct = percentile_positions(paths, [p.likelihood() for p in paths], targets)
    assert len(capm_pct) == len(targets)
    assert all(0.0 < v <= 100.0 for v in capm_pct)
    capm = score_ranking("CAPM", "CAPM", capm_pct)
    assert capm.in_top_25pct == len(targets)
    # the depth-first heuristic must do worse than CAPM on the corpus
    deep = next(b for b in build_baselines(graph) if b.id == "B3")
    deep_pct = percentile_positions(paths, [deep.score(p) for p in paths], targets)
    assert score_ranking("B3", "deep", deep_pct).median > capm.median


def test_score_ranking_handles_empty_input():
    empty = score_ranking("X", "none", [])
    assert math.isnan(empty.median) and empty.in_top_10pct == 0


# --- elicitation ---------------------------------------------------------

def test_elicitation_scales_and_parsing():
    from capm.elicitation import P_SCALE, parse_answer

    assert parse_answer("H", "p") == P_SCALE["H"]
    assert parse_answer(" vh ", "delta") == pytest.approx(0.80)
    assert parse_answer("0,45", "p") == pytest.approx(0.45)
    assert parse_answer("", "p") is None
    assert parse_answer("nonsense", "p") is None
    assert parse_answer("1.4", "p") is None          # out of range
    assert parse_answer("-3", "effort") is None      # not a duration
    assert parse_answer("36", "effort") == pytest.approx(36.0)


def test_elicitation_form_covers_the_graph_and_hides_current_values():
    from capm.architecture import build_graph as _build
    from capm.elicitation import FORM_HEADER, build_form

    graph = _build()
    rows = build_form(graph)
    assert len(rows) == len(graph.edges)
    assert len(rows[0]) == len(FORM_HEADER)
    current_p = FORM_HEADER.index("current_p")
    assert all(r[current_p] == "" for r in rows), "round 1 must not anchor the panel"
    shown = build_form(graph, show_current=True)
    assert all(r[current_p] != "" for r in shown)
    assert len(build_form(graph, limit=5)) == 5


def test_elicitation_aggregates_by_median_and_flags_disagreement():
    from capm.elicitation import aggregate

    agreeing = [{"step_id": "a|b|T1", "your_p": "H"},
                {"step_id": "a|b|T1", "your_p": "H"},
                {"step_id": "a|b|T1", "your_p": "M"}]
    split = [{"step_id": "a|b|T1", "your_p": "VL"},
             {"step_id": "a|b|T1", "your_p": "VH"},
             {"step_id": "a|b|T1", "your_p": "M"}]
    calm = aggregate(agreeing)["a|b|T1"]["p"]
    noisy = aggregate(split)["a|b|T1"]["p"]
    assert calm.median == pytest.approx(0.60)
    assert calm.n == 3 and not calm.disagreement
    assert noisy.median == pytest.approx(0.35)
    assert noisy.disagreement
    assert aggregate([{"your_p": "H"}]) == {}          # rows without a step are ignored


def test_overrides_round_trip_into_the_graph(tmp_path):
    from capm.architecture import build_graph as _build
    from capm.elicitation import aggregate, compare, load_overrides, write_overrides

    graph = _build()
    edge = graph.edges[0]
    sid = f"{edge.src}|{edge.dst}|{edge.technique}"
    estimates = aggregate([{"step_id": sid, "your_p": "VL", "your_delta": "VH",
                            "your_effort_h": "40"}])
    path = write_overrides(str(tmp_path / "over.csv"), estimates)
    overrides = load_overrides(path)
    assert overrides[edge.key]["p"] == pytest.approx(0.05)

    updated = _build(overrides)
    changed = next(e for e in updated.edges if e.key == edge.key)
    assert changed.p == pytest.approx(0.05)
    assert changed.delta == pytest.approx(0.80)
    assert changed.effort_h == pytest.approx(40.0)
    untouched = next(e for e in updated.edges if e.key == graph.edges[1].key)
    assert untouched.p == graph.edges[1].p
    assert updated.validate() == []

    shift = compare(graph, overrides)
    assert len(shift) == 1 and shift[0]["p_shift"] == pytest.approx(0.05 - edge.p)
