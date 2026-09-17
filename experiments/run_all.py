#!/usr/bin/env python3
"""Reproducible experiment pipeline for the paper.

    python3 experiments/run_all.py [--quick]

Writes CSV tables, LaTeX tables, SVG figures and ``summary.json`` into
``experiments/results/``. Every number quoted in the paper comes from this file.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
from typing import Dict, List, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capm.architecture import build_graph
from capm.controls import CONTROLS, Portfolio, SCENARIOS, coverage_table
from capm.incidents import analyse_corpus, leave_one_out_report, load_incidents, realise
from capm.model import Edge, Path
from capm.paths import (choke_points, enumerate_paths, k_best_paths, purdue_depth,
                        rank_paths, zone_transitions)
from capm.evaluation import (build_baselines, kendall_tau_b, percentile_positions,
                             score_ranking, wilcoxon_signed_rank, wilson_interval)
from capm.report import (barh_chart, ensure_dir, grouped_bar_chart, line_chart,
                         write_csv)
from capm.risk import ACTOR_PROFILES, SimulationConfig, simulate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "experiments", "results")
TAB = os.path.join(RES, "tables")
FIG = os.path.join(RES, "figures")

SUMMARY: Dict[str, object] = {}


def short(node_id: str, graph) -> str:
    return graph.assets[node_id].name if node_id in graph.assets else node_id


def path_str(path: Path, graph) -> str:
    return " -> ".join(short(n, graph) for n in path.nodes)


# ==========================================================================
# E1 -- structure of the attack surface
# ==========================================================================

def e1_structure(graph) -> None:
    print("[E1] graph structure and path enumeration")
    summary = graph.summary()
    all_paths = enumerate_paths(graph, "ext_actor", max_length=12)
    scored = rank_paths(all_paths)
    lengths: Dict[int, int] = {}
    depth_hist: Dict[int, int] = {}
    per_impact: Dict[str, int] = {}
    ot_paths = 0
    for p in all_paths:
        lengths[p.length] = lengths.get(p.length, 0) + 1
        d = purdue_depth(p, graph)
        depth_hist[d] = depth_hist.get(d, 0) + 1
        per_impact[p.target] = per_impact.get(p.target, 0) + 1
        if d <= 2:
            ot_paths += 1

    prod = [(p, w) for p, w in scored if p.target == "imp_prod_stop"]
    prod_ot = [(p, w) for p, w in prod if purdue_depth(p, graph) <= 2]
    top = prod[:15]

    write_csv(os.path.join(TAB, "e1_top_paths_production.csv"),
              ["rank", "likelihood", "steps", "zone_transitions", "lowest_purdue_level",
               "effort_h", "techniques", "path"],
              [(i + 1, f"{w:.5f}", p.length, zone_transitions(p, graph), purdue_depth(p, graph),
                f"{p.effort_h():.0f}", " ".join(p.techniques), path_str(p, graph))
               for i, (p, w) in enumerate(top)])

    barh_chart(os.path.join(FIG, "f1_top_paths.svg"),
               [f"{i+1}. " + " > ".join(n.split("_")[0] + ":" + n.split("_", 1)[1][:11]
                                        for n in p.nodes[1:]) for i, (p, _) in enumerate(top[:10])],
               [w for _, w in top[:10]],
               "Ten most likely paths to production stoppage (baseline $S_0$)",
               xlabel="path likelihood L(pi)", value_fmt="{:.3f}", left=380)

    # technique frequency across the ranked paths, weighted by likelihood
    tech_mass: Dict[str, float] = {}
    for p, w in scored:
        for t in set(p.techniques):
            tech_mass[t] = tech_mass.get(t, 0.0) + w
    total_mass = sum(w for _, w in scored) or 1.0
    tech_rank = sorted(((t, m / total_mass) for t, m in tech_mass.items()), key=lambda x: -x[1])[:15]
    write_csv(os.path.join(TAB, "e1_technique_mass.csv"),
              ["technique", "name", "matrix", "tactic", "likelihood_share"],
              [(t, graph.techniques[t].name, graph.techniques[t].matrix,
                graph.techniques[t].tactic, f"{m:.4f}") for t, m in tech_rank])
    barh_chart(os.path.join(FIG, "f2_technique_mass.svg"),
               [f"{t} {graph.techniques[t].name[:34]}" for t, _ in tech_rank],
               [m for _, m in tech_rank],
               "ATT&CK techniques by share of total path likelihood",
               xlabel="share of aggregate path likelihood", value_fmt="{:.2f}", left=360)

    SUMMARY["E1"] = {
        "graph": summary,
        "paths_total": len(all_paths),
        "paths_per_impact": per_impact,
        "paths_reaching_level2_or_below": ot_paths,
        "share_paths_reaching_level2_or_below": ot_paths / float(len(all_paths)),
        "length_histogram": dict(sorted(lengths.items())),
        "purdue_depth_histogram": dict(sorted(depth_hist.items())),
        "production_paths": len(prod),
        "production_paths_via_ot": len(prod_ot),
        "best_production_likelihood": prod[0][1] if prod else 0.0,
        "best_production_path": path_str(prod[0][0], graph) if prod else "",
        "best_ot_production_likelihood": prod_ot[0][1] if prod_ot else 0.0,
        "best_ot_production_path": path_str(prod_ot[0][0], graph) if prod_ot else "",
        "likelihood_ratio_it_over_ot": (prod[0][1] / prod_ot[0][1]) if prod_ot else float("nan"),
        "top_techniques": [{"id": t, "share": round(m, 4)} for t, m in tech_rank],
    }


# ==========================================================================
# E2 -- empirical corpus
# ==========================================================================

def e2_corpus(graph) -> None:
    print("[E2] incident corpus reconciliation")
    incidents = load_incidents()
    report = analyse_corpus(graph, incidents)
    loo = leave_one_out_report(incidents)

    all_paths = enumerate_paths(graph, "ext_actor", max_length=12)
    scored = rank_paths(all_paths)
    order = {p.nodes: i for i, (p, _) in enumerate(scored)}

    rows: List[Sequence[object]] = []
    percentiles: List[float] = []
    for inc in incidents:
        path, err = realise(graph, inc.node_path)
        if path is None:
            rows.append((inc.id, inc.year, inc.victim, inc.primary_impact, inc.confidence,
                         "not representable", "", err))
            continue
        same_target = [i for i, (p, _) in enumerate(scored) if p.target == path.target]
        rank = order.get(path.nodes)
        pct = ""
        if rank is not None and same_target:
            position = sum(1 for i in same_target if i < rank) + 1
            pct_val = 100.0 * position / len(same_target)
            percentiles.append(pct_val)
            pct = f"{pct_val:.1f}"
        rows.append((inc.id, inc.year, inc.victim, inc.primary_impact, inc.confidence,
                     f"{path.likelihood():.5f}", pct, path_str(path, graph)))

    write_csv(os.path.join(TAB, "e2_corpus_paths.csv"),
              ["id", "year", "victim", "impact", "confidence", "likelihood",
               "percentile_among_model_paths", "reconstructed_path"], rows)

    years = sorted(report.per_year)
    line_chart(os.path.join(FIG, "f3_corpus_timeline.svg"),
               [("incidents in corpus", [(float(y), float(report.per_year[y])) for y in years])],
               "Automotive manufacturing incidents in the corpus, by year",
               xlabel="year", ylabel="incidents", x_fmt="{:.0f}", y_fmt="{:.0f}")
    planes = ["it", "identity", "cloud", "ot", "supply_chain"]
    grouped_bar_chart(os.path.join(FIG, "f4_corpus_planes.svg"), planes,
                      [("incidents traversing the plane",
                        [float(report.per_plane.get(p, 0)) for p in planes])],
                      "Planes traversed by the 20 corpus incidents",
                      ylabel="incidents", value_fmt="{:.0f}")

    n = report.total
    intervals = {
        "availability": wilson_interval(report.per_impact.get("imp_prod_stop", 0), n),
        "supply_chain": wilson_interval(
            sum(1 for i in incidents if i.is_supply_chain), n),
        "ot_interaction": wilson_interval(
            int(round(report.ot_interaction_share * n)), n),
    }
    write_csv(os.path.join(TAB, "e2_corpus_proportions.csv"),
              ["proportion", "successes", "n", "estimate", "ci_low", "ci_high"],
              [(k, int(round(v[0] * n)), n, f"{v[0]:.3f}", f"{v[1]:.3f}", f"{v[2]:.3f}")
               for k, v in intervals.items()])

    SUMMARY["E2"] = {
        "corpus_size": report.total,
        "wilson_intervals": {k: {"estimate": round(v[0], 4), "ci_low": round(v[1], 4),
                                 "ci_high": round(v[2], 4)} for k, v in intervals.items()},
        "representable": report.representable,
        "coverage": report.coverage,
        "gaps": report.gaps,
        "per_plane": report.per_plane,
        "per_impact": report.per_impact,
        "per_role": report.per_role,
        "per_year": report.per_year,
        "supply_chain_share": report.supply_chain_share,
        "availability_share": report.availability_share,
        "ot_interaction_share": report.ot_interaction_share,
        "leave_one_out": loo,
        "median_percentile": sorted(percentiles)[len(percentiles) // 2] if percentiles else None,
        "mean_percentile": (sum(percentiles) / len(percentiles)) if percentiles else None,
        "percentile_below_25": sum(1 for p in percentiles if p <= 25.0),
        "percentile_count": len(percentiles),
    }


# ==========================================================================
# E3 -- choke points
# ==========================================================================

def e3_chokepoints(graph) -> None:
    print("[E3] choke-point and conduit criticality")
    all_paths = enumerate_paths(graph, "ext_actor", max_length=12)
    scored = rank_paths(all_paths)
    nodes, edges = choke_points(scored, graph)
    node_rows = [(n, graph.assets[n].name, graph.assets[n].zone,
                  graph.purdue_of(n), f"{share:.4f}", count) for n, share, count in nodes[:15]]
    write_csv(os.path.join(TAB, "e3_node_criticality.csv"),
              ["asset", "name", "zone", "purdue", "likelihood_share", "paths"], node_rows)
    barh_chart(os.path.join(FIG, "f5_chokepoints.svg"),
               [f"{graph.assets[n].name[:36]} ({graph.assets[n].zone})" for n, _, _ in nodes[:12]],
               [s for _, s, _ in nodes[:12]],
               "Choke points by share of aggregate path likelihood",
               xlabel="share of likelihood mass", value_fmt="{:.2f}", left=400)

    edge_rows = [(k[0], k[1], k[2], graph.techniques[k[2]].name, f"{share:.4f}", count)
                 for k, share, count in edges[:15]]
    write_csv(os.path.join(TAB, "e3_conduit_criticality.csv"),
              ["src", "dst", "technique", "technique_name", "likelihood_share", "paths"], edge_rows)
    SUMMARY["E3"] = {
        "top_nodes": [{"asset": n, "name": graph.assets[n].name, "zone": graph.assets[n].zone,
                       "share": round(s, 4)} for n, s, _ in nodes[:12]],
        "top_conduits": [{"src": k[0], "dst": k[1], "technique": k[2], "share": round(s, 4)}
                         for k, s, _ in edges[:12]],
    }


# ==========================================================================
# E4 -- scenario risk
# ==========================================================================

def e4_scenarios(graph, trials: int) -> None:
    print("[E4] scenario risk quantification")
    rows: List[Sequence[object]] = []
    per_profile: Dict[str, Dict[str, object]] = {}
    for profile in ACTOR_PROFILES:
        cfg = SimulationConfig(trials=trials, profile=profile)
        results = {}
        for key in ("S0", "S1", "S2", "S3", "S4", "S5"):
            pf = SCENARIOS[key]
            res = simulate(graph, pf, pf.name, cfg)
            results[key] = res
            rows.append((profile, key, pf.name, f"{res.p_any_impact:.4f}",
                         f"{res.p_impact.get('imp_prod_stop', 0):.4f}",
                         f"{res.p_impact.get('imp_ip', 0):.4f}",
                         f"{res.p_impact.get('imp_safety', 0):.4f}",
                         f"{res.mean_downtime_h:.1f}", f"{res.mean_loss:.2f}",
                         f"{res.mean_loss_given_impact:.2f}", f"{res.ale:.2f}",
                         f"{pf.cost():.0f}"))
        per_profile[profile] = {k: v.as_row() for k, v in results.items()}
        if profile == "ransomware":
            base = results["S0"].ale
            SUMMARY["E4_baseline_ale"] = base
            SUMMARY["E4_reduction"] = {k: round(100.0 * (base - v.ale) / base, 1)
                                       for k, v in results.items()}
    write_csv(os.path.join(TAB, "e4_scenarios.csv"),
              ["profile", "scenario", "name", "p_impact", "p_production_stop", "p_ip_theft",
               "p_safety", "mean_downtime_h", "mean_loss_musd", "mean_loss_given_impact_musd",
               "ale_musd", "control_cost_index"], rows)
    ransom = [r for r in rows if r[0] == "ransomware"]
    scen_names = ["S0", "S1", "S2", "S3", "S4", "S5"]
    grouped_bar_chart(
        os.path.join(FIG, "f6_scenario_ale.svg"), scen_names,
        [(p, [float(per_profile[p][s]["ale_musd"]) for s in scen_names]) for p in ACTOR_PROFILES],
        "Annualised loss expectancy by scenario and actor profile",
        ylabel="ALE (million USD / plant-year)", value_fmt="{:.0f}")
    SUMMARY["E4"] = per_profile


# ==========================================================================
# E5 -- control cost-effectiveness
# ==========================================================================

def e5_controls(graph, trials: int) -> None:
    print("[E5] marginal control value and greedy portfolio")
    cfg = SimulationConfig(trials=trials, profile="ransomware")
    base = simulate(graph, SCENARIOS["S0"], "S0", cfg)
    full = SCENARIOS["S5"]
    full_res = simulate(graph, full, full.name, cfg)
    base_best = max((p.likelihood() for p in
                     k_best_paths(graph, "ext_actor", "imp_prod_stop", 1)), default=0.0)
    rows: List[Sequence[object]] = []
    marg: List[Tuple[str, float, float]] = []
    necessity: List[Tuple[str, float]] = []
    for cid in sorted(CONTROLS):
        pf = Portfolio((cid,), name=f"S0+{cid}")
        res = simulate(graph, pf, pf.name, cfg)
        delta = base.ale - res.ale
        # path-level effect: how much the single control slows the best route
        best_with = max((p.likelihood(pf) for p in
                         k_best_paths(graph, "ext_actor", "imp_prod_stop", 1, pf)), default=0.0)
        path_drop = 100.0 * (1.0 - best_with / base_best) if base_best else 0.0
        # necessity: ALE increase when the control is removed from the full programme
        without = full.without_control(cid)
        res_wo = simulate(graph, without, without.name, cfg)
        need = res_wo.ale - full_res.ale
        necessity.append((cid, need))
        rows.append((cid, CONTROLS[cid].name, f"{CONTROLS[cid].cost:.0f}", f"{res.ale:.2f}",
                     f"{delta:.2f}", f"{100.0 * delta / base.ale:.1f}",
                     f"{delta / CONTROLS[cid].cost:.2f}", f"{path_drop:.1f}", f"{need:.2f}",
                     "; ".join(CONTROLS[cid].iec62443), "; ".join(CONTROLS[cid].csf)))
        marg.append((cid, delta, delta / CONTROLS[cid].cost))
    write_csv(os.path.join(TAB, "e5_marginal_controls.csv"),
              ["control", "name", "cost_index", "ale_musd", "ale_reduction_musd",
               "ale_reduction_pct", "reduction_per_cost", "best_path_likelihood_drop_pct",
               "necessity_ale_increase_if_removed_musd", "iec62443_3_3", "nist_csf_2_0"], rows)
    nec_sorted = sorted(necessity, key=lambda t: -t[1])
    barh_chart(os.path.join(FIG, "f11_control_necessity.svg"),
               [f"{c} {CONTROLS[c].name[:38]}" for c, _ in nec_sorted[:12]],
               [max(v, 0.0) for _, v in nec_sorted[:12]],
               "Necessity: ALE increase when a control is removed from the full programme",
               xlabel="ALE increase (million USD / plant-year)", value_fmt="{:.1f}", left=420)
    marg_sorted = sorted(marg, key=lambda t: -t[1])
    barh_chart(os.path.join(FIG, "f7_marginal_controls.svg"),
               [f"{c} {CONTROLS[c].name[:38]}" for c, _, _ in marg_sorted[:12]],
               [d for _, d, _ in marg_sorted[:12]],
               "Marginal ALE reduction of a single control (ransomware profile)",
               xlabel="ALE reduction (million USD / plant-year)", value_fmt="{:.1f}", left=420)
    barh_chart(os.path.join(FIG, "f8_control_efficiency.svg"),
               [f"{c} {CONTROLS[c].name[:38]}" for c, _, _ in sorted(marg, key=lambda t: -t[2])[:12]],
               [r for _, _, r in sorted(marg, key=lambda t: -t[2])[:12]],
               "Cost-effectiveness: ALE reduction per unit of control cost",
               xlabel="ALE reduction per cost index point", value_fmt="{:.2f}", left=420)

    # greedy portfolio construction
    greedy_rows: List[Sequence[object]] = []
    curves: Dict[str, List[Tuple[float, float]]] = {}
    for profile in ACTOR_PROFILES:
        pcfg = SimulationConfig(trials=trials, profile=profile)
        pf = Portfolio((), name="greedy")
        cur = simulate(graph, pf, pf.name, pcfg)
        curve = [(0.0, cur.ale)]
        chosen: List[str] = []
        for step in range(6):
            best = None
            for cid in sorted(CONTROLS):
                if cid in pf.active:
                    continue
                cand = pf.with_control(cid)
                res = simulate(graph, cand, cand.name, pcfg)
                gain = cur.ale - res.ale
                eff = gain / CONTROLS[cid].cost
                if best is None or eff > best[2]:
                    best = (cid, gain, eff, res)
            if best is None or best[1] <= 0:
                break
            cid, gain, eff, res = best
            pf = pf.with_control(cid)
            chosen.append(cid)
            cur = res
            greedy_rows.append((profile, step + 1, cid, CONTROLS[cid].name,
                                f"{CONTROLS[cid].cost:.0f}", f"{res.ale:.2f}", f"{gain:.2f}",
                                f"{eff:.2f}", f"{pf.cost():.0f}"))
            curve.append((pf.cost(), res.ale))
        curves[profile] = curve
        if profile == "ransomware":
            SUMMARY["E5_greedy_ransomware"] = chosen
    write_csv(os.path.join(TAB, "e5_greedy_portfolio.csv"),
              ["profile", "step", "control", "name", "cost_index", "ale_after_musd",
               "ale_gain_musd", "gain_per_cost", "cumulative_cost"], greedy_rows)
    line_chart(os.path.join(FIG, "f9_greedy_curve.svg"),
               [(p, curves[p]) for p in curves],
               "Efficient frontier: ALE against cumulative control cost",
               xlabel="cumulative control cost index", ylabel="ALE (million USD / plant-year)",
               x_fmt="{:.0f}", y_fmt="{:.0f}")
    SUMMARY["E5"] = {
        "baseline_ale": base.ale,
        "full_programme_ale": full_res.ale,
        "necessity": [{"control": c, "delta_ale_if_removed": round(v, 3)} for c, v in nec_sorted],
        "marginal": [{"control": c, "delta_ale": round(d, 3), "per_cost": round(r, 3)}
                     for c, d, r in marg_sorted],
        "greedy": [list(r) for r in greedy_rows],
    }


# ==========================================================================
# E6 -- sensitivity and robustness
# ==========================================================================

def e6_sensitivity(graph, trials: int) -> None:
    print("[E6] sensitivity and robustness")
    # (a) ranking stability under parameter perturbation
    rng = random.Random(4242)
    baseline_top = [p.nodes for p, _ in
                    rank_paths(enumerate_paths(graph, "ext_actor", max_length=12))
                    if p.target == "imp_prod_stop"][:10]
    overlaps: List[float] = []
    top1_stable = 0
    replicates = 200
    for _ in range(replicates):
        perturbed = build_graph()
        new_edges: List[Edge] = []
        for e in perturbed.edges:
            fp = min(0.999, max(0.001, e.p * math.exp(rng.gauss(0.0, 0.35))))
            fd = min(0.95, max(0.0, e.delta * math.exp(rng.gauss(0.0, 0.35))))
            new_edges.append(Edge(e.src, e.dst, e.technique, fp, fd, e.effort_h,
                                  e.controls, e.rationale, e.evidence))
        perturbed.edges = new_edges
        top = [p.nodes for p, _ in
               rank_paths(enumerate_paths(perturbed, "ext_actor", max_length=12))
               if p.target == "imp_prod_stop"][:10]
        overlaps.append(len(set(top) & set(baseline_top)) / 10.0)
        if top and top[0] == baseline_top[0]:
            top1_stable += 1
    mean_overlap = sum(overlaps) / len(overlaps)

    # (b) one-at-a-time sweeps on the risk model
    sweeps: Dict[str, List[Tuple[float, float]]] = {}
    rows: List[Sequence[object]] = []
    for factor in (0.5, 0.75, 1.0, 1.25, 1.5):
        g2 = build_graph()
        g2.edges = [Edge(e.src, e.dst, e.technique, e.p,
                         min(0.95, e.delta * factor), e.effort_h, e.controls,
                         e.rationale, e.evidence) for e in g2.edges]
        res = simulate(g2, SCENARIOS["S0"], "S0", SimulationConfig(trials=trials))
        sweeps.setdefault("detection efficacy x", []).append((factor, res.ale))
        rows.append(("detection_multiplier", factor, f"{res.ale:.2f}", f"{res.p_any_impact:.4f}"))
    for lam in (0.5, 1.0, 1.5, 2.5, 4.0):
        res = simulate(graph, SCENARIOS["S0"], "S0",
                       SimulationConfig(trials=trials, frequency=lam))
        sweeps.setdefault("campaign frequency /yr", []).append((lam, res.ale))
        rows.append(("campaign_frequency", lam, f"{res.ale:.2f}", f"{res.p_any_impact:.4f}"))
    for budget in (168.0, 360.0, 720.0, 1440.0):
        res = simulate(graph, SCENARIOS["S0"], "S0",
                       SimulationConfig(trials=trials, budget_h=budget))
        rows.append(("attacker_budget_h", budget, f"{res.ale:.2f}", f"{res.p_any_impact:.4f}"))
    write_csv(os.path.join(TAB, "e6_sensitivity.csv"),
              ["parameter", "value", "ale_musd", "p_impact"], rows)
    line_chart(os.path.join(FIG, "f10_sensitivity.svg"),
               [(k, v) for k, v in sweeps.items()],
               "One-at-a-time sensitivity of the annualised loss expectancy",
               xlabel="parameter multiplier or value", ylabel="ALE (million USD / plant-year)",
               x_fmt="{:.2f}", y_fmt="{:.0f}")

    # (c) stability of the control ranking under perturbation
    cfg = SimulationConfig(trials=max(trials // 2, 2000))
    base = simulate(graph, SCENARIOS["S0"], "S0", cfg)
    ranks: Dict[str, List[int]] = {c: [] for c in CONTROLS}
    for rep in range(12):
        rng2 = random.Random(1000 + rep)
        g3 = build_graph()
        g3.edges = [Edge(e.src, e.dst, e.technique,
                         min(0.999, max(0.001, e.p * math.exp(rng2.gauss(0.0, 0.3)))),
                         min(0.95, max(0.0, e.delta * math.exp(rng2.gauss(0.0, 0.3)))),
                         e.effort_h, e.controls, e.rationale, e.evidence) for e in g3.edges]
        b = simulate(g3, SCENARIOS["S0"], "S0", cfg)
        scores = []
        for cid in sorted(CONTROLS):
            r = simulate(g3, Portfolio((cid,)), cid, cfg)
            scores.append((cid, (b.ale - r.ale) / CONTROLS[cid].cost))
        scores.sort(key=lambda t: -t[1])
        for pos, (cid, _) in enumerate(scores):
            ranks[cid].append(pos + 1)
    rank_rows = sorted((((sum(v) / len(v)) if v else 99), c) for c, v in ranks.items())
    write_csv(os.path.join(TAB, "e6_control_rank_stability.csv"),
              ["control", "name", "mean_rank", "best_rank", "worst_rank"],
              [(c, CONTROLS[c].name, f"{m:.1f}", min(ranks[c]), max(ranks[c]))
               for m, c in rank_rows])
    SUMMARY["E6"] = {
        "replicates": replicates,
        "mean_top10_overlap": mean_overlap,
        "top1_stability": top1_stable / float(replicates),
        "sweeps": {k: [[a, round(b, 3)] for a, b in v] for k, v in sweeps.items()},
        "baseline_ale_check": base.ale,
        "control_rank_stability": [{"control": c, "mean_rank": round(m, 2),
                                    "best": min(ranks[c]), "worst": max(ranks[c])}
                                   for m, c in rank_rows],
    }


# ==========================================================================
# E7 -- comparison against baseline prioritisations
# ==========================================================================

def e7_baselines(graph) -> None:
    print("[E7] comparison against baseline prioritisations")
    all_paths = enumerate_paths(graph, "ext_actor", max_length=12)
    incidents = load_incidents()
    targets: List[Path] = []
    for inc in incidents:
        path, _ = realise(graph, inc.node_path)
        if path is not None:
            targets.append(path)

    capm_scores = [p.likelihood() for p in all_paths]
    capm_pct = percentile_positions(all_paths, capm_scores, targets)
    capm = score_ranking("CAPM", "CAPM path likelihood", capm_pct)

    rows: List[Sequence[object]] = [
        (capm.id, capm.name, f"{capm.median:.1f}", f"{capm.mean:.1f}",
         capm.in_top_10pct, capm.in_top_25pct, "", "", "")
    ]
    results = [capm]
    for base in build_baselines(graph):
        scores = [base.score(p) for p in all_paths]
        pct = percentile_positions(all_paths, scores, targets)
        scored = score_ranking(base.id, base.name, pct)
        scored.kendall_vs_capm = kendall_tau_b(capm_scores, scores)
        scored.wilcoxon_vs_capm = wilcoxon_signed_rank(capm_pct, pct)
        results.append(scored)
        w = scored.wilcoxon_vs_capm
        rows.append((base.id, base.name, f"{scored.median:.1f}", f"{scored.mean:.1f}",
                     scored.in_top_10pct, scored.in_top_25pct,
                     f"{scored.kendall_vs_capm:+.2f}",
                     f"{w['p_value']:.4f}", f"{w['effect']:+.2f}"))
    write_csv(os.path.join(TAB, "e7_baselines.csv"),
              ["ranking", "name", "median_percentile", "mean_percentile",
               "incidents_in_top_10pct", "incidents_in_top_25pct",
               "kendall_tau_vs_capm", "wilcoxon_p_vs_capm", "rank_biserial_effect"],
              rows)
    barh_chart(os.path.join(FIG, "f12_baselines.svg"),
               [f"{r.id} {r.name}" for r in results],
               [r.median for r in results],
               "Median percentile of the corpus incidents under each ranking (lower is better)",
               xlabel="median percentile among paths to the same consequence",
               value_fmt="{:.1f}", left=320)
    SUMMARY["E7"] = {
        "corpus_paths_scored": len(targets),
        "rankings": [
            {"id": r.id, "name": r.name, "median_percentile": round(r.median, 2),
             "mean_percentile": round(r.mean, 2), "in_top_10pct": r.in_top_10pct,
             "in_top_25pct": r.in_top_25pct,
             "kendall_vs_capm": (round(r.kendall_vs_capm, 4)
                                 if r.kendall_vs_capm is not None else None),
             "wilcoxon_p_vs_capm": (round(r.wilcoxon_vs_capm["p_value"], 5)
                                    if r.wilcoxon_vs_capm else None),
             "rank_biserial_effect": (round(r.wilcoxon_vs_capm["effect"], 4)
                                      if r.wilcoxon_vs_capm else None)}
            for r in results],
    }


# ==========================================================================
# Standards mapping table
# ==========================================================================

def standards_table() -> None:
    rows = coverage_table()
    write_csv(os.path.join(TAB, "controls_standards_mapping.csv"),
              ["control", "name", "cost_index", "iec62443_3_3", "nist_csf_2_0"], rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="fewer Monte Carlo trials")
    args = ap.parse_args()
    trials = 4000 if args.quick else 20000
    t0 = time.time()
    for d in (RES, TAB, FIG):
        ensure_dir(d)
    graph = build_graph()
    e1_structure(graph)
    e2_corpus(graph)
    e3_chokepoints(graph)
    e4_scenarios(graph, trials)
    e5_controls(graph, trials)
    e6_sensitivity(graph, trials)
    e7_baselines(graph)
    standards_table()
    SUMMARY["meta"] = {
        "trials": trials,
        "generated_s": round(time.time() - t0, 1),
        "python": sys.version.split()[0],
    }
    with open(os.path.join(RES, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(SUMMARY, fh, indent=2, sort_keys=False)
    # The paper's own tables and figures are rendered separately, in every
    # supported language, by experiments/build_paper_assets.py; this step only
    # produces results. Keeping the two apart means a typesetting change never
    # requires re-running ten minutes of Monte Carlo.
    print(f"done in {time.time() - t0:.1f}s -> {RES}")


if __name__ == "__main__":
    main()
