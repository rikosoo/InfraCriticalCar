"""Command-line interface for exploring the model.

    python3 -m capm.cli graph
    python3 -m capm.cli paths --target imp_prod_stop -k 10 --scenario S0
    python3 -m capm.cli chokepoints
    python3 -m capm.cli risk --scenario S4 --profile ransomware --trials 20000
    python3 -m capm.cli corpus
"""

from __future__ import annotations

import argparse
import json
from typing import List

from .architecture import build_graph
from .controls import CONTROLS, Portfolio, SCENARIOS
from .incidents import analyse_corpus, leave_one_out_report, load_incidents, realise
from .paths import choke_points, enumerate_paths, k_best_paths, purdue_depth, rank_paths
from .risk import ACTOR_PROFILES, SimulationConfig, simulate


def _portfolio(name: str) -> Portfolio:
    if name in SCENARIOS:
        return SCENARIOS[name]
    controls = tuple(c.strip() for c in name.split(",") if c.strip())
    return Portfolio(controls, name=name)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="capm", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("graph", help="print the structure of the reference architecture")

    p_paths = sub.add_parser("paths", help="rank the most likely attack paths")
    p_paths.add_argument("--target", default="imp_prod_stop")
    p_paths.add_argument("-k", type=int, default=10)
    p_paths.add_argument("--scenario", default="S0",
                         help="named scenario (S0..S5) or a comma-separated control list")

    sub.add_parser("chokepoints", help="rank assets by likelihood-weighted criticality")

    p_risk = sub.add_parser("risk", help="run the Monte Carlo campaign simulation")
    p_risk.add_argument("--scenario", default="S0")
    p_risk.add_argument("--profile", default="ransomware", choices=sorted(ACTOR_PROFILES))
    p_risk.add_argument("--trials", type=int, default=20000)
    p_risk.add_argument("--frequency", type=float, default=1.5)

    sub.add_parser("corpus", help="summarise the empirical incident corpus")
    sub.add_parser("controls", help="list the control catalogue and standards mapping")

    args = ap.parse_args(argv)
    graph = build_graph()

    if args.command == "graph":
        print(json.dumps(graph.summary(), indent=2))
        print(f"zones: {', '.join(sorted(graph.zones))}")
        print(f"impacts: {', '.join(graph.impacts)}")
        return 0

    if args.command == "paths":
        pf = _portfolio(args.scenario)
        for i, path in enumerate(k_best_paths(graph, "ext_actor", args.target, args.k, pf), 1):
            print(f"{i:2d}. L={path.likelihood(pf):.5f} steps={path.length} "
                  f"min-Purdue={purdue_depth(path, graph)} effort={path.effort_h():.0f}h")
            print(f"    {' -> '.join(graph.assets[n].name for n in path.nodes)}")
            print(f"    {' '.join(path.techniques)}")
        return 0

    if args.command == "chokepoints":
        scored = rank_paths(enumerate_paths(graph, "ext_actor", max_length=12))
        nodes, edges = choke_points(scored, graph)
        print("asset criticality (share of aggregate path likelihood)")
        for node, share, count in nodes[:15]:
            print(f"  {share:6.3f}  {graph.assets[node].name:42s} {graph.assets[node].zone} "
                  f"({count} paths)")
        print("conduit criticality")
        for key, share, count in edges[:10]:
            print(f"  {share:6.3f}  {key[0]} -> {key[1]} [{key[2]}] ({count} paths)")
        return 0

    if args.command == "risk":
        pf = _portfolio(args.scenario)
        cfg = SimulationConfig(trials=args.trials, profile=args.profile,
                               frequency=args.frequency)
        res = simulate(graph, pf, pf.name, cfg)
        print(json.dumps(res.as_row(), indent=2))
        print("consequence probabilities:")
        for impact, prob in sorted(res.p_impact.items(), key=lambda t: -t[1]):
            print(f"  {prob:7.4f}  {graph.assets[impact].name}")
        return 0

    if args.command == "corpus":
        report = analyse_corpus(graph, load_incidents())
        loo = leave_one_out_report()
        print(f"incidents: {report.total}   representable: {report.representable} "
              f"({report.coverage:.0%})")
        print(f"availability impact: {report.availability_share:.0%}   "
              f"supply chain: {report.supply_chain_share:.0%}   "
              f"reached Purdue <= 3: {report.ot_interaction_share:.0%}")
        print(f"leave-one-out: {loo['score']:.0%} (internal only: {loo['score_internal']:.0%})")
        for inc in load_incidents():
            path, err = realise(graph, inc.node_path)
            like = f"{path.likelihood():.5f}" if path else "n/a"
            print(f"  {inc.id} {inc.year} {inc.victim[:28]:28s} {inc.confidence:9s} L={like}")
        return 0

    if args.command == "controls":
        for cid in sorted(CONTROLS):
            c = CONTROLS[cid]
            print(f"{c.id}  cost={c.cost:>2.0f}  m={c.m:.2f} u={c.u:.2f} rec={c.recovery:.2f}  {c.name}")
            print(f"      IEC 62443-3-3: {', '.join(c.iec62443)}   NIST CSF 2.0: {', '.join(c.csf)}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
