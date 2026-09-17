#!/usr/bin/env python3
"""Run a parameter elicitation round.

    # 1. produce the form to send to the panel (top 30 steps by risk mass)
    python3 experiments/elicitation.py form --limit 30

    # 2. after collecting one filled CSV per expert
    python3 experiments/elicitation.py ingest responses/*.csv

    # 3. re-run the whole study on the elicited values
    python3 experiments/run_all.py --overrides data/parameter_overrides.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from typing import List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from capm.architecture import build_graph
from capm.elicitation import (aggregate, build_form, compare, load_overrides,
                              read_responses, write_form, write_overrides)
from capm.paths import choke_points, enumerate_paths, rank_paths
from capm.report import write_csv


def cmd_form(args: argparse.Namespace) -> int:
    graph = build_graph()
    scored = rank_paths(enumerate_paths(graph, "ext_actor", max_length=12))
    _, conduits = choke_points(scored, graph)
    rows = build_form(graph, priority=conduits, limit=args.limit,
                      show_current=args.show_current)
    path = write_form(os.path.join(ROOT, args.out), rows)
    print(f"wrote {path} with {len(rows)} steps")
    print("Send one copy per expert. Do not merge them: disagreement is the signal.")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    responses = read_responses(args.responses)
    estimates = aggregate(responses)
    if not estimates:
        print("no usable answers found", file=sys.stderr)
        return 1
    overrides_path = write_overrides(os.path.join(ROOT, args.out), estimates)

    flagged = [sid for sid, fields in estimates.items()
               if any(f.disagreement for f in fields.values())]
    panel = max((f.n for fields in estimates.values() for f in fields.values()), default=0)
    graph = build_graph()
    diff = compare(graph, load_overrides(overrides_path))
    write_csv(os.path.join(ROOT, "data", "elicitation_shift.csv"),
              ["step", "p_before", "p_after", "p_shift", "delta_before", "delta_after",
               "delta_shift", "effort_before", "effort_after"],
              [(r["step"], r["p_before"], r["p_after"], f"{r['p_shift']:+.3f}",
                r["delta_before"], r["delta_after"], f"{r['delta_shift']:+.3f}",
                r["effort_before"], r["effort_after"]) for r in diff])

    print(f"panel size: up to {panel} respondents per step")
    print(f"steps with an answer: {len(estimates)}")
    print(f"steps needing a second round (IQR above threshold): {len(flagged)}")
    for sid in flagged[:10]:
        print(f"  {sid}")
    print(f"wrote {overrides_path} and data/elicitation_shift.csv")
    if diff:
        worst = diff[0]
        print(f"largest move: {worst['step']} p {worst['p_before']} -> {worst['p_after']}")
    print("Re-run: python3 experiments/run_all.py --overrides data/parameter_overrides.csv")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    f = sub.add_parser("form", help="emit the elicitation form")
    f.add_argument("--limit", type=int, default=30,
                   help="how many steps to ask about (default 30, ordered by risk mass)")
    f.add_argument("--out", default="data/elicitation_form.csv")
    f.add_argument("--show-current", action="store_true",
                   help="reveal the published estimates; only for a second round")
    f.set_defaults(func=cmd_form)

    i = sub.add_parser("ingest", help="aggregate filled forms into parameter overrides")
    i.add_argument("responses", nargs="+", help="one filled CSV per respondent")
    i.add_argument("--out", default="data/parameter_overrides.csv")
    i.set_defaults(func=cmd_ingest)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
