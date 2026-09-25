#!/usr/bin/env python3
"""Generate the supplementary parameter tables for the submission.

The reviewer's first question about a model like this one is where the numbers
came from. This emits, straight from the model, every parameter the paper uses:
each attack step with its probability, its detection probability, its effort,
the band each value falls in, the controls that apply to it, the incidents that
support it and a one-line rationale; then the control catalogue, the consequence
model and the reproduction instructions. Nothing is retyped, so the supplement
cannot drift from the code.

    python3 experiments/build_supplementary.py
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from capm.architecture import AMPLIFIERS, build_graph
from capm.controls import CONTROLS
from capm.elicitation import DELTA_SCALE, EFFORT_SCALE, P_SCALE
from capm.report import write_latex_table

OUT = os.path.join(ROOT, "paper", "ijcip", "supp-tables")


def band(value: float, scale) -> str:
    """The anchored band a published estimate falls in, nearest anchor."""
    return min(scale.items(), key=lambda kv: abs(kv[1] - value))[0]


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    g = build_graph()

    rows = []
    for e in sorted(g.edges, key=lambda x: (g.purdue_of(x.src) * -1, x.src, x.dst)):
        rows.append((
            f"{g.assets[e.src].name} $\\to$ {g.assets[e.dst].name}",
            e.technique,
            f"{e.p:.2f} ({band(e.p, P_SCALE)})",
            f"{e.delta:.2f} ({band(e.delta, DELTA_SCALE)})",
            f"{e.effort_h:.0f} ({band(e.effort_h, EFFORT_SCALE)})",
            " ".join(e.controls) or "--",
            " ".join(e.evidence) or "--",
            e.rationale or "--",
        ))
    write_latex_table(
        os.path.join(OUT, "s1_steps.tex"),
        ["Step", "Technique", "$p$", "$\\delta$", "Effort (h)", "Controls", "Evidence",
         "Rationale"],
        rows,
        caption="Every attack step of the reference architecture with its parameters, the "
                "anchored band each value falls in, the controls that act on it, the corpus "
                "incidents that support it, and the reason the step is modelled. Bands are "
                "those of the elicitation instrument: VL, L, M, H, VH.",
        label="tab:s1", align="p{4.6cm}lllllp{3.2cm}p{4.4cm}", star=True)

    write_latex_table(
        os.path.join(OUT, "s2_bands.tex"),
        ["Band", "$p$: the step succeeds", "$\\delta$: detected \\emph{and} contained",
         "Effort"],
        [("VL", "0.05 rarely works", "0.05 we would not notice", "2 h under half a day"),
         ("L", "0.15 needs a specific weakness", "0.20 noticed too late", "8 h about a day"),
         ("M", "0.35 works about as often as not", "0.40 even chance", "24 h a few days"),
         ("H", "0.60 usually works", "0.60 usually contained", "80 h one to two weeks"),
         ("VH", "0.85 almost always works", "0.80 almost always contained", "200 h over a month")],
        caption="The anchored bands. Published estimates are reported against these bands so "
                "that a reader can see the granularity actually claimed, and so that a panel "
                "re-eliciting the model answers on the same scale.",
        label="tab:s2", align="lp{4.2cm}p{4.6cm}p{3.6cm}")

    write_latex_table(
        os.path.join(OUT, "s3_controls.tex"),
        ["ID", "Control", "$m$", "$u$", "Recovery", "Cost", "IEC 62443-3-3", "NIST CSF 2.0"],
        [(c.id, c.name, f"{c.m:.2f}", f"{c.u:.2f}", f"{c.recovery:.2f}", f"{c.cost:.0f}",
          "; ".join(c.iec62443), "; ".join(c.csf))
         for c in (CONTROLS[k] for k in sorted(CONTROLS))],
        caption="Control catalogue: mitigation $m$, detection uplift $u$, recovery effect, "
                "relative annualised cost index, and the standard requirements each control "
                "implements.",
        label="tab:s3", align="lp{4.4cm}llllp{2.6cm}p{2.6cm}", star=True)

    cons_rows = []
    for impact, cons in g.consequences.items():
        lo, mode, hi = cons.downtime_h
        f_lo, f_mode, f_hi = cons.fixed_cost
        cons_rows.append((
            g.assets[impact].name,
            f"({lo:.0f}, {mode:.0f}, {hi:.0f})" if hi else "--",
            f"{cons.cost_per_h:.2f}" if cons.cost_per_h else "--",
            f"({f_lo:.0f}, {f_mode:.0f}, {f_hi:.0f})",
            "yes" if cons.safety else "no"))
    write_latex_table(
        os.path.join(OUT, "s4_consequences.tex"),
        ["Consequence", "Downtime h (min, mode, max)", "Loss rate (M\\$/h)",
         "Fixed cost (M\\$, min, mode, max)", "Safety"],
        cons_rows,
        caption="Consequence model. Durations and fixed costs are triangular. The outage of a "
                "campaign that traverses a recovery-inhibiting asset is multiplied: "
                + ", ".join(f"{g.assets[k].name} $\\times${v}" for k, v in sorted(AMPLIFIERS.items()))
                + ".",
        label="tab:s4", align="p{4cm}llll", star=True)

    print(f"wrote {len(os.listdir(OUT))} supplementary tables to {OUT}")


if __name__ == "__main__":
    main()
