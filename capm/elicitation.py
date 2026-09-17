"""Structured parameter elicitation: forms, aggregation and overrides.

The weakest point of the model is that ``p``, ``delta`` and ``effort`` are the
authors' estimates. This module turns that into a procedure a plant can run in
an afternoon and a paper can describe in a subsection:

1.  :func:`build_form` emits one row per attack step, ordered by how much the
    step matters to the conclusions, so a first round can cover the steps that
    carry most of the risk mass instead of all 91.
2.  Experts answer on an anchored five-point scale (or write a number directly),
    which practitioners calibrate far better than raw probabilities.
3.  :func:`aggregate` combines the responses by median, reports the interquartile
    range as the measure of disagreement, and flags the steps where the panel
    did not converge --- those are the ones a second Delphi round revisits.
4.  :func:`write_overrides` produces the parameter file that
    ``build_graph(overrides=...)`` applies, so the whole pipeline can be re-run
    on elicited values and the paper can report before-and-after.

Nothing here assumes a particular panel size; the statistics are order-based
precisely because panels are small.
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import AttackGraph, Edge

#: Anchored scales. Practitioners pick a label; the label maps to a number.
P_SCALE: Dict[str, float] = {
    "VL": 0.05,   # would rarely work even against a weak target
    "L": 0.15,    # works occasionally, needs luck or a specific weakness
    "M": 0.35,    # works about as often as not
    "H": 0.60,    # usually works against a typical plant
    "VH": 0.85,   # almost always works
}

DELTA_SCALE: Dict[str, float] = {
    "VL": 0.05,   # we would almost certainly not notice
    "L": 0.20,    # we might notice, probably too late
    "M": 0.40,    # even chance of catching and containing it
    "H": 0.60,    # we would usually catch and contain it
    "VH": 0.80,   # we would almost certainly catch and contain it
}

EFFORT_SCALE: Dict[str, float] = {
    "VL": 2.0,    # under half a day
    "L": 8.0,     # about a day
    "M": 24.0,    # a few days
    "H": 80.0,    # one to two weeks
    "VH": 200.0,  # more than a month
}

SCALES = {"p": P_SCALE, "delta": DELTA_SCALE, "effort": EFFORT_SCALE}

#: Steps whose interquartile range exceeds this go to a second round.
DISAGREEMENT_THRESHOLD = {"p": 0.25, "delta": 0.25, "effort": 48.0}

FORM_HEADER = [
    "step_id", "priority", "src", "dst", "src_name", "dst_name", "technique",
    "technique_name", "question_p", "question_delta", "question_effort",
    "current_p", "current_delta", "current_effort_h",
    "your_p", "your_delta", "your_effort_h", "comment",
]


def step_id(edge: Edge) -> str:
    return f"{edge.src}|{edge.dst}|{edge.technique}"


def build_form(
    graph: AttackGraph,
    priority: Optional[Sequence[Tuple[Tuple[str, str, str], float, int]]] = None,
    limit: Optional[int] = None,
    show_current: bool = False,
) -> List[List[object]]:
    """Rows of an elicitation form, most consequential step first.

    ``priority`` is the conduit criticality produced by
    :func:`capm.paths.choke_points`; without it the form keeps model order.
    ``show_current`` is off by default: showing the authors' own estimate to the
    panel would anchor it, which is exactly what the exercise must avoid. Turn
    it on only for a second round, where the panel is meant to reconsider a
    value it has already seen.
    """
    order: Dict[Tuple[str, str, str], float] = {}
    if priority:
        for key, share, _count in priority:
            order[key] = share
    rows: List[List[object]] = []
    for edge in graph.edges:
        rows.append([
            step_id(edge),
            f"{order.get(edge.key, 0.0):.5f}",
            edge.src, edge.dst,
            graph.assets[edge.src].name, graph.assets[edge.dst].name,
            edge.technique, graph.techniques[edge.technique].name,
            (f"Given an attacker who already controls '{graph.assets[edge.src].name}', "
             f"how often does {edge.technique} against '{graph.assets[edge.dst].name}' "
             f"succeed? (VL/L/M/H/VH or a probability)"),
            ("How often would your monitoring detect AND contain that step before the "
             "attacker builds on it? (VL/L/M/H/VH or a probability)"),
            ("How much hands-on time would the step cost a competent attacker? "
             "(VL/L/M/H/VH or hours)"),
            edge.p if show_current else "",
            edge.delta if show_current else "",
            edge.effort_h if show_current else "",
            "", "", "", "",
        ])
    rows.sort(key=lambda r: -float(r[1]))
    return rows[:limit] if limit else rows


def write_form(path: str, rows: Iterable[Sequence[object]]) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(FORM_HEADER)
        for row in rows:
            writer.writerow(list(row))
    return path


def parse_answer(value: str, field: str) -> Optional[float]:
    """Read one answer: a scale label, or a number in the field's own units."""
    text = (value or "").strip().upper()
    if not text:
        return None
    scale = SCALES[field]
    if text in scale:
        return scale[text]
    try:
        number = float(text.replace(",", "."))
    except ValueError:
        return None
    if field in ("p", "delta") and not 0.0 <= number <= 1.0:
        return None
    if field == "effort" and number <= 0:
        return None
    return number


def _quantile(sorted_values: Sequence[float], q: float) -> float:
    if not sorted_values:
        return float("nan")
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = q * (len(sorted_values) - 1)
    low = int(pos)
    high = min(low + 1, len(sorted_values) - 1)
    frac = pos - low
    return sorted_values[low] * (1 - frac) + sorted_values[high] * frac


@dataclass
class StepEstimate:
    step_id: str
    field: str
    values: List[float]
    median: float
    iqr: float
    n: int
    disagreement: bool


def aggregate(responses: Sequence[Dict[str, str]]) -> Dict[str, Dict[str, StepEstimate]]:
    """Aggregate filled forms (rows from any number of respondents) by step.

    Returns ``{step_id: {field: StepEstimate}}``. The median is the consensus
    value, the interquartile range is the disagreement measure, and a step whose
    IQR exceeds the field's threshold is flagged for a second round.
    """
    collected: Dict[str, Dict[str, List[float]]] = {}
    for row in responses:
        sid = (row.get("step_id") or "").strip()
        if not sid:
            continue
        for field, column in (("p", "your_p"), ("delta", "your_delta"),
                              ("effort", "your_effort_h")):
            answer = parse_answer(row.get(column, ""), field)
            if answer is None:
                continue
            collected.setdefault(sid, {}).setdefault(field, []).append(answer)
    out: Dict[str, Dict[str, StepEstimate]] = {}
    for sid, fields in collected.items():
        for field, values in fields.items():
            ordered = sorted(values)
            iqr = _quantile(ordered, 0.75) - _quantile(ordered, 0.25)
            out.setdefault(sid, {})[field] = StepEstimate(
                step_id=sid, field=field, values=ordered,
                median=_quantile(ordered, 0.5), iqr=iqr, n=len(ordered),
                disagreement=iqr > DISAGREEMENT_THRESHOLD[field],
            )
    return out


def read_responses(paths: Sequence[str]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for path in paths:
        with open(path, newline="", encoding="utf-8") as fh:
            rows.extend(dict(r) for r in csv.DictReader(fh))
    return rows


def write_overrides(path: str, estimates: Dict[str, Dict[str, StepEstimate]]) -> str:
    """Write the parameter file consumed by ``build_graph(overrides=...)``."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["src", "dst", "technique", "p", "delta", "effort_h",
                         "panel_n", "iqr_p", "iqr_delta", "needs_second_round"])
        for sid, fields in sorted(estimates.items()):
            try:
                src, dst, technique = sid.split("|")
            except ValueError:
                continue
            p = fields.get("p")
            d = fields.get("delta")
            e = fields.get("effort")
            flagged = any(f.disagreement for f in fields.values())
            writer.writerow([
                src, dst, technique,
                f"{p.median:.4f}" if p else "",
                f"{d.median:.4f}" if d else "",
                f"{e.median:.1f}" if e else "",
                max((f.n for f in fields.values()), default=0),
                f"{p.iqr:.4f}" if p else "",
                f"{d.iqr:.4f}" if d else "",
                "yes" if flagged else "no",
            ])
    return path


def load_overrides(path: str) -> Dict[Tuple[str, str, str], Dict[str, float]]:
    """Read an overrides file into the mapping ``build_graph`` expects."""
    out: Dict[Tuple[str, str, str], Dict[str, float]] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row["src"].strip(), row["dst"].strip(), row["technique"].strip())
            values: Dict[str, float] = {}
            for field, column in (("p", "p"), ("delta", "delta"), ("effort_h", "effort_h")):
                text = (row.get(column) or "").strip()
                if text:
                    values[field] = float(text)
            if values:
                out[key] = values
    return out


def compare(graph: AttackGraph, overrides: Dict[Tuple[str, str, str], Dict[str, float]]
            ) -> List[Dict[str, object]]:
    """Rows describing how far the elicited values moved each parameter."""
    rows: List[Dict[str, object]] = []
    for edge in graph.edges:
        new = overrides.get(edge.key)
        if not new:
            continue
        rows.append({
            "step": step_id(edge),
            "p_before": edge.p, "p_after": new.get("p", edge.p),
            "delta_before": edge.delta, "delta_after": new.get("delta", edge.delta),
            "effort_before": edge.effort_h, "effort_after": new.get("effort_h", edge.effort_h),
            "p_shift": new.get("p", edge.p) - edge.p,
            "delta_shift": new.get("delta", edge.delta) - edge.delta,
        })
    rows.sort(key=lambda r: -abs(float(r["p_shift"])))
    return rows
