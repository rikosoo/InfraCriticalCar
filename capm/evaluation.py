"""Statistical evaluation: interval estimates and comparison against baselines.

Two questions a reviewer asks of a prioritisation model. First, *how uncertain
are the descriptive proportions* drawn from a 20-incident corpus -- answered
with Wilson score intervals, which behave correctly for small samples and
proportions near 0 or 1, unlike the normal approximation. Second, *better than
what?* -- answered by ranking the same path set with four baseline heuristics
that stand in for how plants prioritise today, and scoring every ranking against
the same ground truth: where the paths that incidents actually took fall in it.

Everything here is exact and dependency-free: the Wilcoxon signed-rank test uses
the exact permutation distribution (computed by dynamic programming over the
signed ranks) rather than a normal approximation, which matters at n = 20.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .model import AttackGraph, Path

Z95 = 1.959963984540054


# --------------------------------------------------------------------------
# Interval estimates
# --------------------------------------------------------------------------

def wilson_interval(successes: int, n: int, z: float = Z95) -> Tuple[float, float, float]:
    """Wilson score interval for a binomial proportion.

    Returns ``(point_estimate, lower, upper)``. With ``n = 20`` the normal
    approximation is unusable for proportions near 0 or 1 -- for 2/20 it dips
    below zero -- while the Wilson interval stays inside [0, 1].
    """
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0 <= successes <= n:
        raise ValueError("successes must lie in [0, n]")
    p = successes / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return p, max(0.0, centre - half), min(1.0, centre + half)


def format_interval(successes: int, n: int, pct: bool = True) -> str:
    p, lo, hi = wilson_interval(successes, n)
    if pct:
        return f"{100 * p:.0f}\\% (95\\% CI {100 * lo:.0f}--{100 * hi:.0f}\\%)"
    return f"{p:.2f} ({lo:.2f}-{hi:.2f})"


# --------------------------------------------------------------------------
# Non-parametric tests
# --------------------------------------------------------------------------

def _average_ranks(values: Sequence[float]) -> List[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        mean_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = mean_rank
        i = j + 1
    return ranks


def wilcoxon_signed_rank(a: Sequence[float], b: Sequence[float]) -> Dict[str, float]:
    """Exact two-sided Wilcoxon signed-rank test for paired samples.

    Pairs with zero difference are dropped (Wilcoxon's original handling). The
    null distribution is enumerated exactly by dynamic programming over the
    signed ranks, so the result is valid at the sample sizes used here; average
    ranks are doubled to keep the dynamic programme integral in the presence of
    ties.
    """
    if len(a) != len(b):
        raise ValueError("paired samples must have equal length")
    diffs = [x - y for x, y in zip(a, b) if x != y]
    n = len(diffs)
    if n == 0:
        return {"n": 0, "w_plus": 0.0, "p_value": 1.0, "effect": 0.0}
    ranks = _average_ranks([abs(d) for d in diffs])
    scaled = [int(round(2 * r)) for r in ranks]
    w_plus = sum(s for s, d in zip(scaled, diffs) if d > 0)
    total = sum(scaled)
    # counts[s] = number of sign assignments whose positive-rank sum is s
    counts = [0] * (total + 1)
    counts[0] = 1
    for s in scaled:
        for value in range(total, s - 1, -1):
            if counts[value - s]:
                counts[value] += counts[value - s]
    space = float(2 ** n)
    le = sum(counts[: w_plus + 1]) / space
    ge = sum(counts[w_plus:]) / space
    p = min(1.0, 2.0 * min(le, ge))
    expected = total / 2.0
    return {
        "n": float(n),
        "w_plus": w_plus / 2.0,
        "expected_w_plus": expected / 2.0,
        "p_value": p,
        # rank-biserial correlation: +1 means a is larger throughout
        "effect": (2.0 * w_plus / total - 1.0) if total else 0.0,
    }


def kendall_tau_b(a: Sequence[float], b: Sequence[float]) -> float:
    """Kendall's tau-b, with the standard correction for ties."""
    n = len(a)
    if n != len(b) or n < 2:
        raise ValueError("need two equal-length samples of at least two elements")
    concordant = discordant = ties_a = ties_b = 0
    for i in range(n - 1):
        ai, bi = a[i], b[i]
        for j in range(i + 1, n):
            da, db = ai - a[j], bi - b[j]
            if da == 0 and db == 0:
                continue
            if da == 0:
                ties_a += 1
            elif db == 0:
                ties_b += 1
            elif (da > 0) == (db > 0):
                concordant += 1
            else:
                discordant += 1
    pairs_a = concordant + discordant + ties_a
    pairs_b = concordant + discordant + ties_b
    denom = math.sqrt(pairs_a * pairs_b)
    return (concordant - discordant) / denom if denom else 0.0


# --------------------------------------------------------------------------
# Baseline prioritisations
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Baseline:
    """A way of ordering attack paths, highest score first."""

    id: str
    name: str
    description: str
    score: Callable[[Path], float]


def build_baselines(graph: AttackGraph) -> List[Baseline]:
    """The prioritisations CAPM is measured against.

    ``B1`` is the classical attack-graph proxy (fewest steps wins). ``B2`` is
    vulnerability-centric practice: it multiplies exploitation probabilities and
    ignores detection and containment entirely, which is what a CVSS-style
    exploitability score does. ``B3`` encodes the zone-centric assumption this
    paper questions: the deeper into the Purdue hierarchy a path reaches, the
    more it matters. ``B4`` is the segmentation-centric reflex that a path
    crossing more security zones is the more serious one.

    A consequence-magnitude baseline is deliberately absent: paths are scored
    within the set that reaches the same consequence, so a ranking driven by
    consequence alone is constant inside every comparison set and degenerates to
    its tie-breaker. Comparing consequence-first prioritisation would require a
    different, cross-consequence metric.
    """
    from .paths import purdue_depth, zone_transitions

    return [
        Baseline("B1", "Fewest steps",
                 "Shortest path in hops, the classical attack-graph proxy",
                 lambda p: -float(p.length)),
        Baseline("B2", "Exploitability only",
                 "Product of step success probabilities, ignoring detection and "
                 "containment, as vulnerability-centric scoring does",
                 lambda p: math.prod(e.p for e in p.edges)),
        Baseline("B3", "Deepest OT reach",
                 "Paths that reach the lowest Purdue level first, the implicit "
                 "ranking of zone-centric practice",
                 lambda p: (5 - purdue_depth(p, graph)) * 1000.0 - p.length),
        Baseline("B4", "Most zones crossed",
                 "Paths crossing the most IEC 62443 zone boundaries first, the "
                 "segmentation-centric reflex",
                 lambda p: float(zone_transitions(p, graph))),
    ]


# --------------------------------------------------------------------------
# Scoring a ranking against the corpus
# --------------------------------------------------------------------------

@dataclass
class RankingScore:
    id: str
    name: str
    percentiles: List[float]
    median: float
    mean: float
    in_top_10pct: int
    in_top_25pct: int
    kendall_vs_capm: Optional[float] = None
    wilcoxon_vs_capm: Optional[Dict[str, float]] = None


def percentile_positions(
    paths: Sequence[Path],
    scores: Sequence[float],
    targets: Sequence[Path],
) -> List[float]:
    """Percentile of each target path within the ranking, among the paths that
    reach the same consequence. Lower is better: 0 would be the top of the list.
    """
    by_target: Dict[str, List[Tuple[float, Tuple[str, ...]]]] = {}
    for path, score in zip(paths, scores):
        by_target.setdefault(path.target, []).append((score, path.nodes))
    for key in by_target:
        by_target[key].sort(key=lambda t: -t[0])
    out: List[float] = []
    for target_path in targets:
        bucket = by_target.get(target_path.target, [])
        position = next((i for i, (_, nodes) in enumerate(bucket)
                         if nodes == target_path.nodes), None)
        if position is None or not bucket:
            continue
        out.append(100.0 * (position + 1) / len(bucket))
    return out


def _median(values: Sequence[float]) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def score_ranking(rid: str, name: str, percentiles: Sequence[float]) -> RankingScore:
    return RankingScore(
        id=rid, name=name, percentiles=list(percentiles),
        median=_median(percentiles),
        mean=(sum(percentiles) / len(percentiles)) if percentiles else float("nan"),
        in_top_10pct=sum(1 for p in percentiles if p <= 10.0),
        in_top_25pct=sum(1 for p in percentiles if p <= 25.0),
    )
