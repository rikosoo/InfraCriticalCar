"""Monte Carlo campaign simulation and risk quantification.

The path ranking of :mod:`capm.paths` answers *where* an attacker is likely to
go. It does not answer *how often* the plant loses money, because a real
campaign is a sequential decision process under a time budget in which the
defender may contain the intrusion at any step. This module therefore runs a
campaign simulation on the same graph:

1.  the actor starts at the entry point with an effort budget ``budget_h``;
2.  at each step it picks the frontier step that minimises the expected
    remaining resistance to an impact (a best-first policy on the log-likelihood
    metric), with a configurable amount of policy noise;
3.  the step consumes ``effort_h`` hours, succeeds with probability ``p'`` and is
    detected-and-contained with probability ``delta'``; containment ends the
    campaign;
4.  reaching an impact node records a consequence; the campaign continues until
    the budget is exhausted, the frontier is empty, or the actor is contained.

Losses are sampled from the triangular consequence distributions of the impact
nodes, amplified when the campaign traversed a recovery-inhibiting asset (for
example the backup infrastructure) and shortened by consequence-side controls
(tested offline backups, manual degraded-mode production).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from .architecture import AMPLIFIERS
from .model import AttackGraph, Edge
from .paths import edge_weight

Lookup = Optional[Callable[[Edge], Tuple[float, float]]]

#: Expected number of targeted, hands-on-keyboard campaigns per plant-year.
#: Calibrated in Section V of the paper; varied in the sensitivity analysis.
DEFAULT_FREQUENCY = 1.5

#: Relative utility an actor profile assigns to each consequence. The campaign
#: policy is utility-aware: a big-game ransomware crew drives at production
#: stoppage because that is what pays, an espionage actor at design data, and a
#: sabotage actor at safety and quality. Values are in (0, 1].
ACTOR_PROFILES: Dict[str, Dict[str, float]] = {
    "ransomware": {
        "imp_prod_stop": 1.00, "imp_pii": 0.40, "imp_ip": 0.35,
        "imp_quality": 0.25, "imp_safety": 0.30,
    },
    "espionage": {
        "imp_ip": 1.00, "imp_pii": 0.35, "imp_prod_stop": 0.15,
        "imp_quality": 0.20, "imp_safety": 0.05,
    },
    "sabotage": {
        "imp_safety": 1.00, "imp_quality": 0.85, "imp_prod_stop": 0.80,
        "imp_ip": 0.10, "imp_pii": 0.05,
    },
}


@dataclass
class SimulationConfig:
    trials: int = 20000
    budget_h: float = 720.0          # 30 days of hands-on-keyboard activity
    seed: int = 20260916
    policy_noise: float = 0.35       # std-dev of Gumbel-like noise on step choice
    max_attempts_per_edge: int = 2
    frequency: float = DEFAULT_FREQUENCY
    #: impacts that satisfy the actor's primary objective and end the campaign
    terminal_impacts: Tuple[str, ...] = ("imp_prod_stop", "imp_safety")
    #: actor profile used by the campaign policy (see ACTOR_PROFILES)
    profile: str = "ransomware"


@dataclass
class RiskResult:
    scenario: str
    profile: str
    trials: int
    p_any_impact: float
    p_impact: Dict[str, float]
    p_contained: float
    mean_loss: float                  # MUSD per campaign
    median_loss: float
    p95_loss: float
    mean_loss_given_impact: float
    p95_loss_given_impact: float
    mean_downtime_h: float
    p95_downtime_h: float
    mean_ttc_h: float                 # mean time to first consequence
    ale: float                        # annualised loss expectancy, MUSD/plant-year
    technique_frequency: Dict[str, float] = field(default_factory=dict)
    node_frequency: Dict[str, float] = field(default_factory=dict)

    def as_row(self) -> Dict[str, object]:
        return {
            "scenario": self.scenario,
            "profile": self.profile,
            "p_any_impact": round(self.p_any_impact, 4),
            "p_production_stop": round(self.p_impact.get("imp_prod_stop", 0.0), 4),
            "p_contained": round(self.p_contained, 4),
            "mean_loss_musd": round(self.mean_loss, 2),
            "p95_loss_musd": round(self.p95_loss, 2),
            "mean_loss_given_impact_musd": round(self.mean_loss_given_impact, 2),
            "p95_loss_given_impact_musd": round(self.p95_loss_given_impact, 2),
            "mean_downtime_h": round(self.mean_downtime_h, 1),
            "mean_ttc_h": round(self.mean_ttc_h, 1),
            "ale_musd": round(self.ale, 2),
        }


def _goal_distance(
    graph: AttackGraph,
    portfolio: Lookup,
    values: Optional[Dict[str, float]] = None,
) -> Dict[str, float]:
    """Utility-weighted resistance from every node to the actor's objectives.

    ``dist(v)`` is the minimum, over impacts ``i``, of the log-likelihood
    resistance of the best path from ``v`` to ``i`` minus ``log`` of the utility
    the actor assigns to ``i``. A best-first policy on this quantity therefore
    trades expected effort off against expected reward instead of simply running
    at the nearest consequence.
    """
    import heapq

    values = values or {i: 1.0 for i in graph.impacts}
    rev: Dict[str, List[Edge]] = {}
    for e in graph.edges:
        rev.setdefault(e.dst, []).append(e)
    dist: Dict[str, float] = {
        i: -math.log(max(values.get(i, 0.01), 1e-6)) for i in graph.impacts
    }
    heap = [(dist[i], i) for i in graph.impacts]
    heapq.heapify(heap)
    seen: Set[str] = set()
    while heap:
        d, node = heapq.heappop(heap)
        if node in seen:
            continue
        seen.add(node)
        for e in rev.get(node, ()):  # noqa: B007
            nd = d + edge_weight(e, portfolio)
            if nd < dist.get(e.src, math.inf) - 1e-15:
                dist[e.src] = nd
                heapq.heappush(heap, (nd, e.src))
    return dist


def simulate(
    graph: AttackGraph,
    portfolio: Lookup = None,
    name: str = "S0",
    config: Optional[SimulationConfig] = None,
) -> RiskResult:
    cfg = config or SimulationConfig()
    rng = random.Random(cfg.seed)
    values = ACTOR_PROFILES.get(cfg.profile)
    if values is None:
        raise KeyError(f"unknown actor profile {cfg.profile!r}")
    dist = _goal_distance(graph, portfolio, values)
    adj: Dict[str, List[Edge]] = {}
    for e in graph.edges:
        adj.setdefault(e.src, []).append(e)

    recovery = portfolio.recovery_factor() if hasattr(portfolio, "recovery_factor") else 1.0

    impacts_hit: Dict[str, int] = {i: 0 for i in graph.impacts}
    losses: List[float] = []
    downtimes: List[float] = []
    ttcs: List[float] = []
    contained = 0
    any_impact = 0
    tech_count: Dict[str, int] = {}
    node_count: Dict[str, int] = {}

    for _ in range(cfg.trials):
        held: Set[str] = set(graph.entry_points)
        attempts: Dict[Tuple[str, str, str], int] = {}
        spent = 0.0
        reached: List[str] = []
        used_techniques: Set[str] = set()
        stopped = False
        first_impact_time: Optional[float] = None

        while not stopped and spent < cfg.budget_h:
            frontier: List[Tuple[float, Edge]] = []
            # iterate deterministically: set iteration order depends on the
            # per-process hash seed and would make runs irreproducible
            for node in sorted(held):
                for e in adj.get(node, ()):  # noqa: B007
                    if e.dst in held:
                        continue
                    if attempts.get(e.key, 0) >= cfg.max_attempts_per_edge:
                        continue
                    if spent + e.effort_h > cfg.budget_h:
                        continue
                    score = edge_weight(e, portfolio) + dist.get(e.dst, 25.0)
                    score += rng.gauss(0.0, cfg.policy_noise)
                    frontier.append((score, e))
            if not frontier:
                break
            frontier.sort(key=lambda t: (t[0], t[1].key))
            _, edge = frontier[0]
            attempts[edge.key] = attempts.get(edge.key, 0) + 1
            spent += edge.effort_h
            mit, upl = (0.0, 0.0) if portfolio is None else portfolio(edge)
            p_eff, d_eff = edge.effective(mit, upl)
            if rng.random() < d_eff:
                if not reached:
                    contained += 1
                stopped = True
                break
            if rng.random() < p_eff:
                held.add(edge.dst)
                used_techniques.add(edge.technique)
                if graph.assets[edge.dst].is_impact:
                    reached.append(edge.dst)
                    if first_impact_time is None:
                        first_impact_time = spent
                    if edge.dst in cfg.terminal_impacts:
                        stopped = True

        if reached:
            any_impact += 1
            amp = 1.0
            for node, factor in sorted(AMPLIFIERS.items()):
                if node in held:
                    amp *= factor
            downtime = 0.0
            fixed = 0.0
            for impact in sorted(set(reached)):
                impacts_hit[impact] += 1
                cons = graph.consequences[impact]
                lo, mode, hi = cons.downtime_h
                if hi > 0:
                    d = rng.triangular(lo, hi, mode) * amp * recovery
                    downtime = max(downtime, d)
                f_lo, f_mode, f_hi = cons.fixed_cost
                if f_hi > 0:
                    fixed += rng.triangular(f_lo, f_hi, f_mode)
            cost_rate = max(
                graph.consequences[i].cost_per_h for i in sorted(set(reached))
            )
            losses.append(downtime * cost_rate + fixed)
            downtimes.append(downtime)
            if first_impact_time is not None:
                ttcs.append(first_impact_time)
            for t in sorted(used_techniques):
                tech_count[t] = tech_count.get(t, 0) + 1
            for n in sorted(held):
                node_count[n] = node_count.get(n, 0) + 1
        else:
            losses.append(0.0)
            downtimes.append(0.0)

    n = float(cfg.trials)
    losses_sorted = sorted(losses)
    positive = sorted(x for x in losses if x > 0.0)
    down_sorted = sorted(downtimes)
    mean_loss = sum(losses) / n
    return RiskResult(
        scenario=name,
        profile=cfg.profile,
        trials=cfg.trials,
        p_any_impact=any_impact / n,
        p_impact={k: v / n for k, v in impacts_hit.items()},
        p_contained=contained / n,
        mean_loss=mean_loss,
        median_loss=_quantile(losses_sorted, 0.5),
        p95_loss=_quantile(losses_sorted, 0.95),
        mean_loss_given_impact=(sum(positive) / len(positive)) if positive else 0.0,
        p95_loss_given_impact=_quantile(positive, 0.95),
        mean_downtime_h=sum(downtimes) / n,
        p95_downtime_h=_quantile(down_sorted, 0.95),
        mean_ttc_h=(sum(ttcs) / len(ttcs)) if ttcs else float("nan"),
        ale=cfg.frequency * mean_loss,
        technique_frequency={k: v / max(any_impact, 1) for k, v in tech_count.items()},
        node_frequency={k: v / max(any_impact, 1) for k, v in node_count.items()},
    )


def _quantile(sorted_values: Sequence[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, max(0, int(round(q * (len(sorted_values) - 1)))))
    return sorted_values[idx]


def marginal_value(
    graph: AttackGraph,
    base_portfolio,
    candidate: str,
    config: Optional[SimulationConfig] = None,
) -> Tuple[float, float]:
    """Return (ALE reduction, ALE reduction per unit cost) for adding a control."""
    from .controls import CONTROLS

    cfg = config or SimulationConfig()
    base = simulate(graph, base_portfolio, base_portfolio.name, cfg)
    improved = base_portfolio.with_control(candidate)
    after = simulate(graph, improved, improved.name, cfg)
    delta = base.ale - after.ale
    return delta, delta / CONTROLS[candidate].cost
