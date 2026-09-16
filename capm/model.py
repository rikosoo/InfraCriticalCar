"""Core data model for the Cyberattack Path Model (CAPM).

The model represents an automotive manufacturing enterprise as a directed,
labelled attack graph

    G = (V, E, Z, tau, p, delta, c)

where

*   ``V`` is a set of *assets* (including the attacker's starting position and
    a set of terminal *impact* nodes),
*   ``E`` subset of V x V is a set of *attack steps* (edges),
*   ``Z`` is a partition of ``V`` into IEC 62443 *zones*,
*   ``tau: E -> T`` labels every edge with a MITRE ATT&CK technique (Enterprise
    or ICS),
*   ``p: E -> (0, 1]`` is the conditional success probability of the step given
    that the attacker holds the source asset,
*   ``delta: E -> [0, 1)`` is the probability that the step is *detected and
    contained* by the defender before the attacker can build on it,
*   ``c: E -> R+`` is the expected attacker effort (in hours) for the step.

Every numeric parameter is an explicit, versioned, expert-elicited estimate;
see ``capm/parameters.py`` and Section "Threats to validity" of the paper.
Nothing in this package depends on third-party libraries: the whole pipeline
runs on a stock CPython 3.9+ interpreter so that the results are reproducible
without a package index.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Static taxonomies
# --------------------------------------------------------------------------

#: Purdue Enterprise Reference Architecture levels used throughout the paper.
PURDUE_LEVELS: Dict[int, str] = {
    5: "Level 5 - Internet / external parties",
    4: "Level 4 - Enterprise IT and cloud",
    35: "Level 3.5 - Industrial DMZ (IDMZ)",
    3: "Level 3 - Site operations (MES, historian, engineering)",
    2: "Level 2 - Area supervisory control (SCADA/HMI)",
    1: "Level 1 - Basic control (PLC, safety PLC, robot controller)",
    0: "Level 0 - Process (sensors, actuators, line hardware)",
}

#: The four *planes* the paper argues must be modelled jointly.
PLANES = ("it", "identity", "cloud", "ot", "supply_chain")


@dataclass(frozen=True)
class Zone:
    """An IEC 62443-3-2 security zone."""

    id: str
    name: str
    purdue: int
    plane: str
    sl_target: int  # IEC 62443-3-3 target security level (SL-T), 0..4

    def __post_init__(self) -> None:
        if self.plane not in PLANES:
            raise ValueError(f"unknown plane {self.plane!r} for zone {self.id!r}")
        if self.purdue not in PURDUE_LEVELS:
            raise ValueError(f"unknown Purdue level {self.purdue} for zone {self.id!r}")
        if not 0 <= self.sl_target <= 4:
            raise ValueError(f"SL-T out of range for zone {self.id!r}")


@dataclass(frozen=True)
class Asset:
    """A node of the attack graph."""

    id: str
    name: str
    zone: str
    kind: str  # actor | host | service | identity | data | device | impact
    description: str = ""

    @property
    def is_impact(self) -> bool:
        return self.kind == "impact"


@dataclass(frozen=True)
class Technique:
    """A MITRE ATT&CK technique (Enterprise or ICS matrix)."""

    id: str
    name: str
    tactic: str
    matrix: str  # "enterprise" | "ics"

    def __post_init__(self) -> None:
        if self.matrix not in ("enterprise", "ics"):
            raise ValueError(f"unknown matrix {self.matrix!r} for {self.id!r}")


@dataclass(frozen=True)
class Consequence:
    """Consequence model attached to an impact node.

    ``downtime_h`` is the triangular distribution (min, mode, max) of production
    downtime in hours; ``cost_per_h`` is the loss rate in millions of USD per
    hour of stopped line; ``fixed_cost`` covers response, forensics, data
    handling and regulatory cost in millions of USD.
    """

    downtime_h: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    cost_per_h: float = 0.0
    fixed_cost: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    safety: bool = False


@dataclass(frozen=True)
class Edge:
    """An atomic attack step."""

    src: str
    dst: str
    technique: str
    p: float                      # conditional success probability
    delta: float                  # probability of detection-and-containment
    effort_h: float               # expected attacker effort in hours
    controls: Tuple[str, ...] = ()  # controls whose efficacy applies to this step
    rationale: str = ""
    evidence: Tuple[str, ...] = ()  # incident ids from data/incidents.csv

    def __post_init__(self) -> None:
        if not 0.0 < self.p <= 1.0:
            raise ValueError(f"p out of range on {self.src}->{self.dst}")
        if not 0.0 <= self.delta < 1.0:
            raise ValueError(f"delta out of range on {self.src}->{self.dst}")
        if self.effort_h <= 0:
            raise ValueError(f"effort must be positive on {self.src}->{self.dst}")

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.src, self.dst, self.technique)

    def effective(self, mitigation: float = 0.0, uplift: float = 0.0) -> Tuple[float, float]:
        """Return ``(p', delta')`` after applying a control portfolio.

        ``mitigation`` in [0, 1] is the fraction of the step's success
        likelihood removed by the active controls; ``uplift`` in [0, 1] is the
        residual-risk reduction achieved through detection, applied to the
        *undetected* probability mass.
        """
        p_eff = self.p * (1.0 - _clip(mitigation))
        d_eff = self.delta + (1.0 - self.delta) * _clip(uplift)
        return (max(p_eff, 1e-9), min(d_eff, 1.0 - 1e-9))


def _clip(x: float) -> float:
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)


@dataclass
class AttackGraph:
    """A validated attack graph plus its zone/technique/consequence metadata."""

    zones: Dict[str, Zone] = field(default_factory=dict)
    assets: Dict[str, Asset] = field(default_factory=dict)
    techniques: Dict[str, Technique] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    consequences: Dict[str, Consequence] = field(default_factory=dict)
    entry_points: Tuple[str, ...] = ()

    # -- construction -----------------------------------------------------
    def add_zone(self, zone: Zone) -> None:
        self.zones[zone.id] = zone

    def add_asset(self, asset: Asset) -> None:
        if asset.zone not in self.zones:
            raise KeyError(f"asset {asset.id!r} references unknown zone {asset.zone!r}")
        self.assets[asset.id] = asset

    def add_technique(self, technique: Technique) -> None:
        self.techniques[technique.id] = technique

    def add_edge(self, edge: Edge) -> None:
        if edge.src not in self.assets:
            raise KeyError(f"edge source {edge.src!r} is not an asset")
        if edge.dst not in self.assets:
            raise KeyError(f"edge target {edge.dst!r} is not an asset")
        if edge.technique not in self.techniques:
            raise KeyError(f"edge {edge.src}->{edge.dst} uses unknown technique {edge.technique!r}")
        if self.assets[edge.src].is_impact:
            raise ValueError(f"impact node {edge.src!r} must be terminal")
        self.edges.append(edge)

    # -- queries ----------------------------------------------------------
    @property
    def impacts(self) -> List[str]:
        return [a.id for a in self.assets.values() if a.is_impact]

    def out_edges(self, node: str) -> List[Edge]:
        return [e for e in self.edges if e.src == node]

    def in_edges(self, node: str) -> List[Edge]:
        return [e for e in self.edges if e.dst == node]

    def zone_of(self, node: str) -> Zone:
        return self.zones[self.assets[node].zone]

    def purdue_of(self, node: str) -> int:
        return self.zone_of(node).purdue

    def crosses_zone(self, edge: Edge) -> bool:
        return self.assets[edge.src].zone != self.assets[edge.dst].zone

    def matrix_of(self, edge: Edge) -> str:
        return self.techniques[edge.technique].matrix

    def validate(self) -> List[str]:
        """Return a list of structural problems (empty list == valid graph)."""
        problems: List[str] = []
        for node in self.entry_points:
            if node not in self.assets:
                problems.append(f"entry point {node!r} is not an asset")
        if not self.impacts:
            problems.append("graph has no impact node")
        seen = set()
        for e in self.edges:
            if e.key in seen:
                problems.append(f"duplicate edge {e.key}")
            seen.add(e.key)
        reachable = self.reachable_from(self.entry_points)
        for impact in self.impacts:
            if impact not in reachable:
                problems.append(f"impact {impact!r} unreachable from entry points")
        orphans = [a for a in self.assets if a not in reachable]
        for o in sorted(orphans):
            problems.append(f"asset {o!r} unreachable from entry points")
        return problems

    def reachable_from(self, sources: Iterable[str]) -> set:
        adj: Dict[str, List[str]] = {}
        for e in self.edges:
            adj.setdefault(e.src, []).append(e.dst)
        seen = set(sources)
        stack = list(seen)
        while stack:
            cur = stack.pop()
            for nxt in adj.get(cur, ()):  # noqa: B007
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    # -- reporting --------------------------------------------------------
    def summary(self) -> Dict[str, object]:
        ent = sum(1 for e in self.edges if self.matrix_of(e) == "enterprise")
        ics = sum(1 for e in self.edges if self.matrix_of(e) == "ics")
        per_plane: Dict[str, int] = {}
        for a in self.assets.values():
            plane = self.zones[a.zone].plane
            per_plane[plane] = per_plane.get(plane, 0) + 1
        return {
            "zones": len(self.zones),
            "assets": len(self.assets),
            "edges": len(self.edges),
            "techniques": len({e.technique for e in self.edges}),
            "enterprise_edges": ent,
            "ics_edges": ics,
            "cross_zone_edges": sum(1 for e in self.edges if self.crosses_zone(e)),
            "impacts": len(self.impacts),
            "assets_per_plane": per_plane,
        }


@dataclass(frozen=True)
class Path:
    """An attack path: a sequence of edges from an entry point to an impact."""

    edges: Tuple[Edge, ...]

    @property
    def nodes(self) -> Tuple[str, ...]:
        if not self.edges:
            return ()
        return (self.edges[0].src,) + tuple(e.dst for e in self.edges)

    @property
    def techniques(self) -> Tuple[str, ...]:
        return tuple(e.technique for e in self.edges)

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def target(self) -> str:
        return self.edges[-1].dst

    def effort_h(self) -> float:
        return sum(e.effort_h for e in self.edges)

    def likelihood(self, portfolio: Optional["ControlLookup"] = None) -> float:
        """Probability that the *whole* path succeeds without containment."""
        acc = 1.0
        for e in self.edges:
            mit, upl = (0.0, 0.0) if portfolio is None else portfolio(e)
            p_eff, d_eff = e.effective(mit, upl)
            acc *= p_eff * (1.0 - d_eff)
        return acc

    def label(self) -> str:
        return " -> ".join(self.nodes)

    def zones(self, graph: AttackGraph) -> Tuple[str, ...]:
        out: List[str] = []
        for n in self.nodes:
            z = graph.assets[n].zone
            if not out or out[-1] != z:
                out.append(z)
        return tuple(out)


#: A callable ``edge -> (mitigation, detection_uplift)``.
ControlLookup = object


def technique_histogram(paths: Sequence[Path]) -> Dict[str, int]:
    hist: Dict[str, int] = {}
    for path in paths:
        for t in path.techniques:
            hist[t] = hist.get(t, 0) + 1
    return hist
