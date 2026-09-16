"""The empirical incident corpus and its reconciliation with the model.

``data/incidents.csv`` holds 20 publicly reported incidents that hit automotive
manufacturing between 2017 and 2025. Every record carries a *reconstructed
path*: the sequence of reference-architecture assets that public reporting
supports. The reconstruction is deliberately coarse -- with the exception of a
handful of cases, victims do not publish forensic detail -- so each record also
carries a confidence label:

``high``       the sequence follows directly from the victim's own disclosure;
``medium``     the sequence follows from consistent reporting by several sources;
``low``        the entry vector is reported but the internal propagation is inferred;
``disputed``   sources disagree on the entry vector (the reconstruction is one
               of the reported hypotheses);
``attempted``  the campaign was interrupted before impact;
``partial``    the observed consequence lies partly outside the plant-centric
               scope of the model.

Experiment E2 uses this corpus to test *structural adequacy*: can the reference
graph express what actually happened? Cases that it cannot express are reported
as coverage gaps rather than hidden.
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .model import AttackGraph, Edge, Path

DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "incidents.csv")


@dataclass(frozen=True)
class Incident:
    id: str
    year: int
    victim: str
    role: str
    actor: str
    initial_access: str
    planes: Tuple[str, ...]
    primary_impact: str
    disruption: str
    node_path: Tuple[str, ...]
    confidence: str
    sources: Tuple[str, ...]

    @property
    def is_supply_chain(self) -> bool:
        return "supply_chain" in self.planes

    @property
    def is_availability(self) -> bool:
        return self.primary_impact == "imp_prod_stop"


def load_incidents(path: str = DATA_PATH) -> List[Incident]:
    out: List[Incident] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out.append(Incident(
                id=row["id"],
                year=int(row["year"]),
                victim=row["victim"],
                role=row["role"],
                actor=row["actor_or_malware"],
                initial_access=row["initial_access_public"],
                planes=tuple(p for p in row["planes"].split(";") if p),
                primary_impact=row["primary_impact"],
                disruption=row["disruption_reported"],
                node_path=tuple(n for n in row["attack_path"].split("|") if n),
                confidence=row["path_confidence"],
                sources=tuple(s for s in row["sources"].split(";") if s),
            ))
    return out


def realise(graph: AttackGraph, nodes: Sequence[str]) -> Tuple[Optional[Path], Optional[str]]:
    """Turn a node sequence into a model path, or explain why it is not one."""
    chain: List[Edge] = []
    for src, dst in zip(nodes, nodes[1:]):
        if src not in graph.assets:
            return None, f"unknown asset {src!r}"
        if dst not in graph.assets:
            return None, f"unknown asset {dst!r}"
        options = [e for e in graph.edges if e.src == src and e.dst == dst]
        if not options:
            return None, f"no modelled step {src} -> {dst}"
        options.sort(key=lambda e: -(e.p * (1.0 - e.delta)))
        chain.append(options[0])
    return Path(tuple(chain)), None


@dataclass
class CorpusReport:
    total: int
    representable: int
    gaps: List[Tuple[str, str]]
    per_plane: Dict[str, int]
    per_impact: Dict[str, int]
    per_role: Dict[str, int]
    per_year: Dict[int, int]
    likelihood: Dict[str, float]
    supply_chain_share: float
    availability_share: float
    ot_interaction_share: float

    @property
    def coverage(self) -> float:
        return self.representable / float(self.total) if self.total else 0.0


def analyse_corpus(graph: AttackGraph, incidents: Optional[Sequence[Incident]] = None) -> CorpusReport:
    incidents = list(incidents or load_incidents())
    gaps: List[Tuple[str, str]] = []
    likelihood: Dict[str, float] = {}
    representable = 0
    per_plane: Dict[str, int] = {}
    per_impact: Dict[str, int] = {}
    per_role: Dict[str, int] = {}
    per_year: Dict[int, int] = {}
    ot_touch = 0
    for inc in incidents:
        path, err = realise(graph, inc.node_path)
        if path is None:
            gaps.append((inc.id, err or "unspecified"))
        else:
            representable += 1
            likelihood[inc.id] = path.likelihood()
            if any(graph.zone_of(n).plane == "ot" and graph.purdue_of(n) <= 3
                   for n in path.nodes):
                ot_touch += 1
        for plane in inc.planes:
            per_plane[plane] = per_plane.get(plane, 0) + 1
        per_impact[inc.primary_impact] = per_impact.get(inc.primary_impact, 0) + 1
        per_role[inc.role] = per_role.get(inc.role, 0) + 1
        per_year[inc.year] = per_year.get(inc.year, 0) + 1
    n = float(len(incidents)) or 1.0
    return CorpusReport(
        total=len(incidents),
        representable=representable,
        gaps=gaps,
        per_plane=per_plane,
        per_impact=per_impact,
        per_role=per_role,
        per_year=dict(sorted(per_year.items())),
        likelihood=likelihood,
        supply_chain_share=sum(1 for i in incidents if i.is_supply_chain) / n,
        availability_share=sum(1 for i in incidents if i.is_availability) / n,
        ot_interaction_share=ot_touch / n,
    )


def leave_one_out_report(incidents: Optional[Sequence[Incident]] = None) -> Dict[str, object]:
    """Ablation testing whether each incident is expressible *without* the steps
    that were added because of it.

    Because the reference graph was informed by the corpus, plain coverage is a
    consistency check rather than a validation. This ablation is stricter: for
    each incident ``X`` it rebuilds the graph after deleting every edge whose
    only supporting evidence is ``X`` and then asks whether ``X`` is still a
    path of the reduced model. A high score means the corpus is expressed by
    structure that generalises across incidents rather than by steps
    hand-fitted to single cases.
    """
    from .architecture import EDGES, build_graph
    from .model import Edge

    incidents = list(incidents or load_incidents())
    survived: List[str] = []
    failed: List[Tuple[str, str]] = []
    failed_internal: List[Tuple[str, str]] = []
    survived_internal: List[str] = []
    for inc in incidents:
        graph = build_graph()
        entries = set(graph.entry_points)
        keep, keep_internal = [], []
        for e in graph.edges:
            ev = set(e.evidence)
            solely = bool(ev) and ev == {inc.id}
            if not solely:
                keep.append(e)
                keep_internal.append(e)
            elif e.src in entries:
                # initial-access steps are idiosyncratic by nature: the second
                # ablation keeps them and removes only internal propagation
                keep_internal.append(e)
        graph_internal = build_graph()
        graph_internal.edges = keep_internal
        path_i, err_i = realise(graph_internal, inc.node_path)
        if path_i is not None:
            survived_internal.append(inc.id)
        else:
            failed_internal.append((inc.id, err_i or ""))
        graph.edges = keep
        path, err = realise(graph, inc.node_path)
        if path is None:
            failed.append((inc.id, err or ""))
        else:
            survived.append(inc.id)
    n = float(len(incidents)) or 1.0
    return {
        "total": len(incidents),
        "survived": len(survived),
        "score": len(survived) / n,
        "survived_internal": len(survived_internal),
        "score_internal": len(survived_internal) / n,
        "failed": failed,
        "failed_internal": failed_internal,
    }
