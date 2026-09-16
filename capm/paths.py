"""Attack-path enumeration, ranking and choke-point analysis.

A path's *likelihood* is the product over its steps of the probability that the
step succeeds and is not contained,

    L(pi) = prod_{e in pi} p'(e) * (1 - delta'(e)),

where ``p'`` and ``delta'`` already include the effect of the deployed control
portfolio. Maximising ``L`` is equivalent to minimising the additive weight
``w(e) = -log(p'(e) (1 - delta'(e)))``, so the most likely path is a shortest
path under ``w`` (Dijkstra) and the *k* most likely paths follow from Yen's
algorithm. This is the standard log-transform used in probabilistic attack-graph
analysis; it keeps the ranking exact while avoiding numerical underflow.
"""

from __future__ import annotations

import heapq
import math
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .model import AttackGraph, Edge, Path

Lookup = Optional[Callable[[Edge], Tuple[float, float]]]


def edge_weight(edge: Edge, portfolio: Lookup = None) -> float:
    mit, upl = (0.0, 0.0) if portfolio is None else portfolio(edge)
    p_eff, d_eff = edge.effective(mit, upl)
    return -math.log(p_eff * (1.0 - d_eff))


def _adjacency(graph: AttackGraph) -> Dict[str, List[Edge]]:
    adj: Dict[str, List[Edge]] = {}
    for e in graph.edges:
        adj.setdefault(e.src, []).append(e)
    return adj


def best_path(
    graph: AttackGraph,
    source: str,
    target: str,
    portfolio: Lookup = None,
    banned_edges: Optional[Set[Tuple[str, str, str]]] = None,
    banned_nodes: Optional[Set[str]] = None,
) -> Optional[Path]:
    """Most likely path from ``source`` to ``target`` (None if unreachable)."""
    banned_edges = banned_edges or set()
    banned_nodes = banned_nodes or set()
    if source in banned_nodes:
        return None
    adj = _adjacency(graph)
    dist: Dict[str, float] = {source: 0.0}
    prev: Dict[str, Edge] = {}
    visited: Set[str] = set()
    heap: List[Tuple[float, str]] = [(0.0, source)]
    while heap:
        d, node = heapq.heappop(heap)
        if node in visited:
            continue
        visited.add(node)
        if node == target:
            break
        for e in adj.get(node, ()):  # noqa: B007
            if e.key in banned_edges or e.dst in banned_nodes:
                continue
            nd = d + edge_weight(e, portfolio)
            if nd < dist.get(e.dst, math.inf) - 1e-15:
                dist[e.dst] = nd
                prev[e.dst] = e
                heapq.heappush(heap, (nd, e.dst))
    if target not in dist:
        return None
    chain: List[Edge] = []
    cur = target
    while cur != source:
        e = prev[cur]
        chain.append(e)
        cur = e.src
    return Path(tuple(reversed(chain)))


def k_best_paths(
    graph: AttackGraph,
    source: str,
    target: str,
    k: int = 10,
    portfolio: Lookup = None,
) -> List[Path]:
    """The ``k`` most likely loop-free paths (Yen's algorithm)."""
    first = best_path(graph, source, target, portfolio)
    if first is None:
        return []
    accepted: List[Path] = [first]
    candidates: List[Tuple[float, int, Path]] = []
    counter = 0
    while len(accepted) < k:
        prev_path = accepted[-1]
        for i in range(prev_path.length):
            spur_node = prev_path.edges[i].src
            root_edges = prev_path.edges[:i]
            banned_edges: Set[Tuple[str, str, str]] = set()
            for p in accepted:
                if p.length > i and p.edges[:i] == root_edges:
                    banned_edges.add(p.edges[i].key)
            banned_nodes = {e.src for e in root_edges}
            spur = best_path(graph, spur_node, target, portfolio, banned_edges, banned_nodes)
            if spur is None:
                continue
            total = Path(tuple(root_edges) + spur.edges)
            if any(total.edges == p.edges for p in accepted):
                continue
            weight = -math.log(max(total.likelihood(portfolio), 1e-300))
            entry = (weight, counter, total)
            counter += 1
            if not any(c[2].edges == total.edges for c in candidates):
                heapq.heappush(candidates, entry)
        if not candidates:
            break
        accepted.append(heapq.heappop(candidates)[2])
    return accepted


def enumerate_paths(
    graph: AttackGraph,
    source: str,
    targets: Optional[Iterable[str]] = None,
    max_length: int = 12,
    limit: int = 2_000_000,
) -> List[Path]:
    """Depth-first enumeration of all loop-free paths up to ``max_length``."""
    goals = set(targets) if targets is not None else set(graph.impacts)
    adj = _adjacency(graph)
    out: List[Path] = []
    stack: List[Tuple[str, List[Edge], Set[str]]] = [(source, [], {source})]
    while stack:
        node, chain, seen = stack.pop()
        if len(out) >= limit:
            break
        for e in adj.get(node, ()):  # noqa: B007
            if e.dst in seen:
                continue
            new_chain = chain + [e]
            if e.dst in goals:
                out.append(Path(tuple(new_chain)))
                continue  # impact nodes are terminal
            if len(new_chain) < max_length:
                stack.append((e.dst, new_chain, seen | {e.dst}))
    return out


def rank_paths(paths: Sequence[Path], portfolio: Lookup = None) -> List[Tuple[Path, float]]:
    scored = [(p, p.likelihood(portfolio)) for p in paths]
    scored.sort(key=lambda t: (-t[1], t[0].length))
    return scored


def choke_points(
    scored: Sequence[Tuple[Path, float]],
    graph: AttackGraph,
) -> Tuple[List[Tuple[str, float, int]], List[Tuple[Tuple[str, str, str], float, int]]]:
    """Likelihood-weighted node and conduit criticality.

    A node's criticality is the share of the total path likelihood mass that
    traverses it; the same is computed for edges (conduits). This is the
    attack-graph analogue of flow betweenness and identifies where a single
    control removes the most aggregate risk.
    """
    total = sum(w for _, w in scored) or 1.0
    node_mass: Dict[str, float] = {}
    node_count: Dict[str, int] = {}
    edge_mass: Dict[Tuple[str, str, str], float] = {}
    edge_count: Dict[Tuple[str, str, str], int] = {}
    for path, w in scored:
        for n in path.nodes:
            node_mass[n] = node_mass.get(n, 0.0) + w
            node_count[n] = node_count.get(n, 0) + 1
        for e in path.edges:
            edge_mass[e.key] = edge_mass.get(e.key, 0.0) + w
            edge_count[e.key] = edge_count.get(e.key, 0) + 1
    nodes = sorted(
        ((n, m / total, node_count[n]) for n, m in node_mass.items()),
        key=lambda t: -t[1],
    )
    edges = sorted(
        ((k, m / total, edge_count[k]) for k, m in edge_mass.items()),
        key=lambda t: -t[1],
    )
    # drop the attacker node and pure modelling artefacts from node ranking
    nodes = [t for t in nodes if t[0] not in graph.entry_points]
    return nodes, edges


def zone_transitions(path: Path, graph: AttackGraph) -> int:
    return sum(1 for e in path.edges if graph.crosses_zone(e))


def purdue_depth(path: Path, graph: AttackGraph) -> int:
    """Lowest Purdue level touched by the path (5 = external, 0 = process)."""
    levels = [graph.purdue_of(n) for n in path.nodes if graph.assets[n].zone != "Z-CONS"]
    return min(levels) if levels else 5
