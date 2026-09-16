"""CAPM -- Cyberattack Path Model for automotive manufacturing.

A dependency-free reference implementation of the attack-path model described in
"From Cloud to Assembly Line: Modelling Cyberattack Paths in Automotive
Manufacturing as Critical Infrastructure".
"""

__version__ = "1.0.0"

from .architecture import build_graph  # noqa: F401
from .controls import CONTROLS, Portfolio, SCENARIOS  # noqa: F401
from .incidents import analyse_corpus, load_incidents  # noqa: F401
from .model import AttackGraph, Edge, Path  # noqa: F401
from .paths import enumerate_paths, k_best_paths, rank_paths  # noqa: F401
from .risk import SimulationConfig, simulate  # noqa: F401

__all__ = [
    "build_graph", "AttackGraph", "Edge", "Path", "CONTROLS", "Portfolio", "SCENARIOS",
    "enumerate_paths", "k_best_paths", "rank_paths", "simulate", "SimulationConfig",
    "load_incidents", "analyse_corpus", "__version__",
]
