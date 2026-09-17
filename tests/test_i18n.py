import pytest

from capm.architecture import build_graph
from capm.controls import CONTROLS, SCENARIOS
from capm.i18n import (ASSETS_PT, CONFIDENCE_PT, CONTROLS_PT, PLANES_PT, PROFILES_PT,
                       SCENARIOS_PT, asset, control)
from capm.incidents import load_incidents
from capm.risk import ACTOR_PROFILES


def test_every_asset_has_a_portuguese_name():
    graph = build_graph()
    missing = [a for a in graph.assets if a not in ASSETS_PT]
    assert missing == []


def test_every_control_and_scenario_has_a_portuguese_name():
    assert [c for c in CONTROLS if c not in CONTROLS_PT] == []
    assert [s for s in SCENARIOS if s not in SCENARIOS_PT] == []


def test_every_confidence_label_and_profile_is_translated():
    labels = {i.confidence for i in load_incidents()}
    assert labels <= set(CONFIDENCE_PT)
    assert set(ACTOR_PROFILES) <= set(PROFILES_PT)


def test_every_plane_is_translated():
    graph = build_graph()
    planes = {z.plane for z in graph.zones.values()}
    assert planes <= set(PLANES_PT)


def test_lookup_falls_back_to_english():
    assert asset("ops_mes", "en", "Manufacturing execution system") == \
        "Manufacturing execution system"
    assert asset("ops_mes", "pt").startswith("Sistema de execu")
    assert control("C08", "en", CONTROLS["C08"].name) == CONTROLS["C08"].name
    assert control("C08", "pt").startswith("Backups imut")
    assert asset("not_an_asset", "pt", "fallback") == "fallback"


def test_translations_do_not_collide():
    assert len(set(ASSETS_PT.values())) == len(ASSETS_PT)
    assert len(set(CONTROLS_PT.values())) == len(CONTROLS_PT)


def test_baseline_names_are_translated():
    from capm.architecture import build_graph as _build
    from capm.evaluation import build_baselines
    import importlib.util
    import os
    import sys

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "build_paper_assets", os.path.join(root, "experiments", "build_paper_assets.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_paper_assets"] = module
    spec.loader.exec_module(module)

    names = {b.name for b in build_baselines(_build())} | {"CAPM path likelihood"}
    missing = [n for n in names if n not in module.BASELINE_NAMES_PT]
    assert missing == []


def test_every_control_has_a_short_chart_label():
    from capm.controls import CONTROLS as _CONTROLS
    from capm.i18n import CONTROLS_SHORT_EN, CONTROLS_SHORT_PT, control_short

    assert set(CONTROLS_SHORT_EN) == set(_CONTROLS)
    assert set(CONTROLS_SHORT_PT) == set(_CONTROLS)
    for cid in _CONTROLS:
        for lang in ("en", "pt"):
            label = control_short(cid, lang)
            assert 0 < len(label) <= 34, f"{cid} label too long for an axis: {label}"
    assert control_short("C08", "en") == "immutable tested backups"
    assert control_short("C99", "en") == "C99"
