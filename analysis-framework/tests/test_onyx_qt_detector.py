"""Onyx reviewed hash routeとterminal family意味論を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_ROOT = REPOSITORY_ROOT / "analysis-framework"
COMMON = FRAMEWORK_ROOT / "common"
for import_root in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def _load_detector():
    path = FRAMEWORK_ROOT / "malware" / "valleyrat" / "detect.py"
    spec = importlib.util.spec_from_file_location("onyx_valleyrat_detector", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


DETECTOR = _load_detector()


def test_reviewed_route_does_not_claim_terminal_family(monkeypatch) -> None:
    """exact routeは専用handler選択に使うが、終端family確定とは記録しない。"""

    data = b"MZ offline onyx routing fixture"
    digest = hashlib.sha256(data).hexdigest()
    monkeypatch.setitem(DETECTOR.KNOWN_CAMPAIGNS, digest, "onyx_qt_loader")
    monkeypatch.setitem(
        DETECTOR.REVIEWED_SAMPLES,
        digest,
        {
            "campaign": "onyx_qt_loader",
            "terminal_component": "onyx_terminal_stage",
            "terminal_family_attribution": "component_confirmed_family_unresolved",
            "routing_semantics": "reviewed_static_handler_route_not_family_confirmation",
        },
    )

    result = DETECTOR.detect(data, Path("fixture.exe"))
    route = result["campaigns"][0]
    semantics = result["observations"]["reviewed_routing_semantics"]

    assert result["matched"] is True
    assert route["campaign_type"] == "onyx_qt_loader"
    assert route["attribution_scope"] == "reviewed_component_handler_route"
    assert route["terminal_family_confirmed"] is False
    assert semantics == {
        "scope": "component_handler_routing",
        "terminal_component": "onyx_terminal_stage",
        "terminal_family_attribution": "component_confirmed_family_unresolved",
        "terminal_family_confirmed": False,
    }
