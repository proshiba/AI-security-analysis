"""StealC v1/v2統合抽出器が自動解析へ到達することを確認する。"""

from __future__ import annotations

import sys
from pathlib import Path


COMMON_ROOT = Path(__file__).resolve().parents[1] / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

from handler_catalog import (  # noqa: E402
    _candidate_handler_specs,
    discover_handlers,
    load_handler,
    preflight_handler_for_assessment,
    preflight_handler_runtime_import,
)


def test_stealc_integrated_handler_is_discovered_and_loadable() -> None:
    handlers = [item for item in discover_handlers() if item.family == "stealc"]
    paths = {item.relative_path: item for item in handlers}
    legacy = paths["extractors/stealc/extractor.py"]
    integrated = paths["extractors/stealc/integrated.py"]

    assert legacy.automatic is True
    assert integrated.automatic is True
    assert integrated.invocation == "bytes_name"
    handler, invocation = load_handler(integrated)
    assert invocation == "bytes_name"
    result = handler(b"not-a-pe", "fixture.bin")
    assert result["config"]["profile"] is None
    assert result["executed"] is False
    assert result["network_contacted"] is False

    preflight = preflight_handler_for_assessment(
        integrated, actual_format="pe", input_size=658_432
    )
    assert preflight["eligible"] is True
    runtime = preflight_handler_runtime_import(
        integrated, static_preflight=preflight, timeout_seconds=20
    )
    assert runtime["eligible"] is True
    assert runtime["network_allowed"] is False


def test_reviewed_integrated_adapters_are_allowlisted() -> None:
    integrated = {
        item.family: item
        for item in discover_handlers()
        if item.relative_path.endswith("/integrated.py")
    }
    assert set(integrated) == {
        "asyncrat",
        "dcrat",
        "njrat",
        "stealc",
        "venomrat",
        "vidar",
        "xworm",
    }
    vidar = integrated["vidar"]
    preflight = preflight_handler_for_assessment(
        vidar, actual_format="pe", input_size=1024
    )
    assert preflight["eligible"] is True
    runtime = preflight_handler_runtime_import(
        vidar, static_preflight=preflight, timeout_seconds=20
    )
    assert runtime["eligible"] is True
    assert runtime["network_allowed"] is False


def test_vidar_automatic_selection_uses_semantic_adapter_only() -> None:
    catalog = discover_handlers()
    selected, basis, _fallback = _candidate_handler_specs(
        {
            "family": "vidar",
            "assessment_eligible": True,
            "routing_mode": "candidate_verification",
            "sources": ["external_metadata"],
            "caller_selected_string": False,
        },
        catalog,
        {"status": "no_trusted_detector"},
    )
    paths = {item.relative_path for item in selected}
    assert "extractors/vidar/integrated.py" in paths
    assert "extractors/vidar/extractor.py" not in paths
    assert basis["selected_handler_count"] == len(selected)
