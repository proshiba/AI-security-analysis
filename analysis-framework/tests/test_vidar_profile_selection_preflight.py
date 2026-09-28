"""Vidarの候補選択を通常のAST監査と検体なし隔離importへ結び付ける。"""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from handler_catalog import (
    discover_handlers,
    preflight_handler_for_assessment,
    preflight_handler_runtime_import,
)


@pytest.mark.parametrize("handler_id", [
    "vidar:extractors.vidar.extractor.py:extract",
    "vidar:extractors.vidar.integrated.py:extract",
])
def test_unique_profile_selection_passes_static_and_isolated_import(handler_id):
    """source snapshotを監査し、handlerには検体も人工bytesも渡さない。"""
    specs = {spec.id: spec for spec in discover_handlers()}
    spec = specs[handler_id]
    result = preflight_handler_for_assessment(spec, actual_format="pe", input_size=1)
    assert result["eligible"] is True, result["blockers"]
    assert result["blockers"] == []
    for flag in ("sample_execution_allowed", "network_allowed", "filesystem_write_allowed"):
        assert result[flag] is False
    imported = preflight_handler_runtime_import(spec, static_preflight=result, timeout_seconds=10.0)
    assert imported["eligible"] is True, imported["blockers"]
    assert imported["attempted"] is True
    assert imported["handler_imported"] is True
    assert imported["isolated_process"] is True
    assert imported["sanitized_environment"] is True
    for flag in ("sample_execution_allowed", "network_allowed", "filesystem_write_allowed"):
        assert imported[flag] is False
