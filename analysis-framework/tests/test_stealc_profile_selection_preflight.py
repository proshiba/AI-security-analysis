"""StealCの設定選択修正を通常の静的起動前監査へ結び付ける。"""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from handler_catalog import discover_handlers, preflight_handler_for_assessment


@pytest.mark.parametrize("handler_id", [
    "stealc:extractors.stealc.extractor.py:extract",
    "stealc:extractors.stealc.integrated.py:extract",
])
def test_validated_profile_selection_remains_static_only(handler_id):
    specs = {spec.id: spec for spec in discover_handlers()}
    result = preflight_handler_for_assessment(
        specs[handler_id], actual_format="pe", input_size=1
    )
    assert result["eligible"] is True, result["blockers"]
    assert result["blockers"] == []
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False
