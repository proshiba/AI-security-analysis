"""CLR境界修正がscript-only handlerの安全監査互換性を保つことを検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from handler_catalog import discover_handlers, preflight_handler_for_assessment


@pytest.fixture(scope="module")
def managed_handler_specs():
    return {spec.id: spec for spec in discover_handlers()}


@pytest.mark.parametrize("handler_id", [
    "asyncrat:extractors.asyncrat.extractor.py:extract",
    "donutloader:extractors.donutloader.extractor.py:extract",
    "purehvnc:analysis.framework.malware.purehvnc.extract.config.py:extract_config",
    "purehvnc:extractors.purehvnc.extractor.py:extract",
])
def test_managed_detector_handlers_remain_eligible_for_static_preflight(managed_handler_specs, handler_id):
    result = preflight_handler_for_assessment(
        managed_handler_specs[handler_id], actual_format="pe", input_size=1
    )
    assert result["eligible"] is True, result["blockers"]
    assert result["blockers"] == []
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False
