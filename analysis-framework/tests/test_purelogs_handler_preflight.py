"""PureLogs extractorが自動解析の静的依存監査を通過することを検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from handler_catalog import discover_handlers, preflight_handler_for_assessment


def test_purelogs_handler_is_eligible_for_static_preflight() -> None:
    """公平な文字列走査と複数設定源の比較を含むhandlerを自動実行可能に保つ。"""

    handlers = {spec.id: spec for spec in discover_handlers()}
    handler = handlers["purelogs:extractors.purelogs.extractor.py:extract"]

    result = preflight_handler_for_assessment(
        handler,
        actual_format="pe",
        input_size=4096,
    )

    assert result["eligible"] is True, result["blockers"]
    assert result["blockers"] == []
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False
    assert result["dependency_audit"]["issues"] == []
