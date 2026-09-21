"""NanoCore設定復号器の自動実行契約を検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

FRAMEWORK = Path(__file__).resolve().parents[1]
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from handler_catalog import discover_handlers, preflight_handler_for_assessment  # noqa: E402


def test_nanocore_decryption_handler_is_bounded_and_preflight_eligible() -> None:
    """decrepit TripleDESの使用後もPE限定で隔離workerへ進める。"""

    handler = next(spec for spec in discover_handlers() if spec.family == "nanocore" and spec.automatic)
    assert handler.input_formats == ("pe",)
    assessment = preflight_handler_for_assessment(handler, actual_format="pe", input_size=4096)
    assert assessment["eligible"] is True
    assert assessment["blockers"] == []
    assert assessment["sample_execution_allowed"] is False
    assert assessment["network_allowed"] is False
    assert assessment["filesystem_write_allowed"] is False
