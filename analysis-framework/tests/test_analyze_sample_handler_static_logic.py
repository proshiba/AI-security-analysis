from __future__ import annotations

import json
import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analyze_sample as module  # noqa: E402


def test_successful_handler_representative_functions_are_collected(tmp_path: Path) -> None:
    handler_dir = tmp_path / "handlers"
    handler_dir.mkdir()
    artifact = handler_dir / "result.json"
    artifact.write_text(
        json.dumps(
            {
                "result": {
                    "representative_functions": [{"name": "ExecutePayload", "role": "stage_download_and_execution"}]
                }
            }
        ),
        encoding="utf-8",
    )

    records = module._handler_static_logic_records(
        tmp_path,
        [{"status": "succeeded", "result": "handlers/result.json"}],
    )

    assert records == [{"name": "ExecutePayload", "role": "stage_download_and_execution"}]


def test_failed_handler_records_are_not_collected(tmp_path: Path) -> None:
    assert (
        module._handler_static_logic_records(
            tmp_path,
            [{"status": "failed", "result": "handlers/result.json"}],
        )
        == []
    )
