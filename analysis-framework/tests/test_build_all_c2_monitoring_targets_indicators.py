"""iocs.json／indicators.json統合走査の回帰テスト。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from build_all_c2_monitoring_targets import build_inventory


def _write_case(root: Path, sample: str, payload: dict, name: str) -> None:
    path = root / "fixture" / "versions" / "unknown" / "cases" / sample / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_indicator_only_case_is_included(tmp_path: Path) -> None:
    malware_root = tmp_path / "malware"
    _write_case(
        malware_root,
        "e" * 64,
        {
            "indicators": [
                {
                    "type": "endpoint",
                    "value": "192.144.32.84:16383",
                    "role": "c2_endpoint",
                    "confidence": "confirmed_static_config",
                }
            ]
        },
        "indicators.json",
    )
    plan, inventory = build_inventory(malware_root, generated_date="2026-08-09")
    assert any(
        target["host"] == "192.144.32.84" and target["port"] == 16383
        for target in plan["targets"]
    )
    assert inventory["schema_version"] == 2
    assert inventory["scanned_ioc_file_count"] == 1
    assert inventory["scanned_iocs_json_file_count"] == 0
    assert inventory["scanned_indicators_json_file_count"] == 1


def test_duplicate_evidence_across_both_case_files_is_counted_once(tmp_path: Path) -> None:
    malware_root = tmp_path / "malware"
    sample = "f" * 64
    payload = {
        "indicators": [
            {
                "type": "endpoint",
                "value": "duplicate.example:4444",
                "role": "c2_endpoint",
                "confidence": "confirmed",
            }
        ]
    }
    _write_case(malware_root, sample, payload, "iocs.json")
    _write_case(malware_root, sample, payload, "indicators.json")
    plan, inventory = build_inventory(malware_root, generated_date="2026-08-09")
    matches = [target for target in plan["targets"] if target["host"] == "duplicate.example"]
    assert len(matches) == 1
    assert inventory["candidate_evidence_record_count"] == 1
    assert inventory["duplicate_evidence_record_count"] == 1
    assert inventory["scanned_ioc_file_count"] == 2
    assert inventory["scanned_iocs_json_file_count"] == 1
    assert inventory["scanned_indicators_json_file_count"] == 1


def test_malformed_ioc_and_indicator_files_are_reported_fail_closed(tmp_path: Path) -> None:
    results = tmp_path / "analysis-results"
    case = results / "malware" / "fixture" / "versions" / "unknown" / "cases" / ("1" * 64)
    case.mkdir(parents=True)
    (case / "iocs.json").write_text("[]", encoding="utf-8")
    (case / "indicators.json").write_text(
        '{"indicators":[],"indicators":[]}',
        encoding="utf-8",
    )
    plan, inventory = build_inventory(results, generated_date="2026-08-09")
    assert inventory["scanned_ioc_file_count"] == 2
    assert inventory["parse_error_count"] == 2
    assert len(inventory["parse_errors"]) == 2
    assert not any("fixture" in str(target.get("family")) for target in plan["targets"])
