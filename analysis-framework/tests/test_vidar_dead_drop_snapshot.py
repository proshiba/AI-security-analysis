"""Vidar dead-drop snapshot相関器を検証する。"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

VIDAR = Path(__file__).parents[1] / "malware" / "vidar"
if str(VIDAR) not in sys.path:
    sys.path.insert(0, str(VIDAR))

MODULE = importlib.import_module("dead_drop_snapshot")


def _write_fixture(tmp_path: Path, endpoint: str = "8.8.8.8:443") -> tuple[Path, Path]:
    config = {
        "sha256": "a" * 64,
        "dead_drop": [
            {"value": "https://telegram.me/example", "role": "dead_drop.telegram", "c2": False},
            {
                "value": "https://www.pinterest.com/example",
                "role": "dead_drop.pinterest_profile",
                "c2": False,
            },
            {
                "value": "https://steamcommunity.com/profiles/76561190000000000",
                "role": "dead_drop.steam_profile",
                "c2": False,
            },
        ],
    }
    snapshots = []
    for service, source, body in (
        ("telegram", config["dead_drop"][0]["value"], f"status {endpoint}"),
        ("pinterest", config["dead_drop"][1]["value"], f"description={endpoint}"),
    ):
        path = tmp_path / f"{service}.html"
        path.write_text(body, encoding="utf-8")
        snapshots.append(
            {
                "service": service,
                "source_url": source,
                "captured_at": "2026-08-19T00:00:00Z",
                "body_path": path.name,
                "body_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    manifest = {
        "schema_version": 1,
        "sample_sha256": "a" * 64,
        "snapshots": snapshots,
        "safety": {
            "sample_executed": False,
            "network_contacted_during_analysis": False,
            "snapshots_captured_outside_this_tool": True,
        },
    }
    config_path = tmp_path / "config.json"
    manifest_path = tmp_path / "manifest.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return config_path, manifest_path


def test_two_distinct_services_recover_one_candidate_without_confirming_c2(tmp_path: Path) -> None:
    config, manifest = _write_fixture(tmp_path)
    result = MODULE.analyze_snapshot_set(config, manifest)

    assert result["status"] == "correlated_final_c2_candidate"
    assert result["final_c2_candidate"] == "8.8.8.8:443"
    assert result["probable_c2"] is True
    assert result["c2_confirmed"] is False
    assert result["corroborating_service_count"] == 2
    assert result["safety"]["network_contacted"] is False
    assert result["safety"]["shared_service_is_c2"] is False


def test_one_service_is_inconclusive(tmp_path: Path) -> None:
    config, manifest = _write_fixture(tmp_path)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["snapshots"] = document["snapshots"][:1]
    manifest.write_text(json.dumps(document), encoding="utf-8")

    result = MODULE.analyze_snapshot_set(config, manifest)

    assert result["status"] == "inconclusive_snapshot_set"
    assert result["final_c2_candidate"] is None


@pytest.mark.parametrize("endpoint", ("127.0.0.1:443", "10.0.0.1:80", "999.1.1.1:443"))
def test_non_public_or_invalid_ip_is_not_a_candidate(tmp_path: Path, endpoint: str) -> None:
    config, manifest = _write_fixture(tmp_path, endpoint)
    assert MODULE.analyze_snapshot_set(config, manifest)["final_c2_candidate"] is None


def test_snapshot_hash_mutation_is_rejected(tmp_path: Path) -> None:
    config, manifest = _write_fixture(tmp_path)
    (tmp_path / "telegram.html").write_text("changed", encoding="utf-8")
    with pytest.raises(MODULE.VidarDeadDropError, match="SHA-256"):
        MODULE.analyze_snapshot_set(config, manifest)


def test_unconfigured_source_is_rejected(tmp_path: Path) -> None:
    config, manifest = _write_fixture(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["snapshots"][0]["source_url"] = "https://t.me/unrelated"
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(MODULE.VidarDeadDropError, match="静的config"):
        MODULE.analyze_snapshot_set(config, manifest)


def test_multiple_candidates_in_one_snapshot_are_rejected(tmp_path: Path) -> None:
    config, manifest = _write_fixture(tmp_path)
    path = tmp_path / "telegram.html"
    path.write_text("8.8.8.8:443 and 1.1.1.1:443", encoding="utf-8")
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["snapshots"][0]["body_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(MODULE.VidarDeadDropError, match="複数endpoint"):
        MODULE.analyze_snapshot_set(config, manifest)


def test_duplicate_key_is_rejected(tmp_path: Path) -> None:
    config, manifest = _write_fixture(tmp_path)
    original = config.read_text(encoding="utf-8")
    config.write_text(original[:-1] + ',"sha256":"' + "b" * 64 + '"}', encoding="utf-8")
    with pytest.raises(MODULE.VidarDeadDropError, match="重複"):
        MODULE.analyze_snapshot_set(config, manifest)


def test_positive_safety_flag_is_rejected(tmp_path: Path) -> None:
    config, manifest = _write_fixture(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    unsafe = deepcopy(value)
    unsafe["safety"]["network_contacted_during_analysis"] = True
    manifest.write_text(json.dumps(unsafe), encoding="utf-8")
    with pytest.raises(MODULE.VidarDeadDropError, match="safety"):
        MODULE.analyze_snapshot_set(config, manifest)
