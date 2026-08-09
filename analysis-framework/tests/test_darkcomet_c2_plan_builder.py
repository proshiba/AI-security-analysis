from __future__ import annotations

import sys
from pathlib import Path

COMMON = Path(__file__).parents[1] / "common"
REPOSITORY_ROOT = Path(__file__).parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from build_all_c2_monitoring_targets import build_inventory
from c2_protocol_probe_profiles import load_profiles


def test_builder_adds_three_exact_darkcomet_profiles_only_with_valid_public_evidence(
    tmp_path: Path,
) -> None:
    profiles = load_profiles()
    profile = profiles["darkcomet-b9b052df-f168-name-1604"]
    root = Path("\\\\?\\" + str(tmp_path.resolve()))
    relative = str(profile["source"]).split(":", 1)[0]
    evidence = root / relative
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes((REPOSITORY_ROOT / relative).read_bytes())

    plan, inventory = build_inventory(
        root / "analysis-results",
        generated_date="2026-08-09",
    )
    selected = [
        target
        for target in plan["targets"]
        if target.get("protocol_profile_id", "").startswith("darkcomet-b9b052df-")
    ]
    assert {(target["host"], target["port"]) for target in selected} == {
        ("f168.name", 1604),
        ("f168.com.co", 1604),
        ("f168hi.com", 1604),
    }
    assert {target["protocol"] for target in selected} == {"darkcomet"}
    assert {target["method"] for target in selected} == {"darkcomet_server_first_idtype"}
    assert {target["maximum_response_bytes"] for target in selected} == {12}
    assert all(len(target["protocol_profile_evidence_sha256"]) == 64 for target in selected)
    assert {target["protocol_profile_evidence_source"] for target in selected} == {
        profiles[target["protocol_profile_id"]]["source"] for target in selected
    }
    assert inventory["reviewed_protocol_target_count"] == 3
    assert inventory["reviewed_profile_only_target_count"] == 3


def test_builder_keeps_darkcomet_profiles_blocked_without_or_with_invalid_evidence(
    tmp_path: Path,
) -> None:
    plan, inventory = build_inventory(
        tmp_path / "analysis-results",
        generated_date="2026-08-09",
    )
    assert not [
        target
        for target in plan["targets"]
        if target.get("protocol_profile_id", "").startswith("darkcomet-b9b052df-")
    ]
    assert inventory["reviewed_protocol_target_count"] == 0
    assert inventory["reviewed_profile_only_target_count"] == 0
