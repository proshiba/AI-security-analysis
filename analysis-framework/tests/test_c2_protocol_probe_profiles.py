from __future__ import annotations

import sys
from pathlib import Path

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from build_all_c2_monitoring_targets import build_inventory  # noqa: E402
from c2_protocol_probe_profiles import (  # noqa: E402
    ProtocolProfileError,
    load_profiles,
    resolve_profile,
)


def test_registry_contains_reviewed_valleyrat_protocols() -> None:
    profiles = load_profiles()
    assert len(profiles) == 6
    assert {profile["method"] for profile in profiles.values()} == {
        "winos_heartbeat",
        "vvas_checkin",
        "n520_server_first",
    }


def test_profile_requires_exact_host_and_port() -> None:
    with pytest.raises(ProtocolProfileError):
        resolve_profile(
            "valleyrat-winos-heartbeat-20260727",
            "other.example",
            6685,
        )
    with pytest.raises(ProtocolProfileError):
        resolve_profile(
            "valleyrat-winos-heartbeat-20260727",
            "haochisadnka.cc",
            6698,
        )


def test_builder_adds_only_profiles_with_existing_repository_evidence(
    tmp_path: Path,
) -> None:
    results_root = tmp_path / "analysis-results"
    profile = load_profiles()["valleyrat-vvas-8bf54-6666"]
    evidence = tmp_path / profile["source"].split(":", 1)[0]
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}", encoding="utf-8")

    plan, inventory = build_inventory(results_root, generated_date="2026-08-02")
    assert [(item["host"], item["port"], item["method"]) for item in plan["targets"]] == [
        ("202.95.8.27", 6666, "vvas_checkin"),
        ("202.95.8.27", 8888, "vvas_checkin"),
    ]
    assert inventory["reviewed_protocol_target_count"] == 2
    assert inventory["reviewed_profile_only_target_count"] == 2
