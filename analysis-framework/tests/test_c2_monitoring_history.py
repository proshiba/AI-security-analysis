from __future__ import annotations

import json
import sys
from pathlib import Path


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_monitoring_history as history  # noqa: E402


def target(host: str = "c2.example") -> dict:
    return {
        "target_id": host,
        "family": "fixture",
        "host": host,
        "port": 443,
        "protocol": "tcp",
        "method": "tcp_connect",
        "transport": "direct",
        "sample_sha256s": ["a" * 64],
        "associated_case_count": 1,
        "analyzed_dates": ["2026-08-01"],
        "sources": ["fixture"],
    }


def entry(
    timestamp: str,
    *,
    ips: list[str],
    reachable: bool,
    asn: int = 64500,
    organization: str = "Fixture Hosting",
    host: str = "c2.example",
) -> dict:
    state = (
        "transport_reachable_c2_not_confirmed"
        if reachable
        else "not_reachable_at_observation"
    )
    return {
        "target_id": host,
        "family": "fixture",
        "host": host,
        "port": 443,
        "protocol": "tcp",
        "transport": "direct",
        "method": "tcp_connect",
        "sample_sha256s": ["a" * 64],
        "observation": {
            "timestamp_utc": timestamp,
            "resolved_ips": ips,
            "alive": reachable,
            "target_contact_attempted": True,
            "target_connection_established": reachable,
        },
        "assessment": {
            "state": state,
            "reachability_confidence": 0.9 if reachable else 0.0,
        },
        "maxmind": {
            "records": [
                {
                    "ip": address,
                    "as": {
                        "autonomous_system_number": asn,
                        "autonomous_system_organization": organization,
                    },
                }
                for address in ips
            ]
        },
    }


def result(*entries: dict) -> dict:
    return {
        "schema_version": 1,
        "policy": {"network_enabled": True},
        "results": list(entries),
    }


def write_previous(root: Path, run_date: str, payload: dict) -> None:
    directory = root / run_date
    directory.mkdir(parents=True)
    (directory / "monitoring-results.json").write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )


def test_cloudflare_rotation_is_recorded_but_not_counted_as_infrastructure_change(
    tmp_path: Path,
) -> None:
    write_previous(
        tmp_path,
        "2026-08-01",
        result(
            entry(
                "2026-08-01T00:00:00+00:00",
                ips=["104.21.1.1"],
                reachable=True,
                asn=13335,
                organization="Cloudflare, Inc.",
            )
        ),
    )
    current = result(
        entry(
            "2026-08-02T00:00:00+00:00",
            ips=["172.67.1.1"],
            reachable=True,
            asn=13335,
            organization="Cloudflare, Inc.",
        )
    )

    enriched, monitoring, active = history.apply_monitoring_history(
        current,
        {"schema_version": 1, "targets": [target()]},
        history_root=tmp_path,
        current_run_name="2026-08-02",
    )

    dns = enriched["results"][0]["dns_tracking"]
    assert dns["raw_ip_change_count"] == 1
    assert dns["infrastructure_ip_change_count"] == 0
    assert dns["shared_cdn_rotation_ignored_count"] == 1
    assert dns["history"][-1]["change_classification"] == "shared_cdn_rotation_ignored"
    assert monitoring["endpoints"][0]["monitoring_lifecycle"]["status"] == "active_on"
    assert len(active["targets"]) == 1


def test_non_cdn_ip_change_is_counted_as_infrastructure_change(tmp_path: Path) -> None:
    write_previous(
        tmp_path,
        "2026-08-01",
        result(entry("2026-08-01T00:00:00+00:00", ips=["192.0.2.1"], reachable=True)),
    )
    current = result(
        entry("2026-08-02T00:00:00+00:00", ips=["198.51.100.2"], reachable=True)
    )

    enriched, _monitoring, _active = history.apply_monitoring_history(
        current,
        {"schema_version": 1, "targets": [target()]},
        history_root=tmp_path,
        current_run_name="2026-08-02",
    )

    dns = enriched["results"][0]["dns_tracking"]
    assert dns["raw_ip_change_count"] == 1
    assert dns["infrastructure_ip_change_count"] == 1
    assert dns["history"][-1]["change_classification"] == "infrastructure_ip_change"


def test_two_off_observations_spanning_seven_days_retire_target(tmp_path: Path) -> None:
    write_previous(
        tmp_path,
        "2026-08-01",
        result(entry("2026-08-01T00:00:00+00:00", ips=["192.0.2.1"], reachable=False)),
    )
    current = result(
        entry("2026-08-08T00:00:00+00:00", ips=["192.0.2.1"], reachable=False)
    )

    enriched, monitoring, active = history.apply_monitoring_history(
        current,
        {"schema_version": 1, "targets": [target()]},
        history_root=tmp_path,
        current_run_name="2026-08-08",
    )

    lifecycle = enriched["results"][0]["monitoring_lifecycle"]
    assert lifecycle["status"] == "retired_stopped"
    assert lifecycle["inactive_days"] == 7.0
    assert lifecycle["transition"] == "monitoring_stopped_after_7d_without_on"
    assert active["targets"] == []
    assert monitoring["endpoints"][0]["events"][-1]["event"] == lifecycle["transition"]


def test_single_off_or_unobserved_result_does_not_retire_target(tmp_path: Path) -> None:
    current = result(
        entry("2026-08-08T00:00:00+00:00", ips=["192.0.2.1"], reachable=False)
    )
    enriched, _monitoring, active = history.apply_monitoring_history(
        current,
        {"schema_version": 1, "targets": [target()]},
        history_root=tmp_path,
        current_run_name="2026-08-08",
    )
    assert enriched["results"][0]["monitoring_lifecycle"]["status"] == "active_grace"
    assert len(active["targets"]) == 1

    current["policy"]["network_enabled"] = False
    enriched, _monitoring, active = history.apply_monitoring_history(
        current,
        {"schema_version": 1, "targets": [target()]},
        history_root=tmp_path,
        current_run_name="2026-08-08",
    )
    assert enriched["results"][0]["monitoring_lifecycle"]["status"] == "active_unobserved"
    assert len(active["targets"]) == 1


def test_previous_active_targets_are_carried_forward_and_deduplicated() -> None:
    current_plan = {"schema_version": 1, "targets": [target("new.example")]}
    previous_plan = {"schema_version": 1, "targets": [target("old.example")]}

    merged, carried = history.carry_forward_active_targets(current_plan, previous_plan)

    assert carried == 1
    assert {item["host"] for item in merged["targets"]} == {"new.example", "old.example"}
    merged_again, carried_again = history.carry_forward_active_targets(merged, previous_plan)
    assert carried_again == 0
    assert len(merged_again["targets"]) == 2


def test_onion_is_not_carried_forward_when_policy_excludes_it() -> None:
    current_plan = {
        "schema_version": 1,
        "onion_excluded_by_policy": True,
        "targets": [target("new.example")],
    }
    previous_plan = {
        "schema_version": 1,
        "targets": [target("hiddenserviceexample.onion")],
    }

    merged, carried = history.carry_forward_active_targets(current_plan, previous_plan)

    assert carried == 0
    assert [item["host"] for item in merged["targets"]] == ["new.example"]