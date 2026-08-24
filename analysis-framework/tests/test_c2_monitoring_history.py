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


def test_previous_daily_handoff_tags_are_not_carried_into_current_run() -> None:
    current_handoff = {"source_date": "2026-08-24"}
    previous_handoff = {"source_date": "2026-08-23"}
    current_plan = {
        "schema_version": 1,
        "daily_source_handoffs": [current_handoff],
        "targets": [target("new.example")],
    }
    prior_target = target("old.example")
    prior_target["daily_source_dates"] = ["2026-08-23"]
    previous_plan = {
        "schema_version": 1,
        "daily_source_handoffs": [previous_handoff],
        "targets": [prior_target],
    }

    merged, carried = history.carry_forward_active_targets(current_plan, previous_plan)

    assert carried == 1
    carried_target = next(item for item in merged["targets"] if item["host"] == "old.example")
    assert "daily_source_dates" not in carried_target
    assert merged["daily_source_handoffs"] == [current_handoff]
    assert current_plan["targets"] == [target("new.example")]
    assert previous_plan["targets"][0]["daily_source_dates"] == ["2026-08-23"]


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


def rat_activity(*, command_count: int, confirmed: bool) -> dict:
    commands = (
        [
            {
                "session_id": "session-001",
                "message_kind": "system_info_request",
                "wire_sha256": "b" * 64,
            }
        ]
        if command_count
        else []
    )
    return {
        "schema_version": 1,
        "session_count": 1,
        "latest_session_at_utc": "2026-08-09T00:00:02+00:00",
        "connection_established_count": 1,
        "handshake_confirmed_count": int(confirmed),
        "c2_confirmed_session_count": int(confirmed),
        "command_count": command_count,
        "command_fingerprints": commands,
        "synthetic_reply_count": command_count,
        "synthetic_reply_sent": bool(command_count),
        "status_counts": {"completed": 1},
        "task_executed": False,
        "real_effect_performed": False,
        "payload_download_attempted": False,
        "followup_network_attempted": False,
        "raw_transcript_published": False,
    }


def test_protocol_activity_is_tracked_separately_and_positive_evidence_marks_on(
    tmp_path: Path,
) -> None:
    current_entry = entry(
        "2026-08-09T00:00:00+00:00",
        ips=["192.0.2.1"],
        reachable=False,
    )
    current_entry["rat_emulation"] = rat_activity(command_count=1, confirmed=True)
    current = result(current_entry)
    current["policy"]["network_enabled"] = False

    enriched, monitoring, active = history.apply_monitoring_history(
        current,
        {"schema_version": 1, "targets": [target()]},
        history_root=tmp_path,
        current_run_name="2026-08-09",
    )

    observed = enriched["results"][0]
    tracking = observed["protocol_activity_tracking"]
    assert observed["availability_status"] == "on"
    assert observed["monitoring_lifecycle"]["status"] == "active_on"
    assert tracking["history"][0]["activity_state"] == "command_observed"
    assert tracking["unique_command_fingerprint_count"] == 1
    assert tracking["synthetic_reply_sent"] is True
    assert tracking["task_executed"] is False
    assert tracking["real_effect_performed"] is False
    assert monitoring["endpoints"][0]["protocol_activity_tracking"] == tracking
    assert enriched["monitoring_history_summary"]["protocol_activity_endpoint_count"] == 1
    assert enriched["monitoring_history_summary"]["protocol_command_observation_count"] == 1
    assert len(active["targets"]) == 1


def test_command_absence_never_becomes_off_evidence(tmp_path: Path) -> None:
    current_entry = entry(
        "2026-08-09T00:00:00+00:00",
        ips=[],
        reachable=False,
    )
    current_entry["rat_emulation"] = rat_activity(command_count=0, confirmed=False)
    current = result(current_entry)
    current["policy"]["network_enabled"] = False

    enriched, _monitoring, active = history.apply_monitoring_history(
        current,
        {"schema_version": 1, "targets": [target()]},
        history_root=tmp_path,
        current_run_name="2026-08-09",
    )

    observed = enriched["results"][0]
    tracking = observed["protocol_activity_tracking"]
    assert observed["availability_status"] == "not_observed"
    assert observed["monitoring_lifecycle"]["status"] == "active_unobserved"
    assert tracking["history"][0]["activity_state"] == "session_without_confirmed_command"
    assert tracking["command_absence_is_off_evidence"] is False
    assert enriched["monitoring_history_summary"]["command_absence_is_off_evidence"] is False
    assert len(active["targets"]) == 1


def test_unsafe_protocol_activity_is_not_used_as_positive_evidence(
    tmp_path: Path,
) -> None:
    current_entry = entry(
        "2026-08-09T00:00:00+00:00",
        ips=[],
        reachable=False,
    )
    activity = rat_activity(command_count=1, confirmed=True)
    activity["task_executed"] = True
    current_entry["rat_emulation"] = activity
    current = result(current_entry)
    current["policy"]["network_enabled"] = False

    enriched, _monitoring, active = history.apply_monitoring_history(
        current,
        {"schema_version": 1, "targets": [target()]},
        history_root=tmp_path,
        current_run_name="2026-08-09",
    )

    observed = enriched["results"][0]
    assert observed["availability_status"] == "not_observed"
    assert "protocol_activity_tracking" not in observed
    assert len(active["targets"]) == 1
