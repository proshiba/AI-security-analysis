from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
REPOSITORY_ROOT = Path(__file__).parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import monitor_recent_c2  # noqa: E402
from c2_protocol_probe_profiles import (  # noqa: E402
    apply_profiles,
    profile_registry_metadata,
)


def reviewed_plan() -> dict:
    registry_pin = profile_registry_metadata()
    targets, _added = apply_profiles(
        [],
        repository_root=REPOSITORY_ROOT,
        expected_profile_registry_sha256=registry_pin["sha256"],
    )
    target = next(value for value in targets if value.get("protocol_profile_id") == "darkcomet-b9b052df-f168-name-1604")
    return {
        "schema_version": 1,
        "analysis_window": {"start": "2026-08-09", "end": "2026-08-09"},
        "protocol_profile_registry": registry_pin,
        "targets": [target],
    }


def exact_observation() -> dict:
    return {
        "timestamp_utc": "2026-08-09T00:00:00+00:00",
        "status": "confirmed_darkcomet_idtype",
        "alive": True,
        "c2_confirmed": True,
        "target_contact_attempted": True,
        "target_connection_established": True,
        "application_data_sent": False,
        "sent_bytes": 0,
        "protocol_response_received": True,
        "server_first_response_received": True,
        "server_first_bytes_received": 12,
        "received_bytes": 12,
        "wire_encoding": "ascii_hex",
        "idtype_exact_match": True,
        "decrypted_plaintext_published": False,
        "rc4_key_published": False,
        "resolved_ips": ["203.0.113.8"],
        "stage_requested": False,
        "victim_metadata_sent": False,
        "operation_command_sent": False,
    }


def test_darkcomet_exact_idtype_confirms_without_application_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict] = []

    def fake_probe(
        target: dict,
        **kwargs,
    ) -> dict:
        calls.append(target)
        assert kwargs["allow_network"] is True
        assert target["protocol_profile_id"] == "darkcomet-b9b052df-f168-name-1604"
        assert len(target["protocol_profile_evidence_sha256"]) == 64
        observation = exact_observation()
        observation["execution_engine"] = "nmap_nse"
        return observation

    monkeypatch.setattr(monitor_recent_c2, "probe_target_with_nmap", fake_probe)
    result = monitor_recent_c2.monitor(reviewed_plan(), allow_network=True, repository_root=REPOSITORY_ROOT)
    entry = result["results"][0]
    assert len(calls) == 1
    assert entry["assessment"]["state"] == "c2_protocol_confirmed"
    assert entry["assessment"]["c2_operational_confidence"] == 0.98
    assert entry["protocol_profile_evidence_sha256"] == calls[0]["protocol_profile_evidence_sha256"]
    assert entry["observation"]["application_data_sent"] is False
    assert result["policy"]["malware_checkin_sent"] is False


@pytest.mark.parametrize(
    ("status", "received", "state"),
    [
        ("darkcomet_idtype_mismatch", 12, "darkcomet_challenge_mismatch_c2_not_confirmed"),
        ("confirmed_darkcomet_idtype", 12, "darkcomet_confirmation_inconsistent_c2_not_confirmed"),
        ("darkcomet_ciphertext_partial", 5, "darkcomet_partial_challenge_c2_not_confirmed"),
        ("darkcomet_ciphertext_malformed", 12, "darkcomet_malformed_challenge_c2_not_confirmed"),
        ("darkcomet_ciphertext_overlong", 13, "darkcomet_overlong_challenge_c2_not_confirmed"),
        ("connected_no_response", 0, "darkcomet_server_first_no_response_c2_not_confirmed"),
        (
            "receive_skipped_deadline_exhausted",
            0,
            "darkcomet_receive_skipped_deadline_exhausted_c2_not_confirmed",
        ),
    ],
)
def test_non_exact_states_keep_c2_operational_confidence_zero(
    status: str,
    received: int,
    state: str,
) -> None:
    target = reviewed_plan()["targets"][0]
    observation = exact_observation()
    observation.update(
        {
            "status": status,
            "c2_confirmed": True,
            "idtype_exact_match": False,
            "server_first_bytes_received": received,
            "protocol_response_received": received > 0,
        }
    )
    assessment = monitor_recent_c2.assess_observation(target, observation)
    assert assessment["state"] == state
    assert assessment["c2_operational_confidence"] == 0.0
    assert assessment["method_confidence_ceiling"] == 0.98


def test_plan_revalidates_evidence_after_build_mutation_and_deletion(tmp_path: Path) -> None:
    plan = reviewed_plan()
    source = plan["targets"][0]["protocol_profile_evidence_source"].split(":", 1)[0]
    root = Path("\\\\?\\" + str(tmp_path.resolve()))
    destination = root / source
    destination.parent.mkdir(parents=True)
    destination.write_bytes((REPOSITORY_ROOT / source).read_bytes())
    monitor_recent_c2.validate_plan(copy.deepcopy(plan), repository_root=root)

    destination.write_bytes(destination.read_bytes() + b"\n")
    with pytest.raises(monitor_recent_c2.PlanError, match="SHA-256"):
        monitor_recent_c2.validate_plan(copy.deepcopy(plan), repository_root=root)
    destination.unlink()
    with pytest.raises(monitor_recent_c2.PlanError, match="再検証"):
        monitor_recent_c2.validate_plan(copy.deepcopy(plan), repository_root=root)


def test_darkcomet_profile_is_exact_host_port_and_evidence_pin() -> None:
    value = reviewed_plan()
    value["targets"][0]["host"] = "other.example"
    with pytest.raises(monitor_recent_c2.PlanError):
        monitor_recent_c2.validate_plan(value, repository_root=REPOSITORY_ROOT)
    value = reviewed_plan()
    value["targets"][0].pop("protocol_profile_evidence_sha256")
    with pytest.raises(monitor_recent_c2.PlanError, match="証拠source/SHA-256"):
        monitor_recent_c2.validate_plan(value, repository_root=REPOSITORY_ROOT)


def test_darkcomet_hint_without_reviewed_endpoint_is_dns_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = reviewed_plan()
    target = value["targets"][0]
    target.update(
        {
            "host": "unreviewed.example",
            "port": 1604,
            "protocol": "tcp",
            "method": "protocol_profile_required",
            "protocol_hints": ["darkcomet"],
            "protocol_profile_required": True,
            "protocol_profile_status": "reviewed_exact_profile_missing",
            "maximum_response_bytes": 256,
        }
    )
    target.pop("protocol_profile_id")
    target.pop("protocol_profile_evidence_sha256")
    target.pop("protocol_profile_evidence_source")
    monkeypatch.setattr(
        monitor_recent_c2,
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
            "execution_engine": "nmap_nse",
            "status": "dns_resolved",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": False,
            "target_connection_established": False,
            "application_data_sent": False,
            "resolved_ips": ["203.0.113.9"],
        },
    )
    result = monitor_recent_c2.monitor(value, allow_network=True, repository_root=REPOSITORY_ROOT)
    entry = result["results"][0]
    assert entry["observation"]["target_contact_attempted"] is False
    assert entry["assessment"]["state"] == "protocol_profile_required_c2_unverified"
    assert entry["assessment"]["c2_operational_confidence"] == 0.0
