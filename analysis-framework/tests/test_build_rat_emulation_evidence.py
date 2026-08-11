from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import build_rat_emulation_evidence as builder  # noqa: E402
import rat_emulation_evidence as evidence  # noqa: E402
from c2_protocol_probe_profiles import load_profiles as load_protocol_profiles  # noqa: E402
from rat_emulator_profiles import load_registry  # noqa: E402
from tls_messagepack_rat_host_emulator import resolve_profile as resolve_tls_profile  # noqa: E402


REGISTRY = load_registry()
PROTOCOL_PROFILES = load_protocol_profiles(
    expected_sha256=REGISTRY.protocol_profile_registry["sha256"]
)
PROFILE = next(iter(REGISTRY.profiles.values()))
TLS_PROFILES = [
    profile
    for profile in REGISTRY.profiles.values()
    if profile["adapter_id"] == "tls_messagepack_rat_host"
]


def plan() -> dict:
    return {
        "schema_version": 1,
        "protocol_profile_registry": deepcopy(REGISTRY.protocol_profile_registry),
        "targets": [
            {
                "target_id": "fixture",
                "family": PROFILE["family"],
                "host": PROFILE["host"],
                "port": PROFILE["port"],
                "protocol": PROTOCOL_PROFILES[PROFILE["protocol_profile_id"]][
                    "protocol"
                ],
                "transport": "direct",
                "http_path": None,
                "protocol_profile_id": PROFILE["protocol_profile_id"],
                "protocol_profile_registry_source": REGISTRY.protocol_profile_registry[
                    "source"
                ],
                "protocol_profile_registry_sha256": REGISTRY.protocol_profile_registry[
                    "sha256"
                ],
                "sample_sha256s": list(PROFILE["sample_sha256s"]),
            }
        ],
    }


def plan_for(profile: dict) -> dict:
    value = plan()
    value["targets"] = [
        {
            "target_id": f"fixture-{profile['family']}",
            "family": profile["family"],
            "host": profile["host"],
            "port": profile["port"],
            "protocol": PROTOCOL_PROFILES[profile["protocol_profile_id"]]["protocol"],
            "transport": "direct",
            "http_path": None,
            "protocol_profile_id": profile["protocol_profile_id"],
            "protocol_profile_registry_source": REGISTRY.protocol_profile_registry[
                "source"
            ],
            "protocol_profile_registry_sha256": REGISTRY.protocol_profile_registry[
                "sha256"
            ],
            "sample_sha256s": list(profile["sample_sha256s"]),
        }
    ]
    return value


def public_summary(*, session_id: str = "session-001") -> dict:
    events = [
        {
            "sequence": 1,
            "captured_at": "2026-08-09T00:00:00Z",
            "direction": "internal",
            "event_type": "preconnect_policy_validated",
            "frame": None,
            "public_fields": {"single_connection": True},
            "event_sha256": "1" * 64,
        },
        {
            "sequence": 2,
            "captured_at": "2026-08-09T00:00:01Z",
            "direction": "internal",
            "event_type": "tls_certificate_pinned",
            "frame": None,
            "public_fields": {"certificate_sha256": "2" * 64},
            "event_sha256": "2" * 64,
        },
        {
            "sequence": 3,
            "captured_at": "2026-08-09T00:00:02Z",
            "direction": "internal",
            "event_type": "n520_handshake_validated",
            "frame": None,
            "public_fields": {"header_matches": True},
            "event_sha256": "3" * 64,
        },
        {
            "sequence": 4,
            "captured_at": "2026-08-09T00:00:03Z",
            "direction": "internal",
            "event_type": "n520_command_decision",
            "frame": None,
            "public_fields": {
                "command": 16,
                "classification": "server_plugin_transfer",
                "secret": "DO_NOT_PUBLISH_EVENT_SECRET",
            },
            "event_sha256": "4" * 64,
        },
    ]
    return {
        "schema_version": 1,
        "artifact_type": "defensive_rat_emulator_public_summary",
        "session_id": session_id,
        "started_at": "2026-08-09T00:00:00Z",
        "completed_at": "2026-08-09T00:00:04Z",
        "status": "completed",
        "stop_reason": "file_or_plugin_transfer_refused",
        "metadata": {
            "profile_id": PROFILE["profile_id"],
            "family": PROFILE["family"],
            "protocol_profile_id": PROFILE["protocol_profile_id"],
            "registry_sha256": REGISTRY.sha256,
            "protocol_profile_object_sha256": PROFILE[
                "protocol_profile_object_sha256"
            ],
            "evidence_sha256": PROFILE["evidence_sha256"],
            "sample_executed": False,
            "token": "DO_NOT_PUBLISH_METADATA_TOKEN",
        },
        "event_count": len(events),
        "transcript_root_sha256": "5" * 64,
        "events": events,
        "adapter_result": {
            "schema_version": 1,
            "family": PROFILE["family"],
            "protocol": "n520",
            "status": "file_or_plugin_transfer_refused",
            "registration": {
                "sent": True,
                "command": 1,
                "sequence": 1,
                "payload_size": 0,
                "real_identity_sent": False,
                "packet_size": 80,
                "packet_sha256": "6" * 64,
            },
            "collection": {
                "response_size": 128,
                "response_sha256": "7" * 64,
                "frame_count": 1,
            },
            "decisions": [
                {
                    "command": 16,
                    "classification": "server_plugin_transfer",
                    "direction": "server_to_client",
                    "action": "refuse_file_or_plugin_transfer_and_terminate",
                    "reason": "fixture",
                    "should_respond": False,
                    "terminate_session": True,
                    "transfer_refused": True,
                    "payload": "DO_NOT_PUBLISH_DECISION_PAYLOAD",
                }
            ],
            "safety": {
                "sample_executed": False,
                "host_operation_executed": False,
                "file_or_plugin_retained": False,
                "file_or_plugin_executed": False,
                "fake_result_sent": False,
                "fake_result_wire_schema": "unresolved",
                "live_fake_result_transmission_allowed": False,
                "application_send_count": 1,
                "session_continues": False,
            },
        },
        "raw": "DO_NOT_PUBLISH_ROOT_RAW",
    }


def tls_public_summary(
    profile: dict,
    *,
    packet_kind: str = "heartbeat",
    session_id: str = "tls-session-001",
) -> dict:
    exact = resolve_tls_profile(profile)
    if packet_kind == "heartbeat":
        opcode = exact.heartbeat_response_opcode
    elif packet_kind == "file_or_plugin":
        opcode = sorted(exact.file_opcodes)[0]
    elif packet_kind == "operation":
        opcode = sorted(exact.operation_opcodes)[0]
    else:
        opcode = "unreviewedTask"
    action = {
        "heartbeat": "record_heartbeat_response_and_terminate",
        "file_or_plugin": "refuse_file_or_plugin_and_terminate",
        "operation": "refuse_operation_and_terminate",
        "unknown": "terminate_unknown_command",
    }[packet_kind]
    status = {
        "heartbeat": "heartbeat_response_observed",
        "file_or_plugin": "file_or_plugin_refused",
        "operation": "operation_refused",
        "unknown": "unknown_command_terminated",
    }[packet_kind]
    registration = {
        "packet_kind": "registration",
        "opcode": "ClientInfo",
        "frame_size": 120,
        "frame_sha256": "a" * 64,
        "decoded_size": 100,
        "decoded_sha256": "1" * 64,
        "synthetic": True,
    }
    heartbeat_request = {
        "packet_kind": "heartbeat_request",
        "opcode": exact.heartbeat_request_opcode,
        "sent": True,
        "synthetic": True,
        "frame_size": 44,
        "frame_sha256": "b" * 64,
        "decoded_size": 20,
        "decoded_sha256": "2" * 64,
    }
    command = {
        "command": opcode,
        "opcode": opcode,
        "classification": packet_kind,
        "packet_kind": packet_kind,
        "action": action,
        "should_respond": False,
        "terminate_session": True,
        "frame_size": 64,
        "frame_sha256": "c" * 64,
        "decoded_size": 30,
        "decoded_sha256": "3" * 64,
    }
    events = [
        {
            "event_type": "preconnect_policy_validated",
            "captured_at": "2026-08-09T00:00:00Z",
            "frame": None,
            "public_fields": {"single_connection": True},
        },
        {
            "event_type": "tls_certificate_pinned",
            "captured_at": "2026-08-09T00:00:00.100Z",
            "frame": None,
            "public_fields": {"certificate_sha256": profile["expected_certificate_sha256"]},
        },
        {
            "event_type": "reviewed_registration_frame",
            "captured_at": "2026-08-09T00:00:01Z",
            "frame": {"size": 120, "sha256": "a" * 64},
            "public_fields": {
                "size": 120,
                "sha256": "a" * 64,
                "real_identity_sent": False,
                "synthetic": True,
            },
        },
        {
            "event_type": "registration_sent",
            "captured_at": "2026-08-09T00:00:01.100Z",
            "frame": None,
            "public_fields": dict(registration),
        },
        {
            "event_type": "reviewed_fixed_heartbeat_request_frame",
            "captured_at": "2026-08-09T00:00:01.200Z",
            "frame": {"size": 44, "sha256": "b" * 64},
            "public_fields": {
                "size": 44,
                "sha256": "b" * 64,
                "real_identity_sent": False,
                "synthetic": True,
            },
        },
        {
            "event_type": "heartbeat_request_sent",
            "captured_at": "2026-08-09T00:00:01.300Z",
            "frame": None,
            "public_fields": dict(heartbeat_request),
        },
        {
            "event_type": "command_classified",
            "captured_at": "2026-08-09T00:00:02Z",
            "frame": None,
            "public_fields": {
                key: command[key]
                for key in (
                    "packet_kind",
                    "opcode",
                    "action",
                    "should_respond",
                    "terminate_session",
                    "frame_size",
                    "frame_sha256",
                    "decoded_size",
                    "decoded_sha256",
                )
            },
        },
        {
            "event_type": "session_terminated",
            "captured_at": "2026-08-09T00:00:02.100Z",
            "frame": None,
            "public_fields": {"packet_kind": packet_kind, "opcode": opcode},
        },
    ]
    return {
        "schema_version": 1,
        "artifact_type": "defensive_rat_emulator_public_summary",
        "session_id": session_id,
        "started_at": "2026-08-09T00:00:00Z",
        "completed_at": "2026-08-09T00:00:03Z",
        "status": "completed",
        "stop_reason": status,
        "metadata": {
            "profile_id": profile["profile_id"],
            "family": profile["family"],
            "protocol_profile_id": profile["protocol_profile_id"],
            "registry_sha256": REGISTRY.sha256,
            "protocol_profile_object_sha256": profile[
                "protocol_profile_object_sha256"
            ],
            "evidence_sha256": profile["evidence_sha256"],
            "sample_executed": False,
        },
        "event_count": len(events),
        "transcript_root_sha256": "4" * 64,
        "events": events,
        "adapter_result": {
            "schema_version": 1,
            "family": profile["family"],
            "protocol": profile["family"],
            "status": status,
            "certificate_mismatch_is_negative_evidence": False,
            "registration": registration,
            "collection": {
                "received_bytes": 64,
                "read_calls": 2,
                "frame_count": 1,
                "command_count": 1,
            },
            "command": command,
            "decisions": [deepcopy(command)],
            "heartbeat_request": heartbeat_request,
            "safety": {
                "sample_executed": False,
                "real_host_information_read": False,
                "real_effect_performed": False,
                "file_or_plugin_retained": False,
                "file_or_plugin_executed": False,
                "operation_executed": False,
                "secondary_network_performed": False,
                "arbitrary_fake_result_sent": False,
                "live_arbitrary_result_allowed": False,
                "application_send_count": 2,
                "session_continues": False,
            },
        },
    }


def archive_report(session_id: str = "tls-session-001") -> dict:
    return {
        "schema_version": "analysis-datastore-upload-report/v1",
        "status": "verified",
        "target": session_id,
        "created_at_utc": "2026-08-09T00:05:00Z",
        "object_uri": (
            "s3://malware-analysis-datastore-720232834682/analysis-targets/"
            f"{session_id}/2026/08/{session_id}-20260809T000500Z-eeeeeeeeeeee.zip"
        ),
        "archive_sha256": "d" * 64,
        "manifest_sha256": "e" * 64,
        "archive_size": 4096,
        "file_count": 8,
        "total_uncompressed_size": 8192,
        "s3_verification": {
            "account": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/private-role",
            "etag": "private-etag",
            "server_side_encryption": "AES256",
        },
        "local_source_deleted": False,
        "local_archive_retained": False,
    }


def write_json(path: Path, value: dict) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_builder_creates_pipeline_compatible_allowlisted_sidecar(
    short_tmp: Path,
) -> None:
    source = short_tmp / "public-summary.json"
    source_sha = write_json(source, public_summary())
    built = builder.build_evidence(
        [builder.SummaryInput(source, source_sha)],
        plan(),
        reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        maximum_summary_age_hours=2,
    )
    serialized = json.dumps(built, ensure_ascii=False, sort_keys=True)
    for secret in (
        "DO_NOT_PUBLISH_EVENT_SECRET",
        "DO_NOT_PUBLISH_METADATA_TOKEN",
        "DO_NOT_PUBLISH_DECISION_PAYLOAD",
        "DO_NOT_PUBLISH_ROOT_RAW",
    ):
        assert secret not in serialized
    session = built["sessions"][0]
    assert session["emulator_profile_id"] == PROFILE["profile_id"]
    assert session["source_summary_snapshot"]["sha256"] == source_sha
    assert session["c2_confirmed"] is True
    assert session["commands"][0]["opcode"] == 16
    assert session["commands"][0]["wire_sha256"] == "7" * 64
    assert session["synthetic_replies"] == []
    assert session["private_evidence"] == {
        "archived": False,
        "transcript_root_sha256": "5" * 64,
    }

    output = short_tmp / "rat-emulation-evidence.json"
    builder.write_evidence(output, built, input_paths=[source])
    output_sha = hashlib.sha256(output.read_bytes()).hexdigest()
    validated = evidence.load_and_validate(output, output_sha, plan())
    assert validated["sessions"][0]["command_count"] == 1
    assert validated["sessions"][0]["source_summary_snapshot"]["sha256"] == source_sha
    with pytest.raises(FileExistsError):
        builder.write_evidence(output, built, input_paths=[source])


def test_builder_rejects_hash_mismatch_duplicate_and_expired_summary(
    short_tmp: Path,
) -> None:
    source = short_tmp / "public-summary.json"
    digest = write_json(source, public_summary())

    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="pin"):
        builder.build_evidence(
            [builder.SummaryInput(source, "0" * 64)],
            plan(),
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="重複"):
        builder.build_evidence(
            [
                builder.SummaryInput(source, digest),
                builder.SummaryInput(source, digest),
            ],
            plan(),
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="期限切れ"):
        builder.build_evidence(
            [builder.SummaryInput(source, digest)],
            plan(),
            reference_time=datetime(2026, 8, 11, 1, tzinfo=UTC),
        )


def test_builder_rejects_profile_binding_and_unsafe_adapter_result(
    short_tmp: Path,
) -> None:
    wrong_binding = public_summary()
    wrong_binding["metadata"]["family"] = "other-rat"
    binding_path = short_tmp / "binding.json"
    binding_sha = write_json(binding_path, wrong_binding)
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="binding"):
        builder.build_evidence(
            [builder.SummaryInput(binding_path, binding_sha)],
            plan(),
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )

    unsafe = public_summary()
    unsafe["adapter_result"]["safety"]["host_operation_executed"] = True
    unsafe_path = short_tmp / "unsafe.json"
    unsafe_sha = write_json(unsafe_path, unsafe)
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="safety"):
        builder.build_evidence(
            [builder.SummaryInput(unsafe_path, unsafe_sha)],
            plan(),
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )


def test_monitoring_plan_requires_expected_sha(short_tmp: Path) -> None:
    path = short_tmp / "targets.json"
    digest = write_json(path, plan())

    assert builder.load_monitoring_plan(path, digest) == plan()
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="pin"):
        builder.load_monitoring_plan(path, "0" * 64)


@pytest.mark.parametrize(
    "profile",
    TLS_PROFILES,
    ids=lambda value: value["family"],
)
def test_tls_messagepack_builder_publishes_one_safe_command_without_fake_result(
    short_tmp: Path,
    profile: dict,
) -> None:
    source = short_tmp / f"{profile['family']}-public-summary.json"
    source_sha = write_json(source, tls_public_summary(profile))

    built = builder.build_evidence(
        [builder.SummaryInput(source, source_sha)],
        plan_for(profile),
        reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
    )
    session = built["sessions"][0]
    command = session["commands"][0]
    exact = resolve_tls_profile(profile)
    assert command == {
        "sequence": 1,
        "direction": "server_to_client",
        "observed_at_utc": "2026-08-09T00:00:02+00:00",
        "message_kind": "heartbeat",
        "packet_kind": "heartbeat",
        "opcode": exact.heartbeat_response_opcode,
        "wire_size": 64,
        "wire_sha256": "c" * 64,
        "arguments_published": False,
        "raw_published": False,
    }
    assert session["heartbeat_count"] == 1
    assert session["synthetic_replies"] == []
    assert session["safety"]["task_executed"] is False
    serialized = json.dumps(built, ensure_ascii=False, sort_keys=True)
    assert "ClientInfo" not in serialized
    assert "sandbox-user" not in serialized
    assert "real_host_information_read" not in serialized

    output = short_tmp / f"{profile['family']}-sidecar.json"
    builder.write_evidence(output, built, input_paths=[source])
    output_sha = hashlib.sha256(output.read_bytes()).hexdigest()
    validated = evidence.load_and_validate(output, output_sha, plan_for(profile))
    assert validated["sessions"][0]["heartbeat_count"] == 1
    assert validated["sessions"][0]["synthetic_reply_count"] == 0
    assert validated["sessions"][0]["commands"][0]["packet_kind"] == "heartbeat"


def test_real_monitoring_target_shape_accepts_live_asyncrat_summary_and_report(
    short_tmp: Path,
) -> None:
    repository = COMMON.parents[1]
    plan_path = (
        repository
        / "analysis-results"
        / "research"
        / "c2-monitoring"
        / "2026-08-09"
        / "targets.json"
    )
    summary_path = (
        repository
        / "analysis-results"
        / "research"
        / "c2-protocol-profiles"
        / "2026-08-09-rat-emulator"
        / "live-asyncrat-058-20260809.json"
    )
    plan_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    summary_sha = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    historical_plan = builder.load_monitoring_plan(plan_path, plan_sha)
    real_plan = deepcopy(historical_plan)
    real_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    current_summary = deepcopy(real_summary)
    current_summary["metadata"]["registry_sha256"] = REGISTRY.sha256
    current_summary["metadata"]["evidence_sha256"] = REGISTRY.profiles[
        real_summary["metadata"]["profile_id"]
    ]["evidence_sha256"]
    current_summary_path = short_tmp / "current-registry-live-asyncrat.json"
    current_summary_sha = write_json(current_summary_path, current_summary)
    current_protocol_registry = REGISTRY.protocol_profile_registry
    real_plan["protocol_profile_registry"] = deepcopy(current_protocol_registry)
    asyncrat_targets = [
        target
        for target in real_plan["targets"]
        if target.get("protocol_profile_id")
        == real_summary["metadata"]["protocol_profile_id"]
    ]
    assert len(asyncrat_targets) == 1
    asyncrat_target = asyncrat_targets[0]
    asyncrat_target["protocol_profile_registry_source"] = current_protocol_registry[
        "source"
    ]
    asyncrat_target["protocol_profile_registry_sha256"] = current_protocol_registry[
        "sha256"
    ]
    report_path = short_tmp / "real-shape-archive-report.json"
    report_sha = write_json(report_path, archive_report(real_summary["session_id"]))

    built = builder.build_evidence(
        [builder.SummaryInput(current_summary_path, current_summary_sha)],
        real_plan,
        archive_reports=[builder.ArchiveReportInput(report_path, report_sha)],
        reference_time=datetime(2026, 8, 9, 10, tzinfo=UTC),
        maximum_summary_age_hours=2,
    )
    session = built["sessions"][0]
    assert session["family"] == "asyncrat"
    assert session["protocol"] == "asyncrat"
    assert session["transport"] == "direct"
    assert session["private_evidence"]["archived"] is True

    output = short_tmp / "real-shape-sidecar.json"
    builder.write_evidence(
        output,
        built,
        input_paths=[plan_path, current_summary_path, report_path],
    )
    output_sha = hashlib.sha256(output.read_bytes()).hexdigest()
    validated = evidence.load_and_validate(output, output_sha, real_plan)
    assert validated["sessions"][0]["protocol"] == "asyncrat"
    assert validated["sessions"][0]["transport"] == "direct"
    assert hashlib.sha256(plan_path.read_bytes()).hexdigest() == plan_sha
    assert hashlib.sha256(summary_path.read_bytes()).hexdigest() == summary_sha


@pytest.mark.parametrize(
    ("field", "value"),
    [("transport", "tls"), ("protocol", "tcp")],
)
def test_tls_profile_rejects_nonmonitoring_transport_or_generic_protocol(
    short_tmp: Path,
    field: str,
    value: str,
) -> None:
    profile = TLS_PROFILES[0]
    source = short_tmp / f"wrong-target-{field}.json"
    source_sha = write_json(source, tls_public_summary(profile))
    wrong_plan = plan_for(profile)
    wrong_plan["targets"][0][field] = value
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="監視target|完全一致"):
        builder.build_evidence(
            [builder.SummaryInput(source, source_sha)],
            wrong_plan,
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )


TLS_POLICY_CASES = [
    *( (profile, "file_or_plugin") for profile in TLS_PROFILES ),
    *(
        (profile, "operation")
        for profile in TLS_PROFILES
        if resolve_tls_profile(profile).operation_opcodes
    ),
    *( (profile, "unknown") for profile in TLS_PROFILES ),
]


@pytest.mark.parametrize(
    ("profile", "packet_kind"),
    TLS_POLICY_CASES,
    ids=lambda value: value["family"] if isinstance(value, dict) else value,
)
def test_tls_messagepack_nonheartbeat_command_is_no_response_and_terminate(
    short_tmp: Path,
    profile: dict,
    packet_kind: str,
) -> None:
    summary = tls_public_summary(profile, packet_kind=packet_kind)
    source = short_tmp / f"{profile['family']}-{packet_kind}.json"
    digest = write_json(source, summary)
    built = builder.build_evidence(
        [builder.SummaryInput(source, digest)],
        plan_for(profile),
        reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
    )
    session = built["sessions"][0]
    assert session["commands"][0]["packet_kind"] == packet_kind
    assert session["heartbeat_count"] == 0
    assert session["synthetic_replies"] == []

    unsafe = tls_public_summary(profile, packet_kind=packet_kind)
    unsafe["adapter_result"]["command"]["should_respond"] = True
    unsafe["adapter_result"]["decisions"][0]["should_respond"] = True
    unsafe["events"][6]["public_fields"]["should_respond"] = True
    unsafe_path = short_tmp / f"unsafe-{profile['family']}-{packet_kind}.json"
    unsafe_sha = write_json(unsafe_path, unsafe)
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="無応答終了policy"):
        builder.build_evidence(
            [builder.SummaryInput(unsafe_path, unsafe_sha)],
            plan_for(profile),
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )


def test_tls_messagepack_rejects_real_host_raw_duplicate_and_wire_tampering(
    short_tmp: Path,
) -> None:
    profile = TLS_PROFILES[0]
    cases: list[tuple[str, dict, str]] = []

    real_host = tls_public_summary(profile)
    real_host["adapter_result"]["safety"]["real_host_information_read"] = True
    cases.append(("real-host", real_host, "safety|合成ClientInfo"))

    raw = tls_public_summary(profile)
    raw["adapter_result"]["command"]["payload"] = "DO_NOT_ACCEPT_RAW_COMMAND"
    cases.append(("raw", raw, "raw|本文field"))

    duplicate = tls_public_summary(profile)
    duplicate["adapter_result"]["decisions"].append(
        deepcopy(duplicate["adapter_result"]["command"])
    )
    cases.append(("duplicate", duplicate, "1件"))

    wire = tls_public_summary(profile)
    wire["events"][6]["public_fields"]["frame_sha256"] = "9" * 64
    cases.append(("wire", wire, "一致"))

    for name, value, pattern in cases:
        source = short_tmp / f"tamper-{name}.json"
        digest = write_json(source, value)
        with pytest.raises(builder.RatEmulationEvidenceBuildError, match=pattern):
            builder.build_evidence(
                [builder.SummaryInput(source, digest)],
                plan_for(profile),
                reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
            )


def test_verified_archive_report_adds_only_safe_private_reference(short_tmp: Path) -> None:
    profile = TLS_PROFILES[0]
    summary_source = short_tmp / "tls-summary.json"
    summary_sha = write_json(summary_source, tls_public_summary(profile))
    report_source = short_tmp / "archive-report.json"
    report_sha = write_json(report_source, archive_report())

    built = builder.build_evidence(
        [builder.SummaryInput(summary_source, summary_sha)],
        plan_for(profile),
        archive_reports=[builder.ArchiveReportInput(report_source, report_sha)],
        reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
    )
    private = built["sessions"][0]["private_evidence"]
    assert private == {
        "archived": True,
        "datastore_target": "tls-session-001",
        "object_uri": archive_report()["object_uri"],
        "archive_sha256": "d" * 64,
        "manifest_sha256": "e" * 64,
        "archive_report_sha256": report_sha,
        "server_side_encryption": "AES256",
        "transcript_root_sha256": "4" * 64,
    }
    serialized = json.dumps(built, ensure_ascii=False, sort_keys=True)
    assert "private-role" not in serialized
    assert "private-etag" not in serialized
    assert "123456789012" not in serialized

    output = short_tmp / "archived-sidecar.json"
    builder.write_evidence(output, built, input_paths=[summary_source, report_source])
    output_sha = hashlib.sha256(output.read_bytes()).hexdigest()
    validated = evidence.load_and_validate(output, output_sha, plan_for(profile))
    assert validated["sessions"][0]["private_evidence"] == private


@pytest.mark.parametrize(
    ("field", "value", "pattern"),
    [
        ("status", "uploaded", "verified"),
        ("target", "other-session", "binding"),
        (
            "object_uri",
            "s3://other-bucket/analysis-targets/tls-session-001/archive.zip",
            "bucket",
        ),
        ("archive_sha256", "not-a-hash", "SHA-256"),
    ],
)
def test_archive_report_tamper_is_rejected(
    short_tmp: Path,
    field: str,
    value: object,
    pattern: str,
) -> None:
    profile = TLS_PROFILES[0]
    summary_source = short_tmp / f"summary-{field}.json"
    summary_sha = write_json(summary_source, tls_public_summary(profile))
    report = archive_report()
    report[field] = value
    report_source = short_tmp / f"report-{field}.json"
    report_sha = write_json(report_source, report)
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match=pattern):
        builder.build_evidence(
            [builder.SummaryInput(summary_source, summary_sha)],
            plan_for(profile),
            archive_reports=[builder.ArchiveReportInput(report_source, report_sha)],
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )


def test_archive_report_requires_matching_count_hash_encryption_and_no_raw(
    short_tmp: Path,
) -> None:
    profile = TLS_PROFILES[0]
    summary_source = short_tmp / "summary.json"
    summary_sha = write_json(summary_source, tls_public_summary(profile))
    report = archive_report()
    report_source = short_tmp / "report.json"
    write_json(report_source, report)

    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="同じ件数"):
        builder.build_evidence(
            [builder.SummaryInput(summary_source, summary_sha)],
            plan_for(profile),
            archive_reports=[],
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="pin"):
        builder.build_evidence(
            [builder.SummaryInput(summary_source, summary_sha)],
            plan_for(profile),
            archive_reports=[builder.ArchiveReportInput(report_source, "0" * 64)],
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )

    encryption = archive_report()
    encryption["s3_verification"]["server_side_encryption"] = "aws:kms"
    encryption_path = short_tmp / "bad-encryption.json"
    encryption_sha = write_json(encryption_path, encryption)
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="AES256"):
        builder.build_evidence(
            [builder.SummaryInput(summary_source, summary_sha)],
            plan_for(profile),
            archive_reports=[builder.ArchiveReportInput(encryption_path, encryption_sha)],
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )

    raw = archive_report()
    raw["payload"] = "DO_NOT_ACCEPT_ARCHIVE_PAYLOAD"
    raw_path = short_tmp / "raw-report.json"
    raw_sha = write_json(raw_path, raw)
    with pytest.raises(builder.RatEmulationEvidenceBuildError, match="raw|本文field"):
        builder.build_evidence(
            [builder.SummaryInput(summary_source, summary_sha)],
            plan_for(profile),
            archive_reports=[builder.ArchiveReportInput(raw_path, raw_sha)],
            reference_time=datetime(2026, 8, 9, 1, tzinfo=UTC),
        )
