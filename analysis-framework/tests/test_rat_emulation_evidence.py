from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import rat_emulation_evidence as evidence  # noqa: E402
from c2_protocol_probe_profiles import load_profiles as load_protocol_profiles  # noqa: E402
from rat_emulator_profiles import load_registry as load_emulator_registry  # noqa: E402
from run_c2_monitoring_pipeline import (  # noqa: E402
    load_optional_rat_emulation_evidence,
)


EMULATOR_REGISTRY = load_emulator_registry()
PROTOCOL_PROFILES = load_protocol_profiles(
    expected_sha256=EMULATOR_REGISTRY.protocol_profile_registry["sha256"]
)
EMULATOR_PROFILE = next(iter(EMULATOR_REGISTRY.profiles.values()))
PROTOCOL = PROTOCOL_PROFILES[EMULATOR_PROFILE["protocol_profile_id"]]["protocol"]
REGISTRY = deepcopy(EMULATOR_REGISTRY.protocol_profile_registry)
SAMPLE = EMULATOR_PROFILE["sample_sha256s"][0]


def monitoring_plan() -> dict:
    return {
        "schema_version": 1,
        "protocol_profile_registry": deepcopy(REGISTRY),
        "targets": [
            {
                "target_id": "fixture",
                "family": EMULATOR_PROFILE["family"],
                "host": EMULATOR_PROFILE["host"],
                "port": EMULATOR_PROFILE["port"],
                "protocol": PROTOCOL,
                "transport": "direct",
                "http_path": None,
                "protocol_profile_id": EMULATOR_PROFILE["protocol_profile_id"],
                "protocol_profile_registry_source": REGISTRY["source"],
                "protocol_profile_registry_sha256": REGISTRY["sha256"],
                "sample_sha256s": [SAMPLE],
            }
        ],
    }


def sidecar() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-08-09T00:00:03Z",
        "protocol_profile_registry": deepcopy(REGISTRY),
        "emulator_profile_registry": {
            "source": EMULATOR_REGISTRY.source,
            "sha256": EMULATOR_REGISTRY.sha256,
        },
        "sessions": [
            {
                "schema_version": 1,
                "session_id": "session-001",
                "family": EMULATOR_PROFILE["family"],
                "host": EMULATOR_PROFILE["host"],
                "port": EMULATOR_PROFILE["port"],
                "protocol": PROTOCOL,
                "transport": "direct",
                "http_path": None,
                "protocol_profile_id": EMULATOR_PROFILE["protocol_profile_id"],
                "protocol_profile_registry_source": REGISTRY["source"],
                "protocol_profile_registry_sha256": REGISTRY["sha256"],
                "emulator_profile_id": EMULATOR_PROFILE["profile_id"],
                "emulator_profile_registry_source": EMULATOR_REGISTRY.source,
                "emulator_profile_registry_sha256": EMULATOR_REGISTRY.sha256,
                "sample_sha256s": [SAMPLE],
                "source_summary_snapshot": {
                    "size": 1024,
                    "sha256": "2" * 64,
                    "link_count": 1,
                    "local_path": "C:/DO_NOT_PUBLISH_SUMMARY",
                },
                "started_at_utc": "2026-08-09T00:00:00Z",
                "ended_at_utc": "2026-08-09T00:00:02Z",
                "status": "completed",
                "connection_established": True,
                "handshake_confirmed": True,
                "registration_accepted": True,
                "c2_confirmed": True,
                "heartbeat_count": 1,
                "commands": [
                    {
                        "sequence": 1,
                        "direction": "server_to_client",
                        "observed_at_utc": "2026-08-09T00:00:01Z",
                        "message_kind": "system_info_request",
                        "opcode": "0x21",
                        "wire_size": 48,
                        "wire_sha256": "c" * 64,
                        "arguments_published": False,
                        "raw_published": False,
                        "command_content": "DO_NOT_PUBLISH_COMMAND",
                        "nested": {
                            "token": "DO_NOT_PUBLISH_TOKEN",
                            "url": "https://do-not-publish.invalid/payload",
                        },
                    }
                ],
                "synthetic_replies": [
                    {
                        "sequence": 1,
                        "sent_at_utc": "2026-08-09T00:00:01.100Z",
                        "reply_kind": "fake_system_info",
                        "template_id": "reviewed_static_empty",
                        "wire_size": 32,
                        "wire_sha256": "d" * 64,
                        "real_effect_performed": False,
                        "raw_published": False,
                        "payload": "DO_NOT_PUBLISH_PAYLOAD",
                    }
                ],
                "safety": {
                    field: False
                    for field in evidence.REQUIRED_FALSE_SAFETY_FIELDS
                },
                "private_evidence": {
                    "archived": True,
                    "transcript_root_sha256": "e" * 64,
                    "datastore_target": "session-001",
                    "archive_sha256": "f" * 64,
                    "manifest_sha256": "1" * 64,
                    "local_path": "C:/DO_NOT_PUBLISH_TRANSCRIPT",
                },
                "unknown_root": {
                    "credential": "DO_NOT_PUBLISH_CREDENTIAL",
                },
            }
        ],
        "unknown_root": {"raw": "DO_NOT_PUBLISH_RAW"},
    }


def write_sidecar(path: Path, value: dict) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_load_rebuilds_strict_allowlist_and_attach_tracks_safe_activity(
    short_tmp: Path,
) -> None:
    source = short_tmp / "evidence.json"
    digest = write_sidecar(source, sidecar())

    public = evidence.load_and_validate(source, digest, monitoring_plan())
    serialized = json.dumps(public, ensure_ascii=False, sort_keys=True)

    for secret in (
        "DO_NOT_PUBLISH_COMMAND",
        "DO_NOT_PUBLISH_TOKEN",
        "do-not-publish.invalid",
        "DO_NOT_PUBLISH_PAYLOAD",
        "C:/DO_NOT_PUBLISH_TRANSCRIPT",
        "C:/DO_NOT_PUBLISH_SUMMARY",
        "DO_NOT_PUBLISH_CREDENTIAL",
        "DO_NOT_PUBLISH_RAW",
    ):
        assert secret not in serialized
    session = public["sessions"][0]
    assert session["private_evidence"]["transcript_root_sha256"] == "e" * 64
    assert session["synthetic_reply_sent"] is True
    assert session["synthetic_replies"][0]["synthetic_reply_sent"] is True
    assert session["synthetic_replies"][0]["task_executed"] is False
    assert set(session["commands"][0]) == {
        "arguments_published",
        "direction",
        "message_kind",
        "observed_at_utc",
        "opcode",
        "packet_kind",
        "raw_published",
        "sequence",
        "wire_sha256",
        "wire_size",
    }

    monitoring = {
        "schema_version": 1,
        "policy": {"network_enabled": False},
        "results": [deepcopy(monitoring_plan()["targets"][0])],
    }
    public_digest = evidence.public_sha256(public)
    evidence.attach_sessions(
        monitoring,
        public,
        evidence_source="rat-emulation-evidence.json",
        evidence_sha256=public_digest,
    )

    activity = monitoring["results"][0]["rat_emulation"]
    assert activity["c2_confirmed_session_count"] == 1
    assert activity["command_count"] == 1
    assert activity["synthetic_reply_sent"] is True
    assert activity["task_executed"] is False
    assert activity["real_effect_performed"] is False
    assert monitoring["policy"]["rat_emulation_raw_transcript_published"] is False


def test_direct_monitoring_transport_is_separate_from_tls_emulator_transport(
    short_tmp: Path,
) -> None:
    assert EMULATOR_PROFILE["transport"] == "tls"
    assert monitoring_plan()["targets"][0]["transport"] == "direct"
    assert monitoring_plan()["targets"][0]["protocol"] == PROTOCOL
    source = short_tmp / "direct-monitoring-sidecar.json"
    digest = write_sidecar(source, sidecar())

    validated = evidence.load_and_validate(source, digest, monitoring_plan())
    session = validated["sessions"][0]
    assert session["transport"] == "direct"
    assert session["protocol"] == PROTOCOL

    for field, value in (("transport", "tls"), ("protocol", "tcp")):
        wrong_plan = monitoring_plan()
        wrong_plan["targets"][0][field] = value
        with pytest.raises(evidence.RatEmulationEvidenceError, match="endpoint|binding|plan外"):
            evidence.load_and_validate(source, digest, wrong_plan)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("family", "other-rat"),
        ("host", "203.0.113.11"),
        ("protocol_profile_id", "unreviewed-profile"),
        ("protocol_profile_registry_sha256", "9" * 64),
    ],
)
def test_load_rejects_session_binding_mismatch(
    short_tmp: Path,
    field: str,
    value: object,
) -> None:
    value_document = sidecar()
    value_document["sessions"][0][field] = value
    source = short_tmp / f"binding-{field}.json"
    digest = write_sidecar(source, value_document)

    with pytest.raises(evidence.RatEmulationEvidenceError, match="binding|endpoint|plan外"):
        evidence.load_and_validate(source, digest, monitoring_plan())


def test_load_rejects_sha_mismatch_and_unsafe_execution_claim(short_tmp: Path) -> None:
    source = short_tmp / "evidence.json"
    write_sidecar(source, sidecar())

    with pytest.raises(evidence.RatEmulationEvidenceError, match="pin"):
        evidence.load_and_validate(source, "0" * 64, monitoring_plan())

    unsafe = sidecar()
    unsafe["sessions"][0]["safety"]["task_executed"] = True
    unsafe_source = short_tmp / "unsafe.json"
    unsafe_digest = write_sidecar(unsafe_source, unsafe)
    with pytest.raises(evidence.RatEmulationEvidenceError, match="task_executed"):
        evidence.load_and_validate(unsafe_source, unsafe_digest, monitoring_plan())


def test_load_requires_private_transcript_root_hash(short_tmp: Path) -> None:
    value = sidecar()
    del value["sessions"][0]["private_evidence"]["transcript_root_sha256"]
    source = short_tmp / "missing-root.json"
    digest = write_sidecar(source, value)

    with pytest.raises(evidence.RatEmulationEvidenceError, match="transcript_root_sha256"):
        evidence.load_and_validate(source, digest, monitoring_plan())


def test_optional_pipeline_input_requires_path_and_sha_pin(short_tmp: Path) -> None:
    source = short_tmp / "evidence.json"
    digest = write_sidecar(source, sidecar())
    plan = monitoring_plan()

    assert load_optional_rat_emulation_evidence(None, None, plan) is None
    with pytest.raises(ValueError, match="同時"):
        load_optional_rat_emulation_evidence(source, None, plan)
    with pytest.raises(ValueError, match="同時"):
        load_optional_rat_emulation_evidence(None, digest, plan)

    public, public_digest = load_optional_rat_emulation_evidence(
        source,
        digest,
        plan,
    )
    assert public_digest == evidence.public_sha256(public)
    assert public["source_snapshot"]["sha256"] == digest
