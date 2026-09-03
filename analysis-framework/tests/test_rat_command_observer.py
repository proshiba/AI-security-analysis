from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import rat_command_observer as observer  # noqa: E402
from tls_messagepack_rat_host_emulator import encode_frame  # noqa: E402

VENOM_SAMPLE = "6a24ba25482c73d193fcc208d8ae267236b870b9ab30c44cabe2dc8bfb7a1073"
VENOM_CURRENT_SAMPLE = "2b0af18bdd10782cf72a985b2f49564aa9058c34645205afb4fcc27724794f6a"
STEALC_SAMPLE = "47854afb3cfeb64a85dda148e00e5ca83168f431a28e5c5fb28733e37f484b13"
REMUS_SAMPLE = "2b3a23db5ca7464a5c7f0975790af54097ed127a66ab0b551123831e8f40dfc6"
VIDAR_SAMPLE = "3d2cea3eaa43053ae0efa20de8544387d7cabeb70c89980f4241f3b6efa0e323"
VIDAR_CURRENT_SAMPLE = "0030c014ec4fae311492a87011f565f9ff3b1881137dda152953c6fe718e33e0"


def remcos_frame(command_id: int, *fields: bytes) -> bytes:
    payload = observer.REMCOS_DELIMITER.join(fields)
    following = struct.pack("<I", command_id) + payload
    return observer.REMCOS_MAGIC + struct.pack("<I", len(following)) + following


def vidar_result(candidate: str | None = "8.8.8.8:443") -> dict:
    return {
        "schema_version": 1,
        "profile": "vidar_dead_drop_snapshot_correlation_v1",
        "sample_sha256": VIDAR_SAMPLE,
        "status": "correlated_final_c2_candidate" if candidate else "inconclusive_snapshot_set",
        "final_c2_candidate": candidate,
        "final_c2_candidate_recovered": candidate is not None,
        "c2_confirmed": False,
        "probable_c2": candidate is not None,
        "confidence": 0.85 if candidate else 0.0,
        "corroborating_service_count": 2 if candidate else 0,
        "observations": [],
        "safety": {
            "network_contacted": False,
            "sample_executed": False,
            "raw_snapshot_published": False,
            "shared_service_is_c2": False,
            "active_probe_required": False,
        },
    }


def test_unknown_profile_and_wrong_sample_fail_closed() -> None:
    with pytest.raises(observer.RatCommandObserverError, match="未レビュー"):
        observer.observe_command("venomrat", {}, direction="server_to_client")
    with pytest.raises(observer.RatCommandObserverError, match="sample SHA-256"):
        observer.observe_command(
            "stealc-v2-1backs-decoded-json-v1",
            {"type": "create"},
            direction="client_to_server",
            sample_sha256="8a7e70710748b10cec4c9f0653c55a0439a7f5f8f51b1e60284ace75a2118c7b",
        )


def test_non_string_mapping_key_fails_closed() -> None:
    with pytest.raises(observer.RatCommandObserverError, match="key"):
        observer.observe_command(
            "stealc-v2-1backs-decoded-json-v1",
            {"opcode": "error", 1: "invalid"},
            direction="server_to_client",
            sample_sha256=STEALC_SAMPLE,
        )


def test_command_observation_requires_internal_factory() -> None:
    with pytest.raises(observer.RatCommandObserverError, match="internal factory"):
        observer.CommandObservation(
            profile=observer.resolve_profile("remcos-decrypted-plaintext-framing-v1"),
            direction="server_to_client",
            event_kind="forged",
            category="forged",
            normalized_command="forged",
            protocol_identifier="forged",
            identifier_confidence="forged",
            message_size=1,
            message_sha256="0" * 64,
            public_details={
                "operation_executed": True,
                "raw_content_published": True,
                "token": "SECRET",
            },
        )


@pytest.mark.parametrize(
    ("profile_id", "message", "direction", "sample_sha256"),
    [
        (
            "venomrat-603-6a24ba25-messagepack-v1",
            b"unused",
            "client_to_server",
            VENOM_SAMPLE,
        ),
        (
            "remus-ba0044e8-decoded-task-v1",
            {},
            "client_to_server",
            REMUS_SAMPLE,
        ),
        (
            "vidar-dead-drop-snapshot-v1",
            {},
            "server_to_client",
            VIDAR_SAMPLE,
        ),
    ],
)
def test_profile_direction_mismatch_fails_closed(
    profile_id: str,
    message: dict | bytes,
    direction: str,
    sample_sha256: str,
) -> None:
    with pytest.raises(observer.RatCommandObserverError, match="許可方向"):
        observer.observe_command(
            profile_id,
            message,
            direction=direction,
            sample_sha256=sample_sha256,
        )


def test_venom_exact_plugin_frame_is_observed_without_retaining_binary_publicly() -> None:
    frame = encode_frame({"Pac_ket": "plu_gin", "Dll": b"PRIVATE-PLUGIN"})
    result = observer.observe_command(
        "venomrat-603-6a24ba25-messagepack-v1",
        frame,
        direction="server_to_client",
        sample_sha256=VENOM_SAMPLE,
    )
    public = result.public_event()
    assert public["normalized_command"] == "plugin_delivery"
    assert public["category"] == "payload_transfer"
    assert public["operation_executed"] is False
    assert public["plugin_retained_by_observer"] is False
    assert "PRIVATE-PLUGIN" not in json.dumps(public)
    assert result.private_fields["decoded_message"]["Dll"]["binary_size"] == 14


def test_venom_unknown_opcode_is_hashed_but_not_published() -> None:
    frame = encode_frame({"Pac_ket": "private-command-name", "Message": "secret"})
    result = observer.observe_command(
        "venomrat-603-6a24ba25-messagepack-v1",
        frame,
        direction="server_to_client",
        sample_sha256=VENOM_SAMPLE,
    ).public_event()
    assert result["normalized_command"] == "unknown"
    assert result["protocol_identifier"] is None
    assert result["protocol_identifier_sha256"] == hashlib.sha256(b"private-command-name").hexdigest()


@pytest.mark.parametrize(
    ("opcode", "expected_kind", "expected_normalized"),
    [
        ("Po_ng", "heartbeat", "heartbeat_response"),
        ("plu_gin", "file_or_plugin", "plugin_delivery"),
        ("HVNCStop", "unknown", "unknown"),
    ],
)
def test_current_venom_exact_messagepack_frame_classification(
    opcode: str,
    expected_kind: str,
    expected_normalized: str,
) -> None:
    frame = encode_frame({"Pac_ket": opcode, "Message": "offline-fixture"})
    public = observer.observe_command(
        "venomrat-603-2b0af18b-messagepack-v1",
        frame,
        direction="server_to_client",
        sample_sha256=VENOM_CURRENT_SAMPLE,
    ).public_event()
    assert public["packet_kind"] == expected_kind
    assert public["normalized_command"] == expected_normalized
    if expected_kind == "unknown":
        assert public["identifier_confidence"] == "unknown"
        assert public["protocol_identifier"] is None
    assert public["protocol_status"] == ("one_bounded_inbound_frame_heartbeat_request_unreviewed")
    assert public["operation_executed"] is False


def test_current_venom_observer_does_not_accept_old_exact_sample() -> None:
    frame = encode_frame({"Pac_ket": "Po_ng"})
    with pytest.raises(observer.RatCommandObserverError, match="sample SHA-256"):
        observer.observe_command(
            "venomrat-603-2b0af18b-messagepack-v1",
            frame,
            direction="server_to_client",
            sample_sha256=VENOM_SAMPLE,
        )


def test_stealc_configuration_and_loader_are_distinct() -> None:
    config = observer.observe_command(
        "stealc-v2-1backs-decoded-json-v1",
        {"opcode": "success", "access_token": "a" * 64, "self_delete": True, "loader": False, "browsers": ["fixture"]},
        direction="server_to_client",
        sample_sha256=STEALC_SAMPLE,
    ).public_event()
    loader = observer.observe_command(
        "stealc-v2-1backs-decoded-json-v1",
        {"opcode": "success", "loader": [{"url": "https://payload.invalid/private.exe"}]},
        direction="server_to_client",
        sample_sha256=STEALC_SAMPLE,
    )
    assert config["normalized_command"] == "initial_configuration"
    assert config["configuration_fields"] == ["browsers", "loader", "self_delete"]
    assert loader.public_event()["normalized_command"] == "loader_configuration"
    assert loader.public_event()["loader_entry_schema_confirmed"] is True
    assert "payload.invalid" not in json.dumps(loader.public_event())
    assert loader.private_fields["decoded_message"]["loader"][0]["url"].startswith("https://")


@pytest.mark.parametrize(
    ("status", "normalized"),
    [
        ("blocked", "registration_blocked"),
        ("block", "registration_blocked"),
        ("error", "status_error"),
        ("unknown", "status_unknown"),
        ("error1", "status_error1"),
        ("error5", "status_error5"),
    ],
)
def test_stealc_status_taxonomy(status: str, normalized: str) -> None:
    result = observer.observe_command(
        "stealc-v2-1backs-decoded-json-v1",
        {"opcode": status},
        direction="server_to_client",
        sample_sha256=STEALC_SAMPLE,
    ).public_event()
    assert result["normalized_command"] == normalized
    assert result["operation_executed"] is False


def test_stealc_dynamic_hex_field_does_not_break_deduplication() -> None:
    first = observer.observe_command(
        "stealc-v2-1backs-decoded-json-v1",
        {"opcode": "success", "access_token": "a" * 64, "self_delete": True, "abcdef1234": "1111111111"},
        direction="server_to_client",
        sample_sha256=STEALC_SAMPLE,
    )
    second = observer.observe_command(
        "stealc-v2-1backs-decoded-json-v1",
        {"opcode": "success", "access_token": "b" * 64, "self_delete": True, "abcdef5678": "2222222222"},
        direction="server_to_client",
        sample_sha256=STEALC_SAMPLE,
    )
    assert first.message_sha256 == second.message_sha256
    assert first.public_event()["dynamic_hex_field_count"] == 1


def test_remus_retains_unknown_name_and_data_only_in_private_event() -> None:
    result = observer.observe_command(
        "remus-ba0044e8-decoded-task-v1",
        {"type": 3, "name": "cmd.exe /c whoami", "data": "private-data"},
        direction="server_to_client",
        sample_sha256=REMUS_SAMPLE,
    )
    public = result.public_event()
    assert public["normalized_command"] == "task_type_3"
    assert public["task_schema_confirmed"] is False
    assert "whoami" not in json.dumps(public)
    assert result.private_fields["decoded_task_envelope"]["name"].endswith("whoami")
    with pytest.raises(observer.RatCommandObserverError, match="key集合"):
        observer.observe_command(
            "remus-ba0044e8-decoded-task-v1",
            {"type": 3, "name": "x", "data": "y", "extra": True},
            direction="server_to_client",
            sample_sha256=REMUS_SAMPLE,
        )


def test_remcos_plaintext_command_line_is_private_and_length_bound() -> None:
    frame = remcos_frame(0x0E, b"cmd.exe /c whoami", b"20")
    result = observer.observe_command(
        "remcos-published-340-taxonomy-v1",
        frame,
        direction="server_to_client",
    )
    public = result.public_event()
    assert public["normalized_command"] == "interactive_shell"
    assert public["protocol_identifier"] == "0x0e"
    assert public["taxonomy_source"] == observer.REMCOS_PUBLISHED_TAXONOMY_SOURCE
    assert public["taxonomy_evidence_artifact_pinned"] is False
    assert "whoami" not in json.dumps(public)
    assert result.private_fields["decoded_payload_fields"][0] == "cmd.exe /c whoami"
    malformed = bytearray(frame)
    malformed[4:8] = struct.pack("<I", 1)
    with pytest.raises(observer.RatCommandObserverError, match="実長"):
        observer.parse_remcos_plaintext_frame(malformed)


def test_remcos_plaintext_field_count_is_bounded() -> None:
    fields = (b"x",) * (observer.MAXIMUM_COLLECTION_ITEMS + 1)
    with pytest.raises(observer.RatCommandObserverError, match="field数"):
        observer.parse_remcos_plaintext_frame(remcos_frame(0x0E, *fields))


def test_remcos_stream_decoder_handles_one_byte_fragmentation_and_coalescing() -> None:
    first = remcos_frame(0x01, b"0", b"30")
    second = remcos_frame(0x11, b"alpha")
    third = remcos_frame(0x1F, b"beta")
    decoder = observer.RemcosPlaintextStreamDecoder()

    emitted: list[bytes] = []
    for byte in first:
        emitted.extend(decoder.feed(bytes([byte])))
    assert emitted == [first]
    assert decoder.feed(second + third) == [second, third]
    assert decoder.total_input_bytes == len(first) + len(second) + len(third)
    assert decoder.decoded_frames == 3
    assert decoder.buffered_bytes == 0
    decoder.finish()


def test_remcos_stream_decoder_fails_closed_on_truncation_magic_and_limits() -> None:
    frame = remcos_frame(0x01, b"0", b"30")

    truncated = observer.RemcosPlaintextStreamDecoder()
    assert truncated.feed(frame[:-1]) == []
    with pytest.raises(observer.RatCommandObserverError, match="不完全"):
        truncated.finish()

    bad_magic = observer.RemcosPlaintextStreamDecoder()
    with pytest.raises(observer.RatCommandObserverError, match="magic"):
        bad_magic.feed(b"X")

    oversized = observer.RemcosPlaintextStreamDecoder(
        maximum_frame_bytes=12,
        maximum_stream_bytes=64,
    )
    with pytest.raises(observer.RatCommandObserverError, match="frameが上限"):
        oversized.feed(frame)

    limited = observer.RemcosPlaintextStreamDecoder(maximum_frames=1)
    with pytest.raises(observer.RatCommandObserverError, match="frame数"):
        limited.feed(frame + frame)


def test_remcos_unversioned_profile_publishes_id_but_not_guessed_semantics() -> None:
    frame = remcos_frame(0x0E, b"private command line")
    result = observer.observe_command(
        "remcos-decrypted-plaintext-framing-v1",
        frame,
        direction="server_to_client",
        sample_sha256="61321510045ef68e4e20672cb1b130a2632d7b3cb1c3c8348c4c5e300d0d8a19",
    )

    public = result.public_event()
    assert public["protocol_identifier"] == "0x0e"
    assert public["normalized_command"] == "unknown"
    assert public["identifier_confidence"] == "observed_identifier_semantics_unresolved"
    assert public["published_taxonomy_applied"] is False
    assert public["exact_sample_binding"] is False
    assert public["taxonomy_source"] is None
    assert "private command line" not in json.dumps(public)
    assert result.private_fields["decoded_payload_fields"] == ["private command line"]


def test_vidar_is_configuration_instruction_not_interactive_command() -> None:
    result = observer.observe_command(
        "vidar-dead-drop-snapshot-v1",
        vidar_result(),
        direction="internal",
        sample_sha256=VIDAR_SAMPLE,
    )
    public = result.public_event()
    assert public["event_kind"] == "configuration_instruction"
    assert public["interactive_command"] is False
    assert public["candidate_present"] is True
    assert "8.8.8.8" not in json.dumps(public)
    assert result.private_fields["snapshot_result"]["final_c2_candidate"] == "8.8.8.8:443"


def test_vidar_current_decoded_correlation_remains_bootstrap_only() -> None:
    message = vidar_result("correlated.example:443")
    message.update(
        {
            "sample_sha256": VIDAR_CURRENT_SAMPLE,
            "status": "decoded_correlated_final_c2_candidate",
            "confidence": 0.95,
            "endpoint_resolution": {
                "method": "tag_bound_enc_decoder_two_service_correlation",
                "shared_service_response_decoded": True,
                "protocol_recovered": False,
                "protocol_status": "unresolved_static_protocol",
            },
            "safety": {
                "network_contacted": False,
                "sample_executed": False,
                "tool_published_raw_response": False,
                "tool_managed_output_repository_publication": False,
                "shared_service_is_c2": False,
                "active_probe_required": False,
            },
        }
    )
    result = observer.observe_command(
        "vidar-dead-drop-snapshot-v1",
        message,
        direction="internal",
        sample_sha256=VIDAR_CURRENT_SAMPLE,
    )
    public = result.public_event()
    assert public["protocol_status"] == "bootstrap_resolver_only_not_interactive_command_c2"
    assert public["normalized_command"] == "correlated_endpoint_candidate"
    assert public["interactive_command"] is False
    assert "correlated.example" not in json.dumps(public)


def test_vidar_current_decoded_correlation_requires_two_services() -> None:
    message = vidar_result("correlated.example:443")
    message.update(
        {
            "sample_sha256": VIDAR_CURRENT_SAMPLE,
            "status": "decoded_correlated_final_c2_candidate",
            "corroborating_service_count": 1,
            "endpoint_resolution": {
                "method": "tag_bound_enc_decoder_two_service_correlation",
                "shared_service_response_decoded": True,
                "protocol_recovered": False,
                "protocol_status": "unresolved_static_protocol",
            },
            "safety": {
                "network_contacted": False,
                "sample_executed": False,
                "tool_published_raw_response": False,
                "tool_managed_output_repository_publication": False,
                "shared_service_is_c2": False,
                "active_probe_required": False,
            },
        }
    )
    with pytest.raises(observer.RatCommandObserverError, match="status/count"):
        observer.observe_command(
            "vidar-dead-drop-snapshot-v1",
            message,
            direction="internal",
            sample_sha256=VIDAR_CURRENT_SAMPLE,
        )


def test_quasar_upstream_taxonomy_never_claims_exact_sample_wire_match() -> None:
    result = observer.observe_command(
        "quasar-upstream-decoded-message-v1",
        {
            "$type": "Quasar.Common.Messages.DoShellExecute, Quasar.Common",
            "Command": "powershell.exe -NoProfile -Command private",
        },
        direction="server_to_client",
        sample_sha256="a63cffc78eea1c004b2e56ef5ae6573662376b5c6ec8ebbaef27cac7344fc743",
    )
    public = result.public_event()
    assert public["normalized_command"] == "shell_execute"
    assert public["exact_sample_wire_match"] is False
    assert public["serializer_reimplemented"] is False
    assert "powershell" not in json.dumps(public).casefold()
    assert "powershell" in result.private_fields["decoded_message"]["Command"].casefold()


def test_binary_spool_decoder_rejects_extra_keys_and_invalid_base64() -> None:
    envelope = {
        "schema_version": 1,
        "profile_id": "remcos-published-340-taxonomy-v1",
        "sample_sha256": None,
        "source_scope": "offline_capture",
        "direction": "server_to_client",
        "captured_at": "2026-08-27T00:00:00Z",
        "encoding": "frame_base64",
        "frame_base64": base64.b64encode(remcos_frame(0x01, b"0", b"20")).decode("ascii"),
    }
    assert isinstance(observer.decode_spool_message(envelope["profile_id"], envelope), bytes)
    with pytest.raises(observer.RatCommandObserverError, match="key集合"):
        observer.decode_spool_message(envelope["profile_id"], {**envelope, "unsafe": True})
    with pytest.raises(observer.RatCommandObserverError, match="base64"):
        observer.decode_spool_message(envelope["profile_id"], {**envelope, "frame_base64": "%%%"})

    mutations = [
        {**envelope, "schema_version": 999},
        {**envelope, "profile_id": "remcos-decrypted-plaintext-framing-v1"},
        {**envelope, "source_scope": "live_c2"},
        {**envelope, "direction": "client_to_server"},
        {**envelope, "captured_at": "not-a-time"},
        {**envelope, "sample_sha256": "not-a-sha256"},
        {key: value for key, value in envelope.items() if key != "captured_at"},
    ]
    for mutation in mutations:
        with pytest.raises(observer.RatCommandObserverError):
            observer.decode_spool_message(envelope["profile_id"], mutation)
