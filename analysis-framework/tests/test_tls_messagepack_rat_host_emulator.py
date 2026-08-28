from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
MODULE = COMMON / "tls_messagepack_rat_host_emulator.py"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("tls_messagepack_rat_host_emulator", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HOST = _load()


class LoopbackStream:
    def __init__(self, incoming: bytes, *, chunk_size: int | None = None) -> None:
        self.incoming = bytearray(incoming)
        self.chunk_size = chunk_size
        self.sent: list[bytes] = []
        self.timeout_seconds: float | None = None
        self.recv_calls = 0

    def settimeout(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, maximum_bytes: int) -> bytes:
        self.recv_calls += 1
        if not self.incoming:
            return b""
        size = maximum_bytes
        if self.chunk_size is not None:
            size = min(size, self.chunk_size)
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk


class ApplicationFrameStream:
    def __init__(self, frame: bytes, *, before: object, after: object) -> None:
        self.frame = frame
        self.inbound_read_calls = before
        self.after = after
        self.sent: list[bytes] = []
        self.timeout_seconds: float | None = None
        self.application_read_calls = 0

    def settimeout(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv_application_frame(self, maximum_frame_bytes: int) -> bytes:
        self.application_read_calls += 1
        self.inbound_read_calls = self.after
        assert len(self.frame) <= maximum_frame_bytes
        return self.frame


def _frame_from_messagepack(raw: bytes) -> bytes:
    payload = struct.pack("<I", len(raw)) + gzip.compress(raw, mtime=0)
    return struct.pack("<I", len(payload)) + payload


def _decode(frame: bytes) -> dict[str, HOST.Scalar]:
    return HOST._decode_frame(frame, HOST.SessionLimits()).values


def _assert_no_bytes(value: Any) -> None:
    assert not isinstance(value, (bytes, bytearray, memoryview))
    if isinstance(value, dict):
        for key, item in value.items():
            _assert_no_bytes(key)
            _assert_no_bytes(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _assert_no_bytes(item)


def test_exact_async_registration_is_fixed_and_has_no_unconfirmed_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COMPUTERNAME", "REAL-HOST-MUST-NOT-LEAK")
    monkeypatch.setenv("USERNAME", "REAL-USER-MUST-NOT-LEAK")
    values = HOST.build_synthetic_client_info(HOST.ASYNC_PROFILE_ID)
    assert list(values) == [
        "Packet",
        "HWID",
        "User",
        "OS",
        "Path",
        "Admin",
        "Performance",
        "Pastebin",
        "Antivirus",
        "Installed",
        "Pong",
        "Group",
    ]
    assert values["Packet"] == "ClientInfo"
    assert values["User"] == "sandbox-user"
    assert "Version" not in values
    assert "REAL-HOST" not in repr(values)
    assert "REAL-USER" not in repr(values)
    profile = HOST.resolve_profile(HOST.ASYNC_PROFILE_ID)
    assert profile.evidence_sha256 == "479f96e2d8c9179e1e982ee094a1f83b102d1803cfe83f00fb1b711b93810340"


def test_exact_venom_registration_has_confirmed_version_and_map16() -> None:
    values = HOST.build_synthetic_client_info(HOST.VENOM_PROFILE_ID)
    assert len(values) == 22
    assert values["Pac_ket"] == "ClientInfo"
    assert values["ClientType"] == "Normal"
    assert values["Version"] == "Venom RAT + HVNC + Stealer + Grabber  v6.0.3"
    raw = HOST.encode_messagepack_map(values)
    assert raw[:3] == b"\xde\x00\x16"
    assert _decode(HOST.encode_frame(values)) == values
    profile = HOST.resolve_profile(HOST.VENOM_PROFILE_ID)
    assert profile.evidence_sha256 == "f1841e6e00e029065494ceedf32d11291261f10b17081f9d951b241c1e0015d8"


def test_current_venom_profile_is_evidence_pinned_decode_only() -> None:
    profile = HOST.resolve_profile(HOST.VENOM_CURRENT_PROFILE_ID)
    assert profile.sample_sha256 == ("2b0af18bdd10782cf72a985b2f49564aa9058c34645205afb4fcc27724794f6a")
    assert profile.registration_enabled is False
    assert profile.registration_fields == ()
    assert profile.heartbeat_request_reviewed is False
    assert profile.operation_opcodes == frozenset()
    assert profile.file_opcodes == frozenset({"plu_gin", "save_Plugin"})
    with pytest.raises(HOST.TlsMessagePackHostError, match="registration is disabled"):
        HOST.build_synthetic_client_info(HOST.VENOM_CURRENT_PROFILE_ID)

    assert profile.evidence_source == HOST.VENOM_CURRENT_EVIDENCE_SOURCE
    evidence_path = REPOSITORY_ROOT / profile.evidence_source
    evidence_raw = evidence_path.read_bytes()
    canonical = evidence_raw.decode("utf-8").replace("\r\n", "\n")
    assert "\r" not in canonical
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == profile.evidence_sha256
    evidence = json.loads(canonical)
    assert evidence["artifact_type"] == "venomrat_current_decode_profile_evidence"
    assert evidence["static_configuration"]["group"] == "Default"
    assert evidence["static_configuration"]["install"] == "false"
    assert evidence["static_configuration"]["configured_endpoint"]["use_by_profile"] is False
    assert evidence["registration"]["registration_enabled"] is False
    assert evidence["registration"]["synthetic_client_info_send_allowed"] is False
    assert evidence["messagepack_protocol"]["operation_opcodes"] == []
    assert evidence["messagepack_protocol"]["heartbeat_request"]["send_allowed"] is False
    for artifact in evidence["source_artifacts"]:
        source_raw = (REPOSITORY_ROOT / artifact["path"]).read_bytes()
        source_canonical = source_raw.decode("utf-8").replace("\r\n", "\n")
        assert hashlib.sha256(source_canonical.encode("utf-8")).hexdigest() == (artifact["canonical_lf_json_sha256"])

    current_path = next(
        item["path"]
        for item in evidence["source_artifacts"]
        if "/versions/unknown/" in item["path"] and item["path"].endswith("static-logic.json")
    )
    old_path = next(
        item["path"]
        for item in evidence["source_artifacts"]
        if "/versions/v6.0.3/" in item["path"] and item["path"].endswith("static-logic.json")
    )
    current_logic = json.loads((REPOSITORY_ROOT / current_path).read_text(encoding="utf-8"))
    old_logic = json.loads((REPOSITORY_ROOT / old_path).read_text(encoding="utf-8"))
    current_hashes = {
        function["name"]: function["fingerprints"]["semantic_sequence_sha256"]
        for function in current_logic["functions"]
    }
    old_hashes = {
        function["name"]: function["fingerprints"]["semantic_sequence_sha256"] for function in old_logic["functions"]
    }
    for method in evidence["semantic_lineage"]["methods"]:
        name = method["name"]
        expected = method["semantic_sequence_sha256"]
        assert current_hashes[name] == old_hashes[name] == expected


def test_messagepack_round_trip_supports_map16_strings_integers_and_binary() -> None:
    values: dict[str, HOST.Scalar] = {f"k{index}": index for index in range(13)}
    values.update({"text": "hello", "negative": -33, "binary": b"\x00\x01payload"})
    frame = HOST.encode_frame(values)
    assert _decode(frame) == values


def test_duplicate_map_key_is_rejected() -> None:
    raw = b"\x82\xa1A\xa1x\xa1A\xa1y"
    with pytest.raises(HOST.TlsMessagePackHostError, match="duplicate"):
        HOST._decode_frame(_frame_from_messagepack(raw), HOST.SessionLimits())


@pytest.mark.parametrize(
    "raw",
    [
        b"\x81\xd9\x01A\xa1x",
        b"\xde\x00\x01\xa1A\xa1x",
        b"\x81\xa1A\xcd\x00\x80",
        b"\x81\xa1A\xc5\x00\x01x",
    ],
)
def test_noncanonical_overlong_encodings_are_rejected(raw: bytes) -> None:
    with pytest.raises(HOST.TlsMessagePackHostError, match="overlong"):
        HOST._decode_frame(_frame_from_messagepack(raw), HOST.SessionLimits())


def test_trailing_gzip_member_is_rejected() -> None:
    raw = HOST.encode_messagepack_map({"Packet": "pong"})
    compressed = gzip.compress(raw, mtime=0) + gzip.compress(b"x", mtime=0)
    payload = struct.pack("<I", len(raw)) + compressed
    frame = struct.pack("<I", len(payload)) + payload
    with pytest.raises(HOST.TlsMessagePackHostError, match="concatenated|trailing"):
        HOST._decode_frame(frame, HOST.SessionLimits())


def test_declared_size_prevents_decompression_bomb() -> None:
    raw = b"A" * 4096
    payload = struct.pack("<I", 1) + gzip.compress(raw, mtime=0)
    frame = struct.pack("<I", len(payload)) + payload
    with pytest.raises(HOST.TlsMessagePackHostError, match="bomb|size"):
        HOST._decode_frame(frame, HOST.SessionLimits())


@pytest.mark.parametrize(
    ("profile_id", "packet_key", "opcode"),
    [
        (HOST.ASYNC_PROFILE_ID, "Packet", "savePlugin"),
        (HOST.ASYNC_PROFILE_ID, "Packet", "winUpdate"),
        (HOST.VENOM_PROFILE_ID, "Pac_ket", "plu_gin"),
        (HOST.VENOM_PROFILE_ID, "Pac_ket", "loadofflinelog"),
    ],
)
def test_file_and_plugin_commands_are_fingerprinted_but_never_retained(
    profile_id: str, packet_key: str, opcode: str
) -> None:
    secret = b"PLUGIN-BYTES-MUST-NOT-LEAK"
    incoming = HOST.encode_frame({packet_key: opcode, "Dll": secret})
    stream = LoopbackStream(incoming)
    result = HOST.run_host_session(stream, profile_id, allow_registration=True)
    assert result["status"] == "file_or_plugin_refused"
    assert result["command"]["packet_kind"] == "file_or_plugin"
    assert result["command"]["fingerprint"]["binary_payload_count"] == 1
    assert result["command"]["fingerprint"]["binary_payload_size"] == len(secret)
    expected = hashlib.sha256(struct.pack(">Q", len(secret)) + secret).hexdigest()
    assert result["command"]["fingerprint"]["binary_payload_sha256"] == expected
    assert secret.decode() not in repr(result)
    assert len(stream.sent) == 1
    assert result["safety"]["file_or_plugin_retained"] is False
    assert result["safety"]["file_or_plugin_executed"] is False
    _assert_no_bytes(result)


@pytest.mark.parametrize(
    ("profile_id", "packet_key", "opcode"),
    [
        (HOST.VENOM_PROFILE_ID, "Pac_ket", "HVNCStop"),
    ],
)
def test_operation_commands_have_no_effect_and_receive_no_reply(profile_id: str, packet_key: str, opcode: str) -> None:
    stream = LoopbackStream(HOST.encode_frame({packet_key: opcode, "Message": "ignored"}))
    result = HOST.run_host_session(stream, profile_id, allow_registration=True)
    assert result["command"]["packet_kind"] == "operation"
    assert result["command"]["operation_executed"] is False
    assert result["safety"]["real_effect_performed"] is False
    assert result["safety"]["secondary_network_performed"] is False
    assert len(stream.sent) == 1


@pytest.mark.parametrize(
    ("profile_id", "packet_key", "opcode"),
    [
        (HOST.ASYNC_PROFILE_ID, "Packet", "pong"),
        (HOST.VENOM_PROFILE_ID, "Pac_ket", "Po_ng"),
    ],
)
def test_only_reviewed_fixed_ping_can_be_sent_before_heartbeat_response(
    profile_id: str, packet_key: str, opcode: str
) -> None:
    stream = LoopbackStream(HOST.encode_frame({packet_key: opcode, "Message": 91}))
    events: list[dict[str, Any]] = []
    result = HOST.run_host_session(
        stream,
        profile_id,
        allow_registration=True,
        allow_heartbeat_request=True,
        transcript_callback=events.append,
    )
    assert result["status"] == "heartbeat_response_observed"
    assert len(stream.sent) == 2
    assert _decode(stream.sent[1]) == {packet_key: "Ping", "Message": ""}
    assert result["heartbeat_request"]["sent"] is True
    assert result["heartbeat_request"]["synthetic"] is True
    assert result["command"]["should_respond"] is False
    assert result["command"]["opcode"] == opcode
    assert "protocol_identifier" not in result["command"]
    assert result["safety"]["arbitrary_fake_result_sent"] is False
    assert [event["event"] for event in events] == [
        "registration_sent",
        "heartbeat_request_sent",
        "command_classified",
        "session_terminated",
    ]
    assert events[-2]["opcode"] == opcode
    assert events[-1]["opcode"] == opcode
    assert "protocol_identifier" not in events[-2]
    assert "protocol_identifier" not in events[-1]
    _assert_no_bytes(events)


def test_heartbeat_request_requires_separate_explicit_approval() -> None:
    stream = LoopbackStream(HOST.encode_frame({"Packet": "pong"}))
    result = HOST.run_host_session(stream, HOST.ASYNC_PROFILE_ID, allow_registration=True)
    assert result["status"] == "unsolicited_heartbeat_response_observed"
    assert result["heartbeat_request"]["sent"] is False
    assert len(stream.sent) == 1


def test_current_venom_unreviewed_heartbeat_fails_before_registration() -> None:
    stream = LoopbackStream(HOST.encode_frame({"Pac_ket": "Po_ng"}))
    with pytest.raises(HOST.TlsMessagePackHostError, match="registration is disabled"):
        HOST.run_host_session(
            stream,
            HOST.VENOM_CURRENT_PROFILE_ID,
            allow_registration=True,
            allow_heartbeat_request=True,
        )
    assert stream.sent == []
    assert stream.timeout_seconds is None


def test_unknown_command_terminates_without_reply_or_argument_disclosure() -> None:
    stream = LoopbackStream(HOST.encode_frame({"Packet": "mystery", "token": "secret"}))
    events: list[dict[str, Any]] = []
    result = HOST.run_host_session(
        stream,
        HOST.ASYNC_PROFILE_ID,
        allow_registration=True,
        transcript_callback=events.append,
    )
    opcode_digest = hashlib.sha256(b"mystery").hexdigest()
    assert result["status"] == "unknown_command_terminated"
    assert result["command"]["opcode"] is None
    assert result["command"]["protocol_identifier"] is None
    assert result["command"]["protocol_identifier_sha256"] == opcode_digest
    assert "secret" not in repr(result)
    assert "token" not in repr(result)
    assert "mystery" not in repr(result)
    assert "mystery" not in repr(events)
    for event in events[-2:]:
        assert event["opcode"] is None
        assert event["protocol_identifier"] is None
        assert event["protocol_identifier_sha256"] == opcode_digest
    assert len(stream.sent) == 1


def test_registration_must_be_explicitly_approved() -> None:
    stream = LoopbackStream(HOST.encode_frame({"Packet": "pong"}))
    with pytest.raises(HOST.TlsMessagePackHostError, match="explicit approval"):
        HOST.run_host_session(stream, HOST.ASYNC_PROFILE_ID)
    assert stream.sent == []
    assert stream.timeout_seconds is None


def test_profile_registry_binding_mismatch_is_rejected() -> None:
    with pytest.raises(HOST.TlsMessagePackHostError, match="binding mismatch"):
        HOST.resolve_profile(
            {
                "profile_id": HOST.ASYNC_PROFILE_ID,
                "family": "venomrat",
                "handler": "asyncrat_tls_messagepack",
            }
        )


def test_malformed_response_gets_no_command_reply() -> None:
    stream = LoopbackStream(struct.pack("<I", 128) + b"short")
    with pytest.raises(HOST.TlsMessagePackHostError, match="closed"):
        HOST.run_host_session(stream, HOST.ASYNC_PROFILE_ID, allow_registration=True)
    assert len(stream.sent) == 1


def test_read_call_limit_is_enforced() -> None:
    incoming = HOST.encode_frame({"Packet": "pong"})
    stream = LoopbackStream(incoming, chunk_size=1)
    with pytest.raises(HOST.TlsMessagePackHostError, match="read-call"):
        HOST.run_host_session(
            stream,
            HOST.ASYNC_PROFILE_ID,
            allow_registration=True,
            session_limits={"maximum_read_calls": 2},
        )
    assert len(stream.sent) == 1


def test_application_frame_reader_read_call_delta_limit_is_enforced() -> None:
    stream = ApplicationFrameStream(
        HOST.encode_frame({"Packet": "pong"}),
        before=10,
        after=13,
    )
    events: list[dict[str, Any]] = []
    with pytest.raises(HOST.TlsMessagePackHostError, match="read-call limit"):
        HOST.run_host_session(
            stream,
            HOST.ASYNC_PROFILE_ID,
            allow_registration=True,
            session_limits={"maximum_read_calls": 2},
            transcript_callback=events.append,
        )
    assert stream.application_read_calls == 1
    assert len(stream.sent) == 1
    assert [event["event"] for event in events] == ["registration_sent"]


@pytest.mark.parametrize(
    ("before", "after", "expected_application_reads", "error"),
    [
        (None, 1, 0, "non-negative integer"),
        (True, 1, 0, "non-negative integer"),
        (-1, 0, 0, "non-negative integer"),
        (3, 2, 1, "decreased"),
        (0, "1", 1, "non-negative integer"),
        (0, True, 1, "non-negative integer"),
        (0, -1, 1, "non-negative integer"),
    ],
)
def test_application_frame_reader_rejects_invalid_read_call_counters(
    before: object,
    after: object,
    expected_application_reads: int,
    error: str,
) -> None:
    stream = ApplicationFrameStream(
        HOST.encode_frame({"Packet": "pong"}),
        before=before,
        after=after,
    )
    with pytest.raises(HOST.TlsMessagePackHostError, match=error):
        HOST.run_host_session(
            stream,
            HOST.ASYNC_PROFILE_ID,
            allow_registration=True,
        )
    assert stream.application_read_calls == expected_application_reads
    assert len(stream.sent) == 1


def test_application_frame_reader_reports_valid_read_call_delta() -> None:
    stream = ApplicationFrameStream(
        HOST.encode_frame({"Packet": "pong"}),
        before=10,
        after=12,
    )
    result = HOST.run_host_session(
        stream,
        HOST.ASYNC_PROFILE_ID,
        allow_registration=True,
        session_limits={"maximum_read_calls": 2},
    )
    assert result["collection"]["read_calls"] == 2
    assert result["status"] == "unsolicited_heartbeat_response_observed"


def test_send_byte_limit_is_checked_before_registration_send() -> None:
    stream = LoopbackStream(HOST.encode_frame({"Packet": "pong"}))
    with pytest.raises(HOST.TlsMessagePackHostError, match="send-byte"):
        HOST.run_host_session(
            stream,
            HOST.ASYNC_PROFILE_ID,
            allow_registration=True,
            session_limits={"maximum_send_bytes": 64},
        )
    assert stream.sent == []


def test_arbitrary_synthetic_result_has_no_live_wire_representation() -> None:
    decision = HOST.synthetic_result_decision(HOST.VENOM_PROFILE_ID, "runningapp", "not_executed")
    assert decision["send_allowed"] is False
    assert decision["fixture_only"] is True
    assert decision["wire_schema_status"] == "operation_result_serializer_unresolved"
    assert decision["wire_bytes"] is None
    assert decision["family"] == "venomrat"
    assert decision["direction"] == "client_to_server"
    assert decision["operation_executed"] is False
    assert decision["real_effect_performed"] is False
    assert decision["arbitrary_fake_result_sent"] is False
    assert HOST.LIVE_ARBITRARY_RESULT_ALLOWED is False


def test_module_does_not_read_host_identity_environment() -> None:
    source = (COMMON / "tls_messagepack_rat_host_emulator.py").read_text(encoding="utf-8")
    forbidden = ["os.environ", "os.getenv", "gethostname(", "getpass.getuser", "platform."]
    assert not any(item in source for item in forbidden)
    assert "socket.create_connection" not in source
    assert "subprocess" not in source
    assert os.environ.get("USERNAME") not in repr(HOST.build_synthetic_client_info(HOST.ASYNC_PROFILE_ID))
