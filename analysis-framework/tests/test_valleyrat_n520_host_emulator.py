"""ValleyRAT/N520 host adapterの安全境界をloopback fixtureで検証する。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE = FRAMEWORK / "malware" / "valleyrat" / "n520_host_emulator.py"


def _load():
    spec = importlib.util.spec_from_file_location("valleyrat_n520_host_emulator", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


N520 = _load()
HANDSHAKE = base64.b64decode(
    "VedMRkxG6ePmvrff01cXjuWZG+aqQh24G//XqST3EZ6HtDJGPpyDZkEDR1c="
)


class LoopbackStream:
    """server-first responseを返し、client送信を記録するfixture。"""

    def __init__(self, incoming: bytes, *, finish: str = "timeout") -> None:
        self.incoming = bytearray(incoming)
        self.finish = finish
        self.sent: list[bytes] = []
        self.timeout_seconds: float | None = None
        self.recv_calls = 0

    def settimeout(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, maximum_bytes: int) -> bytes:
        self.recv_calls += 1
        if self.incoming:
            chunk = bytes(self.incoming[:maximum_bytes])
            del self.incoming[:maximum_bytes]
            return chunk
        if self.finish == "closed":
            return b""
        raise TimeoutError("loopback idle")


def _server_frame(command: int, payload: bytes = b"", *, sequence: int = 7) -> bytes:
    parsed = N520.parse_handshake(HANDSHAKE)
    return N520.build_packet(
        parsed["session_id"],
        sequence,
        command,
        payload,
        N520.derive_session_key(HANDSHAKE),
        iv=bytes([command]) * 16,
    )


def test_builds_exactly_one_empty_command_one_registration() -> None:
    packet = N520.build_empty_registration(HANDSHAKE, iv=b"R" * 16)
    parsed = N520.parse_handshake(HANDSHAKE)
    frames, remainder = N520.decode_stream(
        packet,
        parsed["session_id"],
        N520.derive_session_key(HANDSHAKE),
    )
    assert remainder == b""
    assert len(frames) == 1
    assert frames[0]["authenticated"] is True
    assert frames[0]["sequence"] == 1
    assert frames[0]["command"] == 1
    assert frames[0]["payload"] == b""


def test_unknown_command_is_fingerprinted_without_response_and_terminates() -> None:
    payload = b"unknown-command-fixture-secret"
    stream = LoopbackStream(HANDSHAKE + _server_frame(99, payload))
    events: list[dict] = []
    result = N520.run_bounded_host_session(
        stream,
        policy=N520.HostPolicy(maximum_response_bytes=4096),
        allow_empty_registration=True,
        registration_iv=b"R" * 16,
        transcript_callback=events.append,
    )
    public = result.to_dict()

    assert len(stream.sent) == 1
    assert public["status"] == "unknown_command_terminated"
    assert public["decisions"][0]["classification"] == "unknown_command"
    assert public["decisions"][0]["should_respond"] is False
    assert public["decisions"][0]["terminate_session"] is True
    assert public["decisions"][0]["fingerprint"]["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert public["decisions"][0]["fingerprint"]["frame_size"] == len(_server_frame(99, payload))
    assert public["safety"]["application_send_count"] == 1
    assert public["safety"]["fake_result_sent"] is False
    assert payload.decode() not in repr(public)
    assert payload.decode() not in repr(events)


@pytest.mark.parametrize(
    ("command", "payload", "expected_input_size"),
    [
        (16, b"plugin.dll\0MZ-plugin-body", 0),
        (18, b"plugin.dll\0" + (3).to_bytes(4, "little") + b"arg" + b"MZ-plugin-body", 3),
    ],
)
def test_file_and_plugin_transfers_are_refused_without_retention(
    command: int,
    payload: bytes,
    expected_input_size: int,
) -> None:
    stream = LoopbackStream(HANDSHAKE + _server_frame(command, payload))
    result = N520.run_bounded_host_session(
        stream,
        allow_empty_registration=True,
        registration_iv=b"R" * 16,
    ).to_dict()

    assert len(stream.sent) == 1
    assert result["status"] == "file_or_plugin_transfer_refused"
    decision = result["decisions"][0]
    assert decision["transfer_refused"] is True
    assert decision["should_respond"] is False
    transfer = decision["fingerprint"]["transfer"]
    assert transfer["parse_status"] == "recognized"
    assert transfer["input_size"] == expected_input_size
    assert transfer["artifact_retained"] is False
    assert transfer["artifact_executed"] is False
    assert result["safety"]["file_or_plugin_retained"] is False
    assert b"MZ-plugin-body".decode() not in repr(result)


def test_invalid_handshake_sends_no_application_data() -> None:
    corrupted = bytearray(HANDSHAKE)
    corrupted[-1] ^= 1
    stream = LoopbackStream(bytes(corrupted), finish="closed")
    with pytest.raises(N520.InvalidHandshakeError):
        N520.run_bounded_host_session(stream, allow_empty_registration=True)
    assert stream.sent == []


def test_registration_requires_explicit_permission() -> None:
    stream = LoopbackStream(HANDSHAKE, finish="closed")
    with pytest.raises(N520.RegistrationNotAllowedError):
        N520.run_bounded_host_session(stream)
    assert stream.sent == []


def test_empty_response_stops_at_the_bounded_timeout() -> None:
    stream = LoopbackStream(HANDSHAKE)
    result = N520.run_bounded_host_session(
        stream,
        allow_empty_registration=True,
        registration_iv=b"R" * 16,
    ).to_dict()
    assert result["status"] == "no_command_observed"
    assert result["collection"]["timed_out"] is True
    assert result["collection"]["response_size"] == 0
    assert len(stream.sent) == 1


def test_policy_rejects_fractional_integer_limits() -> None:
    with pytest.raises(TypeError):
        N520.HostPolicy(maximum_frames=1.5)


def test_response_limit_is_enforced_after_the_single_registration() -> None:
    stream = LoopbackStream(HANDSHAKE + b"A" * 65, finish="closed")
    with pytest.raises(N520.ResponseLimitExceededError):
        N520.run_bounded_host_session(
            stream,
            policy=N520.HostPolicy(maximum_response_bytes=64, read_chunk_bytes=64),
            allow_empty_registration=True,
            registration_iv=b"R" * 16,
        )
    assert len(stream.sent) == 1


def test_tampered_frame_is_never_classified_as_a_command() -> None:
    packet = bytearray(_server_frame(16, b"plugin.dll\0MZpayload"))
    packet[20] ^= 1
    stream = LoopbackStream(HANDSHAKE + bytes(packet))
    result = N520.run_bounded_host_session(
        stream,
        allow_empty_registration=True,
        registration_iv=b"R" * 16,
    ).to_dict()
    assert result["status"] == "invalid_frame_terminated"
    assert result["decisions"][0]["command"] is None
    assert result["decisions"][0]["classification"] == "unauthenticated_or_invalid_frame"
    assert result["decisions"][0]["transfer_refused"] is False
    assert len(stream.sent) == 1


def test_synthetic_result_is_abstract_and_fixture_only() -> None:
    decision = N520.synthetic_result_decision(16, outcome="success").to_dict()
    assert decision["fixture_only"] is True
    assert decision["send_allowed"] is False
    assert decision["wire_schema_status"] == "unresolved"
    assert decision["wire_bytes"] is None
    assert N520.LIVE_FAKE_RESULT_TRANSMISSION_ALLOWED is False


def test_common_entry_returns_only_sanitized_metadata() -> None:
    payload = b"private-loopback-command"
    stream = LoopbackStream(HANDSHAKE + _server_frame(77, payload), finish="closed")
    result = N520.run_host_session(
        stream,
        session_limits={"max_bytes": 4096, "max_frames": 2, "idle_timeout_seconds": 1.0},
        allow_registration=True,
    )
    assert result["protocol"] == "n520"
    assert result["decisions"][0]["fingerprint"]["payload_size"] == len(payload)
    assert payload.decode() not in repr(result)
    assert len(stream.sent) == 1
