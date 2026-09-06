"""ValleyRAT/Winos host adapterの安全境界をoffline fixtureで検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE = FRAMEWORK / "malware" / "valleyrat" / "winos_host_emulator.py"


def _load():
    spec = importlib.util.spec_from_file_location("valleyrat_winos_host_emulator", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


WINOS = _load()
HEADER = b"0123456789"


class LoopbackStream:
    """有界fragmentを返し、client送信を記録するoffline fixture。"""

    def __init__(
        self,
        incoming: bytes = b"",
        *,
        fragment_size: int = 64,
        finish: str = "timeout",
    ) -> None:
        self.incoming = bytearray(incoming)
        self.fragment_size = fragment_size
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
            length = min(maximum_bytes, self.fragment_size, len(self.incoming))
            chunk = bytes(self.incoming[:length])
            del self.incoming[:length]
            return chunk
        if self.finish == "closed":
            return b""
        raise TimeoutError("offline fixture idle")


def _frame(command: int, payload: bytes = b"") -> bytes:
    return WINOS.build_frame(bytes([command]) + payload, HEADER)


def test_builds_fixed_synthetic_c9_heartbeat() -> None:
    heartbeat = WINOS.build_c9_heartbeat(header=HEADER)
    parsed = WINOS.parse_frame(heartbeat)
    assert parsed.complete is True
    assert parsed.command == 0xC9
    assert parsed.declared_length == 15
    assert bytes.fromhex(parsed.header_hex) == HEADER
    assert bytes.fromhex(parsed.payload_hex) == b"\xC9"


def test_observes_one_fragmented_heartbeat_frame_without_reply() -> None:
    response = _frame(0xC9, b"\x00")
    stream = LoopbackStream(response, fragment_size=2)
    events: list[dict] = []
    result = WINOS.run_bounded_host_session(
        stream,
        policy=WINOS.HostPolicy(read_chunk_bytes=3),
        allow_c9_heartbeat=True,
        heartbeat_header=HEADER,
        transcript_callback=events.append,
    ).to_dict()

    assert len(stream.sent) == 1
    assert WINOS.parse_frame(stream.sent[0]).command == 0xC9
    assert result["status"] == "heartbeat_response_observed"
    assert result["registration"]["sent"] is False
    assert result["decisions"][0]["role"] == "heartbeat_or_status"
    fingerprint = result["decisions"][0]["fingerprint"]
    assert fingerprint["frame_size"] == len(response)
    assert fingerprint["frame_sha256"] == hashlib.sha256(response).hexdigest()
    assert fingerprint["integrity_authenticated"] is False
    assert result["safety"]["victim_metadata_sent"] is False
    assert result["safety"]["stage_requested"] is False
    assert result["safety"]["response_integrity_authenticated"] is False
    assert result["safety"]["application_send_count"] == 1
    assert "payload_hex" not in repr(result)
    assert "payload_hex" not in repr(events)


def test_c9_flag_one_is_recorded_as_registration_request_but_not_answered() -> None:
    stream = LoopbackStream(_frame(0xC9, b"\x01"), finish="closed")
    events: list[dict] = []
    result = WINOS.run_bounded_host_session(
        stream,
        allow_c9_heartbeat=True,
        heartbeat_header=HEADER,
        transcript_callback=events.append,
    ).to_dict()

    assert len(stream.sent) == 1
    assert result["status"] == "registration_requested_but_not_sent"
    assert result["registration"] == {
        "sent": False,
        "supported": False,
        "requested": True,
        "offline_reference_available": True,
        "reference_layout_id": "winos-public-logininfo-wide-reference-v1",
        "sample_bound": False,
        "external_send_allowed": False,
        "login_token_status": "unresolved_requires_exact_sample_review",
    }
    assert result["decisions"][0]["classification"] == "registration_challenge_observed"
    assert result["decisions"][0]["action"] == "registration_not_sent_and_terminate"
    assert result["decisions"][0]["registration_requested"] is True
    assert result["safety"]["registration_sent"] is False
    assert all(event.get("registration_sent") is not True for event in events)


@pytest.mark.parametrize(
    ("command", "role"),
    [
        (0xCA, "registration_completed"),
        (0xCB, "registration_acknowledgement"),
        (0x04, "stage_channel_control"),
        (0x05, "stage_channel_metadata"),
        (0x06, "client_registration"),
    ],
)
def test_known_roles_are_classified_but_never_answered(
    command: int,
    role: str,
) -> None:
    stream = LoopbackStream(_frame(command), finish="closed")
    result = WINOS.run_bounded_host_session(
        stream,
        allow_c9_heartbeat=True,
        heartbeat_header=HEADER,
    ).to_dict()
    assert len(stream.sent) == 1
    assert result["status"] == "known_command_observed_and_terminated"
    assert result["decisions"][0]["role"] == role
    assert result["decisions"][0]["should_respond"] is False
    assert result["decisions"][0]["terminate_session"] is True
    assert result["safety"]["registration_sent"] is False
    assert result["safety"]["stage_requested"] is False


def test_unknown_command_is_hashed_rejected_and_not_answered() -> None:
    secret = b"private-operation-arguments"
    response = _frame(0x99, secret)
    stream = LoopbackStream(response)
    events: list[dict] = []
    result = WINOS.run_bounded_host_session(
        stream,
        allow_c9_heartbeat=True,
        heartbeat_header=HEADER,
        transcript_callback=events.append,
    ).to_dict()

    assert len(stream.sent) == 1
    assert result["status"] == "unknown_command_rejected"
    decision = result["decisions"][0]
    assert decision["command"] == 0x99
    assert decision["role"] == "unknown_or_operation_command"
    assert decision["classification"] == "unknown_command_rejected"
    assert decision["should_respond"] is False
    assert decision["fingerprint"]["frame_sha256"] == hashlib.sha256(response).hexdigest()
    assert secret.decode() not in repr(result)
    assert secret.decode() not in repr(events)


def test_permission_gate_sends_nothing() -> None:
    stream = LoopbackStream(_frame(0xC9))
    with pytest.raises(WINOS.HeartbeatNotAllowedError):
        WINOS.run_bounded_host_session(stream)
    assert stream.sent == []


@pytest.mark.parametrize(
    "incoming",
    [
        struct.pack("<I", 13),
        b"\x0f\x00",
        struct.pack("<I", 20) + b"A" * 4,
    ],
)
def test_malformed_or_truncated_frame_is_rejected(incoming: bytes) -> None:
    stream = LoopbackStream(incoming, finish="closed")
    with pytest.raises(WINOS.MalformedFrameError):
        WINOS.run_bounded_host_session(
            stream,
            allow_c9_heartbeat=True,
            heartbeat_header=HEADER,
        )
    assert len(stream.sent) == 1


def test_declared_length_bomb_is_rejected_before_body_read() -> None:
    stream = LoopbackStream(struct.pack("<I", 65) + b"B" * 61)
    with pytest.raises(WINOS.ResponseLimitExceededError, match="declared length"):
        WINOS.run_bounded_host_session(
            stream,
            allow_c9_heartbeat=True,
            heartbeat_header=HEADER,
        )
    assert len(stream.sent) == 1
    assert len(stream.incoming) == 61
    with pytest.raises(WINOS.ResponseLimitExceededError, match="絶対受信上限"):
        WINOS.classify_received_frame(b"A" * 65)


def test_only_first_of_two_frames_is_consumed() -> None:
    first = _frame(0xC9)
    second = _frame(0x04, b"stage")
    stream = LoopbackStream(first + second)
    result = WINOS.run_bounded_host_session(
        stream,
        allow_c9_heartbeat=True,
        heartbeat_header=HEADER,
    ).to_dict()
    assert result["collection"]["frame_count"] == 1
    assert result["decisions"][0]["command"] == 0xC9
    assert bytes(stream.incoming) == second
    assert len(stream.sent) == 1


def test_passive_observer_keeps_connection_and_discards_multiple_frames() -> None:
    first = _frame(0xC9)
    second = _frame(0xCA)
    stream = LoopbackStream(first + second, finish="closed")
    result = WINOS.run_passive_observation_session(
        stream,
        policy=WINOS.PassiveObservationPolicy(
            duration_seconds=30.0,
            maximum_frames=4,
        ),
        allow_c9_heartbeat=True,
        heartbeat_header=HEADER,
    ).to_dict()

    assert result["status"] == "peer_closed"
    assert len(stream.sent) == 1
    assert result["collection"]["frame_count"] == 2
    assert [item["command"] for item in result["decisions"]] == [0xC9, 0xCA]
    assert all(item["action"] == "record_and_discard" for item in result["decisions"])
    assert all(item["should_respond"] is False for item in result["decisions"])
    assert all(item["terminate_session"] is False for item in result["decisions"])
    assert result["safety"]["received_frame_executed"] is False
    assert result["safety"]["received_frame_reply_sent"] is False
    assert result["safety"]["received_frame_discarded_count"] == 2
    assert "operator-arguments" not in repr(result)


def test_passive_unknown_command_stops_without_reply_or_reading_next_frame() -> None:
    unknown = _frame(0x99, b"operator-arguments")
    later = _frame(0xC9)
    stream = LoopbackStream(unknown + later, finish="closed")
    result = WINOS.run_passive_observation_session(
        stream,
        policy=WINOS.PassiveObservationPolicy(duration_seconds=30.0),
        allow_c9_heartbeat=True,
    ).to_dict()
    assert result["status"] == "unknown_command_rejected"
    assert result["collection"]["frame_count"] == 1
    assert result["decisions"][0]["terminate_session"] is True
    assert result["decisions"][0]["should_respond"] is False
    assert result["decisions"][0]["action"] == "no_response_and_terminate"
    assert bytes(stream.incoming) == later
    assert len(stream.sent) == 1
    assert "operator-arguments" not in repr(result)


def test_passive_standalone_monotonic_deadline_bounds_each_fragment() -> None:
    clock = [0.0]

    class SlowStream(LoopbackStream):
        def recv(self, maximum_bytes: int) -> bytes:
            assert self.timeout_seconds is not None
            clock[0] += min(self.timeout_seconds, 0.4)
            if clock[0] >= 1.0:
                raise TimeoutError("fixture deadline")
            return super().recv(maximum_bytes)

    stream = SlowStream(_frame(0xC9), fragment_size=1)
    with pytest.raises(WINOS.MalformedFrameError, match="truncate"):
        WINOS.run_passive_observation_session(
            stream,
            policy=WINOS.PassiveObservationPolicy(duration_seconds=1.0),
            allow_c9_heartbeat=True,
            monotonic=lambda: clock[0],
        )
    assert clock[0] == pytest.approx(1.0)
    assert stream.recv_calls == 2
    assert len(stream.sent) == 1


def test_passive_immediate_timeouts_do_not_claim_elapsed_observation_window() -> None:
    stream = LoopbackStream()
    result = WINOS.run_passive_observation_session(
        stream,
        policy=WINOS.PassiveObservationPolicy(duration_seconds=1.0),
        allow_c9_heartbeat=True,
        monotonic=lambda: 0.0,
    ).to_dict()
    assert result["status"] == "idle_read_limit_reached"
    assert result["collection"]["frame_count"] == 0
    assert stream.recv_calls == 2
    assert len(stream.sent) == 1


def test_passive_standalone_idle_completion_requires_elapsed_deadline() -> None:
    clock = [0.0]

    class IdleStream(LoopbackStream):
        def recv(self, maximum_bytes: int) -> bytes:
            assert self.timeout_seconds is not None
            clock[0] += self.timeout_seconds
            return super().recv(maximum_bytes)

    stream = IdleStream()
    result = WINOS.run_passive_observation_session(
        stream,
        policy=WINOS.PassiveObservationPolicy(duration_seconds=1.0),
        allow_c9_heartbeat=True,
        monotonic=lambda: clock[0],
    ).to_dict()
    assert result["status"] == "observation_window_complete"
    assert clock[0] == pytest.approx(1.0)
    assert stream.recv_calls == 1


def test_passive_events_have_bounded_monotonic_millisecond_timestamps() -> None:
    clock = [100.0]
    events: list[dict] = []

    class TimedStream(LoopbackStream):
        def recv(self, maximum_bytes: int) -> bytes:
            clock[0] += 0.125
            return super().recv(maximum_bytes)

    stream = TimedStream(_frame(0xC9), finish="closed")
    WINOS.run_passive_observation_session(
        stream,
        policy=WINOS.PassiveObservationPolicy(duration_seconds=1.0),
        allow_c9_heartbeat=True,
        transcript_callback=events.append,
        monotonic=lambda: clock[0],
    )
    assert [event["event"] for event in events] == [
        "winos_c9_heartbeat_sent", "winos_frame_recorded_and_discarded",
        "winos_observation_stopped",
    ]
    assert [event["elapsed_ms"] for event in events] == [0, 250, 375]
    assert all(event["timing_basis"] == "session_monotonic" for event in events)
    assert all(type(event["elapsed_ms"]) is int for event in events)
    assert all(0 <= event["elapsed_ms"] <= 1000 for event in events)
    assert len(stream.sent) == 1
    assert "payload_hex" not in repr(events)


def test_passive_stopped_event_time_is_clamped_to_duration() -> None:
    clock = [0.0]
    events: list[dict] = []

    class DelayedIdleStream(LoopbackStream):
        def recv(self, maximum_bytes: int) -> bytes:
            clock[0] = 1.25
            return super().recv(maximum_bytes)

    WINOS.run_passive_observation_session(
        DelayedIdleStream(),
        policy=WINOS.PassiveObservationPolicy(duration_seconds=1.0),
        allow_c9_heartbeat=True,
        transcript_callback=events.append,
        monotonic=lambda: clock[0],
    )
    assert events[-1]["elapsed_ms"] == 1000
    assert events[-1]["timing_basis"] == "session_monotonic"


@pytest.mark.parametrize("bad", [True, float("nan"), float("inf"), "0"])
def test_passive_invalid_initial_clock_prevents_send(bad) -> None:
    stream = LoopbackStream()
    with pytest.raises(WINOS.WinosHostEmulatorError, match="単調時計"):
        WINOS.run_passive_observation_session(
            stream,
            policy=WINOS.PassiveObservationPolicy(duration_seconds=1.0),
            allow_c9_heartbeat=True,
            monotonic=lambda: bad,
        )
    assert stream.sent == []


def test_idle_timeout_is_not_a_stopped_c2_conclusion() -> None:
    stream = LoopbackStream()
    result = WINOS.run_bounded_host_session(
        stream,
        allow_c9_heartbeat=True,
        heartbeat_header=HEADER,
    ).to_dict()
    assert result["status"] == "no_frame_observed"
    assert result["collection"]["timed_out"] is True
    assert result["collection"]["frame_count"] == 0
    assert len(stream.sent) == 1


def test_read_call_limit_and_invalid_policy_fail_closed() -> None:
    stream = LoopbackStream(_frame(0xC9), fragment_size=1)
    with pytest.raises(WINOS.ResponseLimitExceededError, match="read call"):
        WINOS.run_bounded_host_session(
            stream,
            policy=WINOS.HostPolicy(maximum_read_calls=2),
            allow_c9_heartbeat=True,
            heartbeat_header=HEADER,
        )
    assert len(stream.sent) == 1
    with pytest.raises(ValueError, match="maximum_frames"):
        WINOS.HostPolicy(maximum_frames=2)
    with pytest.raises(ValueError, match="14から64"):
        WINOS.HostPolicy(maximum_response_bytes=65)
    with pytest.raises(ValueError, match="整数"):
        WINOS.HostPolicy(maximum_read_calls=1.5)


def test_common_entry_returns_sanitized_single_send_result() -> None:
    secret = b"not-public"
    response = _frame(0x77, secret)
    stream = LoopbackStream(response)
    result = WINOS.run_host_session(
        stream,
        session_limits={
            "max_bytes": 64,
            "max_frames": 1,
            "idle_timeout_seconds": 1.0,
            "max_read_calls": 8,
            "read_chunk_bytes": 64,
        },
        allow_registration=True,
    )
    assert result["protocol"] == "winos_custom_tcp"
    assert result["required_endpoint_role"] == "control"
    assert result["registration"]["sent"] is False
    assert result["safety"]["stage_requested"] is False
    assert result["safety"]["unknown_command_reply_sent"] is False
    assert len(stream.sent) == 1
    assert secret.decode() not in repr(result)
