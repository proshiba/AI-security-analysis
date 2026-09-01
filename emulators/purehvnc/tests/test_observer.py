"""PureRAT loopback長時間observerの安全境界test。"""

from __future__ import annotations

import socket
import threading

import pytest

from emulators.purehvnc.observer import (
    ObservationPolicy,
    ObserverError,
    build_empty_registration_frame,
    build_fixture_frame,
    classify_frame,
    connect_loopback,
    observe_connected_stream,
)


def _message(discriminator: int) -> bytes:
    key = (discriminator << 3) | 2
    output = bytearray()
    while key > 0x7F:
        output.append((key & 0x7F) | 0x80)
        key >>= 7
    output.extend((key, 0))
    return build_fixture_frame(bytes(output))


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class FakeStream:
    def __init__(self, chunks: list[bytes | BaseException], clock: FakeClock) -> None:
        self.chunks = list(chunks)
        self.clock = clock
        self.sent: list[bytes] = []
        self.timeout: float | None = None

    def recv(self, maximum_bytes: int) -> bytes:
        self.clock.value += 0.25
        if not self.chunks:
            raise TimeoutError("idle")
        current = self.chunks.pop(0)
        if isinstance(current, BaseException):
            raise current
        if len(current) > maximum_bytes:
            self.chunks.insert(0, current[maximum_bytes:])
            return current[:maximum_bytes]
        return current

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def settimeout(self, timeout_seconds: float) -> None:
        self.timeout = timeout_seconds


def test_observer_waits_across_idle_polls_and_stops_on_command() -> None:
    clock = FakeClock()
    heartbeat = _message(2)
    command = _message(86)
    stream = FakeStream([TimeoutError("idle"), heartbeat, command], clock)
    events: list[dict] = []

    result = observe_connected_stream(
        stream,
        policy=ObservationPolicy(duration_seconds=30, poll_seconds=1),
        event_callback=events.append,
        monotonic=clock,
    ).to_dict()

    assert stream.sent == [build_empty_registration_frame()]
    assert result["status"] == "sensitive_frame_observed"
    assert result["collection"]["frame_count"] == 2
    assert result["collection"]["command_count"] == 1
    assert result["collection"]["idle_polls"] == 1
    assert [item["classification"] for item in result["observations"]] == [
        "heartbeat_observed",
        "command_observed_and_refused",
    ]
    assert result["safety"]["operation_executed"] is False
    assert result["safety"]["command_reply_sent"] is False
    assert all("raw_payload" not in event for event in events)


@pytest.mark.parametrize("discriminator", [5, 38, 86, 99])
def test_sensitive_and_unknown_frames_are_recorded_then_stop(discriminator: int) -> None:
    observation = classify_frame(_message(discriminator), maximum_frame_bytes=65_536)
    assert observation.terminate_session is True
    assert observation.action == "record_and_stop"


def test_kill_switch_stops_without_reading_or_replying() -> None:
    clock = FakeClock()
    stream = FakeStream([_message(2)], clock)
    result = observe_connected_stream(
        stream,
        policy=ObservationPolicy(duration_seconds=30),
        stop_requested=lambda: True,
        monotonic=clock,
    ).to_dict()
    assert result["status"] == "kill_switch_released"
    assert result["collection"]["frame_count"] == 0
    assert stream.chunks
    assert len(stream.sent) == 1


def test_external_target_is_rejected_before_socket_use(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def forbidden(*_args: object, **_kwargs: object) -> socket.socket:
        nonlocal called
        called = True
        raise AssertionError("external target拒否後にsocketを呼んではいけません")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    with pytest.raises(ValueError, match="loopback-only"):
        connect_loopback("192.0.2.1", 56001, timeout=1)
    assert called is False


def test_real_loopback_socket_observes_heartbeat_then_command() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(3)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = int(server.getsockname()[1])
    received: list[bytes] = []
    server_errors: list[BaseException] = []

    def fixture_c2() -> None:
        try:
            client, peer = server.accept()
            with client:
                assert peer[0] == "127.0.0.1"
                client.settimeout(3)
                expected = len(build_empty_registration_frame())
                registration = bytearray()
                while len(registration) < expected:
                    chunk = client.recv(expected - len(registration))
                    if not chunk:
                        break
                    registration.extend(chunk)
                received.append(bytes(registration))
                client.sendall(_message(2))
                client.sendall(_message(86))
        except BaseException as exc:  # pragma: no cover - parent側で再送出する
            server_errors.append(exc)
        finally:
            server.close()

    worker = threading.Thread(target=fixture_c2, daemon=True)
    worker.start()
    with connect_loopback("127.0.0.1", port, timeout=3) as stream:
        result = observe_connected_stream(
            stream,
            policy=ObservationPolicy(duration_seconds=10, poll_seconds=0.2),
        ).to_dict()
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert not server_errors
    assert received == [build_empty_registration_frame()]
    assert result["status"] == "sensitive_frame_observed"
    assert result["collection"]["frame_count"] == 2
    assert result["collection"]["command_count"] == 1
    assert result["safety"]["operation_executed"] is False
    assert result["safety"]["command_reply_sent"] is False


def test_truncated_and_overlong_frames_fail_closed() -> None:
    with pytest.raises(ObserverError):
        classify_frame(b"\x01\x00\x00\x00x", maximum_frame_bytes=65_536)
    clock = FakeClock()
    stream = FakeStream([struct_prefix := (65_536).to_bytes(4, "little")], clock)
    with pytest.raises(ObserverError):
        observe_connected_stream(
            stream,
            policy=ObservationPolicy(
                duration_seconds=30,
                maximum_frame_bytes=65_536,
                maximum_total_bytes=65_536,
            ),
            monotonic=clock,
        )
    assert struct_prefix


def test_policy_remains_bounded() -> None:
    with pytest.raises(ValueError):
        ObservationPolicy(duration_seconds=24 * 60 * 60 + 1)
    with pytest.raises(ValueError):
        ObservationPolicy(maximum_frames=4097)
    with pytest.raises(ValueError):
        ObservationPolicy(maximum_frame_bytes=100, maximum_total_bytes=99)
