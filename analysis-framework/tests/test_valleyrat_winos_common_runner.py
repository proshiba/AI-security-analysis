"""ValleyRAT/Winosの共通runner統合と外部live拒否の回帰テスト。"""

from __future__ import annotations

import json
import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import run_defensive_rat_emulator as runner
from rat_emulator_profiles import resolve_profile
from rat_emulator_transcript import (
    SessionTranscriptWriter,
    build_public_summary,
)

PROFILE_ID = "valleyrat-winos-heartbeat-20260803-ljdnxz"


class FragmentingSocket:
    """127.0.0.1 socketを使いつつ受信chunkを2 byteへ制限する。"""

    def __init__(self, inner: socket.socket) -> None:
        self.inner = inner

    def settimeout(self, value: float) -> None:
        self.inner.settimeout(value)

    def recv(self, maximum: int) -> bytes:
        return self.inner.recv(min(maximum, 2))

    def sendall(self, value: bytes) -> None:
        self.inner.sendall(value)

    def close(self) -> None:
        self.inner.close()


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        chunk = stream.recv(size - len(output))
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def test_loopback_sends_one_c9_reads_one_application_frame_and_never_replies(
    short_tmp: Path,
) -> None:
    profile = resolve_profile(PROFILE_ID)
    adapter = runner._load_adapter("valleyrat_winos_v1")
    response = adapter.build_frame(
        b"\x77S3CR3T",
        adapter.DEFAULT_SYNTHETIC_HEADER,
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    observed: dict[str, bytes] = {}

    def serve() -> None:
        connection, _peer = listener.accept()
        with connection:
            observed["heartbeat"] = _recv_exact(connection, 15)
            connection.sendall(response)
            connection.settimeout(2.0)
            try:
                observed["reply"] = connection.recv(1)
            except TimeoutError:
                observed["reply"] = b"timeout"

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = socket.create_connection(listener.getsockname(), timeout=2.0)
    private_parent = short_tmp / "winos-private"
    private_parent.mkdir()
    kill_path = short_tmp / "winos-kill"
    kill_path.write_text("armed\n", encoding="ascii")
    transcript_path = private_parent / "session"
    transcript = SessionTranscriptWriter(transcript_path, session_id="winos-loopback")
    guarded = runner.GuardedStream(
        FragmentingSocket(client),
        limits=profile["limits"],
        kill_switch=runner.KillSwitch(kill_path),
        transcript=transcript,
    )
    try:
        result = runner._run_adapter(
            profile,
            guarded,
            runner._adapter_event_callback(transcript),
        )
        public_adapter = runner._public_adapter_result(result, profile)
    finally:
        client.close()
        listener.close()
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert observed["heartbeat"] == adapter.build_c9_heartbeat()
    assert observed["reply"] == b""
    assert guarded.outbound_frames == 1
    assert guarded.outbound_bytes == 15
    assert guarded.inbound_frames == 1
    assert 1 < guarded.inbound_read_calls <= 16
    assert guarded.inbound_bytes == len(response) <= 64
    assert public_adapter["registration"]["sent"] is False
    assert public_adapter["registration"]["supported"] is False
    assert public_adapter["registration"]["requested"] is False
    assert public_adapter["registration"]["offline_reference_available"] is True
    assert public_adapter["registration"]["external_send_allowed"] is False
    assert public_adapter["collection"]["frame_count"] == 1
    assert public_adapter["decisions"][0]["should_respond"] is False
    assert public_adapter["decisions"][0]["terminate_session"] is True
    assert public_adapter["safety"]["registration_sent"] is False
    assert public_adapter["safety"]["stage_requested"] is False
    assert "S3CR3T" not in json.dumps(public_adapter, ensure_ascii=False)

    transcript.finalize(status="completed", stop_reason=result["status"])
    summary = build_public_summary(transcript_path)
    event_types = [event["event_type"] for event in summary["events"]]
    assert event_types.count("reviewed_fixed_heartbeat_request_frame") == 1
    assert "reviewed_registration_frame" not in event_types
    heartbeat_event = next(
        event
        for event in summary["events"]
        if event["event_type"] == "reviewed_fixed_heartbeat_request_frame"
    )
    assert heartbeat_event["public_fields"]["synthetic_request_sent"] is True
    raw_frames = [path.read_bytes() for path in (transcript_path / "frames").iterdir()]
    assert response not in raw_frames


def test_preflight_and_external_live_fail_before_lease_dns_maxmind_or_socket(
    short_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        calls.append("called")
        raise AssertionError("offline-only boundaryより後を呼んではいけません")

    monkeypatch.setattr(runner, "resolve_active_live_lease", forbidden)
    monkeypatch.setattr(runner.socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(runner.socket, "create_connection", forbidden)
    preflight = runner.preflight(PROFILE_ID)
    assert preflight["network_used"] is False
    assert preflight["live_enabled"] is False
    assert preflight["live_lease"] is None
    assert preflight["live_scope"] == "offline_or_loopback_only"
    assert calls == []

    output = short_tmp / "must-not-exist"
    with pytest.raises(runner.RatEmulatorRunError, match="offline.*loopback"):
        runner.run_live_session(
            PROFILE_ID,
            allow_network=True,
            allow_live_c2_emulation=True,
            acknowledged_profile=PROFILE_ID,
            kill_switch_path=None,
            private_output_directory=output,
            maxmind_cache_directory=short_tmp / "maxmind",
            resolver=forbidden,
            maxmind_preparer=forbidden,
            stream_opener=forbidden,
            adapter_runner=forbidden,
        )
    assert calls == []
    assert not output.exists()


@pytest.mark.parametrize("prefix", [b"\x10", struct.pack("<I", 16), struct.pack("<I", 16) + b"A"])
def test_guarded_partial_total_length_timeout_is_not_idle(
    short_tmp: Path,
    prefix: bytes,
) -> None:
    """途中header/bodyのtimeout後に残りを別frameへ再解釈しない。"""

    class PartialStream:
        def __init__(self) -> None:
            self.pending = bytearray(prefix)
            self.calls = 0

        def settimeout(self, _seconds: float) -> None:
            pass

        def recv(self, maximum: int) -> bytes:
            self.calls += 1
            if not self.pending:
                raise TimeoutError("fixture timeout")
            result = bytes(self.pending[:maximum])
            del self.pending[:maximum]
            return result

    switch = short_tmp / "armed"
    switch.write_text("armed", encoding="ascii")
    parent = short_tmp / "private-timeout"
    parent.mkdir()
    writer = SessionTranscriptWriter(parent / "session", session_id="partial-timeout")
    stream = PartialStream()
    guard = runner.GuardedStream(
        stream,
        limits=resolve_profile(PROFILE_ID)["limits"],
        kill_switch=runner.KillSwitch(switch),
        transcript=writer,
    )
    guard.settimeout(1.0)
    with pytest.raises(runner.RatEmulatorRunError, match="partial_frame_timeout"):
        guard.recv_total_length_application_frame(64)
    assert guard.inbound_frames == 0
    assert guard.inbound_bytes == len(prefix)
    assert guard.inbound_read_calls == stream.calls


def test_guarded_empty_total_length_timeout_remains_idle(short_tmp: Path) -> None:
    class IdleStream:
        def settimeout(self, _seconds: float) -> None:
            pass

        def recv(self, _maximum: int) -> bytes:
            raise TimeoutError("fixture idle")

    switch = short_tmp / "armed"
    switch.write_text("armed", encoding="ascii")
    parent = short_tmp / "private-idle"
    parent.mkdir()
    writer = SessionTranscriptWriter(parent / "session", session_id="idle-timeout")
    guard = runner.GuardedStream(
        IdleStream(),
        limits=resolve_profile(PROFILE_ID)["limits"],
        kill_switch=runner.KillSwitch(switch),
        transcript=writer,
    )
    guard.settimeout(1.0)
    with pytest.raises(TimeoutError):
        guard.recv_total_length_application_frame(64)
    assert guard.inbound_read_calls == 1
    assert guard.inbound_bytes == 0
    assert guard.inbound_frames == 0


def test_passive_timing_reaches_public_transcript_without_raw_frame(short_tmp: Path) -> None:
    adapter = runner._load_adapter("valleyrat_winos_external_v1")
    clock = [10.0]
    response = adapter.build_frame(b"\xc9", adapter.DEFAULT_SYNTHETIC_HEADER)

    class TimedStream:
        def __init__(self) -> None:
            self.pending = bytearray(response)
            self.sent: list[bytes] = []

        def settimeout(self, _seconds: float) -> None:
            pass

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

        def recv(self, maximum: int) -> bytes:
            clock[0] += 0.125
            value = bytes(self.pending[:maximum])
            del self.pending[:maximum]
            return value

    parent = short_tmp / "private-timing"
    parent.mkdir()
    target = parent / "session"
    writer = SessionTranscriptWriter(target, session_id="winos-timing")
    callback = runner._adapter_event_callback(
        writer, adapter_id="valleyrat_winos_external_v1", maximum_elapsed_ms=1000,
    )
    stream = TimedStream()
    result = adapter.run_passive_observation_session(
        stream, policy=adapter.PassiveObservationPolicy(duration_seconds=1.0),
        allow_c9_heartbeat=True, transcript_callback=callback,
        monotonic=lambda: clock[0],
    )
    writer.finalize(status="completed", stop_reason=result.status)
    public = build_public_summary(target)
    assert [event["public_fields"]["elapsed_ms"] for event in public["events"]] == [0, 250, 375]
    assert all(event["public_fields"]["timing_basis"] == "session_monotonic" for event in public["events"])
    assert len(stream.sent) == 1
    assert list((target / "frames").iterdir()) == []
    assert "payload_hex" not in json.dumps(public)


@pytest.mark.parametrize("fields", [
    {"elapsed_ms": True, "timing_basis": "session_monotonic"},
    {"elapsed_ms": 1.0, "timing_basis": "session_monotonic"},
    {"elapsed_ms": float("nan"), "timing_basis": "session_monotonic"},
    {"elapsed_ms": -1, "timing_basis": "session_monotonic"},
    {"elapsed_ms": 1001, "timing_basis": "session_monotonic"},
    {"elapsed_ms": "1", "timing_basis": "session_monotonic"},
    {"elapsed_ms": 1, "timing_basis": "caller_wall_clock"},
    {"elapsed_ms": 1, "timing_basis": True},
    {"elapsed_ms": 1},
    {"timing_basis": "session_monotonic"},
])
def test_winos_callback_rejects_invalid_timing_before_append(short_tmp: Path, fields: dict) -> None:
    parent = short_tmp / "private-bad-timing"
    parent.mkdir()
    target = parent / "session"
    writer = SessionTranscriptWriter(target, session_id="bad-timing")
    callback = runner._adapter_event_callback(
        writer, adapter_id="valleyrat_winos_external_v1", maximum_elapsed_ms=1000,
    )
    with pytest.raises(runner.RatEmulatorRunError, match="経過時刻"):
        callback({"event": "winos_frame_recorded_and_discarded", **fields})
    assert list((target / "events").iterdir()) == []
    assert list((target / "frames").iterdir()) == []


@pytest.mark.parametrize("adapter_id", [None, "valleyrat_n520_v1", "purerat_direct_tls_v1"])
def test_other_adapters_drop_winos_timing_fields(short_tmp: Path, adapter_id: str | None) -> None:
    parent = short_tmp / "private-other"
    parent.mkdir()
    target = parent / "session"
    writer = SessionTranscriptWriter(target, session_id="other-adapter")
    callback = runner._adapter_event_callback(writer, adapter_id=adapter_id)
    callback({"event": "other_event", "elapsed_ms": 123, "timing_basis": "secret-not-an-allowed-basis"})
    writer.finalize(status="completed", stop_reason="fixture")
    public = build_public_summary(target)
    assert "elapsed_ms" not in public["events"][0]["public_fields"]
    assert "timing_basis" not in public["events"][0]["public_fields"]
    assert "secret-not-an-allowed-basis" not in json.dumps(public)


@pytest.mark.parametrize("bad", [True, 0, -1, 1.0, float("nan"), 28_800_001])
def test_callback_duration_limit_is_a_bounded_integer(bad) -> None:
    with pytest.raises(runner.RatEmulatorRunError, match="時刻の上限"):
        runner._adapter_event_callback(None, maximum_elapsed_ms=bad)


def test_winos_callback_rejects_backwards_timing_without_partial_event(short_tmp: Path) -> None:
    parent = short_tmp / "private-reversed"
    parent.mkdir()
    target = parent / "session"
    writer = SessionTranscriptWriter(target, session_id="reversed-time")
    callback = runner._adapter_event_callback(
        writer, adapter_id="valleyrat_winos_external_v1", maximum_elapsed_ms=1000,
    )
    callback({"event": "winos_frame_recorded_and_discarded", "elapsed_ms": 500, "timing_basis": "session_monotonic"})
    with pytest.raises(runner.RatEmulatorRunError, match="経過時刻"):
        callback({"event": "winos_frame_recorded_and_discarded", "elapsed_ms": 499, "timing_basis": "session_monotonic"})
    callback({"event": "winos_observation_stopped", "elapsed_ms": 500, "timing_basis": "session_monotonic"})
    writer.finalize(status="completed", stop_reason="fixture")
    public = build_public_summary(target)
    assert [event["public_fields"]["elapsed_ms"] for event in public["events"]] == [500, 500]
