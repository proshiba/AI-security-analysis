"""ValleyRAT/Winosの共通runner統合と外部live拒否の回帰テスト。"""

from __future__ import annotations

import json
import socket
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
