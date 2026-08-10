"""防御用RAT emulator runnerの既定拒否と有界実行検証。"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import run_defensive_rat_emulator as runner  # noqa: E402
import tls_messagepack_rat_host_emulator as tls_host  # noqa: E402
from rat_emulator_profiles import resolve_profile  # noqa: E402
from rat_emulator_transcript import SessionTranscriptWriter  # noqa: E402

PROFILE_ID = "valleyrat-n520-host-d11e793-9999"
ASYNC_PROFILE_ID = "asyncrat-058-20f21565-191-96-78-221-7788"
VENOM_PROFILE_ID = "venomrat-603-6a24ba25-localto-6377"
ACTIVE_LEASE_NOW = datetime(2026, 8, 9, 9, 30, tzinfo=UTC)


class FakeStream:
    def __init__(self, chunks: list[bytes] | None = None) -> None:
        self.chunks = list(chunks or [])
        self.sent: list[bytes] = []
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def recv(self, maximum: int) -> bytes:
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        assert len(value) <= maximum
        return value

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def close(self) -> None:
        self.closed = True


def _kill_switch(path: Path) -> Path:
    path.write_text("armed\n", encoding="ascii")
    return path


def _maxmind(_cache: Path, pinned_ip: str) -> dict[str, Any]:
    return {
        "freshness_policy": {
            "checked_before_live_check": True,
            "maximum_build_age_hours": 24.0,
            "refresh_performed": False,
        },
        "city_build_time_utc": "2026-08-09T00:00:00+00:00",
        "asn_build_time_utc": "2026-08-09T00:00:00+00:00",
        "ip_record": {"ip": pinned_ip, "geo": None, "as": None},
    }


def test_preflight_never_uses_dns_or_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network must not be used")

    monkeypatch.setattr(runner.socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(runner.socket, "create_connection", forbidden)
    result = runner.preflight(PROFILE_ID, lease_now_utc=ACTIVE_LEASE_NOW)
    assert result["network_used"] is False
    assert result["adapter_contract_version"] == 1


@pytest.mark.parametrize("profile_id", [ASYNC_PROFILE_ID, VENOM_PROFILE_ID])
def test_tls_preflight_publishes_non_exclusion_certificate_policy(profile_id: str) -> None:
    result = runner.preflight(profile_id, lease_now_utc=ACTIVE_LEASE_NOW)
    assert result["network_used"] is False
    assert result["adapter_id"] == "tls_messagepack_rat_host"
    assert result["certificate_mismatch_is_negative_evidence"] is False


@pytest.mark.parametrize(
    "override",
    [
        {"allow_network": False},
        {"allow_live_c2_emulation": False},
        {"acknowledged_profile": "wrong-profile"},
        {"kill_switch_path": None},
    ],
)
def test_missing_live_gate_fails_before_any_network_or_maxmind(
    short_tmp: Path,
    override: dict[str, object],
) -> None:
    private_parent = short_tmp / "private"
    private_parent.mkdir()
    cache = short_tmp / "cache"
    switch = _kill_switch(short_tmp / "kill-switch")
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        calls.append("called")
        raise AssertionError("gate failure must occur first")

    options: dict[str, object] = {
        "allow_network": True,
        "allow_live_c2_emulation": True,
        "acknowledged_profile": PROFILE_ID,
        "kill_switch_path": switch,
    }
    options.update(override)
    with pytest.raises(runner.RatEmulatorRunError):
        runner.run_live_session(
            PROFILE_ID,
            **options,
            lease_now_utc=ACTIVE_LEASE_NOW,
            private_output_directory=private_parent / "session",
            maxmind_cache_directory=cache,
            resolver=forbidden,
            maxmind_preparer=forbidden,
            stream_opener=forbidden,
            adapter_runner=forbidden,
        )
    assert calls == []
    assert not (private_parent / "session").exists()


def test_single_bounded_session_separates_post_registration_raw(short_tmp: Path) -> None:
    private_parent = short_tmp / "private"
    private_parent.mkdir()
    switch = _kill_switch(short_tmp / "kill-switch")
    stream = FakeStream([b"HS", b"SECRET-COMMAND"])
    profile = resolve_profile(PROFILE_ID)
    opens: list[str] = []

    def opener(_profile: dict, pinned_ip: str) -> tuple[FakeStream, str]:
        opens.append(pinned_ip)
        return stream, profile["expected_certificate_sha256"]

    def adapter(
        _profile: dict,
        guarded: runner.GuardedStream,
        callback: Any,
    ) -> dict[str, Any]:
        guarded.settimeout(1.0)
        assert guarded.recv(2) == b"HS"
        guarded.sendall(b"REG")
        assert guarded.recv(64) == b"SECRET-COMMAND"
        callback(
            {
                "event": "n520_command_decision",
                "command": 99,
                "classification": "unknown_command",
                "action": "no_response_and_terminate",
                "fingerprint": {"operator_value": "SECRET-COMMAND"},
            }
        )
        return {
            "family": "valleyrat",
            "protocol": "n520",
            "status": "unknown_command_terminated",
            "registration": {
                "sent": True,
                "command": 1,
                "sequence": 1,
                "payload_size": 0,
                "real_identity_sent": False,
                "packet_size": 3,
                "packet_sha256": hashlib.sha256(b"REG").hexdigest(),
            },
            "collection": {"response_size": 14, "frame_count": 1},
            "decisions": [
                {
                    "command": 99,
                    "classification": "unknown_command",
                    "direction": "server_to_client",
                    "action": "no_response_and_terminate",
                    "reason": "fixture",
                    "should_respond": False,
                    "terminate_session": True,
                    "transfer_refused": False,
                    "fingerprint": {
                        "operator_value": "SECRET-COMMAND",
                        "frame_sha256": "f" * 64,
                        "frame_size": 14,
                    },
                }
            ],
            "safety": {
                "sample_executed": False,
                "host_operation_executed": False,
                "fake_result_sent": False,
                "application_send_count": 1,
            },
        }

    output = private_parent / "session"
    public = runner.run_live_session(
        PROFILE_ID,
        allow_network=True,
        allow_live_c2_emulation=True,
        acknowledged_profile=PROFILE_ID,
        kill_switch_path=switch,
        lease_now_utc=ACTIVE_LEASE_NOW,
        private_output_directory=output,
        maxmind_cache_directory=short_tmp / "cache",
        maxmind_preparer=_maxmind,
        stream_opener=opener,
        adapter_runner=adapter,
    )
    assert opens == ["118.107.21.88"]
    assert stream.sent == [b"REG"]
    assert stream.closed is True
    assert public["adapter_result"]["status"] == "unknown_command_terminated"
    assert public["adapter_result"]["decisions"][0]["frame_sha256"] == "f" * 64
    assert public["adapter_result"]["decisions"][0]["frame_size"] == 14
    encoded = json.dumps(public, ensure_ascii=False)
    assert "SECRET-COMMAND" not in encoded
    raw_values = [item.read_bytes() for item in (output / "frames").iterdir()]
    assert b"HS" in raw_values
    assert b"REG" in raw_values
    assert b"SECRET-COMMAND" not in raw_values


@pytest.mark.parametrize(
    ("profile_id", "packet_key", "heartbeat"),
    [
        (ASYNC_PROFILE_ID, "Packet", "pong"),
        (VENOM_PROFILE_ID, "Pac_ket", "Po_ng"),
    ],
)
def test_tls_messagepack_runner_sends_fixed_ping_then_reads_fragmented_response(
    short_tmp: Path,
    profile_id: str,
    packet_key: str,
    heartbeat: str,
) -> None:
    private_parent = short_tmp / f"private-{heartbeat}"
    private_parent.mkdir()
    switch = _kill_switch(short_tmp / f"kill-{heartbeat}")
    incoming = tls_host.encode_frame({packet_key: heartbeat, "Message": 17})
    stream = FakeStream([bytes([value]) for value in incoming])
    profile = resolve_profile(profile_id)

    def opener(_profile: dict, pinned_ip: str) -> tuple[FakeStream, str]:
        assert pinned_ip == profile["pinned_ips"][0]
        return stream, profile["expected_certificate_sha256"]

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        return [
            (
                runner.socket.AF_INET,
                runner.socket.SOCK_STREAM,
                6,
                "",
                (profile["pinned_ips"][0], profile["port"]),
            )
        ]

    output = private_parent / "session"
    public = runner.run_live_session(
        profile_id,
        allow_network=True,
        allow_live_c2_emulation=True,
        acknowledged_profile=profile_id,
        kill_switch_path=switch,
        lease_now_utc=ACTIVE_LEASE_NOW,
        private_output_directory=output,
        maxmind_cache_directory=short_tmp / f"cache-{heartbeat}",
        resolver=resolver,
        maxmind_preparer=_maxmind,
        stream_opener=opener,
    )

    adapter = public["adapter_result"]
    assert adapter["status"] == "heartbeat_response_observed"
    assert adapter["command"]["opcode"] == heartbeat
    assert adapter["command"]["packet_kind"] == "heartbeat"
    assert adapter["command"]["frame_size"] == len(incoming)
    assert adapter["command"]["frame_sha256"] == hashlib.sha256(incoming).hexdigest()
    assert adapter["heartbeat_request"]["sent"] is True
    assert adapter["heartbeat_request"]["synthetic"] is True
    assert adapter["heartbeat_request"]["opcode"] == "Ping"
    assert adapter["certificate_mismatch_is_negative_evidence"] is False
    assert len(stream.sent) == 2
    assert tls_host._decode_frame(
        stream.sent[1], tls_host.SessionLimits()
    ).values == {packet_key: "Ping", "Message": ""}
    assert stream.closed is True
    assert adapter["collection"]["frame_count"] == 1
    assert adapter["collection"]["command_count"] == 1

    heartbeat_transport = [
        event
        for event in public["events"]
        if event["event_type"] == "reviewed_fixed_heartbeat_request_frame"
    ]
    assert len(heartbeat_transport) == 1
    assert heartbeat_transport[0]["public_fields"]["synthetic_request_sent"] is True
    callback_events = [
        event for event in public["events"] if event["event_type"] == "heartbeat_request_sent"
    ]
    assert callback_events[0]["public_fields"]["opcode"] == "Ping"
    assert callback_events[0]["public_fields"]["packet_kind"] == "heartbeat_request"
    assert callback_events[0]["public_fields"]["synthetic"] is True
    raw_values = [item.read_bytes() for item in (output / "frames").iterdir()]
    assert incoming not in raw_values


def test_certificate_mismatch_is_recorded_before_registration_and_fails_closed(
    short_tmp: Path,
) -> None:
    profile = resolve_profile(ASYNC_PROFILE_ID)
    private_parent = short_tmp / "private-mismatch"
    private_parent.mkdir()
    switch = _kill_switch(short_tmp / "kill-mismatch")
    stream = FakeStream()
    public_output = short_tmp / "mismatch-public.json"
    observed = "0" * 64

    def opener(_profile: dict, _pinned_ip: str) -> tuple[FakeStream, str]:
        return stream, observed

    with pytest.raises(runner.TlsCertificatePinMismatch):
        runner.run_live_session(
            ASYNC_PROFILE_ID,
            allow_network=True,
            allow_live_c2_emulation=True,
            acknowledged_profile=ASYNC_PROFILE_ID,
            kill_switch_path=switch,
            lease_now_utc=ACTIVE_LEASE_NOW,
            private_output_directory=private_parent / "session",
            maxmind_cache_directory=short_tmp / "cache-mismatch",
            public_output=public_output,
            maxmind_preparer=_maxmind,
            stream_opener=opener,
        )
    public = json.loads(public_output.read_text(encoding="utf-8"))
    events = [
        event for event in public["events"] if event["event_type"] == "tls_certificate_mismatch"
    ]
    assert len(events) == 1
    fields = events[0]["public_fields"]
    assert fields["expected_certificate_sha256"] == profile["expected_certificate_sha256"]
    assert fields["observed_certificate_sha256"] == observed
    assert fields["application_frame_sent"] is False
    assert fields["certificate_mismatch_is_negative_evidence"] is False
    assert fields["c2_exclusion_supported"] is False
    assert stream.sent == []
    assert stream.closed is True


def test_private_location_rejected_before_maxmind(short_tmp: Path) -> None:
    switch = _kill_switch(short_tmp / "kill-switch")
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        calls.append("called")
        raise AssertionError("private path rejection must occur first")

    with pytest.raises(runner.RatEmulatorRunError, match="repository"):
        runner.run_live_session(
            PROFILE_ID,
            allow_network=True,
            allow_live_c2_emulation=True,
            acknowledged_profile=PROFILE_ID,
            kill_switch_path=switch,
            lease_now_utc=ACTIVE_LEASE_NOW,
            private_output_directory=COMMON / "unsafe-private-session",
            maxmind_cache_directory=short_tmp / "cache",
            maxmind_preparer=forbidden,
            stream_opener=forbidden,
            adapter_runner=forbidden,
        )
    assert calls == []


def test_kill_switch_removal_and_second_send_fail_closed(short_tmp: Path) -> None:
    switch_path = _kill_switch(short_tmp / "kill-switch")
    switch = runner.KillSwitch(switch_path)
    switch_path.unlink()
    with pytest.raises(runner.RatEmulatorRunError, match="解除"):
        switch.require_armed()

    active_path = _kill_switch(short_tmp / "active-switch")
    parent = short_tmp / "private"
    parent.mkdir()
    writer = SessionTranscriptWriter(parent / "session", session_id="fixture")
    stream = FakeStream()
    guarded = runner.GuardedStream(
        stream,
        limits=resolve_profile(PROFILE_ID)["limits"],
        kill_switch=runner.KillSwitch(active_path),
        transcript=writer,
    )
    guarded.sendall(b"one")
    with pytest.raises(runner.RatEmulatorRunError, match="outbound frame"):
        guarded.sendall(b"two")
    assert stream.sent == [b"one"]


def test_dns_must_contain_exact_pin_and_replay_is_offline(short_tmp: Path) -> None:
    profile = {
        "host": "example.test",
        "port": 443,
        "pinned_ips": ["8.8.8.8"],
    }

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        return [(socket_family(), 1, 6, "", ("1.1.1.1", 443))]

    with pytest.raises(runner.RatEmulatorRunError, match="pinned IP"):
        runner.resolve_single_pinned_ip(profile, resolver=resolver)

    parent = short_tmp / "replay"
    parent.mkdir()
    transcript = parent / "session"
    writer = SessionTranscriptWriter(transcript, session_id="fixture")
    writer.append_event("internal", "offline", public_fields={"ok": True})
    writer.finalize(status="completed", stop_reason="offline")
    result = runner.replay_transcript(transcript)
    assert result["mode"] == "offline_replay"
    assert result["network_used"] is False


def socket_family() -> int:
    return runner.socket.AF_INET
