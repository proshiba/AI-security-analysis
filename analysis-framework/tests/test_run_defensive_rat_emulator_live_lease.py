"""RATエミュレーターrunnerの短期live lease境界検証。"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import run_defensive_rat_emulator as runner  # noqa: E402
from rat_emulator_profiles import resolve_profile  # noqa: E402
from rat_emulator_transcript import SessionTranscriptWriter  # noqa: E402

PROFILE_ID = "valleyrat-n520-host-d11e793-9999"
REVIEWED = datetime(2026, 8, 9, 9, 30, tzinfo=UTC)
EXPIRES = datetime(2026, 8, 10, 9, 30, tzinfo=UTC)


class SequenceClock:
    def __init__(self, values: list[float]) -> None:
        self.values = list(values)

    def __call__(self) -> float:
        if not self.values:
            raise AssertionError("monotonic fixtureを使い切りました")
        return self.values.pop(0)


class TimeoutHistoryStream:
    def __init__(self, chunks: list[bytes] | None = None) -> None:
        self.chunks = list(chunks or [])
        self.timeout_history: list[float] = []
        self.sent: list[bytes] = []

    def settimeout(self, value: float) -> None:
        self.timeout_history.append(value)

    def recv(self, maximum: int) -> bytes:
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        assert len(value) <= maximum
        return value

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def close(self) -> None:
        return None


def _kill_switch(path: Path) -> Path:
    path.write_text("armed\n", encoding="ascii")
    return path


def test_preflight_publishes_active_lease_and_cli_has_no_time_override() -> None:
    result = runner.preflight(PROFILE_ID, lease_now_utc=REVIEWED)
    assert result["network_used"] is False
    assert result["registry_sha256"] == (
        "3f3d2afc8879a987ad0dde8abce200d371af452b94a4018d941cf62545d0c8b4"
    )
    assert result["live_lease"] == {
        "source": "analysis-framework/common/rat_emulator_live_leases.json",
        "sha256": result["live_lease"]["sha256"],
        "reviewed_at_utc": "2026-08-09T09:30:00Z",
        "expires_at_utc": "2026-08-10T09:30:00Z",
        "review_owner": "security-analysis-review",
    }
    assert len(result["live_lease"]["sha256"]) == 64

    parser = runner.build_parser()
    subparsers = next(action for action in parser._actions if action.dest == "command")
    for child in subparsers.choices.values():
        destinations = {action.dest for action in child._actions}
        assert "lease_now_utc" not in destinations
        assert "now_utc" not in destinations


def test_expired_lease_fails_before_maxmind_dns_or_tcp(short_tmp: Path) -> None:
    private_parent = short_tmp / "private"
    private_parent.mkdir()
    switch = _kill_switch(short_tmp / "kill-switch")
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        calls.append("called")
        raise AssertionError("期限切れleaseでは外部処理を開始できません")

    output = private_parent / "session"
    with pytest.raises(runner.RatEmulatorRunError, match="期限切れ"):
        runner.run_live_session(
            PROFILE_ID,
            allow_network=True,
            allow_live_c2_emulation=True,
            acknowledged_profile=PROFILE_ID,
            kill_switch_path=switch,
            private_output_directory=output,
            maxmind_cache_directory=short_tmp / "cache",
            lease_now_utc=EXPIRES,
            resolver=forbidden,
            maxmind_preparer=forbidden,
            stream_opener=forbidden,
            adapter_runner=forbidden,
        )
    assert calls == []
    assert not output.exists()


def test_lease_expiry_during_maxmind_prevents_dns_and_tcp(short_tmp: Path) -> None:
    private_parent = short_tmp / "private"
    private_parent.mkdir()
    switch = _kill_switch(short_tmp / "kill-switch")
    calls: list[str] = []

    def maxmind(_cache: Path, pinned_ip: str) -> dict[str, object]:
        calls.append("maxmind")
        return {"ip_record": {"ip": pinned_ip}}

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        calls.append("forbidden")
        raise AssertionError("lease期限後にDNS/TCPを開始できません")

    with pytest.raises(runner.RatEmulatorRunError, match="期限切れ"):
        runner.run_live_session(
            PROFILE_ID,
            allow_network=True,
            allow_live_c2_emulation=True,
            acknowledged_profile=PROFILE_ID,
            kill_switch_path=switch,
            private_output_directory=private_parent / "session",
            maxmind_cache_directory=short_tmp / "cache",
            lease_now_utc=EXPIRES - timedelta(milliseconds=100),
            monotonic=SequenceClock([0.0, 0.2]),
            resolver=forbidden,
            maxmind_preparer=maxmind,
            stream_opener=forbidden,
            adapter_runner=forbidden,
        )
    assert calls == ["maxmind"]


def test_each_io_refreshes_timeout_to_remaining_lease(short_tmp: Path) -> None:
    parent = short_tmp / "private"
    parent.mkdir()
    switch = _kill_switch(short_tmp / "kill-switch")
    writer = SessionTranscriptWriter(parent / "session", session_id="lease-timeout")
    stream = TimeoutHistoryStream([b"x"])
    clock = SequenceClock([0.0, 0.0, 0.0, 0.4, 0.4, 0.4, 0.8, 0.8, 1.0])
    guarded = runner.GuardedStream(
        stream,
        limits=resolve_profile(PROFILE_ID)["limits"],
        kill_switch=runner.KillSwitch(switch),
        transcript=writer,
        monotonic=clock,
        lease_deadline_monotonic=1.0,
    )

    guarded.settimeout(5.0)
    guarded.sendall(b"registration")
    assert guarded.recv(1) == b"x"
    assert stream.timeout_history == pytest.approx([1.0, 0.6, 0.2])
    with pytest.raises(runner.RatEmulatorRunError, match="期限"):
        guarded.sendall(b"must-not-send")
    assert stream.sent == [b"registration"]
