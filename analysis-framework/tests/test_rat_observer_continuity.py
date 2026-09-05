"""期限待ち・再接続・中断・healthの長期観測回帰を検証する。"""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
DOCKER = ROOT / "analysis-framework" / "docker" / "rat-emulators"
COMMON = ROOT / "analysis-framework" / "common"
for directory in (DOCKER, COMMON):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import observer_status
import run_defensive_rat_emulator as runner_module


@pytest.fixture
def harness(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("_continuity_supervisor", DOCKER / "purerat_long_running_observer.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    root = tmp_path / "observations"
    root.mkdir()
    armed = tmp_path / "armed"
    armed.write_text("fixture")
    common = tmp_path / "common"
    common.mkdir()
    (common / "rat_emulator_live_leases.json").write_text("fixture-lease-identity")
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module.signal, "signal", lambda *_args: None)
    settings = module.ObserverSettings(module.PROFILE_ID, root, root / "sessions", armed, tmp_path / "cache")
    fake = SimpleNamespace(
        __file__=str(common / "runner.py"),
        KillSwitch=runner_module.KillSwitch,
    )

    def permit():
        return {"live_enabled": True, "network_used": False,
                "live_lease": {"sha256": module._lease_registry_identity(fake)}}

    fake.preflight = lambda _profile: permit()

    def sleep(seconds):
        clock[0] += seconds
        if clock[0] > 4000 and armed.exists():
            armed.unlink()

    def events():
        return [json.loads(line) for line in (root / "observer-events.jsonl").read_text().splitlines()]

    return SimpleNamespace(module=module, runner=fake, root=root, armed=armed, clock=clock,
                           sleep=sleep, settings=settings, events=events, permit=permit)


def test_expired_preflight_does_not_consume_retries_and_recovers(harness):
    h = harness
    checks = []
    sessions = []

    def preflight(_profile):
        checks.append(1)
        if len(checks) <= 6:
            raise runner_module.RatEmulatorRunError("短期live leaseが期限切れです")
        return h.permit()

    def session(_profile, **kwargs):
        sessions.append(1)
        kwargs["progress_callback"]({"state": "observing", "connected": True})
        return {"adapter_result": {"status": "observation_window_complete"}}

    h.runner.preflight = preflight
    h.runner.run_live_session = session
    h.module.observe_forever(h.runner, settings=h.settings, maximum_attempts=1, sleep=h.sleep)
    assert len(sessions) == 1
    refused = [e for e in h.events() if e["event_type"] == "preflight_refused"]
    assert len(refused) == 1
    assert refused[0]["retry_consumed"] is False
    assert refused[0]["consecutive_failures"] == 0
    assert any(e["event_type"] == "preflight_restored" for e in h.events())


@pytest.mark.parametrize("outcome", ["reset", "peer_closed"])
def test_failed_connections_stop_at_initial_plus_three_and_survive_restart(harness, outcome):
    h = harness
    calls = []

    def session(_profile, **_kwargs):
        calls.append(1)
        if outcome == "reset":
            raise ConnectionResetError(104, "fixture")
        return {"adapter_result": {"status": "peer_closed"}}

    h.runner.run_live_session = session
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert len(calls) == 4
    document = json.loads((h.root / "retry-circuit.json").read_text())
    assert document["circuit_open"] is True
    assert document["consecutive_failures"] == 4
    h.armed.write_text("restarted")
    h.clock[0] = 100.0
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert len(calls) == 4


def test_invalid_new_lease_does_not_reset_persisted_circuit(harness):
    h = harness
    identity = h.module._lease_registry_identity(h.runner)
    circuit = h.module.PersistentRetryCircuit(h.root / "retry-circuit.json")
    circuit.load(identity)
    for _ in range(4):
        circuit.record_failure()
    Path(h.runner.__file__).with_name("rat_emulator_live_leases.json").write_text("invalid-new-lease")
    h.runner.preflight = lambda _profile: (_ for _ in ()).throw(ValueError("invalid"))
    h.runner.run_live_session = lambda *_args, **_kwargs: pytest.fail("接続は禁止")
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    document = json.loads((h.root / "retry-circuit.json").read_text())
    assert document["circuit_open"] is True
    assert document["lease_registry_sha256"] == identity


def test_maxmind_wait_does_not_spend_network_retries(harness):
    h = harness
    calls = []

    def session(_profile, **kwargs):
        calls.append(1)
        if len(calls) <= 5:
            kwargs["progress_callback"]({"state": "waiting_maxmind", "connected": False})
            raise runner_module.RatEmulatorRunError("公式cacheの更新が必要です")
        return {"adapter_result": {"status": "observation_window_complete"}}

    h.runner.run_live_session = session
    h.module.observe_forever(h.runner, settings=h.settings, maximum_attempts=6, sleep=h.sleep)
    assert len(calls) == 6
    document = json.loads((h.root / "retry-circuit.json").read_text())
    assert document["consecutive_failures"] == 0


def test_completed_windows_repeat_but_command_termination_does_not(harness):
    h = harness
    outcomes = iter(["observation_window_complete", "observation_window_complete", "command_refused"])
    calls = []

    def session(_profile, **_kwargs):
        outcome = next(outcomes)
        calls.append(outcome)
        return {"adapter_result": {"status": outcome}}

    h.runner.run_live_session = session
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert len(calls) == 3
    assert json.loads((h.root / "observer-status.json").read_text())["state"] == "policy_stopped"


def test_tls_policy_failure_does_not_repeat(harness):
    h = harness
    calls = []

    def session(_profile, **kwargs):
        calls.append(1)
        kwargs["progress_callback"]({"state": "connecting", "transport_phase": "tls_handshake_completed"})
        raise runner_module.TlsCertificatePinMismatch("a" * 64, "b" * 64)

    h.runner.run_live_session = session
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert len(calls) == 1
    assert json.loads((h.root / "observer-status.json").read_text())["state"] == "policy_stopped"


def test_health_reports_blocked_and_stale_not_merely_running(tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(observer_status.time, "monotonic", lambda: clock[0])
    path = tmp_path / "status.json"
    status = observer_status.ObserverStatus(path, "fixture")
    status.update("observing", connected=True)
    assert observer_status.read_health(path)[1] is True
    status.update("waiting_preflight", connected=False)
    assert observer_status.read_health(path)[1] is False
    status.update("observing", connected=True)
    clock[0] += 91
    assert observer_status.read_health(path)[1] is False
    status.update()
    assert observer_status.read_health(path)[1] is True


def test_health_rejects_symlink_and_raw_payload_fields(tmp_path):
    target = tmp_path / "target"
    target.write_text("original")
    path = tmp_path / "status"
    path.symlink_to(target)
    with pytest.raises(ValueError):
        observer_status.ObserverStatus(path, "fixture").update("observing")
    with pytest.raises(ValueError):
        observer_status.ObserverStatus(tmp_path / "new", "fixture").update("observing", raw_frame=b"secret")
    assert target.read_text() == "original"


def test_guarded_stream_cancellation_prevents_send(tmp_path):
    from rat_emulator_transcript import SessionTranscriptWriter
    armed = tmp_path / "armed"
    armed.write_text("fixture")
    calls = []
    stream = SimpleNamespace(sendall=lambda value: calls.append(value))
    guard = runner_module.GuardedStream(
        stream, limits={"duration_seconds": 60}, kill_switch=runner_module.KillSwitch(armed),
        transcript=SessionTranscriptWriter(tmp_path / "session", session_id="cancel"),
        stop_requested=lambda: True,
    )
    with pytest.raises(runner_module.ObserverStopRequested):
        guard.sendall(b"must-not-be-sent")
    assert calls == []


def test_tcp_keepalive_is_enabled_on_loopback_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        result = runner_module._enable_tcp_keepalive(sock)
        assert result["tcp_keepalive_enabled"] is True
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
        if hasattr(socket, "TCP_KEEPIDLE"):
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 60


def test_storage_limit_keeps_evidence_and_refuses_new_session(harness, monkeypatch):
    h = harness
    h.settings.sessions.mkdir()
    path = h.settings.sessions / "retained.bin"
    path.write_bytes(b"fixture")
    monkeypatch.setattr(h.module, "MAXIMUM_SESSION_STORAGE_BYTES", 7)
    h.runner.run_live_session = lambda *_args, **_kwargs: pytest.fail("容量超過時の接続は禁止")
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert path.read_bytes() == b"fixture"
    assert json.loads((h.root / "observer-status.json").read_text())["stop_reason"] == "archive_required"


def test_tls_reset_has_exact_phase_and_closes_socket(monkeypatch):
    events = []
    closed = []
    raw = SimpleNamespace(close=lambda: closed.append("raw"))

    class Context:
        def set_ciphers(self, value):
            assert value == "DEFAULT:@SECLEVEL=0"

        def wrap_socket(self, _raw, *, server_hostname):
            assert server_hostname is None
            raise ConnectionResetError(104, "fixture")

    monkeypatch.setattr(runner_module.ssl, "SSLContext", lambda *_args: Context())
    with pytest.raises(ConnectionResetError):
        runner_module.open_pinned_tls_stream(
            {"port": 56001, "limits": {"duration_seconds": 30}, "tls_version": "TLSv1.0", "sni": None},
            "127.0.0.1", connector=lambda *_args, **_kwargs: raw,
            event_callback=lambda name, fields: events.append(name),
        )
    assert events == ["tcp_connect_started", "tcp_connected", "tls_handshake_started"]
    assert closed == ["raw"]


def test_negotiated_tls_mismatch_refuses_before_certificate_or_registration(monkeypatch):
    closed = []

    class Stream:
        def version(self):
            return "TLSv1.2"

        def getpeercert(self, **_kwargs):
            pytest.fail("version不一致後に次へ進んではいけません")

        def close(self):
            closed.append("tls")

    class Context:
        def set_ciphers(self, _value):
            pass

        def wrap_socket(self, _raw, **_kwargs):
            return Stream()

    monkeypatch.setattr(runner_module.ssl, "SSLContext", lambda *_args: Context())
    raw = SimpleNamespace(close=lambda: closed.append("raw"))
    with pytest.raises(runner_module.RatEmulatorRunError, match="negotiated TLS"):
        runner_module.open_pinned_tls_stream(
            {"port": 56001, "limits": {"duration_seconds": 30}, "tls_version": "TLSv1.0"},
            "127.0.0.1", connector=lambda *_args, **_kwargs: raw,
        )
    assert "tls" in closed and "raw" in closed


def test_winos_uses_its_own_persistent_retry_identity(harness):
    h = harness
    settings = h.module.ObserverSettings(
        h.module.WINOS_SETTINGS.profile_id, h.root, h.settings.sessions,
        h.armed, h.settings.maxmind_cache,
    )
    calls = []

    def session(profile_id, **_kwargs):
        calls.append(profile_id)
        raise ConnectionResetError(104, "fixture")

    h.runner.run_live_session = session
    h.module.observe_forever(h.runner, settings=settings, sleep=h.sleep)
    assert calls == [settings.profile_id] * 4
    assert json.loads((h.root / "retry-circuit.json").read_text())["profile_id"] == settings.profile_id


def test_kill_switch_change_interrupts_cooldown(harness):
    h = harness
    calls = []

    def session(_profile, **_kwargs):
        calls.append(1)
        h.armed.write_text("changed")
        raise ConnectionResetError(104, "fixture")

    h.runner.run_live_session = session
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert len(calls) == 1
    assert h.events()[-1]["kill_switch_disarmed"] is True


def test_lease_changed_after_preflight_never_reconnects(harness):
    h = harness
    verified = h.permit()
    Path(h.runner.__file__).with_name("rat_emulator_live_leases.json").write_text("changed-after-review")
    h.runner.preflight = lambda _profile: verified
    h.runner.run_live_session = lambda *_args, **_kwargs: pytest.fail("未検証leaseへの接続は禁止")
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert not any(e["event_type"] == "session_attempt" for e in h.events())


def test_policy_stop_is_persistent_after_restart(harness):
    h = harness
    calls = []

    def session(_profile, **_kwargs):
        calls.append(1)
        return {"adapter_result": {"status": "command_refused"}}

    h.runner.run_live_session = session
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert len(calls) == 1
    h.clock[0] = 100.0
    h.module.observe_forever(h.runner, settings=h.settings, sleep=h.sleep)
    assert len(calls) == 1


@pytest.mark.parametrize("continuous", [False, True])
def test_capture_mode_retains_exact_endpoint_and_ring_limits(tmp_path, monkeypatch, continuous):
    import winos_wire_capture_entrypoint as capture

    commands = []
    monkeypatch.setattr(capture, "CAPTURE_ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["capture"] + (["--continuous"] if continuous else []))
    monkeypatch.setattr(capture.os, "execv", lambda binary, argv: commands.append((binary, argv)))
    capture.main()
    binary, argv = commands[0]
    assert binary == ("/usr/bin/tcpdump" if continuous else "/usr/bin/timeout")
    assert argv[-7:] == ["tcp", "and", "host", capture.TARGET, "and", "port", capture.PORT]
    assert argv[argv.index("-C") + 1] == "64"
    assert argv[argv.index("-W") + 1] == "16"


def test_capture_storage_limit_preserves_existing_files(tmp_path, monkeypatch):
    import winos_wire_capture_entrypoint as capture

    retained = tmp_path / "winos-fixture.pcap00"
    retained.write_bytes(b"evidence")
    monkeypatch.setattr(capture, "CAPTURE_ROOT", tmp_path)
    monkeypatch.setattr(capture, "MAXIMUM_CAPTURE_FILES", capture.FILES_PER_PROCESS)
    monkeypatch.setattr(sys, "argv", ["capture", "--continuous"])
    monkeypatch.setattr(capture.os, "execv", lambda *_args: pytest.fail("容量上限でcaptureを開始しない"))
    with pytest.raises(capture.CaptureEntrypointError):
        capture.main()
    assert retained.read_bytes() == b"evidence"
