"""PureRAT長期観測supervisorの排他、rotation、非実行契約。"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
DOCKER_ROOT = ROOT / "analysis-framework" / "docker" / "rat-emulators"
MODULE_PATH = DOCKER_ROOT / "purerat_long_running_observer.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "_purerat_long_running_observer_test",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(sys.platform == "win32", reason="flockはLinux Docker専用です")
def test_atomic_claim_rejects_a_second_observer(tmp_path: Path) -> None:
    module = _load_module()
    path = tmp_path / "observer.lock"
    with module.AtomicObserverClaim(path):
        with pytest.raises(module.LongRunningObserverError, match="既に稼働"):
            module.AtomicObserverClaim(path)


def test_jsonl_log_rotates_and_keeps_valid_events(tmp_path: Path) -> None:
    module = _load_module()
    path = tmp_path / "observer-events.jsonl"
    log = module.RotatingJsonlLog(path, maximum_bytes=4096, backups=2)
    for sequence in range(8):
        log.append("fixture", {"sequence": sequence, "padding": "x" * 900})
    paths = sorted(tmp_path.glob("observer-events.jsonl*"))
    assert 2 <= len(paths) <= 3
    for candidate in paths:
        for line in candidate.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            assert event["schema_version"] == 1
            assert event["event_type"] == "fixture"


def test_reset_is_labeled_as_peer_to_observer_and_never_executed() -> None:
    module = _load_module()
    event_type, fields = module._error_event(ConnectionResetError(104, "fixture"))
    assert event_type == "peer_reset_received"
    assert fields["reset_direction"] == "peer_to_observer"
    assert fields["task_executed"] is False
    assert fields["operation_executed"] is False
    assert fields["command_reply_sent"] is False


def test_retry_circuit_allows_only_initial_attempt_plus_three_retries(
    tmp_path: Path,
) -> None:
    module = _load_module()
    path = tmp_path / "retry-circuit.json"
    identity = "a" * 64
    circuit = module.PersistentRetryCircuit(path)
    assert circuit.load(identity) is False
    for expected_failures in range(1, 5):
        circuit.record_failure()
        fields = circuit.public_fields()
        assert fields["consecutive_failures"] == expected_failures
        assert fields["retries_used"] == min(3, max(0, expected_failures - 1))
        assert fields["retries_remaining"] == max(0, 4 - expected_failures)
        assert fields["retry_circuit_open"] is (expected_failures == 4)
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["maximum_retries"] == 3
    assert persisted["consecutive_failures"] == 4
    assert persisted["circuit_open"] is True

    restarted = module.PersistentRetryCircuit(path)
    assert restarted.load(identity) is False
    assert restarted.circuit_open is True
    assert restarted.public_fields()["retries_remaining"] == 0


def test_retry_circuit_resets_only_after_lease_registry_changes(
    tmp_path: Path,
) -> None:
    module = _load_module()
    path = tmp_path / "retry-circuit.json"
    circuit = module.PersistentRetryCircuit(path)
    circuit.load("a" * 64)
    for _ in range(4):
        circuit.record_failure()
    assert circuit.circuit_open is True
    assert circuit.load("a" * 64) is False
    assert circuit.circuit_open is True
    assert circuit.load("b" * 64) is True
    assert circuit.consecutive_failures == 0
    assert circuit.circuit_open is False


def test_retry_state_rejects_symlinks_and_cannot_raise_retry_limit(
    tmp_path: Path,
) -> None:
    module = _load_module()
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    path = tmp_path / "retry-circuit.json"
    path.symlink_to(target)
    with pytest.raises(module.LongRunningObserverError, match="単一の通常file"):
        module.PersistentRetryCircuit(path).load("a" * 64)
    with pytest.raises(module.LongRunningObserverError, match="3回へ固定"):
        module.PersistentRetryCircuit(tmp_path / "other.json", maximum_retries=4)


def test_supervisor_and_entrypoint_have_no_execution_primitives() -> None:
    forbidden_modules = {"subprocess", "pty", "multiprocessing", "ctypes"}
    forbidden_calls = {
        "eval",
        "exec",
        "compile",
        "system",
        "popen",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
    }
    for path in (
        MODULE_PATH,
        DOCKER_ROOT / "purerat_external_observer_entrypoint.py",
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not (
                    {alias.name.split(".", 1)[0] for alias in node.names}
                    & forbidden_modules
                )
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".", 1)[0] not in forbidden_modules
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in forbidden_calls
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in forbidden_calls


def test_long_running_compose_pins_endpoint_and_rotates_wire_capture() -> None:
    compose = (
        DOCKER_ROOT / "docker-compose.purerat-long-running.yml"
    ).read_text(encoding="utf-8")
    capture = (DOCKER_ROOT / "purerat_wire_capture_entrypoint.py").read_text(
        encoding="utf-8"
    )
    capture_dockerfile = (
        DOCKER_ROOT / "purerat-wire-capture.Dockerfile"
    ).read_text(encoding="utf-8")
    assert 'TARGET = "45.192.211.77"' in capture
    assert 'PORT = "56001"' in capture
    assert "MAXIMUM_CAPTURE_FILES = 256" in capture
    assert "FILES_PER_PROCESS = 16" in capture
    assert "CAPTURE_MEGABYTES_PER_FILE = 64" in capture
    assert 'os.execv(arguments[0], arguments)' in capture
    assert "sys.argv" not in capture
    assert "os.environ" not in capture
    assert "172.30.53.10" in compose
    assert "network_mode: service:purerat-observer" in compose
    assert compose.count("restart: unless-stopped") == 2
    assert compose.count("restart: \"no\"") == 1
    assert "- NET_RAW" in compose
    assert compose.count("no-new-privileges:true") == 2
    assert "/home/kali/purerat-observer/captures:/captures:rw" in compose
    assert "USER 10001:10001" in capture_dockerfile
    assert "-perm /6000 -exec chmod a-s" in capture_dockerfile
    assert "setcap cap_net_raw=eip /usr/bin/tcpdump" in capture_dockerfile
    assert "/var/run/docker.sock" not in compose
    assert "network_mode: host" not in compose
    assert "privileged:" not in compose


def test_purerat_egress_policy_allows_only_exact_endpoint() -> None:
    policy = (DOCKER_ROOT / "kali-purerat-egress-policy.sh").read_text(
        encoding="utf-8"
    )
    assert 'SOURCE="172.30.53.10/32"' in policy
    assert 'TARGET="45.192.211.77/32"' in policy
    assert 'PORT="56001"' in policy
    assert 'iptables -A "$CHAIN" -j DROP' in policy
    assert "0.0.0.0/0" not in policy


def test_external_private_retention_keeps_raw_frame_out_of_public_summary(
    tmp_path: Path,
) -> None:
    common = ROOT / "analysis-framework" / "common"
    if str(common) not in sys.path:
        sys.path.insert(0, str(common))
    import run_defensive_rat_emulator as runner
    from rat_emulator_transcript import SessionTranscriptWriter, build_public_summary

    class Stream:
        def __init__(self, inbound: bytes) -> None:
            self.inbound = bytearray(inbound)
            self.sent: list[bytes] = []

        def settimeout(self, _value: float) -> None:
            return None

        def recv(self, maximum: int) -> bytes:
            output = bytes(self.inbound[:maximum])
            del self.inbound[:maximum]
            return output

        def sendall(self, value: bytes) -> None:
            self.sent.append(bytes(value))

        def close(self) -> None:
            return None

    adapter = runner._load_adapter("purerat_direct_tls_v1")
    inbound = adapter.encode_inner_frame(b"\xb2\x05\x00")
    stream = Stream(inbound)
    kill = tmp_path / "armed"
    kill.write_text("armed\n", encoding="ascii")
    transcript_path = tmp_path / "session"
    transcript = SessionTranscriptWriter(transcript_path, session_id="retention")
    guarded = runner.GuardedStream(
        stream,
        limits={
            "duration_seconds": 30.0,
            "maximum_connections": 1,
            "maximum_outbound_frames": 1,
            "maximum_outbound_bytes": 26,
            "maximum_inbound_frames": 1,
            "maximum_inbound_read_calls": 64,
            "maximum_inbound_bytes": 65536,
            "maximum_frame_bytes": 65536,
            "maximum_commands": 1,
            "minimum_send_interval_seconds": 0.0,
        },
        kill_switch=runner.KillSwitch(kill),
        transcript=transcript,
        retain_private_inbound_frames=True,
    )
    guarded.sendall(adapter.build_empty_gclass4_registration_frame())
    assert guarded.recv_application_frame(65536) == inbound
    transcript.finalize(status="completed", stop_reason="fixture")
    frame_paths = sorted((transcript_path / "frames").iterdir())
    assert any(path.name.endswith(".inbound.bin") for path in frame_paths)
    public = json.dumps(build_public_summary(transcript_path), ensure_ascii=False)
    assert "raw_frame_file" not in public
    assert inbound.hex() not in public


def test_purerat_tls10_has_no_sni_and_uses_legacy_security_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    common = ROOT / "analysis-framework" / "common"
    if str(common) not in sys.path:
        sys.path.insert(0, str(common))
    import run_defensive_rat_emulator as runner

    certificate = b"fixture-certificate"
    expected = __import__("hashlib").sha256(certificate).hexdigest()

    class Raw:
        def close(self) -> None:
            return None

    class TlsStream:
        def getpeercert(self, *, binary_form: bool) -> bytes:
            assert binary_form is True
            return certificate

        def close(self) -> None:
            return None

    contexts: list[object] = []

    class Context:
        def __init__(self, protocol: object) -> None:
            assert protocol == runner.ssl.PROTOCOL_TLS_CLIENT
            self.minimum_version = None
            self.maximum_version = None
            self.ciphers: list[str] = []
            self.server_hostname = "not-called"
            contexts.append(self)

        def set_ciphers(self, value: str) -> None:
            self.ciphers.append(value)

        def wrap_socket(self, _raw: Raw, *, server_hostname: str | None):
            self.server_hostname = server_hostname
            return TlsStream()

    monkeypatch.setattr(runner.ssl, "SSLContext", Context)
    connected: list[tuple[tuple[str, int], float]] = []

    def connector(endpoint: tuple[str, int], *, timeout: float) -> Raw:
        connected.append((endpoint, timeout))
        return Raw()

    _stream, digest = runner.open_pinned_tls_stream(
        {
            "port": 56001,
            "tls_version": "TLSv1.0",
            "sni": None,
            "expected_certificate_sha256": expected,
            "limits": {"duration_seconds": 30.0},
        },
        "45.192.211.77",
        connector=connector,
    )
    context = contexts[0]
    assert connected == [(('45.192.211.77', 56001), 30.0)]
    assert context.minimum_version == runner.ssl.TLSVersion.TLSv1
    assert context.maximum_version == runner.ssl.TLSVersion.TLSv1
    assert context.ciphers == ["DEFAULT:@SECLEVEL=0"]
    assert context.server_hostname is None
    assert digest == expected


def test_pre_refreshed_maxmind_cache_needs_no_license_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    common = ROOT / "analysis-framework" / "common"
    if str(common) not in sys.path:
        sys.path.insert(0, str(common))
    import hashlib
    import run_defensive_rat_emulator as runner

    monkeypatch.delenv("MAXMIND_LICENSE_KEY", raising=False)
    for edition in ("GeoLite2-City", "GeoLite2-ASN"):
        content = f"fixture:{edition}".encode("ascii")
        database = tmp_path / f"{edition}.mmdb"
        database.write_bytes(content)
        metadata = {
            "schema_version": 1,
            "edition": edition,
            "mmdb_bytes": len(content),
            "mmdb_sha256": hashlib.sha256(content).hexdigest(),
            "official_checksum_verified": True,
            "license_key_stored": False,
            "download_url_stored": False,
        }
        (tmp_path / f"{edition}.acquisition.json").write_text(
            json.dumps(metadata),
            encoding="utf-8",
        )
    acquired = runner._load_pre_refreshed_maxmind(tmp_path)
    assert set(acquired) == {"GeoLite2-City", "GeoLite2-ASN"}
