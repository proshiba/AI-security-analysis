"""最新Winos external observerの完全一致・非実行契約を検証する。"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
DOCKER = ROOT / "analysis-framework" / "docker" / "rat-emulators"
PROFILE_ID = "valleyrat-winos-heartbeat-20260810-64-81-30-192-6666"
PROTOCOL_PATH = DOCKER / "winos-external-c2-protocol-profiles.json"
PROFILE_PATH = DOCKER / "winos-external-rat-emulator-profiles.json"
LEASE_PATH = DOCKER / "winos-external-rat-emulator-live-leases.json"

if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_protocol_probe_profiles as protocol_registry
import rat_emulator_profiles as emulator_registry
import run_defensive_rat_emulator as runner
from rat_emulator_live_leases import resolve_active_live_lease
from rat_emulator_profiles import RatEmulatorProfileError


def _load_entrypoint():
    path = DOCKER / "winos_external_observer_entrypoint.py"
    spec = importlib.util.spec_from_file_location("winos_external_observer_entrypoint", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_external_registry(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(protocol_registry, "DEFAULT_PROFILE_PATH", PROTOCOL_PATH)
    monkeypatch.setattr(emulator_registry, "DEFAULT_REGISTRY_PATH", PROFILE_PATH)
    return emulator_registry.load_registry(PROFILE_PATH, root=ROOT)


def test_external_profile_is_single_endpoint_bounded_eight_hour_observer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _load_external_registry(monkeypatch)
    assert registry.sha256 == "a9ced4b103d7f4e371af243492e535ead83f932517d1ffe9c8771a7b44ae8762"
    assert list(registry.profiles) == [PROFILE_ID]
    profile = registry.profiles[PROFILE_ID]
    assert profile["adapter_id"] == "valleyrat_winos_external_v1"
    assert profile["host"] == "64.81.30.192"
    assert profile["port"] == 6666
    assert profile["pinned_ips"] == ["64.81.30.192"]
    assert profile["live_scope"] == "leased_external"
    assert profile["station_id_sent"] is False
    assert profile["allow_live_fake_results"] is False
    assert profile["limits"]["maximum_connections"] == 1
    assert profile["limits"]["maximum_outbound_frames"] == 1
    assert profile["limits"]["maximum_outbound_bytes"] == 15
    assert profile["limits"]["duration_seconds"] == 28_800.0
    assert profile["limits"]["maximum_inbound_frames"] == 256
    assert profile["limits"]["maximum_inbound_bytes"] == 16_384
    assert runner.ADAPTER_PATHS[profile["adapter_id"]][-1] == "winos_host_emulator.py"


def test_external_profile_has_an_active_sub_24_hour_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _load_external_registry(monkeypatch)
    lease_registry, lease = resolve_active_live_lease(
        PROFILE_ID,
        now_utc=datetime(2026, 8, 29, 7, 53, tzinfo=UTC),
        path=LEASE_PATH,
        profile_registry=registry,
    )
    assert list(lease_registry.leases) == [PROFILE_ID]
    assert lease.reviewed_at_utc == "2026-08-29T07:53:00Z"
    assert lease.expires_at_utc == "2026-08-30T07:52:00Z"


def test_external_raw_tcp_opener_is_exact_and_single_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _load_external_registry(monkeypatch).profiles[PROFILE_ID]
    sentinel = object()
    calls: list[tuple[tuple[str, int], float]] = []

    def connector(endpoint: tuple[str, int], *, timeout: float):
        calls.append((endpoint, timeout))
        return sentinel

    stream, certificate = runner.open_reviewed_stream(
        profile,
        "64.81.30.192",
        connector=connector,
    )
    assert stream is sentinel
    assert certificate is None
    assert calls == [(('64.81.30.192', 6666), 3.0)]

    changed = dict(profile)
    changed["pinned_ips"] = ["64.81.30.193"]
    with pytest.raises(runner.RatEmulatorRunError, match="raw TCP"):
        runner.open_reviewed_stream(
            changed,
            "64.81.30.193",
            connector=connector,
        )
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host", "64.81.30.193"),
        ("pinned_ips", ["64.81.30.193"]),
        ("adapter_id", "valleyrat_winos_v1"),
        ("allow_live_fake_results", True),
    ],
)
def test_external_profile_mutation_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    monkeypatch.setattr(protocol_registry, "DEFAULT_PROFILE_PATH", PROTOCOL_PATH)
    document = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    document["profiles"][0][field] = value
    path = tmp_path / "mutated-profile.json"
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(RatEmulatorProfileError):
        emulator_registry.load_registry(path, root=ROOT)


def test_external_entrypoint_and_policy_cannot_execute_received_commands() -> None:
    source = (DOCKER / "winos_external_observer_entrypoint.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    forbidden_names = {"eval", "exec", "compile", "system", "popen", "spawn", "run"}
    forbidden_modules = {"subprocess", "pty", "multiprocessing", "ctypes"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not ({alias.name.split(".", 1)[0] for alias in node.names} & forbidden_modules)
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".", 1)[0] not in forbidden_modules
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_names
            elif isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden_names

    policy = (DOCKER / "kali-winos-egress-policy.sh").read_text(encoding="utf-8")
    assert 'SOURCE="172.30.54.10/32"' in policy
    assert 'TARGET="64.81.30.192/32"' in policy
    assert 'PORT="6666"' in policy
    assert 'iptables -A "$CHAIN" -j DROP' in policy
    assert "0.0.0.0/0" not in policy

    capture = (DOCKER / "winos_wire_capture_entrypoint.py").read_text(
        encoding="utf-8"
    )
    assert 'TARGET = "64.81.30.192"' in capture
    assert 'PORT = "6666"' in capture
    assert 'CAPTURE_SECONDS = "28815s"' in capture


def test_external_docker_is_nonroot_read_only_and_bounded() -> None:
    dockerfile = (DOCKER / "winos-external-observer.Dockerfile").read_text(
        encoding="utf-8"
    )
    compose = (DOCKER / "docker-compose.winos-external.yml").read_text(
        encoding="utf-8"
    )
    assert "USER 10001:10001" in dockerfile
    assert "winos-external-c2-protocol-profiles.json" in dockerfile
    assert "winos-external-rat-emulator-profiles.json" in dockerfile
    assert "winos-external-rat-emulator-live-leases.json" in dockerfile
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert 'restart: "no"' in compose
    assert "- observe" in compose
    assert '- "28800"' in compose
    assert '- "3"' in compose
    assert "172.30.54.10" in compose
    assert "network_mode: service:valleyrat-winos-external-observer" in compose
    assert "winos-wire-capture.Dockerfile" in compose
    for forbidden in (
        "privileged:",
        "network_mode: host",
        "/var/run/docker.sock",
        "pid: host",
        "ipc: host",
    ):
        assert forbidden not in compose


def test_observer_keeps_one_session_then_reconnects_only_after_peer_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint = _load_entrypoint()
    outputs = iter(
        [
            (tmp_path / "private-1", tmp_path / "public-1.json"),
            (tmp_path / "private-2", tmp_path / "public-2.json"),
        ]
    )
    monkeypatch.setattr(entrypoint, "_new_output_paths", lambda: next(outputs))
    clock = [100.0]
    monkeypatch.setattr(entrypoint.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(entrypoint.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    class FakeRunner:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def preflight(self, profile_id: str) -> dict[str, object]:
            assert profile_id == PROFILE_ID
            return {
                "endpoint": "64.81.30.192:6666",
                "pinned_ips": ["64.81.30.192"],
                "network_used": False,
            }

        def run_live_session(self, _profile_id: str, **kwargs: object) -> dict[str, object]:
            self.calls.append(kwargs)
            status = "peer_closed" if len(self.calls) == 1 else "observation_window_complete"
            return {
                "adapter_result": {"status": status},
                "transcript_root_sha256": str(len(self.calls)) * 64,
            }

    runner = FakeRunner()
    assert entrypoint._observe(
        runner,
        duration_seconds=28_800.0,
        maximum_retries=3,
    ) == 0
    assert len(runner.calls) == 2
    assert all(call["allow_live_c2_emulation"] is True for call in runner.calls)
    assert runner.calls[0]["session_duration_seconds"] == 28_800.0
    assert runner.calls[1]["session_duration_seconds"] == 28_770.0


def test_observer_connection_refusal_has_three_retry_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint = _load_entrypoint()
    counter = iter(range(4))
    monkeypatch.setattr(
        entrypoint,
        "_new_output_paths",
        lambda: (
            tmp_path / f"private-{next(counter)}",
            tmp_path / "public.json",
        ),
    )
    clock = [200.0]
    monkeypatch.setattr(entrypoint.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(entrypoint.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    class RefusingRunner:
        def __init__(self) -> None:
            self.attempts = 0

        def preflight(self, _profile_id: str) -> dict[str, object]:
            return {"endpoint": "64.81.30.192:6666", "network_used": False}

        def run_live_session(self, _profile_id: str, **_kwargs: object) -> dict[str, object]:
            self.attempts += 1
            raise ConnectionRefusedError(111, "refused")

    runner = RefusingRunner()
    assert entrypoint._observe(
        runner,
        duration_seconds=28_800.0,
        maximum_retries=3,
    ) == 0
    assert runner.attempts == 4
