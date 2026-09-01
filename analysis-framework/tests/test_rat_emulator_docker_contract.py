"""防御的RATエミュレーターDocker定義の安全境界を検証する。"""

from __future__ import annotations

from pathlib import Path
import ast


ROOT = Path(__file__).resolve().parents[2]
DOCKER_ROOT = ROOT / "analysis-framework" / "docker" / "rat-emulators"


def test_dockerfiles_use_nonroot_users_and_fixed_test_commands() -> None:
    for name, expected_test in (
        ("purerat.Dockerfile", "test_observer.py"),
        ("valleyrat-n520.Dockerfile", "test_valleyrat_n520_host_emulator.py"),
    ):
        text = (DOCKER_ROOT / name).read_text(encoding="utf-8")
        assert "USER 10001:10001" in text
        assert "USER root" not in text
        assert "sudo" not in text
        assert "ENTRYPOINT" not in text
        assert expected_test in text
        assert "pytest" in text
        assert "curl " not in text
        assert "wget " not in text


def test_compose_disables_network_and_host_mutation() -> None:
    text = (DOCKER_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert text.count("network_mode: none") == 2
    assert text.count("read_only: true") == 2
    assert text.count("no-new-privileges:true") == 2
    assert text.count("- ALL") == 2
    assert text.count('restart: "no"') == 2
    for forbidden in (
        "privileged:",
        "network_mode: host",
        "/var/run/docker.sock",
        "/dev/",
        "pid: host",
        "ipc: host",
    ):
        assert forbidden not in text


def test_external_observer_is_profile_pinned_and_not_host_configurable() -> None:
    dockerfile = (DOCKER_ROOT / "external-observer.Dockerfile").read_text(encoding="utf-8")
    compose = (DOCKER_ROOT / "docker-compose.external.yml").read_text(encoding="utf-8")
    entrypoint = (DOCKER_ROOT / "external_observer_entrypoint.py").read_text(encoding="utf-8")

    assert "USER 10001:10001" in dockerfile
    assert "python:3.13-slim@sha256:" in dockerfile
    assert "geoip2==${GEOIP2_VERSION}" in dockerfile
    assert "external-c2-protocol-profiles.json" in dockerfile
    assert "external-rat-emulator-profiles.json" in dockerfile
    assert "external-rat-emulator-live-leases.json" in dockerfile
    assert "valleyrat-n520-host-d11e793-9999" in compose
    assert "--acknowledge-profile" in compose
    assert "maxmind-refresh" in compose
    assert "external-setup" in compose
    assert "172.30.52.10" in compose
    assert "network_mode: host" not in compose
    assert "privileged:" not in compose
    assert "/var/run/docker.sock" not in compose
    assert "restart: \"no\"" in compose
    assert "no-new-privileges:true" in compose
    assert "file: /run/rat-emulator-secrets/maxmind-license-key" in compose
    assert "MAXMIND_LICENSE_KEY=" not in compose
    assert "/home/kali/rat-emulator-external-20260824/secrets" not in compose
    assert "C2_HOST" not in compose
    assert "C2_PORT" not in compose
    assert "socket" not in entrypoint
    assert "c2_contacted" in entrypoint
    assert '"maxmind-refresh"' in entrypoint


def test_external_registry_contains_only_the_reviewed_n520_profile() -> None:
    import json

    protocol = json.loads(
        (DOCKER_ROOT / "external-c2-protocol-profiles.json").read_text(encoding="utf-8")
    )
    emulator = json.loads(
        (DOCKER_ROOT / "external-rat-emulator-profiles.json").read_text(encoding="utf-8")
    )
    leases = json.loads(
        (DOCKER_ROOT / "external-rat-emulator-live-leases.json").read_text(encoding="utf-8")
    )
    assert [item["profile_id"] for item in protocol["profiles"]] == [
        "valleyrat-n520-d11e793-9999"
    ]
    assert [item["profile_id"] for item in emulator["profiles"]] == [
        "valleyrat-n520-host-d11e793-9999"
    ]
    assert [item["profile_id"] for item in leases["leases"]] == [
        "valleyrat-n520-host-d11e793-9999"
    ]


def test_external_observer_entrypoint_cannot_execute_received_commands() -> None:
    source = (DOCKER_ROOT / "external_observer_entrypoint.py").read_text(encoding="utf-8")
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


def test_kali_egress_policy_allows_only_reviewed_n520_endpoint() -> None:
    policy = (DOCKER_ROOT / "kali-egress-policy.sh").read_text(encoding="utf-8")
    assert 'SOURCE="172.30.52.10/32"' in policy
    assert 'TARGET="118.107.21.88/32"' in policy
    assert 'PORT="9999"' in policy
    assert "DOCKER-USER" in policy
    assert 'iptables -A "$CHAIN" -j DROP' in policy
    assert "0.0.0.0/0" not in policy


def test_external_n520_waits_within_the_reviewed_idle_bound() -> None:
    runner = (
        ROOT / "analysis-framework" / "common" / "run_defensive_rat_emulator.py"
    ).read_text(encoding="utf-8")
    assert '"timeout_seconds": min(30.0, float(limits["duration_seconds"]))' in runner
    assert 'acquisition.get("official_checksum_verified") is not True' in runner
    assert 'acquisition.get("license_key_stored") is not False' in runner
    assert '"cache_mode": "pre_refreshed_read_only"' in runner
