from __future__ import annotations

import base64
import json
import struct
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
REPOSITORY = Path(__file__).parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import long_running_command_observer as supervisor
from tls_messagepack_rat_host_emulator import encode_frame

STEALC_SAMPLE = "47854afb3cfeb64a85dda148e00e5ca83168f431a28e5c5fb28733e37f484b13"


def initialize(
    tmp_path: Path,
    *,
    retain_private_fields: bool = True,
    rotation_event_count: int = 1000,
) -> tuple[Path, supervisor.LongRunningCommandObservatory]:
    root = (tmp_path / "observatory").resolve()
    supervisor.initialize_observatory(
        root,
        repository_root=REPOSITORY.resolve(),
        policy=supervisor.SupervisorPolicy(rotation_event_count=rotation_event_count),
        retain_private_fields=retain_private_fields,
    )
    return root, supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
    )


def stealc_spool(
    *,
    dynamic_key: str = "abcdef1234",
    dynamic_value: str = "1111111111",
    url: str = "https://payload.invalid/private.exe",
) -> dict:
    return {
        "schema_version": 1,
        "profile_id": "stealc-v2-1backs-decoded-json-v1",
        "sample_sha256": STEALC_SAMPLE,
        "source_scope": "offline_capture",
        "direction": "server_to_client",
        "captured_at": "2026-08-27T00:00:00Z",
        "encoding": "decoded_json",
        "message": {
            "opcode": "success",
            "loader": [{"url": url}],
            dynamic_key: dynamic_value,
        },
    }


def write_spool(root: Path, name: str, value: dict) -> Path:
    path = root / "incoming" / name
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return path


def all_observatory_file_bytes(root: Path) -> bytes:
    return b"\n".join(path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file())


def test_initialization_is_repository_external_and_fail_closed(tmp_path: Path) -> None:
    root, _ = initialize(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["network_scope"] == "offline_or_loopback_only"
    assert manifest["external_c2_connections_allowed"] is False
    assert manifest["command_execution_allowed"] is False
    assert manifest["payload_download_allowed"] is False
    assert len(manifest["profile_registry_sha256"]) == 64
    assert manifest["tail_detection"] == "local_durable_head_checkpoint_v1"
    assert manifest["external_anchor_present"] is False
    assert manifest["coordinated_checkpoint_rollback_detectable"] is False
    with pytest.raises(FileExistsError):
        supervisor.initialize_observatory(root, repository_root=REPOSITORY.resolve())
    with pytest.raises(supervisor.LongRunningObserverError, match="repository配下"):
        supervisor.initialize_observatory(
            (REPOSITORY / "private-observatory-test").resolve(),
            repository_root=REPOSITORY.resolve(),
        )

    wrong_repository = (tmp_path / "wrong-repository").resolve()
    wrong_repository.mkdir()
    with pytest.raises(supervisor.LongRunningObserverError, match="実行module由来"):
        supervisor.initialize_observatory(
            (tmp_path / "wrong-root").resolve(),
            repository_root=wrong_repository,
        )

    worktree = (tmp_path / "other-worktree").resolve()
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: private", encoding="utf-8")
    with pytest.raises(supervisor.LongRunningObserverError, match="git worktree"):
        supervisor.initialize_observatory(
            (worktree / "observatory").resolve(),
            repository_root=REPOSITORY.resolve(),
        )


def test_one_cycle_commits_private_command_and_public_summary_without_url(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    source = write_spool(root, "0001.json", stealc_spool())
    with observatory.claim():
        result = observatory.run_cycle()
    assert result["observed"] == 1
    assert not source.exists()
    assert len(list((root / "processed").glob("*.json"))) == 1
    receipt_path = next((root / "processed").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["artifact_type"] == "sanitized_spool_receipt"
    assert receipt["raw_content_retained"] is False
    assert set(receipt["source"]) == {"size", "sha256"}
    assert "payload.invalid" not in receipt_path.read_text(encoding="utf-8")
    event_path = next((root / "ledger").glob("segment-*/*.json"))
    event = json.loads(event_path.read_text(encoding="utf-8"))
    private_url = event["private_fields"]["decoded_message"]["loader"][0]["url"]
    assert private_url == "https://payload.invalid/private.exe"
    summary = observatory.public_summary()
    assert summary["event_count"] == 1
    assert summary["commands_executed"] is False
    assert summary["responses_sent"] is False
    assert "payload.invalid" not in json.dumps(summary)


def test_identical_source_is_not_committed_twice(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    document = stealc_spool()
    write_spool(root, "0001.json", document)
    with observatory.claim():
        assert observatory.run_cycle()["observed"] == 1
    write_spool(root, "0002.json", document)
    with observatory.claim():
        result = observatory.run_cycle()
    assert result["duplicates"] == 1
    assert observatory.ledger.verify().event_count == 1


def test_semantically_equal_stealc_commands_aggregate_across_restart(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    write_spool(root, "0001.json", stealc_spool())
    with observatory.claim():
        observatory.run_cycle()
    restarted = supervisor.LongRunningCommandObservatory(root, repository_root=REPOSITORY.resolve())
    write_spool(
        root,
        "0002.json",
        stealc_spool(dynamic_key="abcdef5678", dynamic_value="2222222222"),
    )
    with restarted.claim():
        restarted.run_cycle()
    summary = restarted.public_summary()
    assert summary["event_count"] == 2
    assert summary["unique_command_fingerprints"] == 1
    assert summary["observations"][0]["sightings"] == 2


def test_rotation_and_crash_reconstruction_use_append_only_events(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path, rotation_event_count=1)
    write_spool(root, "0001.json", stealc_spool(url="https://payload.invalid/a.exe"))
    write_spool(root, "0002.json", stealc_spool(url="https://payload.invalid/b.exe"))
    with observatory.claim():
        result = observatory.run_cycle(maximum_files=2)
    assert result["observed"] == 2
    assert (root / "ledger" / "segment-000001").is_dir()
    assert (root / "ledger" / "segment-000002").is_dir()
    restarted = supervisor.LongRunningCommandObservatory(root, repository_root=REPOSITORY.resolve())
    state = restarted.ledger.verify()
    assert state.event_count == 2
    assert state.active_segment == 2


def test_ledger_tamper_is_detected(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    write_spool(root, "0001.json", stealc_spool())
    with observatory.claim():
        observatory.run_cycle()
    event_path = next((root / "ledger").glob("segment-*/*.json"))
    event = json.loads(event_path.read_text(encoding="utf-8"))
    event["public_event"]["normalized_command"] = "tampered"
    event_path.write_text(json.dumps(event), encoding="utf-8")
    with pytest.raises(supervisor.LongRunningObserverError, match="chain"):
        observatory.ledger.verify()


def test_single_instance_claim_blocks_second_supervisor(tmp_path: Path) -> None:
    _, observatory = initialize(tmp_path)
    with (
        observatory.claim(),
        pytest.raises(supervisor.LongRunningObserverError, match="claim"),
        observatory.claim(),
    ):
        raise AssertionError("unreachable")
    with observatory.claim():
        pass


def test_invalid_source_scope_is_quarantined_without_ledger_event(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    source = write_spool(root, "external.json", {**stealc_spool(), "source_scope": "external_c2"})
    with observatory.claim():
        result = observatory.run_cycle()
    assert result["rejected"] == 1
    assert not source.exists()
    assert list((root / "rejected").glob("*.input.json")) == []
    reason_path = next((root / "rejected").glob("*.reason.json"))
    reason = json.loads(reason_path.read_text(encoding="utf-8"))
    assert reason["artifact_type"] == "sanitized_spool_receipt"
    assert reason["raw_content_retained"] is False
    assert set(reason["source"]) == {"size", "sha256"}
    assert "external_c2" not in reason_path.read_text(encoding="utf-8")
    assert observatory.ledger.verify().event_count == 0


def test_private_fields_can_be_disabled_without_raw_accepted_or_rejected_spool(
    tmp_path: Path,
) -> None:
    root, observatory = initialize(tmp_path, retain_private_fields=False)
    write_spool(root, "0001.json", stealc_spool())
    with observatory.claim():
        observatory.run_cycle()
    plugin = b"PRIVATE-NO-RETAIN-PLUGIN-COMMAND-URL"
    encoded_plugin = base64.b64encode(encode_frame({"Pac_ket": "plu_gin", "Dll": plugin})).decode("ascii")
    write_spool(
        root,
        "venom.json",
        {
            "schema_version": 1,
            "profile_id": "venomrat-603-6a24ba25-messagepack-v1",
            "sample_sha256": ("6a24ba25482c73d193fcc208d8ae267236b870b9ab30c44cabe2dc8bfb7a1073"),
            "source_scope": "offline_capture",
            "direction": "server_to_client",
            "captured_at": "2026-08-27T00:00:00Z",
            "encoding": "frame_base64",
            "frame_base64": encoded_plugin,
        },
    )
    with observatory.claim():
        assert observatory.run_cycle()["observed"] == 1
    write_spool(
        root,
        "rejected.json",
        {
            **stealc_spool(url="https://reject-secret.invalid/private.exe"),
            "source_scope": "external_c2",
        },
    )
    with observatory.claim():
        assert observatory.run_cycle()["rejected"] == 1
    events = [
        json.loads(path.read_text(encoding="utf-8")) for path in sorted((root / "ledger").glob("segment-*/*.json"))
    ]
    assert len(events) == 2
    assert all(event["private_fields"] == {} for event in events)
    assert all(event["private_fields_retained"] is False for event in events)
    retained = all_observatory_file_bytes(root)
    assert b"payload.invalid" not in retained
    assert b"reject-secret.invalid" not in retained
    assert plugin not in retained
    assert encoded_plugin.encode("ascii") not in retained
    assert b"frame_base64" not in retained


def test_preexisting_kill_switch_stops_before_any_cycle(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    (root / "kill.switch").write_text("stop\n", encoding="utf-8")
    result = observatory.run()
    assert result["stop_reason"] == "kill_switch_present"
    assert result["cycles"] == 0
    assert result["network_contacted"] is False
    assert result["commands_executed"] is False
    assert not (root / "supervisor.claim").exists()


def test_spool_duplicate_key_is_rejected(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    source = root / "incoming" / "duplicate.json"
    source.write_text(
        '{"schema_version":1,"schema_version":1,"profile_id":"x"}',
        encoding="utf-8",
    )
    with observatory.claim():
        result = observatory.run_cycle()
    assert result["rejected"] == 1
    assert observatory.ledger.verify().event_count == 0


def test_storage_capacity_stops_without_rejecting_or_deleting_input(tmp_path: Path) -> None:
    root = (tmp_path / "capacity-observatory").resolve()
    policy = supervisor.SupervisorPolicy(maximum_storage_bytes=1024 * 1024)
    supervisor.initialize_observatory(
        root,
        repository_root=REPOSITORY.resolve(),
        policy=policy,
    )
    source = root / "incoming" / "capacity.json"
    source.write_bytes(b"x" * (1024 * 1024))
    observatory = supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
    )

    result = observatory.run()

    assert result["stop_reason"] == "storage_capacity_reached"
    assert result["cycles"] == 0
    assert source.exists()
    assert list((root / "rejected").iterdir()) == []
    assert not (root / "supervisor.claim").exists()


def test_event_capacity_is_reconstructed_and_stops_after_restart(tmp_path: Path) -> None:
    root = (tmp_path / "event-capacity-observatory").resolve()
    policy = supervisor.SupervisorPolicy(maximum_ledger_events=1)
    supervisor.initialize_observatory(
        root,
        repository_root=REPOSITORY.resolve(),
        policy=policy,
    )
    observatory = supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
    )
    write_spool(root, "0001.json", stealc_spool())
    with observatory.claim():
        assert observatory.run_cycle()["observed"] == 1

    restarted = supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
    )
    result = restarted.run()

    assert result["stop_reason"] == "event_capacity_reached"
    assert result["ledger_event_count"] == 1
    assert result["cycles"] == 0


def test_failure_backoff_uses_bounded_injected_jitter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "jitter-observatory").resolve()
    policy = supervisor.SupervisorPolicy(
        initial_backoff_seconds=1.0,
        maximum_process_runtime_seconds=1.0,
        backoff_jitter_fraction=0.2,
    )
    supervisor.initialize_observatory(
        root,
        repository_root=REPOSITORY.resolve(),
        policy=policy,
    )
    now = [0.0]
    sleeps: list[float] = []

    def advance(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    observatory = supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
        monotonic=lambda: now[0],
        sleeper=advance,
        jitter_source=lambda: 1.0,
    )

    def fail_cycle() -> dict:
        raise OSError("synthetic failure")

    monkeypatch.setattr(observatory, "run_cycle", fail_cycle)
    result = observatory.run()

    assert result["failures"] == 1
    assert result["stop_reason"] == "maximum_runtime_reached"
    assert sleeps == [pytest.approx(1.0)]
    assert now[0] == pytest.approx(1.0)


def test_ledger_commit_error_stops_and_requires_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, observatory = initialize(tmp_path)
    sleeps: list[float] = []

    def fail_commit() -> dict:
        raise supervisor.LedgerCommitError("synthetic checkpoint failure")

    monkeypatch.setattr(observatory, "run_cycle", fail_commit)
    observatory.sleeper = sleeps.append
    result = observatory.run()

    assert result["stop_reason"] == "ledger_commit_failed_restart_required"
    assert result["failures"] == 1
    assert result["cycles"] == 0
    assert sleeps == []


def test_remcos_frame_flows_through_private_spool_without_command_leak(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    delimiter = bytes.fromhex("7c 1e 1e 1f 7c")
    payload = struct.pack("<I", 0x0E) + delimiter.join((b"private command line", b"20"))
    frame = bytes.fromhex("24 04 ff 00") + struct.pack("<I", len(payload)) + payload
    write_spool(
        root,
        "remcos.json",
        {
            "schema_version": 1,
            "profile_id": "remcos-decrypted-plaintext-framing-v1",
            "sample_sha256": ("61321510045ef68e4e20672cb1b130a2632d7b3cb1c3c8348c4c5e300d0d8a19"),
            "source_scope": "offline_capture",
            "direction": "server_to_client",
            "captured_at": "2026-08-27T00:00:00Z",
            "encoding": "frame_base64",
            "frame_base64": base64.b64encode(frame).decode("ascii"),
        },
    )
    with observatory.claim():
        assert observatory.run_cycle()["observed"] == 1

    event_path = next((root / "ledger").glob("segment-*/*.json"))
    event = json.loads(event_path.read_text(encoding="utf-8"))
    assert event["public_event"]["protocol_identifier"] == "0x0e"
    assert event["public_event"]["normalized_command"] == "unknown"
    assert event["private_fields"]["decoded_payload_fields"][0] == "private command line"
    summary = observatory.public_summary()
    assert "private command line" not in json.dumps(summary, ensure_ascii=False)
    assert summary["responses_sent"] is False


def test_bounded_soak_rotates_and_recovers_across_restarts(tmp_path: Path) -> None:
    root = (tmp_path / "soak-observatory").resolve()
    policy = supervisor.SupervisorPolicy(
        rotation_event_count=11,
        maximum_files_per_cycle=13,
        maximum_ledger_events=256,
        maximum_storage_bytes=64 * 1024 * 1024,
    )
    supervisor.initialize_observatory(
        root,
        repository_root=REPOSITORY.resolve(),
        policy=policy,
    )
    for index in range(120):
        write_spool(
            root,
            f"{index:04d}.json",
            stealc_spool(url=f"https://payload.invalid/{index:04d}.exe"),
        )

    observed = 0
    restarts = 0
    while list((root / "incoming").glob("*.json")):
        observatory = supervisor.LongRunningCommandObservatory(
            root,
            repository_root=REPOSITORY.resolve(),
        )
        restarts += 1
        with observatory.claim():
            for _ in range(3):
                result = observatory.run_cycle()
                observed += result["observed"]
                if result["processed"] == 0:
                    break

    recovered = supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
    )
    state = recovered.ledger.verify()
    summary = recovered.public_summary()

    assert observed == 120
    assert state.event_count == 120
    assert restarts >= 4
    assert len(list((root / "ledger").glob("segment-*"))) == 11
    assert summary["event_count"] == 120
    assert summary["storage_bytes"] < summary["storage_limit_bytes"]
    assert "payload.invalid" not in json.dumps(summary)


def test_same_wire_hash_is_not_merged_across_remcos_profiles(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    body = struct.pack("<I", 0xFFFF) + b"same opaque payload"
    frame = bytes.fromhex("24 04 ff 00") + struct.pack("<I", len(body)) + body
    common = {
        "schema_version": 1,
        "source_scope": "offline_capture",
        "direction": "server_to_client",
        "captured_at": "2026-08-27T00:00:00Z",
        "encoding": "frame_base64",
        "frame_base64": base64.b64encode(frame).decode("ascii"),
    }
    write_spool(
        root,
        "generic.json",
        {
            **common,
            "profile_id": "remcos-decrypted-plaintext-framing-v1",
            "sample_sha256": ("61321510045ef68e4e20672cb1b130a2632d7b3cb1c3c8348c4c5e300d0d8a19"),
        },
    )
    write_spool(
        root,
        "version-bound.json",
        {
            **common,
            "profile_id": "remcos-published-340-taxonomy-v1",
            "sample_sha256": None,
        },
    )
    with observatory.claim():
        assert observatory.run_cycle(maximum_files=2)["observed"] == 2

    summary = observatory.public_summary()

    assert summary["event_count"] == 2
    assert summary["unique_command_fingerprints"] == 2
    assert len(summary["observations"]) == 2
    assert {item["profile_id"] for item in summary["observations"]} == {
        "remcos-decrypted-plaintext-framing-v1",
        "remcos-published-340-taxonomy-v1",
    }


def test_profile_registry_hash_is_pinned_and_drift_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _ = initialize(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["profile_registry_sha256"] == supervisor._profile_registry_sha256()
    drifted = dict(supervisor.rat_observer.STEALC_CONFIG_FIELD_TYPES)
    drifted["loader"] = "synthetic_taxonomy_drift"
    monkeypatch.setattr(supervisor.rat_observer, "STEALC_CONFIG_FIELD_TYPES", drifted)
    assert supervisor._profile_registry_sha256() != manifest["profile_registry_sha256"]
    with pytest.raises(supervisor.LongRunningObserverError, match="manifest"):
        supervisor.LongRunningCommandObservatory(
            root,
            repository_root=REPOSITORY.resolve(),
        )


def test_local_checkpoint_detects_deleted_tail_event(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path)
    write_spool(root, "0001.json", stealc_spool())
    write_spool(root, "0002.json", stealc_spool(url="https://payload.invalid/two.exe"))
    with observatory.claim():
        assert observatory.run_cycle(maximum_files=2)["observed"] == 2

    event_paths = sorted((root / "ledger").glob("segment-*/*.json"))
    event_paths[-1].unlink()

    with pytest.raises(supervisor.LedgerCommitError, match="checkpoint"):
        supervisor.LongRunningCommandObservatory(
            root,
            repository_root=REPOSITORY.resolve(),
        )


def test_event_durable_checkpoint_old_crash_state_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, observatory = initialize(tmp_path)
    source = write_spool(root, "0001.json", stealc_spool())

    def fail_checkpoint(*, event_count: int, ledger_head_sha256: str) -> None:
        del event_count, ledger_head_sha256
        raise OSError("synthetic checkpoint failure")

    monkeypatch.setattr(observatory.ledger, "_commit_checkpoint", fail_checkpoint)
    with observatory.claim(), pytest.raises(supervisor.LedgerCommitError, match="checkpoint"):
        observatory.run_cycle()
    assert source.exists()
    assert len(list((root / "ledger").glob("segment-*/*.json"))) == 1
    with pytest.raises(supervisor.LedgerCommitError, match="checkpoint"):
        supervisor.LongRunningCommandObservatory(
            root,
            repository_root=REPOSITORY.resolve(),
        )


def test_checkpoint_committed_before_error_is_safely_recovered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, observatory = initialize(tmp_path)
    source = write_spool(root, "0001.json", stealc_spool())
    original_commit = observatory.ledger._commit_checkpoint

    def commit_then_raise(*, event_count: int, ledger_head_sha256: str) -> None:
        original_commit(
            event_count=event_count,
            ledger_head_sha256=ledger_head_sha256,
        )
        raise OSError("synthetic post-commit failure")

    monkeypatch.setattr(observatory.ledger, "_commit_checkpoint", commit_then_raise)
    with observatory.claim(), pytest.raises(supervisor.LedgerCommitError, match="checkpoint"):
        observatory.run_cycle()
    assert source.exists()

    restarted = supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
    )
    assert restarted.ledger.state.event_count == 1
    with restarted.claim():
        result = restarted.run_cycle()
    assert result["duplicates"] == 1
    assert not source.exists()


def test_retain_true_keeps_plugin_raw_out_of_receipt_and_ledger(tmp_path: Path) -> None:
    root, observatory = initialize(tmp_path, retain_private_fields=True)
    plugin = b"PRIVATE-PLUGIN-RAW-BYTES"
    frame = encode_frame({"Pac_ket": "plu_gin", "Dll": plugin})
    encoded_frame = base64.b64encode(frame).decode("ascii")
    write_spool(
        root,
        "venom.json",
        {
            "schema_version": 1,
            "profile_id": "venomrat-603-6a24ba25-messagepack-v1",
            "sample_sha256": ("6a24ba25482c73d193fcc208d8ae267236b870b9ab30c44cabe2dc8bfb7a1073"),
            "source_scope": "offline_capture",
            "direction": "server_to_client",
            "captured_at": "2026-08-27T00:00:00Z",
            "encoding": "frame_base64",
            "frame_base64": encoded_frame,
        },
    )
    with observatory.claim():
        assert observatory.run_cycle()["observed"] == 1

    retained = all_observatory_file_bytes(root)
    assert plugin not in retained
    assert encoded_frame.encode("ascii") not in retained
    receipt_path = next((root / "processed").glob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert set(receipt["source"]) == {"size", "sha256"}
    event_path = next((root / "ledger").glob("segment-*/*.json"))
    event = json.loads(event_path.read_text(encoding="utf-8"))
    assert event["private_fields"]["decoded_message"]["Dll"]["binary_size"] == len(plugin)


def test_public_summary_uses_direction_in_aggregate_key(tmp_path: Path) -> None:
    _, observatory = initialize(tmp_path)
    public = {
        "profile_id": "remcos-decrypted-plaintext-framing-v1",
        "family": "remcosrat",
        "direction": "server_to_client",
        "category": "unknown",
        "normalized_command": "unknown",
        "message_sha256": "a" * 64,
    }
    observatory.ledger.append(
        source_artifact={"size": 1, "sha256": "1" * 64, "link_count": 1},
        source_scope="offline_capture",
        captured_at="2026-08-27T00:00:00Z",
        sample_sha256=None,
        public_event=public,
        private_fields={},
    )
    observatory.ledger.append(
        source_artifact={"size": 1, "sha256": "2" * 64, "link_count": 1},
        source_scope="offline_capture",
        captured_at="2026-08-27T00:00:01Z",
        sample_sha256=None,
        public_event={**public, "direction": "client_to_server"},
        private_fields={},
    )
    summary = observatory.public_summary()
    assert summary["event_count"] == 2
    assert summary["unique_command_fingerprints"] == 2
    assert len(summary["observations"]) == 2
    assert {item["direction"] for item in summary["observations"]} == {
        "client_to_server",
        "server_to_client",
    }


def test_kill_switch_interrupts_backoff_before_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "kill-during-backoff").resolve()
    policy = supervisor.SupervisorPolicy(
        initial_backoff_seconds=10.0,
        maximum_process_runtime_seconds=20.0,
    )
    supervisor.initialize_observatory(
        root,
        repository_root=REPOSITORY.resolve(),
        policy=policy,
    )
    now = [0.0]
    sleeps: list[float] = []

    def sleep_and_kill(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds
        (root / "kill.switch").write_text("stop\\n", encoding="utf-8")

    observatory = supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
        monotonic=lambda: now[0],
        sleeper=sleep_and_kill,
        jitter_source=lambda: 0.5,
    )

    def fail_cycle() -> dict:
        raise OSError("synthetic failure")

    monkeypatch.setattr(observatory, "run_cycle", fail_cycle)
    result = observatory.run()
    assert result["stop_reason"] == "kill_switch_present"
    assert sleeps == [pytest.approx(supervisor.KILL_SWITCH_POLL_SECONDS)]
    assert now[0] < policy.maximum_process_runtime_seconds


def test_segment_name_width_supports_policy_maximum(tmp_path: Path) -> None:
    root = (tmp_path / "wide-segment").resolve()
    policy = supervisor.SupervisorPolicy(maximum_ledger_events=100_000_000)
    supervisor.initialize_observatory(
        root,
        repository_root=REPOSITORY.resolve(),
        policy=policy,
    )
    observatory = supervisor.LongRunningCommandObservatory(
        root,
        repository_root=REPOSITORY.resolve(),
    )
    name = observatory.ledger._segment_path(100_000_000).name
    assert name == "segment-100000000"
    assert supervisor.SEGMENT_RE.fullmatch(name) is not None


def test_full_storage_reconciliation_rejects_managed_hardlink(
    tmp_path: Path,
) -> None:
    root, observatory = initialize(tmp_path)
    external = tmp_path / "external-hardlink-target.bin"
    external.write_bytes(b"external-content")
    linked = root / "processed" / "hardlinked.bin"
    try:
        linked.hardlink_to(external)
    except OSError as exc:
        pytest.skip(f"hardlink is unavailable on this filesystem: {exc}")
    with pytest.raises(supervisor.LongRunningObserverError, match="hardlink"):
        observatory.storage_bytes(force_full=True)


def test_repeated_cycles_do_not_rescan_full_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _root, observatory = initialize(tmp_path)
    original = supervisor._regular_tree_bytes
    scanned: list[Path] = []

    def record_scan(path: Path, *, stop_after: int | None = None) -> int:
        scanned.append(path)
        return original(path, stop_after=stop_after)

    monkeypatch.setattr(supervisor, "_regular_tree_bytes", record_scan)
    with observatory.claim():
        observatory.run_cycle()
        observatory.run_cycle()
    assert observatory.root not in scanned
    assert scanned
    assert set(scanned) == {observatory.root / "incoming"}

    scanned.clear()
    observatory._cycles_since_full_storage_reconciliation = supervisor.FULL_STORAGE_RECONCILIATION_CYCLES - 1
    with observatory.claim():
        observatory.run_cycle()
    assert observatory.root in scanned
