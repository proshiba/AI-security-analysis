from __future__ import annotations

import importlib.util
import itertools
import json
import struct
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "remcosrat" / "emulator.py"
SPEC = importlib.util.spec_from_file_location("remcosrat_emulator_test_module", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
emulator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(emulator)

REMCOS_SAMPLE_730 = "61321510045ef68e4e20672cb1b130a2632d7b3cb1c3c8348c4c5e300d0d8a19"
MAGIC = bytes.fromhex("24 04 ff 00")
DELIMITER = bytes.fromhex("7c 1e 1e 1f 7c")


def frame(command_id: int, *fields: bytes) -> bytes:
    body = struct.pack("<I", command_id) + DELIMITER.join(fields)
    return MAGIC + struct.pack("<I", len(body)) + body


def test_emulator_observes_fragmented_and_coalesced_stream_without_side_effects() -> None:
    command = frame(0x0E, b"private command line")
    heartbeat = frame(0x01, b"0", b"30")
    result = emulator.emulate(
        {"c2": [{"endpoint": "bebelonserver.example:2404"}]},
        plaintext_stream_chunks=(command[:7], command[7:] + heartbeat),
        sample_sha256=REMCOS_SAMPLE_730,
    )

    assert result["configured_endpoints"] == ["bebelonserver.example:2404"]
    assert result["network_contacted"] is False
    assert result["packets_generated"] == 0
    assert result["operation_executed"] is False
    observation = result["plaintext_observation"]
    assert observation["frame_count"] == 2
    assert observation["stream_chunk_count"] == 2
    assert observation["command_responses_generated"] == 0
    assert [item["protocol_identifier"] for item in observation["events"]] == ["0x0e", "0x01"]
    assert all(item["normalized_command"] == "unknown" for item in observation["events"])
    assert "private command line" not in json.dumps(result, ensure_ascii=False)


def test_configured_endpoints_publish_only_valid_host_port() -> None:
    result = emulator.emulate(
        {
            "c2": [
                {"endpoint": "Example.Invalid:2404"},
                {"endpoint": "https://user:pass@example.invalid/a?token=secret#fragment"},
                {"endpoint": 1234},
            ]
        }
    )
    serialized = json.dumps(result, ensure_ascii=False)
    assert result["configured_endpoints"] == ["example.invalid:2404"]
    assert result["configured_endpoint_input_count"] == 3
    assert result["configured_endpoint_rejected_count"] == 2
    assert len(result["configured_endpoint_sha256s"]) == 2
    assert "user" not in serialized
    assert "pass" not in serialized
    assert "token=secret" not in serialized


def test_published_taxonomy_requires_explicit_profile_selection() -> None:
    command = frame(0x0E, b"private command line")
    selected = emulator.observe_plaintext_stream(
        (command,),
        profile_id="remcos-published-340-taxonomy-v1",
    )["events"][0]
    assert selected["normalized_command"] == "interactive_shell"
    assert selected["published_taxonomy_applied"] is True
    assert selected["exact_sample_binding"] is False
    assert selected["taxonomy_source"] == ("https://www.fortinet.com/blog/threat-research/latest-remcos-rat-phishing")
    assert selected["taxonomy_evidence_artifact_pinned"] is False

    generic = emulator.observe_plaintext_stream(
        (command,),
        sample_sha256=REMCOS_SAMPLE_730,
    )["events"][0]
    assert generic["normalized_command"] == "unknown"
    assert generic["published_taxonomy_applied"] is False
    assert generic["exact_sample_binding"] is False


def test_truncated_plaintext_stream_is_rejected() -> None:
    command = frame(0x01, b"0", b"30")
    with pytest.raises(Exception, match="不完全"):
        emulator.observe_plaintext_stream(
            (command[:-1],),
            sample_sha256=REMCOS_SAMPLE_730,
        )


def test_empty_chunk_iterable_and_aggregate_bytes_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(emulator.RemcosEmulatorError, match="chunk数"):
        emulator.observe_plaintext_stream(itertools.repeat(b""))

    command = frame(0x01, b"0", b"30")
    monkeypatch.setattr(emulator, "MAXIMUM_STREAM_BYTES", len(command))
    with pytest.raises(emulator.RemcosEmulatorError, match="累積byte数"):
        emulator.observe_plaintext_stream(
            (command, b"x"),
            sample_sha256=REMCOS_SAMPLE_730,
        )


def test_cli_chunk_file_count_and_aggregate_bytes_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"aa")
    second.write_bytes(b"bb")

    monkeypatch.setattr(emulator, "MAXIMUM_CLI_CHUNK_FILES", 1)
    with pytest.raises(emulator.RemcosEmulatorError, match="ファイル数"):
        emulator._read_cli_chunks([first, second])

    monkeypatch.setattr(emulator, "MAXIMUM_CLI_CHUNK_FILES", 2)
    monkeypatch.setattr(emulator, "MAXIMUM_CLI_STREAM_BYTES", 3)
    with pytest.raises(emulator.RemcosEmulatorError, match="累積byte数"):
        emulator._read_cli_chunks([first, second])
