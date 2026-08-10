"""防御用RAT emulator transcriptの分離と完全性検証。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from rat_emulator_transcript import (  # noqa: E402
    RatEmulatorTranscriptError,
    SessionTranscriptWriter,
    build_public_summary,
    verify_transcript,
)


def _new_transcript(root: Path) -> Path:
    root.mkdir()
    output = root / "session"
    writer = SessionTranscriptWriter(
        output,
        session_id="fixture-session",
        metadata={"profile_id": "fixture-profile", "sample_executed": False},
    )
    writer.append_event(
        "inbound",
        "handshake",
        raw_frame=b"RAW-HANDSHAKE",
        public_fields={"size": 13, "sha256": "a" * 64},
    )
    writer.append_event(
        "internal",
        "command_classified",
        public_fields={"command": 99, "classification": "unknown"},
        private_fields={"operator_value": "PRIVATE-COMMAND"},
    )
    writer.finalize(status="completed", stop_reason="fixture_complete")
    return output


def test_public_summary_omits_raw_paths_and_private_fields(short_tmp: Path) -> None:
    output = _new_transcript(short_tmp / "private")
    verified = verify_transcript(output)
    summary = build_public_summary(output)
    assert verified["final"]["event_count"] == 2
    assert summary["transcript_root_sha256"] == verified["transcript_root_sha256"]
    encoded = json.dumps(summary, ensure_ascii=False)
    assert "PRIVATE-COMMAND" not in encoded
    assert "raw_frame_file" not in encoded
    assert "private_fields" not in encoded
    assert "RAW-HANDSHAKE" not in encoded
    assert (output / "frames" / "00000001.inbound.bin").read_bytes() == b"RAW-HANDSHAKE"


def test_event_modification_is_detected(short_tmp: Path) -> None:
    output = _new_transcript(short_tmp / "event-tamper")
    event_path = output / "events" / "00000001.json"
    event = json.loads(event_path.read_text(encoding="utf-8"))
    event["public_fields"]["size"] = 999
    event_path.write_text(json.dumps(event), encoding="utf-8")
    with pytest.raises(RatEmulatorTranscriptError, match="hash chain"):
        verify_transcript(output)


def test_raw_modification_and_deletion_are_detected(short_tmp: Path) -> None:
    output = _new_transcript(short_tmp / "raw-tamper")
    (output / "frames" / "00000001.inbound.bin").write_bytes(b"changed")
    with pytest.raises(RatEmulatorTranscriptError, match="raw frame"):
        verify_transcript(output)

    other = _new_transcript(short_tmp / "delete-event")
    (other / "events" / "00000002.json").unlink()
    with pytest.raises(RatEmulatorTranscriptError, match="欠落"):
        verify_transcript(other)


def test_manifest_and_final_state_modification_are_detected(short_tmp: Path) -> None:
    output = _new_transcript(short_tmp / "manifest-tamper")
    manifest_path = output / "session-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metadata"]["profile_id"] = "changed"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(RatEmulatorTranscriptError, match="manifest"):
        verify_transcript(output)

    other = _new_transcript(short_tmp / "final-tamper")
    final_path = other / "final-manifest.json"
    final = json.loads(final_path.read_text(encoding="utf-8"))
    final["status"] = "failed"
    final_path.write_text(json.dumps(final), encoding="utf-8")
    with pytest.raises(RatEmulatorTranscriptError, match="manifest"):
        verify_transcript(other)


def test_extra_file_and_existing_output_are_rejected(short_tmp: Path) -> None:
    output = _new_transcript(short_tmp / "extra")
    (output / "unexpected.txt").write_text("x", encoding="utf-8")
    with pytest.raises(RatEmulatorTranscriptError, match="構成"):
        verify_transcript(output)
    with pytest.raises(FileExistsError, match="上書き"):
        SessionTranscriptWriter(output, session_id="second")


def test_repository_output_and_public_secret_keys_are_rejected(short_tmp: Path) -> None:
    repository = short_tmp / "repository"
    repository.mkdir()
    with pytest.raises(RatEmulatorTranscriptError, match="repository"):
        SessionTranscriptWriter(
            repository / "private-session",
            session_id="fixture",
            repository_root=repository,
        )
    private_parent = short_tmp / "safe"
    private_parent.mkdir()
    with pytest.raises(RatEmulatorTranscriptError, match="非公開情報"):
        SessionTranscriptWriter(
            private_parent / "bad-metadata",
            session_id="fixture",
            metadata={"token": "secret"},
        )
    assert not (private_parent / "bad-metadata").exists()


def test_public_event_rejects_raw_like_fields(short_tmp: Path) -> None:
    parent = short_tmp / "field"
    parent.mkdir()
    writer = SessionTranscriptWriter(parent / "session", session_id="fixture")
    with pytest.raises(RatEmulatorTranscriptError, match="非公開情報"):
        writer.append_event(
            "internal",
            "bad",
            public_fields={"payload": "must-not-be-public"},
        )
