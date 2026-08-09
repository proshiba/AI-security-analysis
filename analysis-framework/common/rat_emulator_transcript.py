#!/usr/bin/env python3
"""防御用RATエミュレーターの非公開通信記録と公開要約を管理する。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from immutable_snapshot import decode_strict_json, read_bounded_snapshot, write_new_json
from safe_private_output import reject_existing_reparse_components, write_private_output

SCHEMA_VERSION = 1
ZERO_HASH = "0" * 64
MAXIMUM_EVENT_COUNT = 10_000
MAXIMUM_JSON_BYTES = 1024 * 1024
MAXIMUM_RAW_FRAME_BYTES = 1024 * 1024
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "body",
        "bytes",
        "command_line",
        "content",
        "credential",
        "data",
        "password",
        "payload",
        "private_fields",
        "raw",
        "raw_frame_file",
        "raw_hex",
        "secret",
        "token",
    }
)
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class RatEmulatorTranscriptError(ValueError):
    """通信記録が安全境界または完全性条件を満たさない。"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath(
            [os.path.normcase(str(_absolute(path))), os.path.normcase(str(_absolute(root)))]
        ) == os.path.normcase(str(_absolute(root)))
    except ValueError:
        return False


def _checked_directory(path: Path) -> None:
    reject_existing_reparse_components(path)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RatEmulatorTranscriptError(f"通常directoryではありません: {path}")


def _json_object(value: Mapping[str, Any] | None, label: str) -> dict[str, Any]:
    result = dict(value or {})
    try:
        json.dumps(result, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RatEmulatorTranscriptError(f"{label}は有限値だけのJSON objectにしてください") from exc
    return result


def _validate_public_value(value: Any, path: str = "public_fields") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise RatEmulatorTranscriptError(f"{path}のkeyは文字列にしてください")
            if key.casefold() in FORBIDDEN_PUBLIC_KEYS:
                raise RatEmulatorTranscriptError(f"非公開情報を公開欄へ記録できません: {path}.{key}")
            _validate_public_value(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_public_value(item, f"{path}[{index}]")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raise RatEmulatorTranscriptError(f"raw bytesを公開欄へ記録できません: {path}")


def _canonical_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _document_sha256(document: object) -> str:
    return hashlib.sha256(_canonical_bytes(document)).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = decode_strict_json(read_bounded_snapshot(path, MAXIMUM_JSON_BYTES).data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulatorTranscriptError(f"通信記録JSONを安全に読めません: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RatEmulatorTranscriptError(f"通信記録JSONはobjectである必要があります: {path}")
    return value


class SessionTranscriptWriter:
    """新規の非公開directoryへ追記専用の通信記録を作成する。"""

    def __init__(
        self,
        directory: Path,
        *,
        session_id: str,
        metadata: Mapping[str, Any] | None = None,
        repository_root: Path | None = None,
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        if not directory.is_absolute():
            raise RatEmulatorTranscriptError("非公開通信記録directoryは絶対pathで指定してください")
        if SESSION_ID_RE.fullmatch(session_id) is None:
            raise RatEmulatorTranscriptError("session_idが不正です")
        public_metadata = _json_object(metadata, "metadata")
        _validate_public_value(public_metadata, "metadata")
        target = _absolute(directory)
        if repository_root is not None and _is_within(target, _absolute(repository_root)):
            raise RatEmulatorTranscriptError("raw通信記録をrepository配下へ保存できません")
        if target.exists() or target.is_symlink():
            raise FileExistsError(f"既存の通信記録directoryは上書きしません: {target}")
        _checked_directory(target.parent)
        target.mkdir()
        _checked_directory(target)
        self.directory = target
        self.events_directory = target / "events"
        self.frames_directory = target / "frames"
        self.events_directory.mkdir()
        self.frames_directory.mkdir()
        _checked_directory(self.events_directory)
        _checked_directory(self.frames_directory)
        self.session_id = session_id
        self._clock = clock
        self._sequence = 0
        self._previous_hash = ZERO_HASH
        self._finalized = False
        self.manifest = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "defensive_rat_emulator_private_transcript",
            "session_id": session_id,
            "started_at": clock(),
            "chain_algorithm": "sha256-canonical-json-v1",
            "initial_event_sha256": ZERO_HASH,
            "metadata": public_metadata,
        }
        write_new_json(target / "session-manifest.json", self.manifest)
        self._manifest_sha256 = read_bounded_snapshot(
            target / "session-manifest.json", MAXIMUM_JSON_BYTES
        ).identity.sha256

    def append_event(
        self,
        direction: str,
        event_type: str,
        *,
        raw_frame: bytes | bytearray | memoryview | None = None,
        public_fields: Mapping[str, Any] | None = None,
        private_fields: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """1件を排他作成し、raw frameは非公開framesだけへ保存する。"""

        if self._finalized:
            raise RatEmulatorTranscriptError("finalize済み通信記録へ追記できません")
        if direction not in {"inbound", "outbound", "internal"}:
            raise RatEmulatorTranscriptError("directionが不正です")
        if not isinstance(event_type, str) or not event_type or len(event_type) > 128:
            raise RatEmulatorTranscriptError("event_typeが不正です")
        if self._sequence >= MAXIMUM_EVENT_COUNT:
            raise RatEmulatorTranscriptError("通信記録event上限を超えました")
        public = _json_object(public_fields, "public_fields")
        private = _json_object(private_fields, "private_fields")
        _validate_public_value(public)
        self._sequence += 1
        name = f"{self._sequence:08d}"
        frame_summary: dict[str, Any] | None = None
        raw_reference: str | None = None
        if raw_frame is not None:
            if not isinstance(raw_frame, (bytes, bytearray, memoryview)):
                raise RatEmulatorTranscriptError("raw_frameはbytesで指定してください")
            frame = bytes(raw_frame)
            if len(frame) > MAXIMUM_RAW_FRAME_BYTES:
                raise RatEmulatorTranscriptError("raw frame上限を超えました")
            digest = hashlib.sha256(frame).hexdigest()
            frame_path = self.frames_directory / f"{name}.{direction}.bin"
            write_private_output(frame_path, frame, digest, allowed_root=self.frames_directory)
            frame_summary = {"size": len(frame), "sha256": digest}
            raw_reference = f"frames/{frame_path.name}"
        event_without_hash = {
            "schema_version": SCHEMA_VERSION,
            "sequence": self._sequence,
            "captured_at": self._clock(),
            "direction": direction,
            "event_type": event_type,
            "frame": frame_summary,
            "public_fields": public,
            "private_fields": private,
            "raw_frame_file": raw_reference,
            "previous_event_sha256": self._previous_hash,
        }
        event = dict(event_without_hash)
        event["event_sha256"] = _document_sha256(event_without_hash)
        write_new_json(self.events_directory / f"{name}.json", event)
        self._previous_hash = str(event["event_sha256"])
        return dict(event)

    def finalize(self, *, status: str, stop_reason: str) -> dict[str, Any]:
        """最終hashを固定し、以降の追記を停止する。"""

        if self._finalized:
            raise RatEmulatorTranscriptError("通信記録は既にfinalize済みです")
        if status not in {"completed", "aborted", "failed"}:
            raise RatEmulatorTranscriptError("statusが不正です")
        if not isinstance(stop_reason, str) or not stop_reason or len(stop_reason) > 512:
            raise RatEmulatorTranscriptError("stop_reasonが不正です")
        final_without_root = {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "defensive_rat_emulator_private_transcript_final",
            "session_id": self.session_id,
            "completed_at": self._clock(),
            "status": status,
            "stop_reason": stop_reason,
            "event_count": self._sequence,
            "last_event_sha256": self._previous_hash,
            "session_manifest_sha256": self._manifest_sha256,
        }
        final = dict(final_without_root)
        final["transcript_root_sha256"] = _document_sha256(final_without_root)
        write_new_json(self.directory / "final-manifest.json", final)
        self._finalized = True
        return dict(final)


def verify_transcript(directory: Path) -> dict[str, Any]:
    """event順序、hash chain、raw frame、最終manifestの完全性を検証する。"""

    root = _absolute(directory)
    _checked_directory(root)
    expected_entries = {"events", "frames", "session-manifest.json", "final-manifest.json"}
    if {item.name for item in root.iterdir()} != expected_entries:
        raise RatEmulatorTranscriptError("通信記録rootの構成が不正です")
    _checked_directory(root / "events")
    _checked_directory(root / "frames")
    manifest_path = root / "session-manifest.json"
    final_path = root / "final-manifest.json"
    manifest = _read_json(manifest_path)
    final = _read_json(final_path)
    claimed_root = final.pop("transcript_root_sha256", None)
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("artifact_type") != "defensive_rat_emulator_private_transcript"
        or manifest.get("chain_algorithm") != "sha256-canonical-json-v1"
        or manifest.get("initial_event_sha256") != ZERO_HASH
        or final.get("schema_version") != SCHEMA_VERSION
        or final.get("artifact_type") != "defensive_rat_emulator_private_transcript_final"
        or final.get("session_id") != manifest.get("session_id")
        or final.get("session_manifest_sha256")
        != read_bounded_snapshot(manifest_path, MAXIMUM_JSON_BYTES).identity.sha256
        or claimed_root != _document_sha256(final)
    ):
        raise RatEmulatorTranscriptError("通信記録manifestのbindingが不正です")
    event_count = final.get("event_count")
    if type(event_count) is not int or not 0 <= event_count <= MAXIMUM_EVENT_COUNT:
        raise RatEmulatorTranscriptError("event_countが不正です")
    event_paths = sorted((root / "events").iterdir(), key=lambda item: item.name)
    if [item.name for item in event_paths] != [f"{index:08d}.json" for index in range(1, event_count + 1)]:
        raise RatEmulatorTranscriptError("event fileの欠落、追加、順序変更を検知しました")
    previous = ZERO_HASH
    expected_frames: set[str] = set()
    for sequence, event_path in enumerate(event_paths, start=1):
        event = _read_json(event_path)
        claimed_hash = event.pop("event_sha256", None)
        if (
            event.get("schema_version") != SCHEMA_VERSION
            or event.get("sequence") != sequence
            or event.get("previous_event_sha256") != previous
            or claimed_hash != _document_sha256(event)
        ):
            raise RatEmulatorTranscriptError(f"event hash chainが不正です: {event_path.name}")
        frame = event.get("frame")
        reference = event.get("raw_frame_file")
        if frame is None and reference is None:
            pass
        elif isinstance(frame, dict) and reference == f"frames/{sequence:08d}.{event.get('direction')}.bin":
            frame_path = root / reference
            snapshot = read_bounded_snapshot(frame_path, MAXIMUM_RAW_FRAME_BYTES)
            if frame != {"size": snapshot.identity.size, "sha256": snapshot.identity.sha256}:
                raise RatEmulatorTranscriptError(f"raw frameのsize/hashが不正です: {reference}")
            expected_frames.add(frame_path.name)
        else:
            raise RatEmulatorTranscriptError(f"raw frame参照が不正です: {event_path.name}")
        previous = str(claimed_hash)
    observed_frames = {item.name for item in (root / "frames").iterdir()}
    if observed_frames != expected_frames:
        raise RatEmulatorTranscriptError("raw frame fileの欠落または追加を検知しました")
    if final.get("last_event_sha256") != previous:
        raise RatEmulatorTranscriptError("最終event hashが一致しません")
    final["transcript_root_sha256"] = claimed_root
    return {
        "manifest": manifest,
        "final": final,
        "last_event_sha256": previous,
        "transcript_root_sha256": claimed_root,
    }


def build_public_summary(directory: Path) -> dict[str, Any]:
    """検証済み記録からraw pathとprivate fieldを除いた公開要約を作る。"""

    verified = verify_transcript(directory)
    root = _absolute(directory)
    events: list[dict[str, Any]] = []
    for event_path in sorted((root / "events").iterdir(), key=lambda item: item.name):
        event = _read_json(event_path)
        events.append(
            {
                "sequence": event["sequence"],
                "captured_at": event["captured_at"],
                "direction": event["direction"],
                "event_type": event["event_type"],
                "frame": event["frame"],
                "public_fields": event["public_fields"],
                "event_sha256": event["event_sha256"],
            }
        )
    final = verified["final"]
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "defensive_rat_emulator_public_summary",
        "session_id": verified["manifest"]["session_id"],
        "started_at": verified["manifest"]["started_at"],
        "completed_at": final["completed_at"],
        "status": final["status"],
        "stop_reason": final["stop_reason"],
        "metadata": verified["manifest"]["metadata"],
        "event_count": final["event_count"],
        "transcript_root_sha256": verified["transcript_root_sha256"],
        "events": events,
    }


__all__ = [
    "RatEmulatorTranscriptError",
    "SessionTranscriptWriter",
    "build_public_summary",
    "verify_transcript",
]
