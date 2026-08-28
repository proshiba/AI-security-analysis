#!/usr/bin/env python3
"""offline／loopback spoolを長期間監視する防御用command observatory。"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import random
import re
import socket
import stat
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, is_dataclass
from dataclasses import fields as dataclass_fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

import rat_command_observer as rat_observer
from immutable_snapshot import decode_strict_json, read_bounded_snapshot
from rat_command_observer import (
    PROFILES,
    RatCommandObserverError,
    decode_spool_message,
    observe_command,
)
from safe_artifact_io import stable_file_identity, unlink_created_file_if_unchanged
from safe_private_output import reject_existing_reparse_components, write_private_output

SCHEMA_VERSION = 1
ZERO_HASH = "0" * 64
MAXIMUM_SPOOL_BYTES = 2 * 1024 * 1024
MAXIMUM_LEDGER_EVENT_BYTES = 2 * 1024 * 1024
MAXIMUM_MANIFEST_BYTES = 256 * 1024
MAXIMUM_RECEIPT_BYTES = 64 * 1024
MAXIMUM_CHECKPOINT_BYTES = 64 * 1024
KILL_SWITCH_POLL_SECONDS = 1.0
FULL_STORAGE_RECONCILIATION_CYCLES = 256
CAPTURED_AT_RE = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
SEGMENT_RE = re.compile(r"^segment-([0-9]{6,9})$")
EVENT_RE = re.compile(r"^([0-9]{12})\.json$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
MODULE_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class LongRunningObserverError(ValueError):
    """observatory layout、ledger、claim、またはspool itemが不正である。"""


class ObserverCapacityReached(LongRunningObserverError):
    """event数またはrepository外private storageがreview済み上限へ到達した。"""

    def __init__(self, reason: str) -> None:
        if reason not in {"event_capacity_reached", "storage_capacity_reached"}:
            raise ValueError("capacity停止理由が不正です")
        self.reason = reason
        super().__init__(reason)


class LedgerCommitError(LongRunningObserverError):
    """event／checkpoint commitが不整合になりledgerを継続利用できない。"""


@dataclass(frozen=True)
class SupervisorPolicy:
    """長期運用を小さなbounded cycleへ分割する固定上限。"""

    rotation_event_count: int = 1000
    rotation_bytes: int = 16 * 1024 * 1024
    maximum_files_per_cycle: int = 64
    maximum_ledger_events: int = 1_000_000
    maximum_storage_bytes: int = 4 * 1024 * 1024 * 1024
    poll_interval_seconds: float = 5.0
    initial_backoff_seconds: float = 1.0
    maximum_backoff_seconds: float = 60.0
    backoff_jitter_fraction: float = 0.2
    circuit_breaker_failures: int = 8
    circuit_breaker_cooldown_seconds: float = 300.0
    maximum_process_runtime_seconds: float = 24 * 60 * 60

    def __post_init__(self) -> None:
        integer_limits = {
            "rotation_event_count": (1, 10_000),
            "rotation_bytes": (1024 * 1024, 1024 * 1024 * 1024),
            "maximum_files_per_cycle": (1, 1024),
            "maximum_ledger_events": (1, 100_000_000),
            "maximum_storage_bytes": (1024 * 1024, 1024 * 1024 * 1024 * 1024),
            "circuit_breaker_failures": (1, 100),
        }
        for name, (minimum, maximum) in integer_limits.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise LongRunningObserverError(f"{name}が安全範囲外です")
        numeric_limits = {
            "poll_interval_seconds": (0.1, 60.0),
            "initial_backoff_seconds": (0.1, 60.0),
            "maximum_backoff_seconds": (0.1, 3600.0),
            "backoff_jitter_fraction": (0.0, 0.5),
            "circuit_breaker_cooldown_seconds": (1.0, 24 * 60 * 60.0),
            "maximum_process_runtime_seconds": (1.0, 24 * 60 * 60.0),
        }
        for name, (minimum, maximum) in numeric_limits.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise LongRunningObserverError(f"{name}は数値で指定してください")
            if not minimum <= float(value) <= maximum:
                raise LongRunningObserverError(f"{name}が安全範囲外です")
        if self.maximum_backoff_seconds < self.initial_backoff_seconds:
            raise LongRunningObserverError("maximum backoffはinitial backoff以上にしてください")

    def public_dict(self) -> dict[str, int | float]:
        return {
            "rotation_event_count": self.rotation_event_count,
            "rotation_bytes": self.rotation_bytes,
            "maximum_files_per_cycle": self.maximum_files_per_cycle,
            "maximum_ledger_events": self.maximum_ledger_events,
            "maximum_storage_bytes": self.maximum_storage_bytes,
            "poll_interval_seconds": self.poll_interval_seconds,
            "initial_backoff_seconds": self.initial_backoff_seconds,
            "maximum_backoff_seconds": self.maximum_backoff_seconds,
            "backoff_jitter_fraction": self.backoff_jitter_fraction,
            "circuit_breaker_failures": self.circuit_breaker_failures,
            "circuit_breaker_cooldown_seconds": self.circuit_breaker_cooldown_seconds,
            "maximum_process_runtime_seconds": self.maximum_process_runtime_seconds,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SupervisorPolicy:
        expected = set(cls().__dict__)
        if set(value) != expected:
            raise LongRunningObserverError("supervisor policyのkey集合が不一致です")
        return cls(**dict(value))


@dataclass
class LedgerState:
    """event ledgerから再構築できる非永続状態。"""

    event_count: int = 0
    last_event_sha256: str = ZERO_HASH
    active_segment: int = 1
    active_segment_events: int = 0
    active_segment_bytes: int = 0
    source_sha256s: set[str] = field(default_factory=set)
    first_sequence_by_command: dict[str, int] = field(default_factory=dict)
    sightings_by_command: dict[str, int] = field(default_factory=dict)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _document_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_registry_value(value: Any) -> Any:
    """profile dataclassとtaxonomy値を型差を失わずcanonical JSONへ写像する。"""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, type) and value.__module__ == "builtins" and value.__qualname__ in {"bool", "list"}:
        return {"builtin_type": value.__qualname__}
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _canonical_registry_value(getattr(value, item.name)) for item in dataclass_fields(value)}
    if isinstance(value, Mapping):
        pairs = [
            {
                "key": _canonical_registry_value(key),
                "value": _canonical_registry_value(item),
            }
            for key, item in value.items()
        ]
        return sorted(pairs, key=_canonical_bytes)
    if isinstance(value, (set, frozenset)):
        return sorted(
            (_canonical_registry_value(item) for item in value),
            key=_canonical_bytes,
        )
    if isinstance(value, (list, tuple)):
        return [_canonical_registry_value(item) for item in value]
    if isinstance(value, re.Pattern):
        return {"pattern": value.pattern, "flags": value.flags}
    raise LongRunningObserverError(f"profile registryにcanonical化できない型があります: {type(value).__name__}")


def _profile_registry_document() -> dict[str, Any]:
    taxonomy_names = (
        "VENOM_TAXONOMY",
        "STEALC_CONFIG_FIELD_TYPES",
        "STEALC_CONFIG_FIELDS",
        "STEALC_STATUS_FIELDS",
        "STEALC_DYNAMIC_HEX_RE",
        "STEALC_TOKEN_RE",
        "STEALC_UUID_RE",
        "REMCOS_COMMANDS",
        "QUASAR_TAXONOMY",
    )
    return {
        "schema_version": int(rat_observer.SCHEMA_VERSION),
        "profiles": [_canonical_registry_value(PROFILES[profile_id]) for profile_id in sorted(PROFILES)],
        "taxonomies": {name: _canonical_registry_value(getattr(rat_observer, name)) for name in taxonomy_names},
    }


def _profile_registry_sha256() -> str:
    return _document_sha256(_profile_registry_document())


def _validated_repository_root(repository_root: Path) -> Path:
    if not repository_root.is_absolute():
        raise LongRunningObserverError("repository rootは絶対pathで指定してください")
    try:
        supplied = repository_root.resolve(strict=True)
    except OSError as exc:
        raise LongRunningObserverError("repository rootを解決できません") from exc
    actual = MODULE_REPOSITORY_ROOT.resolve(strict=True)
    if os.path.normcase(str(supplied)) != os.path.normcase(str(actual)):
        raise LongRunningObserverError("repository rootは実行module由来のrepositoryと一致する必要があります")
    return actual


def _git_worktree_ancestor(path: Path) -> Path | None:
    current = path if path.exists() and path.is_dir() else path.parent
    for candidate in (current, *current.parents):
        if os.path.lexists(candidate / ".git"):
            return candidate
    return None


def _reject_git_worktree_path(path: Path) -> None:
    worktree = _git_worktree_ancestor(path)
    if worktree is not None:
        raise LongRunningObserverError(f"observatoryをgit worktree配下へ作成・実行できません: {worktree}")


def _head_checkpoint_document(
    *,
    event_count: int,
    ledger_head_sha256: str,
    profile_registry_sha256: str,
    updated_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "defensive_observatory_local_ledger_head_checkpoint",
        "event_count": event_count,
        "ledger_head_sha256": ledger_head_sha256,
        "profile_registry_sha256": profile_registry_sha256,
        "updated_at": updated_at,
        "tail_detection": "local_durable_head_checkpoint_v1",
        "external_anchor_present": False,
        "coordinated_checkpoint_rollback_detectable": False,
    }


def _command_fingerprint(
    public_event: Mapping[str, Any],
    sample_sha256: str | None,
) -> str:
    fields = {
        name: public_event.get(name)
        for name in (
            "profile_id",
            "family",
            "direction",
            "category",
            "normalized_command",
            "message_sha256",
        )
    }
    if not all(isinstance(value, str) and value for value in fields.values()):
        raise LongRunningObserverError("command fingerprint fieldが不正です")
    message_sha256 = str(fields["message_sha256"])
    if re.fullmatch(r"[0-9a-f]{64}", message_sha256) is None:
        raise LongRunningObserverError("command message SHA-256が不正です")
    if sample_sha256 is not None and re.fullmatch(r"[0-9a-f]{64}", sample_sha256) is None:
        raise LongRunningObserverError("command sample SHA-256が不正です")
    return _document_sha256(
        {
            **fields,
            "sample_sha256": sample_sha256,
        }
    )


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
        raise LongRunningObserverError(f"通常directoryではありません: {path}")


def _regular_tree_bytes(root: Path, *, stop_after: int | None = None) -> int:
    """reparse pointを辿らず、observatory内の通常file sizeだけを集計する。"""

    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        _checked_directory(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                metadata = entry.stat(follow_symlinks=False)
                attributes = int(getattr(metadata, "st_file_attributes", 0))
                if entry.is_symlink() or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                    raise LongRunningObserverError(f"storage集計中にreparse pointを検出しました: {entry.path}")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(Path(entry.path))
                elif stat.S_ISREG(metadata.st_mode):
                    entry_path = Path(entry.path)
                    at_path = entry_path.lstat()
                    path_attributes = int(getattr(at_path, "st_file_attributes", 0))
                    if (
                        not stat.S_ISREG(at_path.st_mode)
                        or stat.S_ISLNK(at_path.st_mode)
                        or path_attributes & FILE_ATTRIBUTE_REPARSE_POINT
                        or int(getattr(at_path, "st_nlink", 1)) != 1
                    ):
                        raise LongRunningObserverError(
                            f"storage\u96c6\u8a08\u4e2d\u3067hardlink\u307e\u305f\u306freparse point\u3092\u691c\u51fa\u3057\u307e\u3057\u305f: {entry.path}"
                        )
                    after_path = entry_path.lstat()
                    if (
                        stable_file_identity(at_path) != stable_file_identity(after_path)
                        or at_path.st_size != after_path.st_size
                        or int(getattr(after_path, "st_nlink", 1)) != 1
                    ):
                        raise LongRunningObserverError(
                            f"storage\u96c6\u8a08\u4e2d\u3067file\u7f6e\u63db\u3092\u691c\u51fa\u3057\u307e\u3057\u305f: {entry.path}"
                        )
                    total += at_path.st_size
                else:
                    raise LongRunningObserverError(f"storage集計中に通常file以外を検出しました: {entry.path}")
                if stop_after is not None and total > stop_after:
                    return total
    return total


def _read_json(path: Path, maximum: int) -> tuple[dict[str, Any], Any]:
    try:
        snapshot = read_bounded_snapshot(path, maximum)
        value = decode_strict_json(snapshot.data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise LongRunningObserverError(f"JSON snapshotを安全に読めません: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LongRunningObserverError(f"JSON rootはobjectである必要があります: {path}")
    return value, snapshot


def _serialized_private_json(value: object, *, maximum: int) -> bytes:
    raw = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        ).encode("utf-8")
        + b"\n"
    )
    if len(raw) > maximum:
        raise LongRunningObserverError("private JSONが許可上限を超えています")
    return raw


def _write_new_private_json(
    path: Path,
    value: object,
    *,
    allowed_root: Path,
    maximum: int = MAXIMUM_LEDGER_EVENT_BYTES,
) -> str:
    raw = _serialized_private_json(value, maximum=maximum)
    digest = hashlib.sha256(raw).hexdigest()
    return write_private_output(path, raw, digest, allowed_root=allowed_root)


def _fsync_directory(path: Path) -> None:
    """POSIXではrename後のdirectory entryもdurableにする。Windowsはreplaceに委ねる。"""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_private_json(
    path: Path,
    value: object,
    *,
    allowed_root: Path,
    maximum: int,
) -> int:
    """既存private JSONを同一directory内temporaryからatomic replaceしsize差を返す。"""

    _, before = _read_json(path, maximum)
    raw = _serialized_private_json(value, maximum=maximum)
    digest = hashlib.sha256(raw).hexdigest()
    temporary = path.with_name(f".{path.name}.replace-{uuid.uuid4().hex}.tmp")
    metadata: os.stat_result | None = None
    try:
        write_private_output(
            temporary,
            raw,
            digest,
            allowed_root=allowed_root,
        )
        metadata = temporary.lstat()
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        committed = read_bounded_snapshot(path, maximum)
        if committed.identity.sha256 != digest:
            raise LedgerCommitError("checkpoint atomic replace後のhashが一致しません")
        return int(committed.identity.size) - int(before.identity.size)
    except BaseException:
        if metadata is not None:
            unlink_created_file_if_unchanged(temporary, metadata)
        raise


def initialize_observatory(
    root: Path,
    *,
    repository_root: Path,
    policy: SupervisorPolicy | None = None,
    retain_private_fields: bool = False,
) -> dict[str, Any]:
    """repository外の新規rootへobservatory layoutを排他作成する。"""

    target = _absolute(root)
    if not root.is_absolute():
        raise LongRunningObserverError("observatory rootは絶対pathで指定してください")
    repository = _validated_repository_root(repository_root)
    if _is_within(target, repository):
        raise LongRunningObserverError("command observatoryをrepository配下へ作成できません")
    _reject_git_worktree_path(target)
    reject_existing_reparse_components(target)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"observatory rootは新規pathにしてください: {target}")
    _checked_directory(target.parent)
    target.mkdir()
    _checked_directory(target)
    for name in ("incoming", "processed", "rejected", "ledger"):
        (target / name).mkdir()
        _checked_directory(target / name)
    active = policy or SupervisorPolicy()
    created_at = _utc_now()
    registry_sha256 = _profile_registry_sha256()
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "defensive_long_running_command_observatory",
        "created_at": created_at,
        "network_scope": "offline_or_loopback_only",
        "external_c2_connections_allowed": False,
        "command_execution_allowed": False,
        "command_response_allowed": False,
        "payload_download_allowed": False,
        "automatic_stale_claim_recovery": False,
        "retain_private_fields": bool(retain_private_fields),
        "profiles": sorted(PROFILES),
        "profile_registry_sha256": registry_sha256,
        "policy": active.public_dict(),
        "chain_algorithm": "sha256-canonical-json-v1",
        "initial_event_sha256": ZERO_HASH,
        "tail_detection": "local_durable_head_checkpoint_v1",
        "external_anchor_present": False,
        "coordinated_checkpoint_rollback_detectable": False,
    }
    _write_new_private_json(
        target / "manifest.json",
        manifest,
        allowed_root=target,
        maximum=MAXIMUM_MANIFEST_BYTES,
    )
    _write_new_private_json(
        target / "ledger-head.json",
        _head_checkpoint_document(
            event_count=0,
            ledger_head_sha256=ZERO_HASH,
            profile_registry_sha256=registry_sha256,
            updated_at=created_at,
        ),
        allowed_root=target,
        maximum=MAXIMUM_CHECKPOINT_BYTES,
    )
    return manifest


class ExclusiveClaim:
    """同じobservatoryを複数processが処理しないための排他claim。"""

    def __init__(self, root: Path, *, clock: Callable[[], str] = _utc_now) -> None:
        self.root = root
        self.path = root / "supervisor.claim"
        self.clock = clock
        self.token = uuid.uuid4().hex
        self._created_metadata: os.stat_result | None = None

    def __enter__(self) -> Self:
        claim = {
            "schema_version": SCHEMA_VERSION,
            "token": self.token,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "claimed_at": self.clock(),
        }
        raw = _canonical_bytes(claim) + b"\n"
        try:
            with self.path.open("xb", buffering=0) as handle:
                self._created_metadata = os.fstat(handle.fileno())
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as exc:
            raise LongRunningObserverError("別processのsupervisor claimが存在します") from exc
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._created_metadata is None:
            return
        try:
            claim, _ = _read_json(self.path, MAXIMUM_MANIFEST_BYTES)
        except LongRunningObserverError:
            return
        if claim.get("token") == self.token:
            unlink_created_file_if_unchanged(self.path, self._created_metadata)


class ObservationLedger:
    """append-only event、global hash chain、local durable headを管理する。"""

    def __init__(
        self,
        root: Path,
        *,
        policy: SupervisorPolicy,
        retain_private_fields: bool,
        clock: Callable[[], str] = _utc_now,
        storage_delta: Callable[[int], None] | None = None,
    ) -> None:
        self.root = root
        self.checkpoint_path = root.parent / "ledger-head.json"
        self.policy = policy
        self.retain_private_fields = retain_private_fields
        self.clock = clock
        self.profile_registry_sha256 = _profile_registry_sha256()
        self._storage_delta = storage_delta or (lambda _delta: None)
        self._poisoned = False
        self.state = self.verify()

    def require_healthy(self) -> None:
        if self._poisoned:
            raise LedgerCommitError("ledger commit失敗後はprocessを再起動しcheckpointを再検証してください")

    def _segment_path(self, number: int) -> Path:
        if not 1 <= number <= self.policy.maximum_ledger_events:
            raise LongRunningObserverError("ledger segment番号がpolicy範囲外です")
        return self.root / f"segment-{number:06d}"

    def _event_paths(self) -> list[Path]:
        paths: list[Path] = []
        segment_numbers: list[int] = []
        for item in self.root.iterdir():
            match = SEGMENT_RE.fullmatch(item.name)
            if match is None:
                raise LongRunningObserverError(f"ledgerに未定義entryがあります: {item.name}")
            number = int(match.group(1))
            if item.name != f"segment-{number:06d}":
                raise LongRunningObserverError(f"ledger segment名がcanonicalではありません: {item.name}")
            _checked_directory(item)
            segment_numbers.append(number)
        if segment_numbers and sorted(segment_numbers) != list(range(1, max(segment_numbers) + 1)):
            raise LongRunningObserverError("ledger segment番号に欠落があります")
        for number in sorted(segment_numbers):
            segment = self._segment_path(number)
            segment_paths = sorted(segment.iterdir(), key=lambda value: value.name)
            for event_path in segment_paths:
                if EVENT_RE.fullmatch(event_path.name) is None:
                    raise LongRunningObserverError(f"segmentに未定義entryがあります: {event_path.name}")
                paths.append(event_path)
        return paths

    def _verify_checkpoint(self, state: LedgerState) -> None:
        checkpoint, _ = _read_json(self.checkpoint_path, MAXIMUM_CHECKPOINT_BYTES)
        expected_keys = {
            "schema_version",
            "artifact_type",
            "event_count",
            "ledger_head_sha256",
            "profile_registry_sha256",
            "updated_at",
            "tail_detection",
            "external_anchor_present",
            "coordinated_checkpoint_rollback_detectable",
        }
        updated_at = checkpoint.get("updated_at")
        if (
            set(checkpoint) != expected_keys
            or checkpoint.get("schema_version") != SCHEMA_VERSION
            or checkpoint.get("artifact_type") != "defensive_observatory_local_ledger_head_checkpoint"
            or checkpoint.get("event_count") != state.event_count
            or checkpoint.get("ledger_head_sha256") != state.last_event_sha256
            or checkpoint.get("profile_registry_sha256") != self.profile_registry_sha256
            or not isinstance(updated_at, str)
            or CAPTURED_AT_RE.fullmatch(updated_at) is None
            or checkpoint.get("tail_detection") != "local_durable_head_checkpoint_v1"
            or checkpoint.get("external_anchor_present") is not False
            or checkpoint.get("coordinated_checkpoint_rollback_detectable") is not False
        ):
            raise LedgerCommitError("local durable head checkpointとledger headが一致しません")

    def _verify_with_events(
        self,
        *,
        collect_events: bool,
    ) -> tuple[LedgerState, list[dict[str, Any]]]:
        state = LedgerState()
        verified_events: list[dict[str, Any]] = []
        expected_sequence = 1
        active_segment = 1
        active_events = 0
        active_bytes = 0
        previous = ZERO_HASH
        for path in self._event_paths():
            event, snapshot = _read_json(path, MAXIMUM_LEDGER_EVENT_BYTES)
            segment_match = SEGMENT_RE.fullmatch(path.parent.name)
            if segment_match is None:
                raise LongRunningObserverError("event segment名が不正です")
            segment_number = int(segment_match.group(1))
            if segment_number != active_segment:
                active_segment = segment_number
                active_events = 0
                active_bytes = 0
            claimed = event.pop("event_sha256", None)
            if (
                event.get("schema_version") != SCHEMA_VERSION
                or event.get("sequence") != expected_sequence
                or path.name != f"{expected_sequence:012d}.json"
                or event.get("previous_event_sha256") != previous
                or claimed != _document_sha256(event)
            ):
                raise LongRunningObserverError(f"ledger event chainが不正です: {path}")
            source = event.get("source_artifact")
            command = event.get("command_deduplication")
            public_event = event.get("public_event")
            sample_sha256 = event.get("sample_sha256")
            if (
                not isinstance(source, dict)
                or not isinstance(command, dict)
                or not isinstance(public_event, dict)
                or (sample_sha256 is not None and not isinstance(sample_sha256, str))
            ):
                raise LongRunningObserverError("ledger event metadataが不正です")
            source_sha256 = source.get("sha256")
            fingerprint = command.get("fingerprint")
            expected_fingerprint = _command_fingerprint(public_event, sample_sha256)
            if (
                not isinstance(source_sha256, str)
                or SHA256_RE.fullmatch(source_sha256) is None
                or not isinstance(fingerprint, str)
                or fingerprint != expected_fingerprint
            ):
                raise LongRunningObserverError("ledger fingerprintが不正です")
            state.source_sha256s.add(source_sha256)
            state.first_sequence_by_command.setdefault(fingerprint, expected_sequence)
            state.sightings_by_command[fingerprint] = state.sightings_by_command.get(fingerprint, 0) + 1
            if command.get("first_seen_sequence") != state.first_sequence_by_command[fingerprint]:
                raise LongRunningObserverError("command first-seen bindingが不正です")
            if command.get("sighting_index") != state.sightings_by_command[fingerprint]:
                raise LongRunningObserverError("command sighting indexが不正です")
            if collect_events:
                verified_events.append(dict(event))
            previous = str(claimed)
            expected_sequence += 1
            active_events += 1
            active_bytes += int(snapshot.identity.size)
        state.event_count = expected_sequence - 1
        state.last_event_sha256 = previous
        state.active_segment = active_segment
        state.active_segment_events = active_events
        state.active_segment_bytes = active_bytes
        self._verify_checkpoint(state)
        return state, verified_events

    def verify(self) -> LedgerState:
        """全eventとlocal durable headを同じsnapshot境界で検証する。"""

        return self._verify_with_events(collect_events=False)[0]

    def verified_events(self) -> tuple[LedgerState, list[dict[str, Any]]]:
        """public summary用に検証済みevent documentを再読込なしで返す。"""

        return self._verify_with_events(collect_events=True)

    def _commit_checkpoint(self, *, event_count: int, ledger_head_sha256: str) -> None:
        delta = _replace_private_json(
            self.checkpoint_path,
            _head_checkpoint_document(
                event_count=event_count,
                ledger_head_sha256=ledger_head_sha256,
                profile_registry_sha256=self.profile_registry_sha256,
                updated_at=self.clock(),
            ),
            allowed_root=self.root.parent,
            maximum=MAXIMUM_CHECKPOINT_BYTES,
        )
        self._storage_delta(delta)

    def append(
        self,
        *,
        source_artifact: Mapping[str, Any],
        source_scope: str,
        captured_at: str,
        sample_sha256: str | None,
        public_event: Mapping[str, Any],
        private_fields: Mapping[str, Any],
    ) -> dict[str, Any]:
        """eventを先にdurable化し、次にlocal headをatomic commitする。"""

        self.require_healthy()
        self._verify_checkpoint(self.state)
        fingerprint = _command_fingerprint(public_event, sample_sha256)
        source_sha256 = str(source_artifact.get("sha256") or "")
        if SHA256_RE.fullmatch(source_sha256) is None:
            raise LongRunningObserverError("source artifact SHA-256が不正です")
        sequence = self.state.event_count + 1
        first_seen = self.state.first_sequence_by_command.get(fingerprint, sequence)
        sighting_index = self.state.sightings_by_command.get(fingerprint, 0) + 1
        event_without_hash = {
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
            "recorded_at": self.clock(),
            "captured_at": captured_at,
            "source_scope": source_scope,
            "sample_sha256": sample_sha256,
            "source_artifact": dict(source_artifact),
            "public_event": dict(public_event),
            "private_fields": dict(private_fields) if self.retain_private_fields else {},
            "private_fields_retained": self.retain_private_fields,
            "command_deduplication": {
                "fingerprint": fingerprint,
                "first_seen_sequence": first_seen,
                "sighting_index": sighting_index,
            },
            "previous_event_sha256": self.state.last_event_sha256,
        }
        event = dict(event_without_hash)
        event["event_sha256"] = _document_sha256(event_without_hash)
        provisional_size = len(_serialized_private_json(event, maximum=MAXIMUM_LEDGER_EVENT_BYTES))
        if provisional_size > self.policy.rotation_bytes:
            raise LongRunningObserverError("単一ledger eventがrotation byte上限を超えています")
        segment_number = self.state.active_segment
        active_segment_events = self.state.active_segment_events
        active_segment_bytes = self.state.active_segment_bytes
        if active_segment_events >= self.policy.rotation_event_count or (
            active_segment_events > 0 and active_segment_bytes + provisional_size > self.policy.rotation_bytes
        ):
            segment_number += 1
            active_segment_events = 0
            active_segment_bytes = 0
        segment = self._segment_path(segment_number)
        if not segment.exists():
            segment.mkdir()
        _checked_directory(segment)
        destination = segment / f"{sequence:012d}.json"
        _write_new_private_json(destination, event, allowed_root=self.root)
        committed = read_bounded_snapshot(destination, MAXIMUM_LEDGER_EVENT_BYTES)
        try:
            self._commit_checkpoint(
                event_count=sequence,
                ledger_head_sha256=str(event["event_sha256"]),
            )
        except Exception as exc:
            self._poisoned = True
            raise LedgerCommitError("event durable化後にlocal head checkpointをcommitできません") from exc
        self._storage_delta(int(committed.identity.size))
        self.state.event_count = sequence
        self.state.last_event_sha256 = str(event["event_sha256"])
        self.state.active_segment = segment_number
        self.state.active_segment_events = active_segment_events + 1
        self.state.active_segment_bytes = active_segment_bytes + committed.identity.size
        self.state.source_sha256s.add(source_sha256)
        self.state.first_sequence_by_command.setdefault(fingerprint, sequence)
        self.state.sightings_by_command[fingerprint] = sighting_index
        return event


class LongRunningCommandObservatory:
    """network APIを持たず、private spoolだけを処理する常駐supervisor。"""

    def __init__(
        self,
        root: Path,
        *,
        repository_root: Path,
        clock: Callable[[], str] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        jitter_source: Callable[[], float] = random.random,
    ) -> None:
        self.root = _absolute(root)
        self.repository_root = _validated_repository_root(repository_root)
        if _is_within(self.root, self.repository_root):
            raise LongRunningObserverError("observatory rootをrepository配下から実行できません")
        _reject_git_worktree_path(self.root)
        _checked_directory(self.root)
        for name in ("incoming", "processed", "rejected", "ledger"):
            _checked_directory(self.root / name)
        manifest, _ = _read_json(self.root / "manifest.json", MAXIMUM_MANIFEST_BYTES)
        registry_sha256 = _profile_registry_sha256()
        if (
            manifest.get("schema_version") != SCHEMA_VERSION
            or manifest.get("artifact_type") != "defensive_long_running_command_observatory"
            or manifest.get("network_scope") != "offline_or_loopback_only"
            or manifest.get("external_c2_connections_allowed") is not False
            or manifest.get("command_execution_allowed") is not False
            or manifest.get("command_response_allowed") is not False
            or manifest.get("payload_download_allowed") is not False
            or manifest.get("automatic_stale_claim_recovery") is not False
            or not isinstance(manifest.get("retain_private_fields"), bool)
            or manifest.get("profiles") != sorted(PROFILES)
            or manifest.get("profile_registry_sha256") != registry_sha256
            or manifest.get("chain_algorithm") != "sha256-canonical-json-v1"
            or manifest.get("initial_event_sha256") != ZERO_HASH
            or manifest.get("tail_detection") != "local_durable_head_checkpoint_v1"
            or manifest.get("external_anchor_present") is not False
            or manifest.get("coordinated_checkpoint_rollback_detectable") is not False
        ):
            raise LongRunningObserverError("observatory manifestの安全契約が不一致です")
        policy_value = manifest.get("policy")
        if not isinstance(policy_value, dict):
            raise LongRunningObserverError("observatory policyが不正です")
        self.policy = SupervisorPolicy.from_mapping(policy_value)
        self.retain_private_fields = manifest["retain_private_fields"]
        self.clock = clock
        self.monotonic = monotonic
        self.sleeper = sleeper
        self.jitter_source = jitter_source
        self._surface_storage_bytes = self._surface_bytes()
        total_storage = _regular_tree_bytes(
            self.root,
            stop_after=self.policy.maximum_storage_bytes,
        )
        if self._surface_storage_bytes > total_storage:
            raise LongRunningObserverError("storage cache初期値が不整合です")
        self._managed_storage_bytes = total_storage - self._surface_storage_bytes
        self._cycles_since_full_storage_reconciliation = 0
        self.ledger = ObservationLedger(
            self.root / "ledger",
            policy=self.policy,
            retain_private_fields=self.retain_private_fields,
            clock=clock,
            storage_delta=self._adjust_managed_storage,
        )

    def _dynamic_root_file_bytes(self, path: Path) -> int:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return 0
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or attributes & FILE_ATTRIBUTE_REPARSE_POINT
            or int(getattr(metadata, "st_nlink", 1)) != 1
        ):
            raise LongRunningObserverError(f"observatory control entryが通常の単一fileではありません: {path}")
        return int(metadata.st_size)

    def _surface_bytes(self) -> int:
        return (
            _regular_tree_bytes(
                self.root / "incoming",
                stop_after=self.policy.maximum_storage_bytes if hasattr(self, "policy") else None,
            )
            + self._dynamic_root_file_bytes(self.root / "supervisor.claim")
            + self._dynamic_root_file_bytes(self.root / "kill.switch")
        )

    def _adjust_managed_storage(self, delta: int) -> None:
        if isinstance(delta, bool) or not isinstance(delta, int):
            raise LongRunningObserverError("storage cache差分が不正です")
        updated = self._managed_storage_bytes + delta
        if updated < 0:
            raise LongRunningObserverError("storage cacheが負値になります")
        self._managed_storage_bytes = updated

    def storage_bytes(
        self,
        *,
        force_full: bool = False,
        refresh_surface: bool = True,
    ) -> int:
        """通常cycleはincoming/control surfaceだけを再走査し、定期的に全treeを照合する。"""

        if force_full:
            total = _regular_tree_bytes(
                self.root,
                stop_after=self.policy.maximum_storage_bytes,
            )
            surface = self._surface_bytes()
            if surface > total:
                raise LongRunningObserverError("storage full reconciliationが不整合です")
            self._surface_storage_bytes = surface
            self._managed_storage_bytes = total - surface
            self._cycles_since_full_storage_reconciliation = 0
            return total
        if refresh_surface:
            self._surface_storage_bytes = self._surface_bytes()
        return self._managed_storage_bytes + self._surface_storage_bytes

    def _require_capacity(
        self,
        *,
        additional_bytes: int = 0,
        refresh_surface: bool = True,
        force_full: bool = False,
    ) -> int:
        if isinstance(additional_bytes, bool) or not isinstance(additional_bytes, int) or additional_bytes < 0:
            raise LongRunningObserverError("capacity予約量が不正です")
        self.ledger.require_healthy()
        if self.ledger.state.event_count >= self.policy.maximum_ledger_events:
            raise ObserverCapacityReached("event_capacity_reached")
        current = self.storage_bytes(
            force_full=force_full,
            refresh_surface=refresh_surface,
        )
        if current >= self.policy.maximum_storage_bytes or (
            current + additional_bytes > self.policy.maximum_storage_bytes
        ):
            raise ObserverCapacityReached("storage_capacity_reached")
        return current

    def _jittered_delay(self, base_seconds: float) -> float:
        sample = self.jitter_source()
        if isinstance(sample, bool) or not isinstance(sample, (int, float)) or not 0.0 <= float(sample) <= 1.0:
            raise LongRunningObserverError("jitter sourceは0.0から1.0の範囲である必要があります")
        fraction = self.policy.backoff_jitter_fraction
        multiplier = 1.0 + ((2.0 * float(sample)) - 1.0) * fraction
        return float(base_seconds) * multiplier

    def claim(self) -> ExclusiveClaim:
        return ExclusiveClaim(self.root, clock=self.clock)

    def _processed_path(self, source_sha256: str) -> Path:
        return self.root / "processed" / f"{source_sha256}.json"

    def _receipt_document(self, snapshot: Any, *, status: str) -> dict[str, Any]:
        if status not in {"processed", "rejected"}:
            raise LongRunningObserverError("receipt statusが不正です")
        return {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "sanitized_spool_receipt",
            "status": status,
            "source": {
                "size": int(snapshot.identity.size),
                "sha256": str(snapshot.identity.sha256),
            },
            "recorded_at": self.clock(),
            "raw_content_retained": False,
        }

    def _validate_receipt(
        self,
        destination: Path,
        snapshot: Any,
        *,
        status: str,
    ) -> int:
        receipt, committed = _read_json(destination, MAXIMUM_RECEIPT_BYTES)
        source = receipt.get("source")
        if (
            set(receipt)
            != {
                "schema_version",
                "artifact_type",
                "status",
                "source",
                "recorded_at",
                "raw_content_retained",
            }
            or receipt.get("schema_version") != SCHEMA_VERSION
            or receipt.get("artifact_type") != "sanitized_spool_receipt"
            or receipt.get("status") != status
            or receipt.get("raw_content_retained") is not False
            or not isinstance(source, dict)
            or set(source) != {"size", "sha256"}
            or source.get("size") != snapshot.identity.size
            or source.get("sha256") != snapshot.identity.sha256
        ):
            raise LongRunningObserverError("sanitized receiptとsource identityが不一致です")
        return int(committed.identity.size)

    def _retain_source_copy(self, snapshot: Any) -> None:
        """互換method名を維持し、raw copyでなくSHA-256／size receiptだけを保存する。"""

        destination = self._processed_path(snapshot.identity.sha256)
        if destination.exists():
            self._validate_receipt(destination, snapshot, status="processed")
            return
        _write_new_private_json(
            destination,
            self._receipt_document(snapshot, status="processed"),
            allowed_root=self.root / "processed",
            maximum=MAXIMUM_RECEIPT_BYTES,
        )
        size = self._validate_receipt(
            destination,
            snapshot,
            status="processed",
        )
        self._adjust_managed_storage(size)

    def _reject_source(self, path: Path, error: Exception) -> dict[str, Any]:
        """不正入力のraw bytesを複製せず、SHA-256／size receiptだけを残す。"""

        del error
        before = path.lstat()
        snapshot = read_bounded_snapshot(path, MAXIMUM_SPOOL_BYTES)
        marker_path = self.root / "rejected" / f"{snapshot.identity.sha256}.reason.json"
        receipt = self._receipt_document(snapshot, status="rejected")
        additional = (
            0
            if marker_path.exists()
            else len(
                _serialized_private_json(
                    receipt,
                    maximum=MAXIMUM_RECEIPT_BYTES,
                )
            )
        )
        self._require_capacity(additional_bytes=additional)
        if marker_path.exists():
            self._validate_receipt(
                marker_path,
                snapshot,
                status="rejected",
            )
        else:
            _write_new_private_json(
                marker_path,
                receipt,
                allowed_root=self.root / "rejected",
                maximum=MAXIMUM_RECEIPT_BYTES,
            )
            size = self._validate_receipt(
                marker_path,
                snapshot,
                status="rejected",
            )
            self._adjust_managed_storage(size)
        unlink_created_file_if_unchanged(path, before)
        return {
            "status": "rejected",
            "source_sha256": snapshot.identity.sha256,
            "source_size": snapshot.identity.size,
            "raw_source_retained": False,
        }

    def process_file(self, path: Path) -> dict[str, Any]:
        """1 spool fileをsnapshot化し、分類・ledger commit・private移送する。"""

        if path.parent != self.root / "incoming" or path.suffix.casefold() != ".json":
            raise LongRunningObserverError("spool input pathがincoming JSONではありません")
        before = path.lstat()
        try:
            document, snapshot = _read_json(path, MAXIMUM_SPOOL_BYTES)
            after = path.lstat()
            if stable_file_identity(before) != stable_file_identity(after):
                raise LongRunningObserverError("spool inputがsnapshot後に置換されました")
            if document.get("schema_version") != SCHEMA_VERSION:
                raise LongRunningObserverError("spool schema_versionが未対応です")
            source_scope = document.get("source_scope")
            if source_scope not in {"offline_capture", "loopback"}:
                raise LongRunningObserverError("spool source_scopeはoffline/loopbackだけを許可します")
            captured_at = document.get("captured_at")
            if not isinstance(captured_at, str) or CAPTURED_AT_RE.fullmatch(captured_at) is None:
                raise LongRunningObserverError("spool captured_atがUTC秒精度ではありません")
            profile_id = document.get("profile_id")
            direction = document.get("direction")
            sample_sha256 = document.get("sample_sha256")
            if not isinstance(profile_id, str) or not isinstance(direction, str):
                raise LongRunningObserverError("spool profile_id/directionが不正です")
            if sample_sha256 is not None and not isinstance(sample_sha256, str):
                raise LongRunningObserverError("spool sample_sha256が不正です")
            message = decode_spool_message(profile_id, document)
            observation = observe_command(
                profile_id,
                message,
                direction=direction,
                sample_sha256=sample_sha256,
            )
            duplicate = snapshot.identity.sha256 in self.ledger.state.source_sha256s
            receipt_path = self._processed_path(snapshot.identity.sha256)
            receipt = self._receipt_document(snapshot, status="processed")
            additional = (
                0
                if receipt_path.exists()
                else len(
                    _serialized_private_json(
                        receipt,
                        maximum=MAXIMUM_RECEIPT_BYTES,
                    )
                )
            )
            if not duplicate:
                additional += MAXIMUM_LEDGER_EVENT_BYTES
            self._require_capacity(
                additional_bytes=additional,
                refresh_surface=False,
            )
            self._retain_source_copy(snapshot)
            if duplicate:
                unlink_created_file_if_unchanged(path, before)
                return {"status": "duplicate_source", "source_sha256": snapshot.identity.sha256}
            event = self.ledger.append(
                source_artifact=snapshot.identity.public_dict(),
                source_scope=source_scope,
                captured_at=captured_at,
                sample_sha256=sample_sha256.casefold() if sample_sha256 is not None else None,
                public_event=observation.public_event(),
                private_fields=observation.private_fields,
            )
            removed = unlink_created_file_if_unchanged(path, before)
            return {
                "status": "observed",
                "sequence": event["sequence"],
                "event_sha256": event["event_sha256"],
                "source_sha256": snapshot.identity.sha256,
                "source_removed_after_verified_receipt": removed,
                "raw_source_retained": not removed,
            }
        except ObserverCapacityReached:
            raise
        except LedgerCommitError:
            raise
        except (OSError, ValueError, RatCommandObserverError, LongRunningObserverError) as exc:
            try:
                return self._reject_source(path, exc)
            except ObserverCapacityReached:
                raise
            except (OSError, ValueError, LongRunningObserverError):
                raise LongRunningObserverError(f"spool itemを拒否領域へ固定できません: {path}: {exc}") from exc

    def run_cycle(self, *, maximum_files: int | None = None) -> dict[str, Any]:
        """一回のbounded scanだけを実行する。呼出し側がclaimを保持する。"""

        self._cycles_since_full_storage_reconciliation += 1
        force_full = self._cycles_since_full_storage_reconciliation >= FULL_STORAGE_RECONCILIATION_CYCLES
        self._require_capacity(force_full=force_full)
        limit = maximum_files or self.policy.maximum_files_per_cycle
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= self.policy.maximum_files_per_cycle
        ):
            raise LongRunningObserverError("cycle file上限が不正です")
        paths = heapq.nsmallest(
            limit,
            (item for item in (self.root / "incoming").iterdir() if item.suffix.casefold() == ".json"),
            key=lambda item: item.name,
        )
        results = [self.process_file(path) for path in paths]
        return {
            "processed": len(results),
            "observed": sum(item["status"] == "observed" for item in results),
            "duplicates": sum(item["status"] == "duplicate_source" for item in results),
            "rejected": sum(item["status"] == "rejected" for item in results),
            "ledger_event_count": self.ledger.state.event_count,
            "ledger_head_sha256": self.ledger.state.last_event_sha256,
            "storage_bytes": self.storage_bytes(),
            "storage_limit_bytes": self.policy.maximum_storage_bytes,
            "results": results,
        }

    def _termination_reason(self, deadline: float) -> str | None:
        if (self.root / "kill.switch").exists():
            return "kill_switch_present"
        if self.monotonic() >= deadline:
            return "maximum_runtime_reached"
        return None

    def _sleep_interruptibly(self, seconds: float, *, deadline: float) -> str | None:
        remaining_delay = max(0.0, float(seconds))
        while remaining_delay > 0:
            reason = self._termination_reason(deadline)
            if reason is not None:
                return reason
            remaining_runtime = max(0.0, deadline - self.monotonic())
            if remaining_runtime <= 0:
                return "maximum_runtime_reached"
            step = min(
                remaining_delay,
                remaining_runtime,
                KILL_SWITCH_POLL_SECONDS,
            )
            self.sleeper(step)
            remaining_delay -= step
        return self._termination_reason(deadline)

    def run(self) -> dict[str, Any]:
        """runtime残量とkill switchで全sleepを分割したbounded supervisor。"""

        started = self.monotonic()
        deadline = started + self.policy.maximum_process_runtime_seconds
        cycles = observed = rejected = failures = 0
        consecutive_failures = 0
        backoff = self.policy.initial_backoff_seconds
        stop_reason = "maximum_runtime_reached"
        with self.claim():
            while True:
                reason = self._termination_reason(deadline)
                if reason is not None:
                    stop_reason = reason
                    break
                try:
                    result = self.run_cycle()
                except ObserverCapacityReached as exc:
                    stop_reason = exc.reason
                    break
                except LedgerCommitError:
                    failures += 1
                    stop_reason = "ledger_commit_failed_restart_required"
                    break
                except (OSError, ValueError, LongRunningObserverError):
                    failures += 1
                    consecutive_failures += 1
                    reason = self._sleep_interruptibly(
                        self._jittered_delay(backoff),
                        deadline=deadline,
                    )
                    if reason is not None:
                        stop_reason = reason
                        break
                    backoff = min(backoff * 2, self.policy.maximum_backoff_seconds)
                    if consecutive_failures >= self.policy.circuit_breaker_failures:
                        reason = self._sleep_interruptibly(
                            self._jittered_delay(self.policy.circuit_breaker_cooldown_seconds),
                            deadline=deadline,
                        )
                        if reason is not None:
                            stop_reason = reason
                            break
                        consecutive_failures = 0
                        backoff = self.policy.initial_backoff_seconds
                    continue
                cycles += 1
                observed += int(result["observed"])
                rejected += int(result["rejected"])
                consecutive_failures = 0
                backoff = self.policy.initial_backoff_seconds
                if int(result["processed"]) == 0:
                    reason = self._sleep_interruptibly(
                        self.policy.poll_interval_seconds,
                        deadline=deadline,
                    )
                    if reason is not None:
                        stop_reason = reason
                        break
        return {
            "status": "stopped",
            "stop_reason": stop_reason,
            "cycles": cycles,
            "observed": observed,
            "rejected": rejected,
            "failures": failures,
            "ledger_event_count": self.ledger.state.event_count,
            "ledger_head_sha256": self.ledger.state.last_event_sha256,
            "storage_bytes": self.storage_bytes(),
            "storage_limit_bytes": self.policy.maximum_storage_bytes,
            "network_contacted": False,
            "commands_executed": False,
            "responses_sent": False,
        }

    def public_summary(self) -> dict[str, Any]:
        """private fieldsとsource pathを除き、長期sightingをcommand単位で集約する。"""

        verified, events = self.ledger.verified_events()
        aggregates: dict[tuple[str, str, str, str, str, str, str], dict[str, Any]] = {}
        for event in events:
            public = event["public_event"]
            key = (
                str(public["profile_id"]),
                str(event.get("sample_sha256") or ""),
                str(public["family"]),
                str(public["direction"]),
                str(public["category"]),
                str(public["normalized_command"]),
                str(public["message_sha256"]),
            )
            item = aggregates.setdefault(
                key,
                {
                    "profile_id": key[0],
                    "sample_sha256": key[1] or None,
                    "family": key[2],
                    "direction": key[3],
                    "category": key[4],
                    "normalized_command": key[5],
                    "message_sha256": key[6],
                    "first_seen_sequence": event["sequence"],
                    "last_seen_sequence": event["sequence"],
                    "sightings": 0,
                    "operation_executed": False,
                },
            )
            item["last_seen_sequence"] = event["sequence"]
            item["sightings"] += 1
        return {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "defensive_long_running_command_observatory_public_summary",
            "network_scope": "offline_or_loopback_only",
            "event_count": verified.event_count,
            "unique_command_fingerprints": len(verified.sightings_by_command),
            "ledger_head_sha256": verified.last_event_sha256,
            "tail_detection": "local_durable_head_checkpoint_v1",
            "external_anchor_present": False,
            "coordinated_checkpoint_rollback_detectable": False,
            "private_fields_retained": self.retain_private_fields,
            "storage_bytes": self.storage_bytes(),
            "storage_limit_bytes": self.policy.maximum_storage_bytes,
            "maximum_ledger_events": self.policy.maximum_ledger_events,
            "raw_content_published": False,
            "commands_executed": False,
            "responses_sent": False,
            "observations": sorted(
                aggregates.values(),
                key=lambda item: (
                    item["family"],
                    item["profile_id"],
                    item["direction"],
                    item["normalized_command"],
                    item["message_sha256"],
                ),
            ),
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="repository外へ新規observatoryを作成する")
    initialize.add_argument("--root", type=Path, required=True)
    initialize.add_argument("--repository-root", type=Path, required=True)
    initialize.add_argument("--retain-private-fields", action="store_true")
    initialize.add_argument("--rotation-events", type=int, default=1000)
    initialize.add_argument("--rotation-bytes", type=int, default=16 * 1024 * 1024)
    initialize.add_argument("--maximum-ledger-events", type=int, default=1_000_000)
    initialize.add_argument("--maximum-storage-bytes", type=int, default=4 * 1024 * 1024 * 1024)
    initialize.add_argument("--backoff-jitter-fraction", type=float, default=0.2)
    for name in ("once", "run", "summary", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--root", type=Path, required=True)
        command.add_argument("--repository-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            policy = SupervisorPolicy(
                rotation_event_count=args.rotation_events,
                rotation_bytes=args.rotation_bytes,
                maximum_ledger_events=args.maximum_ledger_events,
                maximum_storage_bytes=args.maximum_storage_bytes,
                backoff_jitter_fraction=args.backoff_jitter_fraction,
            )
            result = initialize_observatory(
                args.root,
                repository_root=args.repository_root,
                policy=policy,
                retain_private_fields=args.retain_private_fields,
            )
        else:
            observatory = LongRunningCommandObservatory(
                args.root,
                repository_root=args.repository_root,
            )
            if args.command == "once":
                with observatory.claim():
                    result = observatory.run_cycle()
            elif args.command == "run":
                result = observatory.run()
            elif args.command == "summary":
                result = observatory.public_summary()
            else:
                state = observatory.ledger.verify()
                result = {
                    "status": "verified",
                    "event_count": state.event_count,
                    "ledger_head_sha256": state.last_event_sha256,
                    "tail_detection": "local_durable_head_checkpoint_v1",
                    "external_anchor_present": False,
                    "coordinated_checkpoint_rollback_detectable": False,
                }
    except (OSError, ValueError, LongRunningObserverError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
