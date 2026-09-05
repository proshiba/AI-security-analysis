#!/usr/bin/env python3
"""PureRATの有界sessionを安全な間隔で反復する長期観測supervisor。"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import signal
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable


PROFILE_ID = "purerat-441-d025a296-direct-tls10-empty-gclass4"
OBSERVATION_ROOT = Path("/var/lib/rat-emulator/observations")
SESSION_ROOT = OBSERVATION_ROOT / "sessions"
EVENT_LOG = OBSERVATION_ROOT / "observer-events.jsonl"
CLAIM_FILE = OBSERVATION_ROOT / "observer.lock"
RETRY_STATE_FILE = OBSERVATION_ROOT / "retry-circuit.json"
KILL_SWITCH = Path("/run/rat-emulator/armed")
MAXMIND_CACHE_ROOT = Path("/var/cache/rat-emulator/maxmind")
MAXIMUM_LOG_BYTES = 8 * 1024 * 1024
MAXIMUM_LOG_BACKUPS = 16
BASE_COOLDOWN_SECONDS = 30.0
MAXIMUM_COOLDOWN_SECONDS = 900.0
SLEEP_POLL_SECONDS = 1.0
CAPTURE_STARTUP_GRACE_SECONDS = 5.0
MAXIMUM_EVENT_BYTES = 64 * 1024
MAXIMUM_RETRIES = 3
MAXIMUM_CONSECUTIVE_FAILURES = MAXIMUM_RETRIES + 1
CIRCUIT_OPEN_POLL_SECONDS = 60.0
MAXIMUM_LEASE_REGISTRY_BYTES = 64 * 1024
MAXIMUM_RETRY_STATE_BYTES = 4096
MAXIMUM_SESSION_STORAGE_BYTES = 512 * 1024 * 1024
MAXIMUM_SESSION_FILES = 32768


def _require_storage_capacity(root: Path) -> None:
    """保持済み成果物を削除せず、容量または件数上限で新規接続を止める。"""

    used = 0
    count = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise LongRunningObserverError("session保存先のlinkを拒否しました")
            count += 1
            if stat.S_ISREG(metadata.st_mode):
                used += metadata.st_size
            if count >= MAXIMUM_SESSION_FILES or used >= MAXIMUM_SESSION_STORAGE_BYTES:
                raise LongRunningObserverError("観測保存容量の上限です。既存成果物の保管が必要です")


@dataclass(frozen=True)
class ObserverSettings:
    """入口ごとに固定するprofileと保存先。C2の任意指定は受け取らない。"""

    profile_id: str
    root: Path
    sessions: Path
    kill_switch: Path
    maxmind_cache: Path


WINOS_SETTINGS = ObserverSettings(
    "valleyrat-winos-heartbeat-20260810-64-81-30-192-6666",
    Path("/var/lib/rat-emulator/transcripts"),
    Path("/var/lib/rat-emulator/transcripts/sessions"),
    KILL_SWITCH,
    MAXMIND_CACHE_ROOT,
)


class LongRunningObserverError(RuntimeError):
    """長期観測の排他・固定path・log契約に違反した。"""


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _checked_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink < 2
    ):
        raise LongRunningObserverError(f"通常directoryではありません: {path}")


def _prepare_fixed_directories() -> None:
    _checked_directory(OBSERVATION_ROOT)
    SESSION_ROOT.mkdir(mode=0o700, exist_ok=True)
    _checked_directory(SESSION_ROOT)


class AtomicObserverClaim:
    """同じobservation volumeでobserverを1 processだけに限定する。"""

    def __init__(self, path: Path = CLAIM_FILE) -> None:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        self._descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(self._descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(self._descriptor)
            raise LongRunningObserverError("observer claimは単一の通常fileにしてください")
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self._descriptor)
            raise LongRunningObserverError("別のobserverが既に稼働しています") from exc
        os.ftruncate(self._descriptor, 0)
        os.write(self._descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(self._descriptor)

    def close(self) -> None:
        if self._descriptor >= 0:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            os.close(self._descriptor)
            self._descriptor = -1

    def __enter__(self) -> AtomicObserverClaim:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class PersistentRetryCircuit:
    """同じlease identityで初回失敗後の再試行を3回までに固定する。"""

    _EXPECTED_KEYS = frozenset(
        {
            "schema_version",
            "profile_id",
            "lease_registry_sha256",
            "consecutive_failures",
            "maximum_retries",
            "circuit_open",
            "updated_at_utc",
        }
    )

    def __init__(
        self,
        path: Path | None = None,
        *,
        maximum_retries: int = MAXIMUM_RETRIES,
        profile_id: str = PROFILE_ID,
    ) -> None:
        if maximum_retries != MAXIMUM_RETRIES:
            raise LongRunningObserverError("retry上限は3回へ固定されています")
        self.path = path if path is not None else RETRY_STATE_FILE
        self.maximum_retries = maximum_retries
        self.profile_id = profile_id
        self.lease_registry_sha256 = "unavailable"
        self.consecutive_failures = 0
        self.circuit_open = False

    def _reject_nonregular(self) -> None:
        if not self.path.exists() and not self.path.is_symlink():
            return
        metadata = self.path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or self.path.is_symlink()
            or metadata.st_nlink != 1
        ):
            raise LongRunningObserverError("retry stateは単一の通常fileにしてください")

    def _validate_identity(self, value: object) -> str:
        if value == "unavailable":
            return value
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise LongRunningObserverError("lease registry identityが不正です")
        return value

    def _document(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "profile_id": self.profile_id,
            "lease_registry_sha256": self.lease_registry_sha256,
            "consecutive_failures": self.consecutive_failures,
            "maximum_retries": self.maximum_retries,
            "circuit_open": self.circuit_open,
            "updated_at_utc": _utc_now(),
        }

    def _read_document(self) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise LongRunningObserverError("retry stateを開けません") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or not 1 <= metadata.st_size <= MAXIMUM_RETRY_STATE_BYTES
            ):
                raise LongRunningObserverError("retry stateのidentityまたはsizeが不正です")
            content = bytearray()
            while len(content) <= MAXIMUM_RETRY_STATE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(4096, MAXIMUM_RETRY_STATE_BYTES + 1 - len(content)),
                )
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
            if (
                after.st_dev != metadata.st_dev
                or after.st_ino != metadata.st_ino
                or after.st_size != metadata.st_size
                or len(content) != metadata.st_size
                or len(content) > MAXIMUM_RETRY_STATE_BYTES
            ):
                raise LongRunningObserverError("retry stateが読込中に変化しました")
        finally:
            os.close(descriptor)
        try:
            document = json.loads(content.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LongRunningObserverError("retry stateを厳格にdecodeできません") from exc
        if not isinstance(document, dict):
            raise LongRunningObserverError("retry stateはobjectである必要があります")
        return document

    def _write(self) -> None:
        self._reject_nonregular()
        encoded = (
            json.dumps(
                self._document(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LongRunningObserverError("retry state一時fileのidentityが不正です")
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise LongRunningObserverError("retry stateを書き込めません")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.path)
        directory_descriptor = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def load(self, lease_registry_sha256: str, *, allow_reset: bool = True) -> bool:
        """stateを読み、lease変更時だけcounterをresetする。"""

        active_identity = self._validate_identity(lease_registry_sha256)
        self._reject_nonregular()
        if not self.path.exists():
            self.lease_registry_sha256 = active_identity
            self.consecutive_failures = 0
            self.circuit_open = False
            self._write()
            return False
        document = self._read_document()
        if not isinstance(document, dict) or set(document) != self._EXPECTED_KEYS:
            raise LongRunningObserverError("retry stateのkey集合が不正です")
        if (
            document.get("schema_version") != 1
            or document.get("profile_id") != self.profile_id
            or document.get("maximum_retries") != self.maximum_retries
            or not isinstance(document.get("consecutive_failures"), int)
            or isinstance(document.get("consecutive_failures"), bool)
            or not 0 <= document["consecutive_failures"] <= MAXIMUM_CONSECUTIVE_FAILURES
            or not isinstance(document.get("circuit_open"), bool)
            or document["circuit_open"]
            != (document["consecutive_failures"] >= MAXIMUM_CONSECUTIVE_FAILURES)
            or not isinstance(document.get("updated_at_utc"), str)
        ):
            raise LongRunningObserverError("retry stateの値が不正です")
        stored_identity = self._validate_identity(document.get("lease_registry_sha256"))
        if stored_identity != active_identity and allow_reset:
            self.lease_registry_sha256 = active_identity
            self.consecutive_failures = 0
            self.circuit_open = False
            self._write()
            return True
        self.lease_registry_sha256 = stored_identity
        self.consecutive_failures = document["consecutive_failures"]
        self.circuit_open = document["circuit_open"]
        return False

    def record_failure(self) -> None:
        self.consecutive_failures = min(
            MAXIMUM_CONSECUTIVE_FAILURES,
            self.consecutive_failures + 1,
        )
        self.circuit_open = (
            self.consecutive_failures >= MAXIMUM_CONSECUTIVE_FAILURES
        )
        self._write()

    def record_success(self) -> None:
        if self.consecutive_failures == 0 and not self.circuit_open:
            return
        self.consecutive_failures = 0
        self.circuit_open = False
        self._write()

    def public_fields(self) -> dict[str, Any]:
        retries_used = max(0, self.consecutive_failures - 1)
        return {
            "consecutive_failures": self.consecutive_failures,
            "maximum_retries": self.maximum_retries,
            "retries_used": min(self.maximum_retries, retries_used),
            "retries_remaining": max(0, self.maximum_retries - retries_used),
            "retry_circuit_open": self.circuit_open,
        }


class PersistentPolicyStop(PersistentRetryCircuit):
    """command・pin違反による停止を再起動後も保持する。"""

    def _document(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "profile_id": self.profile_id,
            "lease_registry_sha256": self.lease_registry_sha256,
            "stop_reason": self.stop_reason,
        }

    def mark(self, identity: str, reason: str) -> None:
        """現在のレビュー済みleaseに停止理由を結び付ける。"""

        self.lease_registry_sha256 = self._validate_identity(identity)
        self.stop_reason = reason[:128]
        self._write()

    def blocked_reason(self, identity: str) -> str | None:
        """検証済みの別leaseが来るまで停止理由を返す。"""

        self._reject_nonregular()
        if not self.path.exists():
            return None
        document = self._read_document()
        if (set(document) != {"schema_version", "profile_id", "lease_registry_sha256", "stop_reason"}
                or document.get("schema_version") != 1
                or document.get("profile_id") != self.profile_id
                or not isinstance(document.get("stop_reason"), str)
                or not 1 <= len(document["stop_reason"]) <= 128):
            raise LongRunningObserverError("policy停止記録が不正です")
        stored = self._validate_identity(document["lease_registry_sha256"])
        return document["stop_reason"] if stored == identity else None


class RotatingJsonlLog:
    """単一writerのJSONLをsize上限でrotationし、各行をfsyncする。"""

    def __init__(
        self,
        path: Path = EVENT_LOG,
        *,
        maximum_bytes: int = MAXIMUM_LOG_BYTES,
        backups: int = MAXIMUM_LOG_BACKUPS,
    ) -> None:
        if maximum_bytes < 4096 or not 1 <= backups <= 128:
            raise LongRunningObserverError("log rotation上限が不正です")
        self.path = path
        self.maximum_bytes = maximum_bytes
        self.backups = backups

    def _reject_nonregular(self, path: Path) -> None:
        if not path.exists() and not path.is_symlink():
            return
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
            raise LongRunningObserverError(f"logは単一の通常fileにしてください: {path}")

    def _rotate(self) -> None:
        self._reject_nonregular(self.path)
        oldest = self.path.with_name(f"{self.path.name}.{self.backups}")
        if oldest.exists() or oldest.is_symlink():
            self._reject_nonregular(oldest)
            oldest.unlink()
        for index in range(self.backups - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if source.exists() or source.is_symlink():
                self._reject_nonregular(source)
                os.replace(source, self.path.with_name(f"{self.path.name}.{index + 1}"))
        if self.path.exists():
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))

    def append(self, event_type: str, fields: dict[str, Any]) -> dict[str, Any]:
        if not event_type or len(event_type) > 128:
            raise LongRunningObserverError("event_typeが不正です")
        event = {
            "schema_version": 1,
            "captured_at_utc": _utc_now(),
            "event_type": event_type,
            **fields,
        }
        encoded = (
            json.dumps(event, ensure_ascii=False, allow_nan=False, sort_keys=True)
            + "\n"
        ).encode("utf-8")
        if len(encoded) > MAXIMUM_EVENT_BYTES:
            raise LongRunningObserverError("observer eventが上限を超えました")
        self._reject_nonregular(self.path)
        current_size = self.path.stat().st_size if self.path.exists() else 0
        if current_size and current_size + len(encoded) > self.maximum_bytes:
            self._rotate()
        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LongRunningObserverError("observer log identityが不正です")
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise LongRunningObserverError("observer logを書き込めません")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        print(encoded.decode("utf-8").rstrip(), flush=True)
        return event


def _safe_public_result(result: dict[str, Any]) -> dict[str, Any]:
    adapter = result.get("adapter_result")
    if not isinstance(adapter, dict):
        return {
            "status": result.get("status"),
            "stop_reason": result.get("stop_reason"),
            "event_count": result.get("event_count"),
            "transcript_root_sha256": result.get("transcript_root_sha256"),
        }
    collection = adapter.get("collection") if isinstance(adapter.get("collection"), dict) else {}
    safety = adapter.get("safety") if isinstance(adapter.get("safety"), dict) else {}
    decisions = adapter.get("decisions") if isinstance(adapter.get("decisions"), list) else []
    return {
        "status": adapter.get("status"),
        "response_size": collection.get("response_size"),
        "response_sha256": collection.get("response_sha256"),
        "frame_count": collection.get("frame_count"),
        "decisions": decisions,
        "transcript_root_sha256": result.get("transcript_root_sha256"),
        "task_executed": safety.get("task_executed"),
        "operation_executed": safety.get("operation_executed"),
        "plugin_or_file_executed": safety.get("plugin_or_file_executed"),
        "command_reply_sent": safety.get("command_reply_sent"),
    }


def _error_event(exc: BaseException) -> tuple[str, dict[str, Any]]:
    fields: dict[str, Any] = {
        "error_type": type(exc).__name__,
        "error_number": getattr(exc, "errno", None),
        "task_executed": False,
        "operation_executed": False,
        "command_reply_sent": False,
    }
    if type(exc).__name__ == "RatEmulatorRunError":
        fields["refusal_reason"] = str(exc).replace("\r", " ").replace("\n", " ")[:512]
    if isinstance(exc, ConnectionResetError) or getattr(exc, "errno", None) == errno.ECONNRESET:
        return "peer_reset_received", {**fields, "reset_direction": "peer_to_observer"}
    if isinstance(exc, TimeoutError):
        return "transport_timeout", fields
    return "session_failed", fields


def _lease_registry_identity(runner: Any) -> str:
    """runnerと同じdirectoryのlease registryをbounded readして識別する。"""

    module_path = getattr(runner, "__file__", None)
    if not isinstance(module_path, str):
        return "unavailable"
    path = Path(module_path).with_name("rat_emulator_live_leases.json")
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= MAXIMUM_LEASE_REGISTRY_BYTES
        ):
            return "unavailable"
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_dev != metadata.st_dev
                or opened.st_ino != metadata.st_ino
                or opened.st_size != metadata.st_size
            ):
                return "unavailable"
            content = bytearray()
            while len(content) <= MAXIMUM_LEASE_REGISTRY_BYTES:
                chunk = os.read(
                    descriptor,
                    min(65536, MAXIMUM_LEASE_REGISTRY_BYTES + 1 - len(content)),
                )
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
            if (
                after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino
                or after.st_size != opened.st_size
                or not content
                or len(content) > MAXIMUM_LEASE_REGISTRY_BYTES
            ):
                return "unavailable"
        finally:
            os.close(descriptor)
    except OSError:
        return "unavailable"
    return hashlib.sha256(content).hexdigest()


def _interruptible_wait(
    seconds: float,
    stopping: Callable[[], bool],
    sleep: Callable[[float], None],
    *,
    kill_switch: Path | None = None,
    tick: Callable[[], None] | None = None,
) -> bool:
    deadline = time.monotonic() + max(0.0, seconds)
    path = kill_switch if kill_switch is not None else KILL_SWITCH
    while not stopping() and path.exists():
        if tick is not None:
            tick()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        sleep(min(SLEEP_POLL_SECONDS, remaining))
    return False


def observe_forever(
    runner: Any,
    *,
    base_cooldown_seconds: float = BASE_COOLDOWN_SECONDS,
    maximum_cooldown_seconds: float = MAXIMUM_COOLDOWN_SECONDS,
    maximum_attempts: int = 0,
    sleep: Callable[[float], None] = time.sleep,
    settings: ObserverSettings | None = None,
) -> int:
    """有界sessionを直列実行し、許可待ちと通信失敗を別に管理する。"""

    from observer_status import ObserverStatus

    if not 1.0 <= base_cooldown_seconds <= maximum_cooldown_seconds <= 3600.0:
        raise LongRunningObserverError("cooldown範囲が不正です")
    if maximum_attempts < 0:
        raise LongRunningObserverError("maximum_attemptsが不正です")
    settings = settings or ObserverSettings(
        PROFILE_ID, OBSERVATION_ROOT, SESSION_ROOT, KILL_SWITCH, MAXMIND_CACHE_ROOT
    )
    if settings.profile_id not in {PROFILE_ID, WINOS_SETTINGS.profile_id}:
        raise LongRunningObserverError("未レビューのobserver profileです")
    _checked_directory(settings.root)
    settings.sessions.mkdir(mode=0o700, exist_ok=True)
    _checked_directory(settings.sessions)
    stopping_flag = False
    kill_switch_disarmed = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stopping_flag
        stopping_flag = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    stopping = lambda: stopping_flag
    log = RotatingJsonlLog(settings.root / "observer-events.jsonl")
    status = ObserverStatus(settings.root / "observer-status.json", settings.profile_id)
    observer_kill_switch = runner.KillSwitch(settings.kill_switch)
    attempts = 0
    retry_circuit = PersistentRetryCircuit(
        settings.root / "retry-circuit.json", profile_id=settings.profile_id
    )
    policy_stop = PersistentPolicyStop(
        settings.root / "policy-stop.json", profile_id=settings.profile_id
    )

    def tick() -> None:
        nonlocal kill_switch_disarmed, stopping_flag
        try:
            observer_kill_switch.require_armed()
        except Exception:
            kill_switch_disarmed = True
            stopping_flag = True
            status.update("stopped", connected=False, stop_reason="kill_switch_disarmed")
            return
        status.update()

    def wait(seconds: float) -> bool:
        return _interruptible_wait(
            seconds, stopping, sleep, kill_switch=settings.kill_switch, tick=tick
        )

    with AtomicObserverClaim(settings.root / "observer.lock"):
        lease_identity = _lease_registry_identity(runner)
        retry_circuit.load(lease_identity, allow_reset=False)
        status.update("starting", **retry_circuit.public_fields())
        log.append(
            "observer_started",
            {
                "profile_id": settings.profile_id,
                "base_cooldown_seconds": base_cooldown_seconds,
                "maximum_cooldown_seconds": maximum_cooldown_seconds,
                "maximum_attempts": maximum_attempts,
                **retry_circuit.public_fields(),
                "capture_startup_grace_seconds": CAPTURE_STARTUP_GRACE_SECONDS,
                "sample_executed": False,
            },
        )
        last_preflight_error: tuple[str, str] | None = None
        wait(CAPTURE_STARTUP_GRACE_SECONDS)
        while not stopping() and settings.kill_switch.exists():
            try:
                observer_kill_switch.require_armed()
            except Exception as exc:
                kill_switch_disarmed = True
                log.append(
                    "kill_switch_disarmed",
                    {
                        "error_type": type(exc).__name__,
                        "task_executed": False,
                        "operation_executed": False,
                    },
                )
                break
            if maximum_attempts and attempts >= maximum_attempts:
                break
            attempt_id = uuid.uuid4().hex
            try:
                preflight = runner.preflight(settings.profile_id)
                if preflight.get("live_enabled") is not True:
                    raise LongRunningObserverError("profileはlive観測を許可していません")
                current_lease_identity = _lease_registry_identity(runner)
                verified_lease = preflight.get("live_lease")
                if (current_lease_identity == "unavailable"
                        or not isinstance(verified_lease, dict)
                        or verified_lease.get("sha256") != current_lease_identity):
                    raise LongRunningObserverError("preflight後にlease identityが変化しました")
            except Exception as exc:
                _event_type, fields = _error_event(exc)
                status.update(
                    "waiting_preflight", connected=False,
                    error_type=fields["error_type"],
                    refusal_reason=fields.get("refusal_reason"),
                    next_check_seconds=CIRCUIT_OPEN_POLL_SECONDS,
                    **retry_circuit.public_fields(),
                )
                error_identity = (fields["error_type"], fields.get("refusal_reason", ""))
                if error_identity != last_preflight_error:
                    log.append("preflight_refused", {
                        **fields, **retry_circuit.public_fields(),
                        "network_attempted": False, "retry_consumed": False,
                    })
                    last_preflight_error = error_identity
                if not wait(CIRCUIT_OPEN_POLL_SECONDS):
                    break
                continue
            else:
                if last_preflight_error is not None:
                    log.append("preflight_restored", {"network_attempted": False})
                    last_preflight_error = None
                if current_lease_identity != retry_circuit.lease_registry_sha256:
                    retry_circuit.load(current_lease_identity)
                    log.append("retry_circuit_reset_after_reviewed_lease_change", {
                        "profile_id": settings.profile_id, **retry_circuit.public_fields(),
                    })
                blocked_reason = policy_stop.blocked_reason(current_lease_identity)
                if blocked_reason is not None:
                    status.update("policy_stopped", connected=False, stop_reason=blocked_reason)
                    if not wait(CIRCUIT_OPEN_POLL_SECONDS):
                        break
                    continue
                if retry_circuit.circuit_open:
                    status.update("retry_limit_reached", connected=False, **retry_circuit.public_fields())
                    if not wait(CIRCUIT_OPEN_POLL_SECONDS):
                        break
                    continue
                try:
                    _require_storage_capacity(settings.sessions)
                except LongRunningObserverError as exc:
                    status.update("local_error", connected=False,
                                  error_type=type(exc).__name__, stop_reason="archive_required")
                    log.append("archive_required", {"network_attempted": False})
                    break
                attempts += 1
                private = settings.sessions / f"{settings.profile_id}-{attempt_id}"
                public = settings.sessions / f"{settings.profile_id}-{attempt_id}-public.json"
                status.update("validating", connected=False, attempt_count=attempts,
                              error_type=None, refusal_reason=None, transport_phase=None,
                              inbound_frames=0, inbound_bytes=0, outbound_frames=0, outbound_bytes=0,
                              **retry_circuit.public_fields())
                log.append(
                    "session_attempt",
                    {
                        "attempt_id": attempt_id,
                        "profile_id": settings.profile_id,
                        "endpoint": preflight.get("endpoint"),
                        "pinned_ips": preflight.get("pinned_ips"),
                        "live_lease": preflight.get("live_lease"),
                        "preflight_network_used": preflight.get("network_used"),
                        "network_authorized": True,
                    },
                )
                try:
                    result = runner.run_live_session(
                        settings.profile_id,
                        allow_network=True,
                        allow_live_c2_emulation=True,
                        acknowledged_profile=settings.profile_id,
                        kill_switch_path=settings.kill_switch,
                        private_output_directory=private,
                        maxmind_cache_directory=settings.maxmind_cache,
                        public_output=public,
                        stop_requested=stopping,
                        progress_callback=status.progress,
                    )
                except Exception as exc:
                    event_type, fields = _error_event(exc)
                    if stopping():
                        break
                    network_failure = isinstance(exc, (ConnectionError, TimeoutError))
                    network_failure = network_failure or (
                        isinstance(exc, OSError) and getattr(exc, "errno", None) in {
                            errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED,
                            errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH,
                        }
                    )
                    if network_failure:
                        retry_circuit.record_failure()
                    else:
                        status.update("local_error", connected=False, error_type=type(exc).__name__,
                                      refusal_reason=fields.get("refusal_reason"))
                    log.append(
                        event_type,
                        {
                            "attempt_id": attempt_id,
                            **fields,
                            **retry_circuit.public_fields(),
                            "retry_consumed": network_failure,
                        },
                    )
                    if not network_failure:
                        if status.fields.get("transport_phase") is not None:
                            policy_stop.mark(current_lease_identity, type(exc).__name__)
                            status.update("policy_stopped", connected=False,
                                          stop_reason=type(exc).__name__)
                            break
                        if isinstance(exc, OSError):
                            # disk、permission等の障害中に接続を反復しない。
                            break
                        if not wait(CIRCUIT_OPEN_POLL_SECONDS):
                            break
                        continue
                else:
                    summary = _safe_public_result(result)
                    outcome = summary.get("status") or summary.get("stop_reason")
                    adapter = result.get("adapter_result", {})
                    collection = adapter.get("collection", {})
                    decisions = adapter.get("decisions", [])
                    benign_heartbeat = (
                        outcome == "known_non_operation_message_observed"
                        and len(decisions) == 1
                        and decisions[0].get("discriminator") == 2
                    )
                    empty_timeout = (
                        outcome == "registration_sent_no_frame_observed"
                        and (collection.get("timed_out") is True or collection.get("peer_closed") is True)
                    )
                    if outcome == "peer_closed" or empty_timeout:
                        retry_circuit.record_failure()
                    elif outcome == "observation_window_complete" or benign_heartbeat:
                        retry_circuit.record_success()
                    else:
                        # task/未知frameを受信して終了したsessionを成功再接続へ回さない。
                        policy_stop.mark(current_lease_identity, str(outcome))
                        status.update("policy_stopped", connected=False, stop_reason=str(outcome))
                        log.append("observation_policy_stopped", summary)
                        break
                    log.append(
                        "session_completed",
                        {
                            "attempt_id": attempt_id,
                            "public_summary_file": public.name,
                            **summary,
                            **retry_circuit.public_fields(),
                        },
                    )
            if retry_circuit.circuit_open:
                log.append(
                    "retry_limit_reached",
                    {
                        "profile_id": settings.profile_id,
                        **retry_circuit.public_fields(),
                        "task_executed": False,
                        "operation_executed": False,
                        "command_reply_sent": False,
                    },
                )
                status.update("retry_limit_reached", connected=False, **retry_circuit.public_fields())
                continue
            cooldown = min(
                maximum_cooldown_seconds,
                base_cooldown_seconds
                * (2 ** min(retry_circuit.consecutive_failures, 10)),
            )
            status.update("cooldown", connected=False, next_check_seconds=cooldown,
                          **retry_circuit.public_fields())
            if not wait(cooldown):
                break
        log.append(
            "observer_stopped",
            {
                "attempt_count": attempts,
                "signal_received": stopping(),
                "kill_switch_present": settings.kill_switch.exists(),
                "kill_switch_disarmed": kill_switch_disarmed,
                "sample_executed": False,
                **retry_circuit.public_fields(),
            },
        )
        if status.state not in {"policy_stopped", "local_error"}:
            status.update("stopped", connected=False, **retry_circuit.public_fields())
    return 0


__all__ = [
    "AtomicObserverClaim",
    "LongRunningObserverError",
    "RotatingJsonlLog",
    "observe_forever",
]
