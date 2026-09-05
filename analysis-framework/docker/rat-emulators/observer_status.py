#!/usr/bin/env python3
"""観測の実状態をatomic JSONへ保存し、通信なしでhealthを判定する。"""

from __future__ import annotations

import argparse
import json
import os
import stat
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


STATUS_PATHS = {
    "purerat": Path("/var/lib/rat-emulator/observations/observer-status.json"),
    "winos": Path("/var/lib/rat-emulator/transcripts/observer-status.json"),
}
HEALTHY_STATES = {"starting", "validating", "resolving", "connecting", "observing", "cooldown"}
STATES = HEALTHY_STATES | {
    "waiting_preflight", "waiting_maxmind", "retry_limit_reached", "local_error",
    "policy_stopped", "stopped",
}
MAXIMUM_STATUS_BYTES = 8192
FIELDS = {
    "connected", "transport_phase", "inbound_frames", "inbound_bytes",
    "outbound_frames", "outbound_bytes", "attempt_count", "consecutive_failures",
    "retries_used", "retries_remaining", "retry_circuit_open", "maximum_retries",
    "error_type", "refusal_reason", "next_check_seconds", "stop_reason",
}


def _regular(path: Path) -> None:
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("statusは単一の通常fileに限定します")


class ObserverStatus:
    """10秒ごと、または状態遷移時に現在状態を更新する。"""

    def __init__(self, path: Path, profile_id: str) -> None:
        self.path = path
        self.profile_id = profile_id
        self.run_id = uuid.uuid4().hex
        self.last_write = float("-inf")
        self.state = "starting"
        self.fields: dict[str, Any] = {"connected": False}

    def update(self, state: str | None = None, **fields: Any) -> None:
        """本文・資格情報を受け取らず、allowlistの運用metadataだけ保存する。"""

        state = state or self.state
        if state not in STATES or set(fields) - FIELDS:
            raise ValueError("未定義のobserver statusです")
        changed = state != self.state
        self.state = state
        self.fields.update(fields)
        now = time.monotonic()
        if not changed and now - self.last_write < 10.0:
            return
        document = {
            "schema_version": 1,
            "profile_id": self.profile_id,
            "run_id": self.run_id,
            "pid": os.getpid(),
            "updated_at_utc": datetime.now(UTC).isoformat(),
            "updated_at_monotonic": now,
            "state": state,
            **self.fields,
        }
        data = (json.dumps(document, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        if len(data) > MAXIMUM_STATUS_BYTES:
            raise ValueError("statusのsize上限を超えました")
        _regular(self.path)
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("status書込に失敗しました")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        _regular(self.path)
        os.replace(temporary, self.path)
        self.last_write = now

    def progress(self, fields: dict[str, Any]) -> None:
        """共通runnerから接続段階と送受信件数を受け取る。"""

        self.update(**fields)


def read_health(path: Path) -> tuple[dict[str, Any], bool]:
    """同じLinux bootのmonotonic clockで鮮度を確認する。外部通信はしない。"""

    _regular(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("statusのfile identityが不正です")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAXIMUM_STATUS_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAXIMUM_STATUS_BYTES:
        raise ValueError("statusが過大です")
    document = json.loads(data)
    timestamp = document.get("updated_at_monotonic")
    if type(timestamp) not in (int, float):
        raise ValueError("status時刻が不正です")
    age = time.monotonic() - timestamp
    healthy = 0 <= age <= 90.0 and document.get("state") in HEALTHY_STATES
    return {
        "state": document.get("state"),
        "connected": document.get("connected") is True,
        "fresh": 0 <= age <= 90.0,
        "healthy": healthy,
        "error_type": document.get("error_type"),
        "retries_remaining": document.get("retries_remaining"),
    }, healthy


def main() -> int:
    """Docker HEALTHCHECK用の固定保存先を読み取る。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=tuple(STATUS_PATHS))
    args = parser.parse_args()
    try:
        result, healthy = read_health(STATUS_PATHS[args.family])
    except (OSError, ValueError, TypeError, AttributeError):
        result, healthy = {"state": "status_unavailable", "healthy": False}, False
    print(json.dumps(result, ensure_ascii=False))
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
