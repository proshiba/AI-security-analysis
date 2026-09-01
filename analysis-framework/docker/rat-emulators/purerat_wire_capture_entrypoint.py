#!/usr/bin/env python3
"""固定PureRAT endpointのpcapを再起動をまたいで循環保存する。"""

from __future__ import annotations

import os
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path


CAPTURE_ROOT = Path("/captures")
MAXIMUM_CAPTURE_FILES = 256
FILES_PER_PROCESS = 16
CAPTURE_MEGABYTES_PER_FILE = 64
TARGET = "45.192.211.77"
PORT = "56001"


class CaptureEntrypointError(RuntimeError):
    """capture保存先または既存fileが安全条件を満たさない。"""


def _capture_files() -> list[Path]:
    metadata = CAPTURE_ROOT.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or CAPTURE_ROOT.is_symlink():
        raise CaptureEntrypointError("capture rootは通常directoryにしてください")
    files: list[Path] = []
    for path in CAPTURE_ROOT.glob("purerat-*.pcap*"):
        item = path.lstat()
        if not stat.S_ISREG(item.st_mode) or path.is_symlink() or item.st_nlink != 1:
            raise CaptureEntrypointError("既存pcapは単一の通常fileにしてください")
        files.append(path)
    return sorted(files, key=lambda path: (path.stat().st_mtime_ns, path.name))


def _reserve_rotation_capacity() -> None:
    files = _capture_files()
    keep_before_start = MAXIMUM_CAPTURE_FILES - FILES_PER_PROCESS
    for path in files[: max(0, len(files) - keep_before_start)]:
        path.unlink()


def main() -> None:
    _reserve_rotation_capacity()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    prefix = CAPTURE_ROOT / f"purerat-{stamp}-{uuid.uuid4().hex}.pcap"
    arguments = [
        "/usr/bin/tcpdump",
        "-i",
        "any",
        "-nn",
        "-s",
        "0",
        "-U",
        "-C",
        str(CAPTURE_MEGABYTES_PER_FILE),
        "-W",
        str(FILES_PER_PROCESS),
        "-w",
        str(prefix),
        "tcp",
        "and",
        "host",
        TARGET,
        "and",
        "port",
        PORT,
    ]
    print(
        f"pcap rotationを開始します: prefix={prefix.name} "
        f"files={FILES_PER_PROCESS} size_mb={CAPTURE_MEGABYTES_PER_FILE}",
        flush=True,
    )
    os.execv(arguments[0], arguments)


if __name__ == "__main__":
    main()
