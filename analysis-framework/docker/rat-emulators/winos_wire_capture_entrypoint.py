#!/usr/bin/env python3
"""固定Winos endpointのpcapを8時間だけ循環保存する。"""

from __future__ import annotations

import os
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path


CAPTURE_ROOT = Path("/captures")
TARGET = "64.81.30.192"
PORT = "6666"
CAPTURE_SECONDS = "28815s"
FILES_PER_PROCESS = 16
CAPTURE_MEGABYTES_PER_FILE = 64


class CaptureEntrypointError(RuntimeError):
    """pcap保存先が固定契約を満たさない。"""


def main() -> None:
    metadata = CAPTURE_ROOT.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or CAPTURE_ROOT.is_symlink():
        raise CaptureEntrypointError("capture rootは通常directoryにしてください")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    prefix = CAPTURE_ROOT / f"winos-{stamp}-{uuid.uuid4().hex}.pcap"
    arguments = [
        "/usr/bin/timeout",
        "--signal=INT",
        "--kill-after=15s",
        CAPTURE_SECONDS,
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
        f"8時間pcapを開始します: prefix={prefix.name} target={TARGET}:{PORT}",
        flush=True,
    )
    os.execv(arguments[0], arguments)


if __name__ == "__main__":
    main()
