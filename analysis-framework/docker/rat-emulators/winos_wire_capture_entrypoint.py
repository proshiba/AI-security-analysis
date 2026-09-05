#!/usr/bin/env python3
"""固定Winos endpointのpcapを容量制限付きで循環保存する。"""

from __future__ import annotations

import argparse
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
MAXIMUM_CAPTURE_FILES = 256


class CaptureEntrypointError(RuntimeError):
    """pcap保存先が固定契約を満たさない。"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--continuous", action="store_true", help="8時間timeoutを付けず循環captureを続ける")
    args = parser.parse_args()
    metadata = CAPTURE_ROOT.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or CAPTURE_ROOT.is_symlink():
        raise CaptureEntrypointError("capture rootは通常directoryにしてください")
    existing = list(CAPTURE_ROOT.glob("winos-*.pcap*"))
    if len(existing) + FILES_PER_PROCESS > MAXIMUM_CAPTURE_FILES:
        raise CaptureEntrypointError("pcap保管が必要です。既存fileは削除しません")
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
    if args.continuous:
        arguments = arguments[4:]
    print(
        f"pcapを開始します: continuous={args.continuous} prefix={prefix.name} target={TARGET}:{PORT}",
        flush=True,
    )
    os.execv(arguments[0], arguments)


if __name__ == "__main__":
    main()
