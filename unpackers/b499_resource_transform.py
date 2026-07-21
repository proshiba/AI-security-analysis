#!/usr/bin/env python3
"""b499 reviewed .NETリソースから保護PEを非実行で復元する。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path


REVIEWED_RESOURCE_SHA256 = "ffcf2c8636f04ceed6f6a47b063aa836939df61c6e11daf84077fa0f4211f031"
EXPECTED_PAYLOAD_SHA256 = "7b39dffa112396ab085484fdb0000512d84b3df040d69eb611d91800d8ceab63"


def _int32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def transform(data: bytes) -> bytes:
    """Run.Program.chapterで確認したunchecked Int32変換を適用する。"""
    state_a = 17937
    state_b = 50497
    output = bytearray(data)
    for index, value in enumerate(output):
        state_b = _int32((state_b ^ index) * 31)
        state_a = _int32((state_a + state_b) ^ 13)
        temporary = value ^ (state_a & 0xFF)
        output[index] = ((temporary - state_b) ^ 45) & 0xFF
        state_b = _int32(state_b + output[index])
    return bytes(output)


def recover(resource_data: bytes) -> tuple[dict[str, object], bytes]:
    """reviewed Dataエントリの欠落先頭1バイトと終端を厳密に補正する。"""
    digest = hashlib.sha256(resource_data).hexdigest()
    if digest != REVIEWED_RESOURCE_SHA256:
        raise ValueError("reviewed b499 DataリソースのSHA-256と一致しません")
    boundary = resource_data.find(b"@")
    if boundary != 140631:
        raise ValueError("次の.NET Resourcesエントリ境界が期待位置にありません")
    encoded = b"w" + resource_data[:boundary]
    decoded = base64.b64decode(encoded, validate=True)
    payload = transform(decoded)
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    if payload_sha256 != EXPECTED_PAYLOAD_SHA256:
        raise ValueError("復元PEのSHA-256が期待値と一致しません")
    report: dict[str, object] = {
        "schema_version": 1,
        "profile": "b499-run-program-chapter",
        "source_sha256": digest,
        "base64_size": len(encoded),
        "decoded_size": len(decoded),
        "payload_sha256": payload_sha256,
        "payload_size": len(payload),
        "is_pe": payload.startswith(b"MZ"),
        "executed": False,
        "network_contacted": False,
        "family_status": "終端ファミリー未確定",
    }
    return report, payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("resource", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    report, payload = recover(args.resource.read_bytes())
    if args.output:
        args.output.write_bytes(payload)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
