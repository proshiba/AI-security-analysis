#!/usr/bin/env python3
"""e629のcPHa画素列後段にあるMist変換を静的に再現する。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


REVIEWED_SOURCE_SHA256 = "3d7e4c197f7b7b85099d3a7890689e22dd17fd44a3b84c01b0e0c56fa2b1b936"
REVIEWED_OUTPUT_SHA256 = "000341162792d707cb5777cf67e0b466ed76d3562c9b10a93c1eec7d94df96aa"
ENCODED_KEY = bytes.fromhex("006700790068")
KEY_CYCLE = ENCODED_KEY[:3]
SEED_XOR = 112


def is_pe(data: bytes) -> bool:
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    return 0 <= offset <= len(data) - 4 and data[offset : offset + 4] == b"PE\0\0"


def mist_transform(data: bytes, *, enforce_reviewed_hash: bool = True) -> bytes:
    """CILで確認した反復XORを適用する。同じ関数で逆変換できる。"""
    digest = hashlib.sha256(data).hexdigest()
    if enforce_reviewed_hash and digest != REVIEWED_SOURCE_SHA256:
        raise ValueError("レビュー済みe629 cPHa画素payloadのSHA-256と一致しません")
    if not data:
        raise ValueError("空データは変換できません")
    seed = data[-1] ^ SEED_XOR
    return bytes(
        value ^ seed ^ KEY_CYCLE[index % len(KEY_CYCLE)]
        for index, value in enumerate(data)
    )


def analyze(data: bytes) -> tuple[dict[str, object], bytes]:
    output = mist_transform(data)
    output_sha256 = hashlib.sha256(output).hexdigest()
    if output_sha256 != REVIEWED_OUTPUT_SHA256 or not is_pe(output):
        raise ValueError("Mist変換後のPEがレビュー済み値と一致しません")
    return {
        "schema_version": 1,
        "classification": "unclassified_managed_image_loader",
        "reported_label": "AgentTesla",
        "reported_label_confirmed": False,
        "source": {
            "role": "cPHa_BGRA_pixel_payload",
            "sha256": REVIEWED_SOURCE_SHA256,
            "size": len(data),
        },
        "algorithm": {
            "encoded_key_hex": ENCODED_KEY.hex(),
            "cycle_length": len(KEY_CYCLE),
            "seed_expression": "source_last_byte XOR 112",
            "seed": data[-1] ^ SEED_XOR,
            "byte_expression": "source[i] XOR seed XOR key[i % 3]",
        },
        "decoded": {
            "role": "WinTune_managed_PE",
            "sha256": output_sha256,
            "size": len(output),
            "valid_pe": True,
            "content_published": False,
        },
        "next_layer": {
            "resource_sha256": "25ad43a0a65964a0542e5d5952378201667e46617f97554fea7dba487b66f1c3",
            "pretransform_or_vm_status": "unresolved",
            "final_family": "unresolved",
            "c2": [],
        },
        "emulation": {
            "cpu_or_clr_execution": False,
            "network_contacted": False,
            "process_started": False,
            "files_written_by_default": False,
        },
    }, output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--private-payload-output",
        type=Path,
        help="git管理外の隔離先へだけ復元PEを保存する",
    )
    args = parser.parse_args()
    report, payload = analyze(args.source.read_bytes())
    if args.private_payload_output:
        args.private_payload_output.write_bytes(payload)
        report["decoded"]["private_output_written"] = True
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
