#!/usr/bin/env python3
"""LuaJIT ステージ内の置換・反転・Base64・PolyRot ペイロードを静的復元する。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path


PROFILES = {
    "e940": {
        "variable": "UMGYBRK", "header": "|O", "source_alphabet": ";:?,.<>`|!",
        "target_alphabet": "ABCDEFabcd", "expected_sha256": "49c8cedd040f2cd2a1674736f23a375e4dc64741563bf18e532104070ff49350",
    },
    "f146": {
        "variable": "UYCZBVL", "header": "|6", "source_alphabet": ")_-[]{};:?",
        "target_alphabet": "ABCDEFabcd", "expected_sha256": "89feaca882d64b37fab5666a674d6ab5746fd66a28431a335e12e5f712330a74",
    },
}


def inverse_polyrot(data: bytes) -> bytes:
    if not data or not 128 <= data[0] <= 221:
        raise ValueError("PolyRotヘッダーが不正です")
    rotation = 94 - (data[0] - 128)
    return bytes(33 + ((value - 33 + rotation) % 94) if 33 <= value <= 126 else value for value in data[1:])


def recover(text: str, profile_name: str) -> tuple[bytes, dict[str, object]]:
    profile = PROFILES[profile_name]
    match = re.search(r"local\s+" + re.escape(profile["variable"]) + r'\s*=\s*"([^"]+)"', text)
    if not match or not match.group(1).startswith(profile["header"]):
        raise ValueError("対象Lua変数またはヘッダーがありません")
    table = str.maketrans(profile["source_alphabet"], profile["target_alphabet"])
    encoded = match.group(1)[len(profile["header"]):].translate(table)[::-1]
    rotated = base64.b64decode(encoded, validate=True)
    payload = inverse_polyrot(rotated)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != profile["expected_sha256"]:
        raise ValueError("復元ペイロードのSHA-256がレビュー済み値と一致しません")
    return payload, {
        "profile": profile_name, "variable": profile["variable"], "header": profile["header"],
        "sha256": digest, "size": len(payload), "magic_hex": payload[:16].hex(), "executed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--artifact-xor-a5", type=Path)
    args = parser.parse_args()
    payload, report = recover(args.input.read_text(encoding="utf-8"), args.profile)
    if args.artifact_xor_a5:
        args.artifact_xor_a5.write_bytes(bytes(value ^ 0xA5 for value in payload))
        report["artifact_storage"] = "xor-a5"
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json: args.json.write_text(rendered, encoding="utf-8")
    else: print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
