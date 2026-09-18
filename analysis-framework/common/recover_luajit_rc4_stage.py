"""LuaJIT bytecodeローダーと暗号化blobから後段を静的に復元する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pefile


MAX_LOADER_BYTES = 1024 * 1024
MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024
MAX_KEY_CANDIDATES = 64
MAX_PE_OFFSET = 1024 * 1024
MIN_PE_BYTES = 4096


class RecoveryRejected(ValueError):
    """構造証拠または上限を満たさない復号候補を拒否する。"""


def rc4_transform(data: bytes, key: bytes) -> bytes:
    """byte列へのRC4変換だけを実施し、復元したコードを実行しない。"""

    if not 8 <= len(key) <= 24 or len(data) > MAX_CIPHERTEXT_BYTES:
        raise RecoveryRejected("鍵または入力長が上限外です")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray(len(data))
    for offset, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def key_candidates(loader: bytes) -> list[bytes]:
    """LuaJIT内の英小文字・数字リテラルを有界で列挙する。"""

    if not loader.startswith(b"\x1bLJ") or len(loader) > MAX_LOADER_BYTES:
        raise RecoveryRejected("LuaJIT bytecodeの形式または長さが不正です")
    required = (b"VirtualAlloc", b"VirtualProtect", b"CreateThread")
    if not all(anchor in loader for anchor in required):
        raise RecoveryRejected("メモリ内ローダーの構造手掛かりが不足しています")
    values = list(
        dict.fromkeys(
            re.findall(rb"(?<![A-Za-z0-9])[a-z0-9]{8,24}(?![A-Za-z0-9])", loader)
        )
    )
    if len(values) > MAX_KEY_CANDIDATES:
        raise RecoveryRejected("復号鍵候補の上限を超えました")
    return values


def find_embedded_pe(blob: bytes) -> tuple[int, bytes, dict[str, Any]] | None:
    """先頭近傍のMZ候補に対してPE headerと全節境界を検証する。"""

    position = 0
    while True:
        position = blob.find(b"MZ", position, min(len(blob), MAX_PE_OFFSET))
        if position < 0:
            return None
        tail = blob[position:]
        position += 2
        if len(tail) < MIN_PE_BYTES:
            continue
        try:
            pe = pefile.PE(data=tail, fast_load=True)
        except pefile.PEFormatError:
            continue
        if pe.FILE_HEADER.Machine not in {0x14C, 0x8664}:
            continue
        if not 1 <= pe.FILE_HEADER.NumberOfSections <= 32:
            continue
        raw_end = max(
            (section.PointerToRawData + section.SizeOfRawData for section in pe.sections),
            default=0,
        )
        if raw_end < MIN_PE_BYTES or raw_end > len(tail):
            continue
        return position - 2, tail, {
            "machine": f"0x{pe.FILE_HEADER.Machine:04x}",
            "section_count": pe.FILE_HEADER.NumberOfSections,
            "minimum_raw_end": raw_end,
            "tail_size": len(tail),
        }


def recover(loader: bytes, ciphertext: bytes) -> tuple[dict[str, Any], bytes, bytes]:
    """鍵候補を試し、構造検証済みの一意な後段だけを返す。"""

    if not ciphertext or len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise RecoveryRejected("暗号化blobの長さが上限外です")
    keys = key_candidates(loader)
    matches: list[tuple[bytes, bytes, int, bytes, dict[str, Any]]] = []
    for key in keys:
        clear = rc4_transform(ciphertext, key)
        found = find_embedded_pe(clear)
        if found is not None:
            offset, pe_bytes, pe_metadata = found
            matches.append((key, clear, offset, pe_bytes, pe_metadata))
    if len(matches) != 1:
        raise RecoveryRejected(f"構造検証済み復号候補が一意ではありません: {len(matches)}")
    key, clear, offset, pe_bytes, pe_metadata = matches[0]
    report = {
        "schema_version": 1,
        "status": "recovered_pe_candidate",
        "loader_sha256": hashlib.sha256(loader).hexdigest(),
        "encrypted_blob_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "key_candidate_count": len(keys),
        "selected_key_sha256": hashlib.sha256(key).hexdigest(),
        "decrypted_stage_sha256": hashlib.sha256(clear).hexdigest(),
        "decrypted_stage_size": len(clear),
        "embedded_pe_offset": offset,
        "embedded_pe_sha256": hashlib.sha256(pe_bytes).hexdigest(),
        "embedded_pe": pe_metadata,
        "evidence_boundary": {
            "rc4_recipe_confirmed_by_bytecode_instruction_review": False,
            "decrypted_pe_is_terminal_payload": False,
            "family_confirmed": False,
            "c2_confirmed": False,
        },
        "safety": {"sample_executed": False, "network_contacted": False},
    }
    return report, clear, pe_bytes


def main() -> int:
    """私有ディレクトリへ復元物、機械可読な来歴を保存する。"""

    parser = argparse.ArgumentParser(description="LuaJITの暗号化後段を実行せずに静的復元します。")
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--encrypted-blob", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    loader = args.loader.read_bytes()
    ciphertext = args.encrypted_blob.read_bytes()
    report, clear, pe_bytes = recover(loader, ciphertext)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "decrypted-stage.quarantine.bin").write_bytes(clear)
    (args.output_dir / "embedded-pe.quarantine.bin").write_bytes(pe_bytes)
    (args.output_dir / "recovery.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
