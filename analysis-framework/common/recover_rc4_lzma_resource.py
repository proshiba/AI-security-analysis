"""PEリソースを指定されたRC4鍵とLZMAで静的復元する。検体は実行しない。"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path

import pefile


MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_RESOURCE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("RC4鍵が空です")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(len(data))
    i = j = 0
    for offset, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def decompress_lzma_alone(data: bytes, *, maximum: int) -> bytes:
    if maximum <= 0:
        raise ValueError("復元上限は正でなければなりません")
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    output = decompressor.decompress(data, max_length=maximum + 1)
    if len(output) > maximum or not decompressor.eof:
        raise ValueError("LZMAの復元上限超過または入力の切断")
    return output


def _resource_bytes(pe: pefile.PE, *, resource_type: int, resource_id: int, language: int) -> bytes:
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if type_entry.id != resource_type:
            continue
        for name_entry in type_entry.directory.entries:
            if name_entry.id != resource_id:
                continue
            for language_entry in name_entry.directory.entries:
                if language_entry.id != language:
                    continue
                info = language_entry.data.struct
                if not 0 < info.Size <= MAX_RESOURCE_BYTES:
                    raise ValueError("リソースのサイズが上限外です")
                result = pe.get_data(info.OffsetToData, info.Size)
                if len(result) != info.Size:
                    raise ValueError("リソースが途中で切れています")
                return result
    raise ValueError("指定したリソースが見つかりません")


def recover(
    source: bytes,
    *,
    expected_sha256: str,
    resource_type: int,
    resource_id: int,
    language: int,
    key_rva: int,
    key_size: int,
    maximum_output: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[bytes, dict[str, object]]:
    source_hash = hashlib.sha256(source).hexdigest()
    if source_hash != expected_sha256.lower():
        raise ValueError("入力SHA-256が一致しません")
    if not 0 < len(source) <= MAX_SOURCE_BYTES:
        raise ValueError("入力サイズが上限外です")
    if not 1 <= key_size <= 256:
        raise ValueError("RC4鍵長が上限外です")
    pe = pefile.PE(data=source, fast_load=False)
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        raise ValueError("PEリソースがありません")
    key = pe.get_data(key_rva, key_size)
    if len(key) != key_size:
        raise ValueError("RC4鍵の読取り範囲が不正です")
    encrypted = _resource_bytes(
        pe, resource_type=resource_type, resource_id=resource_id, language=language
    )
    compressed = rc4_decrypt(encrypted, key)
    payload = decompress_lzma_alone(compressed, maximum=maximum_output)
    if not payload.startswith(b"MZ"):
        raise ValueError("復元結果はPE形式ではありません")
    child = pefile.PE(data=payload, fast_load=True)
    if child.OPTIONAL_HEADER.SizeOfImage <= 0:
        raise ValueError("復元PEのヘッダが不正です")
    report: dict[str, object] = {
        "schema_version": 1,
        "source_sha256": source_hash,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "language": language,
        "encrypted_resource_sha256": hashlib.sha256(encrypted).hexdigest(),
        "encrypted_resource_size": len(encrypted),
        "key_rva": hex(key_rva),
        "key_size": key_size,
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "transform": "rc4_then_lzma_alone",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_size": len(payload),
        "payload_machine": hex(child.FILE_HEADER.Machine),
        "sample_executed": False,
        "network_contacted": False,
    }
    return payload, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--resource-type", type=int, default=10)
    parser.add_argument("--resource-id", type=int, required=True)
    parser.add_argument("--language", type=int, default=1033)
    parser.add_argument("--key-rva", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--key-size", type=int, required=True)
    parser.add_argument("--max-output", type=int, default=DEFAULT_MAX_OUTPUT_BYTES)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    output_dir = args.output_dir.resolve(strict=False)
    if output_dir == repository or repository in output_dir.parents:
        raise ValueError("復元した検体を公開リポジトリ内へ保存できません")
    source = args.input.read_bytes()
    payload, report = recover(
        source,
        expected_sha256=args.expected_sha256,
        resource_type=args.resource_type,
        resource_id=args.resource_id,
        language=args.language,
        key_rva=args.key_rva,
        key_size=args.key_size,
        maximum_output=args.max_output,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{report['payload_sha256']}.quarantine.bin"
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() != report["payload_sha256"]:
            raise ValueError("既存の復元ファイルとSHA-256が一致しません")
    else:
        with target.open("xb") as handle:
            handle.write(payload)
    print(json.dumps({**report, "private_output": str(target)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
