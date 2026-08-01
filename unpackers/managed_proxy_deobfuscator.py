#!/usr/bin/env python3
"""Eazfuscator系managed PEの動的プロキシ表を静的に復号する。

検体、CLR、復号後CILは実行せず、ファイル内resourceだけを解析する。
完全なプロキシ対応表は明示指定時だけ結果へ含める。
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import json
import logging
import math
from pathlib import Path
import struct
from typing import Any, Iterable
import warnings

try:
    import dnfile
except ImportError:  # pragma: no cover - 依存関係がない環境
    dnfile = None

MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_PROXY_RECORDS = 16_384
MAX_RESOURCE_COUNT = 4_096
_U32_MASK = 0xFFFFFFFF

EAZ_PROXY_TRANSFORMS = (
    {"profile": "eazfuscator_dynamic_proxy_v1", "seed": 1_383_095_734, "addend": 848_575_190},
    {"profile": "eazfuscator_dynamic_proxy_v2", "seed": 1_039_778_284, "addend": 1_651_518_254},
)


@contextmanager
def _contained_parser_diagnostics():
    """dnfile／pefileの既知の診断をこの解析scope内だけ抑止する。"""
    previous_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        logging.disable(previous_disable)


def _u32(value: int) -> int:
    return value & _U32_MASK


def decrypt_eaz_proxy_table(
    data: bytes,
    *,
    seed: int = 1_383_095_734,
    addend: int = 848_575_190,
) -> bytes:
    """確認済みEazfuscator系word変換を適用する。"""
    if not data or len(data) % 4:
        raise ValueError("プロキシresource長は4の倍数である必要があります")
    output = bytearray(len(data))
    accumulator = 0
    for index in range(len(data) // 4):
        encrypted = struct.unpack_from("<I", data, index * 4)[0]
        previous = accumulator
        value26 = _u32(seed)
        value27 = 549_118_782
        value28 = 353_686_739
        value29 = previous
        value2a = _u32(addend)
        mixed = _u32(((value26 >> 5) | _u32(value26 << 27)) ^ value29)
        low_pairs = mixed & 0x00FF00FF
        high_pairs = mixed & 0xFF00FF00
        value26 = _u32((high_pairs >> 8) | (low_pairs << 8))
        value27 = _u32(1_298_283_676 - 597_857_876 + 232_318_664)
        value28 = _u32(-value26)
        if value29 == 0:
            value29 = _U32_MASK
        quotient = _u32(value26 // value29 + value29)
        value29 = _u32(value26 - quotient)
        value27 = _u32(9_495 * (value27 & 0xFFFF) - (value27 >> 16))
        value28 = _u32(10_476 * (value28 & 0xFFFF) - (value28 >> 16))
        value26 = _u32(22_014 * value26 + value29)
        value29 = _u32(value29 ^ _u32(value29 << 9))
        value29 = _u32(value29 + value28)
        value29 = _u32(value29 ^ _u32(value29 << 1))
        value29 = _u32(value29 * 2)
        value29 = _u32(value29 ^ (value29 >> 5))
        value29 = _u32(value29 + value2a)
        value29 = _u32(((_u32(value28 << 11) + value26) ^ value28) + value29)
        accumulator = _u32(previous + value29)
        struct.pack_into("<I", output, index * 4, accumulator ^ encrypted)
    return bytes(output)


def parse_proxy_records(clear: bytes) -> list[dict[str, Any]]:
    """復号済み8-byteプロキシrecordを解析する。"""
    if not clear or len(clear) % 8:
        raise ValueError("復号済みプロキシ表の長さは8の倍数である必要があります")
    if len(clear) // 8 > MAX_PROXY_RECORDS:
        raise ValueError("プロキシrecord数が安全上限を超えています")
    records = []
    for offset in range(0, len(clear), 8):
        field_token, encoded_target = struct.unpack_from("<II", clear, offset)
        callvirt = bool(encoded_target & 0x40000000)
        target_token = encoded_target & 0xBFFFFFFF
        records.append({
            "index": offset // 8,
            "field_token": f"0x{field_token:08x}",
            "target_token": f"0x{target_token:08x}",
            "call_kind": "callvirt" if callvirt else "call",
            "valid": field_token >> 24 == 0x04 and target_token >> 24 in {0x06, 0x0A, 0x2B},
        })
    return records


def resource_summary(name: str, content: bytes) -> dict[str, Any]:
    """埋込みresourceの公開可能な静的特徴を返す。"""
    counts = Counter(content)
    entropy = -sum((count / len(content)) * math.log2(count / len(content)) for count in counts.values()) if content else 0.0
    return {
        "name": name[:512],
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "entropy": round(entropy, 4),
        "protected_candidate": len(content) >= 256 and entropy >= 7.2,
    }


def _resource_blobs(data: bytes, pe: Any) -> Iterable[tuple[str, bytes]]:
    table = getattr(getattr(pe.net, "mdtables", None), "ManifestResource", None)
    rows = getattr(table, "rows", ()) or ()
    base_rva = int(pe.net.struct.ResourcesRva)
    for index, row in enumerate(rows):
        if index >= MAX_RESOURCE_COUNT:
            break
        if getattr(row, "Implementation", None) is not None:
            continue
        header_offset = int(pe.get_offset_from_rva(base_rva + int(row.Offset)))
        if not 0 <= header_offset <= len(data) - 4:
            continue
        size = struct.unpack_from("<I", data, header_offset)[0]
        start = header_offset + 4
        if size <= MAX_RESOURCE_BYTES and size <= len(data) - start:
            yield str(row.Name), data[start : start + size]


def analyze_proxy_resources(resources: Iterable[tuple[str, bytes]], *, include_records: bool = False) -> dict[str, Any]:
    """resource群から妥当な動的プロキシ表候補を抽出する。"""
    candidates = []
    for name, content in resources:
        if len(content) < 64 or len(content) % 8:
            continue
        for transform in EAZ_PROXY_TRANSFORMS:
            try:
                clear = decrypt_eaz_proxy_table(
                    content,
                    seed=int(transform["seed"]),
                    addend=int(transform["addend"]),
                )
                records = parse_proxy_records(clear)
            except (ArithmeticError, ValueError):
                continue
            valid_count = sum(bool(record["valid"]) for record in records)
            ratio = valid_count / len(records)
            if valid_count < 8 or ratio < 0.95:
                continue
            item = {
                "resource_name": name,
                "resource_sha256": hashlib.sha256(content).hexdigest(),
                "resource_size": len(content),
                "clear_sha256": hashlib.sha256(clear).hexdigest(),
                "transform_profile": transform["profile"],
                "record_count": len(records),
                "valid_record_count": valid_count,
                "valid_record_ratio": round(ratio, 4),
                "call_count": sum(record["call_kind"] == "call" for record in records),
                "callvirt_count": sum(record["call_kind"] == "callvirt" for record in records),
            }
            if include_records:
                item["records"] = records
            candidates.append(item)
            break
    return {
        "status": "matched" if candidates else "not_matched",
        "profile": "eazfuscator_dynamic_proxy_multi_variant" if candidates else None,
        "candidates": candidates,
    }


def analyze_managed_protector(data: bytes, *, include_records: bool = False) -> dict[str, Any]:
    """managed PEを実行せずprotector profileを抽出する。"""
    result = {
        "schema_version": 1,
        "analysis": "static_managed_proxy_deobfuscation",
        "status": "not_started",
        "sha256": hashlib.sha256(data).hexdigest(),
        "executed": False,
        "emulated": False,
        "clr_loaded": False,
        "network_contacted": False,
        "proxy_analysis": None,
        "resource_inventory": [],
        "limitations": [],
    }
    if len(data) > MAX_INPUT_BYTES:
        result["status"] = "input_too_large"
        return result
    if dnfile is None:
        result["status"] = "dependency_missing"
        return result
    try:
        with _contained_parser_diagnostics():
            pe = dnfile.dnPE(data=data)
        if not getattr(pe, "net", None):
            result["status"] = "not_managed_pe"
            return result
        resources = list(_resource_blobs(data, pe))
        result["resource_inventory"] = [resource_summary(name, content) for name, content in resources]
        proxy = analyze_proxy_resources(resources, include_records=include_records)
        result["proxy_analysis"] = proxy
        result["status"] = "matched" if proxy["status"] == "matched" else "no_match"
        if proxy["status"] == "matched":
            result["limitations"] = [
                "動的プロキシ表は復元済みだが、呼出し先本体の仮想化解除は別工程です。",
                "暗号化assembly resourceのsample固有鍵はこのprofileでは復元しません。",
            ]
    except Exception as error:
        result["status"] = "parse_error"
        result["parse_error"] = type(error).__name__
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="managed PEの動的プロキシ表を静的解析する")
    parser.add_argument("input", type=Path)
    parser.add_argument("--include-records", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = analyze_managed_protector(args.input.read_bytes(), include_records=args.include_records)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report["status"] in {"matched", "no_match"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
