#!/usr/bin/env python3
"""Eazfuscator系managed PEの動的プロキシ表を静的に復号する。

検体、CLR、復号後CILは実行せず、ファイル内resourceだけを解析する。
完全なプロキシ対応表は明示指定時だけ結果へ含める。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import struct
import warnings
from collections import Counter
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    from .managed_metadata import MetadataResolver
except ImportError:  # 単独CLI
    from managed_metadata import MetadataResolver

try:
    from .managed_resource_snapshot import (
        prepare_resource_snapshot,
        revalidated_resource_scan,
    )
except ImportError:  # 単独CLIまたは新依存が不足した状態
    try:
        from managed_resource_snapshot import (
            prepare_resource_snapshot,
            revalidated_resource_scan,
        )
    except ImportError:
        prepare_resource_snapshot = revalidated_resource_scan = None

try:
    from .managed_constructor_guard import preflight_clr_declarations
except ImportError:  # 単独CLIまたは新依存が不足した状態
    try:
        from managed_constructor_guard import preflight_clr_declarations
    except ImportError:
        preflight_clr_declarations = None

try:
    import dnfile
except ImportError:  # pragma: no cover - 依存関係がない環境
    dnfile = None

MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_PROXY_RECORDS = 16_384
MAX_RESOURCE_COUNT = 4_096
MAX_PROXY_TRANSFORMS = 16
_U32_MASK = 0xFFFFFFFF

EAZ_PROXY_TRANSFORMS = (
    {
        "profile": "eazfuscator_dynamic_proxy_v1",
        "seed": 1_383_095_734,
        "addend": 848_575_190,
    },
    {
        "profile": "eazfuscator_dynamic_proxy_v2",
        "seed": 1_039_778_284,
        "addend": 1_651_518_254,
    },
    {
        "profile": "eazfuscator_dynamic_proxy_v3",
        "seed": 305_765_753,
        "addend": 489_775_852,
    },
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
    if len(data) > MAX_PROXY_RECORDS * 8:
        raise ValueError("プロキシ変換byte数が安全上限を超えています")
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
    seen_fields: dict[int, int] = {}
    for offset in range(0, len(clear), 8):
        field_token, encoded_target = struct.unpack_from("<II", clear, offset)
        callvirt = bool(encoded_target & 0x40000000)
        target_token = encoded_target & 0xBFFFFFFF
        reasons = []
        if field_token >> 24 != 0x04 or not field_token & 0xFFFFFF:
            reasons.append("invalid_field_token")
        if target_token >> 24 not in {0x06, 0x0A, 0x2B} or not target_token & 0xFFFFFF:
            reasons.append("invalid_method_token")
        if field_token in seen_fields:
            reasons.append("duplicate_field_mapping")
            earlier = records[seen_fields[field_token]]
            earlier["valid"] = False
            if "duplicate_field_mapping" not in earlier["invalid_reasons"]:
                earlier["invalid_reasons"].append("duplicate_field_mapping")
        else:
            seen_fields[field_token] = len(records)
        records.append(
            {
                "index": offset // 8,
                "field_token": f"0x{field_token:08x}",
                "target_token": f"0x{target_token:08x}",
                "call_kind": "callvirt" if callvirt else "call",
                "valid": not reasons,
                "invalid_reasons": reasons,
            }
        )
    return records


def _validated_proxy_transforms(
    transforms: Iterable[dict[str, Any]] | None,
) -> tuple[dict[str, Any], ...]:
    """重複排除した有界transform集合を返す。"""

    selected = EAZ_PROXY_TRANSFORMS if transforms is None else tuple(transforms)
    if not selected or len(selected) > MAX_PROXY_TRANSFORMS:
        raise ValueError("proxy transform数が安全上限外です")
    result = []
    seen: set[tuple[int, int]] = set()
    for item in selected:
        if not isinstance(item, dict):
            raise TypeError("proxy transformの形式が不正です")
        profile = item.get("profile")
        seed = item.get("seed")
        addend = item.get("addend")
        if (
            not isinstance(profile, str)
            or not profile
            or len(profile) > 128
            or any(ord(char) < 32 or ord(char) == 127 for char in profile)
            or isinstance(seed, bool)
            or not isinstance(seed, int)
            or isinstance(addend, bool)
            or not isinstance(addend, int)
            or not 0 <= seed <= _U32_MASK
            or not 0 <= addend <= _U32_MASK
        ):
            raise ValueError("proxy transformの値が不正です")
        identity = (seed, addend)
        if identity in seen:
            continue
        seen.add(identity)
        result.append({"profile": profile, "seed": seed, "addend": addend})
    if not result:
        raise ValueError("proxy transform候補がありません")
    return tuple(result)


def resource_summary(name: str, content: bytes) -> dict[str, Any]:
    """埋込みresourceの公開可能な静的特徴を返す。"""
    counts = Counter(content)
    entropy = (
        -sum(
            (count / len(content)) * math.log2(count / len(content))
            for count in counts.values()
        )
        if content
        else 0.0
    )
    return {
        "name": name[:512],
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "entropy": round(entropy, 4),
        "protected_candidate": len(content) >= 256 and entropy >= 7.2,
    }


def _consumed_metadata_coverage(resolver, work, scan):
    """元resolverのcoverageを変えず、最新のsource照合を別scopeで公開する。"""
    coverage = resolver.coverage()
    resource_coverage = scan.coverage()
    fresh_work = resource_coverage["work"]
    accepted = (
        work["accepted"] is True
        and resource_coverage["input_binding_verified"] is True
        and fresh_work["shared_snapshot_reused"] is True
    )
    coverage["shared_snapshot"] = {
        **work,
        "accepted": accepted,
        "resource_consumer_source_work": dict(fresh_work),
    }
    if not accepted:
        coverage["complete"] = False
    return coverage


def _preparation_failed_coverage():
    """新依存の失敗をcompleteやno-resourceへ丸めない固定公開診断。"""
    return {
        "status": "partial",
        "inventory_complete": False,
        "embedded_scan_complete": False,
        "input_binding_verified": False,
        "reason_counts": {"resource_snapshot_preparation_failed": 1},
    }


def _resource_blob_scope(data: bytes, pe: Any, *, resource_scan=None):
    """最新のsource証明済みdescriptorだけから本文を取得する。"""
    if resource_scan is None:
        resource_scan, _, _ = prepare_resource_snapshot(
            data,
            pe,
            max_resources=MAX_RESOURCE_COUNT,
            max_resource_bytes=MAX_RESOURCE_BYTES,
        )
    fresh = revalidated_resource_scan(data, resource_scan)
    resources = [
        (
            descriptor.name,
            data[
                descriptor.body_offset : descriptor.body_offset + descriptor.body_size
            ],
        )
        for descriptor in fresh._descriptors
        if descriptor.kind == "embedded"
    ]
    return resources, fresh


def _resource_blobs(data: bytes, pe: Any) -> Iterable[tuple[str, bytes]]:
    """従来Iterable契約を維持し、再検証済み本文だけをyieldする。"""
    resources, _ = _resource_blob_scope(data, pe)
    yield from resources


def analyze_proxy_resources(
    resources: Iterable[tuple[str, bytes]],
    *,
    include_records: bool = False,
    metadata_resolver: MetadataResolver | None = None,
    transforms: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """resource群から妥当な動的プロキシ表候補を抽出する。"""
    reviewed_transforms = _validated_proxy_transforms(transforms)
    candidates = []
    rejected = []
    budget_exhausted = []
    total_bytes = 0
    for resource_index, (name, content) in enumerate(resources):
        if resource_index >= MAX_RESOURCE_COUNT:
            budget_exhausted.append("resources")
            break
        total_bytes += len(content)
        if total_bytes > MAX_RESOURCE_BYTES:
            budget_exhausted.append("resource_bytes")
            break
        if len(content) < 64 or len(content) % 8:
            continue
        if len(content) > MAX_PROXY_RECORDS * 8:
            budget_exhausted.append("proxy_records")
            continue
        for transform in reviewed_transforms:
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
            # 率だけで不正recordを含む表全体を採用しない。
            if valid_count < 8 or ratio < 0.95:
                continue
            reasons = Counter(
                reason for record in records for reason in record["invalid_reasons"]
            )
            if metadata_resolver is not None:
                for record in records:
                    record["field_resolution"] = metadata_resolver.resolve(
                        int(record["field_token"], 16), kind="field"
                    )
                    record["target_resolution"] = metadata_resolver.resolve(
                        int(record["target_token"], 16)
                    )
                reasons.update(
                    resolution["reason"]
                    for record in records
                    for resolution in (
                        record["field_resolution"],
                        record["target_resolution"],
                    )
                    if resolution["status"] != "resolved"
                )
            if reasons:
                rejected.append(
                    {
                        "resource_sha256": hashlib.sha256(content).hexdigest(),
                        "transform_profile": transform["profile"],
                        "record_count": len(records),
                        "reason_counts": dict(sorted(reasons.items())),
                        "status": "rejected_not_verified_proxy_table",
                    }
                )
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
                "callvirt_count": sum(
                    record["call_kind"] == "callvirt" for record in records
                ),
                "validation_level": "metadata_declaration_validated_candidate"
                if metadata_resolver
                else "syntactic_candidate_only",
                "runtime_dispatch_verified": False,
                "protector_attribution_confirmed": False,
            }
            if include_records:
                item["records"] = records
            candidates.append(item)
            break
    if metadata_resolver is not None and not metadata_resolver.coverage()["complete"]:
        budget_exhausted.append("reference_metadata")
    return {
        "status": "partial_budget"
        if budget_exhausted
        else "matched"
        if candidates
        else "not_matched",
        "profile": "eazfuscator_dynamic_proxy_multi_variant" if candidates else None,
        "candidates": candidates,
        "rejected_candidates": rejected,
        "budget_exhausted": sorted(set(budget_exhausted)),
        "metadata_coverage": metadata_resolver.coverage()
        if metadata_resolver
        else None,
    }


def analyze_managed_protector(
    data: bytes,
    *,
    include_records: bool = False,
    additional_transforms: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """managed PEを実行せずprotector profileを抽出する。"""
    if type(data) is not bytes:
        raise TypeError("dataにはexact bytesを指定してください")
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
        if preflight_clr_declarations is None:
            raise ValueError("metadata_constructor_preflight_dependency_missing")
        metadata_preflight = preflight_clr_declarations(data)
    except Exception:  # noqa: BLE001 - optional parserの例外型は依存版ごとに異なる
        metadata_preflight = {
            "status": "partial",
            "accepted": False,
            "scope": "constructor_declarations_only",
            "input_bound": False,
            "reason_counts": {"preflight_dependency_failed": 1},
        }
    result["metadata_preflight"] = metadata_preflight
    if not metadata_preflight["accepted"]:
        result["status"] = "partial_budget"
        result["budget_exhausted"] = ["metadata_constructor_preflight"]
        result["resource_coverage"] = _preparation_failed_coverage()
        result["reference_metadata_coverage"] = {
            "complete": False,
            "shared_snapshot": {"accepted": False},
        }
        return result
    try:
        with _contained_parser_diagnostics():
            pe = dnfile.dnPE(data=data, clr_lazy_load=True)
        if not getattr(pe, "net", None):
            result["status"] = "not_managed_pe"
            return result
        try:
            if prepare_resource_snapshot is None or revalidated_resource_scan is None:
                raise ValueError("resource_snapshot_dependency_missing")
            resource_scan, resolver, shared_work = prepare_resource_snapshot(
                data,
                pe,
                max_resources=MAX_RESOURCE_COUNT,
                max_resource_bytes=MAX_RESOURCE_BYTES,
            )
            resources, resource_scan = _resource_blob_scope(
                data, pe, resource_scan=resource_scan
            )
            result["resource_coverage"] = resource_scan.coverage()
            result["reference_metadata_coverage"] = _consumed_metadata_coverage(
                resolver, shared_work, resource_scan
            )
        except Exception:  # noqa: BLE001 - snapshot parserの例外型は依存版ごとに異なる
            result["status"] = "partial_budget"
            result["budget_exhausted"] = ["resource_snapshot"]
            result["resource_coverage"] = _preparation_failed_coverage()
            result["reference_metadata_coverage"] = {
                "complete": False,
                "shared_snapshot": {"accepted": False},
            }
            return result
        result["resource_inventory"] = [
            resource_summary(name, content) for name, content in resources
        ]
        supplied_transforms = tuple(additional_transforms or ())
        proxy = analyze_proxy_resources(
            resources,
            include_records=include_records,
            metadata_resolver=resolver,
            transforms=(
                (*EAZ_PROXY_TRANSFORMS, *supplied_transforms)
                if supplied_transforms
                else None
            ),
        )
        proxy["transform_discovery"] = {
            "status": (
                "caller_supplied_static_recipe"
                if supplied_transforms
                else "built_in_profiles_only"
            ),
            "supplied_transform_count": len(supplied_transforms),
        }
        proxy["metadata_coverage"] = result["reference_metadata_coverage"]
        if (
            not result["resource_coverage"]["inventory_complete"]
            or not result["reference_metadata_coverage"]["shared_snapshot"]["accepted"]
        ):
            proxy["status"] = "partial_budget"
            proxy["budget_exhausted"] = sorted(
                set(proxy["budget_exhausted"] + ["resource_inventory"])
            )
        result["proxy_analysis"] = proxy
        result["status"] = (
            "partial_budget"
            if proxy["status"] == "partial_budget"
            or not resolver.coverage()["complete"]
            else "matched"
            if proxy["status"] == "matched"
            else "no_match"
        )
        if proxy["candidates"]:
            result["limitations"] = [
                "proxy表の変換候補とmetadata宣言を照合済みですが、実行時dispatchとprotector帰属は未確認です。",
                "MethodSpecのgeneric引数はsignature上の境界と数だけを確認し、generic制約や実行時型選択は検証しません。",
                "暗号化assembly resourceのsample固有鍵はこのprofileでは復元しません。",
            ]
    except Exception as error:  # noqa: BLE001 - managed metadata parser境界
        result["status"] = "parse_error"
        result["parse_error"] = type(error).__name__
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="managed PEの動的プロキシ表を静的解析する"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--include-records", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = analyze_managed_protector(
        args.input.read_bytes(), include_records=args.include_records
    )
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report["status"] in {"matched", "no_match"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
