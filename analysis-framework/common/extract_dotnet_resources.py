#!/usr/bin/env python3
""".NETマニフェストリソースを実行せず抽出し、ハッシュ一覧を作成する。"""

from __future__ import annotations

import argparse
import hashlib
from itertools import islice
import json
import re
import stat
import sys
from pathlib import Path

import dnfile

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from unpackers.managed_il_triage import _contain_parser_diagnostics  # noqa: E402


SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
MAX_RESOURCE_INPUT_BYTES = 128 * 1024 * 1024
MAX_RESOURCE_COUNT = 512
MAX_RESOURCE_ENTRY_COUNT = 4096
MAX_RESOURCE_VALUE_BYTES = 64 * 1024 * 1024
MAX_RESOURCE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_SERIALIZED_STRING_BYTES = 64 * 1024 * 1024
BUDGET_WARNING_PREFIX = ".NETリソース表を読めませんでした: 解析上限を超えました:"
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)
RESERVED_OUTPUT_NAMES = frozenset({"manifest.json"})
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ResourceBudgetError(ValueError):
    """resource抽出の明示的な入力・個数・byte上限超過を表す。"""


class ResourceStructureError(ValueError):
    """ResourceSet entryの重複・重なり・境界不正を表す。"""


def safe_name(value: str, index: int) -> str:
    """リソース名をWindows予約名とmanifest衝突のない単一名へ正規化する。"""

    name = SAFE_NAME.sub("_", Path(value.replace(chr(92), "/")).name).strip("._")
    name = name or f"resource-{index:04d}.bin"
    reserved_stem = name.split(".", 1)[0].rstrip(" .").upper()
    if reserved_stem in WINDOWS_RESERVED_NAMES or name.casefold() in RESERVED_OUTPUT_NAMES:
        name = f"resource-{index:04d}-{name}"
    return name


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def reject_existing_reparse_components(path: Path) -> None:
    """既存の出力先componentにsymlink/junction等があれば拒否する。"""

    absolute = path.absolute()
    parts = absolute.parts
    if not parts:
        raise ValueError("出力先パスが空です")
    current = Path(parts[0])
    if _is_reparse_point(current):
        raise ValueError(f"出力先にreparse pointが含まれます: {current}")
    for part in parts[1:]:
        current /= part
        try:
            current.lstat()
        except FileNotFoundError:
            break
        if _is_reparse_point(current):
            raise ValueError(f"出力先にreparse pointが含まれます: {current}")


def _existing_path(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True

def _entry_bytes(value: object) -> tuple[bytes, str] | None:
    if isinstance(value, bytes):
        if len(value) > MAX_RESOURCE_VALUE_BYTES:
            raise ResourceBudgetError("単一resource valueがbyte上限を超えています")
        return value, "binary"
    if isinstance(value, str):
        if len(value) > MAX_RESOURCE_VALUE_BYTES:
            raise ResourceBudgetError("単一resource stringが文字数上限を超えています")
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_RESOURCE_VALUE_BYTES:
            raise ResourceBudgetError("単一resource stringがbyte上限を超えています")
        return encoded, "utf-8"
    return None


def _bounded_items(value: object, limit: int, label: str) -> list[object]:
    try:
        items = list(islice(iter(value or []), limit + 1))
    except TypeError as exc:
        raise ValueError(f"{label}を反復できません") from exc
    if len(items) > limit:
        raise ResourceBudgetError(f"{label}数が{limit}件を超えています")
    return items


def _read_7bit_uint(raw: bytes, offset: int, end: int) -> tuple[int, int]:
    """BinaryReader形式の7-bit非負整数を最大5 byteで読む。"""

    value = 0
    for index in range(5):
        if offset >= end:
            raise ValueError("7-bit整数が切断されています")
        current = raw[offset]
        offset += 1
        if index == 4 and current > 0x0F:
            raise ValueError("7-bit整数が32-bit範囲を超えています")
        value |= (current & 0x7F) << (index * 7)
        if not current & 0x80:
            return value, offset
    raise ValueError("7-bit整数が終端されていません")


def _resource_entry_bounds(
    resource_set: object,
    entries: list[object],
) -> list[tuple[int, int]]:
    """全entryのDataOffsetを一度だけ検証し、重複のない境界を返す。"""

    raw_value = getattr(resource_set, "_data", b"")
    raw = bytes(raw_value) if isinstance(raw_value, (bytes, bytearray)) else b""
    header = getattr(resource_set, "struct", None)
    base = int(getattr(header, "DataSectionOffset", 0) or 0)
    if not raw or not base:
        raise ResourceStructureError("ResourceSet raw dataまたはDataSectionOffsetがありません")
    starts = [
        base + int(getattr(getattr(entry, "struct", None), "DataOffset", 0) or 0)
        for entry in entries
    ]
    if len(starts) != len(set(starts)):
        raise ResourceStructureError("ResourceSet entryのDataOffsetが重複しています")
    if any(start < base or start >= len(raw) for start in starts):
        raise ResourceStructureError("ResourceSet entryのDataOffsetがraw data範囲外です")
    ordered = sorted(starts)
    ends = {start: ordered[index + 1] if index + 1 < len(ordered) else len(raw) for index, start in enumerate(ordered)}
    return [(start, ends[start]) for start in starts]


def _serialized_resource_string(
    resource_set: object,
    entry: object,
    index: int,
    *,
    bounds: tuple[int, int] | None = None,
) -> bytes:
    """ResourceSetのSystem.Stringをentry境界内で厳密に復号する。"""

    raw_value = getattr(resource_set, "_data", b"")
    raw = bytes(raw_value) if isinstance(raw_value, (bytes, bytearray)) else b""
    if not raw:
        raise ResourceStructureError("ResourceSet raw dataがありません")
    if len(raw) > MAX_RESOURCE_TOTAL_BYTES:
        raise ResourceBudgetError("ResourceSet raw dataが総byte上限を超えています")
    if bounds is None:
        entries = _bounded_items(
            getattr(resource_set, "entries", []),
            MAX_RESOURCE_ENTRY_COUNT,
            "ResourceSet entry",
        )
        if not 0 <= index < len(entries):
            raise ResourceStructureError("ResourceSet entry indexがありません")
        bounds = _resource_entry_bounds(resource_set, entries)[index]
    start, end = bounds
    if not 0 <= start < end <= len(raw):
        raise ResourceStructureError("System.String entry境界が不正です")

    try:
        type_code, cursor = _read_7bit_uint(raw, start, end)
    except ValueError as exc:
        raise ResourceStructureError("System.String type codeがentry境界で切断されています") from exc
    if type_code != 1:
        raise ValueError(f"System.Stringの組み込みtype codeではありません: {type_code}")
    try:
        size, cursor = _read_7bit_uint(raw, cursor, end)
    except ValueError as exc:
        raise ResourceStructureError("System.String lengthがentry境界で切断されています") from exc
    if size > MAX_SERIALIZED_STRING_BYTES:
        raise ResourceBudgetError("System.Stringが解析上限を超えています")
    if cursor + size > end:
        raise ResourceStructureError("System.String payloadが次entryへ重なっています")
    value = raw[cursor : cursor + size]
    value.decode("utf-8", errors="strict")
    return value

def _budget_failure(reason: str) -> tuple[list[dict], list[str]]:
    return [], [f"{BUDGET_WARNING_PREFIX} {reason}"]


def _structure_failure(reason: str) -> tuple[list[dict], list[str]]:
    return [], [f".NETリソース表を読めませんでした: {reason}"]


@_contain_parser_diagnostics
def resource_blobs(data: bytes) -> tuple[list[dict], list[str]]:
    """上限内のblob/stringリソースと解析上の警告を返す。"""

    if len(data) > MAX_RESOURCE_INPUT_BYTES:
        return _budget_failure("入力サイズ")
    warnings: list[str] = []
    try:
        pe = dnfile.dnPE(data=data)
    except Exception as exc:
        return [], [f"dnfileでPEを解析できませんでした: {type(exc).__name__}"]
    if pe.net is None:
        return [], ["CLRヘッダーがないため.NETリソースを解析できません。"]
    try:
        resources = _bounded_items(
            pe.net.resources,
            MAX_RESOURCE_COUNT,
            "manifest resource",
        )
    except ResourceBudgetError as exc:
        return _budget_failure(str(exc))
    except Exception as exc:
        return [], [f".NETリソース表を読めませんでした: {type(exc).__name__}"]

    results: list[dict] = []
    output_index = 0
    total_entries = 0
    total_bytes = 0
    total_output_bytes = 0
    for resource in resources:
        try:
            direct = _entry_bytes(resource.data)
        except ResourceBudgetError as exc:
            return _budget_failure(str(exc))
        if direct is not None:
            raw, encoding = direct
            total_bytes += len(raw)
            if total_bytes > MAX_RESOURCE_TOTAL_BYTES:
                return _budget_failure("resource value総byte数")
            total_output_bytes += len(raw)
            if total_output_bytes > MAX_RESOURCE_TOTAL_BYTES:
                return _budget_failure("結果resource value総byte数")
            output_index += 1
            results.append(
                {
                    "index": output_index,
                    "original_name": str(resource.name),
                    "container_name": None,
                    "resource_type": ("manifest_blob" if encoding == "binary" else "System.String"),
                    "value_encoding": encoding,
                    "serialization_validated": True,
                    "output_name": safe_name(str(resource.name), output_index),
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "data": raw,
                }
            )
            continue
        entries_source = getattr(resource.data, "entries", None)
        if entries_source is None:
            warnings.append(f"{resource.name}: 未対応の複合.resources形式です。")
            continue
        remaining = MAX_RESOURCE_ENTRY_COUNT - total_entries
        try:
            entries = _bounded_items(
                entries_source,
                remaining,
                "ResourceSet entry総",
            )
        except ResourceBudgetError as exc:
            return _budget_failure(str(exc))
        total_entries += len(entries)
        raw_value = getattr(resource.data, "_data", None)
        has_serialized_data = isinstance(raw_value, (bytes, bytearray)) and bool(
            int(
                getattr(
                    getattr(resource.data, "struct", None),
                    "DataSectionOffset",
                    0,
                )
                or 0
            )
        )
        entry_bounds: list[tuple[int, int]] | None = None
        if has_serialized_data:
            raw_size = len(raw_value)
            if raw_size > MAX_RESOURCE_VALUE_BYTES:
                return _budget_failure("単一ResourceSet raw data")
            total_bytes += raw_size
            if total_bytes > MAX_RESOURCE_TOTAL_BYTES:
                return _budget_failure("ResourceSet raw data総byte数")
            try:
                entry_bounds = _resource_entry_bounds(resource.data, entries)
            except ResourceStructureError as exc:
                return _structure_failure(str(exc))
        for entry_index, entry in enumerate(entries):
            entry_name = str(getattr(entry, "name", f"entry-{output_index + 1:04d}"))
            resource_type = str(getattr(entry, "type_name", "unknown"))
            serialization_validated = False
            if resource_type == "System.String" and has_serialized_data:
                try:
                    converted = (
                        _serialized_resource_string(
                            resource.data,
                            entry,
                            entry_index,
                            bounds=entry_bounds[entry_index] if entry_bounds else None,
                        ),
                        "utf-8",
                    )
                    serialization_validated = True
                except ResourceBudgetError as exc:
                    return _budget_failure(str(exc))
                except ResourceStructureError as exc:
                    return _structure_failure(str(exc))
                except (UnicodeDecodeError, ValueError) as exc:
                    warnings.append(
                        f"{resource.name}/{entry_name}: System.String境界検証に失敗しました: {type(exc).__name__}"
                    )
                    try:
                        converted = _entry_bytes(getattr(entry, "value", None))
                    except ResourceBudgetError as budget:
                        return _budget_failure(str(budget))
            else:
                try:
                    converted = _entry_bytes(getattr(entry, "value", None))
                except ResourceBudgetError as exc:
                    return _budget_failure(str(exc))
            if converted is None:
                continue
            value, encoding = converted
            if not has_serialized_data:
                total_bytes += len(value)
                if total_bytes > MAX_RESOURCE_TOTAL_BYTES:
                    return _budget_failure("resource entry value総byte数")
            total_output_bytes += len(value)
            if total_output_bytes > MAX_RESOURCE_TOTAL_BYTES:
                return _budget_failure("結果resource entry value総byte数")
            output_index += 1
            results.append(
                {
                    "index": output_index,
                    "original_name": entry_name,
                    "container_name": str(resource.name),
                    "resource_type": resource_type,
                    "value_encoding": encoding,
                    "serialization_validated": serialization_validated,
                    "output_name": safe_name(entry_name, output_index),
                    "size": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                    "data": value,
                }
            )
    return results, warnings


def extract(input_path: Path, output_dir: Path, expected_sha256: str) -> dict:
    """入力hashと全出力先を検証してから、既存fileを上書きせず抽出する。"""

    data = input_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256.lower():
        raise ValueError(f"SHA-256不一致: expected={expected_sha256.lower()} actual={digest}")

    resources, warnings = resource_blobs(data)
    reject_existing_reparse_components(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reject_existing_reparse_components(output_dir)

    used_names: set[str] = set()
    planned: list[tuple[dict, str, Path, bytes]] = []
    for item in resources:
        index = int(item["index"])
        name = safe_name(str(item["output_name"]), index)
        candidate = name
        collision_index = 1
        while candidate.casefold() in used_names:
            candidate = f"{index:04d}-{collision_index:02d}-{name}"
            collision_index += 1
        name = candidate
        used_names.add(name.casefold())
        target = output_dir / name
        reject_existing_reparse_components(target)
        if _existing_path(target):
            raise FileExistsError(f"既存のresource出力は上書きしません: {target}")
        payload = item.get("data")
        if not isinstance(payload, bytes):
            raise TypeError(f"resource出力がbytesではありません: {name}")
        planned.append((item, name, target, payload))

    manifest_path = output_dir / "manifest.json"
    reject_existing_reparse_components(manifest_path)
    if _existing_path(manifest_path):
        raise FileExistsError(f"既存manifestは上書きしません: {manifest_path}")

    public_resources: list[dict] = []
    for item, name, target, payload in planned:
        with target.open("xb") as handle:
            handle.write(payload)
        public_resources.append(
            {key: value for key, value in item.items() if key != "data"}
            | {"output_name": name}
        )

    result = {
        "schema_version": 2,
        "parent_sha256": digest,
        "resource_count": len(public_resources),
        "resources": public_resources,
        "warnings": warnings,
        "executed": False,
        "network_contacted": False,
    }
    with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result

def main() -> int:
    """CLIから入力hash検証付きで.NET resourceを抽出する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    result = extract(args.input, args.output_dir, args.expected_sha256)
    print(json.dumps({"resource_count": result["resource_count"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
