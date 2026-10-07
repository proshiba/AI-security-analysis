#!/usr/bin/env python3
"""上限付きbyte変換を宣言型プロファイルから静的に適用する。"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import time
from typing import Any, Mapping

import pefile

from unpackers.donut_unpacker import DONUT_LOADER_PROLOGUES, MAX_LOADER_PREFIX_SIZE
from unpackers.bounded_pe_scan import inspect_structural_pe_extent


DEFAULT_PROFILE_PATH = (
    Path(__file__).resolve().parent / "profiles" / "byte_transforms.json"
)
PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
ALLOWED_FORMATS = {
    "any",
    "data",
    "pe",
    "script",
    "zip",
    "7z",
    "cab",
    "rar",
    "xz",
    "png",
    "asar",
    "elf",
    "pdf",
    "java-class",
    "apple-disk-image",
    "autoit-a3x",
    "ole",
    "rtf",
    "macho",
}
ALLOWED_OPERATIONS = {
    "reverse",
    "rotate_left",
    "rotate_right",
    "xor_byte",
    "xor_repeating",
    "slice",
}
ALLOWED_VALIDATORS = {"donut_shellcode", "magic", "pe", "zip"}
MAX_INPUT_SIZE = 64 * 1024 * 1024
MAX_PROFILES = 128
MAX_OPERATIONS = 16
MAX_PROFILE_DOCUMENT_SIZE = 1024 * 1024
MAX_VALIDATOR_STRIDES = 16
MAX_MAGIC_BYTES = 4096
MAX_TRANSFORM_WORK_BYTES = 256 * 1024 * 1024
MAX_RETAINED_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_TRANSFORM_ELAPSED_SECONDS = 10.0
MAX_ZIP_VALIDATOR_MEMBERS = 4096
MAX_DONUT_HEADER_PROBES = 4096
MAX_DONUT_HEADER_CANDIDATES = 256
MAX_DONUT_HEADER_OFFSETS = 16
_ZIP_EOCD = struct.Struct("<4sHHHHIIH")
_ZIP_CENTRAL = struct.Struct("<4s6H3I5H2I")
_ZIP_LOCAL = struct.Struct("<4s5H3I2H")


class TransformProfileError(ValueError):
    """変換プロファイルまたは変換結果が契約を満たさない場合に送出する。"""


class _TransformBudgetExceeded(TransformProfileError):
    """変換の合計処理量・時間・保持量が上限へ達したことを示す。"""

    def __init__(self, reason: str, validation: dict[str, Any] | None = None):
        self.reason = reason
        self.validation = validation
        super().__init__("宣言型byte変換の共有予算を超過しました")


@dataclass
class _TransformBudget:
    """一呼出し内で全プロファイルが共有する静的変換予算。"""

    maximum_work_bytes: int
    maximum_artifact_bytes: int
    deadline: float
    work_bytes: int = 0
    artifact_bytes: int = 0
    operation_bytes: int = 0
    validator_bytes: int = 0

    def check_time(self) -> None:
        """操作境界の時刻を確認する。進行中のPython操作は強制中断しない。"""

        if time.monotonic() >= self.deadline:
            raise _TransformBudgetExceeded("elapsed_time_limit")

    def consume(self, size: int, *, validator: bool = False) -> None:
        """操作入力またはvalidator観測byte数を実処理前に予約する。"""

        self.check_time()
        if size > self.maximum_work_bytes - self.work_bytes:
            raise _TransformBudgetExceeded("validator_work_bytes_limit" if validator else "operation_bytes_limit")
        self.work_bytes += size
        if validator:
            self.validator_bytes += size
        else:
            self.operation_bytes += size

    def retain(self, size: int) -> None:
        """構造検証済み成果物の保持量を追加前に検証する。"""

        self.check_time()
        if size > self.maximum_artifact_bytes - self.artifact_bytes:
            raise _TransformBudgetExceeded("retained_artifact_bytes_limit")
        self.artifact_bytes += size


def _make_budget(max_work_bytes: int, max_artifact_bytes: int, max_elapsed_seconds: float) -> _TransformBudget:
    """単一／複数profileが同じdown-only hard limitを使う。"""

    _integer(max_work_bytes, "max_work_bytes", 1, MAX_TRANSFORM_WORK_BYTES)
    _integer(max_artifact_bytes, "max_artifact_bytes", 1, MAX_RETAINED_ARTIFACT_BYTES)
    if (not isinstance(max_elapsed_seconds, (int, float)) or isinstance(max_elapsed_seconds, bool)
            or not 0 < max_elapsed_seconds <= MAX_TRANSFORM_ELAPSED_SECONDS or not math.isfinite(max_elapsed_seconds)):
        raise TransformProfileError("変換の時間上限が不正です")
    return _TransformBudget(max_work_bytes, max_artifact_bytes, time.monotonic() + max_elapsed_seconds)


def _budget_report(budget: _TransformBudget, max_elapsed_seconds: float) -> dict[str, Any]:
    """値やbyte本体を含めず、事前予約した作業・保持予算だけを公開する。"""

    return {
        "maximum_work_bytes": budget.maximum_work_bytes,
        "maximum_artifact_bytes": budget.maximum_artifact_bytes,
        "maximum_elapsed_seconds": max_elapsed_seconds,
        "operation_input_bytes": budget.operation_bytes,
        "validator_probe_bytes": budget.validator_bytes,
        "total_work_bytes": budget.work_bytes,
        "retained_artifact_bytes": budget.artifact_bytes,
        "deadline_checked_at_operation_boundaries": True,
    }


def _fields(value: Mapping[str, Any], required: set[str], optional: set[str]) -> None:
    """未知の設定keyと欠落した必須keyを固定診断で拒否する。"""

    keys = set(value)
    if not required <= keys or keys - required - optional:
        raise TransformProfileError("プロファイルの設定keyが契約と一致しません")


def sha256_bytes(data: bytes) -> str:
    """小文字のSHA-256を返す。"""

    return hashlib.sha256(data).hexdigest()


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TransformProfileError(f"{field}は整数である必要があります")
    if not minimum <= value <= maximum:
        raise TransformProfileError(
            f"{field}は{minimum}から{maximum}の範囲で指定してください"
        )
    return value


def _hex_bytes(value: object, field: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_MAGIC_BYTES * 2
        or len(value) % 2
        or re.fullmatch(r"[0-9a-fA-F]+", value) is None
    ):
        raise TransformProfileError(f"{field}は空でないhex文字列である必要があります")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise TransformProfileError(f"{field}が不正なhexです") from exc
    if not result:
        raise TransformProfileError(f"{field}を空にできません")
    return result


def _validate_operation(value: object, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TransformProfileError(f"operations[{index}]はobjectである必要があります")
    operation = value.get("operation")
    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise TransformProfileError("未対応operationです")
    required = {"operation"}
    optional: set[str] = set()
    if operation in {"rotate_left", "rotate_right"}:
        required.add("amount")
    elif operation == "xor_byte":
        required.add("key")
    elif operation == "xor_repeating":
        required.add("key_hex")
    elif operation == "slice":
        optional.update({"offset", "length"})
    _fields(value, required, optional)
    normalized: dict[str, Any] = {"operation": operation}
    if operation in {"rotate_left", "rotate_right"}:
        normalized["amount"] = _integer(
            value.get("amount"),
            f"operations[{index}].amount",
            0,
            2**63 - 1,
        )
    elif operation == "xor_byte":
        normalized["key"] = _integer(
            value.get("key"),
            f"operations[{index}].key",
            0,
            255,
        )
    elif operation == "xor_repeating":
        key = _hex_bytes(value.get("key_hex"), f"operations[{index}].key_hex")
        if len(key) > 4096:
            raise TransformProfileError("xor_repeating keyが4096 bytesを超えています")
        normalized["key"] = key
    elif operation == "slice":
        normalized["offset"] = _integer(
            value.get("offset", 0),
            f"operations[{index}].offset",
            0,
            MAX_INPUT_SIZE,
        )
        length = value.get("length")
        normalized["length"] = (
            None
            if length is None
            else _integer(
                length,
                f"operations[{index}].length",
                0,
                MAX_INPUT_SIZE,
            )
        )
    return normalized


def _validate_validator(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TransformProfileError("validatorはobjectである必要があります")
    validator_type = value.get("type")
    if not isinstance(validator_type, str) or validator_type not in ALLOWED_VALIDATORS:
        raise TransformProfileError("未対応validatorです")
    _fields(
        value,
        {"type", "magic_hex"} if validator_type == "magic" else {"type"},
        {"offset"} if validator_type == "magic" else
        ({"strides"} if validator_type == "donut_shellcode" else set()),
    )
    normalized: dict[str, Any] = {"type": validator_type}
    if validator_type == "donut_shellcode":
        strides = value.get("strides", [1])
        if not isinstance(strides, list) or not 1 <= len(strides) <= MAX_VALIDATOR_STRIDES:
            raise TransformProfileError(
                "donut_shellcode.stridesは空でない配列が必要です"
            )
        normalized["strides"] = tuple(
            _integer(item, "donut_shellcode.strides", 1, 4096) for item in strides
        )
        if len(set(normalized["strides"])) != len(normalized["strides"]):
            raise TransformProfileError("donut_shellcode.stridesが重複しています")
    elif validator_type == "magic":
        normalized["magic"] = _hex_bytes(value.get("magic_hex"), "magic_hex")
        offset = _integer(value.get("offset", 0), "magic.offset", 0, MAX_INPUT_SIZE)
        normalized["offset"] = offset
    return normalized


def validate_profile(value: object) -> dict[str, Any]:
    """一つの変換プロファイルを検証・正規化する。"""

    if not isinstance(value, Mapping):
        raise TransformProfileError("profileはobjectである必要があります")
    _fields(
        value,
        {"id", "artifact_kind", "operations", "validator"},
        {"description", "input_formats", "name_suffixes", "min_input_size", "max_input_size"},
    )
    profile_id = value.get("id")
    artifact_kind = value.get("artifact_kind")
    if not isinstance(profile_id, str) or PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise TransformProfileError("profile.idが不正です")
    if (
        not isinstance(artifact_kind, str)
        or PROFILE_ID_RE.fullmatch(artifact_kind) is None
    ):
        raise TransformProfileError("artifact_kindが不正です")
    formats = value.get("input_formats", ["any"])
    if (
        not isinstance(formats, list)
        or not 1 <= len(formats) <= len(ALLOWED_FORMATS)
        or any(not isinstance(item, str) or item not in ALLOWED_FORMATS for item in formats)
        or len(set(formats)) != len(formats)
    ):
        raise TransformProfileError("input_formatsが不正です")
    suffixes = value.get("name_suffixes", [])
    if not isinstance(suffixes, list) or len(suffixes) > 32 or any(
        not isinstance(item, str)
        or re.fullmatch(r"\.[A-Za-z0-9_-]{1,63}", item) is None for item in suffixes
    ):
        raise TransformProfileError("name_suffixesが不正です")
    if len({item.casefold() for item in suffixes}) != len(suffixes):
        raise TransformProfileError("name_suffixesが重複しています")
    description = value.get("description", "")
    if (
        not isinstance(description, str)
        or len(description) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in description)
    ):
        raise TransformProfileError("descriptionが不正です")
    operations = value.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_OPERATIONS:
        raise TransformProfileError(
            f"operationsは1から{MAX_OPERATIONS}件で指定してください"
        )
    maximum = _integer(
        value.get("max_input_size", MAX_INPUT_SIZE),
        "max_input_size",
        1,
        MAX_INPUT_SIZE,
    )
    minimum = _integer(
        value.get("min_input_size", 1),
        "min_input_size",
        1,
        maximum,
    )
    return {
        "id": profile_id,
        "description": description,
        "artifact_kind": artifact_kind,
        "input_formats": frozenset(formats),
        "name_suffixes": tuple(item.casefold() for item in suffixes),
        "min_input_size": minimum,
        "max_input_size": maximum,
        "operations": tuple(
            _validate_operation(item, index) for index, item in enumerate(operations)
        ),
        "validator": _validate_validator(value.get("validator")),
    }


@lru_cache(maxsize=16)
def _load_profiles_cached(
    raw: bytes,
) -> tuple[dict[str, Any], ...]:
    """検証した同一handleの文書bytesだけをcache keyにする。"""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise TransformProfileError("JSON設定keyが重複しています")
            result[key] = item
        return result

    def reject_constant(_value: str) -> None:
        raise TransformProfileError("JSONに非有限値を使用できません")

    try:
        document = json.loads(
            raw.decode("utf-8-sig"), object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TransformProfileError("変換プロファイルのJSONが不正です") from exc
    if (
        not isinstance(document, Mapping)
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
    ):
        raise TransformProfileError("変換プロファイルのschema_versionが不正です")
    _fields(document, {"schema_version", "profiles"}, set())
    values = document.get("profiles")
    if not isinstance(values, list) or len(values) > MAX_PROFILES:
        raise TransformProfileError(f"profilesは最大{MAX_PROFILES}件の配列が必要です")
    profiles: list[dict[str, Any]] = []
    ids: set[str] = set()
    for value in values:
        profile = validate_profile(value)
        if profile["id"] in ids:
            raise TransformProfileError(f"profile idが重複しています: {profile['id']}")
        ids.add(profile["id"])
        profiles.append(profile)
    return tuple(profiles)


def _bounded_regular_file_bytes(path: Path, maximum_size: int) -> bytes:
    """CLI入力と設定に共通する、通常fileの単一handle有界snapshot。"""

    absolute = Path(os.path.abspath(path))
    directories: list[tuple[Path, int, int]] = []
    for component in (absolute, *absolute.parents):
        information = component.lstat()
        if stat.S_ISLNK(information.st_mode) or getattr(information, "st_file_attributes", 0) & 0x400:
            raise TransformProfileError("入力fileのlinkまたはreparseを使用できません")
        if component != absolute:
            directories.append((component, information.st_dev, information.st_ino))
    before = absolute.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 1 <= before.st_size <= maximum_size
    ):
        raise TransformProfileError("入力fileの型・size・link数が不正です")

    def identity(information: os.stat_result) -> tuple[int, ...]:
        return (
            information.st_dev, information.st_ino, information.st_size,
            information.st_mtime_ns, information.st_nlink,
        )

    with absolute.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if identity(before) != identity(opened):
            raise TransformProfileError("プロファイルfileが読込前に変更されました")
        raw = stream.read(maximum_size + 1)
        after = os.fstat(stream.fileno())
    path_after = absolute.lstat()
    # Windowsのpath statとhandle statはctimeの意味が異なるため、同じ取得方式内で比較する。
    if (
        len(raw) != before.st_size
        or identity(before) != identity(after)
        or identity(before) != identity(path_after)
        or opened.st_ctime_ns != after.st_ctime_ns
        or before.st_ctime_ns != path_after.st_ctime_ns
        or stat.S_ISLNK(path_after.st_mode)
        or getattr(path_after, "st_file_attributes", 0) & 0x400
    ):
        raise TransformProfileError("プロファイルfileが読込中に変更されました")
    for component, device, inode in directories:
        information = component.lstat()
        if (
            information.st_dev != device or information.st_ino != inode
            or not stat.S_ISDIR(information.st_mode)
            or getattr(information, "st_file_attributes", 0) & 0x400
        ):
            raise TransformProfileError("入力の親directoryが読込中に変更されました")
    return raw


def load_profiles(
    path: Path = DEFAULT_PROFILE_PATH,
) -> tuple[dict[str, Any], ...]:
    """通常fileを有界・単一handleで検証し、独立copyの設定を返す。"""

    raw = _bounded_regular_file_bytes(path, MAX_PROFILE_DOCUMENT_SIZE)
    # sizeとmtimeだけが同じ別内容、または返却dictの変更でcacheを汚染しない。
    return copy.deepcopy(_load_profiles_cached(raw))


def apply_operations(
    data: bytes,
    operations: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
    *,
    max_input_size: int = MAX_INPUT_SIZE,
    _budget: _TransformBudget | None = None,
) -> bytes:
    """許可リストにある可逆byte操作を順番どおり適用する。"""

    if not isinstance(data, bytes):
        raise TransformProfileError("入力はimmutable bytesで指定してください")
    _integer(max_input_size, "max_input_size", 1, MAX_INPUT_SIZE)
    if not isinstance(operations, (tuple, list)) or not 1 <= len(operations) <= MAX_OPERATIONS:
        raise TransformProfileError("操作列の型または件数が不正です")
    if not data:
        raise TransformProfileError("入力を空にできません")
    if len(data) > max_input_size:
        raise TransformProfileError(f"入力が上限 {max_input_size} bytesを超えています")
    current = data
    budget = _budget or _make_budget(MAX_TRANSFORM_WORK_BYTES, MAX_RETAINED_ARTIFACT_BYTES, MAX_TRANSFORM_ELAPSED_SECONDS)
    for item in operations:
        if not isinstance(item, Mapping):
            raise TransformProfileError("操作はobjectで指定してください")
        operation = item.get("operation")
        if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
            raise TransformProfileError("未対応operationです")
        required = {"operation"}
        if operation in {"rotate_left", "rotate_right"}:
            required.add("amount")
            _integer(item.get("amount"), "amount", 0, 2**63 - 1)
        elif operation == "xor_byte":
            required.add("key")
            _integer(item.get("key"), "key", 0, 255)
        elif operation == "xor_repeating":
            required.add("key")
            key = item.get("key")
            if not isinstance(key, bytes) or not 1 <= len(key) <= 4096:
                raise TransformProfileError("繰り返しXOR鍵が不正です")
        elif operation == "slice":
            required.update({"offset", "length"})
            _integer(item.get("offset"), "offset", 0, MAX_INPUT_SIZE)
            if item.get("length") is not None:
                _integer(item.get("length"), "length", 0, MAX_INPUT_SIZE)
        _fields(item, required, set())
        budget.consume(len(current))
        if operation == "reverse":
            current = current[::-1]
        elif operation in {"rotate_left", "rotate_right"}:
            shift = int(item["amount"]) % len(current)
            if shift:
                current = (
                    current[shift:] + current[:shift]
                    if operation == "rotate_left"
                    else current[-shift:] + current[:-shift]
                )
        elif operation == "xor_byte":
            key = int(item["key"])
            current = bytes(value ^ key for value in current)
        elif operation == "xor_repeating":
            key = bytes(item["key"])
            current = bytes(
                value ^ key[index % len(key)] for index, value in enumerate(current)
            )
        elif operation == "slice":
            offset = int(item["offset"])
            length = item["length"]
            current = (
                current[offset:]
                if length is None
                else current[offset : offset + int(length)]
            )
        else:
            raise TransformProfileError(f"未対応operationです: {operation}")
        if not current:
            raise TransformProfileError(f"{operation}の結果が空になりました")
        if len(current) > max_input_size:
            raise TransformProfileError(
                f"{operation}の結果が上限 {max_input_size} bytesを超えています"
            )
        budget.check_time()
    return current


def _validate_zip_headers(data: bytes) -> tuple[bool, dict[str, Any]]:
    """ZIPを展開せず、通常ZIPの宣言件数・central/local境界を照合する。"""

    evidence: dict[str, Any] = {
        "type": "zip",
        "parse_status": "structural_bounds_rejected",
        "member_content_read": False,
        "content_crc_verified": False,
    }

    def reject(reason: str) -> tuple[bool, dict[str, Any]]:
        return False, {**evidence, "reason": reason}

    offset = data.rfind(b"PK\x05\x06", max(0, len(data) - 65535 - _ZIP_EOCD.size))
    if offset < 0 or offset + _ZIP_EOCD.size > len(data):
        return reject("missing_or_truncated_eocd")
    _, disk, central_disk, disk_count, count, central_size, central_offset, comment_size = _ZIP_EOCD.unpack_from(data, offset)
    if disk or central_disk or disk_count != count:
        return reject("unsupported_multidisk")
    if count == 65535 or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        return reject("unsupported_zip64")
    if count > MAX_ZIP_VALIDATOR_MEMBERS:
        return reject("member_count_limit")
    if offset + _ZIP_EOCD.size + comment_size != len(data) or central_offset + central_size != offset:
        return reject("central_extent_mismatch")
    cursor = central_offset
    ranges: list[tuple[int, int]] = []
    for _index in range(count):
        if cursor + _ZIP_CENTRAL.size > offset:
            return reject("truncated_central_header")
        central = _ZIP_CENTRAL.unpack_from(data, cursor)
        if central[0] != b"PK\x01\x02":
            return reject("invalid_central_header")
        flags, method, crc, compressed_size, plain_size = central[3], central[4], central[7], central[8], central[9]
        name_size, extra_size, member_comment_size, start_disk = central[10:14]
        local_offset = central[16]
        if start_disk or 0xFFFFFFFF in (compressed_size, plain_size, local_offset):
            return reject("unsupported_member_extent")
        next_cursor = cursor + _ZIP_CENTRAL.size + name_size + extra_size + member_comment_size
        if next_cursor > offset or not name_size:
            return reject("central_variable_extent_mismatch")
        if local_offset + _ZIP_LOCAL.size > central_offset:
            return reject("local_header_out_of_bounds")
        local = _ZIP_LOCAL.unpack_from(data, local_offset)
        if local[0] != b"PK\x03\x04" or local[2] != flags or local[3] != method or local[9] != name_size:
            return reject("local_central_header_mismatch")
        data_start = local_offset + _ZIP_LOCAL.size + local[9] + local[10]
        data_end = data_start + compressed_size
        if data_end > central_offset:
            return reject("member_extent_out_of_bounds")
        central_name = data[cursor + _ZIP_CENTRAL.size : cursor + _ZIP_CENTRAL.size + name_size]
        if data[local_offset + _ZIP_LOCAL.size : local_offset + _ZIP_LOCAL.size + name_size] != central_name:
            return reject("local_central_name_mismatch")
        if flags & 8:
            descriptor_offset = data_end
            if data[descriptor_offset : descriptor_offset + 4] == b"PK\x07\x08":
                descriptor_offset += 4
            if descriptor_offset + 12 > central_offset or struct.unpack_from("<III", data, descriptor_offset) != (crc, compressed_size, plain_size):
                return reject("data_descriptor_mismatch")
            data_end = descriptor_offset + 12
        elif (local[6], local[7], local[8]) != (crc, compressed_size, plain_size):
            return reject("local_central_size_crc_mismatch")
        ranges.append((local_offset, data_end))
        cursor = next_cursor
    if cursor != offset:
        return reject("central_count_size_mismatch")
    previous_end = 0
    for start, end in sorted(ranges):
        if start < previous_end:
            return reject("overlapping_member_extent")
        previous_end = end
    return True, {**evidence, "parse_status": "header_bounds_validated", "member_count": count}


def _observe_donut_headers(data: bytes, strides: tuple[int, ...] | list[int], budget: _TransformBudget) -> dict[str, Any]:
    """headerだけを観測し、laneや重複candidate本体をmaterializeしない。"""

    offsets: list[int] = []
    probes = 0
    candidates = 0
    scans = 0
    longest = max(len(value) for value in DONUT_LOADER_PROLOGUES)

    def evidence(complete: bool, reason: str | None = None) -> dict[str, Any]:
        return {
            "type": "donut_shellcode", "candidate_count": candidates,
            "candidate_count_scope": "header_observation_positions_not_unique_payloads",
            "candidate_count_is_lower_bound": not complete,
            "candidate_offsets": list(offsets), "candidate_offsets_returned": len(offsets),
            "candidate_offsets_truncated": candidates > len(offsets),
            "header_probes": probes, "stride_scans_started": scans,
            "scan_complete": complete, "limit_reasons": [reason] if reason else [],
            "limits": {"maximum_header_probes": MAX_DONUT_HEADER_PROBES,
                       "maximum_header_candidates": MAX_DONUT_HEADER_CANDIDATES,
                       "maximum_returned_offsets": MAX_DONUT_HEADER_OFFSETS,
                       "maximum_shared_work_bytes": budget.maximum_work_bytes},
            "candidate_bytes_materialized": False, "instance_decrypted": False,
            "runtime_code_executed": False,
        }

    try:
        for stride in strides:
            # 全phaseは元入力のE8位置から直接求め、strideごとの巨大laneは作らない。
            budget.consume(len(data), validator=True)
            scans += 1
            cursor = 0
            while True:
                offset = data.find(b"\xe8", cursor)
                if offset < 0:
                    break
                cursor = offset + 1
                if probes >= MAX_DONUT_HEADER_PROBES:
                    raise _TransformBudgetExceeded("donut_header_probe_limit")
                budget.consume(5, validator=True)
                probes += 1
                if offset + 4 * stride >= len(data):
                    continue
                length = int.from_bytes(data[offset + stride:offset + 5 * stride:stride], "little")
                code = offset + (5 + length) * stride
                if length <= 0 or code + (min(len(value) for value in DONUT_LOADER_PROLOGUES) - 1) * stride >= len(data):
                    continue
                window_end = min(len(data), code + (MAX_LOADER_PREFIX_SIZE + longest) * stride)
                window_size = (window_end - code + stride - 1) // stride
                budget.consume(window_size, validator=True)
                window = data[code:window_end:stride]
                matched = any(window.startswith(prologue, gap)
                              for gap in range(MAX_LOADER_PREFIX_SIZE + 1)
                              for prologue in DONUT_LOADER_PROLOGUES)
                if not matched:
                    continue
                if candidates >= MAX_DONUT_HEADER_CANDIDATES:
                    raise _TransformBudgetExceeded("donut_header_candidate_limit")
                candidates += 1
                if len(offsets) < MAX_DONUT_HEADER_OFFSETS:
                    offsets.append(offset)
        budget.check_time()
    except _TransformBudgetExceeded as failure:
        if failure.reason in {"donut_header_probe_limit", "donut_header_candidate_limit"}:
            # inventoryだけが未完了の場合は、観測済みの外形を独立根拠として残す。
            # hard work/time/retainの超過はこの経路へ入れず、成果物を破棄する。
            try:
                budget.check_time()
            except _TransformBudgetExceeded as hard_failure:
                raise _TransformBudgetExceeded(hard_failure.reason, evidence(False, hard_failure.reason)) from hard_failure
            return evidence(False, failure.reason)
        raise _TransformBudgetExceeded(failure.reason, evidence(False, failure.reason)) from failure
    return evidence(True)


def validate_output(
    data: bytes,
    validator: Mapping[str, Any],
    *,
    _budget: _TransformBudget | None = None,
) -> tuple[bool, dict[str, Any]]:
    """変換後byte列を構造で検証し、単なる復号推測を成果物にしない。"""

    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_INPUT_SIZE:
        raise TransformProfileError("構造検証入力の型またはsizeが不正です")
    if not isinstance(validator, Mapping):
        raise TransformProfileError("構造validatorの型が不正です")
    validator_type = validator.get("type")
    if validator_type == "donut_shellcode":
        _fields(validator, {"type", "strides"}, set())
        strides = validator.get("strides")
        if not isinstance(strides, (list, tuple)) or not 1 <= len(strides) <= MAX_VALIDATOR_STRIDES:
            raise TransformProfileError("構造validatorのstride件数が不正です")
        for stride in strides:
            _integer(stride, "stride", 1, 4096)
        if len(set(strides)) != len(strides):
            raise TransformProfileError("構造validatorのstrideが重複しています")
        budget = _budget or _make_budget(MAX_TRANSFORM_WORK_BYTES, MAX_RETAINED_ARTIFACT_BYTES, MAX_TRANSFORM_ELAPSED_SECONDS)
        validation = _observe_donut_headers(data, strides, budget)
        return validation["candidate_count"] > 0, validation
    if validator_type == "magic":
        _fields(validator, {"type", "offset", "magic"}, set())
        _integer(validator.get("offset"), "offset", 0, MAX_INPUT_SIZE)
        if not isinstance(validator.get("magic"), bytes) or not 1 <= len(validator["magic"]) <= MAX_MAGIC_BYTES:
            raise TransformProfileError("構造validatorのmagicが不正です")
        offset = int(validator["offset"])
        matched = data[offset : offset + len(validator["magic"])] == validator["magic"]
        return matched, {"type": validator_type, "offset": offset}
    if validator_type == "pe":
        _fields(validator, {"type"}, set())
        if not data.startswith(b"MZ"):
            return False, {"type": validator_type, "parse_status": "not_pe"}
        extent = inspect_structural_pe_extent(data, max_extent=MAX_INPUT_SIZE)
        if extent.extent is None:
            return False, {"type": validator_type, "parse_status": "structural_bounds_rejected", "reason": extent.reason}
        try:
            parsed = pefile.PE(data=data, fast_load=True)
        except pefile.PEFormatError:
            return False, {"type": validator_type, "parse_status": "parse_failed"}
        try:
            if len(parsed.sections) != parsed.FILE_HEADER.NumberOfSections:
                return False, {"type": validator_type, "parse_status": "section_count_mismatch"}
        finally:
            parsed.close()
        return True, {"type": validator_type, "parse_status": "parsed", "validated_extent": extent.extent}
    if validator_type == "zip":
        _fields(validator, {"type"}, set())
        return _validate_zip_headers(data)
    raise TransformProfileError("未対応validatorです")


def _recover_validated_profile(
    data: bytes,
    normalized: Mapping[str, Any],
    *,
    budget: _TransformBudget | None = None,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """検証済みプロファイルを適用する内部入口。"""

    if not isinstance(data, bytes):
        raise TransformProfileError("入力はimmutable bytesで指定してください")
    budget = budget or _make_budget(MAX_TRANSFORM_WORK_BYTES, MAX_RETAINED_ARTIFACT_BYTES, MAX_TRANSFORM_ELAPSED_SECONDS)
    budget.check_time()
    if not normalized["min_input_size"] <= len(data) <= normalized["max_input_size"]:
        return (
            {
                "profile_id": normalized["id"],
                "status": "input_outside_bounds",
                "input_size": len(data),
                "min_input_size": normalized["min_input_size"],
                "max_input_size": normalized["max_input_size"],
                "executed": False,
                "network_contacted": False,
            },
            [],
        )
    clear = apply_operations(
        data,
        normalized["operations"],
        max_input_size=normalized["max_input_size"],
        _budget=budget,
    )
    budget.check_time()
    matched, validation = validate_output(clear, normalized["validator"], _budget=budget)
    budget.check_time()
    validation_limits = list(validation.get("limit_reasons") or [])
    report = {
        "profile_id": normalized["id"],
        "status": ("partial_shared_budget_limit" if validation_limits else
                   "validated_artifact_recovered" if matched else "validation_failed"),
        "input_sha256": sha256_bytes(data),
        "input_size": len(data),
        "output_sha256": sha256_bytes(clear) if matched else None,
        "output_size": len(clear) if matched else None,
        "operations": _public_operations(normalized["operations"]),
        "transform_key_values_published": False,
        "validation": validation,
        "executed": False,
        "network_contacted": False,
    }
    if validation_limits:
        report.update(profile_evaluation_complete=False, limit_reasons=validation_limits)
    budget.check_time()
    if matched:
        budget.retain(len(clear))
    artifacts = [(normalized["artifact_kind"], clear)] if matched else []
    return report, artifacts


def _public_operations(operations: tuple[Mapping[str, Any], ...]) -> list[dict[str, Any]]:
    """鍵本体は除外し、操作名・非鍵parameter・鍵の長さとhashだけを公開する。"""

    result = []
    for operation in operations:
        public = {key: value for key, value in operation.items() if key not in {"key", "key_hex"}}
        if "key" in operation:
            key_bytes = bytes([operation["key"]]) if operation["operation"] == "xor_byte" else operation["key"]
            public.update(key_size=len(key_bytes), key_sha256=sha256_bytes(key_bytes), key_published=False)
        result.append(public)
    return result


def recover_transform_profile(
    data: bytes,
    profile: Mapping[str, Any],
    *,
    max_work_bytes: int = MAX_TRANSFORM_WORK_BYTES,
    max_artifact_bytes: int = MAX_RETAINED_ARTIFACT_BYTES,
    max_elapsed_seconds: float = MAX_TRANSFORM_ELAPSED_SECONDS,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """単一profileも全体予算で検証し、上限到達をpartialへ分離する。"""

    normalized = validate_profile(profile)
    budget = _make_budget(max_work_bytes, max_artifact_bytes, max_elapsed_seconds)
    try:
        report, artifacts = _recover_validated_profile(data, normalized, budget=budget)
        report.setdefault("profile_evaluation_complete", True)
        report.setdefault("limit_reasons", [])
    except _TransformBudgetExceeded as failure:
        report = {"profile_id": normalized["id"], "status": "partial_shared_budget_limit",
                  "reason": failure.reason, "profile_evaluation_complete": False,
                  "limit_reasons": [failure.reason], "executed": False, "network_contacted": False}
        if failure.validation is not None:
            report["validation"] = failure.validation
        artifacts = []
    report["budget"] = _budget_report(budget, max_elapsed_seconds)
    return report, artifacts


def recover_profiled_transforms(
    data: bytes,
    *,
    input_format: str,
    source_name: str = "",
    profiles_path: Path = DEFAULT_PROFILE_PATH,
    max_work_bytes: int = MAX_TRANSFORM_WORK_BYTES,
    max_artifact_bytes: int = MAX_RETAINED_ARTIFACT_BYTES,
    max_elapsed_seconds: float = MAX_TRANSFORM_ELAPSED_SECONDS,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """形式と任意suffixに合う全プロファイルを決定的に評価する。"""

    if not isinstance(data, bytes):
        raise TransformProfileError("入力はimmutable bytesで指定してください")
    if not isinstance(input_format, str) or input_format not in ALLOWED_FORMATS:
        raise TransformProfileError("入力形式が不正です")
    if not isinstance(source_name, str) or len(source_name) > 4096:
        raise TransformProfileError("入力名の型または長さが不正です")
    budget = _make_budget(max_work_bytes, max_artifact_bytes, max_elapsed_seconds)
    attempts: list[dict[str, Any]] = []
    artifacts: list[tuple[str, bytes]] = []
    limit_reasons: list[str] = []
    suffix = Path(source_name).suffix.casefold()
    for profile in load_profiles(profiles_path):
        if (
            "any" not in profile["input_formats"]
            and input_format not in profile["input_formats"]
        ):
            attempts.append(
                {"profile_id": profile["id"], "status": "skipped_input_format"}
            )
            continue
        if profile["name_suffixes"] and suffix not in profile["name_suffixes"]:
            attempts.append(
                {"profile_id": profile["id"], "status": "skipped_name_suffix"}
            )
            continue
        if limit_reasons:
            attempts.append({"profile_id": profile["id"], "status": "skipped_shared_budget_limit"})
            continue
        try:
            report, recovered = _recover_validated_profile(data, profile, budget=budget)
        except _TransformBudgetExceeded as exc:
            limit_reasons.append(exc.reason)
            attempt = {"profile_id": profile["id"], "status": "shared_budget_limit", "reason": exc.reason}
            if exc.validation is not None:
                attempt["validation"] = exc.validation
            attempts.append(attempt)
            continue
        except TransformProfileError:
            # 一つのprofileのslice等がこの入力へ適用できなくても他profileを失わない。
            attempts.append({"profile_id": profile["id"], "status": "transform_rejected"})
            continue
        attempts.append(report)
        artifacts.extend(recovered)
        limit_reasons.extend(report.get("limit_reasons") or [])
    if not limit_reasons:
        try:
            budget.check_time()
        except _TransformBudgetExceeded as failure:
            limit_reasons.append(failure.reason)
    return (
        {
            "schema_version": 1,
            "status": (
                "partial_shared_budget_limit" if limit_reasons else
                "validated_artifacts_recovered"
                if artifacts
                else "no_profile_recovered_artifact"
            ),
            "profiles_evaluated": sum(
                item["status"] not in {"skipped_input_format", "skipped_name_suffix", "skipped_shared_budget_limit"}
                for item in attempts
            ),
            "attempts": attempts,
            "profile_evaluation_complete": not limit_reasons,
            "limit_reasons": limit_reasons,
            "budget": _budget_report(budget, max_elapsed_seconds),
            "executed": False,
            "network_contacted": False,
        },
        artifacts,
    )


def build_parser() -> argparse.ArgumentParser:
    """宣言型変換CLIのparserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--profiles", type=Path, default=DEFAULT_PROFILE_PATH)
    parser.add_argument(
        "--input-format", default="data", choices=sorted(ALLOWED_FORMATS)
    )
    parser.add_argument("--json", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """復元byteを書き出さず、宣言型変換の検証結果だけを返す。"""

    args = build_parser().parse_args(argv)
    data = _bounded_regular_file_bytes(args.input, MAX_INPUT_SIZE)
    report, artifacts = recover_profiled_transforms(
        data,
        input_format=args.input_format,
        source_name=args.input.name,
        profiles_path=args.profiles,
    )
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(
        json.dumps(
            {
                "status": report["status"],
                "recovered": len(artifacts),
                "executed": False,
                "network_contacted": False,
            },
            ensure_ascii=False,
        )
    )
    return 0 if artifacts else 20


if __name__ == "__main__":
    raise SystemExit(main())
