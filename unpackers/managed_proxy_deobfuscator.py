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
import time
import warnings
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from itertools import islice
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
    from .managed_bitmap_argb_xor import RecoveryError as ManagedMethodRecoveryError
    from .managed_bitmap_argb_xor import _method_raw_window, _normalize_methods
except ImportError:  # 単独CLIまたは新依存が不足した状態
    try:
        from managed_bitmap_argb_xor import RecoveryError as ManagedMethodRecoveryError
        from managed_bitmap_argb_xor import _method_raw_window, _normalize_methods
    except ImportError:
        ManagedMethodRecoveryError = ValueError
        _method_raw_window = None
        _normalize_methods = None

try:
    from dncil.cil.body.reader import read_method_body_from_bytes
    from dncil.cil.enums import OperandType
    from dncil.cil.error import MethodBodyFormatError
except ImportError:  # 単独CLIまたはdncil依存が不足した状態
    read_method_body_from_bytes = None
    OperandType = None
    MethodBodyFormatError = ValueError

try:
    import dnfile
except ImportError:  # pragma: no cover - 依存関係がない環境
    dnfile = None

MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_PROXY_RECORDS = 16_384
MAX_RESOURCE_COUNT = 4_096
MAX_PROXY_TRANSFORMS = 16
MAX_PROFILE_METHODS = 8_192
MAX_PROFILE_INSTRUCTIONS = 250_000
MAX_PROFILE_ELAPSED_SECONDS = 10.0
PROFILE_TIME_CHECK_INTERVAL = 4_096
_U32_MASK = 0xFFFFFFFF

MODSQUARE_PROXY_PROFILE = "eazfuscator_dynamic_proxy_modsquare_v1"
_MODSQUARE_INITIALIZER_INSTRUCTIONS = 624
_MODSQUARE_INITIALIZER_BODY_BYTES = 1_712
_MODSQUARE_BUILD_CONSTANT_INDICES = (151, 153, 155, 157)
_MODSQUARE_INITIALIZER_CANONICAL_SHA256 = (
    "33c6d7e462a34862c93c3d750f3e9edfc0df446fc39bf6e353d1a6cd5e763e88"
)
_MODSQUARE_INITIALIZER_CONTROL_FLOW_SHA256 = (
    "8a00b48e5c061a1fcbcda60395141de45d1799f6a77546ee33ba16065acc1bb7"
)
_MODSQUARE_INITIALIZER_SIGNATURE = b"\x00\x01\x01\x11\x80\xe1"
_MODSQUARE_REQUIRED_APIS = frozenset(
    {
        "System.Reflection.Assembly::GetManifestResourceStream",
        "System.IO.BinaryReader::ReadBytes",
        "System.Type::GetFields",
        "System.Reflection.Module::ResolveMethod",
        "System.Delegate::CreateDelegate",
        "System.Reflection.FieldInfo::SetValue",
        "System.Reflection.Emit.DynamicMethod::.ctor",
    }
)

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


def _profile_deadline(clock: Callable[[], float], max_elapsed_seconds: float) -> float:
    if (
        isinstance(max_elapsed_seconds, bool)
        or not isinstance(max_elapsed_seconds, (int, float))
        or not 0 < max_elapsed_seconds <= MAX_PROFILE_ELAPSED_SECONDS
    ):
        raise ValueError("経過時間上限が不正です")
    return clock() + float(max_elapsed_seconds)


def _check_profile_time(deadline: float, clock: Callable[[], float]) -> None:
    if clock() > deadline:
        raise TimeoutError("managed_proxy_profile_deadline_exceeded")


def decrypt_eaz_proxy_modsquare_table(
    data: bytes,
    *,
    constants: Sequence[int],
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_PROFILE_ELAPSED_SECONDS,
) -> bytes:
    """CILから復元した4定数のword変換を静的に適用する。

    各4-byte wordでbuild固有定数を再初期化し、前wordのaccumulator
    だけを引き継ぐ。CLRやCILは実行しない。
    """

    if type(data) is not bytes:
        raise TypeError("dataにはexact bytesを指定してください")
    if not data or len(data) % 8:
        raise ValueError("プロキシresource長は8の倍数である必要があります")
    if len(data) > MAX_PROXY_RECORDS * 8:
        raise ValueError("プロキシ変換byte数が安全上限を超えています")
    if (
        not isinstance(constants, (tuple, list))
        or len(constants) != 4
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= _U32_MASK
            for value in constants
        )
    ):
        raise ValueError("4個のu32 build定数が必要です")
    deadline = _profile_deadline(clock, max_elapsed_seconds)
    key0, key1, key2, key3 = (int(value) for value in constants)
    output = bytearray(len(data))
    accumulator = 0
    for index in range(len(data) // 4):
        if index % PROFILE_TIME_CHECK_INTERVAL == 0:
            _check_profile_time(deadline, clock)
        encrypted = struct.unpack_from("<I", data, index * 4)[0]
        previous = accumulator
        value0, value1, value2, value3 = key0, key1, key2, key3
        mixed = previous

        modulus = _u32(value2 * 432_322_986)
        if modulus == 0:
            modulus = (1 << 64) - 1
        value3 = _u32(_u32(value3 * value3) % modulus)
        value2 = _u32(36_951 * (value2 & 0xFFFF) + (value2 >> 16))
        value3 = _u32(40_498 * (value3 & 0xFFFF) - (value3 >> 16))
        value1 = _u32(19_870 * value1 - value0 + value3)

        # 元CILは別途nibble-swap(value2) ^ value3を未使用localへ保存する。
        # canonical matcherはそのdead-code shapeも照合し、live pathではこのrotateを使う。
        value2 = _u32((value2 << 15) | (value2 >> 17))
        modulus = _u32(value3 * 88_665_022) | 1
        mixed = _u32(_u32(mixed * mixed) % modulus)
        mixed = _u32(mixed ^ (mixed >> 2))
        mixed = _u32(mixed + value1)
        mixed = _u32(mixed ^ (mixed >> 17))
        mixed = _u32(mixed + value2)
        mixed = _u32(mixed ^ _u32(mixed << 15))
        mixed = _u32(mixed + mixed)
        mixed = _u32((((value1 << 5) + value1) ^ value2) + mixed)
        accumulator = _u32(previous + mixed)
        struct.pack_into("<I", output, index * 4, accumulator ^ encrypted)
    _check_profile_time(deadline, clock)
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


def parse_modsquare_proxy_records(clear: bytes) -> list[dict[str, Any]]:
    """mod-square initializerのexact bit maskで8-byte recordを解析する。"""

    if type(clear) is not bytes:
        raise TypeError("clearにはexact bytesを指定してください")
    if not clear or len(clear) % 8:
        raise ValueError("復号済みプロキシ表の長さは8の倍数である必要があります")
    if len(clear) // 8 > MAX_PROXY_RECORDS:
        raise ValueError("プロキシrecord数が安全上限を超えています")
    records: list[dict[str, Any]] = []
    seen_fields: dict[int, int] = {}
    for offset in range(0, len(clear), 8):
        field_token, encoded_target = struct.unpack_from("<II", clear, offset)
        callvirt = bool(encoded_target & 0x40000000)
        target_token = encoded_target & 0x3FFFFFFF
        reasons = []
        if encoded_target & 0x80000000:
            reasons.append("reserved_target_flag_set")
        if field_token >> 24 != 0x04 or not field_token & 0xFFFFFF:
            reasons.append("invalid_field_token")
        if target_token >> 24 not in {0x06, 0x0A, 0x2B} or not (
            target_token & 0xFFFFFF
        ):
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


class _ModsquareProfileRejected(ValueError):
    """profile候補が存在するが厳密検証を通過しない場合。"""


def _normalized_control_flow(body: Any) -> tuple[tuple[Any, ...], ...]:
    """method bodyのoffsetとbranch/switch先をinstruction indexへ正規化する。"""

    if OperandType is None:
        raise _ModsquareProfileRejected("initializer_cil_parser_unavailable")
    instructions = tuple(getattr(body, "instructions", ()) or ())
    if not instructions or len(instructions) > _MODSQUARE_INITIALIZER_INSTRUCTIONS:
        raise _ModsquareProfileRejected("initializer_control_flow_bounds")
    offsets: dict[int, int] = {}
    for index, instruction in enumerate(instructions):
        offset = getattr(instruction, "offset", None)
        size = getattr(instruction, "size", None)
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or offset in offsets
        ):
            raise _ModsquareProfileRejected("initializer_instruction_layout_invalid")
        offsets[offset] = index
    ordered_offsets = tuple(offsets)
    if ordered_offsets != tuple(sorted(ordered_offsets)):
        raise _ModsquareProfileRejected("initializer_instruction_order_invalid")
    code_end = ordered_offsets[-1] + int(instructions[-1].size)
    header_size = getattr(body, "header_size", None)
    code_size = getattr(body, "code_size", None)
    if (
        isinstance(header_size, bool)
        or not isinstance(header_size, int)
        or isinstance(code_size, bool)
        or not isinstance(code_size, int)
        or header_size < 0
        or code_size <= 0
        or ordered_offsets[0] != header_size
        or code_end != header_size + code_size
    ):
        raise _ModsquareProfileRejected("initializer_code_extent_invalid")
    offsets[code_end] = len(instructions)

    rows: list[tuple[Any, ...]] = []
    branch_types = {OperandType.InlineBrTarget, OperandType.ShortInlineBrTarget}
    for instruction in instructions:
        opcode = getattr(instruction, "opcode", None)
        operand_type = getattr(opcode, "operand_type", None)
        targets: tuple[int, ...] = ()
        if operand_type in branch_types:
            target = getattr(instruction, "operand", None)
            if type(target) is not int or target not in offsets:
                raise _ModsquareProfileRejected("initializer_branch_target_invalid")
            targets = (offsets[target],)
        elif operand_type == OperandType.InlineSwitch:
            raw_targets = getattr(instruction, "operand", None)
            if (
                not isinstance(raw_targets, list)
                or len(raw_targets) > _MODSQUARE_INITIALIZER_INSTRUCTIONS
                or any(
                    type(target) is not int or target not in offsets
                    for target in raw_targets
                )
            ):
                raise _ModsquareProfileRejected("initializer_switch_target_invalid")
            targets = tuple(offsets[target] for target in raw_targets)
        rows.append(
            (
                int(instruction.offset) - header_size,
                int(instruction.size),
                str(getattr(opcode, "name", "")),
                targets,
            )
        )
    return tuple(rows)


def _method_body_details(data: bytes, pe: Any, method: Any) -> dict[str, Any]:
    """source-boundの生method bodyからCFGとEHを完全に抽出する。"""

    if (
        type(data) is not bytes
        or _method_raw_window is None
        or read_method_body_from_bytes is None
    ):
        raise _ModsquareProfileRejected("initializer_method_source_unavailable")
    try:
        start, end = _method_raw_window(pe, data, int(method.rva))
        body = read_method_body_from_bytes(data[start:end])
    except (
        ArithmeticError,
        AttributeError,
        MethodBodyFormatError,
        TypeError,
        ValueError,
    ) as exc:
        raise _ModsquareProfileRejected("initializer_method_body_invalid") from exc
    if (
        int(getattr(body, "size", 0) or 0) != int(method.body_size)
        or len(body.instructions) != len(method.instructions)
        or len(getattr(body, "raw_bytes", b"")) != int(method.body_size)
    ):
        raise _ModsquareProfileRejected("initializer_method_body_mismatch")

    local_signature_sha256 = None
    local_token = getattr(getattr(body, "local_var_sig_tok", None), "value", None)
    if local_token is not None:
        if type(local_token) is not int or local_token >> 24 != 0x11:
            raise _ModsquareProfileRejected("initializer_local_signature_token_invalid")
        rows = _metadata_table_rows(pe, "StandAloneSig", MAX_PROXY_RECORDS)
        rid = local_token & 0xFFFFFF
        if not 0 < rid <= len(rows):
            raise _ModsquareProfileRejected("initializer_local_signature_unresolved")
        signature = getattr(getattr(rows[rid - 1], "Signature", None), "value", None)
        if not isinstance(signature, bytes) or not 0 < len(signature) <= 512:
            raise _ModsquareProfileRejected("initializer_local_signature_invalid")
        local_signature_sha256 = hashlib.sha256(signature).hexdigest()

    handlers = tuple(getattr(body, "exception_handlers", ()) or ())
    more_sections = bool(getattr(getattr(body, "flags", None), "MoreSects", False))
    exception_bytes = int(getattr(body, "exception_handlers_size", -1))
    if more_sections is not bool(handlers) or exception_bytes < 0:
        raise _ModsquareProfileRejected("initializer_exception_sections_invalid")
    handler_rows = []
    for handler in handlers:
        catch_token = getattr(getattr(handler, "catch_type", None), "value", None)
        if catch_token is not None and type(catch_token) is not int:
            raise _ModsquareProfileRejected("initializer_exception_token_invalid")
        values = (
            getattr(handler, "exception_type", None),
            getattr(handler, "try_start", None),
            getattr(handler, "try_end", None),
            getattr(handler, "handler_start", None),
            getattr(handler, "handler_end", None),
            getattr(handler, "filter_start", None),
        )
        if any(type(value) is not int for value in values):
            raise _ModsquareProfileRejected("initializer_exception_shape_invalid")
        handler_rows.append((*values, catch_token))

    header_size = int(body.header_size)
    code_size = int(body.code_size)
    raw_exception_section = body.raw_bytes[header_size + code_size :]
    if len(raw_exception_section) != exception_bytes:
        raise _ModsquareProfileRejected("initializer_exception_extent_invalid")
    shape = {
        "body_size": int(body.size),
        "header_size": header_size,
        "code_size": code_size,
        "max_stack": int(body.max_stack),
        "init_locals": bool(getattr(body.flags, "InitLocals", False)),
        "more_sections": more_sections,
        "local_signature_present": local_signature_sha256 is not None,
        "control_flow": _normalized_control_flow(body),
        "exception_handlers": tuple(handler_rows),
        "exception_section_sha256": hashlib.sha256(raw_exception_section).hexdigest(),
    }
    return {
        "control_flow_sha256": hashlib.sha256(
            json.dumps(shape, separators=(",", ":")).encode("ascii")
        ).hexdigest(),
        "exception_handler_count": len(handlers),
        "has_extra_sections": more_sections,
        "header_size": header_size,
        "code_size": code_size,
    }


def _modsquare_initializer_digest(method: Any) -> str:
    """token行番、難読化名、local番号を除いたCIL shapeを返す。"""

    local_map: dict[int, int] = {}
    rows: list[list[Any]] = []
    for index, instruction in enumerate(method.instructions):
        raw_local = getattr(instruction, "local", None)
        local = None
        if raw_local is not None:
            if isinstance(raw_local, bool) or not isinstance(raw_local, int):
                raise _ModsquareProfileRejected("initializer_local_invalid")
            local = local_map.setdefault(raw_local, len(local_map))
        integer: Any = getattr(instruction, "integer", None)
        if index in _MODSQUARE_BUILD_CONSTANT_INDICES:
            integer = "VAR"
        token = getattr(instruction, "token", None)
        token_kind = token >> 24 if isinstance(token, int) and token else None
        resolved = getattr(instruction, "resolved", "")
        semantic = (
            resolved
            if isinstance(resolved, str) and resolved.startswith("System.")
            else None
        )
        if semantic is None:
            semantic = {
                0x02: "typedef",
                0x04: "fielddef",
                0x06: "methoddef",
            }.get(token_kind)
        rows.append(
            [
                str(getattr(instruction, "opcode", "")),
                local,
                integer,
                token_kind,
                semantic,
                "str"
                if getattr(instruction, "user_string", None) is not None
                else None,
            ]
        )
    return hashlib.sha256(
        json.dumps(rows, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _modsquare_initializer_recipe(
    method: Any,
    *,
    body_details: dict[str, Any],
) -> dict[str, Any] | None:
    """review済みinitializerと一致する場合だけbuild定数を返す。"""

    instructions = tuple(getattr(method, "instructions", ()) or ())
    if (
        len(instructions) != _MODSQUARE_INITIALIZER_INSTRUCTIONS
        or getattr(method, "body_size", None) != _MODSQUARE_INITIALIZER_BODY_BYTES
        or getattr(method, "is_static", None) is not True
    ):
        return None
    if (
        getattr(method, "signature", None) != _MODSQUARE_INITIALIZER_SIGNATURE
        or body_details.get("control_flow_sha256")
        != _MODSQUARE_INITIALIZER_CONTROL_FLOW_SHA256
        or body_details.get("exception_handler_count") != 3
        or body_details.get("has_extra_sections") is not True
    ):
        return None
    apis = {
        item.resolved
        for item in instructions
        if isinstance(getattr(item, "resolved", None), str)
    }
    if not _MODSQUARE_REQUIRED_APIS.issubset(apis):
        return None
    if (
        sum(
            item.resolved == "System.Reflection.Module::ResolveMethod"
            for item in instructions
        )
        != 1
        or sum(
            item.resolved == "System.Reflection.Assembly::GetManifestResourceStream"
            for item in instructions
        )
        != 1
    ):
        return None
    constants = []
    for index in _MODSQUARE_BUILD_CONSTANT_INDICES:
        instruction = instructions[index]
        value = getattr(instruction, "integer", None)
        if (
            getattr(instruction, "opcode", None) != "ldc.i4"
            or index + 1 >= len(instructions)
            or not str(getattr(instructions[index + 1], "opcode", "")).startswith(
                "stloc"
            )
            or isinstance(value, bool)
            or not isinstance(value, int)
        ):
            return None
        constants.append(value & _U32_MASK)
    if _modsquare_initializer_digest(method) != _MODSQUARE_INITIALIZER_CANONICAL_SHA256:
        return None
    literals = [
        item.user_string
        for item in instructions
        if isinstance(getattr(item, "user_string", None), str)
    ]
    if len(literals) != 1 or not literals[0] or len(literals[0]) > 512:
        raise _ModsquareProfileRejected("initializer_resource_literal_ambiguous")
    return {
        "method_token": int(method.token),
        "method_body_sha256": str(method.body_sha256),
        "canonical_sha256": _MODSQUARE_INITIALIZER_CANONICAL_SHA256,
        "constants": tuple(constants),
        "resource_literal": literals[0],
    }


def _metadata_table_rows(pe: Any, name: str, limit: int) -> list[Any]:
    table = getattr(getattr(getattr(pe, "net", None), "mdtables", None), name, None)
    declared = getattr(table, "num_rows", None)
    if (
        isinstance(declared, int)
        and not isinstance(declared, bool)
        and declared > limit
    ):
        raise TimeoutError(f"{name.casefold()}_row_limit")
    rows = list(islice(iter(getattr(table, "rows", ()) or ()), limit + 1))
    if len(rows) > limit:
        raise TimeoutError(f"{name.casefold()}_row_limit")
    if (
        isinstance(declared, int)
        and not isinstance(declared, bool)
        and declared >= 0
        and len(rows) != declared
    ):
        raise TimeoutError(f"{name.casefold()}_row_inventory_incomplete")
    return rows


def _field_owner_tokens(pe: Any) -> tuple[dict[int, int], list[Any]]:
    fields = _metadata_table_rows(pe, "Field", MAX_PROXY_RECORDS)
    types = _metadata_table_rows(pe, "TypeDef", MAX_PROFILE_METHODS)
    owners: dict[int, int] = {}
    for type_rid, row in enumerate(types, 1):
        for reference in getattr(row, "FieldList", ()) or ():
            field_rid = getattr(reference, "row_index", None)
            if (
                isinstance(field_rid, bool)
                or not isinstance(field_rid, int)
                or not 0 < field_rid <= len(fields)
                or field_rid in owners
            ):
                raise _ModsquareProfileRejected("field_owner_ambiguous")
            owners[field_rid] = 0x02000000 | type_rid
    return owners, fields


def _target_has_this(
    pe: Any,
    token: int,
    resolution: dict[str, Any],
    row_cache: dict[str, list[Any]],
) -> bool:
    """callvirtがstatic targetへ向かないことをmetadata宣言で確認する。"""

    for _ in range(2):
        table = token >> 24
        rid = token & 0xFFFFFF
        if table == 0x06:
            rows = row_cache.get("MethodDef")
            if rows is None:
                rows = _metadata_table_rows(pe, "MethodDef", MAX_PROFILE_METHODS)
                row_cache["MethodDef"] = rows
            if not 0 < rid <= len(rows):
                raise _ModsquareProfileRejected("target_method_out_of_range")
            flags = getattr(rows[rid - 1], "Flags", None)
            return not bool(getattr(flags, "mdStatic", False))
        if table == 0x0A:
            rows = row_cache.get("MemberRef")
            if rows is None:
                rows = _metadata_table_rows(pe, "MemberRef", MAX_PROXY_RECORDS)
                row_cache["MemberRef"] = rows
            if not 0 < rid <= len(rows):
                raise _ModsquareProfileRejected("target_memberref_out_of_range")
            signature = getattr(
                getattr(rows[rid - 1], "Signature", None), "value", None
            )
            if (
                not isinstance(signature, bytes)
                or not signature
                or len(signature) > 512
            ):
                raise _ModsquareProfileRejected("target_signature_invalid")
            return bool(signature[0] & 0x20)
        if table == 0x2B:
            definition = resolution.get("definition_token")
            try:
                token = int(definition, 16)
            except (TypeError, ValueError) as exc:
                raise _ModsquareProfileRejected(
                    "target_methodspec_definition_unresolved"
                ) from exc
            continue
        break
    raise _ModsquareProfileRejected("target_method_table_unreviewed")


def _validate_modsquare_proxy_records(
    data: bytes,
    pe: Any,
    methods: Sequence[Any],
    initializer_token: int,
    records: Sequence[dict[str, Any]],
    resolver: MetadataResolver,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, int]:
    """token、owner cctor、use-siteを完全検証する。"""

    if not 8 <= len(records) <= MAX_PROXY_RECORDS:
        raise _ModsquareProfileRejected("proxy_record_count_out_of_bounds")
    if any(record.get("valid") is not True for record in records):
        raise _ModsquareProfileRejected("proxy_record_syntax_invalid")
    coverage = resolver.coverage()
    if coverage.get("complete") is not True:
        raise TimeoutError("proxy_record_metadata_incomplete")

    owner_by_rid, field_rows = _field_owner_tokens(pe)
    fields: list[int] = []
    targets: list[int] = []
    callvirt_count = 0
    target_row_cache: dict[str, list[Any]] = {}
    for index, record in enumerate(records):
        if index % PROFILE_TIME_CHECK_INTERVAL == 0:
            _check_profile_time(deadline, clock)
        try:
            field = int(record["field_token"], 16)
            target = int(record["target_token"], 16)
        except (KeyError, TypeError, ValueError) as exc:
            raise _ModsquareProfileRejected("proxy_record_token_invalid") from exc
        field_resolution = resolver.resolve(field, kind="field")
        target_resolution = resolver.resolve(target)
        if field_resolution.get("status") != "resolved":
            raise _ModsquareProfileRejected("proxy_field_metadata_unresolved")
        if target_resolution.get("status") != "resolved":
            raise _ModsquareProfileRejected("proxy_target_metadata_unresolved")
        rid = field & 0xFFFFFF
        if not 0 < rid <= len(field_rows) or rid not in owner_by_rid:
            raise _ModsquareProfileRejected("proxy_field_owner_unresolved")
        flags = getattr(field_rows[rid - 1], "Flags", None)
        if not bool(getattr(flags, "fdStatic", False)):
            raise _ModsquareProfileRejected("proxy_field_not_static")
        if record.get("call_kind") == "callvirt":
            callvirt_count += 1
            if not _target_has_this(
                pe,
                target,
                target_resolution,
                target_row_cache,
            ):
                raise _ModsquareProfileRejected("proxy_callvirt_static_target")
        elif record.get("call_kind") != "call":
            raise _ModsquareProfileRejected("proxy_call_kind_invalid")
        fields.append(field)
        targets.append(target)

    if len(set(fields)) != len(fields):
        raise _ModsquareProfileRejected("proxy_field_duplicate")
    owner_tokens = {owner_by_rid[field & 0xFFFFFF] for field in fields}
    if len(owner_tokens) != len(fields):
        raise _ModsquareProfileRejected("proxy_owner_reused")

    cctors: dict[int, list[Any]] = {}
    used_fields: Counter[int] = Counter()
    field_set = set(fields)
    total_instructions = 0
    for method_index, method in enumerate(methods):
        if method_index % PROFILE_TIME_CHECK_INTERVAL == 0:
            _check_profile_time(deadline, clock)
        instructions = tuple(getattr(method, "instructions", ()) or ())
        total_instructions += len(instructions)
        if total_instructions > MAX_PROFILE_INSTRUCTIONS:
            raise TimeoutError("profile_instruction_limit")
        if getattr(method, "name", None) == ".cctor":
            cctors.setdefault(int(method.owner_token), []).append(method)
        for instruction in instructions:
            if (
                getattr(instruction, "opcode", None) == "ldsfld"
                and getattr(instruction, "token", None) in field_set
            ):
                used_fields[int(instruction.token)] += 1
    if set(used_fields) != field_set:
        raise _ModsquareProfileRejected("proxy_field_use_incomplete")

    for owner in owner_tokens:
        selected = cctors.get(owner, [])
        if len(selected) != 1:
            raise _ModsquareProfileRejected("proxy_owner_cctor_ambiguous")
        meaningful = [item for item in selected[0].instructions if item.opcode != "nop"]
        if (
            len(meaningful) != 3
            or getattr(selected[0], "signature", None) != b"\x00\x00\x01"
            or getattr(selected[0], "is_static", None) is not True
            or getattr(selected[0], "is_special_name", None) is not True
            or getattr(selected[0], "is_runtime_special_name", None) is not True
            or meaningful[0].opcode != "ldtoken"
            or meaningful[0].token != owner
            or meaningful[1].opcode != "call"
            or meaningful[1].token != initializer_token
            or meaningful[2].opcode != "ret"
        ):
            raise _ModsquareProfileRejected("proxy_owner_cctor_shape_mismatch")
        body_details = _method_body_details(data, pe, selected[0])
        if (
            body_details["exception_handler_count"] != 0
            or body_details["has_extra_sections"] is not False
            or body_details["header_size"] != 1
            or body_details["code_size"] != 11
        ):
            raise _ModsquareProfileRejected("proxy_owner_cctor_body_mismatch")
    _check_profile_time(deadline, clock)
    return {
        "field_count": len(fields),
        "target_count": len(targets),
        "owner_cctor_count": len(owner_tokens),
        "used_field_count": len(used_fields),
        "ldsfld_use_count": sum(used_fields.values()),
        "call_count": len(records) - callvirt_count,
        "callvirt_count": callvirt_count,
    }


def _analyze_modsquare_proxy_profile_resources(
    data: bytes,
    pe: Any,
    resources: Iterable[tuple[str, bytes]],
    resolver: MetadataResolver,
    *,
    include_records: bool = False,
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_PROFILE_ELAPSED_SECONDS,
) -> dict[str, Any]:
    """CIL由来の4定数profileを実行せず一意に復元する。"""

    report: dict[str, Any] = {
        "status": "not_started",
        "profile": None,
        "candidate_count": 0,
        "candidates": [],
        "reason": None,
        "budget_exhausted": [],
        "executed": False,
        "emulated": False,
        "clr_loaded": False,
        "network_contacted": False,
        "raw_resource_name_published": False,
        "raw_resource_bytes_published": False,
    }
    try:
        if type(data) is not bytes:
            raise TypeError("dataにはexact bytesを指定してください")
        deadline = _profile_deadline(clock, max_elapsed_seconds)
        if _normalize_methods is None:
            raise TimeoutError("managed_method_normalizer_dependency_missing")
        if not _metadata_table_rows(pe, "MethodDef", MAX_PROFILE_METHODS):
            report.update(status="not_matched", reason="method_table_empty")
            return report
        methods = _normalize_methods(pe, data, deadline, clock)
        if not 0 < len(methods) <= MAX_PROFILE_METHODS:
            raise TimeoutError("profile_method_limit")
        recipes = []
        for index, method in enumerate(methods):
            if index % PROFILE_TIME_CHECK_INTERVAL == 0:
                _check_profile_time(deadline, clock)
            if (
                len(tuple(getattr(method, "instructions", ()) or ()))
                != _MODSQUARE_INITIALIZER_INSTRUCTIONS
                or getattr(method, "body_size", None)
                != _MODSQUARE_INITIALIZER_BODY_BYTES
                or getattr(method, "is_static", None) is not True
                or getattr(method, "signature", None)
                != _MODSQUARE_INITIALIZER_SIGNATURE
            ):
                continue
            recipe = _modsquare_initializer_recipe(
                method,
                body_details=_method_body_details(data, pe, method),
            )
            if recipe is not None:
                recipes.append(recipe)
        if not recipes:
            report.update(status="not_matched", reason="initializer_profile_not_found")
            return report
        if len(recipes) != 1:
            raise _ModsquareProfileRejected("initializer_profile_ambiguous")
        recipe = recipes[0]

        bounded_resources = []
        total_resource_bytes = 0
        for index, item in enumerate(resources):
            if index >= MAX_RESOURCE_COUNT:
                raise TimeoutError("resource_count_limit")
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or type(item[1]) is not bytes
            ):
                raise _ModsquareProfileRejected("resource_model_invalid")
            total_resource_bytes += len(item[1])
            if total_resource_bytes > MAX_RESOURCE_BYTES:
                raise TimeoutError("resource_byte_limit")
            bounded_resources.append(item)
        matched_resources = [
            item for item in bounded_resources if item[0] == recipe["resource_literal"]
        ]
        if len(matched_resources) != 1:
            raise _ModsquareProfileRejected("initializer_resource_ambiguous_or_missing")
        resource_name, encrypted = matched_resources[0]
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("managed_proxy_profile_deadline_exceeded")
        clear = decrypt_eaz_proxy_modsquare_table(
            encrypted,
            constants=recipe["constants"],
            clock=clock,
            max_elapsed_seconds=min(MAX_PROFILE_ELAPSED_SECONDS, remaining),
        )
        records = parse_modsquare_proxy_records(clear)
        validation = _validate_modsquare_proxy_records(
            data,
            pe,
            methods,
            recipe["method_token"],
            records,
            resolver,
            deadline=deadline,
            clock=clock,
        )
        candidate = {
            "transform_profile": MODSQUARE_PROXY_PROFILE,
            "initializer_method_token": f"0x{recipe['method_token']:08x}",
            "initializer_body_sha256": recipe["method_body_sha256"],
            "initializer_canonical_sha256": recipe["canonical_sha256"],
            "initializer_control_flow_sha256": (
                _MODSQUARE_INITIALIZER_CONTROL_FLOW_SHA256
            ),
            "build_constants_sha256": hashlib.sha256(
                struct.pack("<4I", *recipe["constants"])
            ).hexdigest(),
            "build_constants_returned": False,
            "resource_name_sha256": hashlib.sha256(
                resource_name.encode("utf-8")
            ).hexdigest(),
            "resource_name_length": len(resource_name),
            "resource_sha256": hashlib.sha256(encrypted).hexdigest(),
            "resource_size": len(encrypted),
            "clear_sha256": hashlib.sha256(clear).hexdigest(),
            "record_count": len(records),
            "valid_record_count": len(records),
            "valid_record_ratio": 1.0,
            **validation,
            "validation_level": "cil_recipe_owner_use_and_metadata_validated",
            "runtime_dispatch_verified": False,
            "protector_attribution_confirmed": False,
        }
        if include_records:
            candidate["records"] = records
        report.update(
            status="matched",
            profile=MODSQUARE_PROXY_PROFILE,
            candidate_count=1,
            candidates=[candidate],
        )
        return report
    except TimeoutError as error:
        report.update(
            status="partial_budget",
            reason=str(error),
            budget_exhausted=[str(error)],
        )
        return report
    except ManagedMethodRecoveryError as error:
        report.update(
            status="partial_budget",
            reason="managed_method_normalization_incomplete",
            budget_exhausted=[str(error)],
        )
        return report
    except _ModsquareProfileRejected as error:
        report.update(status="rejected", reason=str(error))
        return report
    except (ArithmeticError, AttributeError, TypeError, ValueError) as error:
        report.update(
            status="partial_budget",
            reason="modsquare_profile_parse_incomplete",
            parse_error=type(error).__name__,
        )
        return report


def analyze_modsquare_proxy_profile(
    data: bytes,
    pe: Any,
    resource_scan: Any,
    resolver: MetadataResolver,
    *,
    include_records: bool = False,
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_PROFILE_ELAPSED_SECONDS,
) -> dict[str, Any]:
    """source再検証済みsnapshotだけからmod-square profileを復元する。"""

    rejected = {
        "status": "partial_budget",
        "profile": None,
        "candidate_count": 0,
        "candidates": [],
        "reason": "modsquare_source_binding_incomplete",
        "budget_exhausted": ["resource_inventory"],
        "source_coverage_verified": False,
        "executed": False,
        "emulated": False,
        "clr_loaded": False,
        "network_contacted": False,
        "raw_resource_name_published": False,
        "raw_resource_bytes_published": False,
    }
    try:
        resources, fresh_scan = _resource_blob_scope(
            data,
            pe,
            resource_scan=resource_scan,
        )
        coverage = fresh_scan.coverage()
        work = coverage.get("work")
        if (
            type(coverage) is not dict
            or coverage.get("inventory_complete") is not True
            or coverage.get("embedded_scan_complete") is not True
            or coverage.get("input_binding_verified") is not True
            or type(work) is not dict
            or work.get("shared_snapshot_reused") is not True
        ):
            return rejected
    except Exception:  # noqa: BLE001 - resource snapshotの依存例外を境界で固定化
        return rejected
    report = _analyze_modsquare_proxy_profile_resources(
        data,
        pe,
        resources,
        resolver,
        include_records=include_records,
        clock=clock,
        max_elapsed_seconds=max_elapsed_seconds,
    )
    report["source_coverage_verified"] = True
    return report


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


def _oversized_resource_may_be_proxy_table(
    content: bytes,
    transforms: Sequence[Mapping[str, Any]],
    metadata_resolver: MetadataResolver | None,
) -> bool:
    """上限超過resourceの先頭8 recordだけでrecipe適用可能性を判定する。

    全体で採用するproxy tableは全recordが構文・metadataとも解決済みで
    なければならない。そのため、各変換で先頭8件すべてがその必要条件を
    満たさない場合は、全体を走査せずとも安全に適用外と証明できる。
    """

    if len(content) < 64 or len(content) % 8:
        return False
    prefix = content[:64]
    for transform in transforms:
        try:
            clear = decrypt_eaz_proxy_table(
                prefix,
                seed=int(transform["seed"]),
                addend=int(transform["addend"]),
            )
            records = parse_proxy_records(clear)
        except (ArithmeticError, KeyError, TypeError, ValueError):
            continue
        if len(records) != 8 or any(
            record.get("valid") is not True for record in records
        ):
            continue
        if metadata_resolver is not None:
            resolved = True
            for record in records:
                try:
                    field = int(record["field_token"], 16)
                    target = int(record["target_token"], 16)
                    field_resolution = metadata_resolver.resolve(field, kind="field")
                    target_resolution = metadata_resolver.resolve(target)
                except (AttributeError, KeyError, TypeError, ValueError):
                    resolved = False
                    break
                if (
                    field_resolution.get("status") != "resolved"
                    or target_resolution.get("status") != "resolved"
                ):
                    resolved = False
                    break
            if not resolved:
                continue
        return True
    return False


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
            if _oversized_resource_may_be_proxy_table(
                content,
                reviewed_transforms,
                metadata_resolver,
            ):
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
        modsquare = analyze_modsquare_proxy_profile(
            data,
            pe,
            resource_scan,
            resolver,
            include_records=include_records,
        )
        proxy["modsquare_profile_analysis"] = modsquare
        if modsquare["status"] == "matched":
            for candidate in modsquare["candidates"]:
                identity = (
                    candidate["resource_sha256"],
                    candidate["clear_sha256"],
                    candidate["record_count"],
                )
                existing = {
                    (
                        item.get("resource_sha256"),
                        item.get("clear_sha256"),
                        item.get("record_count"),
                    )
                    for item in proxy["candidates"]
                }
                if identity not in existing:
                    proxy["candidates"].append(candidate)
            proxy["status"] = "matched"
            proxy["profile"] = "eazfuscator_dynamic_proxy_multi_variant"
        elif modsquare["status"] == "partial_budget" and not proxy["candidates"]:
            proxy["status"] = "partial_budget"
            proxy["budget_exhausted"] = sorted(
                set(proxy["budget_exhausted"] + modsquare.get("budget_exhausted", []))
            )
        proxy["transform_discovery"] = {
            "status": (
                "cil_derived_modsquare_recipe"
                if modsquare["status"] == "matched"
                else "caller_supplied_static_recipe"
                if supplied_transforms
                else "built_in_profiles_only"
            ),
            "supplied_transform_count": len(supplied_transforms),
            "modsquare_profile_status": modsquare["status"],
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
