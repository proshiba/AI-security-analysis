#!/usr/bin/env python3
"""flattened managed resolverのkeyed Eaz resourceを静的に復元する。

CLR、CIL、復元PEは実行しない。MethodDefをdnfile/dncilで有界に読み、
dispatcher経路、定数byte配列、mask loop、word transform、partial-word
loop、raw Deflate、managed PE構造がすべて一致する場合だけ1件を返す。

この復元器が確認するのはprotector recipeであり、マルウェアfamilyではない。
終端設定やfamily固有markerを別途確認するまでfamily帰属には使用しない。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import stat
import struct
import sys
import time
import warnings
import zlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # 単独CLI
    sys.path.insert(0, str(ROOT))
ANALYSIS_ROOT = ROOT / "analysis-framework"
if str(ANALYSIS_ROOT) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_ROOT))

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from malware.purehvnc.managed_resource_recovery import (
    Instruction,
    StaticRecoveryError,
    _array_store,
    _branch_target,
    _eaz_next_accumulator,
    _int_constant,
    _local_index,
    _scalar_assignment,
    _token,
    prove_constant_return,
    trace_flattened_switch,
)

from extractors.managed_pe import has_clr_metadata
from unpackers.bounded_pe_scan import inspect_structural_pe_extent

MAX_INPUT_BYTES = 32 << 20
MAX_METADATA_ROWS = 131_072
MAX_METHOD_ROWS = 4_096
MAX_METHOD_BYTES = 256 << 10
MAX_METHOD_EXTRA_SECTION_BYTES = 256 << 10
MAX_METHOD_EXTRA_SECTIONS = 4_096
MAX_METHOD_INSTRUCTIONS = 8_192
MAX_TOTAL_METHOD_BYTES = 32 << 20
MAX_TOTAL_METHOD_INSTRUCTIONS = 1_000_000
MIN_DISPATCH_TARGETS = 256
MAX_DISPATCH_TARGETS = 1_024
MAX_TRACE_STATES = 1_024
MAX_ARRAY_STORES = 1_024
MAX_RESOURCE_COUNT = 64
MAX_RESOURCE_BYTES = 32 << 20
MAX_TOTAL_RESOURCE_BYTES = 64 << 20
MAX_OUTPUT_BYTES = 64 << 20
MAX_DEFLATE_RATIO = 64.0
MAX_ELAPSED_SECONDS = 10.0
DEFLATE_CHUNK_BYTES = 64 << 10
WORD_TIME_CHECK_INTERVAL = 4_096
_U32_MASK = 0xFFFFFFFF

# 4 buildで、local番号と先頭4定数だけを正規化した142-opcode coreが一致した。
TRANSFORM_CORE_CANONICAL_SHA256 = (
    "81c8ace6e3789d21dbaa5978fff4118d08220f2dbd3598c648354209abf96be8"
)
_TRANSFORM_FIXED_CONSTANTS = (
    5,
    27,
    16_711_935,
    -16_711_936,
    8,
    8,
    1_298_283_676,
    597_857_876,
    232_318_664,
    0,
    1,
    9_495,
    65_535,
    16,
    10_476,
    65_535,
    16,
    22_014,
    9,
    1,
    5,
    11,
)
_CALL_OPCODES = frozenset({"call", "callvirt", "calli", "newobj"})
_SIMPLE_BRANCHES = frozenset(
    {"br", "br.s", "brtrue", "brtrue.s", "brfalse", "brfalse.s"}
)
_RELATIONAL_BRANCHES = frozenset(
    {
        "beq",
        "beq.s",
        "bge",
        "bge.s",
        "bge.un",
        "bge.un.s",
        "bgt",
        "bgt.s",
        "bgt.un",
        "bgt.un.s",
        "ble",
        "ble.s",
        "ble.un",
        "ble.un.s",
        "blt",
        "blt.s",
        "blt.un",
        "blt.un.s",
        "bne.un",
        "bne.un.s",
    }
)


class RecoveryError(ValueError):
    """recipe不一致、入力不整合、または上限超過を表す。"""


@dataclass(frozen=True)
class ResolverRecipe:
    """1個のMethodDefから静的に確定したresource transform。"""

    method_token: int
    switch_targets: int
    traced_states: int
    helper_tokens: tuple[int, ...]
    key: bytes
    key_local: int
    key_alias: int
    key_store_count: int
    mask: bytes
    mask_local: int
    mask_alias: int
    mask_store_count: int
    seed: int
    addend: int
    transform_core_offset: int
    transform_core_end_offset: int
    partial_word_profile: bool


@dataclass(frozen=True)
class _DecodedMethod:
    token: int
    code_size: int
    instructions: tuple[Instruction, ...]


@contextmanager
def _contained_parser_diagnostics():
    """dnfileの既知診断をこの解析scope内だけ抑止する。"""

    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        logging.disable(previous)


def _check_time(deadline: float, clock: Callable[[], float]) -> None:
    if clock() > deadline:
        raise RecoveryError("elapsed_time_limit")


def _operand_value(value: Any) -> Any:
    value = getattr(value, "value", value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_operand_value(item) for item in value]
    return str(value)


def _local(instruction: Instruction, prefix: str) -> int | None:
    try:
        return _local_index(instruction, prefix)
    except StaticRecoveryError as exc:
        raise RecoveryError(str(exc)) from exc


def _constant(instruction: Instruction) -> int | None:
    try:
        return _int_constant(instruction)
    except StaticRecoveryError as exc:
        raise RecoveryError(str(exc)) from exc


def _method_section_end(data: bytes, pe: Any, rva: int, offset: int) -> int:
    """MethodDefを含むPE sectionのfile終端を検証して返す。"""

    try:
        section = pe.get_section_by_rva(rva)
    except Exception as exc:
        raise RecoveryError("method_section_unavailable") from exc
    if section is None:
        raise RecoveryError("method_section_unavailable")
    try:
        raw_start = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise RecoveryError("method_section_invalid") from exc
    if raw_start < 0 or raw_size <= 0:
        raise RecoveryError("method_section_invalid")
    raw_end = raw_start + raw_size
    if raw_end <= raw_start or not raw_start <= offset < raw_end:
        raise RecoveryError("method_offset_outside_section")
    return min(raw_end, len(data))


def _bounded_method_body_data(data: bytes, pe: Any, rva: int, offset: int) -> bytes:
    """宣言headerと追加sectionを検証し、有界なmethod bodyだけを返す。"""

    section_end = _method_section_end(data, pe, rva, offset)
    first = data[offset]
    header_kind = first & 0x03
    if header_kind == 0x02:  # ECMA-335 tiny format
        header_size = 1
        code_size = first >> 2
        more_sections = False
    elif header_kind == 0x03:  # ECMA-335 fat format
        if offset + 12 > section_end:
            raise RecoveryError("method_fat_header_out_of_bounds")
        flags_and_size = struct.unpack_from("<H", data, offset)[0]
        header_size = ((flags_and_size >> 12) & 0x0F) * 4
        if not 12 <= header_size <= 60 or offset + header_size > section_end:
            raise RecoveryError("method_fat_header_invalid")
        code_size = struct.unpack_from("<I", data, offset + 4)[0]
        more_sections = bool(flags_and_size & 0x08)
    else:
        raise RecoveryError("method_header_invalid")

    if not 0 < code_size <= MAX_METHOD_BYTES:
        raise RecoveryError("method_byte_limit")
    body_end = offset + header_size + code_size
    if body_end > section_end:
        raise RecoveryError("method_code_outside_section")
    if not more_sections:
        return data[offset:body_end]

    cursor = (body_end + 3) & ~3
    extra_bytes = cursor - body_end
    section_count = 0
    while True:
        if cursor + 4 > section_end:
            raise RecoveryError("method_extra_section_header_out_of_bounds")
        section_count += 1
        if section_count > MAX_METHOD_EXTRA_SECTIONS:
            raise RecoveryError("method_extra_section_count_limit")
        kind = data[cursor]
        if kind & 0x40:  # fat section header
            section_size = int.from_bytes(data[cursor + 1 : cursor + 4], "little")
        else:  # small section header
            section_size = data[cursor + 1]
        if section_size < 4:
            raise RecoveryError("method_extra_section_size_invalid")
        section_end_offset = cursor + section_size
        if section_end_offset > section_end:
            raise RecoveryError("method_extra_section_out_of_bounds")
        extra_bytes += section_size
        if extra_bytes > MAX_METHOD_EXTRA_SECTION_BYTES:
            raise RecoveryError("method_extra_section_byte_limit")
        if not kind & 0x80:  # MoreSects
            return data[offset:section_end_offset]
        next_cursor = (section_end_offset + 3) & ~3
        extra_bytes += next_cursor - section_end_offset
        if extra_bytes > MAX_METHOD_EXTRA_SECTION_BYTES:
            raise RecoveryError("method_extra_section_byte_limit")
        cursor = next_cursor


def _decode_method(
    data: bytes,
    pe: Any,
    row: Any,
    token: int,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> _DecodedMethod:
    _check_time(deadline, clock)
    rva = int(getattr(row, "Rva", 0) or 0)
    if not rva:
        raise RecoveryError("method_has_no_body")
    try:
        offset = int(pe.get_offset_from_rva(rva))
    except Exception as exc:
        raise RecoveryError("method_rva_invalid") from exc
    if not 0 <= offset < len(data):
        raise RecoveryError("method_offset_out_of_bounds")
    try:
        bounded = _bounded_method_body_data(data, pe, rva, offset)
        body = read_method_body_from_bytes(bounded)
    except RecoveryError:
        raise
    except Exception as exc:
        raise RecoveryError("method_body_parse_failed") from exc
    code_size = int(getattr(body, "code_size", 0) or 0)
    if not 0 < code_size <= MAX_METHOD_BYTES:
        raise RecoveryError("method_byte_limit")
    raw = list(getattr(body, "instructions", ()) or ())
    if not 0 < len(raw) <= MAX_METHOD_INSTRUCTIONS:
        raise RecoveryError("method_instruction_limit")
    instructions = tuple(
        Instruction(
            int(item.offset),
            str(item.opcode.name).casefold(),
            _operand_value(item.operand),
        )
        for item in raw
    )
    if any(
        instructions[index - 1].offset >= instructions[index].offset
        for index in range(1, len(instructions))
    ):
        raise RecoveryError("method_offsets_not_strictly_increasing")
    _check_time(deadline, clock)
    return _DecodedMethod(token, code_size, instructions)


def _metadata_row_count(pe: Any) -> int:
    tables = getattr(getattr(pe, "net", None), "mdtables", None)
    listed = list(getattr(tables, "tables_list", ()) or ())
    if len(listed) > 64:
        raise RecoveryError("metadata_table_count_limit")
    total = 0
    for table in listed:
        rows = list(getattr(table, "rows", ()) or ())
        total += len(rows)
        if total > MAX_METADATA_ROWS:
            raise RecoveryError("metadata_row_limit")
    return total


def _system_byte_tokens(pe: Any) -> frozenset[int]:
    table = getattr(getattr(pe.net, "mdtables", None), "TypeRef", None)
    rows = list(getattr(table, "rows", ()) or ())
    if len(rows) > MAX_METADATA_ROWS:
        raise RecoveryError("typeref_row_limit")
    tokens = {
        0x01000000 | index
        for index, row in enumerate(rows, 1)
        if str(getattr(row, "TypeNamespace", "")) == "System"
        and str(getattr(row, "TypeName", "")) == "Byte"
    }
    if not tokens:
        raise RecoveryError("system_byte_typeref_missing")
    return frozenset(tokens)


def _is_byte_newarr(instruction: Instruction, byte_tokens: frozenset[int]) -> bool:
    return instruction.opcode == "newarr" and instruction.operand in byte_tokens


def _candidate_shape(
    instructions: Sequence[Instruction],
    byte_tokens: frozenset[int],
) -> bool:
    switches = [
        item
        for item in instructions
        if item.opcode == "switch"
        and isinstance(item.operand, (list, tuple))
        and MIN_DISPATCH_TARGETS <= len(item.operand) <= MAX_DISPATCH_TARGETS
    ]
    if len(switches) != 1:
        return False
    allocations: list[int] = []
    for index in range(2, len(instructions)):
        if (
            _is_byte_newarr(instructions[index - 1], byte_tokens)
            and _local(instructions[index], "stloc") is not None
        ):
            size = _constant(instructions[index - 2])
            if size is not None:
                allocations.append(size)
    constants = {_constant(item) for item in instructions}
    return (
        allocations.count(32) == 1
        and allocations.count(16) == 1
        and {9_495, 10_476, 22_014}.issubset(constants)
        and sum(item.opcode == "stelem.i1" for item in instructions) >= 48
    )


def _scan_resolver_candidates(
    data: bytes,
    pe: Any,
    byte_tokens: frozenset[int],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[list[_DecodedMethod], dict[str, int]]:
    table = getattr(getattr(pe.net, "mdtables", None), "MethodDef", None)
    rows = list(getattr(table, "rows", ()) or ())
    if not rows or len(rows) > MAX_METHOD_ROWS:
        raise RecoveryError("method_row_limit")
    candidates: list[_DecodedMethod] = []
    parsed = 0
    bodyless = 0
    failed = 0
    total_bytes = 0
    total_instructions = 0
    for rid, row in enumerate(rows, 1):
        _check_time(deadline, clock)
        if not int(getattr(row, "Rva", 0) or 0):
            bodyless += 1
            continue
        token = 0x06000000 | rid
        try:
            decoded = _decode_method(
                data,
                pe,
                row,
                token,
                deadline=deadline,
                clock=clock,
            )
        except RecoveryError as exc:
            if str(exc) in {"method_byte_limit", "method_instruction_limit"}:
                raise
            failed += 1
            continue
        parsed += 1
        total_bytes += decoded.code_size
        total_instructions += len(decoded.instructions)
        if total_bytes > MAX_TOTAL_METHOD_BYTES:
            raise RecoveryError("total_method_byte_limit")
        if total_instructions > MAX_TOTAL_METHOD_INSTRUCTIONS:
            raise RecoveryError("total_method_instruction_limit")
        if _candidate_shape(decoded.instructions, byte_tokens):
            if candidates:
                # 2件目で一意性は回復しないため、大きな命令tupleを追加保持せず
                # resolver曖昧性を直ちにfail-closedで確定する。
                raise RecoveryError("resolver_candidate_ambiguous")
            candidates.append(decoded)
    if failed:
        raise RecoveryError("method_inventory_incomplete")
    return candidates, {
        "method_rows": len(rows),
        "method_bodies": parsed,
        "bodyless_methods": bodyless,
        "method_bytes": total_bytes,
        "method_instructions": total_instructions,
    }


def _memberref_owner(row: Any) -> tuple[str, str] | None:
    owner = getattr(getattr(row, "Class", None), "row", None)
    namespace = getattr(owner, "TypeNamespace", None)
    name = getattr(owner, "TypeName", None)
    if namespace is None or name is None:
        return None
    return str(namespace), str(name)


def _has_deflate_constructor(pe: Any, instructions: Sequence[Instruction]) -> bool:
    rows = list(
        getattr(
            getattr(getattr(pe.net, "mdtables", None), "MemberRef", None), "rows", ()
        )
        or ()
    )
    for instruction in instructions:
        token = _token(instruction)
        if instruction.opcode != "newobj" or token is None or token >> 24 != 0x0A:
            continue
        rid = token & 0xFFFFFF
        if not 1 <= rid <= len(rows):
            continue
        row = rows[rid - 1]
        if str(getattr(row, "Name", "")) == ".ctor" and _memberref_owner(row) == (
            "System.IO.Compression",
            "DeflateStream",
        ):
            return True
    return False


def _dispatcher_profile(
    instructions: Sequence[Instruction],
) -> tuple[
    int,
    tuple[int, ...],
    int,
    frozenset[int],
    dict[int, int],
]:
    switch_indices = [
        index
        for index, item in enumerate(instructions)
        if item.opcode == "switch"
        and isinstance(item.operand, (list, tuple))
        and MIN_DISPATCH_TARGETS <= len(item.operand) <= MAX_DISPATCH_TARGETS
    ]
    if len(switch_indices) != 1:
        raise RecoveryError("dispatcher_ambiguous")
    index = switch_indices[0]
    if index < 3:
        raise RecoveryError("dispatcher_prologue_missing")
    state = _local(instructions[index - 2], "stloc")
    if (
        _constant(instructions[index - 3]) is None
        or state is None
        or _local(instructions[index - 1], "ldloc") != state
    ):
        raise RecoveryError("dispatcher_prologue_mismatch")
    targets = tuple(instructions[index].operand)
    by_offset = {item.offset for item in instructions}
    if any(
        isinstance(target, bool)
        or not isinstance(target, int)
        or target not in by_offset
        for target in targets
    ):
        raise RecoveryError("dispatcher_target_invalid")
    dispatch_offsets = frozenset(
        {
            instructions[index - 2].offset,
            instructions[index - 1].offset,
            instructions[index].offset,
        }
    )
    if index + 7 >= len(instructions):
        raise RecoveryError("dispatcher_extension_missing")
    extension = instructions[index + 1 : index + 8]
    if (
        _local(extension[0], "ldloc") != state
        or _constant(extension[1]) is None
        or extension[2].opcode not in {"beq", "beq.s"}
        or _local(extension[3], "ldloc") != state
        or _constant(extension[4]) is None
        or extension[5].opcode not in {"beq", "beq.s"}
        or extension[6].opcode not in {"br", "br.s"}
    ):
        raise RecoveryError("dispatcher_extension_mismatch")
    special = _constant(extension[1])
    guard = _constant(extension[4])
    special_target = _branch_target(extension[2])
    guard_target = _branch_target(extension[5])
    fallback = _branch_target(extension[6])
    if (
        special is None
        or guard is None
        or special < len(targets)
        or guard < len(targets)
        or special_target not in by_offset
        or guard_target != instructions[index - 1].offset
        or fallback not in by_offset
    ):
        raise RecoveryError("dispatcher_extension_invalid")
    return index, targets, state, dispatch_offsets, {special: int(special_target)}


def _helper_constants(
    data: bytes,
    pe: Any,
    instructions: Sequence[Instruction],
    dispatch_offsets: frozenset[int],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> dict[int, bool | None | int]:
    tokens: set[int] = set()
    for index, instruction in enumerate(instructions):
        if (
            instruction.opcode in {"brtrue", "brtrue.s", "brfalse", "brfalse.s"}
            and _branch_target(instruction) in dispatch_offsets
            and index
            and instructions[index - 1].opcode == "call"
        ):
            token = _token(instructions[index - 1])
            if token is None or token >> 24 != 0x06:
                raise RecoveryError("dispatcher_helper_token_invalid")
            tokens.add(token)
    if len(tokens) != 2:
        raise RecoveryError("dispatcher_helper_count_mismatch")
    rows = list(getattr(pe.net.mdtables.MethodDef, "rows", ()) or ())
    result: dict[int, bool | None | int] = {}
    for token in sorted(tokens):
        rid = token & 0xFFFFFF
        if not 1 <= rid <= len(rows):
            raise RecoveryError("dispatcher_helper_missing")
        decoded = _decode_method(
            data,
            pe,
            rows[rid - 1],
            token,
            deadline=deadline,
            clock=clock,
        )
        try:
            result[token] = prove_constant_return(decoded.instructions)
        except StaticRecoveryError as exc:
            raise RecoveryError("dispatcher_helper_not_constant") from exc
    if not any(value is True for value in result.values()) or not any(
        value is None for value in result.values()
    ):
        raise RecoveryError("dispatcher_helper_values_mismatch")
    return result


def _array_allocation(
    instructions: Sequence[Instruction],
    index: int,
    byte_tokens: frozenset[int],
) -> tuple[int, int] | None:
    if index < 2 or not _is_byte_newarr(instructions[index - 1], byte_tokens):
        return None
    local = _local(instructions[index], "stloc")
    size = _constant(instructions[index - 2])
    if local is None or size not in {16, 32}:
        return None
    return local, size


def _recover_arrays(
    trace: Any,
    helper_tokens: frozenset[int],
    byte_tokens: frozenset[int],
) -> tuple[dict[int, tuple[int, int, bytes, int]], int]:
    sizes: dict[int, int] = {}
    values: dict[int, dict[int, int]] = {}
    stores: dict[int, int] = {}
    aliases: dict[int, int] = {}
    scalars: dict[int, int] = {}
    allocation_order: list[int] = []
    total_stores = 0
    for block_index, traced in enumerate(trace.blocks):
        if len(aliases) < 2:
            for instruction in traced.instructions:
                if instruction.opcode in _RELATIONAL_BRANCHES:
                    raise RecoveryError("runtime_branch_before_array_completion")
                if (
                    instruction.opcode in _CALL_OPCODES
                    and instruction.operand not in helper_tokens
                ):
                    raise RecoveryError("unknown_call_before_array_completion")
        allowed_array_loads: set[int] = set()
        alias_loads: set[int] = set()
        for index, instruction in enumerate(traced.instructions):
            allocation = _array_allocation(traced.instructions, index, byte_tokens)
            stored_local = _local(instruction, "stloc")
            if allocation is not None:
                local, size = allocation
                if local in sizes or size in sizes.values():
                    raise RecoveryError("array_allocation_ambiguous")
                sizes[local] = size
                values[local] = {}
                stores[local] = 0
                allocation_order.append(size)
                scalars.pop(local, None)
                continue
            if stored_local in sizes:
                raise RecoveryError("array_local_reassigned")
            if instruction.opcode == "stelem.i1" and sizes:
                try:
                    store = _array_store(traced.instructions, index, scalars)
                except StaticRecoveryError as exc:
                    raise RecoveryError("array_store_invalid") from exc
                if store is not None and store[0] in sizes:
                    local, element_index, value = store
                    if not 0 <= element_index < sizes[local]:
                        raise RecoveryError("array_store_out_of_bounds")
                    values[local][element_index] = value
                    stores[local] += 1
                    total_stores += 1
                    if total_stores > MAX_ARRAY_STORES:
                        raise RecoveryError("array_store_limit")
                    source_index = index - 3
                    if (
                        source_index < 0
                        or _local(traced.instructions[source_index], "ldloc") != local
                    ):
                        source_index = index - 5
                    if (
                        source_index < 0
                        or _local(traced.instructions[source_index], "ldloc") != local
                    ):
                        raise RecoveryError("array_store_source_mismatch")
                    allowed_array_loads.add(traced.instructions[source_index].offset)
            loaded_local = _local(instruction, "ldloc")
            if (
                loaded_local in sizes
                and loaded_local not in aliases
                and index + 1 < len(traced.instructions)
            ):
                alias = _local(traced.instructions[index + 1], "stloc")
                if alias is not None:
                    if alias == loaded_local:
                        raise RecoveryError("array_self_alias")
                    if set(values[loaded_local]) != set(range(sizes[loaded_local])):
                        raise RecoveryError("array_initialization_incomplete")
                    aliases[loaded_local] = alias
                    alias_loads.add(instruction.offset)
            try:
                assignment = _scalar_assignment(traced.instructions, index, scalars)
            except StaticRecoveryError as exc:
                raise RecoveryError("scalar_assignment_invalid") from exc
            if assignment is not None:
                scalars[assignment[0]] = assignment[1]
            elif stored_local is not None and allocation is None:
                scalars.pop(stored_local, None)
        for instruction in traced.instructions:
            loaded_local = _local(instruction, "ldloc")
            if (
                loaded_local in sizes
                and instruction.offset not in allowed_array_loads
                and instruction.offset not in alias_loads
            ):
                raise RecoveryError("array_alias_or_use_unproven")
            if instruction.opcode.startswith("ldloca"):
                address_local = _local(instruction, "ldloca")
                if address_local in sizes:
                    raise RecoveryError("array_address_escape")
        if len(aliases) == 2:
            if allocation_order != [32, 16]:
                raise RecoveryError("array_allocation_order_mismatch")
            result = {
                size: (
                    local,
                    aliases[local],
                    bytes(values[local][index] for index in range(size)),
                    stores[local],
                )
                for local, size in sizes.items()
            }
            return result, block_index
    raise RecoveryError("constant_arrays_not_completed")


def _matches_local_constant_store(
    instructions: Sequence[Instruction],
    local: int,
    value: int,
) -> bool:
    return any(
        _constant(instructions[index]) == value
        and _local(instructions[index + 1], "stloc") == local
        for index in range(len(instructions) - 1)
    )


def _matches_increment(
    instructions: Sequence[Instruction], local: int, amount: int = 1
) -> bool:
    return any(
        _local(instructions[index], "ldloc") == local
        and _constant(instructions[index + 1]) == amount
        and instructions[index + 2].opcode == "add"
        and _local(instructions[index + 3], "stloc") == local
        for index in range(len(instructions) - 3)
    )


def _verify_mask_loop(
    instructions: Sequence[Instruction],
    trace: Any,
    prefix_block: int,
    *,
    key_alias: int,
    mask_alias: int,
    dispatcher_offset: int,
    dispatcher_targets: Sequence[int],
    dispatch_offsets: frozenset[int],
    helper_constants: Mapping[int, bool | None | int],
    extra_targets: Mapping[int, int],
) -> None:
    bodies: list[tuple[int, int]] = []
    for index in range(len(instructions) - 10):
        loop_index = _local(instructions[index + 1], "ldloc")
        if (
            _local(instructions[index], "ldloc") == key_alias
            and loop_index is not None
            and _local(instructions[index + 2], "ldloc") == key_alias
            and _local(instructions[index + 3], "ldloc") == loop_index
            and instructions[index + 4].opcode == "ldelem.u1"
            and _local(instructions[index + 5], "ldloc") == mask_alias
            and _local(instructions[index + 6], "ldloc") == loop_index
            and instructions[index + 7].opcode == "ldelem.u1"
            and instructions[index + 8].opcode == "xor"
            and instructions[index + 9].opcode == "conv.u1"
            and instructions[index + 10].opcode == "stelem.i1"
        ):
            bodies.append((instructions[index].offset, loop_index))
    if len(bodies) != 1:
        raise RecoveryError("key_mask_loop_body_ambiguous")
    body_offset, loop_index = bodies[0]
    body_states = [
        state
        for state, target in enumerate(dispatcher_targets)
        if target == body_offset
    ]
    if len(body_states) != 1:
        raise RecoveryError("key_mask_loop_state_ambiguous")
    try:
        body_trace = trace_flattened_switch(
            instructions,
            dispatcher_offset=dispatcher_offset,
            initial_state=body_states[0],
            helper_constants=helper_constants,
            extra_state_targets=extra_targets,
            dispatch_offsets=dispatch_offsets,
            max_states=MAX_TRACE_STATES,
            stop_on_other_conditionals=True,
        )
    except StaticRecoveryError as exc:
        raise RecoveryError("key_mask_loop_body_trace_failed") from exc
    successor = body_trace.blocks[0].successor
    if body_trace.blocks[0].target_offset != body_offset or successor is None:
        raise RecoveryError("key_mask_loop_successor_missing")
    tail = tuple(
        instruction
        for block in trace.blocks[prefix_block + 1 :]
        for instruction in block.instructions
    )
    if not _matches_local_constant_store(tail, loop_index, 0):
        raise RecoveryError("key_mask_loop_index_init_missing")
    conditions = [
        index
        for index in range(len(tail) - 4)
        if _local(tail[index], "ldloc") == loop_index
        and _local(tail[index + 1], "ldloc") == mask_alias
        and tail[index + 2].opcode == "ldlen"
        and tail[index + 3].opcode == "conv.i4"
        and tail[index + 4].opcode in {"blt", "blt.s"}
        and _branch_target(tail[index + 4]) == body_offset
    ]
    if len(conditions) != 1:
        raise RecoveryError("key_mask_loop_condition_missing")
    try:
        loop_trace = trace_flattened_switch(
            instructions,
            dispatcher_offset=dispatcher_offset,
            initial_state=successor,
            helper_constants=helper_constants,
            extra_state_targets=extra_targets,
            dispatch_offsets=dispatch_offsets,
            max_states=MAX_TRACE_STATES,
            stop_on_other_conditionals=True,
        )
    except StaticRecoveryError as exc:
        raise RecoveryError("key_mask_loop_trace_failed") from exc
    loop_instructions = tuple(
        instruction for block in loop_trace.blocks for instruction in block.instructions
    )
    if not _matches_increment(loop_instructions, loop_index):
        raise RecoveryError("key_mask_loop_increment_missing")
    terminal = loop_trace.blocks[-1].instructions
    terminal_match = any(
        _local(terminal[index], "ldloc") == loop_index
        and _local(terminal[index + 1], "ldloc") == mask_alias
        and terminal[index + 2].opcode == "ldlen"
        and terminal[index + 3].opcode == "conv.i4"
        and terminal[index + 4].opcode in {"blt", "blt.s"}
        and _branch_target(terminal[index + 4]) == body_offset
        for index in range(len(terminal) - 4)
    )
    if not terminal_match:
        raise RecoveryError("key_mask_loop_back_edge_missing")


def _canonical_transform_core(
    instructions: Sequence[Instruction],
) -> tuple[int, int, int, int]:
    marker_indices = [
        index for index, item in enumerate(instructions) if _constant(item) == 9_495
    ]
    if len(marker_indices) != 1:
        raise RecoveryError("transform_core_marker_ambiguous")
    marker = marker_indices[0]
    starts = [
        index
        for index in range(max(0, marker - 100), marker)
        if instructions[index].opcode == "dup"
    ]
    if not starts:
        raise RecoveryError("transform_core_start_missing")
    start = starts[-1]
    end = None
    for index in range(start, len(instructions) - 4):
        if [item.opcode for item in instructions[index : index + 4]] == [
            "conv.r.un",
            "conv.r8",
            "conv.u4",
            "add",
        ] and _local(instructions[index + 4], "stloc") is not None:
            end = index + 5
            break
    if end is None:
        raise RecoveryError("transform_core_end_missing")
    core = instructions[start:end]
    if len(core) != 142:
        raise RecoveryError("transform_core_length_mismatch")
    offsets = {item.offset: index for index, item in enumerate(core)}
    local_map: dict[int, int] = {}
    rows: list[list[Any]] = []
    literal_index = 0
    for instruction in core:
        local = None
        if instruction.opcode.startswith(("ldloc", "stloc")):
            local = _local(
                instruction,
                "ldloc" if instruction.opcode.startswith("ldloc") else "stloc",
            )
        if local is not None:
            local_map.setdefault(local, len(local_map))
            operand: Any = ["local", local_map[local]]
        elif instruction.opcode in _RELATIONAL_BRANCHES | _SIMPLE_BRANCHES:
            target = _branch_target(instruction)
            operand = ["target", offsets.get(target, "external")]
        else:
            constant = _constant(instruction)
            if constant is not None:
                operand = [
                    "const",
                    "variable" if literal_index < 4 else constant,
                ]
                literal_index += 1
            else:
                if instruction.operand is not None:
                    raise RecoveryError("transform_core_operand_unexpected")
                operand = None
        rows.append([instruction.opcode, operand])
    digest = hashlib.sha256(
        json.dumps(rows, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    constants = tuple(value for item in core if (value := _constant(item)) is not None)
    if (
        digest != TRANSFORM_CORE_CANONICAL_SHA256
        or len(constants) != 26
        or constants[4:] != _TRANSFORM_FIXED_CONSTANTS
    ):
        raise RecoveryError("transform_core_signature_mismatch")
    return (
        constants[0] & _U32_MASK,
        constants[3] & _U32_MASK,
        core[0].offset,
        core[-1].offset,
    )


def _find_length_operation(
    instructions: Sequence[Instruction], opcode: str
) -> list[tuple[int, int]]:
    found = []
    for index in range(len(instructions) - 5):
        source = _local(instructions[index], "ldloc")
        result = _local(instructions[index + 5], "stloc")
        if (
            source is not None
            and instructions[index + 1].opcode == "ldlen"
            and instructions[index + 2].opcode == "conv.i4"
            and _constant(instructions[index + 3]) == 4
            and instructions[index + 4].opcode == opcode
            and result is not None
        ):
            found.append((source, result))
    return found


def _has_index_condition(
    instructions: Sequence[Instruction], index_local: int, limit_local: int
) -> bool:
    return any(
        _local(instructions[index], "ldloc") == index_local
        and _local(instructions[index + 1], "ldloc") == limit_local
        and instructions[index + 2].opcode in {"blt", "blt.s"}
        for index in range(len(instructions) - 2)
    )


def _verify_partial_word_profile(
    instructions: Sequence[Instruction], byte_tokens: frozenset[int]
) -> None:
    remainders = _find_length_operation(instructions, "rem")
    quotients = _find_length_operation(instructions, "div")
    pairs = [
        (source, remainder, quotient)
        for source, remainder in remainders
        for q_source, quotient in quotients
        if source == q_source and remainder != quotient
    ]
    if len(pairs) != 1:
        raise RecoveryError("partial_word_length_profile_ambiguous")
    source, remainder, _ = pairs[0]
    outputs: list[int] = []
    for index in range(len(instructions) - 4):
        output = _local(instructions[index + 4], "stloc")
        if (
            _local(instructions[index], "ldloc") == source
            and instructions[index + 1].opcode == "ldlen"
            and instructions[index + 2].opcode == "conv.i4"
            and _is_byte_newarr(instructions[index + 3], byte_tokens)
            and output is not None
        ):
            outputs.append(output)
    if len(outputs) != 1:
        raise RecoveryError("partial_word_output_allocation_ambiguous")
    output = outputs[0]
    readers: list[tuple[int, int, int]] = []
    for index in range(len(instructions) - 11):
        accumulator = _local(instructions[index], "ldloc")
        partial_index = _local(instructions[index + 6], "ldloc")
        if (
            accumulator is not None
            and _local(instructions[index + 1], "ldloc") == source
            and _local(instructions[index + 2], "ldloc") == source
            and instructions[index + 3].opcode == "ldlen"
            and instructions[index + 4].opcode == "conv.i4"
            and _constant(instructions[index + 5]) == 1
            and partial_index is not None
            and instructions[index + 7].opcode == "add"
            and instructions[index + 8].opcode == "sub"
            and instructions[index + 9].opcode == "ldelem.u1"
            and instructions[index + 10].opcode == "or"
            and _local(instructions[index + 11], "stloc") == accumulator
        ):
            readers.append((accumulator, partial_index, instructions[index].offset))
    if len(readers) != 1:
        raise RecoveryError("partial_word_reader_ambiguous")
    accumulator, read_index, read_offset = readers[0]
    if (
        not _matches_local_constant_store(instructions, accumulator, 0)
        or not _matches_local_constant_store(instructions, read_index, 0)
        or not _matches_increment(instructions, read_index)
        or not _has_index_condition(instructions, read_index, remainder)
        or not any(
            _local(instructions[index], "ldloc") == accumulator
            and _constant(instructions[index + 1]) == 8
            and instructions[index + 2].opcode == "shl"
            and _local(instructions[index + 3], "stloc") == accumulator
            for index in range(len(instructions) - 3)
        )
        or not any(
            _local(instructions[index], "ldloc") == read_index
            and _constant(instructions[index + 1]) == 0
            and instructions[index + 2].opcode in {"ble", "ble.s"}
            and _branch_target(instructions[index + 2]) == read_offset
            for index in range(len(instructions) - 2)
        )
    ):
        raise RecoveryError("partial_word_reader_flow_mismatch")
    writers: list[tuple[int, int, int, int]] = []
    for index in range(len(instructions) - 12):
        write_index = _local(instructions[index + 2], "ldloc")
        mask_local = _local(instructions[index + 5], "ldloc")
        shift_local = _local(instructions[index + 7], "ldloc")
        if (
            _local(instructions[index], "ldloc") == output
            and _local(instructions[index + 1], "ldloc") is not None
            and write_index is not None
            and instructions[index + 3].opcode == "add"
            and _local(instructions[index + 4], "ldloc") is not None
            and mask_local is not None
            and instructions[index + 6].opcode == "and"
            and shift_local is not None
            and _constant(instructions[index + 8]) == 31
            and instructions[index + 9].opcode == "and"
            and instructions[index + 10].opcode == "shr.un"
            and instructions[index + 11].opcode == "conv.u1"
            and instructions[index + 12].opcode == "stelem.i1"
        ):
            writers.append(
                (write_index, mask_local, shift_local, instructions[index].offset)
            )
    if len(writers) != 1:
        raise RecoveryError("partial_word_writer_ambiguous")
    write_index, mask_local, shift_local, write_offset = writers[0]
    if (
        not _matches_local_constant_store(instructions, write_index, 0)
        or not _matches_local_constant_store(instructions, mask_local, 255)
        or not _matches_local_constant_store(instructions, shift_local, 0)
        or not _matches_increment(instructions, write_index)
        or not _matches_increment(instructions, shift_local, 8)
        or not _has_index_condition(instructions, write_index, remainder)
        or not any(
            _local(instructions[index], "ldloc") == write_index
            and _constant(instructions[index + 1]) == 0
            and instructions[index + 2].opcode in {"ble", "ble.s"}
            and _branch_target(instructions[index + 2]) == write_offset
            for index in range(len(instructions) - 2)
        )
    ):
        raise RecoveryError("partial_word_writer_flow_mismatch")


def _extract_recipe(
    data: bytes,
    pe: Any,
    method: _DecodedMethod,
    byte_tokens: frozenset[int],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> ResolverRecipe:
    instructions = method.instructions
    if not _has_deflate_constructor(pe, instructions):
        raise RecoveryError("deflatestream_constructor_missing")
    (
        switch_index,
        targets,
        _,
        dispatch_offsets,
        extra_targets,
    ) = _dispatcher_profile(instructions)
    helpers = _helper_constants(
        data,
        pe,
        instructions,
        dispatch_offsets,
        deadline=deadline,
        clock=clock,
    )
    key_states = []
    for index in range(2, len(instructions)):
        allocation = _array_allocation(instructions, index, byte_tokens)
        if allocation is None or allocation[1] != 32:
            continue
        matches = [
            state
            for state, target in enumerate(targets)
            if target == instructions[index - 2].offset
        ]
        if len(matches) == 1:
            key_states.extend(matches)
    if len(key_states) != 1:
        raise RecoveryError("key_allocation_state_ambiguous")
    try:
        trace = trace_flattened_switch(
            instructions,
            dispatcher_offset=instructions[switch_index].offset,
            initial_state=key_states[0],
            helper_constants=helpers,
            extra_state_targets=extra_targets,
            dispatch_offsets=dispatch_offsets,
            max_states=MAX_TRACE_STATES,
            stop_on_other_conditionals=True,
        )
    except StaticRecoveryError as exc:
        raise RecoveryError("constant_array_trace_failed") from exc
    arrays, prefix_block = _recover_arrays(trace, frozenset(helpers), byte_tokens)
    key_local, key_alias, key, key_stores = arrays[32]
    mask_local, mask_alias, mask, mask_stores = arrays[16]
    _verify_mask_loop(
        instructions,
        trace,
        prefix_block,
        key_alias=key_alias,
        mask_alias=mask_alias,
        dispatcher_offset=instructions[switch_index].offset,
        dispatcher_targets=targets,
        dispatch_offsets=dispatch_offsets,
        helper_constants=helpers,
        extra_targets=extra_targets,
    )
    seed, addend, core_start, core_end = _canonical_transform_core(instructions)
    _verify_partial_word_profile(instructions, byte_tokens)
    _check_time(deadline, clock)
    return ResolverRecipe(
        method_token=method.token,
        switch_targets=len(targets),
        traced_states=len(trace.blocks),
        helper_tokens=tuple(sorted(helpers)),
        key=key,
        key_local=key_local,
        key_alias=key_alias,
        key_store_count=key_stores,
        mask=mask,
        mask_local=mask_local,
        mask_alias=mask_alias,
        mask_store_count=mask_stores,
        seed=seed,
        addend=addend,
        transform_core_offset=core_start,
        transform_core_end_offset=core_end,
        partial_word_profile=True,
    )


def _resource_blobs(pe: Any) -> list[tuple[str, bytes]]:
    resources = list(getattr(getattr(pe, "net", None), "resources", ()) or ())
    if len(resources) > MAX_RESOURCE_COUNT:
        raise RecoveryError("resource_count_limit")
    result: list[tuple[str, bytes]] = []
    total = 0
    for item in resources:
        blob = getattr(item, "data", None)
        if not isinstance(blob, bytes):
            continue
        if not 0 < len(blob) <= MAX_RESOURCE_BYTES:
            raise RecoveryError("resource_byte_limit")
        total += len(blob)
        if total > MAX_TOTAL_RESOURCE_BYTES:
            raise RecoveryError("total_resource_byte_limit")
        name = str(getattr(item, "name", "unnamed.resource"))
        if not name or len(name) > 512 or any(ord(char) < 32 for char in name):
            raise RecoveryError("resource_name_invalid")
        result.append((name, blob))
    return result


def _decrypt_words(
    data: bytes,
    recipe: ResolverRecipe,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> bytes:
    if not data or len(data) > MAX_RESOURCE_BYTES:
        raise RecoveryError("resource_byte_limit")
    effective = bytearray(recipe.key)
    if len(effective) != 32 or len(recipe.mask) != 16:
        raise RecoveryError("key_or_mask_length_mismatch")
    for index, value in enumerate(recipe.mask):
        effective[index] ^= value
    key_words = struct.unpack("<8I", effective)
    output = bytearray(len(data))
    accumulator = 0
    for word_index, offset in enumerate(range(0, len(data), 4)):
        if word_index % WORD_TIME_CHECK_INTERVAL == 0:
            _check_time(deadline, clock)
        accumulator = (accumulator + key_words[word_index % 8]) & _U32_MASK
        accumulator = _eaz_next_accumulator(
            accumulator,
            seed=recipe.seed,
            addend=recipe.addend,
        )
        chunk = data[offset : offset + 4]
        encrypted = int.from_bytes(chunk, "little")
        clear = (encrypted ^ accumulator).to_bytes(4, "little")
        output[offset : offset + len(chunk)] = clear[: len(chunk)]
    _check_time(deadline, clock)
    return bytes(output)


def _inflate_raw_deflate(
    data: bytes,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> bytes:
    if not data or len(data) > MAX_RESOURCE_BYTES:
        raise RecoveryError("deflate_input_limit")
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    output = bytearray()
    cursor = 0
    try:
        while cursor < len(data):
            _check_time(deadline, clock)
            chunk = data[cursor : cursor + DEFLATE_CHUNK_BYTES]
            cursor += len(chunk)
            remaining = MAX_OUTPUT_BYTES - len(output)
            if remaining <= 0:
                raise RecoveryError("deflate_output_limit")
            piece = decoder.decompress(chunk, remaining + 1)
            output.extend(piece)
            if len(output) > MAX_OUTPUT_BYTES or decoder.unconsumed_tail:
                raise RecoveryError("deflate_output_limit")
        remaining = MAX_OUTPUT_BYTES - len(output)
        output.extend(decoder.flush(remaining + 1))
    except zlib.error as exc:
        raise RecoveryError("raw_deflate_invalid") from exc
    _check_time(deadline, clock)
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or not output:
        raise RecoveryError("raw_deflate_eof_or_trailing_data")
    if len(output) > MAX_OUTPUT_BYTES:
        raise RecoveryError("deflate_output_limit")
    ratio = len(output) / len(data)
    if ratio > MAX_DEFLATE_RATIO:
        raise RecoveryError("deflate_ratio_limit")
    return bytes(output)


def _is_exact_managed_pe(data: bytes) -> bool:
    if not has_clr_metadata(data):
        return False
    extent = inspect_structural_pe_extent(data, max_extent=MAX_OUTPUT_BYTES)
    return extent.extent == len(data)


def recover_model(
    recipe: ResolverRecipe,
    resources: Iterable[tuple[str, bytes]],
    *,
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_ELAPSED_SECONDS,
    validator: Callable[[bytes], bool] = _is_exact_managed_pe,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """検証済みrecipeとresource群を変換し、単一出力だけを採用する。"""

    if (
        isinstance(max_elapsed_seconds, bool)
        or not isinstance(max_elapsed_seconds, (int, float))
        or not 0 < max_elapsed_seconds <= MAX_ELAPSED_SECONDS
    ):
        raise RecoveryError("elapsed_limit_invalid")
    start = clock()
    deadline = start + float(max_elapsed_seconds)
    candidates: list[tuple[str, bytes, bytes]] = []
    attempts = 0
    rejected = 0
    total = 0
    for index, item in enumerate(resources):
        _check_time(deadline, clock)
        if index >= MAX_RESOURCE_COUNT:
            raise RecoveryError("resource_count_limit")
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], bytes)
        ):
            raise RecoveryError("resource_model_invalid")
        name, encrypted = item
        if not encrypted or len(encrypted) > MAX_RESOURCE_BYTES:
            raise RecoveryError("resource_byte_limit")
        total += len(encrypted)
        if total > MAX_TOTAL_RESOURCE_BYTES:
            raise RecoveryError("total_resource_byte_limit")
        attempts += 1
        try:
            transformed = _decrypt_words(
                encrypted, recipe, deadline=deadline, clock=clock
            )
            output = _inflate_raw_deflate(transformed, deadline=deadline, clock=clock)
        except RecoveryError:
            rejected += 1
            continue
        valid_output = validator(output)
        _check_time(deadline, clock)
        if not valid_output:
            rejected += 1
            continue
        if candidates:
            # 2件目が成立した時点で一意性は回復しない。以降の最大64 MiB出力を
            # 保持・検証せず、曖昧さをfail-closedで確定する。
            return {
                "status": "rejected",
                "reason": "decoded_candidate_ambiguous",
                "resource_attempts": attempts,
                "resource_rejections": rejected,
                "decoded_candidates": 2,
                "family_attribution_allowed": False,
                "terminal_config_markers_confirmed": False,
            }, []
        candidates.append((name, encrypted, output))
    _check_time(deadline, clock)
    elapsed = clock() - start
    if len(candidates) != 1:
        return {
            "status": "rejected",
            "reason": (
                "decoded_candidate_missing"
                if not candidates
                else "decoded_candidate_ambiguous"
            ),
            "resource_attempts": attempts,
            "resource_rejections": rejected,
            "decoded_candidates": len(candidates),
            "family_attribution_allowed": False,
            "terminal_config_markers_confirmed": False,
        }, []
    name, encrypted, output = candidates[0]
    report = {
        "status": "recovered_managed_resource",
        "method_token": f"0x{recipe.method_token:08x}",
        "recipe": "eaz_keyed_u32_partial_raw_deflate_v1",
        "resource": {
            "name": name,
            "size": len(encrypted),
            "sha256": hashlib.sha256(encrypted).hexdigest(),
            "partial_word_bytes": len(encrypted) % 4,
        },
        "static_evidence": {
            "switch_targets": recipe.switch_targets,
            "traced_states": recipe.traced_states,
            "constant_helpers": [f"0x{token:08x}" for token in recipe.helper_tokens],
            "key_length": len(recipe.key),
            "key_sha256": hashlib.sha256(recipe.key).hexdigest(),
            "key_constant_stores": recipe.key_store_count,
            "mask_length": len(recipe.mask),
            "mask_sha256": hashlib.sha256(recipe.mask).hexdigest(),
            "mask_constant_stores": recipe.mask_store_count,
            "seed": recipe.seed,
            "addend": recipe.addend,
            "transform_core_canonical_sha256": (TRANSFORM_CORE_CANONICAL_SHA256),
            "transform_core_offsets": [
                recipe.transform_core_offset,
                recipe.transform_core_end_offset,
            ],
            "partial_word_profile_verified": recipe.partial_word_profile,
            "compression": "raw_deflate",
        },
        "output": {
            "size": len(output),
            "sha256": hashlib.sha256(output).hexdigest(),
            "format": "managed_pe",
            "compression_ratio": round(len(output) / len(encrypted), 6),
        },
        "resource_attempts": attempts,
        "resource_rejections": rejected,
        "elapsed_seconds": round(max(0.0, elapsed), 6),
        "limits": {
            "input_bytes": MAX_INPUT_BYTES,
            "metadata_rows": MAX_METADATA_ROWS,
            "method_rows": MAX_METHOD_ROWS,
            "method_bytes_each": MAX_METHOD_BYTES,
            "method_extra_section_bytes_each": MAX_METHOD_EXTRA_SECTION_BYTES,
            "method_extra_sections_each": MAX_METHOD_EXTRA_SECTIONS,
            "method_instructions_each": MAX_METHOD_INSTRUCTIONS,
            "method_bytes_total": MAX_TOTAL_METHOD_BYTES,
            "method_instructions_total": MAX_TOTAL_METHOD_INSTRUCTIONS,
            "resource_count": MAX_RESOURCE_COUNT,
            "resource_bytes_each": MAX_RESOURCE_BYTES,
            "resource_bytes_total": MAX_TOTAL_RESOURCE_BYTES,
            "output_bytes": MAX_OUTPUT_BYTES,
            "deflate_ratio": MAX_DEFLATE_RATIO,
            "elapsed_seconds": float(max_elapsed_seconds),
        },
        "sample_execution": False,
        "clr_load": False,
        "instruction_emulation": False,
        "external_communication": False,
        "family_attribution_allowed": False,
        "terminal_config_markers_confirmed": False,
    }
    return report, [("managed-eaz-resource-pe", output)]


def recover_managed_eaz_resource(
    data: bytes,
    *,
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_ELAPSED_SECONDS,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """managed PEから単一のEaz protected resourceを静的復元する。"""

    if not isinstance(data, bytes):
        return {"status": "rejected", "reason": "input_not_bytes"}, []
    if not data or len(data) > MAX_INPUT_BYTES:
        return {"status": "rejected", "reason": "input_byte_limit"}, []
    if (
        isinstance(max_elapsed_seconds, bool)
        or not isinstance(max_elapsed_seconds, (int, float))
        or not 0 < max_elapsed_seconds <= MAX_ELAPSED_SECONDS
    ):
        return {"status": "rejected", "reason": "elapsed_limit_invalid"}, []
    start = clock()
    deadline = start + float(max_elapsed_seconds)
    try:
        _check_time(deadline, clock)
        is_managed = has_clr_metadata(data)
        _check_time(deadline, clock)
        if not is_managed:
            return {"status": "not_applicable", "reason": "not_managed_pe"}, []
        with _contained_parser_diagnostics():
            pe = dnfile.dnPE(data=data, clr_lazy_load=False)
        _check_time(deadline, clock)
        if getattr(pe, "net", None) is None:
            raise RecoveryError("clr_metadata_missing")
        metadata_rows = _metadata_row_count(pe)
        byte_tokens = _system_byte_tokens(pe)
        candidates, scan = _scan_resolver_candidates(
            data,
            pe,
            byte_tokens,
            deadline=deadline,
            clock=clock,
        )
        if not candidates:
            return {
                "status": "not_applicable",
                "reason": "resolver_recipe_not_found",
                "method_scan": scan,
            }, []
        if len(candidates) != 1:
            raise RecoveryError("resolver_candidate_ambiguous")
        recipe = _extract_recipe(
            data,
            pe,
            candidates[0],
            byte_tokens,
            deadline=deadline,
            clock=clock,
        )
        resources = _resource_blobs(pe)
        remaining = deadline - clock()
        if remaining <= 0:
            raise RecoveryError("elapsed_time_limit")
        report, artifacts = recover_model(
            recipe,
            resources,
            clock=clock,
            max_elapsed_seconds=min(float(max_elapsed_seconds), remaining),
        )
        report["input"] = {
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        report["metadata_rows"] = metadata_rows
        report["method_scan"] = scan
        report["elapsed_seconds_total"] = round(max(0.0, clock() - start), 6)
        return report, artifacts
    except RecoveryError as exc:
        return {
            "status": "rejected",
            "reason": str(exc),
            "input": {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            "family_attribution_allowed": False,
            "terminal_config_markers_confirmed": False,
        }, []
    except Exception as exc:  # noqa: BLE001 - untrusted parserをfail-closedで隔離する
        return {
            "status": "rejected",
            "reason": "static_analysis_failed",
            "error_type": type(exc).__name__,
            "input": {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            "family_attribution_allowed": False,
            "terminal_config_markers_confirmed": False,
        }, []


def _read_bounded(path: Path) -> bytes:
    before = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or getattr(before, "st_file_attributes", 0) & 0x400
    ):
        raise RecoveryError("input_not_regular_file")
    if not 0 < before.st_size <= MAX_INPUT_BYTES:
        raise RecoveryError("input_byte_limit")

    def identity(information: os.stat_result) -> tuple[int, ...]:
        return (
            information.st_dev,
            information.st_ino,
            information.st_size,
            information.st_mtime_ns,
            information.st_nlink,
        )

    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if identity(before) != identity(opened):
            raise RecoveryError("input_changed_while_opening")
        data = stream.read(MAX_INPUT_BYTES + 1)
        after_handle = os.fstat(stream.fileno())
    after_path = path.lstat()
    if (
        len(data) != before.st_size
        or identity(before) != identity(after_handle)
        or identity(before) != identity(after_path)
        or stat.S_ISLNK(after_path.st_mode)
        or getattr(after_path, "st_file_attributes", 0) & 0x400
    ):
        raise RecoveryError("input_changed_while_reading")
    return data


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="managed Eaz resourceを実行せず静的復元する"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help="単一復元PEの保存先（既存fileは上書きしない）",
    )
    args = parser.parse_args(argv)
    try:
        data = _read_bounded(args.input)
        report, artifacts = recover_managed_eaz_resource(data)
        if artifacts and args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            created = False
            try:
                with args.output.open("xb") as stream:
                    created = True
                    stream.write(artifacts[0][1])
            except FileExistsError:
                raise RecoveryError("output_exists")
            except OSError:
                if created:
                    try:
                        args.output.unlink(missing_ok=True)
                    except OSError:
                        pass
                raise
            report["output_path"] = str(args.output.resolve())
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if report.get("status") == "recovered_managed_resource" else 1
    except (OSError, RecoveryError) as exc:
        print(
            json.dumps(
                {"status": "rejected", "reason": type(exc).__name__},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
