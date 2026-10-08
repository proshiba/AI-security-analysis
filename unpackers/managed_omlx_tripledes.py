#!/usr/bin/env python3
"""OMLX仮想化string tableからTripleDES/GZip終端PEを静的復元する。

検体、CLR、CIL、復元後PEは実行しない。対応するのは、静的に
証明したOMLX opcode profileの定数データフロー、Eaz keyed-word
transform、単一のResourceSet ByteArray、TripleDES-CBC/PKCS7、長さ付き
GZipの組合せに限る。不明なopcode、複数候補、不完全なresource境界は
fail-closedで拒否する。このrecipeだけでmalware familyは確定しない。
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import dnfile
from malware.purehvnc.managed_resource_recovery import (
    OmlxInstruction,
    OmlxMethod,
    StaticRecoveryError,
    decode_length_prefixed_utf16le,
    decrypt_keyed_eaz_resource,
    decrypt_tripledes_cbc_pkcs7_base64,
    inflate_length_prefixed_gzip,
    parse_omlx_header,
    parse_omlx_method,
    recover_omlx_int32_static_initializer,
)

from extractors.managed_pe import has_clr_metadata
from unpackers.bounded_pe_scan import inspect_structural_pe_extent
from unpackers.managed_eaz_resource import (
    RecoveryError,
    _canonical_transform_core,
    _constant,
    _contained_parser_diagnostics,
    _decode_method,
    _is_byte_newarr,
    _local,
    _metadata_row_count,
    _resource_blobs,
    _system_byte_tokens,
    _verify_partial_word_profile,
    recover_managed_eaz_resource,
)
from unpackers.managed_omlx_semantics import (
    OmlxDispatcherFingerprint,
    OmlxSemanticError,
    extract_omlx_handler_shapes,
    infer_method0_opcode_candidates,
)
from unpackers.managed_tripledes_gzip import _framework_references

MAX_INPUT_BYTES = 32 << 20
MAX_OUTPUT_BYTES = 64 << 20
MAX_RESOURCE_COUNT = 64
MAX_RESOURCE_BYTES = 32 << 20
MAX_RESOURCE_ENTRY_COUNT = 4_096
MAX_TOTAL_RESOURCE_ENTRY_BYTES = 64 << 20
MAX_OMLX_STEPS = 20_000
MAX_STACK_DEPTH = 1_024
MAX_ARRAY_BYTES = 4_096
MAX_STRING_COUNT = 4_096
MAX_TERMINAL_BINDING_CANDIDATES = 256
MAX_TERMINAL_VALIDATION_CANDIDATES = 256
MAX_TERMINAL_CIPHERTEXT_WORK_BYTES = 256 << 20
MAX_TERMINAL_INFLATED_WORK_BYTES = 256 << 20
MAX_TABLE_TRANSFORM_WORK_BYTES = 256 << 20
MAX_DYNAMIC_OPCODE_CANDIDATES = 64
MAX_ELAPSED_SECONDS = 20.0
_U32_MASK = 0xFFFFFFFF
_ARGUMENT_RE = re.compile(r"argument\(0x([0-9a-fA-F]{1,8})\)")

# 176-way dispatcherのhandler CILとEaz proxy解決後の実装を独立照合した
# profile。IDだけで受理せず、operand kind、制御フロー、resource binding、
# direct transform、復号後構造をすべて下流で再検証する。
_INITIALIZER_SEMANTICS_V1: Mapping[int, str] = {
    150: "newobj",
    107: "stsfld",
    63: "ldsfld",
    173: "ldc.i4",
    167: "add",
    120: "sub",
    43: "xor",
    111: "shl",
    95: "shr",
    67: "neg",
    98: "not",
    28: "stfld",
    110: "ret",
}

_INITIALIZER_SEMANTICS_COMMON_V2: Mapping[int, str] = {
    154: "newobj",
    2: "stsfld",
    135: "ldsfld",
    21: "ldc.i4",
    52: "add",
    56: "sub",
    32: "xor",
    1: "shl",
    157: "shr",
    83: "neg",
    36: "not",
    41: "stfld",
    118: "ret",
}

_METHOD_OPCODE_V1 = {
    value: value
    for value in (
        1,
        7,
        15,
        29,
        31,
        37,
        38,
        41,
        43,
        46,
        57,
        63,
        66,
        74,
        89,
        96,
        105,
        107,
        110,
        120,
        123,
        128,
        134,
        138,
        148,
        150,
        156,
        167,
        173,
    )
}

# 共通19件buildのvirtual opcodeを上のcanonical IDへ写す。各対応は
# 176-way dispatcher handlerとEaz proxy解決後のoverride CILで照合済み。
_METHOD_OPCODE_COMMON_V2 = {
    21: 173,  # ldc.i4
    149: 7,  # ldloc
    46: 89,  # br
    35: 138,  # stelem.i1
    102: 134,  # call
    22: 96,  # pop
    49: 148,  # stloc
    52: 167,  # add
    56: 120,  # sub
    147: 57,  # brtrue
    62: 31,  # brfalse
    8: 46,  # ldelem.u1
    13: 74,  # dup
    154: 150,  # newobj
    135: 63,  # ldsfld
    2: 107,  # stsfld
    108: 29,  # newarr byte
    92: 41,  # switch
    118: 110,  # ret
    38: 156,  # ldarg
    33: 15,  # beq
    32: 43,  # xor
    67: 66,  # bne.un
    167: 38,  # blt
    113: 105,  # ldlen
    134: 128,  # profile上のidentity conversion
    124: 37,  # conv.u1
    76: 1,  # ldnull
    171: 123,  # conv.i8（この有界dataflowではidentity）
}

_SELECTOR_PROFILE_V1 = (
    (0x04000143, 1_237_853_766, 1_980_934_115),
    (0x0400014B, -218_556_385, -1_603_090_838),
    (0x0400014E, -2_111_836_516, -341_881_206),
)


class OmlxTripledesError(ValueError):
    """受理済み静的profileから外れた入力を表すfail-closed error。"""


class _OmlxHardLimitError(OmlxTripledesError):
    """候補探索で握りつぶしてはならないdeadline／work上限。"""


@dataclass
class _TerminalWorkBudget:
    """固定・dynamic経路で共有する終端検証の累積work budget。"""

    max_candidate_count: int = MAX_TERMINAL_VALIDATION_CANDIDATES
    max_ciphertext_work_bytes: int = MAX_TERMINAL_CIPHERTEXT_WORK_BYTES
    max_inflated_work_bytes: int = MAX_TERMINAL_INFLATED_WORK_BYTES
    max_table_transform_work_bytes: int = MAX_TABLE_TRANSFORM_WORK_BYTES
    candidate_count: int = 0
    ciphertext_work_bytes: int = 0
    inflated_work_bytes: int = 0
    table_transform_work_bytes: int = 0

    @property
    def remaining_inflated_work_bytes(self) -> int:
        return self.max_inflated_work_bytes - self.inflated_work_bytes

    def charge_candidate(self, ciphertext_bytes: int) -> None:
        if self.candidate_count >= self.max_candidate_count:
            raise _OmlxHardLimitError("terminal_validation_candidate_limit")
        if (
            ciphertext_bytes
            > self.max_ciphertext_work_bytes - self.ciphertext_work_bytes
        ):
            raise _OmlxHardLimitError("terminal_ciphertext_work_limit")
        self.candidate_count += 1
        self.ciphertext_work_bytes += ciphertext_bytes

    def charge_inflated_work(self, inflated_bytes: int) -> None:
        if inflated_bytes > self.remaining_inflated_work_bytes:
            raise _OmlxHardLimitError("terminal_inflated_work_limit")
        self.inflated_work_bytes += inflated_bytes

    def charge_table_transform(self, transformed_bytes: int) -> None:
        if (
            transformed_bytes
            > self.max_table_transform_work_bytes - self.table_transform_work_bytes
        ):
            raise _OmlxHardLimitError("table_transform_work_limit")
        self.table_transform_work_bytes += transformed_bytes


@dataclass(frozen=True)
class _TransformRecipe:
    token: int
    seed: int
    addend: int
    core_offsets: tuple[int, int]


@dataclass(frozen=True)
class _TableRecovery:
    clear: bytes
    key: bytes
    mask: bytes
    transform: _TransformRecipe
    steps: int


@dataclass(frozen=True)
class _TerminalBinding:
    """string tableとchild resourceを終端PEまで結ぶ一意な静的候補。"""

    key_offset: int
    iv_offset: int
    resource_name_offset: int
    key_base64: str
    iv_base64: str
    resource_name: str
    ciphertext: bytes
    payload: bytes


@dataclass(frozen=True)
class _OmlxProfile:
    """同じsemanticを別のvirtual opcodeへ割り当てるbuild profile。"""

    profile_id: str
    recipe: str
    initializer_semantics: Mapping[int, str]
    method_opcode_map: Mapping[int, int]


@dataclass(frozen=True)
class _DynamicOmlxCandidate:
    """dispatcher形状から有界推定したOMLX候補集合。"""

    resource_name: str
    resource_blob: bytes
    raw_method0: OmlxMethod
    method1_token: int
    dispatcher: OmlxDispatcherFingerprint
    opcode_maps: tuple[Mapping[int, int], ...]


@dataclass(frozen=True)
class _RecoveredDynamicOutput:
    """1つ以上のopcode候補が同一に復元した終端出力。"""

    method0: OmlxMethod
    table_recovery: _TableRecovery
    table: tuple[tuple[int, str], ...]
    terminal_binding: _TerminalBinding
    candidate_count: int
    viable_candidate_count: int
    viable_mapping_mode_candidate_count: int
    key_mask_modes: tuple[str, ...]


_PROFILES = (
    _OmlxProfile(
        profile_id="omlx_dispatch_v1",
        recipe="omlx_eaz_table_resource_tripledes_gzip_v1",
        initializer_semantics=_INITIALIZER_SEMANTICS_V1,
        method_opcode_map=_METHOD_OPCODE_V1,
    ),
    _OmlxProfile(
        profile_id="omlx_dispatch_common_v2",
        recipe="omlx_eaz_table_resource_tripledes_gzip_v2",
        initializer_semantics=_INITIALIZER_SEMANTICS_COMMON_V2,
        method_opcode_map=_METHOD_OPCODE_COMMON_V2,
    ),
)


def _i32(value: int) -> int:
    value &= _U32_MASK
    return value - (1 << 32) if value & (1 << 31) else value


def _check_time(deadline: float, clock: Callable[[], float]) -> None:
    if clock() > deadline:
        raise _OmlxHardLimitError("elapsed_time_limit")


def _raise_if_elapsed_time_limit(exc: BaseException) -> None:
    """下位decoderのdeadline超過を候補不一致として握りつぶさない。"""

    if str(exc) == "elapsed_time_limit":
        raise _OmlxHardLimitError("elapsed_time_limit") from exc


def _arg_index(opcode: str, operand: Any) -> int | None:
    if opcode.startswith("ldarg.") and opcode[-1:].isdigit():
        return int(opcode[-1])
    if opcode not in {"ldarg", "ldarg.s", "ldarga", "ldarga.s"}:
        return None
    if isinstance(operand, int) and not isinstance(operand, bool):
        return operand
    if isinstance(operand, str) and (match := _ARGUMENT_RE.fullmatch(operand)):
        return int(match.group(1), 16)
    return None


def _verified_transform_recipes(
    data: bytes,
    pe: Any,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> dict[int, _TransformRecipe]:
    rows = list(getattr(getattr(pe.net.mdtables, "MethodDef", None), "rows", ()) or ())
    byte_tokens = _system_byte_tokens(pe)
    result: dict[int, _TransformRecipe] = {}
    for rid, row in enumerate(rows, 1):
        _check_time(deadline, clock)
        token = 0x06000000 | rid
        try:
            method = _decode_method(
                data,
                pe,
                row,
                token,
                deadline=deadline,
                clock=clock,
            )
            seed, addend, start, end = _canonical_transform_core(method.instructions)
            try:
                _verify_partial_word_profile(method.instructions, byte_tokens)
            except RecoveryError as exc:
                _raise_if_elapsed_time_limit(exc)
                _verify_no_mask_partial_word_profile(
                    method.instructions,
                    byte_tokens,
                )
        except RecoveryError as exc:
            _raise_if_elapsed_time_limit(exc)
            continue
        arguments = [
            index
            for item in method.instructions
            if (index := _arg_index(item.opcode, item.operand)) is not None
        ]
        if 1 not in arguments or 3 not in arguments or 2 in arguments:
            continue
        result[token] = _TransformRecipe(token, seed, addend, (start, end))
    _check_time(deadline, clock)
    if not result:
        raise OmlxTripledesError("no_mask_transform_recipe_missing")
    return result


def _verify_no_mask_partial_word_profile(
    instructions: Sequence[Any],
    byte_tokens: frozenset[int],
) -> None:
    """arg3 resourceをpartial wordで読み書きする別buildを検証する。"""

    if len(instructions) < 200 or instructions[-1].opcode != "ret":
        raise RecoveryError("no_mask_partial_word_method_shape_mismatch")
    prefixes = []
    for index in range(len(instructions) - 5):
        argument = _arg_index(instructions[index].opcode, instructions[index].operand)
        stored = _local(instructions[index + 5], "stloc")
        if (
            argument in {1, 3}
            and instructions[index + 1].opcode == "ldlen"
            and instructions[index + 2].opcode == "conv.i4"
            and _constant(instructions[index + 3]) == 4
            and instructions[index + 4].opcode in {"rem", "div"}
            and stored is not None
        ):
            prefixes.append((argument, instructions[index + 4].opcode, stored))
    if (
        sum(1 for argument, opcode, _ in prefixes if argument == 3 and opcode == "rem")
        != 1
        or sum(
            1 for argument, opcode, _ in prefixes if argument == 3 and opcode == "div"
        )
        != 1
        or sum(
            1 for argument, opcode, _ in prefixes if argument == 1 and opcode == "div"
        )
        != 1
    ):
        raise RecoveryError("no_mask_partial_word_length_profile_mismatch")
    allocations = [
        index
        for index in range(len(instructions) - 3)
        if _arg_index(instructions[index].opcode, instructions[index].operand) == 3
        and instructions[index + 1].opcode == "ldlen"
        and instructions[index + 2].opcode == "conv.i4"
        and _is_byte_newarr(instructions[index + 3], byte_tokens)
    ]
    if len(allocations) != 1:
        raise RecoveryError("no_mask_partial_word_output_allocation_mismatch")
    if sum(item.opcode == "ldelem.u1" for item in instructions) < 8:
        raise RecoveryError("no_mask_partial_word_reader_missing")
    if sum(item.opcode == "stelem.i1" for item in instructions) < 4:
        raise RecoveryError("no_mask_partial_word_writer_missing")
    if sum(item.opcode == "stsfld" for item in instructions) != 1:
        raise RecoveryError("no_mask_partial_word_sink_mismatch")


def _canonicalize_omlx_method(
    method: OmlxMethod,
    opcode_map: Mapping[int, int],
) -> OmlxMethod:
    """証明済みprofileに含まれるopcodeだけをcanonical IDへ写す。"""

    instructions = []
    for item in method.instructions:
        canonical = opcode_map.get(item.opcode_id)
        if canonical is None:
            raise OmlxTripledesError(f"omlx_opcode_out_of_profile:{item.opcode_id}")
        instructions.append(
            OmlxInstruction(
                index=item.index,
                record_offset=item.record_offset,
                opcode_id=canonical,
                operand_kind=item.operand_kind,
                operand=item.operand,
            )
        )
    return OmlxMethod(
        method_index=method.method_index,
        metadata_token=method.metadata_token,
        type_count=method.type_count,
        exception_clause_count=method.exception_clause_count,
        type_descriptors=method.type_descriptors,
        instructions=tuple(instructions),
        exception_clauses=method.exception_clauses,
    )


def _find_omlx_candidate(
    resources: Sequence[tuple[str, bytes]],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[str, bytes, OmlxMethod, Any, _OmlxProfile]:
    candidates = []
    for name, blob in resources:
        _check_time(deadline, clock)
        try:
            header = parse_omlx_header(blob)
            if len(header.method_offsets) != 2 or len(header.opcode_map) < 16:
                continue
            raw_method0 = parse_omlx_method(blob, header, 0)
            method1 = parse_omlx_method(
                blob,
                header,
                1,
                allow_unsigned_int32_operands=True,
            )
        except StaticRecoveryError:
            continue
        _check_time(deadline, clock)
        for profile in _PROFILES:
            _check_time(deadline, clock)
            try:
                initializer = recover_omlx_int32_static_initializer(
                    method1,
                    opcode_semantics=profile.initializer_semantics,
                )
                method0 = _canonicalize_omlx_method(
                    raw_method0,
                    profile.method_opcode_map,
                )
            except (StaticRecoveryError, OmlxTripledesError):
                continue
            candidates.append((name, blob, method0, initializer, profile))
    _check_time(deadline, clock)
    if len(candidates) != 1:
        raise OmlxTripledesError(
            "omlx_candidate_missing" if not candidates else "omlx_candidate_ambiguous"
        )
    return candidates[0]


def _find_dynamic_omlx_candidate(
    data: bytes,
    pe: Any,
    resources: Sequence[tuple[str, bytes]],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> _DynamicOmlxCandidate:
    """19-buildで確認したOMLX構造からopcode候補を導く。

    raw opcode ID、sample hash、metadata tokenは固定しない。共通する
    header形状、methodのoperand形状、176-way dispatcher handlerのCIL形状
    だけを使い、未知の追加resourceや複数の一致候補は拒否する。
    """

    candidates: list[_DynamicOmlxCandidate] = []
    for name, blob in resources:
        _check_time(deadline, clock)
        try:
            header = parse_omlx_header(blob)
            if (
                header.feature_flag
                or len(header.opcode_map) != 58
                or header.strings
                or len(header.method_offsets) != 2
                or header.body_offset != 124
            ):
                continue
            raw_method0 = parse_omlx_method(blob, header, 0)
            method1 = parse_omlx_method(
                blob,
                header,
                1,
                allow_unsigned_int32_operands=True,
            )
            if len({item.opcode_id for item in method1.instructions}) != 13:
                continue
            raw_opcodes = {item.opcode_id for item in raw_method0.instructions}
            dispatcher = extract_omlx_handler_shapes(
                data,
                pe,
                raw_opcodes,
                deadline=deadline,
                clock=clock,
            )
            inferred = infer_method0_opcode_candidates(
                raw_method0,
                dispatcher.handler_map(),
                max_candidates=MAX_DYNAMIC_OPCODE_CANDIDATES,
            )
        except (StaticRecoveryError, OmlxSemanticError) as exc:
            _raise_if_elapsed_time_limit(exc)
            continue
        candidates.append(
            _DynamicOmlxCandidate(
                resource_name=name,
                resource_blob=blob,
                raw_method0=raw_method0,
                method1_token=method1.metadata_token,
                dispatcher=dispatcher,
                opcode_maps=inferred.mapping_dicts(),
            )
        )
    _check_time(deadline, clock)
    if len(candidates) != 1:
        raise OmlxTripledesError(
            "omlx_dynamic_candidate_missing"
            if not candidates
            else "omlx_dynamic_candidate_ambiguous"
        )
    return candidates[0]


def _find_bound_resource(
    data: bytes,
    pe: Any,
    method_token: int,
    resources: Mapping[str, bytes],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[str, bytes, int, dict[str, Any], Mapping[int, str]]:
    _check_time(deadline, clock)
    try:
        references, _parameter_counts, declaration_validation = _framework_references(
            pe,
            deadline,
            clock,
        )
    except ValueError as exc:
        _raise_if_elapsed_time_limit(exc)
        raise
    _check_time(deadline, clock)
    getter_tokens = {
        token
        for token, value in references.items()
        if value == "System.Reflection.Assembly::GetManifestResourceStream"
    }
    if not getter_tokens:
        raise OmlxTripledesError("manifest_resource_getter_declaration_missing")
    matches: list[tuple[str, bytes, int]] = []
    rows = list(getattr(getattr(pe.net.mdtables, "MethodDef", None), "rows", ()) or ())
    for rid, row in enumerate(rows, 1):
        _check_time(deadline, clock)
        try:
            method = _decode_method(
                data,
                pe,
                row,
                0x06000000 | rid,
                deadline=deadline,
                clock=clock,
            )
        except RecoveryError as exc:
            _raise_if_elapsed_time_limit(exc)
            continue
        instructions = method.instructions
        for index in range(4, len(instructions)):
            if index % 64 == 0:
                _check_time(deadline, clock)
            if not (
                instructions[index].opcode in {"call", "callvirt"}
                and instructions[index].operand == method_token
                and instructions[index - 1].opcode.startswith("ldarg")
                and instructions[index - 2].opcode in {"call", "callvirt"}
                and instructions[index - 2].operand in getter_tokens
                and instructions[index - 3].opcode == "ldstr"
                and isinstance(instructions[index - 3].operand, int)
            ):
                continue
            token = instructions[index - 3].operand
            try:
                item = pe.net.user_strings.get(token & 0x00FFFFFF)
                name = str(getattr(item, "value", item))
            except Exception as exc:
                raise OmlxTripledesError("resource_name_user_string_invalid") from exc
            if name in resources:
                matches.append((name, resources[name], method.token))
    _check_time(deadline, clock)
    unique = {
        (name, hashlib.sha256(blob).digest(), token): (name, blob, token)
        for name, blob, token in matches
    }
    if len(unique) != 1:
        raise OmlxTripledesError(
            "encrypted_resource_binding_missing"
            if not unique
            else "encrypted_resource_binding_ambiguous"
        )
    name, blob, caller = next(iter(unique.values()))
    return name, blob, caller, declaration_validation, references


def _required_int(instruction: OmlxInstruction) -> int:
    if isinstance(instruction.operand, bool) or not isinstance(
        instruction.operand, int
    ):
        raise OmlxTripledesError("omlx_integer_operand_required")
    return instruction.operand


def _recover_table(
    method: OmlxMethod,
    encrypted: bytes,
    transforms: Mapping[int, _TransformRecipe],
    *,
    entrypoint_token: int,
    deadline: float,
    clock: Callable[[], float],
    work_budget: _TerminalWorkBudget,
) -> _TableRecovery:
    _check_time(deadline, clock)
    stack: list[Any] = []
    locals_: dict[int, Any] = {}
    static_fields: dict[int, Any] = {}
    args: dict[int, Any] = {0: ("stream", encrypted), 1: 0}
    instructions = method.instructions
    ip = 0
    steps = 0
    recovered: _TableRecovery | None = None

    def pop() -> Any:
        if not stack:
            raise OmlxTripledesError("omlx_stack_underflow")
        return stack.pop()

    def push(value: Any) -> None:
        if len(stack) >= MAX_STACK_DEPTH:
            raise OmlxTripledesError("omlx_stack_depth_limit")
        stack.append(value)

    while 0 <= ip < len(instructions):
        _check_time(deadline, clock)
        steps += 1
        if steps > MAX_OMLX_STEPS:
            raise OmlxTripledesError("omlx_step_limit")
        item = instructions[ip]
        opcode = item.opcode_id
        operand = item.operand
        next_ip = ip + 1
        if opcode == 173:  # ldc.i4
            push(_required_int(item))
        elif opcode == 148:  # stloc
            locals_[_required_int(item)] = pop()
        elif opcode == 7:  # ldloc
            local = _required_int(item)
            if local not in locals_:
                raise OmlxTripledesError("omlx_uninitialized_local")
            push(locals_[local])
        elif opcode == 156:  # ldarg
            argument = _required_int(item)
            if argument not in args:
                raise OmlxTripledesError("omlx_argument_out_of_profile")
            push(args[argument])
        elif opcode == 63:  # ldsfld
            field = _required_int(item)
            push(static_fields.get(field, ("static-field", field)))
        elif opcode == 107:  # stsfld
            static_fields[_required_int(item)] = pop()
        elif opcode == 41:  # switch
            selector = pop()
            if not isinstance(selector, int) or not isinstance(operand, tuple):
                raise OmlxTripledesError("omlx_switch_value_invalid")
            if 0 <= selector < len(operand):
                next_ip = int(operand[selector])
        elif opcode == 89:  # br
            next_ip = _required_int(item)
        elif opcode in {15, 66, 38}:  # beq, bne.un, blt
            right, left = pop(), pop()
            if opcode == 15:
                condition = left == right
            elif opcode == 66:
                condition = left != right
            else:
                if not isinstance(left, int) or not isinstance(right, int):
                    raise OmlxTripledesError("omlx_blt_value_invalid")
                condition = _i32(left) < _i32(right)
            if condition:
                next_ip = _required_int(item)
        elif opcode in {31, 57}:  # brfalse, brtrue
            raw_condition = pop()
            if isinstance(raw_condition, tuple):
                raise OmlxTripledesError("omlx_symbolic_branch_condition")
            condition = bool(raw_condition)
            if (opcode == 31 and not condition) or (opcode == 57 and condition):
                next_ip = _required_int(item)
        elif opcode == 96:  # pop
            pop()
        elif opcode == 1:  # ldnull
            push(None)
        elif opcode in {167, 120, 43}:  # add, sub, xor
            right, left = pop(), pop()
            if not isinstance(left, int) or not isinstance(right, int):
                raise OmlxTripledesError("omlx_arithmetic_value_invalid")
            value = {167: left + right, 120: left - right, 43: left ^ right}[opcode]
            push(value & _U32_MASK)
        elif opcode == 74:  # dup
            if not stack:
                raise OmlxTripledesError("omlx_stack_underflow")
            push(stack[-1])
        elif opcode == 29:  # newarr byte
            length = pop()
            if not isinstance(length, int) or not 0 <= length <= MAX_ARRAY_BYTES:
                raise OmlxTripledesError("omlx_array_length_limit")
            push([0] * length)
        elif opcode == 46:  # ldelem.u1
            index, array = pop(), pop()
            if (
                not isinstance(index, int)
                or not isinstance(array, (bytes, bytearray, list))
                or not 0 <= index < len(array)
            ):
                raise OmlxTripledesError("omlx_array_read_invalid")
            push(array[index])
        elif opcode == 105:  # ldlen
            array = pop()
            if not isinstance(array, (bytes, bytearray, list)):
                raise OmlxTripledesError("omlx_array_length_invalid")
            push(len(array))
        elif opcode == 138:  # stelem.i1
            value, index, array = pop(), pop(), pop()
            if (
                not isinstance(array, list)
                or not isinstance(index, int)
                or not isinstance(value, int)
                or not 0 <= index < len(array)
                or not 0 <= value <= 255
            ):
                raise OmlxTripledesError("omlx_array_write_invalid")
            array[index] = value
        elif opcode in {123, 128}:  # profile上のidentity conversion
            push(pop())
        elif opcode == 37:  # conv.u1
            value = pop()
            if not isinstance(value, int):
                raise OmlxTripledesError("omlx_conv_u1_invalid")
            push(value & 0xFF)
        elif opcode == 150:  # newobj
            token = _required_int(item)
            if token == 0x060000D9:
                stream = pop()
                if stream != ("stream", encrypted):
                    raise OmlxTripledesError("omlx_reader_source_mismatch")
                push(("reader", stream))
            elif token == 0x0600008A:
                push(("resource-transform",))
            else:
                raise OmlxTripledesError("omlx_newobj_out_of_profile")
        elif opcode == 134:  # call
            token = _required_int(item)
            if token == 0x060000B3:
                reader = pop()
                if not isinstance(reader, tuple) or reader[:1] != ("reader",):
                    raise OmlxTripledesError("omlx_reader_getter_mismatch")
                push(reader[1])
            elif token == 0x060000B4:
                position, stream = pop(), pop()
                if position != 0 or stream != ("stream", encrypted):
                    raise OmlxTripledesError("omlx_stream_position_mismatch")
            elif token == 0x060000B5:
                stream = pop()
                if stream != ("stream", encrypted):
                    raise OmlxTripledesError("omlx_stream_length_source_mismatch")
                push(len(encrypted))
            elif token == 0x060000B6:
                count, reader = pop(), pop()
                if (
                    not isinstance(count, int)
                    or not 0 <= count <= len(encrypted)
                    or not isinstance(reader, tuple)
                    or reader[:1] != ("reader",)
                ):
                    raise OmlxTripledesError("omlx_reader_read_mismatch")
                push(encrypted[:count])
            elif token == 0x060000B7:
                pop()
            elif token == 0x060000B8:
                array = pop()
                if not isinstance(array, list):
                    raise OmlxTripledesError("omlx_reverse_target_mismatch")
                array.reverse()
            elif token == 0x060000B9:
                pop()
                push(("assembly-name",))
            elif token == 0x060000BA:
                if pop() != ("assembly-name",):
                    raise OmlxTripledesError("omlx_public_key_source_mismatch")
                push(b"")
            elif token == 0x060000C3:
                pop()
                push(("entrypoint", entrypoint_token))
            elif token == 0x060000C4:
                right, left = pop(), pop()
                push(1 if left == right else 0)
            elif token in transforms:
                ciphertext, mask, key, instance = pop(), pop(), pop(), pop()
                if (
                    instance != ("resource-transform",)
                    or bytes(ciphertext) != encrypted
                    or not isinstance(key, list)
                    or not isinstance(mask, list)
                    or len(key) != 32
                    or len(mask) != 16
                    or recovered is not None
                ):
                    raise OmlxTripledesError("omlx_transform_binding_mismatch")
                recipe = transforms[token]
                key_bytes, mask_bytes = bytes(key), bytes(mask)
                _check_time(deadline, clock)
                work_budget.charge_table_transform(len(encrypted))
                clear = decrypt_keyed_eaz_resource(
                    encrypted,
                    key_bytes,
                    key_mask=b"",
                    seed=recipe.seed,
                    addend=recipe.addend,
                    allow_partial_word=True,
                )
                _check_time(deadline, clock)
                recovered = _TableRecovery(
                    clear,
                    key_bytes,
                    mask_bytes,
                    recipe,
                    steps,
                )
            elif token == 0x060000C5:
                push(1)
            elif token == 0x060000C6:
                push(0)
            else:
                raise OmlxTripledesError("omlx_call_out_of_profile")
        elif opcode == 110:  # ret
            if stack or recovered is None:
                raise OmlxTripledesError("omlx_terminal_state_invalid")
            _check_time(deadline, clock)
            return _TableRecovery(
                recovered.clear,
                recovered.key,
                recovered.mask,
                recovered.transform,
                steps,
            )
        else:
            raise OmlxTripledesError(f"omlx_opcode_out_of_profile:{opcode}")
        if not 0 <= next_ip < len(instructions):
            raise OmlxTripledesError("omlx_branch_target_out_of_bounds")
        ip = next_ip
    raise OmlxTripledesError("omlx_method_without_verified_ret")


def _decode_table(
    data: bytes,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[tuple[int, str], ...]:
    _check_time(deadline, clock)
    result: list[tuple[int, str]] = []
    offset = 0
    while offset < len(data):
        _check_time(deadline, clock)
        if len(result) >= MAX_STRING_COUNT:
            raise OmlxTripledesError("string_table_count_limit")
        try:
            value = decode_length_prefixed_utf16le(data, offset)
        except StaticRecoveryError as exc:
            raise OmlxTripledesError("string_table_invalid") from exc
        result.append((offset, value))
        offset += 4 + len(value.encode("utf-16le"))
    if offset != len(data) or not result:
        raise OmlxTripledesError("string_table_boundary_mismatch")
    _check_time(deadline, clock)
    return tuple(result)


def _selectors(
    initializer: Any,
    profile: _OmlxProfile,
) -> tuple[int, int, int]:
    fields = dict(initializer.field_values)
    values: list[int]
    if profile.profile_id == "omlx_dispatch_v1":
        values = []
        for field, left, right in _SELECTOR_PROFILE_V1:
            if field not in fields:
                raise OmlxTripledesError("selector_field_missing")
            values.append((left ^ right ^ fields[field]) & _U32_MASK)
    elif profile.profile_id == "omlx_dispatch_common_v2":
        required = (0x04000167, 0x0400013D, 0x04000155)
        if any(field not in fields for field in required):
            raise OmlxTripledesError("selector_field_missing")
        values = [
            (
                ((-1_197_562_682 << 3) & _U32_MASK)
                ^ (-226_703_778 & _U32_MASK)
                ^ (fields[0x04000167] & _U32_MASK)
            )
            & _U32_MASK,
            (1_966_706_405 ^ 1_586_489_910 ^ (fields[0x0400013D] & _U32_MASK))
            & _U32_MASK,
            (
                ((~1_811_268_187) & _U32_MASK)
                ^ (-2_129_839_413 & _U32_MASK)
                ^ (fields[0x04000155] & _U32_MASK)
            )
            & _U32_MASK,
        ]
    else:
        raise OmlxTripledesError("selector_profile_unreviewed")
    if len(set(values)) != len(values):
        raise OmlxTripledesError("selector_offsets_not_distinct")
    return tuple(values)  # type: ignore[return-value]


def _child_resource_entries(
    child: bytes,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[tuple[str, bytes], ...]:
    _check_time(deadline, clock)
    with _contained_parser_diagnostics():
        pe = dnfile.dnPE(data=child, clr_lazy_load=False)
    _check_time(deadline, clock)
    resources = list(getattr(getattr(pe, "net", None), "resources", ()) or ())
    if len(resources) > MAX_RESOURCE_COUNT:
        raise OmlxTripledesError("child_resource_count_limit")
    result: list[tuple[str, bytes]] = []
    entry_count = 0
    total_bytes = 0
    for resource in resources:
        _check_time(deadline, clock)
        entries = list(getattr(getattr(resource, "data", None), "entries", ()) or ())
        entry_count += len(entries)
        if entry_count > MAX_RESOURCE_ENTRY_COUNT:
            raise OmlxTripledesError("child_resource_entry_count_limit")
        for entry in entries:
            _check_time(deadline, clock)
            value = getattr(entry, "value", None)
            if isinstance(value, (bytes, bytearray)):
                total_bytes += len(value)
                if (
                    len(value) > MAX_RESOURCE_BYTES
                    or total_bytes > MAX_TOTAL_RESOURCE_ENTRY_BYTES
                ):
                    raise OmlxTripledesError("child_resource_entry_byte_limit")
                result.append((str(getattr(entry, "name", "")), bytes(value)))
    _check_time(deadline, clock)
    return tuple(result)


def _single_child_resource_entry(
    child: bytes,
    name: str,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> bytes:
    matches = [
        value
        for entry_name, value in _child_resource_entries(
            child,
            deadline=deadline,
            clock=clock,
        )
        if entry_name == name
    ]
    if len(matches) != 1:
        raise OmlxTripledesError(
            "terminal_resource_entry_missing"
            if not matches
            else "terminal_resource_entry_ambiguous"
        )
    return matches[0]


def _canonical_base64_of_size(value: str, size: int) -> bytes | None:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
        return None
    return raw


def _bytes_identity(value: bytes) -> tuple[int, bytes]:
    return len(value), hashlib.sha256(value).digest()


def _text_identity(value: str) -> tuple[int, bytes]:
    return _bytes_identity(value.encode("utf-8", errors="surrogatepass"))


def _table_identity(table: Sequence[tuple[int, str]]) -> tuple[int, bytes]:
    digest = hashlib.sha256()
    for offset, value in table:
        encoded = value.encode("utf-8", errors="surrogatepass")
        digest.update(offset.to_bytes(8, "little", signed=True))
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    return len(table), digest.digest()


def _terminal_binding_identity(binding: _TerminalBinding) -> tuple[Any, ...]:
    return (
        binding.key_offset,
        binding.iv_offset,
        binding.resource_name_offset,
        _text_identity(binding.key_base64),
        _text_identity(binding.iv_base64),
        _text_identity(binding.resource_name),
        _bytes_identity(binding.ciphertext),
        _bytes_identity(binding.payload),
    )


def _dynamic_output_identity(
    table_recovery: _TableRecovery,
    table: Sequence[tuple[int, str]],
    terminal_binding: _TerminalBinding,
) -> tuple[Any, ...]:
    return (
        _bytes_identity(table_recovery.clear),
        _bytes_identity(table_recovery.key),
        _bytes_identity(table_recovery.mask),
        table_recovery.transform,
        table_recovery.steps,
        _table_identity(table),
        _terminal_binding_identity(terminal_binding),
    )


def _select_terminal_binding(
    table: Sequence[tuple[int, str]],
    child: bytes,
    *,
    deadline: float,
    clock: Callable[[], float],
    work_budget: _TerminalWorkBudget,
) -> _TerminalBinding:
    """型・resource・暗号・圧縮・PE境界を全て満たすselectorを一意化する。

    randomized OMLX dispatcherではselector計算用opcodeもbuildごとに変化する。
    生のoffsetを推測せず、table上の正規境界だけを列挙し、16-byte
    TripleDES key、8-byte IV、単一ResourceSet ByteArray、PKCS7、長さ付き
    GZip、完全なmanaged PEという実際の下流契約を全て満たす1候補だけを
    採用する。0件または複数件ならfail-closedで拒否する。
    """

    _check_time(deadline, clock)
    keys = [
        (offset, value)
        for offset, value in table
        if _canonical_base64_of_size(value, 16) is not None
    ]
    ivs = [
        (offset, value)
        for offset, value in table
        if _canonical_base64_of_size(value, 8) is not None
    ]
    entries = _child_resource_entries(
        child,
        deadline=deadline,
        clock=clock,
    )
    _check_time(deadline, clock)
    by_name: dict[str, list[bytes]] = {}
    for name, value in entries:
        _check_time(deadline, clock)
        by_name.setdefault(name, []).append(value)
    names = [
        (offset, value, by_name[value][0])
        for offset, value in table
        if len(by_name.get(value, ())) == 1
    ]
    combination_count = len(keys) * len(ivs) * len(names)
    if combination_count == 0:
        raise OmlxTripledesError("terminal_binding_candidate_missing")
    if combination_count > MAX_TERMINAL_BINDING_CANDIDATES:
        raise _OmlxHardLimitError("terminal_binding_candidate_limit")

    selected: _TerminalBinding | None = None
    selected_identity: tuple[Any, ...] | None = None
    for key_offset, key_base64 in keys:
        for iv_offset, iv_base64 in ivs:
            for resource_name_offset, resource_name, ciphertext in names:
                if len({key_offset, iv_offset, resource_name_offset}) != 3:
                    continue
                _check_time(deadline, clock)
                work_budget.charge_candidate(len(ciphertext))
                try:
                    clear = decrypt_tripledes_cbc_pkcs7_base64(
                        ciphertext,
                        key_base64,
                        iv_base64,
                    )
                    _check_time(deadline, clock)
                    declared = (
                        int.from_bytes(clear[:4], "little", signed=True)
                        if len(clear) >= 4
                        else 0
                    )
                    inflated_work = 0
                    if 0 < declared <= MAX_OUTPUT_BYTES:
                        # helperは長さ超過検出用にdeclared + 1 byteまで展開する。
                        inflated_work = declared + 1
                        work_budget.charge_inflated_work(inflated_work)
                    remaining_before_inflate = max(
                        1,
                        work_budget.remaining_inflated_work_bytes + inflated_work,
                    )
                    payload = inflate_length_prefixed_gzip(
                        clear,
                        max_output_bytes=min(
                            MAX_OUTPUT_BYTES,
                            remaining_before_inflate,
                        ),
                    )
                    _check_time(deadline, clock)
                    extent = inspect_structural_pe_extent(
                        payload,
                        max_extent=MAX_OUTPUT_BYTES,
                    )
                    _check_time(deadline, clock)
                    if extent.extent != len(payload) or not has_clr_metadata(payload):
                        continue
                    _check_time(deadline, clock)
                except _OmlxHardLimitError:
                    raise
                except (StaticRecoveryError, ValueError, TypeError, IndexError):
                    continue
                candidate = _TerminalBinding(
                    key_offset=key_offset,
                    iv_offset=iv_offset,
                    resource_name_offset=resource_name_offset,
                    key_base64=key_base64,
                    iv_base64=iv_base64,
                    resource_name=resource_name,
                    ciphertext=ciphertext,
                    payload=payload,
                )
                candidate_identity = _terminal_binding_identity(candidate)
                if selected is None:
                    selected = candidate
                    selected_identity = candidate_identity
                elif candidate_identity != selected_identity:
                    raise OmlxTripledesError("terminal_binding_candidate_ambiguous")
    if selected is None:
        raise OmlxTripledesError("terminal_binding_candidate_missing")
    return selected


def _recover_dynamic_outputs(
    raw_method0: OmlxMethod,
    opcode_maps: Sequence[Mapping[int, int]],
    encrypted: bytes,
    transforms: Mapping[int, _TransformRecipe],
    child: bytes,
    *,
    entrypoint_token: int,
    deadline: float,
    clock: Callable[[], float],
    work_budget: _TerminalWorkBudget,
) -> _RecoveredDynamicOutput:
    """全opcode候補を終端PEまで評価し、出力一意性で採用する。"""

    if not opcode_maps or len(opcode_maps) > MAX_DYNAMIC_OPCODE_CANDIDATES:
        raise OmlxTripledesError("omlx_dynamic_mapping_candidate_limit")
    selected_identity: tuple[Any, ...] | None = None
    selected_output: (
        tuple[
            OmlxMethod,
            _TableRecovery,
            tuple[tuple[int, str], ...],
            _TerminalBinding,
        ]
        | None
    ) = None
    selected_modes: set[str] = set()
    viable_mapping_count = 0
    viable_mapping_modes = 0
    for opcode_map in opcode_maps:
        _check_time(deadline, clock)
        try:
            method0 = _canonicalize_omlx_method(raw_method0, opcode_map)
            base_recovery = _recover_table(
                method0,
                encrypted,
                transforms,
                entrypoint_token=entrypoint_token,
                deadline=deadline,
                clock=clock,
                work_budget=work_budget,
            )
        except _OmlxHardLimitError:
            raise
        except (
            OmlxTripledesError,
            StaticRecoveryError,
            ValueError,
            TypeError,
            AttributeError,
            IndexError,
        ):
            continue
        _check_time(deadline, clock)
        work_budget.charge_table_transform(len(encrypted))
        masked_recovery = _TableRecovery(
            clear=decrypt_keyed_eaz_resource(
                encrypted,
                base_recovery.key,
                key_mask=base_recovery.mask,
                seed=base_recovery.transform.seed,
                addend=base_recovery.transform.addend,
                allow_partial_word=True,
            ),
            key=base_recovery.key,
            mask=base_recovery.mask,
            transform=base_recovery.transform,
            steps=base_recovery.steps,
        )
        _check_time(deadline, clock)
        mapping_viable = False
        for key_mask_mode, table_recovery in (
            ("none", base_recovery),
            ("xor16", masked_recovery),
        ):
            _check_time(deadline, clock)
            try:
                table = _decode_table(
                    table_recovery.clear,
                    deadline=deadline,
                    clock=clock,
                )
                terminal_binding = _select_terminal_binding(
                    table,
                    child,
                    deadline=deadline,
                    clock=clock,
                    work_budget=work_budget,
                )
            except _OmlxHardLimitError:
                raise
            except (
                OmlxTripledesError,
                StaticRecoveryError,
                ValueError,
                TypeError,
                AttributeError,
                IndexError,
            ):
                continue
            if not mapping_viable:
                viable_mapping_count += 1
                mapping_viable = True
            viable_mapping_modes += 1
            identity = _dynamic_output_identity(
                table_recovery,
                table,
                terminal_binding,
            )
            _check_time(deadline, clock)
            if selected_identity is None:
                selected_identity = identity
                selected_output = (
                    method0,
                    table_recovery,
                    table,
                    terminal_binding,
                )
            elif identity != selected_identity:
                raise OmlxTripledesError("omlx_dynamic_output_ambiguous")
            selected_modes.add(key_mask_mode)
    _check_time(deadline, clock)
    if selected_output is None:
        raise OmlxTripledesError("omlx_dynamic_output_missing")
    method0, table_recovery, table, terminal_binding = selected_output
    return _RecoveredDynamicOutput(
        method0=method0,
        table_recovery=table_recovery,
        table=table,
        terminal_binding=terminal_binding,
        candidate_count=len(opcode_maps),
        viable_candidate_count=viable_mapping_count,
        viable_mapping_mode_candidate_count=viable_mapping_modes,
        key_mask_modes=tuple(sorted(selected_modes)),
    )


def _verify_sink_api_calls(
    data: bytes,
    pe: Any,
    references: Mapping[int, str],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, int]:
    _check_time(deadline, clock)
    required = {
        "System.Security.Cryptography.TripleDES::Create",
        "System.IO.Compression.GZipStream::.ctor",
        "System.Reflection.Assembly::Load",
    }
    if not required.issubset(set(references.values())):
        raise OmlxTripledesError("terminal_sink_api_declaration_missing")
    counts = {name: 0 for name in required}
    rows = list(getattr(getattr(pe.net.mdtables, "MethodDef", None), "rows", ()) or ())
    for rid, row in enumerate(rows, 1):
        _check_time(deadline, clock)
        try:
            method = _decode_method(
                data,
                pe,
                row,
                0x06000000 | rid,
                deadline=deadline,
                clock=clock,
            )
        except RecoveryError as exc:
            _raise_if_elapsed_time_limit(exc)
            continue
        for item in method.instructions:
            if item.opcode not in {"call", "callvirt", "newobj"}:
                continue
            name = references.get(item.operand)
            if name in counts:
                counts[name] += 1
    _check_time(deadline, clock)
    return counts


def recover_managed_omlx_tripledes(
    data: bytes,
    *,
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_ELAPSED_SECONDS,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """OMLX保護tableとEaz child ResourceSetを単一recipeで復元する。"""

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
    started = clock()
    deadline = started + float(max_elapsed_seconds)
    try:
        _check_time(deadline, clock)
        if not has_clr_metadata(data):
            return {"status": "not_applicable", "reason": "not_managed_pe"}, []
        _check_time(deadline, clock)
        with _contained_parser_diagnostics():
            pe = dnfile.dnPE(data=data, clr_lazy_load=False)
        _check_time(deadline, clock)
        _metadata_row_count(pe)
        resources_list = _resource_blobs(pe)
        _check_time(deadline, clock)
        if not resources_list or len(resources_list) > MAX_RESOURCE_COUNT:
            raise OmlxTripledesError("parent_resource_count_limit")
        resources = dict(resources_list)
        if len(resources) != len(resources_list):
            raise OmlxTripledesError("parent_resource_name_ambiguous")
        _check_time(deadline, clock)
        eaz_report, eaz_artifacts = recover_managed_eaz_resource(
            data,
            clock=clock,
            max_elapsed_seconds=min(10.0, max(0.001, deadline - clock())),
        )
        if eaz_report.get("reason") == "elapsed_time_limit":
            raise _OmlxHardLimitError("elapsed_time_limit")
        _check_time(deadline, clock)
        children = [
            blob for kind, blob in eaz_artifacts if kind == "managed-eaz-resource-pe"
        ]
        if (
            eaz_report.get("status") != "recovered_managed_resource"
            or len(children) != 1
        ):
            raise OmlxTripledesError("eaz_child_binding_missing")
        child = children[0]
        dynamic_candidate: _DynamicOmlxCandidate | None = None
        try:
            (
                omlx_name,
                omlx_blob,
                method0,
                initializer,
                profile,
            ) = _find_omlx_candidate(
                resources_list,
                deadline=deadline,
                clock=clock,
            )
        except OmlxTripledesError as fixed_error:
            if str(fixed_error) != "omlx_candidate_missing":
                raise
            dynamic_candidate = _find_dynamic_omlx_candidate(
                data,
                pe,
                resources_list,
                deadline=deadline,
                clock=clock,
            )
            omlx_name = dynamic_candidate.resource_name
            omlx_blob = dynamic_candidate.resource_blob
            method0 = dynamic_candidate.raw_method0
            initializer = None
            profile = None
        (
            encrypted_name,
            encrypted,
            caller_token,
            declaration_validation,
            references,
        ) = _find_bound_resource(
            data,
            pe,
            method0.metadata_token,
            resources,
            deadline=deadline,
            clock=clock,
        )
        transforms = _verified_transform_recipes(
            data,
            pe,
            deadline=deadline,
            clock=clock,
        )
        entrypoint_token = int(getattr(pe.net.struct, "EntryPointTokenOrRva", 0) or 0)
        terminal_work_budget = _TerminalWorkBudget()
        if dynamic_candidate is None:
            table_recovery = _recover_table(
                method0,
                encrypted,
                transforms,
                entrypoint_token=entrypoint_token,
                deadline=deadline,
                clock=clock,
                work_budget=terminal_work_budget,
            )
            table = _decode_table(
                table_recovery.clear,
                deadline=deadline,
                clock=clock,
            )
            terminal_binding = _select_terminal_binding(
                table,
                child,
                deadline=deadline,
                clock=clock,
                work_budget=terminal_work_budget,
            )
            recipe = profile.recipe
            profile_id = profile.profile_id
            initializer_token = f"0x{initializer.metadata_token:08x}"
            initializer_field_count: int | None = len(initializer.field_values)
            initializer_used = True
            opcode_mapping_source = "reviewed_fixed_profile"
            opcode_mapping_candidate_count = 1
            viable_mapping_candidate_count = 1
            viable_mapping_mode_candidate_count = 1
            distinct_recovered_output_count = 1
            key_mask_candidate_modes = ["none"]
            selected_key_mask_modes = ["none"]
            dispatcher_token = None
            dispatcher_switch_target_count = None
        else:
            dynamic_output = _recover_dynamic_outputs(
                dynamic_candidate.raw_method0,
                dynamic_candidate.opcode_maps,
                encrypted,
                transforms,
                child,
                entrypoint_token=entrypoint_token,
                deadline=deadline,
                clock=clock,
                work_budget=terminal_work_budget,
            )
            method0 = dynamic_output.method0
            table_recovery = dynamic_output.table_recovery
            table = dynamic_output.table
            terminal_binding = dynamic_output.terminal_binding
            recipe = "omlx_eaz_table_resource_tripledes_gzip_dynamic_v3"
            profile_id = "omlx_dispatch_shape_inferred_v3"
            initializer_token = f"0x{dynamic_candidate.method1_token:08x}"
            initializer_field_count = None
            initializer_used = False
            opcode_mapping_source = "operand_handler_shape_bounded_candidates"
            opcode_mapping_candidate_count = dynamic_output.candidate_count
            viable_mapping_candidate_count = dynamic_output.viable_candidate_count
            viable_mapping_mode_candidate_count = (
                dynamic_output.viable_mapping_mode_candidate_count
            )
            distinct_recovered_output_count = 1
            key_mask_candidate_modes = ["none", "xor16"]
            selected_key_mask_modes = list(dynamic_output.key_mask_modes)
            dispatcher_token = f"0x{dynamic_candidate.dispatcher.method_token:08x}"
            dispatcher_switch_target_count = (
                dynamic_candidate.dispatcher.switch_target_count
            )
        key_offset = terminal_binding.key_offset
        iv_offset = terminal_binding.iv_offset
        resource_name_offset = terminal_binding.resource_name_offset
        key_base64 = terminal_binding.key_base64
        iv_base64 = terminal_binding.iv_base64
        terminal_name = terminal_binding.resource_name
        ciphertext = terminal_binding.ciphertext
        payload = terminal_binding.payload
        sink_calls = _verify_sink_api_calls(
            data,
            pe,
            references,
            deadline=deadline,
            clock=clock,
        )
        _check_time(deadline, clock)
        key_bytes = base64.b64decode(key_base64, validate=True)
        iv_bytes = base64.b64decode(iv_base64, validate=True)
        _check_time(deadline, clock)
        report = {
            "status": "recovered_managed_omlx_tripledes",
            "recipe": recipe,
            "input": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
            "omlx": {
                "profile_id": profile_id,
                "resource_name": omlx_name,
                "resource_size": len(omlx_blob),
                "resource_sha256": hashlib.sha256(omlx_blob).hexdigest(),
                "method_token": f"0x{method0.metadata_token:08x}",
                "initializer_token": initializer_token,
                "initializer_field_count": initializer_field_count,
                "initializer_used": initializer_used,
                "opcode_mapping_source": opcode_mapping_source,
                "opcode_mapping_candidate_count": opcode_mapping_candidate_count,
                "viable_mapping_candidate_count": viable_mapping_candidate_count,
                "viable_mapping_mode_candidate_count": (
                    viable_mapping_mode_candidate_count
                ),
                "distinct_recovered_output_count": distinct_recovered_output_count,
                "all_viable_candidates_same_output": True,
                "dispatcher_token": dispatcher_token,
                "dispatcher_switch_target_count": dispatcher_switch_target_count,
                "static_dataflow_steps": table_recovery.steps,
            },
            "encrypted_string_table": {
                "resource_name": encrypted_name,
                "resource_size": len(encrypted),
                "resource_sha256": hashlib.sha256(encrypted).hexdigest(),
                "caller_token": f"0x{caller_token:08x}",
                "transform_token": f"0x{table_recovery.transform.token:08x}",
                "transform_seed": table_recovery.transform.seed,
                "transform_addend": table_recovery.transform.addend,
                "transform_core_offsets": list(table_recovery.transform.core_offsets),
                "transform_arg2_reference_count": 0,
                "partial_word_profile_verified": True,
                "derived_key_length": len(table_recovery.key),
                "derived_key_sha256": hashlib.sha256(table_recovery.key).hexdigest(),
                "mask_length": len(table_recovery.mask),
                "mask_sha256": hashlib.sha256(table_recovery.mask).hexdigest(),
                "key_mask_candidate_modes": key_mask_candidate_modes,
                "selected_key_mask_modes": selected_key_mask_modes,
                "mask_material_published": False,
                "clear_sha256": hashlib.sha256(table_recovery.clear).hexdigest(),
                "string_count": len(table),
                "selector_offsets": [key_offset, iv_offset, resource_name_offset],
                "selector_binding": "unique_typed_resource_crypto_gzip_managed_pe",
                "raw_key_published": False,
                "raw_iv_published": False,
            },
            "terminal_resource": {
                "name": terminal_name,
                "ciphertext_size": len(ciphertext),
                "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                "key_length": len(key_bytes),
                "key_sha256": hashlib.sha256(key_bytes).hexdigest(),
                "iv_length": len(iv_bytes),
                "iv_sha256": hashlib.sha256(iv_bytes).hexdigest(),
            },
            "eaz_child": {
                "size": len(child),
                "sha256": hashlib.sha256(child).hexdigest(),
            },
            "output": {
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "format": "managed_pe",
            },
            "direct_sink_api_calls": sink_calls,
            "sink_api_declarations_verified": True,
            "sink_runtime_dispatch_verified": False,
            "framework_declaration_validation": declaration_validation,
            "sample_execution": False,
            "clr_load": False,
            "external_communication": False,
            "bounded_static_dataflow": True,
            "family_attribution_allowed": False,
            "terminal_config_markers_confirmed": False,
            "elapsed_seconds": round(max(0.0, clock() - started), 6),
            "limits": {
                "input_bytes": MAX_INPUT_BYTES,
                "output_bytes": MAX_OUTPUT_BYTES,
                "resource_count": MAX_RESOURCE_COUNT,
                "resource_bytes_each": MAX_RESOURCE_BYTES,
                "resource_entries": MAX_RESOURCE_ENTRY_COUNT,
                "resource_entry_bytes_total": MAX_TOTAL_RESOURCE_ENTRY_BYTES,
                "omlx_steps": MAX_OMLX_STEPS,
                "stack_depth": MAX_STACK_DEPTH,
                "array_bytes": MAX_ARRAY_BYTES,
                "string_count": MAX_STRING_COUNT,
                "terminal_validation_candidates": (MAX_TERMINAL_VALIDATION_CANDIDATES),
                "terminal_ciphertext_work_bytes": (MAX_TERMINAL_CIPHERTEXT_WORK_BYTES),
                "terminal_inflated_work_bytes": MAX_TERMINAL_INFLATED_WORK_BYTES,
                "table_transform_work_bytes": MAX_TABLE_TRANSFORM_WORK_BYTES,
                "elapsed_seconds": float(max_elapsed_seconds),
            },
        }
        _check_time(deadline, clock)
        return report, [("managed-omlx-tripledes-gzip-pe", payload)]
    except (
        OmlxTripledesError,
        StaticRecoveryError,
        RecoveryError,
        ValueError,
        TypeError,
        AttributeError,
        IndexError,
    ) as exc:
        return {
            "status": "rejected",
            "reason": str(exc),
            "input": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
            "sample_execution": False,
            "external_communication": False,
            "family_attribution_allowed": False,
            "terminal_config_markers_confirmed": False,
        }, []
