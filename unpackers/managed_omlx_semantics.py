#!/usr/bin/env python3
"""OMLX dispatcherからvirtual opcode候補を静的に推定する。

検体固有のSHA-256、metadata token、raw opcode IDはprofileに保持しない。
OMLX methodのoperand型・出現形状と、176-way CLR dispatcher handlerの
短いCIL形状だけからcanonical semantic候補を列挙する。完全な一意性を
無理に仮定せず、呼出側が全候補を復元してtable・終端PEの同一性を確認
できるよう、有界な候補集合を返す。不明な到達opcode、形状の崩れ、候補
上限超過はfail-closedで拒否する。

このモジュールはCLR/CIL/復元物を実行しない。
"""

from __future__ import annotations

import itertools
import time
from collections import defaultdict
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from malware.purehvnc.managed_resource_recovery import OmlxMethod

from unpackers.managed_eaz_resource import (
    RecoveryError,
    _contained_parser_diagnostics,
    _decode_method,
    _metadata_row_count,
)

MAX_INPUT_BYTES = 32 << 20
MAX_METHOD_ROWS = 4_096
MAX_TOTAL_METHOD_BYTES = 32 << 20
MAX_TOTAL_METHOD_INSTRUCTIONS = 1_000_000
MAX_HANDLER_PREFIX_INSTRUCTIONS = 32
MAX_ELAPSED_SECONDS = 10.0
DISPATCH_TARGET_COUNT = 176
METHOD0_OPCODE_COUNT = 29
DEFAULT_MAX_CANDIDATES = 64

_CANONICAL_METHOD0_SEMANTICS = frozenset(
    {
        1,  # ldnull
        7,  # ldloc
        15,  # beq
        29,  # newarr
        31,  # brfalse
        37,  # conv.u1
        38,  # blt
        41,  # switch
        43,  # xor
        46,  # ldelem.u1
        57,  # brtrue
        63,  # ldsfld
        66,  # bne.un
        74,  # dup
        89,  # br
        96,  # pop
        105,  # ldlen
        107,  # stsfld
        110,  # ret
        120,  # sub
        123,  # conv.i8
        128,  # identity conversion
        134,  # call
        138,  # stelem.i1
        148,  # stloc
        150,  # newobj
        156,  # ldarg
        167,  # add
        173,  # ldc.i4
    }
)

_UNCONDITIONAL_TERMINATORS = frozenset(
    {"br", "br.s", "ret", "throw", "rethrow", "switch"}
)
_LDC_OPCODES = frozenset(
    {
        "ldc.i4",
        "ldc.i4.s",
        "ldc.i4.m1",
        "ldc.i4.0",
        "ldc.i4.1",
        "ldc.i4.2",
        "ldc.i4.3",
        "ldc.i4.4",
        "ldc.i4.5",
        "ldc.i4.6",
        "ldc.i4.7",
        "ldc.i4.8",
    }
)


class OmlxSemanticError(ValueError):
    """未対応形状、曖昧性上限超過、または境界不整合を表す。"""


@dataclass(frozen=True)
class OmlxHandlerShape:
    """dispatcher targetから無条件終端までの正規化済み短縮形状。"""

    opcodes: tuple[str, ...]
    early_pop: bool
    has_ldnull: bool
    has_newobj: bool
    has_ret_marker: bool


@dataclass(frozen=True)
class OmlxDispatcherFingerprint:
    """検体固有IDをprofile化せずに得たdispatcherの構造証拠。"""

    method_token: int
    switch_target_count: int
    handlers: tuple[tuple[int, OmlxHandlerShape], ...]

    def handler_map(self) -> dict[int, OmlxHandlerShape]:
        """推定器へ渡せるraw opcode→handler形状を返す。"""

        return dict(self.handlers)


@dataclass(frozen=True)
class OmlxSemanticCandidates:
    """method0の有界なraw opcode→canonical semantic候補集合。"""

    mappings: tuple[tuple[tuple[int, int], ...], ...]
    fixed_mapping: tuple[tuple[int, int], ...]
    ambiguous_groups: tuple[tuple[tuple[int, ...], tuple[int, ...]], ...]

    @property
    def candidate_count(self) -> int:
        return len(self.mappings)

    def mapping_dicts(self) -> tuple[dict[int, int], ...]:
        """既存canonicalizer向けのdictを候補順に返す。"""

        return tuple(dict(mapping) for mapping in self.mappings)


def _check_time(deadline: float, clock: Callable[[], float]) -> None:
    if clock() > deadline:
        raise OmlxSemanticError("elapsed_time_limit")


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _token_table(value: Any) -> int | None:
    integer = _as_int(value)
    if integer is None or not 0 < integer <= 0xFFFFFFFF:
        return None
    table = integer >> 24
    return table if table in {1, 2, 4, 6, 10, 27, 112} else None


def _handler_shape(instructions: Sequence[Any], start: int) -> OmlxHandlerShape:
    prefix = []
    for item in instructions[start : start + MAX_HANDLER_PREFIX_INSTRUCTIONS]:
        prefix.append(item)
        if item.opcode in _UNCONDITIONAL_TERMINATORS:
            break
    if not prefix:
        raise OmlxSemanticError("dispatcher_handler_empty")
    opcodes = tuple(str(item.opcode).casefold() for item in prefix)
    pop_indices = [index for index, opcode in enumerate(opcodes) if opcode == "pop"]
    ldc_indices = [
        index for index, opcode in enumerate(opcodes) if opcode in _LDC_OPCODES
    ]
    early_pop = bool(pop_indices) and (
        not ldc_indices or pop_indices[0] < ldc_indices[0]
    )
    has_ret_marker = any(
        prefix[index].opcode in {"ldc.i4", "ldc.i4.s"}
        and _as_int(prefix[index].operand) == -3
        and prefix[index + 1].opcode == "stfld"
        for index in range(len(prefix) - 1)
    )
    return OmlxHandlerShape(
        opcodes=opcodes,
        early_pop=early_pop,
        has_ldnull="ldnull" in opcodes,
        has_newobj="newobj" in opcodes,
        has_ret_marker=has_ret_marker,
    )


def extract_omlx_handler_shapes(
    data: bytes,
    pe: Any,
    raw_opcodes: Collection[int],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> OmlxDispatcherFingerprint:
    """唯一の176-way dispatcherから指定raw opcodeの形状を抽出する。

    全MethodDefは既存の有界CIL decoderで読み、方法数、合計byte数、合計
    instruction数、経過時間を制限する。switch targetが命令境界でない場合や
    同型dispatcherが複数ある場合は拒否する。
    """

    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_INPUT_BYTES:
        raise OmlxSemanticError("input_size_limit")
    requested = tuple(sorted(set(raw_opcodes)))
    if (
        not requested
        or len(requested) > DISPATCH_TARGET_COUNT
        or any(
            isinstance(item, bool) or not 0 <= item < DISPATCH_TARGET_COUNT
            for item in requested
        )
    ):
        raise OmlxSemanticError("raw_opcode_set_invalid")
    if deadline is None:
        deadline = clock() + MAX_ELAPSED_SECONDS
    _check_time(deadline, clock)
    try:
        _metadata_row_count(pe)
        rows = list(
            getattr(getattr(pe.net.mdtables, "MethodDef", None), "rows", ()) or ()
        )
    except (AttributeError, RecoveryError) as exc:
        raise OmlxSemanticError("metadata_invalid") from exc
    if not 0 < len(rows) <= MAX_METHOD_ROWS:
        raise OmlxSemanticError("method_row_limit")

    candidates: list[tuple[int, Any, tuple[int, ...]]] = []
    total_bytes = 0
    total_instructions = 0
    with _contained_parser_diagnostics():
        for rid, row in enumerate(rows, 1):
            _check_time(deadline, clock)
            if not int(getattr(row, "Rva", 0) or 0):
                continue
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
            except RecoveryError:
                continue
            total_bytes += method.code_size
            total_instructions += len(method.instructions)
            if (
                total_bytes > MAX_TOTAL_METHOD_BYTES
                or total_instructions > MAX_TOTAL_METHOD_INSTRUCTIONS
            ):
                raise OmlxSemanticError("method_scan_limit")
            switches = [
                item
                for item in method.instructions
                if item.opcode == "switch"
                and isinstance(item.operand, (list, tuple))
                and len(item.operand) == DISPATCH_TARGET_COUNT
            ]
            if len(switches) > 1:
                raise OmlxSemanticError("dispatcher_switch_ambiguous")
            if switches:
                candidates.append(
                    (
                        token,
                        method,
                        tuple(switches[0].operand),
                    )
                )
    if len(candidates) != 1:
        raise OmlxSemanticError(
            "dispatcher_missing" if not candidates else "dispatcher_ambiguous"
        )
    token, method, targets = candidates[0]
    offsets = {item.offset: index for index, item in enumerate(method.instructions)}
    if len(offsets) != len(method.instructions):
        raise OmlxSemanticError("dispatcher_instruction_offset_ambiguous")
    if any(_as_int(target) not in offsets for target in targets):
        raise OmlxSemanticError("dispatcher_target_invalid")
    handlers = tuple(
        (
            raw,
            _handler_shape(method.instructions, offsets[targets[raw]]),
        )
        for raw in requested
    )
    _check_time(deadline, clock)
    return OmlxDispatcherFingerprint(
        method_token=token,
        switch_target_count=len(targets),
        handlers=handlers,
    )


def _unique(items: Sequence[int], label: str) -> int:
    if len(items) != 1:
        raise OmlxSemanticError(f"{label}_{'missing' if not items else 'ambiguous'}")
    return items[0]


def _assign(mapping: dict[int, int], raw: int, semantic: int) -> None:
    if raw in mapping or semantic in mapping.values():
        raise OmlxSemanticError("semantic_assignment_collision")
    mapping[raw] = semantic


def infer_method0_opcode_candidates(
    method: OmlxMethod,
    handler_shapes: Mapping[int, OmlxHandlerShape],
    *,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> OmlxSemanticCandidates:
    """operand/dispatcher形状からmethod0 opcode mapping候補を列挙する。

    現在対応する正規化profileは29 semanticで構成される。4個の独立した
    置換群だけを残すため候補数は最大48となる。候補の採用は呼出側で実際の
    table・resource・終端PEを復元し、成功候補の出力が完全一致することを
    条件にする。
    """

    if isinstance(max_candidates, bool) or not 1 <= max_candidates <= 4_096:
        raise OmlxSemanticError("candidate_limit_invalid")
    if method.method_index != 0 or (method.metadata_token >> 24) != 6:
        raise OmlxSemanticError("method0_identity_invalid")
    by_raw: dict[int, list[Any]] = defaultdict(list)
    for item in method.instructions:
        if not 0 <= item.opcode_id < DISPATCH_TARGET_COUNT:
            raise OmlxSemanticError("raw_opcode_out_of_range")
        by_raw[item.opcode_id].append(item)
    raws = frozenset(by_raw)
    if len(raws) != METHOD0_OPCODE_COUNT:
        raise OmlxSemanticError("method0_opcode_count_mismatch")
    if not raws.issubset(handler_shapes):
        raise OmlxSemanticError("handler_shape_missing")

    kinds: dict[int, int] = {}
    operands: dict[int, tuple[Any, ...]] = {}
    for raw, items in by_raw.items():
        observed_kinds = {item.operand_kind for item in items}
        if len(observed_kinds) != 1:
            raise OmlxSemanticError("operand_kind_conflict")
        kinds[raw] = observed_kinds.pop()
        operands[raw] = tuple(item.operand for item in items)

    mapping: dict[int, int] = {}
    kind5 = sorted(raw for raw in raws if kinds[raw] == 5)
    switch = _unique(
        [
            raw
            for raw in kind5
            if len(operands[raw]) == 1
            and isinstance(operands[raw][0], tuple)
            and 128 <= len(operands[raw][0]) <= 4_096
        ],
        "switch",
    )
    if kind5 != [switch]:
        raise OmlxSemanticError("switch_operand_profile_mismatch")
    _assign(mapping, switch, 41)

    kind1 = sorted(raw for raw in raws if kinds[raw] == 1)
    token_tables = {
        raw: tuple(_token_table(value) for value in operands[raw]) for raw in kind1
    }
    newarr = _unique(
        [
            raw
            for raw in kind1
            if len(operands[raw]) == 2 and set(token_tables[raw]) == {1}
        ],
        "newarr",
    )
    newobj = _unique(
        [
            raw
            for raw in kind1
            if len(operands[raw]) == 3
            and set(token_tables[raw]).issubset({6, 10})
            and set(token_tables[raw]) == {6, 10}
        ],
        "newobj",
    )
    call = _unique(
        [
            raw
            for raw in kind1
            if 64 <= len(operands[raw]) <= 512 and set(token_tables[raw]) == {6}
        ],
        "call",
    )
    field_reads = [
        raw
        for raw in kind1
        if len(operands[raw]) == 3 and set(token_tables[raw]) == {4}
    ]
    field_writes = [
        raw
        for raw in kind1
        if len(operands[raw]) == 2 and set(token_tables[raw]) == {4}
    ]
    ldsfld = _unique(field_reads, "ldsfld")
    stsfld = _unique(field_writes, "stsfld")
    for raw, semantic in (
        (newarr, 29),
        (newobj, 150),
        (call, 134),
        (ldsfld, 63),
        (stsfld, 107),
    ):
        _assign(mapping, raw, semantic)

    integer_raws = [
        raw
        for raw in kind1
        if raw not in mapping
        and all(_as_int(value) is not None for value in operands[raw])
        and not any(_token_table(value) is not None for value in operands[raw])
    ]
    ldc = _unique(
        [raw for raw in integer_raws if len(operands[raw]) > 512],
        "ldc_i4",
    )
    integer_without_ldc = [raw for raw in integer_raws if raw != ldc]
    ldloc = _unique(
        [
            raw
            for raw in integer_without_ldc
            if len(operands[raw]) > 200
            and all(0 <= int(value) <= 63 for value in operands[raw])
        ],
        "ldloc",
    )
    branch = _unique(
        [
            raw
            for raw in integer_without_ldc
            if len(operands[raw]) > 200
            and max(int(value) for value in operands[raw]) > 63
        ],
        "br",
    )
    stloc = _unique(
        [
            raw
            for raw in integer_without_ldc
            if 20 <= len(operands[raw]) <= 200
            and all(0 <= int(value) <= 63 for value in operands[raw])
            and "unbox.any" in handler_shapes[raw].opcodes
            and any(
                opcode in {"stloc", "stloc.s"} for opcode in handler_shapes[raw].opcodes
            )
        ],
        "stloc",
    )
    ldarg = _unique(
        [
            raw
            for raw in integer_without_ldc
            if len(operands[raw]) == 2 and set(operands[raw]) == {0, 1}
        ],
        "ldarg",
    )
    beq = _unique(
        [
            raw
            for raw in integer_without_ldc
            if len(operands[raw]) == 2 and 2 in operands[raw]
        ],
        "beq",
    )
    for raw, semantic in (
        (ldc, 173),
        (ldloc, 7),
        (branch, 89),
        (stloc, 148),
        (ldarg, 156),
        (beq, 15),
    ):
        _assign(mapping, raw, semantic)
    remaining_integer = [raw for raw in integer_raws if raw not in mapping]
    conditional_pair = tuple(
        sorted(raw for raw in remaining_integer if 10 <= len(operands[raw]) <= 200)
    )
    relational_pair = tuple(
        sorted(raw for raw in remaining_integer if len(operands[raw]) == 1)
    )
    if len(conditional_pair) != 2 or len(relational_pair) != 2:
        raise OmlxSemanticError("branch_ambiguity_shape_mismatch")
    if set(conditional_pair) | set(relational_pair) != set(remaining_integer):
        raise OmlxSemanticError("integer_operand_profile_unclassified")

    kind0 = sorted(raw for raw in raws if kinds[raw] == 0)
    if any(any(value is not None for value in operands[raw]) for raw in kind0):
        raise OmlxSemanticError("no_operand_profile_mismatch")
    pop = _unique(
        [raw for raw in kind0 if handler_shapes[raw].early_pop],
        "pop",
    )
    ret = _unique(
        [raw for raw in kind0 if handler_shapes[raw].has_ret_marker],
        "ret",
    )
    ldnull = _unique(
        [
            raw
            for raw in kind0
            if handler_shapes[raw].has_ldnull and handler_shapes[raw].has_newobj
        ],
        "ldnull",
    )
    ldlen = _unique(
        [
            raw
            for raw in kind0
            if handler_shapes[raw].has_ldnull and not handler_shapes[raw].has_newobj
        ],
        "ldlen",
    )
    for raw, semantic in (
        (pop, 96),
        (ret, 110),
        (ldnull, 1),
        (ldlen, 105),
    ):
        _assign(mapping, raw, semantic)

    remaining_zero = [raw for raw in kind0 if raw not in mapping]
    stelem = _unique(
        [raw for raw in remaining_zero if len(operands[raw]) > 180],
        "stelem_i1",
    )
    dup = _unique(
        [raw for raw in remaining_zero if 4 <= len(operands[raw]) <= 8],
        "dup",
    )
    ldelem = _unique(
        [raw for raw in remaining_zero if 9 <= len(operands[raw]) <= 16],
        "ldelem_u1",
    )
    identity = _unique(
        [raw for raw in remaining_zero if 2 <= len(operands[raw]) <= 3],
        "identity",
    )
    for raw, semantic in (
        (stelem, 138),
        (dup, 74),
        (ldelem, 46),
        (identity, 128),
    ):
        _assign(mapping, raw, semantic)
    remaining_zero = [raw for raw in kind0 if raw not in mapping]
    arithmetic_pair = tuple(
        sorted(raw for raw in remaining_zero if len(operands[raw]) >= 32)
    )
    conversion_triple = tuple(
        sorted(raw for raw in remaining_zero if len(operands[raw]) == 1)
    )
    if len(arithmetic_pair) != 2 or len(conversion_triple) != 3:
        raise OmlxSemanticError("no_operand_ambiguity_shape_mismatch")
    if set(arithmetic_pair) | set(conversion_triple) != set(remaining_zero):
        raise OmlxSemanticError("no_operand_profile_unclassified")

    ambiguous_groups = (
        (arithmetic_pair, (120, 167)),
        (conditional_pair, (31, 57)),
        (relational_pair, (38, 66)),
        (conversion_triple, (37, 43, 123)),
    )
    candidate_count = 1
    for raw_group, semantic_group in ambiguous_groups:
        if len(raw_group) != len(semantic_group):
            raise OmlxSemanticError("ambiguity_group_size_mismatch")
        candidate_count *= len(tuple(itertools.permutations(semantic_group)))
    if candidate_count > max_candidates:
        raise OmlxSemanticError("candidate_limit_exceeded")

    candidates = []
    permutation_sets = [
        tuple(itertools.permutations(semantic_group))
        for _, semantic_group in ambiguous_groups
    ]
    for selected in itertools.product(*permutation_sets):
        candidate = dict(mapping)
        for (raw_group, _), semantics in zip(ambiguous_groups, selected):
            candidate.update(zip(raw_group, semantics))
        if set(candidate) != set(raws):
            raise OmlxSemanticError("candidate_raw_coverage_mismatch")
        if frozenset(candidate.values()) != _CANONICAL_METHOD0_SEMANTICS:
            raise OmlxSemanticError("candidate_semantic_coverage_mismatch")
        candidates.append(tuple(sorted(candidate.items())))
    unique_candidates = tuple(sorted(set(candidates)))
    if len(unique_candidates) != candidate_count:
        raise OmlxSemanticError("candidate_deduplication_mismatch")
    return OmlxSemanticCandidates(
        mappings=unique_candidates,
        fixed_mapping=tuple(sorted(mapping.items())),
        ambiguous_groups=tuple(
            (tuple(raw_group), tuple(semantic_group))
            for raw_group, semantic_group in ambiguous_groups
        ),
    )
