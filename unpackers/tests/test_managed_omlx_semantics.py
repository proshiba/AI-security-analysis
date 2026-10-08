"""OMLX virtual opcodeの検体非依存推定に対する合成回帰。"""

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from malware.purehvnc.managed_resource_recovery import (
    Instruction,
    OmlxInstruction,
    OmlxMethod,
)

from unpackers import managed_omlx_semantics as semantics

CANONICAL = (
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


def _fixture() -> tuple[
    OmlxMethod, dict[int, semantics.OmlxHandlerShape], dict[int, int]
]:
    raw_for_semantic = {
        semantic: raw for raw, semantic in enumerate(reversed(CANONICAL))
    }
    records: list[OmlxInstruction] = []

    def emit(semantic: int, kind: int, values: list[object]) -> None:
        raw = raw_for_semantic[semantic]
        for value in values:
            records.append(
                OmlxInstruction(
                    index=len(records),
                    record_offset=len(records),
                    opcode_id=raw,
                    operand_kind=kind,
                    operand=value,
                )
            )

    emit(41, 5, [tuple(range(128))])
    emit(29, 1, [0x0100001B] * 2)
    emit(150, 1, [0x06000001, 0x0A000002, 0x06000003])
    emit(134, 1, [0x06000001] * 64)
    emit(63, 1, [0x04000001] * 3)
    emit(107, 1, [0x04000001] * 2)
    emit(173, 1, list(range(513)))
    emit(7, 1, [0] * 201)
    emit(89, 1, [3] * 200 + [1_000])
    emit(148, 1, [0] * 20)
    emit(156, 1, [0, 1])
    emit(15, 1, [2, 19])
    emit(31, 1, [3] * 10 + [500])
    emit(57, 1, [3] * 11 + [600])
    emit(38, 1, [700])
    emit(66, 1, [800])
    for semantic, count in (
        (96, 40),
        (1, 1),
        (110, 1),
        (105, 3),
        (138, 181),
        (74, 6),
        (46, 10),
        (128, 3),
        (120, 32),
        (167, 33),
        (37, 1),
        (43, 1),
        (123, 1),
    ):
        emit(semantic, 0, [None] * count)

    shapes = {
        raw: semantics.OmlxHandlerShape(
            opcodes=(
                ("ldarg.0", "ldfld", "unbox.any", "stloc.s", "br")
                if semantic == 148
                else ("br",)
            ),
            early_pop=semantic == 96,
            has_ldnull=semantic in {1, 105},
            has_newobj=semantic == 1,
            has_ret_marker=semantic == 110,
        )
        for semantic, raw in raw_for_semantic.items()
    }
    method = OmlxMethod(
        method_index=0,
        metadata_token=0x06000095,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=tuple(records),
        exception_clauses=(),
    )
    true_mapping = {raw: semantic for semantic, raw in raw_for_semantic.items()}
    return method, shapes, true_mapping


def test_method0_inference_bounds_ambiguity_and_keeps_true_mapping() -> None:
    method, shapes, true_mapping = _fixture()

    result = semantics.infer_method0_opcode_candidates(method, shapes)

    assert result.candidate_count == 48
    assert true_mapping in result.mapping_dicts()
    assert all(len(mapping) == 29 for mapping in result.mapping_dicts())
    assert all(
        set(mapping.values()) == set(CANONICAL) for mapping in result.mapping_dicts()
    )
    assert [len(group[0]) for group in result.ambiguous_groups] == [2, 2, 2, 3]


def test_method0_inference_rejects_candidate_limit_and_missing_handler() -> None:
    method, shapes, _ = _fixture()
    with pytest.raises(semantics.OmlxSemanticError, match="candidate_limit_exceeded"):
        semantics.infer_method0_opcode_candidates(
            method,
            shapes,
            max_candidates=47,
        )

    shapes.pop(next(iter(shapes)))
    with pytest.raises(semantics.OmlxSemanticError, match="handler_shape_missing"):
        semantics.infer_method0_opcode_candidates(method, shapes)


def test_method0_inference_rejects_inconsistent_operand_kind() -> None:
    method, shapes, _ = _fixture()
    raw = method.instructions[0].opcode_id
    malformed = list(method.instructions)
    original = malformed[0]
    malformed[0] = OmlxInstruction(
        index=original.index,
        record_offset=original.record_offset,
        opcode_id=raw,
        operand_kind=0,
        operand=original.operand,
    )
    broken = OmlxMethod(
        method_index=method.method_index,
        metadata_token=method.metadata_token,
        type_count=method.type_count,
        exception_clause_count=method.exception_clause_count,
        type_descriptors=method.type_descriptors,
        instructions=tuple(malformed),
        exception_clauses=method.exception_clauses,
    )

    with pytest.raises(semantics.OmlxSemanticError):
        semantics.infer_method0_opcode_candidates(broken, shapes)


def test_dispatcher_shape_extraction_requires_one_176_way_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = tuple(1_000 + index * 10 for index in range(176))
    instructions = [Instruction(10, "switch", targets)]
    instructions.extend(Instruction(target, "br", 10) for target in targets)
    dispatcher = SimpleNamespace(
        code_size=2_000,
        instructions=tuple(instructions),
    )
    plain = SimpleNamespace(
        code_size=1,
        instructions=(Instruction(1, "ret"),),
    )
    rows = [SimpleNamespace(Rva=1), SimpleNamespace(Rva=2)]
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(MethodDef=SimpleNamespace(rows=rows))
        )
    )
    monkeypatch.setattr(semantics, "_metadata_row_count", lambda _pe: 2)
    monkeypatch.setattr(semantics, "_contained_parser_diagnostics", nullcontext)
    monkeypatch.setattr(
        semantics,
        "_decode_method",
        lambda _data, _pe, _row, token, **_kwargs: (
            dispatcher if token == 0x06000001 else plain
        ),
    )

    profile = semantics.extract_omlx_handler_shapes(b"MZ", pe, {0, 175})

    assert profile.method_token == 0x06000001
    assert profile.switch_target_count == 176
    assert set(profile.handler_map()) == {0, 175}
