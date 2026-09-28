"""実行しない合成命令recordによる、decoder全本文誤一致防止試験。"""

import struct
import json
from copy import deepcopy
from pathlib import Path

import pytest
from unpackers.go_decoder_shape import ShapeError, function_shape, require_reviewed_shape


def test_reviewed_shape_literals_match_public_json():
    """runtimeの固定literalと人向けJSONの無断差分を拒否する。"""
    import unpackers.go_decoder_shape as shape

    registry = Path(shape.__file__).parent / "profiles" / "go_decoder_shapes.json"
    value = json.loads(registry.read_text(encoding="utf-8"))
    assert value["schema_version"] == 1
    assert list(shape._load_reviewed_shapes()) == value["profiles"]


def test_reviewed_shape_loading_does_not_read_files(monkeypatch):
    """import後のregistry利用にfile/data capabilityを要求しない。"""
    import unpackers.go_decoder_shape as shape

    def reject(*args, **kwargs):
        raise AssertionError("file読込は禁止")

    monkeypatch.setattr(Path, "open", reject)
    monkeypatch.setattr("builtins.open", reject)
    assert len(shape._load_reviewed_shapes()) == 6


def fixture():
    # 実装へ渡すrecordであり、CPU命令やsampleは実行しない。
    instructions = [
        {"va": 0x1000, "bytes": "90", "mnemonic": "movabs", "operands": "rax, 0x4d4873ecade304d5"},
        {"va": 0x1001, "bytes": "90", "mnemonic": "imul", "operands": "rcx"},
        {"va": 0x1002, "bytes": "90", "mnemonic": "sub", "operands": "esi, r9d"},
        {"va": 0x1003, "bytes": "90", "mnemonic": "mov", "operands": "byte ptr [rdi + rcx], sil"},
        {"va": 0x1004, "bytes": "90", "mnemonic": "jne", "operands": "0x1001"},
        {"va": 0x1005, "bytes": "90", "mnemonic": "mov", "operands": "eax, 0x1234"},
        {"va": 0x1006, "bytes": "90", "mnemonic": "call", "operands": "0x2000"},
        {"va": 0x1007, "bytes": "90", "mnemonic": "ret", "operands": ""},
    ]
    function = {"va": 0x1000, "size": 8, "name": "main.randomDecoder"}
    functions = [function, {"va": 0x2000, "size": 8, "name": "runtime.printint"}]
    return instructions, function, functions


def digest(instructions, function, functions):
    return function_shape(instructions, function, functions)


@pytest.mark.parametrize(
    "mutation",
    ["implicit_rax", "implicit_rdx", "byte_change", "skip_branch", "new_opcode", "changed_constant", "width_change"],
)
def test_semantic_mutation_is_rejected(mutation):
    instructions, function, functions = fixture()
    baseline = digest(instructions, function, functions)
    changed = deepcopy(instructions)
    if mutation == "implicit_rax":
        changed[0]["operands"] = "r10, 0x4d4873ecade304d5"
    elif mutation == "implicit_rdx":
        changed[1]["operands"] = "rdx"
    elif mutation == "byte_change":
        changed[3]["mnemonic"] = "xor"
        changed[3]["operands"] = "byte ptr [rdi + rcx], 0x42"
    elif mutation == "skip_branch":
        changed[4]["operands"] = "0x1007"
    elif mutation == "new_opcode":
        changed[2]["mnemonic"] = "add"
    elif mutation == "changed_constant":
        changed[0]["operands"] = "rax, 0x4d4873ecade304d4"
    elif mutation == "width_change":
        changed[2]["operands"] = "rsi, r9"
    value = digest(changed, function, functions)
    with pytest.raises(ShapeError, match="unreviewed_or_ambiguous"):
        require_reviewed_shape(value, [baseline])


def test_only_print_literal_can_change():
    instructions, function, functions = fixture()
    before = digest(instructions, function, functions)
    instructions[5]["operands"] = "eax, 0x5678"
    after = digest(instructions, function, functions)
    assert before["shape_sha256"] == after["shape_sha256"]
    assert after["print_literals_normalized"] == 1


def test_decoder_random_name_and_image_base_do_not_change_shape():
    instructions, function, functions = fixture()
    before = digest(instructions, function, functions)
    function["name"] = "main.anotherRandomDecoder"
    for item in instructions:
        item["va"] += 0x4000
        if item["mnemonic"] in {"jne", "call"}:
            item["operands"] = hex(int(item["operands"], 16) + 0x4000)
    for item in functions:
        item["va"] += 0x4000
    after = digest(instructions, function, functions)
    assert before["shape_sha256"] == after["shape_sha256"]


def test_partial_body_and_invalid_branch_targets_are_rejected():
    instructions, function, functions = fixture()
    with pytest.raises(ShapeError, match="incomplete_function_body"):
        digest(instructions[:-1], function, functions)
    instructions[4]["operands"] = "0x9999"
    with pytest.raises(ShapeError, match="branch_target_not_instruction_boundary"):
        digest(instructions, function, functions)


def test_switch_table_targets_are_part_of_whole_cfg():
    function = {"va": 0x1000, "size": 7, "name": "main.random"}
    instructions = [
        {"va": 0x1000, "bytes": "90", "mnemonic": "cmp", "operands": "rax, 1"},
        {"va": 0x1001, "bytes": "90", "mnemonic": "ja", "operands": "0x1006"},
        {"va": 0x1002, "bytes": "90", "mnemonic": "lea", "operands": "rcx, [rip + 0x1000]"},
        {"va": 0x1003, "bytes": "90", "mnemonic": "jmp", "operands": "qword ptr [rcx + rax*8]"},
        {"va": 0x1004, "bytes": "90", "mnemonic": "nop", "operands": ""},
        {"va": 0x1005, "bytes": "90", "mnemonic": "nop", "operands": ""},
        {"va": 0x1006, "bytes": "90", "mnemonic": "ret", "operands": ""},
    ]
    before = function_shape(instructions, function, [function], lambda va, size: struct.pack("<2Q", 0x1004, 0x1005))
    after = function_shape(instructions, function, [function], lambda va, size: struct.pack("<2Q", 0x1004, 0x1006))
    assert before["switch_table_count"] == 1
    with pytest.raises(ShapeError, match="unreviewed_or_ambiguous"):
        require_reviewed_shape(after, [before])
    with pytest.raises(ShapeError, match="switch_target_not_instruction_boundary"):
        function_shape(instructions, function, [function], lambda va, size: struct.pack("<2Q", 0x1004, 0x9999))
