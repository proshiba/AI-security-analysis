"""Go decoderの全本文・branch・runtime callをレビュー済みshapeへ照合する。

実行、CPU emulation、file書込み、networkを行わない。
関数名乱数・検体SHA・復号keyをshapeの選択には使用しない。
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import time
from bisect import bisect_right
from collections.abc import Callable

import unpackers.go_decoder_profiles as go_decoder_profiles

MAX_INSTRUCTIONS = 50000
MAX_FUNCTION_BYTES = 512 * 1024


class ShapeError(ValueError):
    """未知または壊れたshapeをfail-closedで拒否する。"""


def function_shape(
    instructions: list[dict],
    function: dict,
    functions: list[dict],
    read_va=None,
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """連続全命令を照合可能な形式へ正規化し、強い全本文digestを返す。"""
    if not instructions or len(instructions) > MAX_INSTRUCTIONS:
        raise ShapeError("instruction_count_limit")
    if not 0 < function["size"] <= MAX_FUNCTION_BYTES:
        raise ShapeError("function_size_limit")
    begin, end = function["va"], function["va"] + function["size"]
    expected = begin
    for instruction in instructions:
        size = len(bytes.fromhex(instruction["bytes"]))
        if instruction["va"] != expected or not 1 <= size <= 15:
            raise ShapeError("noncontiguous_instruction_body")
        expected += size
    if expected != end:
        raise ShapeError("incomplete_function_body")
    starts = {i["va"] for i in instructions}
    ordered = sorted(functions, key=lambda x: x["va"])
    function_starts = [f["va"] for f in ordered]

    def external_call(target: int) -> str:
        index = bisect_right(function_starts, target) - 1
        if index < 0:
            raise ShapeError("external_call_not_in_function_table")
        owner = ordered[index]
        if not owner["va"] <= target < owner["va"] + owner["size"]:
            raise ShapeError("external_call_not_in_function_table")
        # compilerのDuff entryは関数内部のoffsetへcallする。
        if target != owner["va"] and owner["name"] not in {
            "runtime.duffzero",
            "runtime.duffcopy",
        }:
            raise ShapeError("unsupported_mid_function_call")
        if not owner["name"].startswith("runtime."):
            raise ShapeError("unreviewed_external_call_family")
        return owner["name"] + "+" + hex(target - owner["va"])

    data_references: dict[int, int] = {}
    rows = []
    direct_branches = []
    runtime_calls = []
    print_literals_normalized = 0
    indirect_calls = []
    switch_tables = []
    for index, instruction in enumerate(instructions):
        if deadline is not None and index % 128 == 0 and clock() >= deadline:
            raise ShapeError("elapsed_time_limit")
        mnemonic, operands = instruction["mnemonic"], instruction["operands"]
        size = len(bytes.fromhex(instruction["bytes"]))
        location = instruction["va"] - begin
        if mnemonic.startswith("j"):
            if not re.fullmatch(r"0x[0-9a-f]+", operands):
                # Goの有界switch loweringだけを認め、全table targetも照合する。
                switch = re.fullmatch(r"qword ptr \[(\w+) \+ (\w+)\*8\]", operands)
                if not switch or index < 3 or read_va is None:
                    raise ShapeError("indirect_jump_not_reviewed")
                base_register, index_register = switch.groups()
                compare, guard, load = instructions[index - 3 : index]
                compare_shape = re.fullmatch(
                    re.escape(index_register) + r", (0x[0-9a-f]+|[0-9]+)",
                    compare["operands"],
                )
                load_shape = re.fullmatch(
                    re.escape(base_register) + r", \[rip (\+|-) (0x[0-9a-f]+)\]",
                    load["operands"],
                )
                if (
                    compare["mnemonic"] != "cmp"
                    or not compare_shape
                    or guard["mnemonic"] != "ja"
                    or load["mnemonic"] != "lea"
                    or not load_shape
                ):
                    raise ShapeError("unreviewed_switch_lowering")
                count = int(compare_shape.group(1), 0) + 1
                if not 1 <= count <= 32:
                    raise ShapeError("switch_target_count_limit")
                table_va = (
                    load["va"]
                    + len(bytes.fromhex(load["bytes"]))
                    + int(load_shape.group(2), 16)
                    * (1 if load_shape.group(1) == "+" else -1)
                )
                raw_table = read_va(table_va, count * 8)
                if len(raw_table) != count * 8:
                    raise ShapeError("switch_table_not_file_backed")
                targets = struct.unpack(f"<{count}Q", raw_table)
                if any(target not in starts for target in targets):
                    raise ShapeError("switch_target_not_instruction_boundary")
                relative_targets = [target - begin for target in targets]
                switch_tables.append([location, relative_targets])
                operands += ":SWITCH_TARGETS=" + ",".join(
                    hex(target) for target in relative_targets
                )
            else:
                target = int(operands, 16)
                if target not in starts:
                    raise ShapeError("branch_target_not_instruction_boundary")
                operands = "LOCAL+" + hex(target - begin)
                direct_branches.append([location, target - begin, mnemonic])
        elif mnemonic == "call":
            if re.fullmatch(r"0x[0-9a-f]+", operands):
                target = int(operands, 16)
                if begin <= target < end:
                    if target not in starts:
                        raise ShapeError("call_target_not_instruction_boundary")
                    operands = "LOCAL+" + hex(target - begin)
                else:
                    operands = external_call(target)
                    runtime_calls.append([location, operands])
            else:
                # indirect callも削除せず、正確なregister/memory operandを保持する。
                # 新規calleeが存在するshapeは既存fingerprintへ一致できない。
                indirect_calls.append([location, operands])
        else:
            rip = re.search(r"\[rip (\+|-) (0x[0-9a-f]+)\]", operands)
            if rip:
                delta = int(rip.group(2), 16) * (1 if rip.group(1) == "+" else -1)
                target = instruction["va"] + size + delta
                if target not in data_references:
                    data_references[target] = len(data_references)
                operands = (
                    operands[: rip.start()]
                    + "[DATA"
                    + str(data_references[target])
                    + "]"
                    + operands[rip.end() :]
                )
            # RAXへの即値から直後のruntime.printint/uintへの一回の使用だけを
            # 印字literalとして正規化する。演算/branch/stack/loop定数は保持する。
            if (
                mnemonic in {"mov", "movabs"}
                and re.fullmatch(r"(?:rax|eax), (?:0x[0-9a-f]+|[0-9]+)", operands)
                and index + 1 < len(instructions)
            ):
                next_instruction = instructions[index + 1]
                if next_instruction["mnemonic"] == "call" and re.fullmatch(
                    r"0x[0-9a-f]+", next_instruction["operands"]
                ):
                    called = external_call(int(next_instruction["operands"], 16))
                    if called in {"runtime.printint+0x0", "runtime.printuint+0x0"}:
                        operands = operands.split(", ")[0] + ", PRINT_LITERAL"
                        print_literals_normalized += 1
        # hardware register名と幅、同一registerの使用関係をそのまま保持する。
        # RAX/RDXは単項imul、ABI、DIV等でも暗黙roleを持つため別名化しない。
        rows.append(f"{location:08x}:{size}:{mnemonic}:{operands}")
    canonical = "\n".join(rows).encode("utf-8")
    return {
        "schema_version": 1,
        "algorithm": "go_full_decoder_shape_v1",
        "shape_sha256": hashlib.sha256(canonical).hexdigest(),
        "function_size": function["size"],
        "instruction_count": len(instructions),
        "branch_count": len(direct_branches),
        "branch_edges_sha256": hashlib.sha256(
            repr(direct_branches).encode()
        ).hexdigest(),
        "runtime_call_count": len(runtime_calls),
        "runtime_call_edges_sha256": hashlib.sha256(
            repr(runtime_calls).encode()
        ).hexdigest(),
        "indirect_call_count": len(indirect_calls),
        "indirect_calls_sha256": hashlib.sha256(
            repr(indirect_calls).encode()
        ).hexdigest(),
        "switch_table_count": len(switch_tables),
        "switch_targets_sha256": hashlib.sha256(
            repr(switch_tables).encode()
        ).hexdigest(),
        "distinct_data_reference_count": len(data_references),
        "print_literals_normalized": print_literals_normalized,
        "implicit_register_roles_preserved": True,
        "all_non_print_immediates_preserved": True,
        "complete_instruction_body_verified": True,
        "sample_sha_used_for_match": False,
        "decoder_name_used_for_match": False,
        "raw_key_used_for_match": False,
    }


def require_reviewed_shape(value: dict, profiles: list[dict]) -> dict:
    """全本文とreview済みshapeが一致する場合だけprofileを返す。"""
    matching = [
        profile
        for profile in profiles
        if profile.get("shape_sha256") == value["shape_sha256"]
        and profile.get("algorithm") == value["algorithm"]
    ]
    if len(matching) != 1:
        raise ShapeError("unreviewed_or_ambiguous_decoder_shape")
    return matching[0]


def _load_reviewed_shapes() -> tuple[dict, ...]:
    # handlerのsource snapshotへ固定されるliteralのみを使用する。
    # JSONとの完全同期はunit testで確認し、import時のfilesystem読込を不要にする。
    profiles = [dict(zip(go_decoder_profiles.PROFILE_FIELDS, row)) for row in go_decoder_profiles.PROFILE_ROWS]
    if not 1 <= len(profiles) <= 64:
        raise ShapeError("shape_registry_layout_invalid")
    for profile in profiles:
        if profile.get("algorithm") != "go_full_decoder_shape_v1" or not re.fullmatch(
            r"[0-9a-f]{64}", str(profile.get("shape_sha256", ""))
        ):
            raise ShapeError("shape_registry_entry_invalid")
    if len({p["shape_sha256"] for p in profiles}) != len(profiles):
        raise ShapeError("duplicate_reviewed_shapes")
    return tuple(profiles)


REVIEWED_SHAPES = _load_reviewed_shapes()
