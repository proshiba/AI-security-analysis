"""managed CILの分岐・resource consumer・PureRAT終端証拠を静的に扱う。

このmoduleはCLRやCILを実行しない。dncilがparseした命令のoperandを保持し、
有界CFG、exact constant proxy、byte配列のreaching definition、PureRAT系の
terminal semantic evidenceを構築する。semantic evidenceはfamily相関にだけ使い、
単独ではfamily確定やC2確認へ昇格させない。
"""

from __future__ import annotations

import hashlib
import time
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

try:
    from .managed_constructor_guard import preflight_clr_declarations
except ImportError:  # 単独CLIの通常相対探索
    from managed_constructor_guard import preflight_clr_declarations


MAX_CFG_INSTRUCTIONS = 20_000
MAX_CFG_BLOCKS = 4_096
MAX_CFG_EDGES = 16_384
MAX_CFG_SWITCH_TARGETS = 8_192
MAX_DATAFLOW_STATES = 16_384
MAX_PROGRAM_BYTES = 32 << 20

_UNCONDITIONAL_BRANCHES = {"br", "br.s", "leave", "leave.s"}
_CONDITIONAL_BRANCHES = {
    "brfalse", "brfalse.s", "brtrue", "brtrue.s", "beq", "beq.s",
    "bge", "bge.s", "bge.un", "bge.un.s", "bgt", "bgt.s",
    "bgt.un", "bgt.un.s", "ble", "ble.s", "ble.un", "ble.un.s",
    "blt", "blt.s", "blt.un", "blt.un.s", "bne.un", "bne.un.s",
}
_TERMINATORS = _UNCONDITIONAL_BRANCHES | _CONDITIONAL_BRANCHES | {
    "switch", "ret", "throw", "rethrow", "endfinally", "endfilter",
}


@dataclass(frozen=True)
class CilInstruction:
    """公開文字列を含めず、branch operandを保持するCIL命令。"""

    offset: int
    opcode: str
    token: int | None = None
    resolved: str = ""
    integer: int | None = None
    local: int | None = None
    user_string_sha256: str | None = None
    user_string_length: int | None = None
    branch_target: int | None = None
    switch_targets: tuple[int, ...] = ()


@dataclass(frozen=True)
class CilMethod:
    """family名へ依存しないmanaged method model。"""

    token: int
    owner: str
    name: str
    body_sha256: str
    instructions: tuple[CilInstruction, ...]


@dataclass(frozen=True)
class CilProgram:
    """実行せずに得たmanaged programの最小model。"""

    input_sha256: str
    entry_token: int | None
    assembly_public_key_state: str
    methods: tuple[CilMethod, ...]


def _operand_offset(value: object) -> int | None:
    candidate = getattr(value, "offset", value)
    if isinstance(candidate, int) and not isinstance(candidate, bool):
        return candidate
    return None


def branch_operands(instruction: object) -> tuple[int | None, tuple[int, ...]]:
    """dncil命令のbranch operandをexact offsetとして保持する。"""

    opcode = str(getattr(getattr(instruction, "opcode", None), "name", "")).lower()
    operand = getattr(instruction, "operand", None)
    if opcode == "switch":
        try:
            values = tuple(_operand_offset(item) for item in (operand or ()))
        except TypeError:
            return None, ()
        if any(value is None for value in values):
            return None, ()
        return None, tuple(int(value) for value in values if value is not None)
    if opcode in _UNCONDITIONAL_BRANCHES | _CONDITIONAL_BRANCHES:
        return _operand_offset(operand), ()
    return None, ()


def instruction_from_raw(
    instruction: object,
    *,
    fallback_offset: int | None = None,
    token: int | None = None,
    resolved: str = "",
    integer: int | None = None,
    local: int | None = None,
    user_string: str | None = None,
) -> CilInstruction:
    """dncil命令をbranch保持modelへ変換し、raw user stringはhash化する。"""

    target, switch_targets = branch_operands(instruction)
    raw_offset = getattr(instruction, "offset", fallback_offset)
    if not isinstance(raw_offset, int) or isinstance(raw_offset, bool) or raw_offset < 0:
        raise ValueError("managed_cil_instruction_offset_missing")
    return CilInstruction(
        offset=raw_offset,
        opcode=str(getattr(getattr(instruction, "opcode", None), "name", "")).lower(),
        token=token,
        resolved=resolved,
        integer=integer,
        local=local,
        user_string_sha256=(
            hashlib.sha256(user_string.encode("utf-8")).hexdigest()
            if isinstance(user_string, str)
            else None
        ),
        user_string_length=len(user_string) if isinstance(user_string, str) else None,
        branch_target=target,
        switch_targets=switch_targets,
    )


def build_bounded_cfg(
    instructions: Sequence[CilInstruction],
    *,
    max_instructions: int = MAX_CFG_INSTRUCTIONS,
    max_blocks: int = MAX_CFG_BLOCKS,
    max_edges: int = MAX_CFG_EDGES,
    max_switch_targets: int = MAX_CFG_SWITCH_TARGETS,
) -> dict[str, Any]:
    """branch targetを失わず、明示予算内だけでbasic-block CFGを作る。"""

    if any(
        not isinstance(value, int) or isinstance(value, bool) or value <= 0
        for value in (max_instructions, max_blocks, max_edges, max_switch_targets)
    ):
        raise ValueError("CFG予算は正の整数で指定してください")
    if not instructions:
        return {
            "status": "empty_method",
            "reason": "method_has_no_instructions",
            "block_count": 0,
            "edge_count": 0,
            "blocks": [],
            "edges": [],
            "branch_operands_preserved": True,
        }
    if len(instructions) > max_instructions:
        return {
            "status": "budget_exceeded",
            "reason": "cfg_instruction_budget_exceeded",
            "instruction_count": len(instructions),
            "blocks": [],
            "edges": [],
            "branch_operands_preserved": True,
        }
    ordered = tuple(sorted(instructions, key=lambda item: item.offset))
    offsets = [item.offset for item in ordered]
    if len(offsets) != len(set(offsets)):
        return {
            "status": "rejected",
            "reason": "duplicate_instruction_offset",
            "blocks": [],
            "edges": [],
            "branch_operands_preserved": True,
        }
    offset_set = set(offsets)
    leaders = {offsets[0]}
    target_count = 0
    for index, item in enumerate(ordered):
        if (
            item.opcode in _UNCONDITIONAL_BRANCHES | _CONDITIONAL_BRANCHES
            and item.branch_target is None
        ):
            return {
                "status": "rejected",
                "reason": "branch_operand_missing",
                "blocks": [],
                "edges": [],
                "branch_operands_preserved": True,
            }
        targets = item.switch_targets or (() if item.branch_target is None else (item.branch_target,))
        target_count += len(targets)
        if target_count > max_switch_targets:
            return {
                "status": "budget_exceeded",
                "reason": "cfg_branch_target_budget_exceeded",
                "blocks": [],
                "edges": [],
                "branch_operands_preserved": True,
            }
        if any(target not in offset_set for target in targets):
            return {
                "status": "rejected",
                "reason": "branch_target_not_instruction_boundary",
                "invalid_targets": sorted(target for target in targets if target not in offset_set),
                "blocks": [],
                "edges": [],
                "branch_operands_preserved": True,
            }
        leaders.update(targets)
        if item.opcode in _TERMINATORS and index + 1 < len(ordered):
            leaders.add(ordered[index + 1].offset)
    sorted_leaders = sorted(leaders)
    if len(sorted_leaders) > max_blocks:
        return {
            "status": "budget_exceeded",
            "reason": "cfg_block_budget_exceeded",
            "block_count": len(sorted_leaders),
            "blocks": [],
            "edges": [],
            "branch_operands_preserved": True,
        }
    leader_set = set(sorted_leaders)
    blocks: list[dict[str, Any]] = []
    offset_to_block: dict[int, int] = {}
    current: list[CilInstruction] = []
    for item in ordered:
        if current and item.offset in leader_set:
            block_index = len(blocks)
            block = {
                "id": block_index,
                "start_offset": current[0].offset,
                "end_offset": current[-1].offset,
                "instruction_offsets": [entry.offset for entry in current],
            }
            blocks.append(block)
            for entry in current:
                offset_to_block[entry.offset] = block_index
            current = []
        current.append(item)
    if current:
        block_index = len(blocks)
        blocks.append(
            {
                "id": block_index,
                "start_offset": current[0].offset,
                "end_offset": current[-1].offset,
                "instruction_offsets": [entry.offset for entry in current],
            }
        )
        for entry in current:
            offset_to_block[entry.offset] = block_index
    by_offset = {item.offset: item for item in ordered}
    edges: list[dict[str, Any]] = []

    def add_edge(source: int, target_offset: int, kind: str, switch_index: int | None = None) -> bool:
        if len(edges) >= max_edges:
            return False
        edge: dict[str, Any] = {
            "source": source,
            "target": offset_to_block[target_offset],
            "kind": kind,
        }
        if switch_index is not None:
            edge["switch_index"] = switch_index
        edges.append(edge)
        return True

    for block_index, block in enumerate(blocks):
        last = by_offset[block["end_offset"]]
        next_block = block_index + 1 if block_index + 1 < len(blocks) else None
        if last.opcode == "switch":
            for switch_index, target in enumerate(last.switch_targets):
                if not add_edge(block_index, target, "switch", switch_index):
                    return {"status": "budget_exceeded", "reason": "cfg_edge_budget_exceeded", "blocks": [], "edges": [], "branch_operands_preserved": True}
            if next_block is not None:
                edges.append({"source": block_index, "target": next_block, "kind": "switch_default"})
        elif last.opcode in _UNCONDITIONAL_BRANCHES:
            if not add_edge(block_index, last.branch_target, "branch"):
                return {"status": "budget_exceeded", "reason": "cfg_edge_budget_exceeded", "blocks": [], "edges": [], "branch_operands_preserved": True}
        elif last.opcode in _CONDITIONAL_BRANCHES:
            if not add_edge(block_index, last.branch_target, "branch_true"):
                return {"status": "budget_exceeded", "reason": "cfg_edge_budget_exceeded", "blocks": [], "edges": [], "branch_operands_preserved": True}
            if next_block is not None:
                edges.append({"source": block_index, "target": next_block, "kind": "fallthrough"})
        elif last.opcode not in {"ret", "throw", "rethrow", "endfinally", "endfilter"} and next_block is not None:
            edges.append({"source": block_index, "target": next_block, "kind": "fallthrough"})
        if len(edges) > max_edges:
            return {"status": "budget_exceeded", "reason": "cfg_edge_budget_exceeded", "blocks": [], "edges": [], "branch_operands_preserved": True}
    return {
        "status": "complete",
        "reason": None,
        "instruction_count": len(ordered),
        "branch_target_count": target_count,
        "unique_branch_target_count": len({target for item in ordered for target in (*item.switch_targets, *(() if item.branch_target is None else (item.branch_target,)))}),
        "block_count": len(blocks),
        "edge_count": len(edges),
        "blocks": blocks,
        "edges": edges,
        "branch_operands_preserved": True,
    }


def classify_exact_constant_proxy(method: CilMethod) -> str | None:
    """副作用を含まないexact bodyだけをtrue／false proxyとして受理する。"""

    opcodes = [item.opcode for item in method.instructions if item.opcode != "nop"]
    if opcodes == ["ldnull", "ldnull", "ceq", "ret"]:
        return "constant_true"
    if opcodes in (["ldnull", "ret"], ["ldc.i4.0", "ret"]):
        return "constant_false"
    if opcodes == ["ldc.i4.1", "ret"]:
        return "constant_true"
    return None


def fold_exact_branch(opcode: str, condition: str | bool | None) -> bool | None:
    """brtrue/brfalseだけをexact constantでfoldし、不明値は残す。"""

    if condition in {"constant_true", True}:
        value = True
    elif condition in {"constant_false", False, None}:
        value = False if condition is not None else None
    else:
        return None
    if opcode in {"brtrue", "brtrue.s"}:
        return value
    if opcode in {"brfalse", "brfalse.s"}:
        return not value
    return None


def fold_metadata_public_key_null_branch(
    opcode: str,
    public_key_state: str,
    *,
    comparison: str = "is_null",
) -> bool | None:
    """Assembly metadataで確定したPublicKey null比較だけをfoldする。

    ``GetPublicKey`` の実行結果を推測せず、Assembly rowが一意でblobが空か否かを
    静的に確定できた場合に限る。戻り値は「branchを取るか」であり、不明はNone。
    """

    if comparison not in {"is_null", "is_not_null"}:
        raise ValueError("PublicKey比較はis_nullまたはis_not_nullで指定してください")
    if public_key_state == "absent":
        condition = comparison == "is_null"
    elif public_key_state == "present":
        condition = comparison == "is_not_null"
    else:
        return None
    return fold_exact_branch(opcode, condition)


def assembly_public_key_state(pe: object) -> str:
    """Assembly metadataのPublicKey blobだけからpresent／absentを返す。"""

    try:
        rows = list(pe.net.mdtables.Assembly.rows)
    except Exception:  # noqa: BLE001 - metadata provider差をunavailableへ閉じる。
        return "unavailable"
    if len(rows) != 1:
        return "ambiguous"
    try:
        value = bytes(getattr(getattr(rows[0], "PublicKey", None), "value", b"") or b"")
    except Exception:  # noqa: BLE001 - metadata provider差をunavailableへ閉じる。
        return "unavailable"
    return "present" if value else "absent"


def verify_length_prefixed_utf16_cache_shape(method: CilMethod) -> dict[str, Any]:
    """4-byte長＋UTF-16 cache形をAPI順序とfield/copy操作だけで検証する。"""

    calls = [
        (index, item.resolved)
        for index, item in enumerate(method.instructions)
        if item.opcode in {"call", "callvirt", "newobj"}
    ]

    def positions(marker: str) -> list[int]:
        return [index for index, resolved in calls if marker in resolved]

    to_int32 = positions("System.BitConverter::ToInt32")
    copies = positions("System.Array::Copy")
    unicode_getter = positions("System.Text.Encoding::get_Unicode")
    get_string = positions("System.Text.Encoding::GetString")
    get_bytes = positions("System.BitConverter::GetBytes")
    resource_reads = positions("System.Reflection.Assembly::GetManifestResourceStream")
    internal_calls = [
        index
        for index, item in enumerate(method.instructions)
        if item.opcode in {"call", "callvirt"}
        and isinstance(item.token, int)
        and item.token >> 24 == 6
    ]
    cache_adds = [
        index for index, item in enumerate(method.instructions)
        if item.opcode == "callvirt"
        and (item.resolved == "Add" or item.resolved.endswith("::Add"))
    ]
    resource_to_decoder = bool(
        resource_reads
        and to_int32
        and resource_reads[0] < to_int32[0]
        and any(resource_reads[0] < index < to_int32[0] for index in internal_calls)
    )
    ordered_decode = bool(
        len(to_int32) == 1
        and len(copies) >= 2
        and len(unicode_getter) == 1
        and len(get_string) == 1
        and to_int32[0] < copies[0] < unicode_getter[0] < get_string[0]
        and get_bytes
        and get_string[0] < get_bytes[0] < copies[-1]
    )
    matched = bool(resource_to_decoder and ordered_decode and len(cache_adds) >= 2)
    return {
        "status": "matched" if matched else "not_matched",
        "reason": None if matched else "length_prefixed_utf16_cache_shape_incomplete",
        "method_token": f"0x{method.token:08x}",
        "method_body_sha256": method.body_sha256,
        "manifest_resource_read_count": len(resource_reads),
        "resource_to_internal_decoder_call": resource_to_decoder,
        "length_prefix_api_count": len(to_int32),
        "copy_api_count": len(copies),
        "unicode_decode_api_count": len(get_string),
        "cache_add_count": len(cache_adds),
        "cache_prefix_rewrite_observed": bool(get_bytes and len(copies) >= 2 and get_bytes[0] < copies[-1]),
        "raw_strings_published": False,
    }


def analyze_byte_array_sink_reaching_definitions(
    method: CilMethod,
    *,
    cfg: Mapping[str, Any] | None = None,
    required_lengths: tuple[int, int] = (32, 16),
    proxy_constants: Mapping[int, str] | None = None,
    custom_sink_tokens: Iterable[int] = (),
    metadata_public_key_state: str = "unavailable",
    max_states: int = MAX_DATAFLOW_STATES,
) -> dict[str, Any]:
    """決定可能なdispatcher pathだけでkey/IV配列の一意writeを検証する。

    未対応call、未知branch、同一indexへの競合write、状態loopを黙って推測せず、
    stable reason codeで拒否する。配列の生値は返さず、完全な場合だけSHA-256を返す。
    """

    if (
        len(required_lengths) != 2
        or any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in required_lengths)
        or not isinstance(max_states, int)
        or isinstance(max_states, bool)
        or max_states <= 0
    ):
        raise ValueError("配列長と状態予算は正の整数で指定してください")
    cfg_result = dict(cfg or build_bounded_cfg(method.instructions))
    if cfg_result.get("status") != "complete":
        return {
            "status": "rejected",
            "reason": cfg_result.get("reason") or "cfg_not_complete",
            "sink_count": 0,
            "arrays": [],
            "metadata_public_key_branch_fold_count": 0,
            "raw_array_values_published": False,
        }
    blocks = cfg_result.get("blocks")
    edges = cfg_result.get("edges")
    if not isinstance(blocks, list) or not blocks or not isinstance(edges, list):
        return {"status": "rejected", "reason": "cfg_model_invalid", "sink_count": 0, "arrays": [], "metadata_public_key_branch_fold_count": 0, "raw_array_values_published": False}
    by_offset = {item.offset: item for item in method.instructions}
    outgoing: dict[int, list[dict[str, Any]]] = {}
    for edge in edges:
        if isinstance(edge, dict) and isinstance(edge.get("source"), int):
            outgoing.setdefault(edge["source"], []).append(edge)
    proxy_values = {
        token: kind == "constant_true"
        for token, kind in (proxy_constants or {}).items()
        if kind in {"constant_true", "constant_false"}
    }
    custom_tokens = set(custom_sink_tokens)
    unknown = ("unknown",)
    stack: list[tuple[Any, ...]] = []
    locals_: dict[int, tuple[Any, ...]] = {}
    static_fields: dict[int, tuple[Any, ...]] = {}
    arrays: dict[int, dict[str, Any]] = {}
    sinks: list[dict[str, Any]] = []
    metadata_public_key_branch_fold_count = 0
    current = 0
    visited: set[tuple[Any, ...]] = set()

    def const(value: int) -> tuple[str, int]:
        return ("const", value & 0xFFFFFFFF)

    def concrete(value: tuple[Any, ...]) -> int | None:
        return value[1] if len(value) == 2 and value[0] == "const" and isinstance(value[1], int) else None

    def truthy(value: tuple[Any, ...]) -> bool | None:
        if len(value) >= 2 and value[0] == "bool" and isinstance(value[1], bool):
            return value[1]
        if value and value[0] == "null":
            return False
        if value and value[0] in {"nonnull", "array", "assembly", "assembly_name"}:
            return True
        number = concrete(value)
        return None if number is None else number != 0

    def semantic_equal(left: tuple[Any, ...], right: tuple[Any, ...]) -> bool | None:
        if left == unknown or right == unknown:
            return None
        if left and right and left[0] == right[0] == "null":
            return True
        if left and right and {left[0], right[0]} == {"null", "nonnull"}:
            return False
        return left == right

    def pop() -> tuple[Any, ...]:
        return stack.pop() if stack else unknown

    def array_report(identifier: int) -> dict[str, Any]:
        item = arrays[identifier]
        length = item["length"]
        writes = item["writes"]
        write_counts = item["write_counts"]
        conflict = any(
            len(values) != 1 or write_counts.get(index) != 1
            for index, values in writes.items()
        )
        complete = bool(
            isinstance(length, int)
            and set(writes) == set(range(length))
            and not conflict
        )
        digest = None
        if complete:
            digest = hashlib.sha256(
                bytes(next(iter(writes[index])) for index in range(length))
            ).hexdigest()
        return {
            "allocation_offset": identifier,
            "length": length,
            "written_index_count": len(writes),
            "conflicting_index_count": sum(
                len(values) != 1 or write_counts.get(index) != 1
                for index, values in writes.items()
            ),
            "duplicate_write_index_count": sum(
                write_counts.get(index, 0) > 1 for index in writes
            ),
            "complete_unique_write_set": complete,
            "sha256": digest,
            "raw_values_published": False,
        }

    for _ in range(max_states):
        signature = (
            current,
            tuple(sorted(locals_.items())),
            tuple(sorted(static_fields.items())),
            tuple(stack),
        )
        if signature in visited:
            return {
                "status": "rejected",
                "reason": "dispatcher_state_reaching_definition_loop",
                "sink_count": len(sinks),
                "arrays": [array_report(identifier) for identifier in sorted(arrays)],
                "metadata_public_key_branch_fold_count": metadata_public_key_branch_fold_count,
                "raw_array_values_published": False,
            }
        visited.add(signature)
        block = blocks[current]
        last_condition: tuple[Any, ...] | None = None
        for offset in block["instruction_offsets"]:
            item = by_offset[offset]
            opcode = item.opcode
            if opcode.startswith("ldc.i4") and item.integer is not None:
                stack.append(const(item.integer))
            elif opcode == "ldnull":
                stack.append(("null",))
            elif opcode.startswith("ldloc") and item.local is not None:
                stack.append(locals_.get(item.local, unknown))
            elif opcode.startswith("stloc") and item.local is not None:
                locals_[item.local] = pop()
            elif opcode == "ldsfld" and isinstance(item.token, int):
                stack.append(static_fields.get(item.token, unknown))
            elif opcode == "stsfld" and isinstance(item.token, int):
                static_fields[item.token] = pop()
            elif opcode.startswith("ldarg"):
                stack.append(unknown)
            elif opcode.startswith("starg"):
                pop()
            elif opcode == "dup":
                stack.append(stack[-1] if stack else unknown)
            elif opcode == "pop":
                pop()
            elif opcode in {"add", "sub", "xor", "and", "or", "mul"}:
                right = concrete(pop())
                left = concrete(pop())
                if left is None or right is None:
                    stack.append(unknown)
                else:
                    operation = {
                        "add": left + right,
                        "sub": left - right,
                        "xor": left ^ right,
                        "and": left & right,
                        "or": left | right,
                        "mul": left * right,
                    }[opcode]
                    stack.append(const(operation))
            elif opcode == "ceq":
                right = pop()
                left = pop()
                equal = semantic_equal(left, right)
                source = (
                    "metadata_public_key_null"
                    if any(len(value) >= 2 and value[-1] == "metadata_public_key" for value in (left, right))
                    else "value_comparison"
                )
                stack.append(("bool", equal, source) if isinstance(equal, bool) else unknown)
            elif opcode == "newarr" and item.resolved == "System.Byte":
                length = concrete(pop())
                identifier = item.offset
                arrays[identifier] = {"length": length, "writes": {}, "write_counts": {}}
                stack.append(("array", identifier))
            elif opcode == "stelem.i1":
                value = concrete(pop())
                index = concrete(pop())
                target = pop()
                if (
                    len(target) == 2
                    and target[0] == "array"
                    and target[1] in arrays
                    and isinstance(index, int)
                    and isinstance(value, int)
                ):
                    arrays[target[1]]["writes"].setdefault(index, set()).add(value & 0xFF)
                    arrays[target[1]]["write_counts"][index] = (
                        arrays[target[1]]["write_counts"].get(index, 0) + 1
                    )
            elif opcode in {"call", "callvirt", "newobj"}:
                if item.token in proxy_values:
                    stack.append(("bool", proxy_values[item.token]))
                elif "System.Reflection.Assembly::GetExecutingAssembly" in item.resolved:
                    stack.append(("assembly",))
                elif "System.Reflection.Assembly::GetName" in item.resolved:
                    pop()
                    stack.append(("assembly_name",))
                elif "System.Reflection.AssemblyName::GetPublicKey" in item.resolved:
                    pop()
                    if metadata_public_key_state == "absent":
                        stack.append(("null", "metadata_public_key"))
                    elif metadata_public_key_state == "present":
                        stack.append(("nonnull", "metadata_public_key"))
                    else:
                        stack.append(unknown)
                elif "SymmetricAlgorithm::CreateDecryptor" in item.resolved:
                    iv = pop()
                    key = pop()
                    pop()  # receiver
                    sinks.append({"offset": item.offset, "kind": "create_decryptor", "array_values": [key, iv]})
                    stack.append(unknown)
                elif item.token in custom_tokens:
                    arguments = [pop() for _ in range(4)]
                    sinks.append({"offset": item.offset, "kind": "custom_transform", "array_values": arguments})
                    stack.append(unknown)
                elif item.resolved.endswith("::.ctor") and opcode == "newobj":
                    stack.append(unknown)
                elif "SymmetricAlgorithm::set_Mode" in item.resolved:
                    pop()
                    pop()
                else:
                    stack.append(unknown)
            elif opcode in {"brtrue", "brtrue.s", "brfalse", "brfalse.s", "switch"}:
                last_condition = pop()
            elif opcode in {"beq", "beq.s", "bne.un", "bne.un.s"}:
                right = pop()
                left = pop()
                equal = semantic_equal(left, right)
                source = (
                    "metadata_public_key_null"
                    if any(len(value) >= 2 and value[-1] == "metadata_public_key" for value in (left, right))
                    else "value_comparison"
                )
                last_condition = ("bool", equal, source) if isinstance(equal, bool) else unknown
            elif opcode in {"ret", "throw", "rethrow"}:
                break
        candidates = outgoing.get(current, [])
        if not candidates:
            break
        selected: dict[str, Any] | None = None
        terminator = by_offset[block["end_offset"]].opcode
        if terminator == "switch":
            value = concrete(last_condition or unknown)
            if value is not None:
                selected = next((edge for edge in candidates if edge.get("kind") == "switch" and edge.get("switch_index") == value), None)
                selected = selected or next((edge for edge in candidates if edge.get("kind") == "switch_default"), None)
        elif terminator in {"brtrue", "brtrue.s", "brfalse", "brfalse.s"}:
            condition = truthy(last_condition or unknown)
            if isinstance(condition, bool):
                take = condition if terminator.startswith("brtrue") else not condition
                kind = "branch_true" if take else "fallthrough"
                selected = next((edge for edge in candidates if edge.get("kind") == kind), None)
                if (
                    (len(last_condition or ()) >= 3 and (last_condition or ())[2] == "metadata_public_key_null")
                    or (last_condition and last_condition[-1] == "metadata_public_key")
                ):
                    metadata_public_key_branch_fold_count += 1
        elif terminator in {"beq", "beq.s", "bne.un", "bne.un.s"}:
            condition = last_condition[1] if last_condition and last_condition[0] == "bool" else None
            if isinstance(condition, bool):
                take = condition if terminator.startswith("beq") else not condition
                kind = "branch_true" if take else "fallthrough"
                selected = next((edge for edge in candidates if edge.get("kind") == kind), None)
                if len(last_condition or ()) >= 3 and (last_condition or ())[2] == "metadata_public_key_null":
                    metadata_public_key_branch_fold_count += 1
        elif len(candidates) == 1:
            selected = candidates[0]
        if selected is None:
            return {
                "status": "rejected",
                "reason": "dispatcher_state_reaching_definition_ambiguous",
                "sink_count": len(sinks),
                "arrays": [array_report(identifier) for identifier in sorted(arrays)],
                "metadata_public_key_branch_fold_count": metadata_public_key_branch_fold_count,
                "raw_array_values_published": False,
            }
        current = selected["target"]
    else:
        return {
            "status": "rejected",
            "reason": "dispatcher_state_budget_exceeded",
            "sink_count": len(sinks),
            "arrays": [array_report(identifier) for identifier in sorted(arrays)],
            "metadata_public_key_branch_fold_count": metadata_public_key_branch_fold_count,
            "raw_array_values_published": False,
        }
    reports = [array_report(identifier) for identifier in sorted(arrays)]
    recovered_sinks = []
    for sink in sinks:
        identifiers = {
            value[1]
            for value in sink["array_values"]
            if len(value) == 2 and value[0] == "array" and value[1] in arrays
        }
        matched_arrays = [report for report in reports if report["allocation_offset"] in identifiers and report["length"] in required_lengths]
        if sorted(report["length"] for report in matched_arrays) == sorted(required_lengths) and all(report["complete_unique_write_set"] for report in matched_arrays):
            recovered_sinks.append({"offset": sink["offset"], "kind": sink["kind"], "arrays": matched_arrays})
    if len(recovered_sinks) != 1:
        return {
            "status": "rejected",
            "reason": "byte_array_sink_binding_missing" if not recovered_sinks else "byte_array_sink_binding_ambiguous",
            "sink_count": len(sinks),
            "recovered_sink_count": len(recovered_sinks),
            "arrays": reports,
            "metadata_public_key_branch_fold_count": metadata_public_key_branch_fold_count,
            "raw_array_values_published": False,
        }
    return {
        "status": "recovered",
        "reason": None,
        "sink_count": len(sinks),
        "recovered_sink_count": 1,
        "sink": recovered_sinks[0],
        "arrays": reports,
        "metadata_public_key_branch_fold_count": metadata_public_key_branch_fold_count,
        "raw_array_values_published": False,
    }


def _internal_calls(method: CilMethod) -> set[int]:
    return {
        item.token
        for item in method.instructions
        if item.opcode in {"call", "callvirt", "newobj"}
        and isinstance(item.token, int)
        and item.token >> 24 == 6
    }


def _call_markers(method: CilMethod) -> tuple[str, ...]:
    return tuple(
        item.resolved
        for item in method.instructions
        if item.opcode in {"call", "callvirt", "newobj"} and item.resolved
    )


def _reaches(
    start: int | None,
    target: int,
    graph: Mapping[int, set[int]],
    *,
    max_depth: int = 6,
    max_visits: int = 2_048,
) -> bool:
    if start is None:
        return False
    queue = deque([(start, 0)])
    visited: set[int] = set()
    while queue and len(visited) < max_visits:
        token, depth = queue.popleft()
        if token == target:
            return True
        if token in visited or depth >= max_depth:
            continue
        visited.add(token)
        queue.extend((child, depth + 1) for child in graph.get(token, ()))
    return False


def analyze_purerat_method_semantics(
    methods: Sequence[CilMethod],
    *,
    entry_token: int | None,
    metadata_public_key_state: str = "unavailable",
) -> dict[str, Any]:
    """PureRAT終端のsemantic roleを相関するが、family確定には使わない。"""

    graph = {method.token: _internal_calls(method) for method in methods}
    incoming: dict[int, set[int]] = {}
    for source, targets in graph.items():
        for target in targets:
            incoming.setdefault(target, set()).add(source)
    config_candidates: list[CilMethod] = []
    tls_candidates: list[CilMethod] = []
    certificate_compare: list[CilMethod] = []
    cache_candidates: list[dict[str, Any]] = []
    plugin_loaders: list[CilMethod] = []
    decryptor_candidates: list[CilMethod] = []
    for method in methods:
        calls = _call_markers(method)
        base64_count = sum("System.Convert::FromBase64String" in value for value in calls)
        x509_ctor = any("X509Certificate2::.ctor" in value for value in calls)
        handoff = False
        for index, item in enumerate(method.instructions):
            if "System.Convert::FromBase64String" not in item.resolved:
                continue
            tail = method.instructions[index + 1 : index + 6]
            has_internal = any(
                entry.opcode in {"call", "callvirt"}
                and isinstance(entry.token, int)
                and entry.token >> 24 == 6
                for entry in tail
            )
            has_cast = any(entry.opcode == "castclass" for entry in tail)
            has_store = any(entry.opcode == "stsfld" for entry in tail)
            handoff = handoff or (has_internal and has_cast and has_store)
        if base64_count >= 2 and x509_ctor and handoff:
            config_candidates.append(method)
        tls_markers = {
            "socket": any("System.Net.Sockets.Socket::" in value for value in calls),
            "network_stream": any("System.Net.Sockets.NetworkStream::.ctor" in value for value in calls),
            "ssl_stream": any("System.Net.Security.SslStream::.ctor" in value for value in calls),
            "authenticate": any("System.Net.Security.SslStream::AuthenticateAsClient" in value for value in calls),
        }
        if all(tls_markers.values()):
            tls_candidates.append(method)
        if any("X509Certificate" in value and "::Equals" in value for value in calls):
            certificate_compare.append(method)
        cache = verify_length_prefixed_utf16_cache_shape(method)
        if cache["status"] == "matched":
            cache_candidates.append(cache)
        if (
            any("System.Reflection.Assembly::Load" in value for value in calls)
            and any("System.Linq.Enumerable::Reverse" in value for value in calls)
            and any("GZip" in value for value in calls)
        ):
            plugin_loaders.append(method)
        if any("SymmetricAlgorithm::CreateDecryptor" in value for value in calls):
            decryptor_candidates.append(method)
    if entry_token is not None:
        candidate_roots = [entry_token]
        root_strategy = "pe_entrypoint"
    else:
        # ReflectiveにロードされるDLLはCLR headerにentry tokenを持たない。
        # その場合もrole単独一致へ降格せず、internal callerを持たないmethodから
        # configとTLSの両方へ到達する共通rootだけを代替根拠にする。
        candidate_roots = [
            method.token for method in methods if not incoming.get(method.token)
        ][:2_048]
        root_strategy = "unreferenced_internal_call_root"
    correlated_roots: list[tuple[int, list[CilMethod], list[CilMethod]]] = []
    for root in candidate_roots:
        root_config = [
            method for method in config_candidates if _reaches(root, method.token, graph)
        ]
        root_tls = [
            method for method in tls_candidates if _reaches(root, method.token, graph)
        ]
        if root_config and root_tls:
            correlated_roots.append((root, root_config, root_tls))
    reachable_config = {
        method.token: method
        for _, root_config, _ in correlated_roots
        for method in root_config
    }
    reachable_tls = {
        method.token: method
        for _, _, root_tls in correlated_roots
        for method in root_tls
    }
    matched = bool(correlated_roots)
    reason = (
        "purerat_terminal_semantic_profile_correlated"
        if matched
        else "config_initialization_semantics_missing"
        if not config_candidates
        else "tls_transport_semantics_missing"
        if not tls_candidates
        else "semantic_root_role_reachability_missing"
    )
    def role(method: CilMethod) -> dict[str, str]:
        return {
            "method_token": f"0x{method.token:08x}",
            "method_body_sha256": method.body_sha256,
        }
    proxy_constants = {
        method.token: kind
        for method in methods
        if (kind := classify_exact_constant_proxy(method)) is not None
    }
    decryptor_dataflow = []
    for method in decryptor_candidates[:16]:
        flow = analyze_byte_array_sink_reaching_definitions(
            method,
            proxy_constants=proxy_constants,
            metadata_public_key_state=metadata_public_key_state,
        )
        decryptor_dataflow.append(
            {
                **role(method),
                "status": flow.get("status"),
                "reason": flow.get("reason"),
                "sink_count": flow.get("sink_count", 0),
                "recovered_sink_count": flow.get("recovered_sink_count", 0),
                "metadata_public_key_branch_fold_count": flow.get(
                    "metadata_public_key_branch_fold_count", 0
                ),
                "arrays": flow.get("arrays", []),
                "raw_array_values_published": False,
            }
        )
    return {
        "schema_version": 1,
        "status": "matched" if matched else "not_matched",
        "reason": reason,
        "entry_token": f"0x{entry_token:08x}" if entry_token is not None else None,
        "semantic_root_strategy": root_strategy,
        "correlated_semantic_roots": [
            role(next(method for method in methods if method.token == root))
            for root, _, _ in correlated_roots
        ],
        "config_initializers": [role(method) for method in config_candidates],
        "semantic_root_reachable_config_initializers": [
            role(reachable_config[token]) for token in sorted(reachable_config)
        ],
        "entry_reachable_config_initializers": (
            [role(reachable_config[token]) for token in sorted(reachable_config)]
            if root_strategy == "pe_entrypoint"
            else []
        ),
        "tls_transport_methods": [role(method) for method in tls_candidates],
        "semantic_root_reachable_tls_transport_methods": [
            role(reachable_tls[token]) for token in sorted(reachable_tls)
        ],
        "entry_reachable_tls_transport_methods": (
            [role(reachable_tls[token]) for token in sorted(reachable_tls)]
            if root_strategy == "pe_entrypoint"
            else []
        ),
        "certificate_compare_methods": [role(method) for method in certificate_compare],
        "length_prefixed_utf16_cache_methods": cache_candidates,
        "registry_or_plugin_loader_methods": [role(method) for method in plugin_loaders],
        "decryptor_key_iv_reaching_definitions": decryptor_dataflow,
        "decryptor_candidate_set_complete": len(decryptor_candidates) <= 16,
        "exact_constant_proxies": [
            {
                **role(next(method for method in methods if method.token == token)),
                "kind": proxy_constants[token],
            }
            for token in sorted(proxy_constants)
        ],
        "family_corroboration_allowed": matched,
        "family_confirmation_allowed": False,
        "c2_confirmation_allowed": False,
        "provider_or_protector_label_used": False,
        "raw_strings_published": False,
        "sample_executed": False,
        "clr_loaded": False,
        "network_contacted": False,
    }


def parse_managed_program(
    data: bytes,
    *,
    max_input_bytes: int = MAX_PROGRAM_BYTES,
    max_elapsed_seconds: float = 15.0,
) -> CilProgram:
    """既存のbounded metadata resolverを使い、branch operand付きmodelを作る。"""

    if type(data) is not bytes:
        raise TypeError("dataにはexact bytesを指定してください")
    if len(data) > max_input_bytes:
        raise ValueError("managed_cil_input_size_exceeded")
    if max_elapsed_seconds <= 0:
        raise ValueError("max_elapsed_secondsは正数で指定してください")
    deadline = time.monotonic() + max_elapsed_seconds
    try:
        metadata_preflight = preflight_clr_declarations(
            data,
            max_input_bytes=max_input_bytes,
        )
    except Exception as exc:
        # guardの実装例外や依存不整合を入力由来の詳細へ展開しない。
        raise ValueError("managed_cil_constructor_preflight_failed") from exc
    if not metadata_preflight.get("accepted", False):
        raise ValueError("managed_cil_constructor_preflight_rejected")
    if time.monotonic() > deadline:
        raise ValueError("managed_cil_deadline_exceeded")
    try:
        import dnfile
        from dncil.cil.body.reader import read_method_body_from_bytes

        from . import managed_bitmap_argb_xor as model
    except ImportError as exc:  # pragma: no cover - dependency errorはcallerで診断する。
        raise ValueError("managed_cil_dependency_missing") from exc
    if time.monotonic() > deadline:
        raise ValueError("managed_cil_deadline_exceeded")
    try:
        pe = dnfile.dnPE(data=data, fast_load=False)
    except Exception as exc:
        # dnfile/pefileは不正PEに対して複数の例外型を返す。入力依存の
        # 例外名や本文を外へ出さず、callerが安定判定できるreasonへ正規化する。
        raise ValueError("managed_cil_parse_failed") from exc
    if not getattr(pe, "net", None) or not getattr(pe.net, "mdtables", None):
        raise ValueError("managed_cil_not_managed_pe")
    if time.monotonic() > deadline:
        raise ValueError("managed_cil_deadline_exceeded")
    normalized = model._normalize_methods(pe, data, deadline, time.monotonic)
    rows = list(getattr(getattr(pe.net.mdtables, "MethodDef", None), "rows", ()) or ())
    by_token = {item.token: item for item in normalized}
    methods: list[CilMethod] = []
    for index, row in enumerate(rows, 1):
        token = 0x06000000 | index
        item = by_token.get(token)
        if item is None:
            continue
        start, end = model._method_raw_window(pe, data, int(getattr(row, "Rva", 0) or 0))
        try:
            raw_body = read_method_body_from_bytes(data[start:end])
        except Exception as exc:
            raise ValueError("managed_cil_method_body_parse_failed") from exc
        raw_by_offset = {int(entry.offset): entry for entry in raw_body.instructions}
        cil = []
        for instruction in item.instructions:
            raw = raw_by_offset.get(instruction.offset)
            if raw is None:
                raise ValueError("managed_cil_instruction_view_mismatch")
            cil.append(
                instruction_from_raw(
                    raw,
                    token=instruction.token,
                    resolved=instruction.resolved,
                    integer=instruction.integer,
                    local=instruction.local,
                    user_string=instruction.user_string,
                )
            )
        methods.append(
            CilMethod(
                token=token,
                owner=item.owner,
                name=item.name,
                body_sha256=item.body_sha256,
                instructions=tuple(cil),
            )
        )
    try:
        raw_entry = int(getattr(pe.net.struct, "EntryPointTokenOrRva", 0) or 0)
    except (TypeError, ValueError):
        raw_entry = 0
    entry_token = raw_entry if raw_entry >> 24 == 6 and raw_entry in by_token else None
    return CilProgram(
        input_sha256=hashlib.sha256(data).hexdigest(),
        entry_token=entry_token,
        assembly_public_key_state=assembly_public_key_state(pe),
        methods=tuple(methods),
    )


def analyze_purerat_terminal_semantics(data: bytes) -> dict[str, Any]:
    """byte入力からPureRAT terminal semantic evidenceだけを安全に返す。"""

    try:
        program = parse_managed_program(data)
    except (TypeError, ValueError, OSError) as error:
        reason = str(error) if str(error).startswith("managed_cil_") else "managed_cil_parse_failed"
        return {
            "schema_version": 1,
            "status": "not_analyzed",
            "reason": reason,
            "family_corroboration_allowed": False,
            "family_confirmation_allowed": False,
            "c2_confirmation_allowed": False,
            "provider_or_protector_label_used": False,
            "raw_strings_published": False,
            "sample_executed": False,
            "clr_loaded": False,
            "network_contacted": False,
        }
    except Exception:  # noqa: BLE001 - untrusted parser例外を安定理由へ閉じる。
        # metadata parserのversion差で未知例外が返っても、untrusted入力の内容や
        # exception本文を公開せず、detector全体をfail-openさせない。
        return {
            "schema_version": 1,
            "status": "not_analyzed",
            "reason": "managed_cil_parse_failed",
            "family_corroboration_allowed": False,
            "family_confirmation_allowed": False,
            "c2_confirmation_allowed": False,
            "provider_or_protector_label_used": False,
            "raw_strings_published": False,
            "sample_executed": False,
            "clr_loaded": False,
            "network_contacted": False,
        }
    result = analyze_purerat_method_semantics(
        program.methods,
        entry_token=program.entry_token,
        metadata_public_key_state=program.assembly_public_key_state,
    )
    cache_methods = result.get("length_prefixed_utf16_cache_methods", [])
    if result.get("status") == "matched" and len(cache_methods) == 1:
        try:
            # managed_purerat_cache_frontend は本moduleの型/CFG modelを利用するため、
            # module初期化時の循環importを避けて候補確定後にだけ読み込む。
            from .managed_purerat_cache_frontend import (
                recover_managed_purerat_cache_frontend,
            )

            cache_report, _ = recover_managed_purerat_cache_frontend(data)
        except Exception:  # noqa: BLE001 - 補助front-end例外を安定理由へ閉じる。
            cache_report = {
                "schema_version": 1,
                "status": "rejected",
                "reason": "managed_utf16_cache_frontend_failed",
            }
        cache_details = cache_report.get("cache", {})
        decoder_details = cache_report.get("decoder", {})
        transform_details = cache_report.get("transform", {})
        result["managed_utf16_cache_recovery"] = {
            "schema_version": cache_report.get("schema_version", 1),
            "status": cache_report.get("status", "rejected"),
            "reason": cache_report.get(
                "reason", "managed_utf16_cache_frontend_failed"
            ),
            "recipe": cache_report.get("recipe"),
            "complete_table_consumed": cache_details.get(
                "complete_table_consumed"
            )
            is True,
            "complete_table_entry_count": cache_details.get(
                "complete_table_entry_count", 0
            ),
            "ordered_overwrite_semantics_verified": decoder_details.get(
                "ordered_overwrite_semantics_verified"
            )
            is True,
            "reverse_mask_verified": decoder_details.get(
                "reverse_mask_verified"
            )
            is True,
            "exact_16_iteration_key_xor_verified": decoder_details.get(
                "exact_16_iteration_key_xor_verified"
            )
            is True,
            "partial_word_profile_verified": transform_details.get(
                "partial_word_profile_verified"
            )
            is True,
            "secondary_string_transform_recovered": False,
            "strict_terminal_schema_confirmed": False,
            "family_confirmation_allowed": False,
            "c2_confirmation_allowed": False,
            "raw_key_material_published": False,
            "raw_strings_published": False,
            "sample_executed": False,
            "clr_loaded": False,
            "network_contacted": False,
        }
    elif result.get("status") == "matched":
        result["managed_utf16_cache_recovery"] = {
            "schema_version": 1,
            "status": "not_attempted",
            "reason": "cache_method_missing_or_ambiguous",
            "secondary_string_transform_recovered": False,
            "strict_terminal_schema_confirmed": False,
            "family_confirmation_allowed": False,
            "c2_confirmation_allowed": False,
            "raw_key_material_published": False,
            "raw_strings_published": False,
            "sample_executed": False,
            "clr_loaded": False,
            "network_contacted": False,
        }
    result.update(
        {
            "input_sha256": program.input_sha256,
            "assembly_public_key_state": program.assembly_public_key_state,
            "method_count": len(program.methods),
        }
    )
    return result


def summarize_cfg(cfg: Mapping[str, Any]) -> dict[str, Any]:
    """大きいblock一覧をreportへ展開せず、安定診断だけを返す。"""

    return {
        "status": cfg.get("status"),
        "reason": cfg.get("reason"),
        "instruction_count": cfg.get("instruction_count", 0),
        "branch_target_count": cfg.get("branch_target_count", 0),
        "unique_branch_target_count": cfg.get("unique_branch_target_count", 0),
        "block_count": cfg.get("block_count", 0),
        "edge_count": cfg.get("edge_count", 0),
        "branch_operands_preserved": cfg.get("branch_operands_preserved") is True,
    }
