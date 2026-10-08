"""確認済みWin32.RMP managed loaderの19引数設定を静的復元する。

検体全体のhashではなく、5個のMethodDef body hashとembedded resource hashが
一致するprofileだけを処理する。CLRやCILは実行せず、profileで確認済みの
resource変換とAES-CBC引数復号だけを再現する。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import dnfile
from Cryptodome.Cipher import AES
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.error import MethodBodyFormatError
from pefile import PEFormatError

MAX_ASSEMBLY_SIZE = 16 * 1024 * 1024
MAX_RESOURCE_SIZE = 1 * 1024 * 1024
MAX_ARGUMENT_CLEAR_SIZE = 4096
MAX_FLATTENED_STATES = 512
MAX_FLATTENED_STEPS = 512
MAX_STATIC_KEY_ARRAY_SIZE = 64
PROFILE_NAME = "win32_rmp_19_argument_loader_v1"

_METHOD_HASHES = {
    0x0600005C: "8be8833f7fd2629e49f5f627e07ce5be852c5cabe377fc4c8d3f04a1766b4019",
    0x060000A9: "361a260f38de5dba4c223c3ad928e1df436483fb3828e554f80ef3c577428b4a",
    0x0600011F: "1a086afe5f72df8eb57a241db6cb82b7a29370652e394421748d183ae2ecf40b",
    0x06000185: "8b9d4c28f0046580824ecaaeab316a82e0aa52bab26f9e3405bcf009a6267c84",
    0x06000188: "3d59a18deff5b44417bc5f9dcea794ba28901c6941f0001d315e05e75d42fa20",
}
_RESOURCE_SHA256 = "03451ba82dd664ed403b320b9f802121fb7c2a70daad5c594cacff8d1bb94e9c"
_RESOURCE_SIZE = 2816
_PASSWORD_OFFSET = 1860
_PASSWORD_SHA256 = "04eb1ae54b779cb8582b0ccd773d88c13316745817ead873ec1c22457516ecb3"
_NONEMPTY_ARGUMENTS = frozenset({0, 2, 3, 4, 6, 8, 9, 10, 11, 12, 14, 15})


class RecoveryError(ValueError):
    """profile不一致、曖昧性、上限超過を安全側へ拒否する。"""


@dataclass(frozen=True)
class _KeyRecipe:
    """難読化CILから一意に確認したresource key構築経路。"""

    key_local: int
    vector_local: int
    source_local: int
    key_initializer_local: int
    vector_initializer_local: int
    token_local: int
    key_allocation_offset: int
    vector_reverse_offset: int
    transform_call_offset: int


@dataclass
class _StaticArrayState:
    """CLRを実行せず、定数配列初期化だけを追跡する状態。"""

    locals: list[object]
    writes: dict[int, set[int]]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _base_report(size: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "not_candidate",
        "profile": PROFILE_NAME,
        "input_size": size,
        "sample_executed": False,
        "clr_loaded": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_key_material_published": False,
        "supports_family_attribution": False,
        "supports_c2_confirmation": False,
        "terminal_payload_confirmed": False,
    }


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _resource_transform(source: bytes, secret: bytes) -> bytes:
    """確認済みMethodDef 0x0600011fのword単位XOR streamを再現する。"""
    if not source or len(source) > MAX_RESOURCE_SIZE or len(secret) != 32:
        raise RecoveryError("resource_transform_bounds")
    remainder = len(source) % 4
    words = len(source) // 4 + bool(remainder)
    output = bytearray(len(source))
    key_words = len(secret) // 4
    accumulator = 0
    for index in range(words):
        key_offset = (index % key_words) * 4
        key_word = int.from_bytes(secret[key_offset : key_offset + 4], "little")
        accumulator = _u32(accumulator + key_word)
        offset = index * 4
        if index == words - 1 and remainder:
            data_word = 0
            for tail_index in range(remainder):
                data_word = _u32(data_word << 8)
                data_word |= source[len(source) - 1 - tail_index]
        else:
            data_word = int.from_bytes(source[offset : offset + 4], "little")
        old = accumulator
        value_11 = 527590211
        value_12 = 145230210
        value_13 = 0x0A3919D0
        value_14 = old
        value_15 = 657434341
        value_14 = _u32(3671 * (value_14 & 0xFFFFF) - (value_14 >> 20))
        value_13 = _u32(2930 * (value_13 & 0xFFFFF) + (value_13 >> 20))
        value_11 = _u32(28218 * value_11 - value_12)
        if value_12 == 0:
            value_12 = _u32(value_12 - 1)
        value_16 = _u32((value_11 // value_12) + value_12)
        value_12 = _u32(((value_11 + value_14) ^ value_16) + value_11)
        if value_11 == 0:
            value_11 = _u32(value_11 - 1)
        value_16 = _u32((value_13 // value_11) + value_11)
        value_11 = _u32(value_13 + value_13 + value_16 + value_13)
        value_12 = _u32(2991 * (value_12 & 0xFFFFF) + (value_12 >> 20))
        value_11 = _u32(2279 * (value_11 & 0xFFFFF) - (value_11 >> 20))
        value_13 = _u32(54990 * value_13 + value_14)
        if value_15 == 0:
            value_15 = _u32(value_15 - 1)
        value_16 = _u32((value_13 // value_15) + value_15)
        value_15 = _u32(value_13 - value_13 + value_16 + value_13)
        value_14 = _u32(value_14 ^ _u32(value_14 << 12))
        value_14 = _u32(value_14 + value_11)
        value_14 = _u32(value_14 ^ (value_14 >> 9))
        value_14 = _u32(value_14 + value_14)
        value_14 = _u32(value_14 ^ _u32(value_14 << 23))
        value_14 = _u32(value_14 + value_15)
        value_14 = _u32(((_u32(value_11 << 4) + value_14) ^ value_11) + value_14)
        accumulator = _u32(old + value_14)
        result = accumulator ^ data_word
        if index == words - 1 and remainder:
            for tail_index in range(remainder):
                output[offset + tail_index] = (result >> (tail_index * 8)) & 0xFF
        else:
            output[offset : offset + 4] = result.to_bytes(4, "little")
    return bytes(output)


def _operand_value(instruction: object) -> object:
    operand = getattr(instruction, "operand", None)
    return getattr(operand, "value", operand)


def _integer(instruction: object) -> int | None:
    name = str(getattr(getattr(instruction, "opcode", None), "name", ""))
    if name == "ldc.i4.m1":
        return -1
    if name.startswith("ldc.i4."):
        suffix = name.rsplit(".", 1)[-1]
        if suffix.isdigit():
            return int(suffix)
    if name in {"ldc.i4", "ldc.i4.s"}:
        value = _operand_value(instruction)
        return value if isinstance(value, int) else None
    return None


def _local_index(instruction: object, prefix: str) -> int | None:
    name = str(getattr(getattr(instruction, "opcode", None), "name", ""))
    match = re.fullmatch(rf"{re.escape(prefix)}\.([0-3])", name)
    if match:
        return int(match.group(1))
    if name not in {prefix, f"{prefix}.s"}:
        return None
    index = getattr(getattr(instruction, "operand", None), "index", None)
    return index if isinstance(index, int) and 0 <= index < 64 else None


def _method_instructions(data: bytes, pe: object, token: int) -> list[object]:
    rows = list(pe.net.mdtables.MethodDef.rows)
    index = token & 0xFFFFFF
    if token >> 24 != 6 or not 1 <= index <= len(rows):
        raise RecoveryError("key_recipe_method_missing")
    rva = int(getattr(rows[index - 1], "Rva", 0) or 0)
    if rva <= 0:
        raise RecoveryError("key_recipe_method_missing")
    offset = int(pe.get_offset_from_rva(rva))
    if not 0 <= offset < len(data):
        raise RecoveryError("key_recipe_method_bounds")
    try:
        body = read_method_body_from_bytes(data[offset:])
    except (MethodBodyFormatError, TypeError, ValueError) as exc:
        raise RecoveryError("key_recipe_method_invalid") from exc
    if not 1 <= len(body.instructions) <= 16_384:
        raise RecoveryError("key_recipe_instruction_limit")
    return list(body.instructions)


def _metadata_type_name(pe: object, token: int) -> tuple[str, str] | None:
    if token >> 24 != 1:
        return None
    rows = list(pe.net.mdtables.TypeRef.rows)
    index = token & 0xFFFFFF
    if not 1 <= index <= len(rows):
        return None
    row = rows[index - 1]
    return str(row.TypeNamespace), str(row.TypeName)


def _member_name(pe: object, token: int) -> tuple[str, str, str] | None:
    if token >> 24 != 0x0A:
        return None
    rows = list(pe.net.mdtables.MemberRef.rows)
    index = token & 0xFFFFFF
    if not 1 <= index <= len(rows):
        return None
    row = rows[index - 1]
    owner = getattr(getattr(row, "Class", None), "row", None)
    if owner is None:
        return None
    return (
        str(getattr(owner, "TypeNamespace", "")),
        str(getattr(owner, "TypeName", "")),
        str(row.Name),
    )


def _wrapper_calls_member(
    data: bytes,
    pe: object,
    token: int,
    expected: tuple[str, str, str],
) -> bool:
    try:
        instructions = _method_instructions(data, pe, token)
    except RecoveryError:
        return False
    meaningful = [
        item
        for item in instructions
        if str(getattr(getattr(item, "opcode", None), "name", "")) != "nop"
    ]
    if [item.opcode.name for item in meaningful] != ["ldarg", "call", "ret"] and [
        item.opcode.name for item in meaningful
    ] != ["ldarg", "callvirt", "ret"]:
        return False
    called = _operand_value(meaningful[1])
    return isinstance(called, int) and _member_name(pe, called) == expected


def _unique_alias(
    instructions: list[object], target_local: int, before: int
) -> int | None:
    candidates: set[int] = set()
    for index in range(1, before):
        source = _local_index(instructions[index - 1], "ldloc")
        target = _local_index(instructions[index], "stloc")
        if source is not None and target == target_local:
            candidates.add(source)
    return next(iter(candidates)) if len(candidates) == 1 else None


def _allocation(
    pe: object,
    instructions: list[object],
    target_local: int,
    before: int,
) -> tuple[int, int] | None:
    candidates: set[tuple[int, int]] = set()
    for index in range(2, before):
        if _local_index(instructions[index], "stloc") != target_local:
            continue
        if instructions[index - 1].opcode.name != "newarr":
            continue
        element_token = _operand_value(instructions[index - 1])
        if not isinstance(element_token, int) or _metadata_type_name(
            pe, element_token
        ) != ("System", "Byte"):
            continue
        size = _integer(instructions[index - 2])
        if size is not None:
            candidates.add((size, int(instructions[index - 2].offset)))
    return next(iter(candidates)) if len(candidates) == 1 else None


def _discover_key_recipe(data: bytes, pe: object) -> _KeyRecipe:
    instructions = _method_instructions(data, pe, 0x0600011F)
    candidates: list[_KeyRecipe] = []
    for call_index in range(4, len(instructions)):
        if instructions[call_index].opcode.name != "call":
            continue
        key_local = _local_index(instructions[call_index - 3], "ldloc")
        vector_local = _local_index(instructions[call_index - 2], "ldloc")
        source_local = _local_index(instructions[call_index - 1], "ldloc")
        if (
            key_local is None
            or vector_local is None
            or source_local is None
            or instructions[call_index - 4].opcode.name != "newobj"
        ):
            continue
        key_initializer = _unique_alias(instructions, key_local, len(instructions))
        vector_initializer = _unique_alias(
            instructions, vector_local, len(instructions)
        )
        if key_initializer is None or vector_initializer is None:
            continue
        key_allocation = _allocation(
            pe, instructions, key_initializer, len(instructions)
        )
        vector_allocation = _allocation(
            pe, instructions, vector_initializer, len(instructions)
        )
        if (
            key_allocation is None
            or vector_allocation is None
            or key_allocation[0] != 32
            or vector_allocation[0] != 16
        ):
            continue

        reverse_offsets: list[int] = []
        for index in range(1, len(instructions)):
            if _local_index(instructions[index - 1], "ldloc") != vector_local:
                continue
            if instructions[index].opcode.name != "call":
                continue
            token = _operand_value(instructions[index])
            if isinstance(token, int) and _wrapper_calls_member(
                data, pe, token, ("System", "Array", "Reverse")
            ):
                reverse_offsets.append(int(instructions[index].offset))
        if len(reverse_offsets) != 1:
            continue

        token_local_candidates: set[int] = set()
        for index in range(3, len(instructions)):
            if instructions[index - 2].opcode.name not in {"call", "callvirt"}:
                continue
            if instructions[index - 1].opcode.name not in {"call", "callvirt"}:
                continue
            token_local = _local_index(instructions[index], "stloc")
            first = _operand_value(instructions[index - 2])
            second = _operand_value(instructions[index - 1])
            if (
                token_local is not None
                and isinstance(first, int)
                and isinstance(second, int)
                and _wrapper_calls_member(
                    data,
                    pe,
                    first,
                    ("System.Reflection", "Assembly", "GetName"),
                )
                and _wrapper_calls_member(
                    data,
                    pe,
                    second,
                    ("System.Reflection", "AssemblyName", "GetPublicKeyToken"),
                )
            ):
                token_local_candidates.add(token_local)
        if len(token_local_candidates) != 1:
            continue
        token_local = next(iter(token_local_candidates))

        injections: set[tuple[int, int]] = set()
        for index in range(5, len(instructions)):
            window = instructions[index - 5 : index + 1]
            if [item.opcode.name for item in window][-2:] != [
                "ldelem.u1",
                "stelem.i1",
            ]:
                continue
            if _local_index(window[0], "ldloc") != vector_local:
                continue
            if _local_index(window[2], "ldloc") != token_local:
                continue
            destination = _integer(window[1])
            source = _integer(window[3])
            if destination is not None and source is not None:
                injections.add((source, destination))
        if injections != {(index, index * 2 + 1) for index in range(8)}:
            continue

        xor_pattern_found = False
        for index in range(10, len(instructions)):
            window = instructions[index - 10 : index + 1]
            if [item.opcode.name for item in window[4:5] + window[7:]] != [
                "ldelem.u1",
                "ldelem.u1",
                "xor",
                "conv.u1",
                "stelem.i1",
            ]:
                continue
            local_values = [
                _local_index(window[position], "ldloc")
                for position in (0, 1, 2, 3, 5, 6)
            ]
            if (
                local_values[0] == key_local
                and local_values[2] == key_local
                and local_values[4] == vector_local
                and local_values[1] == local_values[3] == local_values[5]
            ):
                xor_pattern_found = True
                break
        if not xor_pattern_found:
            continue
        candidates.append(
            _KeyRecipe(
                key_local=key_local,
                vector_local=vector_local,
                source_local=source_local,
                key_initializer_local=key_initializer,
                vector_initializer_local=vector_initializer,
                token_local=token_local,
                key_allocation_offset=key_allocation[1],
                vector_reverse_offset=reverse_offsets[0],
                transform_call_offset=int(instructions[call_index].offset),
            )
        )
    if len(candidates) != 1:
        raise RecoveryError("resource_key_recipe_ambiguous")
    return candidates[0]


def _constant_helper_truth(data: bytes, pe: object, token: int) -> bool | None:
    try:
        instructions = _method_instructions(data, pe, token)
    except RecoveryError:
        return None
    opcodes = [item.opcode.name for item in instructions if item.opcode.name != "nop"]
    if opcodes == ["ldnull", "ret"]:
        return False
    if opcodes == ["ldnull", "ldnull", "ceq", "ret"]:
        return True
    return None


def _flattened_state_blocks(
    data: bytes, pe: object, instructions: list[object]
) -> tuple[dict[int, list[object]], set[int]]:
    switches = [item for item in instructions if item.opcode.name == "switch"]
    if len(switches) != 1:
        raise RecoveryError("resource_key_dispatcher_ambiguous")
    switch = switches[0]
    raw_targets = _operand_value(switch)
    if (
        not isinstance(raw_targets, list)
        or not 2 <= len(raw_targets) <= MAX_FLATTENED_STATES
    ):
        raise RecoveryError("resource_key_dispatcher_bounds")
    if any(not isinstance(value, int) for value in raw_targets):
        raise RecoveryError("resource_key_dispatcher_invalid")
    target_map = {state: offset for state, offset in enumerate(raw_targets)}
    switch_index = instructions.index(switch)
    if switch_index < 2:
        raise RecoveryError("resource_key_dispatcher_invalid")
    dispatcher_targets = {
        int(switch.offset),
        int(instructions[switch_index - 2].offset),
    }
    for index in range(switch_index + 1, min(switch_index + 16, len(instructions))):
        if instructions[index].opcode.name != "beq" or index < 2:
            continue
        state = _integer(instructions[index - 1])
        target = _operand_value(instructions[index])
        if (
            state is not None
            and len(raw_targets) <= state < MAX_FLATTENED_STATES
            and isinstance(target, int)
            and target not in dispatcher_targets
        ):
            target_map[state] = target
    if len(target_map) > MAX_FLATTENED_STATES:
        raise RecoveryError("resource_key_dispatcher_bounds")
    if len(set(target_map.values())) != len(target_map):
        raise RecoveryError("resource_key_dispatcher_ambiguous")
    by_offset = {int(item.offset): index for index, item in enumerate(instructions)}
    if any(offset not in by_offset for offset in target_map.values()):
        raise RecoveryError("resource_key_dispatcher_target_invalid")
    ordered_offsets = sorted(target_map.values())
    blocks: dict[int, list[object]] = {}
    for state, offset in target_map.items():
        begin = by_offset[offset]
        end_offset = next(
            (candidate for candidate in ordered_offsets if candidate > offset),
            1 << 30,
        )
        blocks[state] = [
            item for item in instructions[begin:] if int(item.offset) < end_offset
        ]
    return blocks, dispatcher_targets


def _state_for_offset(blocks: dict[int, list[object]], offset: int) -> int:
    candidates = [
        state
        for state, block in blocks.items()
        if block and int(block[0].offset) <= offset <= int(block[-1].offset)
    ]
    if len(candidates) != 1:
        raise RecoveryError("resource_key_state_mapping_ambiguous")
    return candidates[0]


def _state_transition(
    data: bytes,
    pe: object,
    block: list[object],
    dispatcher_targets: set[int],
) -> tuple[int, int]:
    for index, item in enumerate(block):
        target = _operand_value(item)
        if item.opcode.name in {"brtrue", "brfalse"} and target in dispatcher_targets:
            if index < 2 or block[index - 1].opcode.name != "call":
                continue
            helper_token = _operand_value(block[index - 1])
            candidate = _integer(block[index - 2])
            if not isinstance(helper_token, int) or candidate is None:
                continue
            truth = _constant_helper_truth(data, pe, helper_token)
            if truth is None:
                continue
            taken = (item.opcode.name == "brtrue") == truth
            if taken:
                return candidate, index - 2
        if item.opcode.name == "br" and target in dispatcher_targets and index:
            candidate = _integer(block[index - 1])
            if candidate is not None:
                return candidate, index - 1
    raise RecoveryError("resource_key_state_transition_unresolved")


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _evaluate_array_action(
    data: bytes,
    pe: object,
    action: list[object],
    state: _StaticArrayState,
    dispatcher_targets: set[int],
) -> None:
    stack: list[object] = []
    for item in action:
        name = item.opcode.name
        number = _integer(item)
        if number is not None:
            stack.append(_i32(number))
        elif name.startswith("ldloc"):
            index = _local_index(item, "ldloc")
            if index is None:
                raise RecoveryError("resource_key_local_invalid")
            stack.append(state.locals[index])
        elif name.startswith("stloc"):
            index = _local_index(item, "stloc")
            if index is None or not stack:
                raise RecoveryError("resource_key_local_invalid")
            state.locals[index] = stack.pop()
        elif name == "ldnull":
            stack.append(None)
        elif name == "newarr":
            element_token = _operand_value(item)
            if (
                not stack
                or not isinstance(element_token, int)
                or _metadata_type_name(pe, element_token) != ("System", "Byte")
            ):
                raise RecoveryError("resource_key_array_type_invalid")
            size = stack.pop()
            if not isinstance(size, int) or not 1 <= size <= MAX_STATIC_KEY_ARRAY_SIZE:
                raise RecoveryError("resource_key_array_bounds")
            value = bytearray(size)
            state.writes[id(value)] = set()
            stack.append(value)
        elif name == "stelem.i1":
            if len(stack) < 3:
                raise RecoveryError("resource_key_stack_invalid")
            value = stack.pop()
            index = stack.pop()
            array = stack.pop()
            if (
                not isinstance(array, bytearray)
                or not isinstance(index, int)
                or not isinstance(value, int)
                or not 0 <= index < len(array)
            ):
                raise RecoveryError("resource_key_array_write_invalid")
            writes = state.writes.get(id(array))
            if writes is None:
                raise RecoveryError("resource_key_array_write_invalid")
            array[index] = value & 0xFF
            writes.add(index)
        elif name == "ldelem.u1":
            if len(stack) < 2:
                raise RecoveryError("resource_key_stack_invalid")
            index = stack.pop()
            array = stack.pop()
            if (
                not isinstance(array, bytearray)
                or not isinstance(index, int)
                or not 0 <= index < len(array)
            ):
                raise RecoveryError("resource_key_array_read_invalid")
            stack.append(array[index])
        elif name in {"add", "sub", "xor", "and", "or", "mul"}:
            if len(stack) < 2:
                raise RecoveryError("resource_key_stack_invalid")
            right = stack.pop()
            left = stack.pop()
            if not isinstance(left, int) or not isinstance(right, int):
                raise RecoveryError("resource_key_integer_invalid")
            result = {
                "add": left + right,
                "sub": left - right,
                "xor": left ^ right,
                "and": left & right,
                "or": left | right,
                "mul": left * right,
            }[name]
            stack.append(_i32(result))
        elif name == "conv.u1":
            if not stack or not isinstance(stack[-1], int):
                raise RecoveryError("resource_key_integer_invalid")
            stack[-1] &= 0xFF
        elif name == "conv.i4":
            if not stack or not isinstance(stack[-1], int):
                raise RecoveryError("resource_key_integer_invalid")
            stack[-1] = _i32(stack[-1])
        elif name == "dup":
            if not stack:
                raise RecoveryError("resource_key_stack_invalid")
            stack.append(stack[-1])
        elif name == "pop":
            if not stack:
                raise RecoveryError("resource_key_stack_invalid")
            stack.pop()
        elif name == "call":
            token = _operand_value(item)
            truth = (
                _constant_helper_truth(data, pe, token)
                if isinstance(token, int)
                else None
            )
            if truth is None:
                raise RecoveryError("resource_key_call_not_whitelisted")
            stack.append(1 if truth else None)
        elif name in {"brtrue", "brfalse"}:
            if not stack or _operand_value(item) not in dispatcher_targets:
                raise RecoveryError("resource_key_branch_invalid")
            condition = stack.pop()
            truth = condition is not None and condition != 0
            if (name == "brtrue" and truth) or (name == "brfalse" and not truth):
                raise RecoveryError("resource_key_transition_mismatch")
        elif name == "nop":
            continue
        else:
            raise RecoveryError("resource_key_opcode_not_whitelisted")


def _recover_static_initializers(
    data: bytes, pe: object, recipe: _KeyRecipe
) -> tuple[bytes, bytes, int]:
    instructions = _method_instructions(data, pe, 0x0600011F)
    blocks, dispatcher_targets = _flattened_state_blocks(data, pe, instructions)
    state_number = _state_for_offset(blocks, recipe.key_allocation_offset)
    stop_state = _state_for_offset(blocks, recipe.vector_reverse_offset)
    state = _StaticArrayState(locals=[None] * 64, writes={})
    visited: set[int] = set()
    for _step in range(MAX_FLATTENED_STEPS):
        if state_number == stop_state:
            break
        if state_number in visited or state_number not in blocks:
            raise RecoveryError("resource_key_state_path_ambiguous")
        visited.add(state_number)
        next_state, action_end = _state_transition(
            data, pe, blocks[state_number], dispatcher_targets
        )
        _evaluate_array_action(
            data,
            pe,
            blocks[state_number][:action_end],
            state,
            dispatcher_targets,
        )
        state_number = next_state
    else:
        raise RecoveryError("resource_key_state_step_limit")
    key = state.locals[recipe.key_initializer_local]
    vector = state.locals[recipe.vector_initializer_local]
    if not isinstance(key, bytearray) or len(key) != 32:
        raise RecoveryError("resource_key_initializer_missing")
    if not isinstance(vector, bytearray) or len(vector) != 16:
        raise RecoveryError("resource_vector_initializer_missing")
    if state.writes.get(id(key)) != set(range(32)):
        raise RecoveryError("resource_key_initializer_incomplete")
    if state.writes.get(id(vector)) != set(range(16)):
        raise RecoveryError("resource_vector_initializer_incomplete")
    return bytes(key), bytes(vector), len(visited)


def _assembly_public_key_token(pe: object) -> bytes:
    rows = list(pe.net.mdtables.Assembly.rows)
    if len(rows) != 1:
        raise RecoveryError("assembly_identity_ambiguous")
    try:
        public_key = bytes(rows[0].PublicKey.value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise RecoveryError("assembly_public_key_invalid") from exc
    if not public_key:
        return b""
    if not 16 <= len(public_key) <= 16 * 1024:
        raise RecoveryError("assembly_public_key_bounds")
    digest = hashlib.sha1(public_key).digest()
    return digest[-8:][::-1]


def _combine_resource_transform_key(
    initial_key: bytes, initial_vector: bytes, public_key_token: bytes
) -> tuple[bytes, bytes]:
    if len(initial_key) != 32 or len(initial_vector) != 16:
        raise RecoveryError("resource_key_initializer_bounds")
    if len(public_key_token) not in {0, 8}:
        raise RecoveryError("assembly_public_key_token_bounds")
    vector = bytearray(reversed(initial_vector))
    for index, value in enumerate(public_key_token):
        vector[index * 2 + 1] = value
    key = bytearray(initial_key)
    for index, value in enumerate(vector):
        key[index] ^= value
    return bytes(key), bytes(vector)


def _derive_resource_transform_key(
    data: bytes, pe: object
) -> tuple[bytes, dict[str, object]]:
    recipe = _discover_key_recipe(data, pe)
    initial_key, initial_vector, state_count = _recover_static_initializers(
        data, pe, recipe
    )
    token = _assembly_public_key_token(pe)
    derived, vector = _combine_resource_transform_key(
        initial_key, initial_vector, token
    )
    return derived, {
        "recipe": "flattened_cil_arrays_reverse_public_key_token_xor_v1",
        "method_token": "0x0600011f",
        "key_length": len(derived),
        "key_sha256": _sha256(derived),
        "vector_length": len(vector),
        "vector_sha256": _sha256(vector),
        "public_key_token_length": len(token),
        "public_key_token_sha256": _sha256(token),
        "visited_state_count": state_count,
        "transform_call_offset": recipe.transform_call_offset,
        "raw_key_material_published": False,
    }


def _method_body_hash(data: bytes, pe: object, token: int) -> str:
    rows = list(pe.net.mdtables.MethodDef.rows)
    index = token & 0xFFFFFF
    if token >> 24 != 6 or not 1 <= index <= len(rows):
        raise RecoveryError("profile_method_token_missing")
    row = rows[index - 1]
    rva = int(getattr(row, "Rva", 0) or 0)
    if rva <= 0:
        raise RecoveryError("profile_method_body_missing")
    offset = int(pe.get_offset_from_rva(rva))
    if not 0 <= offset < len(data):
        raise RecoveryError("profile_method_body_bounds")
    body = read_method_body_from_bytes(data[offset:])
    size = int(body.size)
    if not 1 <= size <= 256 * 1024 or offset + size > len(data):
        raise RecoveryError("profile_method_body_bounds")
    return _sha256(data[offset : offset + size])


def _profile_password(data: bytes) -> tuple[bytes, dict[str, object]]:
    if not 1 <= len(data) <= MAX_ASSEMBLY_SIZE:
        raise RecoveryError("assembly_size_blocked")
    try:
        pe = dnfile.dnPE(data=data, clr_lazy_load=True)
        if getattr(pe, "net", None) is None:
            raise RecoveryError("managed_metadata_missing")
        observed = {
            token: _method_body_hash(data, pe, token) for token in _METHOD_HASHES
        }
        if observed != _METHOD_HASHES:
            raise RecoveryError("method_core_profile_mismatch")
        resource_key, key_evidence = _derive_resource_transform_key(data, pe)
        resources = [
            bytes(item.data)
            for item in pe.net.resources
            if isinstance(item.data, bytes)
        ]
    except RecoveryError:
        raise
    except (
        AttributeError,
        IndexError,
        MethodBodyFormatError,
        PEFormatError,
        TypeError,
        ValueError,
    ) as exc:
        raise RecoveryError("managed_metadata_invalid") from exc
    if len(resources) != 1:
        raise RecoveryError("embedded_resource_ambiguous")
    resource = resources[0]
    if len(resource) != _RESOURCE_SIZE or _sha256(resource) != _RESOURCE_SHA256:
        raise RecoveryError("resource_profile_mismatch")
    clear = _resource_transform(resource, resource_key)
    if _PASSWORD_OFFSET + 4 > len(clear):
        raise RecoveryError("password_offset_bounds")
    size = int.from_bytes(
        clear[_PASSWORD_OFFSET : _PASSWORD_OFFSET + 4], "little", signed=True
    )
    begin = _PASSWORD_OFFSET + 4
    end = begin + size
    if not 2 <= size <= 128 or size % 2 or end > len(clear):
        raise RecoveryError("password_string_bounds")
    try:
        password = clear[begin:end].decode("utf-16le").encode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError) as exc:
        raise RecoveryError("password_string_encoding") from exc
    if not 1 <= len(password) <= 32 or _sha256(password) != _PASSWORD_SHA256:
        raise RecoveryError("password_profile_mismatch")
    return password, {
        "method_body_sha256": {
            f"0x{token:08x}": digest for token, digest in sorted(observed.items())
        },
        "resource_sha256": _RESOURCE_SHA256,
        "resource_size": len(resource),
        "resource_key_derivation": key_evidence,
        "password_offset": _PASSWORD_OFFSET,
        "password_length": len(password),
        "password_sha256": _PASSWORD_SHA256,
    }


def _decrypt_argument(encoded: str, password: bytes) -> str:
    if not encoded or len(encoded) > 64 * 1024:
        raise RecoveryError("argument_encoded_bounds")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RecoveryError("argument_base64_invalid") from exc
    if base64.b64encode(blob).decode("ascii") != encoded:
        raise RecoveryError("argument_base64_not_canonical")
    if len(blob) < 32 or (len(blob) - AES.block_size) % AES.block_size:
        raise RecoveryError("argument_ciphertext_bounds")
    key = password + bytes(range(32 - len(password)))
    clear = AES.new(key, AES.MODE_CBC, blob[: AES.block_size]).decrypt(
        blob[AES.block_size :]
    )
    padding = clear[-1]
    if (
        not 1 <= padding <= AES.block_size
        or clear[-padding:] != bytes([padding]) * padding
    ):
        raise RecoveryError("argument_pkcs7_invalid")
    clear = clear[:-padding]
    if len(clear) > MAX_ARGUMENT_CLEAR_SIZE:
        raise RecoveryError("argument_clear_size_blocked")
    try:
        return clear.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecoveryError("argument_utf8_invalid") from exc


def _validate_schema(values: list[str]) -> tuple[str, bool]:
    if len(values) != 19:
        raise RecoveryError("argument_count_mismatch")
    nonempty = {index for index, value in enumerate(values) if value}
    if nonempty != _NONEMPTY_ARGUMENTS:
        raise RecoveryError("argument_presence_profile_mismatch")
    if any(ord(character) < 0x20 or character.isspace() for character in values[0]):
        raise RecoveryError("loader_url_shape_invalid")
    try:
        parsed = urlsplit(values[0])
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise RecoveryError("loader_url_shape_invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RecoveryError("loader_url_shape_invalid")
    if values[2] != values[9] or not re.fullmatch(
        r"[A-Za-z]:\\[^\r\n]{1,512}\\", values[2]
    ):
        raise RecoveryError("destination_path_profile_mismatch")
    if values[3] != values[10] or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", values[3]):
        raise RecoveryError("payload_name_profile_mismatch")
    if values[4] != values[6] or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", values[4]):
        raise RecoveryError("command_alias_profile_mismatch")
    if values[8] != "URL" or values[11].lower() != "js":
        raise RecoveryError("loader_mode_profile_mismatch")
    if not values[12].isdigit() or not 0 <= int(values[12]) <= 86_400:
        raise RecoveryError("loader_numeric_argument_invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", values[14]):
        raise RecoveryError("loader_token_shape_invalid")
    if not values[15].isdigit() or not 0 <= int(values[15]) <= 86_400:
        raise RecoveryError("loader_numeric_argument_invalid")
    query_redacted = bool(parsed.query)
    published_url = parsed._replace(query="").geturl()
    return published_url, query_redacted


def recover_win32_rmp_loader_config(
    assembly: bytes,
    arguments: list[str],
) -> dict[str, object]:
    """profile一致時だけ19個の暗号化引数を復号し、URL候補を返す。"""
    if (
        not isinstance(assembly, bytes)
        or not isinstance(arguments, list)
        or any(not isinstance(value, str) for value in arguments)
    ):
        raise TypeError("assemblyはbytes、argumentsはstrのlistである必要があります")
    report = _base_report(len(assembly))
    try:
        password, profile = _profile_password(assembly)
        if len(arguments) != 19:
            raise RecoveryError("argument_count_mismatch")
        values = [
            _decrypt_argument(value, password) if value else "" for value in arguments
        ]
        loader_url, loader_url_query_redacted = _validate_schema(values)
        value_metadata = [
            {
                "index": index,
                "empty": not value,
                "clear_size": len(value.encode("utf-8")),
                "clear_sha256": _sha256(value.encode("utf-8")),
            }
            for index, value in enumerate(values)
        ]
        report.update(
            {
                "status": "loader_configuration_recovered",
                "profile_evidence": profile,
                "argument_count": len(values),
                "nonempty_argument_count": len(_NONEMPTY_ARGUMENTS),
                "argument_metadata": value_metadata,
                "loader_url_candidates": [loader_url],
                "loader_url_role": "payload_acquisition_candidate",
                "loader_url_is_c2_confirmation": False,
                "loader_url_query_redacted": loader_url_query_redacted,
                "remote_content_retrieved": False,
                "published_clear_argument_indices": [0],
                "raw_loader_url_published": not loader_url_query_redacted,
                "raw_non_url_argument_values_published": False,
                "raw_key_material_published": False,
            }
        )
    except RecoveryError as exc:
        report.update(status="rejected", reason=str(exc))
    return report
