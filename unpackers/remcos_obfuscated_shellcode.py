"""Remcos配送で観測したx86 obfuscated shellcode bootstrapを静的検証する。

対象profileは、呼出元loaderのpageを0 byteで消去し、定数opaque branchを経て
0x300 byteのstack frameを確保し、局所領域を4 byte単位で初期化するx86-32
bootstrapである。shellcodeを実行・emulateせず、review済み命令列の定数伝播と
operand一致だけを有界に評価する。後続body、family、C2、終端payloadはこの
profile一致だけでは確定しない。
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any

try:
    import capstone
    from capstone import x86_const
except ImportError:  # pragma: no cover - 呼出側へ明示statusを返す
    capstone = None
    x86_const = None


@dataclass(frozen=True)
class RemcosObfuscatedShellcodeLimits:
    """bootstrap検証のhard limit。"""

    max_input_bytes: int = 32 * 1024 * 1024
    max_entry_bytes: int = 0x1000
    max_helper_bytes: int = 0x400
    max_instructions: int = 512
    max_jump_segments: int = 16


DEFAULT_LIMITS = RemcosObfuscatedShellcodeLimits()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _base_report(
    data: bytes, limits: RemcosObfuscatedShellcodeLimits
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile": "x86-page-self-erasing-opaque-bootstrap-v1",
        "status": "profile_rejected",
        "input_size": len(data),
        "input_sha256": _sha256(data),
        "candidate_set_complete": False,
        "candidate_set_truncated": False,
        "limits": asdict(limits),
        "safety": {
            "sample_executed": False,
            "shellcode_executed": False,
            "emulation_used": False,
            "network_contacted": False,
            "raw_payload_included": False,
        },
        "evidence_boundary": {
            "family_attribution_allowed": False,
            "c2_confirmation_allowed": False,
            "terminal_payload_recovered": False,
            "bootstrap_profile_is_payload_identity": False,
        },
    }


def _operands(instruction: Any) -> tuple[Any, ...]:
    try:
        return tuple(instruction.operands)
    except (AttributeError, TypeError, capstone.CsError):
        return ()


def _immediate(operand: Any) -> int | None:
    if getattr(operand, "type", None) != x86_const.X86_OP_IMM:
        return None
    return int(operand.imm) & 0xFFFFFFFF


def _direct_target(instruction: Any) -> int | None:
    operands = _operands(instruction)
    if len(operands) != 1:
        return None
    return _immediate(operands[0])


def _is_register(operand: Any, register: int) -> bool:
    return bool(
        getattr(operand, "type", None) == x86_const.X86_OP_REG
        and int(operand.reg) == register
    )


def _is_memory(
    operand: Any,
    *,
    base: int,
    index: int,
    displacement: int | None = None,
    size: int | None = None,
) -> bool:
    if getattr(operand, "type", None) != x86_const.X86_OP_MEM:
        return False
    if int(operand.mem.base) != base or int(operand.mem.index) != index:
        return False
    if int(operand.mem.scale) not in {0, 1}:
        return False
    if displacement is not None and int(operand.mem.disp) != displacement:
        return False
    return size is None or int(operand.size) == size


def _matches_register_pair(
    instruction: Any, mnemonic: str, left: int, right: int
) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == mnemonic
        and len(operands) == 2
        and _is_register(operands[0], left)
        and _is_register(operands[1], right)
    )


def _matches_mov_stack_argument(instruction: Any) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == "mov"
        and len(operands) == 2
        and _is_register(operands[0], x86_const.X86_REG_EBX)
        and _is_memory(
            operands[1],
            base=x86_const.X86_REG_ESP,
            index=x86_const.X86_REG_INVALID,
            displacement=4,
            size=4,
        )
    )


def _trace_direct_jumps(
    data: bytes,
    engine: Any,
    start: int,
    *,
    limits: RemcosObfuscatedShellcodeLimits,
    stop_at_conditional: bool,
    stop_at_return: bool,
    max_segment_bytes: int | None = None,
) -> tuple[list[Any] | None, str]:
    """無条件直接jumpだけを辿り、任意のbranchは実行しない。"""

    current = start
    segments = 0
    consumed = 0
    visited: set[int] = set()
    result: list[Any] = []
    while segments < limits.max_jump_segments:
        if current in visited:
            return None, "jump_cycle_rejected"
        if not 0 <= current < len(data):
            return None, "jump_target_out_of_bounds"
        visited.add(current)
        segments += 1
        decoded = False
        segment_end = min(
            len(data), current + (max_segment_bytes or limits.max_entry_bytes)
        )
        try:
            stream = engine.disasm(data[current:segment_end], current)
            for instruction in stream:
                decoded = True
                consumed += 1
                if consumed > limits.max_instructions:
                    return None, "instruction_limit_exceeded"
                result.append(instruction)
                if instruction.group(capstone.CS_GRP_RET):
                    return (
                        (result, "return")
                        if stop_at_return
                        else (None, "unexpected_return")
                    )
                if instruction.group(capstone.CS_GRP_JUMP):
                    target = _direct_target(instruction)
                    if instruction.mnemonic.casefold() != "jmp":
                        if stop_at_conditional:
                            return result, "conditional"
                        continue
                    if target is None:
                        return None, "indirect_jump_rejected"
                    current = target
                    break
            else:
                return None, "terminator_not_found"
        except (AttributeError, TypeError, ValueError, capstone.CsError):
            return None, "disassembly_failed"
        if not decoded:
            return None, "decode_failed"
    return None, "jump_segment_limit_exceeded"


def _rotate_left(value: int, count: int) -> int:
    count &= 31
    return (
        value
        if count == 0
        else ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF
    )


def _rotate_right(value: int, count: int) -> int:
    count &= 31
    return (
        value
        if count == 0
        else ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF
    )


def _apply_constant_operation(
    value: int, instruction: Any, register: int
) -> int | None:
    """指定registerへのreview済み定数演算だけを評価する。"""

    operands = _operands(instruction)
    mnemonic = instruction.mnemonic.casefold()
    if not operands or not _is_register(operands[0], register):
        return value
    if mnemonic in {"cmp", "test"}:
        return value
    if (
        mnemonic == "xchg"
        and len(operands) == 2
        and _is_register(operands[1], register)
    ):
        return value
    if mnemonic == "inc" and len(operands) == 1:
        return (value + 1) & 0xFFFFFFFF
    if mnemonic == "dec" and len(operands) == 1:
        return (value - 1) & 0xFFFFFFFF
    if mnemonic == "not" and len(operands) == 1:
        return (~value) & 0xFFFFFFFF
    if mnemonic == "neg" and len(operands) == 1:
        return (-value) & 0xFFFFFFFF
    if len(operands) != 2 or (immediate := _immediate(operands[1])) is None:
        return None
    if mnemonic == "mov":
        return immediate
    if mnemonic == "add":
        return (value + immediate) & 0xFFFFFFFF
    if mnemonic == "sub":
        return (value - immediate) & 0xFFFFFFFF
    if mnemonic == "xor":
        return value ^ immediate
    if mnemonic == "rol":
        return _rotate_left(value, immediate)
    if mnemonic == "ror":
        return _rotate_right(value, immediate)
    return None


def _evaluate_register_range(
    instructions: list[Any], start: int, end: int, register: int
) -> int | None:
    value: int | None = None
    for instruction in instructions[start:end]:
        operands = _operands(instruction)
        if not operands or not _is_register(operands[0], register):
            continue
        if value is None:
            if instruction.mnemonic.casefold() in {"cmp", "test"}:
                continue
            if (
                instruction.mnemonic.casefold() == "xchg"
                and len(operands) == 2
                and _is_register(operands[1], register)
            ):
                continue
            if (
                instruction.mnemonic.casefold() != "mov"
                or len(operands) != 2
                or (value := _immediate(operands[1])) is None
            ):
                return None
            continue
        value = _apply_constant_operation(value, instruction, register)
        if value is None:
            return None
    return value


def _verify_page_helper(
    data: bytes,
    engine: Any,
    start: int,
    limits: RemcosObfuscatedShellcodeLimits,
) -> tuple[dict[str, int] | None, str]:
    instructions, status = _trace_direct_jumps(
        data,
        engine,
        start,
        limits=limits,
        stop_at_conditional=False,
        stop_at_return=True,
        max_segment_bytes=limits.max_helper_bytes,
    )
    if instructions is None:
        return None, f"page_helper_{status}"
    if not instructions or not _matches_mov_stack_argument(instructions[0]):
        return None, "page_helper_stack_argument_rejected"
    div_indices = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic.casefold() == "div"
        and len(_operands(instruction)) == 1
        and _is_register(_operands(instruction)[0], x86_const.X86_REG_ECX)
    ]
    if len(div_indices) != 1:
        return None, "page_helper_div_not_unique"
    div_index = div_indices[0]
    page_size = _evaluate_register_range(
        instructions, 0, div_index, x86_const.X86_REG_ECX
    )
    if page_size != 0x1000:
        return None, "page_helper_alignment_rejected"
    if not any(
        _matches_register_pair(
            instruction,
            "xor",
            x86_const.X86_REG_EDX,
            x86_const.X86_REG_EDX,
        )
        for instruction in instructions[:div_index]
    ):
        return None, "page_helper_dividend_high_rejected"
    if not any(
        _matches_register_pair(
            instruction,
            "mov",
            x86_const.X86_REG_EAX,
            x86_const.X86_REG_EBX,
        )
        for instruction in instructions[:div_index]
    ):
        return None, "page_helper_dividend_low_rejected"
    if not any(
        instruction.mnemonic.casefold() == "inc"
        and len(_operands(instruction)) == 1
        and _is_register(_operands(instruction)[0], x86_const.X86_REG_EBX)
        for instruction in instructions[:div_index]
    ) or not any(
        instruction.mnemonic.casefold() == "dec"
        and len(_operands(instruction)) == 1
        and _is_register(_operands(instruction)[0], x86_const.X86_REG_EBX)
        for instruction in instructions[:div_index]
    ):
        return None, "page_helper_byte_walk_rejected"

    branch_indices = [
        index
        for index, instruction in enumerate(
            instructions[div_index + 1 :], div_index + 1
        )
        if instruction.mnemonic.casefold() in {"jne", "jnz"}
        and (_direct_target(instruction) or len(data)) < int(instruction.address)
    ]
    if len(branch_indices) != 1:
        return None, "page_helper_loop_branch_not_unique"
    branch_index = branch_indices[0]
    branch_target = _direct_target(instructions[branch_index])
    if branch_target is None or not start <= branch_target < int(
        instructions[div_index].address
    ):
        return None, "page_helper_loop_target_rejected"
    compare_ok = any(
        instruction.mnemonic.casefold() == "cmp"
        and len(_operands(instruction)) == 2
        and _is_register(_operands(instruction)[0], x86_const.X86_REG_EDX)
        and _immediate(_operands(instruction)[1]) == 0
        for instruction in instructions[div_index + 1 : branch_index]
    )
    if not compare_ok:
        return None, "page_helper_remainder_check_rejected"
    tail = instructions[branch_index + 1 :]
    if not any(
        _matches_register_pair(
            instruction,
            "mov",
            x86_const.X86_REG_EAX,
            x86_const.X86_REG_EBX,
        )
        for instruction in tail
    ):
        return None, "page_helper_result_rejected"
    returns = [
        instruction for instruction in tail if instruction.group(capstone.CS_GRP_RET)
    ]
    if len(returns) != 1:
        return None, "page_helper_return_not_unique"
    return_operands = _operands(returns[0])
    if len(return_operands) != 1 or _immediate(return_operands[0]) != 4:
        return None, "page_helper_stack_cleanup_rejected"
    return {
        "helper_offset": start,
        "alignment_bytes": page_size,
        "loop_branch_offset": int(instructions[branch_index].address),
    }, "confirmed"


def _verify_zero_writer_loop(
    instructions: list[Any], data_size: int
) -> tuple[dict[str, int] | None, str]:
    writers: list[tuple[int, Any]] = []
    for index, instruction in enumerate(instructions):
        operands = _operands(instruction)
        if (
            len(operands) == 2
            and _is_memory(
                operands[0],
                base=x86_const.X86_REG_EAX,
                index=x86_const.X86_REG_INVALID,
                displacement=0,
                size=1,
            )
            and _immediate(operands[1]) is not None
        ):
            writers.append((index, instruction))
    if not writers:
        return None, "zero_writer_missing"
    first_index, first = writers[0]
    if first.mnemonic.casefold() != "mov":
        return None, "zero_writer_initialization_rejected"
    value = _immediate(_operands(first)[1])
    if value is None:
        return None, "zero_writer_initialization_rejected"
    value &= 0xFF
    for _, instruction in writers[1:]:
        immediate = _immediate(_operands(instruction)[1])
        if immediate is None:
            return None, "zero_writer_operation_rejected"
        mnemonic = instruction.mnemonic.casefold()
        if mnemonic == "add":
            value = (value + immediate) & 0xFF
        elif mnemonic == "sub":
            value = (value - immediate) & 0xFF
        elif mnemonic == "xor":
            value ^= immediate & 0xFF
        else:
            return None, "zero_writer_operation_rejected"
    if value != 0:
        return None, "zero_writer_nonzero_result"

    increments = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic.casefold() == "inc"
        and len(_operands(instruction)) == 1
        and _is_register(_operands(instruction)[0], x86_const.X86_REG_EAX)
    ]
    compares = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic.casefold() == "cmp"
        and len(_operands(instruction)) == 2
        and {
            int(operand.reg)
            for operand in _operands(instruction)
            if getattr(operand, "type", None) == x86_const.X86_OP_REG
        }
        == {x86_const.X86_REG_EAX, x86_const.X86_REG_ESI}
    ]
    branches = [
        (index, instruction)
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic.casefold() in {"jne", "jnz"}
    ]
    if len(increments) != 1 or len(compares) != 1 or len(branches) != 1:
        return None, "zero_writer_loop_shape_rejected"
    branch_index, branch = branches[0]
    target = _direct_target(branch)
    first_address = int(first.address)
    loop_start = int(instructions[0].address)
    if (
        target != loop_start
        or not first_index < increments[0] < compares[0] < branch_index
        or not 0 <= first_address < data_size
    ):
        return None, "zero_writer_loop_flow_rejected"
    return {
        "writer_offset": first_address,
        "writer_operation_count": len(writers),
        "loop_branch_offset": int(branch.address),
    }, "confirmed"


def _find_opaque_true_branch(
    data: bytes,
    engine: Any,
    start: int,
    limits: RemcosObfuscatedShellcodeLimits,
) -> tuple[dict[str, int] | None, str]:
    instructions, status = _trace_direct_jumps(
        data,
        engine,
        start,
        limits=limits,
        stop_at_conditional=True,
        stop_at_return=False,
    )
    if instructions is None:
        return None, f"opaque_branch_{status}"
    value: int | None = None
    set_offset: int | None = None
    eax_aliases = {
        x86_const.X86_REG_EAX,
        x86_const.X86_REG_AX,
        x86_const.X86_REG_AH,
        x86_const.X86_REG_AL,
    }
    for instruction in instructions:
        operands = _operands(instruction)
        mnemonic = instruction.mnemonic.casefold()
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and _is_register(operands[0], x86_const.X86_REG_EAX)
            and (immediate := _immediate(operands[1])) is not None
        ):
            value = immediate
            set_offset = int(instruction.address)
            continue
        if (
            value is not None
            and mnemonic == "lea"
            and len(operands) == 2
            and _is_register(operands[0], x86_const.X86_REG_EAX)
            and _is_memory(
                operands[1],
                base=x86_const.X86_REG_EAX,
                index=x86_const.X86_REG_INVALID,
                displacement=0,
            )
        ):
            continue
        if (
            value is not None
            and mnemonic == "cmp"
            and len(operands) == 2
            and _is_register(operands[0], x86_const.X86_REG_EAX)
            and _immediate(operands[1]) == value
        ):
            continue
        if value is not None and instruction.group(capstone.CS_GRP_CALL):
            target = _direct_target(instruction)
            fallthrough = int(instruction.address) + int(instruction.size)
            if target != fallthrough:
                return None, "opaque_branch_call_rejected"
            continue
        if (
            value is not None
            and mnemonic == "xchg"
            and len(operands) == 2
            and int(getattr(operands[0], "reg", 0)) in eax_aliases
            and int(getattr(operands[0], "reg", 0))
            == int(getattr(operands[1], "reg", -1))
        ):
            continue
        if instruction.group(capstone.CS_GRP_JUMP) and mnemonic != "jmp":
            target = _direct_target(instruction)
            if (
                value is not None
                and set_offset is not None
                and mnemonic in {"je", "jz"}
                and target is not None
                and int(instruction.address)
                < target
                < min(len(data), limits.max_entry_bytes)
            ):
                return {
                    "constant_set_offset": set_offset,
                    "branch_offset": int(instruction.address),
                    "taken_target": target,
                }, "confirmed"
            return None, "opaque_branch_condition_rejected"
        if (
            operands
            and _is_register(operands[0], x86_const.X86_REG_EAX)
            and mnemonic not in {"cmp", "test"}
        ):
            value = None
            set_offset = None
            continue
        if value is not None:
            try:
                _, written = instruction.regs_access()
            except (AttributeError, TypeError, ValueError, capstone.CsError):
                return None, "opaque_branch_register_access_rejected"
            if eax_aliases.intersection(int(register) for register in written):
                return None, "opaque_branch_eax_clobber_rejected"
    return None, "opaque_true_branch_not_found"


def _verify_stack_frame_and_zero_loop(
    data: bytes,
    engine: Any,
    start: int,
    limits: RemcosObfuscatedShellcodeLimits,
) -> tuple[dict[str, int] | None, str]:
    end = min(len(data), start + limits.max_entry_bytes)
    try:
        instructions = list(engine.disasm(data[start:end], start))
    except (AttributeError, TypeError, ValueError, capstone.CsError):
        return None, "stack_disassembly_failed"
    if not instructions:
        return None, "stack_decode_failed"
    instructions = instructions[: limits.max_instructions]
    pop_ebx = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic.casefold() == "pop"
        and len(_operands(instruction)) == 1
        and _is_register(_operands(instruction)[0], x86_const.X86_REG_EBX)
    ]
    frame_starts = [
        index
        for index, instruction in enumerate(instructions)
        if _matches_register_pair(
            instruction,
            "mov",
            x86_const.X86_REG_EBP,
            x86_const.X86_REG_ESP,
        )
    ]
    if (
        not pop_ebx
        or len(frame_starts) < 2
        or not pop_ebx[0] < frame_starts[0] < frame_starts[1]
    ):
        return None, "stack_frame_shape_rejected"
    first_frame, second_frame = frame_starts[:2]
    if not any(
        instruction.mnemonic.casefold() == "push"
        and len(_operands(instruction)) == 1
        and _is_register(_operands(instruction)[0], x86_const.X86_REG_EBP)
        for instruction in instructions[first_frame + 1 : second_frame]
    ):
        return None, "stack_frame_save_rejected"
    delta = 0
    for instruction in instructions[first_frame + 1 : second_frame]:
        operands = _operands(instruction)
        if not operands or not _is_register(operands[0], x86_const.X86_REG_ESP):
            continue
        mnemonic = instruction.mnemonic.casefold()
        if mnemonic == "inc" and len(operands) == 1:
            delta += 1
        elif mnemonic == "dec" and len(operands) == 1:
            delta -= 1
        elif len(operands) == 2 and (immediate := _immediate(operands[1])) is not None:
            if mnemonic == "add":
                delta += immediate
            elif mnemonic == "sub":
                delta -= immediate
            else:
                return None, "stack_delta_operation_rejected"
        else:
            return None, "stack_delta_operation_rejected"
        delta = ((delta + 0x80000000) & 0xFFFFFFFF) - 0x80000000
    if delta != -0x300:
        return None, "stack_allocation_rejected"

    tail = instructions[second_frame + 1 :]
    zero_index = next(
        (
            index
            for index, instruction in enumerate(tail)
            if len(_operands(instruction)) == 2
            and instruction.mnemonic.casefold() == "mov"
            and _is_memory(
                _operands(instruction)[0],
                base=x86_const.X86_REG_EBP,
                index=x86_const.X86_REG_ECX,
                displacement=0,
                size=4,
            )
            and _immediate(_operands(instruction)[1]) == 0
        ),
        None,
    )
    if zero_index is None:
        return None, "stack_zero_writer_missing"
    zero_instruction = tail[zero_index]
    start_value = _evaluate_register_range(tail, 0, zero_index, x86_const.X86_REG_ECX)
    if start_value != 0x18:
        return None, "stack_zero_start_rejected"

    cursor_index: int | None = None
    cursor_displacement: int | None = None
    cursor_value = start_value
    for index in range(zero_index + 1, len(tail)):
        instruction = tail[index]
        operands = _operands(instruction)
        if (
            len(operands) == 2
            and instruction.mnemonic.casefold() == "mov"
            and _is_memory(
                operands[0],
                base=x86_const.X86_REG_EBP,
                index=x86_const.X86_REG_INVALID,
                size=4,
            )
            and _is_register(operands[1], x86_const.X86_REG_ECX)
        ):
            cursor_index = index
            cursor_displacement = int(operands[0].mem.disp)
            break
        if operands and _is_register(operands[0], x86_const.X86_REG_ECX):
            updated = _apply_constant_operation(
                cursor_value, instruction, x86_const.X86_REG_ECX
            )
            if updated is None:
                return None, "stack_zero_stride_operation_rejected"
            cursor_value = updated
        elif operands and _is_memory(
            operands[0],
            base=x86_const.X86_REG_EBP,
            index=x86_const.X86_REG_ECX,
            displacement=0,
            size=4,
        ):
            if instruction.mnemonic.casefold() not in {"neg", "rol", "ror"}:
                return None, "stack_zero_memory_operation_rejected"
    if cursor_index is None or cursor_displacement is None or cursor_value != 0x1C:
        return None, "stack_zero_stride_rejected"

    compare_index: int | None = None
    terminal_value: int | None = None
    terminal_start = next(
        (
            index
            for index in range(cursor_index + 1, len(tail))
            if tail[index].mnemonic.casefold() == "mov"
            and len(_operands(tail[index])) == 2
            and _is_register(_operands(tail[index])[0], x86_const.X86_REG_ECX)
            and _immediate(_operands(tail[index])[1]) is not None
        ),
        None,
    )
    if terminal_start is None:
        return None, "stack_zero_terminal_missing"
    for index in range(terminal_start + 1, len(tail)):
        instruction = tail[index]
        operands = _operands(instruction)
        if (
            instruction.mnemonic.casefold() == "cmp"
            and len(operands) == 2
            and _is_memory(
                operands[0],
                base=x86_const.X86_REG_EBP,
                index=x86_const.X86_REG_INVALID,
                displacement=cursor_displacement,
                size=4,
            )
            and _is_register(operands[1], x86_const.X86_REG_ECX)
        ):
            compare_index = index
            break
    if compare_index is None:
        return None, "stack_zero_terminal_compare_missing"
    terminal_value = _evaluate_register_range(
        tail, terminal_start, compare_index, x86_const.X86_REG_ECX
    )
    if terminal_value != 0x178:
        return None, "stack_zero_terminal_rejected"
    reload_indices = [
        index
        for index in range(compare_index + 1, len(tail))
        if tail[index].mnemonic.casefold() == "mov"
        and len(_operands(tail[index])) == 2
        and _is_register(_operands(tail[index])[0], x86_const.X86_REG_ECX)
        and _is_memory(
            _operands(tail[index])[1],
            base=x86_const.X86_REG_EBP,
            index=x86_const.X86_REG_INVALID,
            displacement=cursor_displacement,
            size=4,
        )
    ]
    if len(reload_indices) != 1:
        return None, "stack_zero_cursor_reload_rejected"
    reload_index = reload_indices[0]
    branch = next(
        (
            instruction
            for instruction in tail[reload_index + 1 :]
            if instruction.group(capstone.CS_GRP_JUMP)
        ),
        None,
    )
    if (
        branch is None
        or branch.mnemonic.casefold() not in {"jne", "jnz"}
        or _direct_target(branch) != int(zero_instruction.address)
    ):
        return None, "stack_zero_loop_branch_rejected"
    return {
        "stack_setup_offset": int(instructions[first_frame].address),
        "stack_allocation_bytes": -delta,
        "zero_loop_offset": int(zero_instruction.address),
        "zero_start_offset": start_value,
        "zero_end_exclusive": terminal_value,
        "zero_stride_bytes": cursor_value - start_value,
        "zero_iteration_count": (terminal_value - start_value)
        // (cursor_value - start_value),
    }, "confirmed"


def analyze_remcos_obfuscated_shellcode(
    data: bytes,
    *,
    limits: RemcosObfuscatedShellcodeLimits = DEFAULT_LIMITS,
) -> dict[str, object]:
    """x86 bootstrapを実行せず、限定profileとして検証する。"""

    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    report = _base_report(data, limits)
    if not data or len(data) > limits.max_input_bytes:
        report["status"] = "input_size_rejected"
        return report
    if capstone is None or x86_const is None:
        report["status"] = "dependency_unavailable"
        return report
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True

    try:
        entry = list(engine.disasm(data[: min(len(data), 128)], 0))
    except (AttributeError, TypeError, ValueError, capstone.CsError):
        report["status"] = "entry_disassembly_failed"
        return report
    if (
        not entry
        or entry[0].mnemonic.casefold() != "pop"
        or len(_operands(entry[0])) != 1
        or not _is_register(_operands(entry[0])[0], x86_const.X86_REG_ESI)
    ):
        report["status"] = "entry_pop_rejected"
        return report
    first_jump = next(
        (
            instruction
            for instruction in entry[:16]
            if instruction.mnemonic.casefold() == "jmp"
        ),
        None,
    )
    entry_target = _direct_target(first_jump) if first_jump is not None else None
    if entry_target is None or not 0 < entry_target < min(
        len(data), limits.max_entry_bytes
    ):
        report["status"] = "entry_jump_rejected"
        return report

    try:
        bootstrap = list(
            engine.disasm(
                data[entry_target : min(len(data), entry_target + 128)], entry_target
            )
        )
    except (AttributeError, TypeError, ValueError, capstone.CsError):
        report["status"] = "bootstrap_disassembly_failed"
        return report
    calls = [
        (index, instruction)
        for index, instruction in enumerate(bootstrap[:16])
        if instruction.group(capstone.CS_GRP_CALL)
        and _direct_target(instruction) is not None
    ]
    if len(calls) != 1:
        report["status"] = "bootstrap_helper_call_not_unique"
        return report
    call_index, helper_call = calls[0]
    if not any(
        instruction.mnemonic.casefold() == "push"
        and len(_operands(instruction)) == 1
        and _is_register(_operands(instruction)[0], x86_const.X86_REG_ESI)
        for instruction in [*entry[:16], *bootstrap[:call_index]]
    ):
        report["status"] = "caller_return_preservation_rejected"
        return report
    helper_target = _direct_target(helper_call)
    if helper_target is None:
        report["status"] = "page_helper_target_rejected"
        return report
    helper_evidence, helper_status = _verify_page_helper(
        data, engine, helper_target, limits
    )
    if helper_evidence is None:
        report["status"] = helper_status
        return report

    writer_start = int(helper_call.address) + int(helper_call.size)
    writer_instructions, writer_trace_status = _trace_direct_jumps(
        data,
        engine,
        writer_start,
        limits=limits,
        stop_at_conditional=True,
        stop_at_return=False,
    )
    if writer_instructions is None:
        report["status"] = f"zero_writer_{writer_trace_status}"
        return report
    writer_evidence, writer_status = _verify_zero_writer_loop(
        writer_instructions, len(data)
    )
    if writer_evidence is None:
        report["status"] = writer_status
        return report
    loop_branch = writer_instructions[-1]
    opaque_start = int(loop_branch.address) + int(loop_branch.size)
    opaque_evidence, opaque_status = _find_opaque_true_branch(
        data, engine, opaque_start, limits
    )
    if opaque_evidence is None:
        report["status"] = opaque_status
        return report
    stack_evidence, stack_status = _verify_stack_frame_and_zero_loop(
        data, engine, opaque_evidence["taken_target"], limits
    )
    if stack_evidence is None:
        report["status"] = stack_status
        return report

    report.update(
        {
            "status": "bootstrap_profile_confirmed",
            "candidate_set_complete": True,
            "architecture": "x86-32",
            "self_erasure": {
                "caller_page_alignment_bytes": helper_evidence["alignment_bytes"],
                "byte_writer_operation_count": writer_evidence[
                    "writer_operation_count"
                ],
                "terminating_pointer_register": "esi",
            },
            "opaque_branch": {
                "proof": "eax_immediate_equals_cmp_immediate",
                "taken_condition": "equal",
            },
            "stack_initialization": {
                "allocation_bytes": stack_evidence["stack_allocation_bytes"],
                "zero_start_offset": stack_evidence["zero_start_offset"],
                "zero_end_exclusive": stack_evidence["zero_end_exclusive"],
                "zero_stride_bytes": stack_evidence["zero_stride_bytes"],
                "zero_iteration_count": stack_evidence["zero_iteration_count"],
            },
            "profile_offsets": {
                "entry_jump_target": entry_target,
                "page_helper": helper_evidence["helper_offset"],
                "self_erase_writer": writer_evidence["writer_offset"],
                "opaque_branch": opaque_evidence["branch_offset"],
                "core_entry": opaque_evidence["taken_target"],
                "stack_zero_loop": stack_evidence["zero_loop_offset"],
            },
            "remaining_blocker": "post_bootstrap_body_not_statically_recovered",
        }
    )
    return report


__all__ = [
    "DEFAULT_LIMITS",
    "RemcosObfuscatedShellcodeLimits",
    "analyze_remcos_obfuscated_shellcode",
]
