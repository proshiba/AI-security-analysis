"""Remcos配送で観測したx86 polymorphic XOR loaderを静的復元する。

対象は、直接分岐で分割したx86-32 callbackが第二bufferを別領域へ移し、
``xor dword ptr [edi+eax], imm32`` のloopで復号して ``call edi`` する
限定profileである。命令を実行・emulateせず、有界CFGと命令operandの一致だけで
XOR鍵と処理長を検証する。loaderとdataの組合せが一意に整合しない場合は
fail closedとする。
"""

from __future__ import annotations

import hashlib
from collections import Counter, deque
from dataclasses import asdict, dataclass

from unpackers.remcos_obfuscated_shellcode import (
    analyze_remcos_obfuscated_shellcode,
)

try:
    import capstone
    from capstone import x86_const
except ImportError:  # pragma: no cover - 呼出側へ明示statusを返す
    capstone = None
    x86_const = None


@dataclass(frozen=True)
class RemcosPolymorphicXorLimits:
    """x86 CFG解析と復号のhard limit。"""

    max_loader_bytes: int = 256 * 1024
    max_payload_bytes: int = 32 * 1024 * 1024
    max_blocks: int = 4_096
    max_instructions: int = 100_000
    max_block_instructions: int = 128
    max_block_bytes: int = 512
    min_direct_jumps: int = 32
    max_edges: int = 16_384


DEFAULT_LIMITS = RemcosPolymorphicXorLimits()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _base_report(
    loader: bytes,
    payload: bytes,
    limits: RemcosPolymorphicXorLimits,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile": "remcos-x86-polymorphic-dword-xor-callback-v1",
        "status": "rejected",
        "loader_size": len(loader),
        "loader_sha256": _sha256(loader),
        "payload_size": len(payload),
        "payload_sha256": _sha256(payload),
        "candidate_set_complete": False,
        "candidate_set_truncated": False,
        "candidate_count": 0,
        "limits": asdict(limits),
        "safety": {
            "sample_executed": False,
            "shellcode_executed": False,
            "emulation_used": False,
            "network_contacted": False,
            "raw_key_included": False,
        },
        "evidence_boundary": {
            "family_attribution_allowed": False,
            "c2_confirmation_allowed": False,
            "recovered_shellcode_is_terminal_payload": False,
        },
    }


def _immediate_target(instruction: object) -> int | None:
    operands = tuple(getattr(instruction, "operands", ()))
    if len(operands) != 1 or operands[0].type != x86_const.X86_OP_IMM:
        return None
    return int(operands[0].imm)


def _reachable_instructions(
    data: bytes,
    limits: RemcosPolymorphicXorLimits,
) -> tuple[dict[int, object] | None, dict[str, object]]:
    """直接分岐だけを辿り、実行せず到達可能命令を列挙する。"""

    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    queue: deque[int] = deque([0])
    queued = {0}
    visited: set[int] = set()
    instructions: dict[int, object] = {}
    counters: Counter[str] = Counter()
    edge_count = 0
    external_exact_end = 0
    rejection: str | None = None

    def schedule(target: int) -> None:
        nonlocal edge_count, external_exact_end, rejection
        edge_count += 1
        if edge_count > limits.max_edges:
            rejection = "edge_limit_exceeded"
            return
        if target == len(data):
            external_exact_end += 1
            return
        if not 0 <= target < len(data):
            counters["out_of_bounds_target"] += 1
            return
        if target not in visited and target not in queued:
            if len(visited) + len(queue) >= limits.max_blocks:
                rejection = "block_limit_exceeded"
                return
            queued.add(target)
            queue.append(target)

    while queue and rejection is None:
        start = queue.popleft()
        queued.discard(start)
        if start in visited:
            continue
        visited.add(start)
        decoded = False
        try:
            stream = engine.disasm(data[start : start + limits.max_block_bytes], start)
            for index, instruction in enumerate(stream, 1):
                decoded = True
                address = int(instruction.address)
                instructions.setdefault(address, instruction)
                if len(instructions) > limits.max_instructions:
                    rejection = "instruction_limit_exceeded"
                    break
                if index > limits.max_block_instructions:
                    rejection = "block_instruction_limit_exceeded"
                    break
                end = address + int(instruction.size)
                if instruction.group(capstone.CS_GRP_RET):
                    counters["return"] += 1
                    break
                if instruction.group(capstone.CS_GRP_CALL):
                    target = _immediate_target(instruction)
                    if target is None:
                        counters["indirect_call"] += 1
                    else:
                        counters["direct_call"] += 1
                        schedule(target)
                    schedule(end)
                    continue
                if instruction.group(capstone.CS_GRP_JUMP):
                    target = _immediate_target(instruction)
                    conditional = instruction.mnemonic.casefold() != "jmp"
                    if target is None:
                        rejection = "indirect_jump_rejected"
                        break
                    counters[
                        "direct_conditional_jump" if conditional else "direct_jump"
                    ] += 1
                    schedule(target)
                    if conditional:
                        schedule(end)
                    break
        except (AttributeError, TypeError, ValueError, capstone.CsError):
            rejection = "disassembly_failed"
            break
        if not decoded:
            rejection = "decode_failed"

    metrics = {
        "status": rejection or "complete",
        "block_count": len(visited),
        "instruction_count": len(instructions),
        "edge_count": edge_count,
        "control_flow_counts": dict(sorted(counters.items())),
        "external_exact_end_target_count": external_exact_end,
    }
    return (instructions if rejection is None else None), metrics


def _is_register(operand: object, register: int) -> bool:
    return (
        getattr(operand, "type", None) == x86_const.X86_OP_REG
        and int(operand.reg) == register
    )


def _is_immediate(operand: object, value: int | None = None) -> bool:
    if getattr(operand, "type", None) != x86_const.X86_OP_IMM:
        return False
    return value is None or (int(operand.imm) & 0xFFFFFFFF) == value


def _is_memory(
    operand: object,
    *,
    base: int,
    index: int,
    displacement: int,
    size: int,
) -> bool:
    return bool(
        getattr(operand, "type", None) == x86_const.X86_OP_MEM
        and int(operand.mem.base) == base
        and int(operand.mem.index) == index
        and int(operand.mem.scale) in {0, 1}
        and int(operand.mem.disp) == displacement
        and int(operand.size) == size
    )


def _matches_mov_stack_arg(instruction: object, destination: int, offset: int) -> bool:
    operands = tuple(instruction.operands)
    return bool(
        instruction.mnemonic.casefold() == "mov"
        and len(operands) == 2
        and _is_register(operands[0], destination)
        and _is_memory(
            operands[1],
            base=x86_const.X86_REG_ESP,
            index=x86_const.X86_REG_INVALID,
            displacement=offset,
            size=4,
        )
    )


def _matches_mov_saved_pointer(instruction: object) -> bool:
    operands = tuple(instruction.operands)
    return bool(
        instruction.mnemonic.casefold() == "mov"
        and len(operands) == 2
        and _is_memory(
            operands[0],
            base=x86_const.X86_REG_ESP,
            index=x86_const.X86_REG_INVALID,
            displacement=0x0C,
            size=4,
        )
        and _is_register(operands[1], x86_const.X86_REG_EBX)
    )


def recover_remcos_polymorphic_xor_loader(
    loader: bytes,
    payload: bytes,
    *,
    limits: RemcosPolymorphicXorLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """review済みx86 callbackと対応dataから次段shellcodeを復元する。"""

    if not isinstance(loader, bytes) or not isinstance(payload, bytes):
        raise TypeError("loaderとpayloadはbytesである必要があります")
    report = _base_report(loader, payload, limits)
    if (
        not loader
        or not payload
        or len(loader) > limits.max_loader_bytes
        or len(payload) > limits.max_payload_bytes
    ):
        report["status"] = "input_size_rejected"
        return report, []
    if capstone is None or x86_const is None:
        report["status"] = "dependency_unavailable"
        return report, []

    instructions, cfg = _reachable_instructions(loader, limits)
    report["cfg"] = cfg
    if instructions is None:
        report.update(
            {
                "status": str(cfg["status"]),
                "candidate_set_truncated": str(cfg["status"]).endswith(
                    "limit_exceeded"
                ),
            }
        )
        return report, []
    flow = cfg["control_flow_counts"]
    if (
        int(flow.get("direct_jump", 0)) < limits.min_direct_jumps
        or int(flow.get("indirect_call", 0)) != 2
        or int(flow.get("direct_conditional_jump", 0)) < 1
        or int(cfg["external_exact_end_target_count"]) != 1
    ):
        report["status"] = "polymorphic_cfg_profile_rejected"
        return report, []

    ordered = [instructions[address] for address in sorted(instructions)]
    indirect_calls = [
        instruction
        for instruction in ordered
        if instruction.group(capstone.CS_GRP_CALL)
        and _immediate_target(instruction) is None
    ]
    if [
        int(next(iter(instruction.operands)).reg) for instruction in indirect_calls
    ] != [x86_const.X86_REG_EDX, x86_const.X86_REG_EDI]:
        report["status"] = "indirect_call_profile_rejected"
        return report, []

    expected_loop_size = ((len(payload) + 3) & ~3) + 0x400
    length_loads = []
    xor_loops: list[tuple[object, int]] = []
    zero_eax = []
    add_eax = []
    compare_loop = []
    call_edi = []
    stack_input_eax = []
    stack_input_edi = []
    stack_saved_pointer = []
    stack_reloaded_pointer = []
    conditional_back_edges = []
    for instruction in ordered:
        operands = tuple(instruction.operands)
        mnemonic = instruction.mnemonic.casefold()
        address = int(instruction.address)
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and _is_register(operands[0], x86_const.X86_REG_EDX)
            and _is_immediate(operands[1], expected_loop_size)
        ):
            length_loads.append(instruction)
        if (
            mnemonic == "xor"
            and len(operands) == 2
            and _is_memory(
                operands[0],
                base=x86_const.X86_REG_EDI,
                index=x86_const.X86_REG_EAX,
                displacement=0,
                size=4,
            )
            and _is_immediate(operands[1])
        ):
            xor_loops.append((instruction, int(operands[1].imm) & 0xFFFFFFFF))
        if (
            mnemonic == "xor"
            and len(operands) == 2
            and _is_register(operands[0], x86_const.X86_REG_EAX)
            and _is_register(operands[1], x86_const.X86_REG_EAX)
        ):
            zero_eax.append(instruction)
        if (
            mnemonic == "add"
            and len(operands) == 2
            and _is_register(operands[0], x86_const.X86_REG_EAX)
            and _is_immediate(operands[1], 4)
        ):
            add_eax.append(instruction)
        if (
            mnemonic == "cmp"
            and len(operands) == 2
            and _is_register(operands[0], x86_const.X86_REG_EAX)
            and _is_register(operands[1], x86_const.X86_REG_EDX)
        ):
            compare_loop.append(instruction)
        if (
            mnemonic == "call"
            and len(operands) == 1
            and _is_register(operands[0], x86_const.X86_REG_EDI)
        ):
            call_edi.append(instruction)
        if _matches_mov_stack_arg(instruction, x86_const.X86_REG_EAX, 4):
            stack_input_eax.append(instruction)
        if _matches_mov_stack_arg(instruction, x86_const.X86_REG_EDI, 4):
            stack_input_edi.append(instruction)
        if _matches_mov_saved_pointer(instruction):
            stack_saved_pointer.append(instruction)
        if _matches_mov_stack_arg(instruction, x86_const.X86_REG_EDI, 0x0C):
            stack_reloaded_pointer.append(instruction)
        if instruction.group(capstone.CS_GRP_JUMP) and mnemonic != "jmp":
            target = _immediate_target(instruction)
            if target is not None and target < address:
                conditional_back_edges.append(instruction)

    unique_sets = (
        length_loads,
        xor_loops,
        zero_eax,
        add_eax,
        compare_loop,
        call_edi,
        stack_input_eax,
        stack_input_edi,
        stack_saved_pointer,
        stack_reloaded_pointer,
    )
    if any(len(items) != 1 for items in unique_sets):
        report.update(
            {
                "status": "xor_dataflow_not_unique",
                "profile_counts": {
                    "length_load": len(length_loads),
                    "xor_loop": len(xor_loops),
                    "zero_eax": len(zero_eax),
                    "add_eax": len(add_eax),
                    "compare_loop": len(compare_loop),
                    "call_edi": len(call_edi),
                    "stack_input_eax": len(stack_input_eax),
                    "stack_input_edi": len(stack_input_edi),
                    "stack_saved_pointer": len(stack_saved_pointer),
                    "stack_reloaded_pointer": len(stack_reloaded_pointer),
                },
            }
        )
        return report, []

    xor_instruction, key_integer = xor_loops[0]
    addresses = {
        "length_load": int(length_loads[0].address),
        "zero_eax": int(zero_eax[0].address),
        "stack_reloaded_pointer": int(stack_reloaded_pointer[0].address),
        "xor_loop": int(xor_instruction.address),
        "add_eax": int(add_eax[0].address),
        "compare_loop": int(compare_loop[0].address),
        "call_edi": int(call_edi[0].address),
    }
    if not (
        addresses["length_load"]
        < addresses["zero_eax"]
        < addresses["stack_reloaded_pointer"]
        < addresses["xor_loop"]
        < addresses["add_eax"]
        < addresses["compare_loop"]
        < addresses["call_edi"]
    ):
        report["status"] = "xor_dataflow_order_rejected"
        return report, []
    loop_edges = [
        instruction
        for instruction in conditional_back_edges
        if int(instruction.address) > addresses["compare_loop"]
        and (_immediate_target(instruction) or -1) <= addresses["xor_loop"]
    ]
    if len(loop_edges) != 1:
        report["status"] = "xor_loop_back_edge_not_unique"
        return report, []

    key = key_integer.to_bytes(4, "little")
    if key == b"\x00" * 4:
        report["status"] = "zero_key_rejected"
        return report, []
    decoded = bytes(value ^ key[index & 3] for index, value in enumerate(payload))
    if not decoded or decoded == payload:
        report["status"] = "decoded_output_rejected"
        return report, []

    inner_profile = analyze_remcos_obfuscated_shellcode(decoded)

    report.update(
        {
            "status": "shellcode_recovered",
            "candidate_set_complete": True,
            "candidate_count": 1,
            "architecture": "x86-32",
            "xor_width_bits": 32,
            "xor_key_sha256": _sha256(key),
            "loop_size": expected_loop_size,
            "input_padding_bytes": expected_loop_size - len(payload),
            "decoded_size": len(decoded),
            "decoded_sha256": _sha256(decoded),
            "profile_offsets": addresses,
            "decoded_shellcode_profile": inner_profile,
        }
    )
    return report, [("remcos-polymorphic-xor-shellcode.bin", decoded)]


__all__ = [
    "DEFAULT_LIMITS",
    "RemcosPolymorphicXorLimits",
    "recover_remcos_polymorphic_xor_loader",
]
