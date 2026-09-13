"""SilverFox系感染loaderの多段復元lineageを静的に検証する。

このmoduleは検体を実行せず、file-backed PE byteとx64命令だけを扱う。
hash、file名、外部label、復元endpoint値は判定へ使わない。loaderの復元に
成功してもValleyRAT終端とはみなさず、終端configからconnect/send/recvと
protocolまで別validatorで証明されない限りfamily確定を常に拒否する。
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Literal

import pefile
from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_64, Cs, CsError
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_INVALID,
    X86_REG_RCX,
    X86_REG_RIP,
    X86_REG_RSP,
)

MAXIMUM_INPUT_SIZE = 128 * 1024 * 1024
MAXIMUM_STAGE_SIZE = 4 * 1024 * 1024
MAXIMUM_COMPONENT_SIZE = 16 * 1024 * 1024
MAXIMUM_EXECUTABLE_SECTION_SIZE = 8 * 1024 * 1024
MAXIMUM_RELATIVE_EDGES = 262_144
MAXIMUM_VIRTUAL_ALLOC_CALLS = 256
MAXIMUM_TAIL_STEPS = 64
MAXIMUM_BOOTSTRAP_STEPS = 32
MAXIMUM_MAIN_INSTRUCTIONS = 4_096
MAXIMUM_COMPONENT_INSTRUCTIONS = 65_536
ROUTE_MARKER = b"\x2a\x2f\x26\xfe"
ROUTE_RECORD_SIZE = 32


@dataclass(frozen=True)
class SilverFoxLoaderLineage:
    """公開可能な観測と、後段処理専用の復元componentを保持する。"""

    observation: dict[str, object]
    recovered_component: bytes | None


@dataclass(frozen=True)
class _PeContext:
    data: bytes
    image: pefile.PE
    imports: dict[int, str]


@dataclass(frozen=True)
class _OuterStage:
    data: bytes
    source_rva: int
    size: int
    allocation_call_rva: int
    copy_kind: Literal["rep_movsb", "dword_and_byte_loops"]
    hook_trampoline_proven: bool


@dataclass(frozen=True)
class _FeedbackLayer:
    data: bytes
    main_offset: int
    patch_operation_count: int
    feedback_count: int


@dataclass(frozen=True)
class _ComponentLayer:
    data: bytes
    source_offset: int
    key_length: int
    main_offset: int


def _canonical_register(name: str) -> str:
    aliases = {
        "al": "rax",
        "ah": "rax",
        "ax": "rax",
        "eax": "rax",
        "bl": "rbx",
        "bh": "rbx",
        "bx": "rbx",
        "ebx": "rbx",
        "cl": "rcx",
        "ch": "rcx",
        "cx": "rcx",
        "ecx": "rcx",
        "dl": "rdx",
        "dh": "rdx",
        "dx": "rdx",
        "edx": "rdx",
        "dil": "rdi",
        "edi": "rdi",
        "sil": "rsi",
        "esi": "rsi",
        "bpl": "rbp",
        "ebp": "rbp",
        "spl": "rsp",
        "esp": "rsp",
    }
    if name in aliases:
        return aliases[name]
    if name.startswith("r") and name.endswith(("b", "w", "d")):
        stem = name[1:-1]
        if stem.isdigit():
            return name[:-1]
    return name


def _register_name(instruction: object, register: int) -> str:
    return _canonical_register(str(instruction.reg_name(register)).casefold())


def _load_pe(data: bytes) -> _PeContext | None:
    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAXIMUM_INPUT_SIZE
        or not data.startswith(b"MZ")
    ):
        return None
    try:
        image = pefile.PE(data=data, fast_load=False)
        if (
            int(image.FILE_HEADER.Machine) != 0x8664
            or int(image.OPTIONAL_HEADER.Magic) != 0x20B
        ):
            return None
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
    except (AttributeError, OverflowError, TypeError, ValueError, pefile.PEFormatError):
        return None
    imports: dict[int, str] = {}
    try:
        for descriptor in getattr(image, "DIRECTORY_ENTRY_IMPORT", ()):
            for item in descriptor.imports:
                if item.name is None:
                    continue
                name = item.name.decode("ascii", errors="strict").casefold()
                address = int(item.address)
                rva = address - image_base if address >= image_base else address
                imports[rva] = name
    except (AttributeError, OverflowError, TypeError, UnicodeError, ValueError):
        return None
    return _PeContext(data=data, image=image, imports=imports)


def _fully_file_backed(context: _PeContext, rva: int, size: int) -> bytes | None:
    if not 0 <= rva or not 0 < size <= MAXIMUM_STAGE_SIZE:
        return None
    try:
        offset = int(context.image.get_offset_from_rva(rva))
        final_offset = int(context.image.get_offset_from_rva(rva + size - 1))
    except (OverflowError, TypeError, ValueError, pefile.PEFormatError):
        return None
    if final_offset != offset + size - 1 or not 0 <= offset <= len(context.data) - size:
        return None
    return context.data[offset : offset + size]


def _iat_call_rva(instruction: object) -> int | None:
    if instruction.mnemonic.casefold() != "call" or len(instruction.operands) != 1:
        return None
    operand = instruction.operands[0]
    if (
        operand.type != X86_OP_MEM
        or operand.mem.base != X86_REG_RIP
        or operand.mem.index != X86_REG_INVALID
    ):
        return None
    return instruction.address + instruction.size + int(operand.mem.disp)


def _executable_sections(context: _PeContext) -> list[tuple[int, bytes]] | None:
    result: list[tuple[int, bytes]] = []
    total = 0
    for section in context.image.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        raw = bytes(section.get_data())
        total += len(raw)
        if total > MAXIMUM_EXECUTABLE_SECTION_SIZE:
            return None
        result.append((int(section.VirtualAddress), raw))
    return result


def _relative_edges(
    sections: list[tuple[int, bytes]],
) -> tuple[tuple[int, int, int], ...] | None:
    """E8/E9 edgeを固定上限内だけ列挙し、超過時は部分集合を返さない。"""

    result: list[tuple[int, int, int]] = []
    for section_rva, raw in sections:
        for offset in range(max(0, len(raw) - 4)):
            opcode = raw[offset]
            if opcode not in {0xE8, 0xE9}:
                continue
            if len(result) >= MAXIMUM_RELATIVE_EDGES:
                return None
            displacement = struct.unpack_from("<i", raw, offset + 1)[0]
            source = section_rva + offset
            result.append((source, opcode, source + 5 + displacement))
    return tuple(result)


def _bounded_disassembly(
    decoder: Cs,
    data: bytes,
    address: int,
    *,
    maximum_instructions: int,
) -> list[object] | None:
    """上限+1件だけ要求し、切捨てを検知した場合は全命令を破棄する。"""

    if (
        not isinstance(data, bytes)
        or type(address) is not int
        or type(maximum_instructions) is not int
        or maximum_instructions <= 0
    ):
        return None
    try:
        instructions = list(
            decoder.disasm(
                data,
                address,
                count=maximum_instructions + 1,
            )
        )
    except CsError:
        return None
    if len(instructions) > maximum_instructions:
        return None
    return instructions


def _constant_arguments(instructions: list[object], call_index: int) -> dict[str, int]:
    values: dict[str, int] = {}
    for instruction in instructions[:call_index]:
        operands = instruction.operands
        mnemonic = instruction.mnemonic.casefold()
        if not operands or operands[0].type != X86_OP_REG:
            continue
        target = _register_name(instruction, operands[0].reg)
        if (
            mnemonic == "xor"
            and len(operands) == 2
            and operands[1].type == X86_OP_REG
            and target == _register_name(instruction, operands[1].reg)
        ):
            values[target] = 0
        elif (
            mnemonic == "mov" and len(operands) == 2 and operands[1].type == X86_OP_IMM
        ):
            values[target] = int(operands[1].imm) & 0xFFFFFFFFFFFFFFFF
        elif (
            mnemonic == "mov" and len(operands) == 2 and operands[1].type == X86_OP_REG
        ):
            source = _register_name(instruction, operands[1].reg)
            if source in values:
                values[target] = values[source]
            else:
                values.pop(target, None)
        elif (
            mnemonic == "lea" and len(operands) == 2 and operands[1].type == X86_OP_MEM
        ):
            source = operands[1]
            if source.mem.index == X86_REG_INVALID:
                base = _register_name(instruction, source.mem.base)
                if base in values:
                    values[target] = (
                        values[base] + int(source.mem.disp)
                    ) & 0xFFFFFFFFFFFFFFFF
                else:
                    values.pop(target, None)
            else:
                values.pop(target, None)
        elif (
            mnemonic in {"add", "sub", "or"}
            and len(operands) == 2
            and operands[1].type == X86_OP_IMM
            and target in values
        ):
            immediate = int(operands[1].imm) & 0xFFFFFFFFFFFFFFFF
            if mnemonic == "add":
                values[target] = (values[target] + immediate) & 0xFFFFFFFFFFFFFFFF
            elif mnemonic == "sub":
                values[target] = (values[target] - immediate) & 0xFFFFFFFFFFFFFFFF
            else:
                values[target] |= immediate
        else:
            values.pop(target, None)
    return values


def _copy_candidate(
    context: _PeContext,
    instructions: list[object],
    call_index: int,
    size: int,
    relative_edges: tuple[tuple[int, int, int], ...],
) -> _OuterStage | None:
    aliases = {"rax"}
    source_rva: int | None = None
    source_loaded = False
    destination_loaded = False
    size_loaded = False
    rep_copy = False
    dword_copy = False
    byte_copy = False
    saw_quarter = False
    saw_remainder = False
    allocation_call_rva = instructions[call_index].address
    loader_low = allocation_call_rva - 80
    loader_high = allocation_call_rva + 1
    loader_call_sites = [
        source
        for source, opcode, target in relative_edges
        if opcode == 0xE8 and loader_low <= target < loader_high
    ]
    hook_proven = any(
        opcode == 0xE9 and call_site - 24 <= target <= call_site
        for call_site in loader_call_sites
        for _source, opcode, target in relative_edges
    )
    for instruction in instructions[call_index + 1 : call_index + 65]:
        mnemonic = instruction.mnemonic.casefold()
        operands = instruction.operands
        if mnemonic == "mov" and len(operands) == 2 and operands[0].type == X86_OP_REG:
            target = _register_name(instruction, operands[0].reg)
            if operands[1].type == X86_OP_REG:
                source = _register_name(instruction, operands[1].reg)
                if source in aliases:
                    aliases.add(target)
                else:
                    aliases.discard(target)
                if target == "rdi" and source in aliases:
                    destination_loaded = True
            elif operands[1].type == X86_OP_IMM:
                if target in {"rcx", "rdx"} and int(operands[1].imm) == size:
                    size_loaded = True
                aliases.discard(target)
            continue
        if mnemonic == "lea" and len(operands) == 2 and operands[0].type == X86_OP_REG:
            target = _register_name(instruction, operands[0].reg)
            source = operands[1]
            if (
                target == "rsi"
                and source.type == X86_OP_MEM
                and source.mem.base == X86_REG_RIP
                and source.mem.index == X86_REG_INVALID
            ):
                source_rva = (
                    instruction.address + instruction.size + int(source.mem.disp)
                )
                source_loaded = True
            aliases.discard(target)
            continue
        if mnemonic == "rep movsb":
            rep_copy = source_loaded and destination_loaded and size_loaded
            continue
        if mnemonic == "shr" and operands and operands[0].type == X86_OP_REG:
            saw_quarter |= (
                _register_name(instruction, operands[0].reg) == "rcx"
                and len(operands) == 2
                and operands[1].type == X86_OP_IMM
                and int(operands[1].imm) == 2
            )
        elif mnemonic == "and" and operands and operands[0].type == X86_OP_REG:
            saw_remainder |= (
                _register_name(instruction, operands[0].reg) == "rdx"
                and len(operands) == 2
                and operands[1].type == X86_OP_IMM
                and int(operands[1].imm) == 3
            )
        elif mnemonic == "lodsd":
            dword_copy = source_loaded and destination_loaded and size_loaded
        elif mnemonic == "lodsb":
            byte_copy = True
        if mnemonic == "jmp" and operands and operands[0].type == X86_OP_REG:
            target = _register_name(instruction, operands[0].reg)
            copy_kind: Literal["rep_movsb", "dword_and_byte_loops"] | None = None
            if target in aliases and rep_copy:
                copy_kind = "rep_movsb"
            elif (
                target in aliases
                and dword_copy
                and byte_copy
                and saw_quarter
                and saw_remainder
            ):
                copy_kind = "dword_and_byte_loops"
            if copy_kind is None or source_rva is None or not hook_proven:
                return None
            stage = _fully_file_backed(context, source_rva, size)
            if stage is None:
                return None
            return _OuterStage(
                data=stage,
                source_rva=source_rva,
                size=size,
                allocation_call_rva=allocation_call_rva,
                copy_kind=copy_kind,
                hook_trampoline_proven=True,
            )
    return None


def _outer_stage_candidates(context: _PeContext) -> tuple[_OuterStage, ...] | None:
    sections = _executable_sections(context)
    if sections is None:
        return None
    relative_edges = _relative_edges(sections)
    if relative_edges is None:
        return None
    calls: list[tuple[int, int, bytes]] = []
    for section_rva, raw in sections:
        for offset in range(max(0, len(raw) - 5)):
            if raw[offset : offset + 2] != b"\xff\x15":
                continue
            target = (
                section_rva + offset + 6 + struct.unpack_from("<i", raw, offset + 2)[0]
            )
            if context.imports.get(target) == "virtualalloc":
                instruction_offset = (
                    offset - 1
                    if offset > 0 and 0x40 <= raw[offset - 1] <= 0x4F
                    else offset
                )
                calls.append((section_rva + instruction_offset, section_rva, raw))
                if len(calls) > MAXIMUM_VIRTUAL_ALLOC_CALLS:
                    return None
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    candidates: list[_OuterStage] = []
    for call_rva, section_rva, raw in calls:
        call_offset = call_rva - section_rva
        sequences: list[list[object]] = []
        for distance in range(1, min(97, call_offset + 1)):
            start = call_offset - distance
            code = raw[start : min(len(raw), call_offset + 384)]
            instructions = list(decoder.disasm(code, section_rva + start))
            for index, instruction in enumerate(instructions):
                if instruction.address != call_rva:
                    continue
                if context.imports.get(_iat_call_rva(instruction)) == "virtualalloc":
                    sequences.append(instructions)
                break
        for instructions in sequences:
            call_indexes = [
                index
                for index, instruction in enumerate(instructions)
                if instruction.address == call_rva
            ]
            if len(call_indexes) != 1:
                continue
            call_index = call_indexes[0]
            values = _constant_arguments(instructions, call_index)
            size = values.get("rdx")
            if (
                values.get("rcx") != 0
                or type(size) is not int
                or not 4_096 <= size <= MAXIMUM_STAGE_SIZE
                or values.get("r8") not in {0x1000, 0x3000}
                or values.get("r9") != 0x40
            ):
                continue
            candidate = _copy_candidate(
                context,
                instructions,
                call_index,
                size,
                relative_edges,
            )
            if candidate is not None:
                candidates.append(candidate)
    unique: dict[tuple[int, int, bytes], _OuterStage] = {}
    for candidate in candidates:
        identity = (
            candidate.source_rva,
            candidate.size,
            hashlib.sha256(candidate.data).digest(),
        )
        unique[identity] = candidate
    return tuple(unique.values())


def _rotate_left32(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> ((32 - count) & 31))) & 0xFFFFFFFF


def _rotate_right32(value: int, count: int) -> int:
    count &= 31
    return ((value >> count) | (value << ((32 - count) & 31))) & 0xFFFFFFFF


def _patch_bootstrap(stage: bytes) -> tuple[bytes, int] | None:
    if not 64 <= len(stage) <= MAXIMUM_STAGE_SIZE or stage[0] != 0xE8:
        return None
    target = 5 + struct.unpack_from("<i", stage, 1)[0]
    if not len(stage) - 512 <= target < len(stage):
        return None
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    patched = bytearray(stage)
    pointers: dict[str, int] = {}
    stack = [5]
    pc = target
    seen: set[int] = set()
    patch_count = 0
    for _step in range(MAXIMUM_TAIL_STEPS):
        if pc in seen or not 0 <= pc < len(patched):
            return None
        seen.add(pc)
        instruction = next(
            decoder.disasm(bytes(patched[pc : pc + 15]), pc, count=1),
            None,
        )
        if instruction is None:
            return None
        mnemonic = instruction.mnemonic.casefold()
        operands = instruction.operands
        if mnemonic == "jmp" and len(operands) == 1:
            if operands[0].type == X86_OP_IMM:
                pc = int(operands[0].imm)
                continue
            if operands[0].type == X86_OP_REG:
                name = _register_name(instruction, operands[0].reg)
                if pointers.get(name) == 5 and patch_count >= 3:
                    return bytes(patched), patch_count
            return None
        if mnemonic == "pop" and len(operands) == 1 and operands[0].type == X86_OP_REG:
            if not stack:
                return None
            pointers[_register_name(instruction, operands[0].reg)] = stack.pop()
            pc += instruction.size
            continue
        if operands and operands[0].type == X86_OP_MEM:
            destination = operands[0]
            if (
                destination.mem.index != X86_REG_INVALID
                or destination.mem.base == X86_REG_INVALID
                or destination.size != 4
            ):
                return None
            base = pointers.get(_register_name(instruction, destination.mem.base))
            offset = -1 if base is None else base + int(destination.mem.disp)
            if not 5 <= offset <= 27 or offset + 4 > len(patched):
                return None
            value = int.from_bytes(patched[offset : offset + 4], "little")
            if mnemonic == "not" and len(operands) == 1:
                value = (~value) & 0xFFFFFFFF
            elif (
                mnemonic in {"add", "rol", "ror"}
                and len(operands) == 2
                and operands[1].type == X86_OP_IMM
            ):
                immediate = int(operands[1].imm)
                if mnemonic == "add":
                    value = (value + immediate) & 0xFFFFFFFF
                elif mnemonic == "rol":
                    value = _rotate_left32(value, immediate)
                else:
                    value = _rotate_right32(value, immediate)
            else:
                return None
            patched[offset : offset + 4] = value.to_bytes(4, "little")
            patch_count += 1
            pc += instruction.size
            continue
        same_register_cmov = (
            mnemonic.startswith("cmov")
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg)
            == _register_name(instruction, operands[1].reg)
        )
        same_register_xchg = (
            mnemonic == "xchg"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg)
            == _register_name(instruction, operands[1].reg)
        )
        xor_zero = (
            mnemonic == "xor"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_IMM
            and int(operands[1].imm) == 0
        )
        irrelevant_not = (
            mnemonic == "not"
            and len(operands) == 1
            and operands[0].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg) not in pointers
        )
        flag_only_register_noise = (
            mnemonic in {"bt", "test"}
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg)
            == _register_name(instruction, operands[1].reg)
            and _register_name(instruction, operands[0].reg) not in pointers
        )
        if (
            mnemonic == "clc"
            or same_register_cmov
            or same_register_xchg
            or xor_zero
            or irrelevant_not
            or flag_only_register_noise
        ):
            pc += instruction.size
            continue
        return None
    return None


def _feedback_layer(stage: bytes) -> _FeedbackLayer | None:
    patched_result = _patch_bootstrap(stage)
    if patched_result is None:
        return None
    patched, patch_count = patched_result
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    pc = 5
    key_register: str | None = None
    key: int | None = None
    count: int | None = None
    base_register: str | None = None
    base_offset: int | None = None
    xor_address: int | None = None
    add_proven = False
    loop_proven = False
    feedback_fallthrough: int | None = None
    for _step in range(MAXIMUM_BOOTSTRAP_STEPS):
        instruction = next(
            decoder.disasm(bytes(patched[pc : pc + 15]), pc, count=1),
            None,
        )
        if instruction is None:
            return None
        mnemonic = instruction.mnemonic.casefold()
        operands = instruction.operands
        if mnemonic == "jmp" and len(operands) == 1 and operands[0].type == X86_OP_IMM:
            target = int(operands[0].imm)
            pc = target
            continue
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_IMM
        ):
            name = _register_name(instruction, operands[0].reg)
            if operands[0].size == 1:
                key_register = name
                key = int(operands[1].imm) & 0xFF
            elif name == "rcx":
                count = int(operands[1].imm)
        elif (
            mnemonic == "lea"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.base == X86_REG_RIP
            and operands[1].mem.index == X86_REG_INVALID
        ):
            base_register = _register_name(instruction, operands[0].reg)
            base_offset = (
                instruction.address + instruction.size + int(operands[1].mem.disp)
            )
        elif (
            mnemonic == "xor" and len(operands) == 2 and operands[0].type == X86_OP_MEM
        ):
            memory = operands[0]
            if (
                memory.size != 1
                or memory.mem.base == X86_REG_INVALID
                or memory.mem.index != X86_REG_RCX
                or operands[1].type != X86_OP_REG
                or _register_name(instruction, memory.mem.base) != base_register
                or _register_name(instruction, operands[1].reg) != key_register
            ):
                return None
            xor_address = instruction.address
        elif (
            mnemonic == "add" and len(operands) == 2 and operands[1].type == X86_OP_MEM
        ):
            memory = operands[1]
            add_proven = bool(
                operands[0].type == X86_OP_REG
                and _register_name(instruction, operands[0].reg) == key_register
                and memory.size == 1
                and memory.mem.index == X86_REG_RCX
                and memory.mem.base != X86_REG_INVALID
                and _register_name(instruction, memory.mem.base) == base_register
            )
        elif (
            mnemonic == "loop" and len(operands) == 1 and operands[0].type == X86_OP_IMM
        ):
            loop_proven = int(operands[0].imm) == xor_address and add_proven
            if loop_proven:
                feedback_fallthrough = instruction.address + instruction.size
                break
        pc += instruction.size
    if (
        key is None
        or count is None
        or base_offset is None
        or feedback_fallthrough is None
        or not loop_proven
        or not 1_024 <= count <= len(patched)
        or not 0 <= base_offset + 1 <= base_offset + count < len(patched)
    ):
        return None
    decoded = bytearray(patched)
    running_key = key
    for index in range(count, 0, -1):
        offset = base_offset + index
        decoded[offset] ^= running_key
        running_key = (running_key + decoded[offset]) & 0xFF
    entry_pc = feedback_fallthrough
    entry_seen: set[int] = set()
    main_offset: int | None = None
    for _step in range(8):
        if entry_pc in entry_seen or not 0 <= entry_pc < len(decoded):
            return None
        entry_seen.add(entry_pc)
        entry = next(
            decoder.disasm(
                bytes(decoded[entry_pc : entry_pc + 15]),
                entry_pc,
                count=1,
            ),
            None,
        )
        if entry is None:
            return None
        operands = entry.operands
        if (
            entry.mnemonic.casefold() == "jmp"
            and len(operands) == 1
            and operands[0].type == X86_OP_IMM
        ):
            target = int(operands[0].imm)
            if target > 0x100:
                main_offset = target
                break
            if not feedback_fallthrough <= target <= feedback_fallthrough + 64:
                return None
            entry_pc = target
            continue
        same_register_compare = (
            entry.mnemonic.casefold() == "cmp"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_REG
            and _register_name(entry, operands[0].reg)
            == _register_name(entry, operands[1].reg)
        )
        if not same_register_compare:
            return None
        entry_pc += entry.size
    if main_offset is None or not 0 <= main_offset < len(decoded):
        return None
    return _FeedbackLayer(
        data=bytes(decoded),
        main_offset=main_offset,
        patch_operation_count=patch_count,
        feedback_count=count,
    )


def _stack_strings(instructions: list[object]) -> dict[tuple[int, int], bytes]:
    result: dict[tuple[int, int], bytes] = {}
    index = 0
    while index < len(instructions):
        writes: dict[int, int] = {}
        start_address = instructions[index].address
        current = index
        while current < len(instructions):
            instruction = instructions[current]
            operands = instruction.operands
            if not (
                instruction.mnemonic.casefold() == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_MEM
                and operands[0].size == 1
                and operands[0].mem.base == X86_REG_RSP
                and operands[0].mem.index == X86_REG_INVALID
                and operands[1].type == X86_OP_IMM
            ):
                break
            writes[int(operands[0].mem.disp)] = int(operands[1].imm) & 0xFF
            current += 1
        for start in sorted(writes):
            if start - 1 in writes:
                continue
            value = bytearray()
            position = start
            while position in writes and writes[position] != 0:
                byte = writes[position]
                if not 0x20 <= byte <= 0x7E:
                    value.clear()
                    break
                value.append(byte)
                position += 1
            if len(value) >= 4 and writes.get(position) == 0:
                result[(start_address, start)] = bytes(value)
        index = max(index + 1, current)
    return result


def _stack_operand(instruction: object, operand: object) -> int | None:
    if (
        operand.type == X86_OP_MEM
        and operand.mem.base == X86_REG_RSP
        and operand.mem.index == X86_REG_INVALID
    ):
        return int(operand.mem.disp)
    return None


def _xor_helper_proven(data: bytes, target: int) -> bool:
    if not 0 <= target < len(data):
        return False
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(data[target : target + 256], target))
    if len(instructions) < 20:
        return False
    saved_inputs: set[str] = set()
    for instruction in instructions[:5]:
        operands = instruction.operands
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[1].type == X86_OP_REG
        ):
            saved_inputs.add(_register_name(instruction, operands[1].reg))
    if not {"rcx", "rdx", "r8"}.issubset(saved_inputs):
        return False
    saw_key_nul_compare = False
    saw_length_bound = False
    saw_xor = False
    saw_byte_write = False
    saw_backward_jump = False
    saw_return = False
    for instruction in instructions:
        operands = instruction.operands
        mnemonic = instruction.mnemonic.casefold()
        if mnemonic == "cmp" and len(operands) == 2:
            saw_key_nul_compare |= (
                operands[0].type == X86_OP_MEM
                and operands[0].size == 1
                and operands[1].type == X86_OP_IMM
                and int(operands[1].imm) == 0
            )
            saw_length_bound |= (
                operands[0].type == X86_OP_MEM and operands[1].type == X86_OP_REG
            )
        elif mnemonic == "xor" and len(operands) == 2:
            saw_xor |= operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG
        elif mnemonic == "mov" and len(operands) == 2:
            saw_byte_write |= operands[0].type == X86_OP_MEM and operands[0].size == 1
        elif (
            instruction.group(CS_GRP_JUMP)
            and operands
            and operands[0].type == X86_OP_IMM
        ):
            saw_backward_jump |= int(operands[0].imm) < instruction.address
        elif mnemonic == "ret":
            saw_return = True
            break
    return all(
        (
            saw_key_nul_compare,
            saw_length_bound,
            saw_xor,
            saw_byte_write,
            saw_backward_jump,
            saw_return,
        )
    )


def _component_layer(layer: _FeedbackLayer) -> _ComponentLayer | None:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(
        decoder.disasm(
            layer.data[layer.main_offset :],
            layer.main_offset,
            count=MAXIMUM_MAIN_INSTRUCTIONS,
        )
    )
    if len(instructions) < 100:
        return None
    strings = _stack_strings(instructions)
    stack_constants: dict[int, int] = {}
    for instruction in instructions:
        operands = instruction.operands
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[1].type == X86_OP_IMM
        ):
            displacement = _stack_operand(instruction, operands[0])
            if displacement is not None:
                stack_constants[displacement] = (
                    int(operands[1].imm) & 0xFFFFFFFFFFFFFFFF
                )
    candidates: list[_ComponentLayer] = []
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        if not (
            instruction.mnemonic.casefold() == "lea"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg) == "rdx"
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.base == X86_REG_RIP
            and operands[1].mem.index == X86_REG_INVALID
        ):
            continue
        source = instruction.address + instruction.size + int(operands[1].mem.disp)
        if not 0 <= source < layer.main_offset:
            continue
        length_slots: list[int] = []
        buffer_slots: list[int] = []
        for nearby in instructions[max(0, index - 8) : index + 8]:
            nearby_operands = nearby.operands
            if (
                nearby.mnemonic.casefold() == "mov"
                and len(nearby_operands) == 2
                and nearby_operands[0].type == X86_OP_REG
                and nearby_operands[1].type == X86_OP_MEM
            ):
                name = _register_name(nearby, nearby_operands[0].reg)
                displacement = _stack_operand(nearby, nearby_operands[1])
                if displacement is not None and name == "r8":
                    length_slots.append(displacement)
                elif displacement is not None and name == "rcx":
                    buffer_slots.append(displacement)
        for length_slot in length_slots:
            length = stack_constants.get(length_slot)
            if type(length) is not int or not 4_096 <= length <= MAXIMUM_COMPONENT_SIZE:
                continue
            if source + length > len(layer.data):
                continue
            for buffer_slot in buffer_slots:
                key_displacements: list[tuple[int, int]] = []
                xor_target: int | None = None
                for next_index in range(index + 1, min(len(instructions), index + 50)):
                    current = instructions[next_index]
                    current_operands = current.operands
                    if (
                        current.mnemonic.casefold() == "lea"
                        and len(current_operands) == 2
                        and current_operands[0].type == X86_OP_REG
                        and _register_name(current, current_operands[0].reg) == "r8"
                    ):
                        displacement = _stack_operand(current, current_operands[1])
                        if displacement is not None:
                            key_displacements.append((next_index, displacement))
                    if (
                        current.mnemonic.casefold() == "call"
                        and current_operands
                        and current_operands[0].type == X86_OP_IMM
                        and key_displacements
                    ):
                        window = instructions[max(index, next_index - 5) : next_index]
                        has_length = any(
                            item.mnemonic.casefold() == "mov"
                            and item.operands
                            and item.operands[0].type == X86_OP_REG
                            and _register_name(item, item.operands[0].reg) == "rdx"
                            and len(item.operands) == 2
                            and _stack_operand(item, item.operands[1]) == length_slot
                            for item in window
                        )
                        has_buffer = any(
                            item.mnemonic.casefold() == "mov"
                            and item.operands
                            and item.operands[0].type == X86_OP_REG
                            and _register_name(item, item.operands[0].reg) == "rcx"
                            and len(item.operands) == 2
                            and _stack_operand(item, item.operands[1]) == buffer_slot
                            for item in window
                        )
                        if has_length and has_buffer:
                            xor_target = int(current_operands[0].imm)
                            key_index, key_displacement = key_displacements[-1]
                            break
                if xor_target is None or not _xor_helper_proven(layer.data, xor_target):
                    continue
                key_values = [
                    value
                    for (address, displacement), value in strings.items()
                    if displacement == key_displacement
                    and address <= instructions[key_index].address
                    and 8 <= len(value) <= 64
                ]
                if len(key_values) != 1:
                    continue
                key = key_values[0]
                following = instructions[index : min(len(instructions), index + 180)]
                names = set(_stack_strings(following).values())
                if b"VirtualProtect" not in names:
                    continue
                saw_protect = False
                saw_component_call = False
                for next_index, current in enumerate(following):
                    current_operands = current.operands
                    if current.mnemonic.casefold() == "call" and current_operands:
                        if current_operands[0].type == X86_OP_MEM:
                            window = following[max(0, next_index - 8) : next_index]
                            protect_arguments = {
                                _register_name(item, item.operands[0].reg): item
                                for item in window
                                if item.mnemonic.casefold() in {"mov", "lea"}
                                and item.operands
                                and item.operands[0].type == X86_OP_REG
                            }
                            rcx_item = protect_arguments.get("rcx")
                            rdx_item = protect_arguments.get("rdx")
                            r8_item = protect_arguments.get("r8")
                            if rcx_item and rdx_item and r8_item:
                                saw_protect |= (
                                    _stack_operand(rcx_item, rcx_item.operands[1])
                                    == buffer_slot
                                    and _stack_operand(rdx_item, rdx_item.operands[1])
                                    == length_slot
                                    and r8_item.operands[1].type == X86_OP_IMM
                                    and int(r8_item.operands[1].imm) == 0x40
                                )
                        elif current_operands[0].type == X86_OP_REG:
                            saw_component_call |= saw_protect
                    if (
                        current.mnemonic.casefold() == "call"
                        and current_operands[0].type == X86_OP_MEM
                    ):
                        displacement = _stack_operand(current, current_operands[0])
                        if displacement is not None:
                            for previous in following[
                                max(0, next_index - 4) : next_index
                            ]:
                                previous_operands = previous.operands
                                if (
                                    previous.mnemonic.casefold() == "mov"
                                    and len(previous_operands) == 2
                                    and _stack_operand(previous, previous_operands[0])
                                    == displacement
                                    and previous_operands[1].type == X86_OP_REG
                                    and _register_name(
                                        previous, previous_operands[1].reg
                                    )
                                    == "rax"
                                ):
                                    saw_component_call |= saw_protect
                if not saw_protect or not saw_component_call:
                    continue
                encoded = layer.data[source : source + length]
                decoded = bytes(
                    value ^ key[index % len(key)] for index, value in enumerate(encoded)
                )
                candidates.append(
                    _ComponentLayer(
                        data=decoded,
                        source_offset=source,
                        key_length=len(key),
                        main_offset=layer.main_offset,
                    )
                )
    unique = {
        (item.source_offset, hashlib.sha256(item.data).digest()): item
        for item in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _route_record_count(data: bytes) -> int:
    count = 0
    start = 0
    while True:
        offset = data.find(ROUTE_MARKER, start)
        if offset < 0:
            break
        start = offset + 1
        end = offset + len(ROUTE_MARKER) + ROUTE_RECORD_SIZE
        if end > len(data):
            continue
        record = bytes(value ^ 0xFE for value in data[offset + 4 : end])
        address = record[0:4]
        port = int.from_bytes(record[4:6], "little")
        route_one = record[8:18]
        secondary_value = int.from_bytes(record[20:22], "little")
        final_end = next((index for index in range(24, 32) if record[index] == 0), 32)
        route_three = record[24:final_end]
        if (
            address in {b"\0\0\0\0", b"\xff\xff\xff\xff"}
            or port == 0
            or record[6:8] != b"\0\0"
            or record[18:20] != b"\0\0"
            or secondary_value == 0
            or record[22:24] != b"\0\0"
            or not 4 <= len(route_three) <= 7
            or record[-1] != 0
            or not all(0x20 <= value <= 0x7E for value in route_one + route_three)
        ):
            continue
        count += 1
    return count


def _component_profile(component: bytes) -> dict[str, object] | None:
    if not 4_096 <= len(component) <= MAXIMUM_COMPONENT_SIZE:
        return None
    entry = 0
    if component[0] == 0xE9 and len(component) >= 5:
        entry = 5 + struct.unpack_from("<i", component, 1)[0]
    if not 0 <= entry < len(component):
        return None
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = _bounded_disassembly(
        decoder,
        component[entry:],
        entry,
        maximum_instructions=MAXIMUM_COMPONENT_INSTRUCTIONS,
    )
    if instructions is None:
        return None
    if len(instructions) < 1_000:
        return None
    strings = _stack_strings(instructions)
    names = set(strings.values())
    required_transport = {
        b"wininet.dll",
        b"InternetOpenA",
        b"InternetOpenUrlA",
        b"InternetReadFile",
        b"InternetCloseHandle",
    }
    required_file_write = {b"CreateFileA", b"WriteFile"}
    process_launch_alternatives = {
        b"CreateProcessA",
        b"ShellExecuteA",
        b"ShellExecuteExA",
    }
    if (
        not required_transport.issubset(names)
        or not required_file_write.issubset(names)
        or not names.intersection(process_launch_alternatives)
    ):
        return None
    transport_addresses = [
        address
        for (address, _displacement), value in strings.items()
        if value in required_transport
    ]
    if (
        not transport_addresses
        or max(transport_addresses) - min(transport_addresses) > 1_024
    ):
        return None
    transport_low = min(transport_addresses) - 128
    transport_high = max(transport_addresses) + 2_048
    window = [
        item for item in instructions if transport_low <= item.address <= transport_high
    ]
    direct_calls = sum(
        item.group(CS_GRP_CALL)
        and item.operands
        and item.operands[0].type == X86_OP_IMM
        for item in window
    )
    indirect_calls = sum(
        item.group(CS_GRP_CALL)
        and item.operands
        and item.operands[0].type != X86_OP_IMM
        for item in window
    )
    back_edges = sum(
        item.group(CS_GRP_JUMP)
        and item.operands
        and item.operands[0].type == X86_OP_IMM
        and int(item.operands[0].imm) < item.address
        for item in window
    )
    registry_handoff = component.count(b"SOFTWARE\\JDBCC") >= 2
    if direct_calls < 4 or indirect_calls < 6 or back_edges < 1 or not registry_handoff:
        return None
    socket_names = {
        b"WSAStartup",
        b"socket",
        b"connect",
        b"send",
        b"recv",
        b"WSASend",
        b"WSARecv",
    }
    return {
        "profile": "silverfox_style_infection_downloader_component",
        "wininet_get_read_retry_lineage_proven": True,
        "file_write_and_process_capability_proven": True,
        "registry_handoff_structure_proven": True,
        "valleyrat_socket_api_marker_count": len(names & socket_names),
        "endpoint_values_included": False,
        "raw_command_values_included": False,
    }


def analyze_silverfox_loader_lineage(data: bytes) -> SilverFoxLoaderLineage | None:
    """outer PEを多段復元し、loader証拠とValleyRAT非昇格を返す。"""

    context = _load_pe(data)
    if context is None:
        return None
    candidates = _outer_stage_candidates(context)
    if candidates is None:
        return None
    matched = bool(candidates)
    missing: list[str] = []
    outer = candidates[0] if len(candidates) == 1 else None
    if len(candidates) > 1:
        missing.append("multiple_outer_stage_interpretations_ambiguous")
    elif outer is None:
        missing.append("outer_virtualalloc_copy_jump_lineage_unproven")
    route_count = _route_record_count(data)
    if route_count != 1:
        missing.append(
            "route_record_ambiguous" if route_count > 1 else "route_record_unproven"
        )
    feedback = _feedback_layer(outer.data) if outer is not None else None
    if feedback is None:
        missing.append("feedback_decoder_lineage_unproven")
    component_layer = _component_layer(feedback) if feedback is not None else None
    if component_layer is None:
        missing.append("repeating_xor_component_lineage_unproven")
    profile = (
        _component_profile(component_layer.data)
        if component_layer is not None
        else None
    )
    if profile is None:
        missing.append("infection_downloader_sink_lineage_unproven")
    validated_loader = bool(
        outer is not None
        and route_count == 1
        and feedback is not None
        and component_layer is not None
        and profile is not None
    )
    if not matched and not validated_loader:
        return None
    if validated_loader:
        missing.extend(
            [
                "valleyrat_terminal_component_unproven",
                "valleyrat_terminal_config_to_connect_send_receive_unproven",
                "valleyrat_terminal_protocol_unproven",
            ]
        )
    observation: dict[str, object] = {
        "schema_version": 1,
        "status": (
            "validated_silverfox_style_infection_loader_lineage"
            if validated_loader
            else "silverfox_style_loader_candidate_incomplete_lineage"
        ),
        "matched": matched,
        "component_profile": (
            "silverfox_style_infection_loader"
            if validated_loader
            else "native_loader_candidate"
        ),
        "outer_stage_candidate_count": len(candidates),
        "outer_stage": (
            {
                "size": outer.size,
                "copy_kind": outer.copy_kind,
                "virtualalloc_exact_copy_jump_proven": True,
                "hook_trampoline_proven": outer.hook_trampoline_proven,
                "source_rva_included": False,
            }
            if outer is not None
            else None
        ),
        "route_config": {
            "record_count": route_count,
            "record_size": ROUTE_RECORD_SIZE if route_count == 1 else None,
            "marker_to_xor_record_structure_proven": route_count == 1,
            "endpoint_values_included": False,
            "used_for_valleyrat_c2_confirmation": False,
        },
        "decoders": (
            {
                "tail_patch_operation_count": feedback.patch_operation_count,
                "reverse_feedback_count": feedback.feedback_count,
                "repeating_xor_key_length": component_layer.key_length,
                "decoded_component_size": len(component_layer.data),
                "decoded_component_hash_included": False,
                "key_included": False,
            }
            if feedback is not None and component_layer is not None
            else None
        ),
        "downstream": profile,
        "missing_proof_codes": missing,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "terminal_network_lineage_proven": False,
        "terminal_protocol_lineage_proven": False,
        "candidate_only": True,
        "hash_or_filename_rule_used": False,
        "external_label_used": False,
        "endpoint_values_included": False,
        "raw_payload_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    return SilverFoxLoaderLineage(
        observation=observation,
        recovered_component=component_layer.data if validated_loader else None,
    )


__all__ = [
    "MAXIMUM_INPUT_SIZE",
    "SilverFoxLoaderLineage",
    "analyze_silverfox_loader_lineage",
]
