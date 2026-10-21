"""webio/wer同梱loader候補から手動確認用のroute候補を復元する。

このmoduleは、x64 root PE内のfile-backed blobへ既知の復号手順を適用する。
ただしentry pointからdecoderへの到達性、runtime dispatch slotとcipherの束縛、
markerからHTTP consumerまでの完全なCFG／data-flowは証明していない。このため
結果は自動判定、family帰属、static config、C2確定へ使用せず、手動確認用の
未検証候補としてのみ返す。
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

import pefile
from capstone import CS_ARCH_X86, CS_GRP_JUMP, CS_MODE_64, Cs, CsError
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EAX,
    X86_REG_RAX,
    X86_REG_RBP,
    X86_REG_RBX,
    X86_REG_RIP,
    X86_REG_RSI,
    X86_REG_RSP,
)

MAXIMUM_INPUT_SIZE = 128 * 1024 * 1024
MAXIMUM_BLOB_SIZE = 4 * 1024 * 1024
MAXIMUM_STAGE_SIZE = 16 * 1024 * 1024
MAXIMUM_FUNCTION_SIZE = 64 * 1024
MAXIMUM_INSTRUCTIONS = 32_768
MAXIMUM_EXECUTABLE_SECTION_SIZE = 8 * 1024 * 1024
MAXIMUM_TOTAL_EXECUTABLE_SIZE = 16 * 1024 * 1024
MAXIMUM_DISPATCH_INITIALIZERS = 128
MAXIMUM_CALL_GRAPH_PENDING = 1_024
WEBIO_CONFIG_SIZE = 0xA88
DISPATCH_SLOT_COUNT = 10
CUSTOM_CIPHER_SLOT = 2
HTTP_ROUTE_FORMAT = "http://%hs:%d/getinstall64".encode("utf-16le")
WININET_LIBRARY = "wininet.dll".encode("utf-16le")
HTTP_AGENT = "Downloader".encode("utf-16le")
_CIPHER_CONSTANTS = (0xCAAAFE23, 0x3D57AA23, 0x44D9BB23, 0x9E37CB23)


@dataclass(frozen=True)
class SilverFoxWebioStageRoute:
    """公開可能な未検証route候補だけを保持する。復元byteや生鍵は保持しない。"""

    observation: dict[str, object]


@dataclass(frozen=True)
class _PeContext:
    data: bytes
    image: pefile.PE
    image_base: int


@dataclass(frozen=True)
class _RootBinding:
    blob_rva: int
    blob_size: int
    decoder_rva: int


@dataclass(frozen=True)
class _DispatchProof:
    table_rva: int
    cipher_wrapper_rva: int


@dataclass(frozen=True)
class _RecoveredRoute:
    host: str
    port: int
    transport: str
    prefix_skip: int
    source_blob_size: int
    stage1_size: int
    key_size: int
    encrypted_stage_size: int
    stage2_size: int
    marker_offset: int
    encrypted_config_size: int
    config_size: int


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _rol32(value: int, count: int) -> int:
    value = _u32(value)
    return _u32((value << count) | (value >> (32 - count)))


def _transform_byte(value: int) -> int:
    first = ((~value) + value * 8) & 0xFF
    return ((first ^ ((first >> 5) | ((first * 4) & 0xFF))) + 0x83) & 0xFF


def _custom_cipher_transform(key: bytes, source: bytes) -> bytes:
    """rootのdispatch slot 2が使う対称変換を境界付きで再現する。"""

    if not 1 <= len(key) <= 0x100 or len(source) > MAXIMUM_STAGE_SIZE:
        raise ValueError("invalid custom cipher input")
    state = len(key) ^ 0xCAAAFE23
    for index, value in enumerate(key):
        transformed = _transform_byte(value)
        state = _u32(state ^ (transformed << ((index % 4) * 8)))
        state = _u32(_rol32(state, 7) + 0x3D57AA23)
        state = _u32(state ^ (state >> ((index % 5) + 3)))
    output = bytearray(source)
    for index in range(len(output)):
        transformed = _transform_byte(key[index % len(key)])
        mixed = _u32(state ^ (transformed << ((index % 4) * 8)))
        mixed = _u32(_rol32(mixed, 5) * 0x44D9BB23)
        mixed = _u32(mixed ^ (mixed >> 11) ^ _u32(state << ((index % 3) + 1)))
        output[index] ^= (
            (mixed & 0xFF) ^ ((mixed >> 16) & 0xFF) ^ _transform_byte(state & 0xFF)
        )
        state = _u32(_rol32(state, 3) ^ mixed)
        state = _u32(
            state
            + (_u32((index + 1) * 0x9E37CB23) ^ (transformed << ((index % 4) * 6)))
        )
    return bytes(output)


def _match_length_bits(size: int) -> int:
    for threshold, bits in (
        (0x10, 12),
        (0x20, 11),
        (0x40, 10),
        (0x80, 9),
        (0x100, 8),
        (0x200, 7),
        (0x400, 6),
        (0x800, 5),
    ):
        if size < threshold:
            return bits
    return 4


def _lznt1_decompress(source: bytes, *, output_limit: int) -> bytes:
    """LZNT1 block streamをOS APIや検体実行なしで復号する。"""

    if not source or not 0 < output_limit <= MAXIMUM_STAGE_SIZE:
        raise ValueError("invalid LZNT1 bounds")
    output = bytearray()
    position = 0
    while position < len(source):
        if position + 2 > len(source):
            raise ValueError("truncated LZNT1 header")
        token = struct.unpack_from("<H", source, position)[0]
        position += 2
        if token == 0:
            if any(source[position:]):
                raise ValueError("non-zero data follows LZNT1 terminator")
            position = len(source)
            break
        if token & 0x7000 != 0x3000:
            raise ValueError("invalid LZNT1 chunk signature")
        block_size = (token & 0x0FFF) + 1
        block_end = position + block_size
        if block_end > len(source):
            raise ValueError("truncated LZNT1 chunk")
        block_output_base = len(output)
        if not token & 0x8000:
            if len(output) + block_size > output_limit:
                raise ValueError("LZNT1 output limit exceeded")
            output.extend(source[position:block_end])
            position = block_end
            continue
        while position < block_end:
            flags = source[position]
            position += 1
            for bit_index in range(8):
                if position >= block_end:
                    break
                if not (flags >> bit_index) & 1:
                    if len(output) >= output_limit:
                        raise ValueError("LZNT1 output limit exceeded")
                    output.append(source[position])
                    position += 1
                    continue
                if position + 2 > block_end:
                    raise ValueError("truncated LZNT1 match")
                match = struct.unpack_from("<H", source, position)[0]
                position += 2
                block_output_size = len(output) - block_output_base
                if not block_output_size:
                    raise ValueError("LZNT1 match precedes literal")
                bits = _match_length_bits(block_output_size)
                match_length = (match & ((1 << bits) - 1)) + 3
                distance = (match >> bits) + 1
                if distance > block_output_size:
                    raise ValueError("LZNT1 match crosses chunk boundary")
                if len(output) + match_length > output_limit:
                    raise ValueError("LZNT1 output limit exceeded")
                for _ in range(match_length):
                    output.append(output[-distance])
    if position != len(source) or not output:
        raise ValueError("incomplete LZNT1 stream")
    return bytes(output)


def _xor_swap_stream_transform(key: bytes, source: bytes) -> bytes:
    """stage2のRC4 KSAとXOR-swap PRGAを等価に適用する。"""

    if not 1 <= len(key) <= 0x100 or len(source) > MAXIMUM_STAGE_SIZE:
        raise ValueError("invalid XOR-swap input")
    state = list(range(0x100))
    swap_index = 0
    for index in range(0x100):
        swap_index = (swap_index + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]
    index = 0
    swap_index = 0
    output = bytearray(source)
    for offset, value in enumerate(output):
        index = (index + 1) & 0xFF
        swap_index = (swap_index + state[index]) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]
        output[offset] = value ^ state[index] ^ state[swap_index]
    return bytes(output)


def _load_pe(data: bytes) -> _PeContext | None:
    if (
        type(data) is not bytes
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
        if len(image.sections) > 96:
            return None
        executable_sizes = [
            int(section.SizeOfRawData)
            for section in image.sections
            if int(section.Characteristics) & 0x20000000
        ]
        if (
            any(size > MAXIMUM_EXECUTABLE_SECTION_SIZE for size in executable_sizes)
            or sum(executable_sizes) > MAXIMUM_TOTAL_EXECUTABLE_SIZE
        ):
            return None
    except (AttributeError, OverflowError, TypeError, ValueError, pefile.PEFormatError):
        return None
    return _PeContext(data=data, image=image, image_base=image_base)


def _section_for_rva(context: _PeContext, rva: int):
    for section in context.image.sections:
        start = int(section.VirtualAddress)
        span = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if start <= rva < start + span:
            return section
    return None


def _is_executable_rva(context: _PeContext, rva: int) -> bool:
    section = _section_for_rva(context, rva)
    return bool(section is not None and int(section.Characteristics) & 0x20000000)


def _fully_file_backed(
    context: _PeContext,
    rva: int,
    size: int,
    *,
    maximum_size: int = MAXIMUM_STAGE_SIZE,
) -> bytes | None:
    if not 0 <= rva or not 0 < size <= maximum_size:
        return None
    section = _section_for_rva(context, rva)
    if section is None:
        return None
    section_rva = int(section.VirtualAddress)
    relative = rva - section_rva
    raw_size = int(section.SizeOfRawData)
    raw_offset = int(section.PointerToRawData)
    if relative < 0 or relative + size > raw_size:
        return None
    offset = raw_offset + relative
    if not 0 <= offset <= len(context.data) - size:
        return None
    return context.data[offset : offset + size]


def _bounded_function_bytes(
    context: _PeContext,
    rva: int,
    *,
    maximum_size: int = MAXIMUM_FUNCTION_SIZE,
) -> bytes | None:
    section = _section_for_rva(context, rva)
    if section is None or not int(section.Characteristics) & 0x20000000:
        return None
    relative = rva - int(section.VirtualAddress)
    remaining = int(section.SizeOfRawData) - relative
    if remaining <= 0:
        return None
    return _fully_file_backed(
        context,
        rva,
        min(remaining, maximum_size),
        maximum_size=maximum_size,
    )


def _disassemble(data: bytes, address: int, *, maximum: int = MAXIMUM_INSTRUCTIONS):
    if (
        type(maximum) is not int
        or not 1 <= maximum <= MAXIMUM_INSTRUCTIONS
        or len(data) > MAXIMUM_FUNCTION_SIZE
    ):
        return None
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    try:
        instructions = list(decoder.disasm(data, address, count=maximum + 1))
    except CsError:
        return None
    if len(instructions) > maximum:
        return None
    return instructions


def _register_name(instruction, register: int) -> str:
    """Capstone register IDを比較用の正規名へ変換する。"""

    return instruction.reg_name(register).casefold()


def _root_chain_candidates(context: _PeContext) -> tuple[_RootBinding, ...] | None:
    candidates: list[_RootBinding] = []
    for section in context.image.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        raw_offset = int(section.PointerToRawData)
        raw_size = min(int(section.SizeOfRawData), len(context.data) - raw_offset)
        raw = context.data[raw_offset : raw_offset + raw_size]
        section_rva = int(section.VirtualAddress)
        for offset in range(max(0, len(raw) - 48 + 1)):
            cursor = offset
            state_rva: int | None = None
            calls: list[int] = []
            for _ in range(4):
                if raw[cursor : cursor + 3] != b"\x48\x8b\x0d":
                    break
                instruction_rva = section_rva + cursor
                state = (
                    instruction_rva + 7 + struct.unpack_from("<i", raw, cursor + 3)[0]
                )
                if state_rva is None:
                    state_rva = state
                elif state != state_rva:
                    break
                if raw[cursor + 7] != 0xE8:
                    break
                call_rva = (
                    instruction_rva + 12 + struct.unpack_from("<i", raw, cursor + 8)[0]
                )
                calls.append(call_rva)
                cursor += 12
            if len(calls) != 4 or len(set(calls)) != 4:
                continue
            if not all(_is_executable_rva(context, target) for target in calls):
                continue
            produced = _producer_blob(context, calls[0])
            if produced is None:
                continue
            blob_rva, blob_size = produced
            candidates.append(_RootBinding(blob_rva, blob_size, calls[3]))
    unique = {
        (item.blob_rva, item.blob_size, item.decoder_rva): item for item in candidates
    }
    if len(unique) > 128:
        return None
    return tuple(unique.values())


def _producer_blob(context: _PeContext, function_rva: int) -> tuple[int, int] | None:
    raw = _bounded_function_bytes(context, function_rva, maximum_size=128)
    if raw is None:
        return None
    instructions = _disassemble(raw, context.image_base + function_rva, maximum=128)
    if instructions is None:
        return None
    found: set[tuple[int, int]] = set()
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        if not (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg != 0
            and _register_name(instruction, operands[0].reg) == "r8d"
            and operands[1].type == X86_OP_IMM
        ):
            continue
        size = int(operands[1].imm)
        if not 0x40 <= size <= MAXIMUM_BLOB_SIZE:
            continue
        for candidate in instructions[index + 1 : index + 5]:
            values = candidate.operands
            if not (
                candidate.mnemonic.casefold() == "lea"
                and len(values) == 2
                and values[0].type == X86_OP_REG
                and _register_name(candidate, values[0].reg) == "rdx"
                and values[1].type == X86_OP_MEM
                and values[1].mem.base == X86_REG_RIP
            ):
                continue
            target_va = candidate.address + candidate.size + int(values[1].mem.disp)
            target_rva = target_va - context.image_base
            if (
                _fully_file_backed(
                    context,
                    target_rva,
                    size,
                    maximum_size=MAXIMUM_BLOB_SIZE,
                )
                is not None
            ):
                found.add((target_rva, size))
    return next(iter(found)) if len(found) == 1 else None


def _dispatch_initializers(
    context: _PeContext,
) -> tuple[tuple[int, tuple[int, ...]], ...]:
    found: dict[tuple[int, tuple[int, ...]], tuple[int, tuple[int, ...]]] = {}
    pair_size = 12
    total_size = pair_size * DISPATCH_SLOT_COUNT
    for section in context.image.sections:
        if not int(section.Characteristics) & 0x20000000:
            continue
        raw_offset = int(section.PointerToRawData)
        raw_size = min(int(section.SizeOfRawData), len(context.data) - raw_offset)
        raw = context.data[raw_offset : raw_offset + raw_size]
        section_rva = int(section.VirtualAddress)
        for offset in range(max(0, len(raw) - total_size + 1)):
            factories: list[int] = []
            table_entries: list[int] = []
            for slot in range(DISPATCH_SLOT_COUNT):
                current = offset + slot * pair_size
                if (
                    raw[current] != 0xE8
                    or raw[current + 5 : current + 8] != b"\x48\x89\x05"
                ):
                    break
                instruction_rva = section_rva + current
                factories.append(
                    instruction_rva + 5 + struct.unpack_from("<i", raw, current + 1)[0]
                )
                table_entries.append(
                    instruction_rva
                    + pair_size
                    + struct.unpack_from("<i", raw, current + 8)[0]
                )
            if len(factories) != DISPATCH_SLOT_COUNT:
                continue
            table_base = table_entries[0]
            if table_entries != [
                table_base + index * 8 for index in range(DISPATCH_SLOT_COUNT)
            ]:
                continue
            if not all(_is_executable_rva(context, item) for item in factories):
                continue
            key = (table_base, tuple(factories))
            found[key] = key
            if len(found) > MAXIMUM_DISPATCH_INITIALIZERS:
                return ()
    return tuple(found.values())


def _static_factory_return(context: _PeContext, factory_rva: int) -> int | None:
    raw = _bounded_function_bytes(context, factory_rva, maximum_size=512)
    if raw is None:
        return None
    instructions = _disassemble(raw, context.image_base + factory_rva, maximum=512)
    if not instructions:
        return None
    by_address = {instruction.address: instruction for instruction in instructions}
    pc = instructions[0].address
    rax: int | None = None
    stack: dict[int, int] = {}
    zero_flag: bool | None = None
    for _ in range(128):
        instruction = by_address.get(pc)
        if instruction is None:
            return None
        operands = instruction.operands
        mnemonic = instruction.mnemonic.casefold()
        next_pc = instruction.address + instruction.size
        if mnemonic in {"sub", "add"} and operands and operands[0].type == X86_OP_REG:
            pass
        elif (
            mnemonic == "lea"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg in {X86_REG_RAX, X86_REG_EAX}
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.base == X86_REG_RIP
        ):
            rax = instruction.address + instruction.size + int(operands[1].mem.disp)
        elif (
            mnemonic == "xor"
            and len(operands) == 2
            and all(
                item.type == X86_OP_REG and item.reg in {X86_REG_RAX, X86_REG_EAX}
                for item in operands
            )
        ):
            rax = 0
        elif (
            mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg in {X86_REG_RAX, X86_REG_EAX}
            and operands[1].type == X86_OP_IMM
        ):
            rax = int(operands[1].imm) & 0xFFFFFFFFFFFFFFFF
        elif (
            mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].mem.base == X86_REG_RSP
            and operands[0].mem.index == 0
        ):
            if operands[1].type == X86_OP_REG and operands[1].reg in {
                X86_REG_RAX,
                X86_REG_EAX,
            }:
                if rax is None:
                    return None
                stack[int(operands[0].mem.disp)] = rax
            elif operands[1].type == X86_OP_IMM:
                stack[int(operands[0].mem.disp)] = int(operands[1].imm)
            else:
                return None
        elif (
            mnemonic == "cmp"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg in {X86_REG_RAX, X86_REG_EAX}
            and operands[1].type == X86_OP_IMM
        ):
            zero_flag = rax is not None and rax == int(operands[1].imm)
        elif (
            mnemonic in {"je", "jne"}
            and len(operands) == 1
            and operands[0].type == X86_OP_IMM
        ):
            if zero_flag is None:
                return None
            taken = zero_flag if mnemonic == "je" else not zero_flag
            if taken:
                next_pc = int(operands[0].imm)
        elif (
            mnemonic == "imul"
            and len(operands) == 3
            and operands[0].type == X86_OP_REG
            and operands[0].reg in {X86_REG_RAX, X86_REG_EAX}
            and operands[1].type == X86_OP_REG
            and operands[1].reg in {X86_REG_RAX, X86_REG_EAX}
            and operands[2].type == X86_OP_IMM
        ):
            if rax is None:
                return None
            rax = _u32(rax * int(operands[2].imm))
        elif (
            mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_RAX
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.base == X86_REG_RSP
            and operands[1].mem.index == X86_REG_RAX
        ):
            if rax is None or rax not in stack:
                return None
            rax = stack[rax]
        elif (
            mnemonic == "jmp" and len(operands) == 1 and operands[0].type == X86_OP_IMM
        ):
            next_pc = int(operands[0].imm)
        elif mnemonic == "ret":
            if rax is None:
                return None
            target_rva = rax - context.image_base
            return target_rva if _is_executable_rva(context, target_rva) else None
        else:
            return None
        pc = next_pc
    return None


def _pe_function_instructions(
    context: _PeContext,
    function_rva: int,
    *,
    maximum_size: int = 0x4000,
):
    if type(maximum_size) is not int or not 1 <= maximum_size <= MAXIMUM_FUNCTION_SIZE:
        return None
    raw = _bounded_function_bytes(context, function_rva, maximum_size=maximum_size)
    if raw is None:
        return None
    instructions = _disassemble(
        raw,
        context.image_base + function_rva,
        maximum=4_096,
    )
    if instructions is None:
        return None
    result = []
    for instruction in instructions:
        result.append(instruction)
        if instruction.mnemonic.casefold() == "ret":
            return result
    return None


def _call_graph_has_constants(
    context: _PeContext,
    function_rva: int,
    constants: tuple[int, ...],
) -> bool:
    """bounded direct-call graph上で全定数が命令operandとして現れるか確認する。"""

    pending = [(function_rva, 0)]
    visited: set[int] = set()
    found: set[int] = set()
    while pending:
        if len(pending) > MAXIMUM_CALL_GRAPH_PENDING:
            return False
        current, depth = pending.pop()
        if current in visited or len(visited) >= 256 or depth > 8:
            continue
        visited.add(current)
        instructions = _pe_function_instructions(context, current)
        if instructions is None:
            continue
        for instruction in instructions:
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM:
                    value = int(operand.imm) & 0xFFFFFFFF
                    if value in constants:
                        found.add(value)
            target = _direct_call_target(instruction)
            if target is None:
                continue
            target_rva = target - context.image_base
            if _is_executable_rva(context, target_rva):
                pending.append((target_rva, depth + 1))
    return found == set(constants)


def _key_schedule_wrapper_proven(context: _PeContext, function_rva: int) -> bool:
    """鍵object構築wrapperの入力保存・copy・helper chainを検証する。"""

    instructions = _pe_function_instructions(context, function_rva)
    if instructions is None:
        return False
    saved_inputs: set[str] = set()
    direct_calls = 0
    saw_rep_copy = False
    saw_backward_jump = False
    for instruction in instructions:
        operands = instruction.operands
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[1].type == X86_OP_REG
        ):
            saved_inputs.add(_register_name(instruction, operands[1].reg))
        direct_calls += _direct_call_target(instruction) is not None
        saw_rep_copy |= instruction.mnemonic.casefold() == "rep movsb"
        if (
            instruction.group(CS_GRP_JUMP)
            and operands
            and operands[0].type == X86_OP_IMM
        ):
            saw_backward_jump |= int(operands[0].imm) < instruction.address
    return (
        {"rcx", "rdx", "r8"}.issubset(saved_inputs)
        and direct_calls >= 4
        and saw_rep_copy
        and saw_backward_jump
    )


def _custom_cipher_wrapper_proven(context: _PeContext, wrapper_rva: int) -> bool:
    raw = _bounded_function_bytes(context, wrapper_rva, maximum_size=512)
    if raw is None:
        return False
    instructions = _disassemble(raw, context.image_base + wrapper_rva, maximum=512)
    if not instructions:
        return False
    callees: list[int] = []
    for instruction in instructions:
        if instruction.mnemonic.casefold() == "ret":
            break
        operands = instruction.operands
        if (
            instruction.mnemonic.casefold() == "call"
            and len(operands) == 1
            and operands[0].type == X86_OP_IMM
        ):
            callees.append(int(operands[0].imm) - context.image_base)
    return (
        len(callees) == 2
        and (
            _call_graph_has_constants(context, callees[0], _CIPHER_CONSTANTS[:2])
            or _key_schedule_wrapper_proven(context, callees[0])
        )
        and _call_graph_has_constants(context, callees[1], _CIPHER_CONSTANTS[2:])
    )


def _decoder_consumes_table(
    context: _PeContext,
    decoder_rva: int,
    table_rva: int,
) -> bool:
    raw = _bounded_function_bytes(context, decoder_rva)
    if raw is None:
        return False
    matches = 0
    for offset in range(max(0, len(raw) - 7)):
        if raw[offset : offset + 3] != b"\x48\x8d\x0d":
            continue
        target = decoder_rva + offset + 7 + struct.unpack_from("<i", raw, offset + 3)[0]
        if target != table_rva:
            continue
        tail = raw[offset + 7 : offset + 0x100]
        if b"\x48\x8b\x04\xc1" in tail and (
            b"\xff\x94\x24" in tail or b"\xff\x54\x24" in tail
        ):
            matches += 1
    return matches == 1


def _dispatch_proof(context: _PeContext, decoder_rva: int) -> _DispatchProof | None:
    executable = b"".join(
        context.data[
            int(section.PointerToRawData) : int(section.PointerToRawData)
            + min(
                int(section.SizeOfRawData),
                len(context.data) - int(section.PointerToRawData),
            )
        ]
        for section in context.image.sections
        if int(section.Characteristics) & 0x20000000
    )
    if any(
        executable.count(struct.pack("<I", value)) != 1 for value in _CIPHER_CONSTANTS
    ):
        return None
    valid: list[_DispatchProof] = []
    for table_rva, factories in _dispatch_initializers(context):
        wrappers = tuple(_static_factory_return(context, item) for item in factories)
        wrapper = wrappers[CUSTOM_CIPHER_SLOT]
        if wrapper is None or not _custom_cipher_wrapper_proven(context, wrapper):
            continue
        if any(
            index != CUSTOM_CIPHER_SLOT
            and candidate is not None
            and _custom_cipher_wrapper_proven(context, candidate)
            for index, candidate in enumerate(wrappers)
        ):
            continue
        if not _decoder_consumes_table(context, decoder_rva, table_rva):
            continue
        valid.append(_DispatchProof(table_rva, wrapper))
    unique = {(item.table_rva, item.cipher_wrapper_rva): item for item in valid}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _parse_root_blob(blob: bytes) -> tuple[int, bytes, bytes, int]:
    if len(blob) < 6:
        raise ValueError("root blob is too short")
    prefix_skip = blob[0]
    size_offset = 1 + prefix_skip
    if size_offset + 4 > len(blob):
        raise ValueError("root prefix exceeds blob")
    compressed_size = struct.unpack_from("<I", blob, size_offset)[0]
    compressed_start = size_offset + 4
    compressed_end = compressed_start + compressed_size
    if not 2 <= compressed_size <= MAXIMUM_STAGE_SIZE or compressed_end > len(blob):
        raise ValueError("root compressed stream exceeds blob")
    stage1 = _lznt1_decompress(
        blob[compressed_start:compressed_end],
        output_limit=MAXIMUM_STAGE_SIZE,
    )
    if len(stage1) < 6:
        raise ValueError("stage1 is too short")
    key_size = stage1[0]
    size_position = 1 + key_size
    if not 1 <= key_size <= 0x100 or size_position + 4 > len(stage1):
        raise ValueError("invalid stage1 key schema")
    encrypted_size = struct.unpack_from("<I", stage1, size_position)[0]
    encrypted_start = size_position + 4
    if (
        not 2 <= encrypted_size <= MAXIMUM_STAGE_SIZE
        or encrypted_start + encrypted_size != len(stage1)
    ):
        raise ValueError("stage1 payload is not exact")
    return (
        prefix_skip,
        stage1[1:size_position],
        stage1[encrypted_start:],
        len(stage1),
    )


def _marker_offsets(stage2: bytes) -> tuple[int, ...]:
    found: list[int] = []
    for offset in range(max(0, len(stage2) - 11)):
        marker = stage2[offset : offset + 8]
        if marker[0:2] == b"\xfe\xfa" and marker[-1] == 0xFF and sum(marker) == 0x708:
            found.append(offset)
    return tuple(found)


def _decode_config(config: bytes) -> tuple[str, int, str] | None:
    if len(config) != WEBIO_CONFIG_SIZE:
        return None
    host_raw = config[:0x100].split(b"\0", 1)[0]
    try:
        host = host_raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if (
        not 1 <= len(host) <= 253
        or not re.fullmatch(r"[A-Za-z0-9.-]+", host)
        or host.startswith(".")
        or host.endswith(".")
        or ".." in host
    ):
        return None
    port = struct.unpack_from("<H", config, 0x100)[0]
    if not 1 <= port <= 0xFFFF:
        return None
    try:
        transport = config[0x102:0x10C].decode("utf-16le").split("\0", 1)[0]
    except UnicodeDecodeError:
        return None
    if transport != "HTTP":
        return None
    return host, port, transport


def _function_instructions(stage: bytes, offset: int, maximum_size: int = 4_096):
    if not 0 <= offset < len(stage):
        return None
    instructions = _disassemble(
        stage[offset : min(len(stage), offset + maximum_size)],
        offset,
        maximum=4_096,
    )
    if not instructions:
        return None
    result = []
    for instruction in instructions:
        result.append(instruction)
        if instruction.mnemonic.casefold() == "ret":
            break
    return result if result and result[-1].mnemonic.casefold() == "ret" else None


def _stack_bytes(instructions) -> dict[tuple[int, int], int]:
    values: dict[tuple[int, int], int] = {}
    for instruction in instructions:
        operands = instruction.operands
        if not (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].mem.base in {X86_REG_RSP, X86_REG_RBP}
            and operands[0].mem.index == 0
            and operands[1].type == X86_OP_IMM
            and operands[0].size in {1, 2, 4, 8}
        ):
            continue
        base = int(operands[0].mem.base)
        displacement = int(operands[0].mem.disp)
        size = int(operands[0].size)
        encoded = (int(operands[1].imm) & ((1 << (size * 8)) - 1)).to_bytes(
            size,
            "little",
            signed=False,
        )
        for index, value in enumerate(encoded):
            values[(base, displacement + index)] = value
    return values


def _stack_literal_offsets(instructions, literal: bytes) -> tuple[tuple[int, int], ...]:
    values = _stack_bytes(instructions)
    found: list[tuple[int, int]] = []
    for base, displacement in values:
        if all(
            values.get((base, displacement + index)) == value
            for index, value in enumerate(literal)
        ):
            found.append((base, displacement))
    return tuple(sorted(set(found)))


def _direct_call_target(instruction) -> int | None:
    operands = instruction.operands
    if (
        instruction.mnemonic.casefold() == "call"
        and len(operands) == 1
        and operands[0].type == X86_OP_IMM
    ):
        return int(operands[0].imm)
    return None


def _ksa_helper_proven(stage: bytes, offset: int) -> bool:
    instructions = _function_instructions(stage, offset, 0x180)
    if instructions is None:
        return False
    compare_256 = 0
    byte_writes = 0
    state_tail: set[int] = set()
    saw_division = False
    saw_backward_jump = False
    for instruction in instructions:
        operands = instruction.operands
        if instruction.mnemonic.casefold() == "cmp" and any(
            item.type == X86_OP_IMM and int(item.imm) == 0x100 for item in operands
        ):
            compare_256 += 1
        if instruction.mnemonic.casefold() == "div":
            saw_division = True
        for operand in operands:
            if operand.type == X86_OP_MEM and int(operand.mem.disp) in {0x100, 0x101}:
                state_tail.add(int(operand.mem.disp))
        if (
            instruction.mnemonic.casefold() == "mov"
            and operands
            and operands[0].type == X86_OP_MEM
            and operands[0].size == 1
        ):
            byte_writes += 1
        if (
            instruction.group(CS_GRP_JUMP)
            and operands
            and operands[0].type == X86_OP_IMM
        ):
            saw_backward_jump |= int(operands[0].imm) < instruction.address
    return (
        compare_256 >= 2
        and saw_division
        and state_tail == {0x100, 0x101}
        and byte_writes >= 4
        and saw_backward_jump
    )


def _xor_swap_prga_proven(stage: bytes, offset: int) -> bool:
    instructions = _function_instructions(stage, offset, 0x200)
    if instructions is None:
        return False
    tail_refs = {0x100: 0, 0x101: 0}
    xor_registers: list[int] = []
    indexed_loads = 0
    byte_writes = 0
    saw_backward_jump = False
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        for operand in operands:
            if operand.type == X86_OP_MEM:
                displacement = int(operand.mem.disp)
                if displacement in tail_refs:
                    tail_refs[displacement] += 1
        if (
            instruction.mnemonic.casefold() == "movzx"
            and len(operands) == 2
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.index != 0
        ):
            indexed_loads += 1
        if (
            instruction.mnemonic.casefold() == "xor"
            and len(operands) == 2
            and all(item.type == X86_OP_REG for item in operands)
        ):
            xor_registers.append(index)
        if (
            instruction.mnemonic.casefold() == "mov"
            and operands
            and operands[0].type == X86_OP_MEM
            and operands[0].size == 1
        ):
            byte_writes += 1
        if (
            instruction.group(CS_GRP_JUMP)
            and operands
            and operands[0].type == X86_OP_IMM
        ):
            saw_backward_jump |= int(operands[0].imm) < instruction.address
    return (
        tail_refs[0x100] >= 4
        and tail_refs[0x101] >= 4
        and indexed_loads >= 3
        and len(xor_registers) >= 2
        and xor_registers[-1] > xor_registers[0]
        and byte_writes >= 3
        and saw_backward_jump
    )


def _recent_register_move(
    instructions, index: int, destination: str, source: str, window: int = 12
) -> bool:
    for instruction in instructions[max(0, index - window) : index]:
        operands = instruction.operands
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and all(item.type == X86_OP_REG for item in operands)
            and _register_name(instruction, operands[0].reg) == destination
            and _register_name(instruction, operands[1].reg) == source
        ):
            return True
    return False


def _recent_immediate_move(
    instructions, index: int, destination: str, value: int, window: int = 12
) -> bool:
    for instruction in instructions[max(0, index - window) : index]:
        operands = instruction.operands
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg) == destination
            and operands[1].type == X86_OP_IMM
            and int(operands[1].imm) == value
        ):
            return True
    return False


def _recent_eight_argument(instructions, index: int, *, window: int = 12) -> bool:
    if _recent_immediate_move(instructions, index, "r8d", 8, window=window):
        return True
    start = max(0, index - window)
    for position, instruction in enumerate(instructions[start:index], start=start):
        operands = instruction.operands
        if not (
            instruction.mnemonic.casefold() == "lea"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg) == "r8d"
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.base == X86_REG_RAX
            and operands[1].mem.index == 0
            and int(operands[1].mem.disp) == 8
        ):
            continue
        for prior in instructions[max(start, position - 4) : position]:
            values = prior.operands
            if (
                prior.mnemonic.casefold() == "xor"
                and len(values) == 2
                and all(
                    item.type == X86_OP_REG and item.reg in {X86_REG_RAX, X86_REG_EAX}
                    for item in values
                )
            ):
                return True
    return False


def _recent_lea(
    instructions,
    index: int,
    destination: str,
    base_register: int,
    *,
    window: int = 16,
) -> int | None:
    for instruction in reversed(instructions[max(0, index - window) : index]):
        operands = instruction.operands
        if (
            instruction.mnemonic.casefold() == "lea"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg) == destination
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.base == base_register
            and operands[1].mem.index == 0
        ):
            return int(operands[1].mem.disp)
    return None


def _modified_rc4_binding_proven(stage: bytes, instructions) -> bool:
    ksa_calls: list[tuple[int, int]] = []
    prga_calls: list[tuple[int, int]] = []
    for index, instruction in enumerate(instructions):
        target = _direct_call_target(instruction)
        if target is None:
            continue
        if _ksa_helper_proven(stage, target):
            ksa_calls.append((index, target))
        if _xor_swap_prga_proven(stage, target):
            prga_calls.append((index, target))
    if len(ksa_calls) != 1 or len(prga_calls) != 1:
        return False
    ksa_index, _ = ksa_calls[0]
    prga_index, _ = prga_calls[0]
    if not ksa_index < prga_index:
        return False
    state_disp = _recent_lea(instructions, ksa_index, "rcx", X86_REG_RBP)
    if (
        state_disp is None
        or _recent_lea(instructions, prga_index, "rcx", X86_REG_RBP) != state_disp
    ):
        return False
    if not (
        _recent_register_move(instructions, ksa_index, "rdx", "rsi")
        and _recent_immediate_move(instructions, ksa_index, "r8d", 8)
    ):
        return False
    ciphertext_disp = _recent_lea(instructions, prga_index, "rdx", X86_REG_RBX)
    if ciphertext_disp != 0xC:
        return False
    marker_copy = False
    for index, instruction in enumerate(instructions[:ksa_index]):
        if (
            instruction.mnemonic.casefold() != "call"
            or _direct_call_target(instruction) is not None
        ):
            continue
        if (
            _recent_eight_argument(instructions, index)
            and _recent_register_move(instructions, index, "rdx", "rbx")
            and _recent_register_move(instructions, index, "rcx", "rsi")
        ):
            marker_copy = True
    return marker_copy


def _downloader_helper_proven(stage: bytes, offset: int) -> bool:
    instructions = _function_instructions(stage, offset, 0x600)
    if instructions is None:
        return False
    if len(_stack_literal_offsets(instructions, WININET_LIBRARY)) != 1:
        return False
    if len(_stack_literal_offsets(instructions, HTTP_AGENT)) != 1:
        return False
    immediates = [
        int(operand.imm) & 0xFFFFFFFF
        for instruction in instructions
        for operand in instruction.operands
        if operand.type == X86_OP_IMM
    ]
    indirect_calls = sum(
        1
        for instruction in instructions
        if instruction.mnemonic.casefold() == "call"
        and instruction.operands
        and instruction.operands[0].type != X86_OP_IMM
    )
    backward_jumps = sum(
        1
        for instruction in instructions
        if instruction.group(CS_GRP_JUMP)
        and instruction.operands
        and instruction.operands[0].type == X86_OP_IMM
        and int(instruction.operands[0].imm) < instruction.address
    )
    return (
        immediates.count(0x80000000) >= 2
        and 0x400 in immediates
        and immediates.count(0x400000) >= 2
        and indirect_calls >= 6
        and backward_jumps >= 1
    )


def _stage2_http_consumer_proven(stage: bytes) -> bool:
    if not 0x400 <= len(stage) <= MAXIMUM_STAGE_SIZE:
        return False
    entry = _function_instructions(stage, 0, 32)
    if not entry or len(entry) < 4:
        return False
    main_target = _direct_call_target(entry[1])
    if (
        entry[0].mnemonic.casefold() != "sub"
        or main_target is None
        or entry[-1].mnemonic.casefold() != "ret"
    ):
        return False
    main = _function_instructions(stage, main_target, 0x4000)
    if main is None or len(main) > 2_048:
        return False
    if len(_stack_literal_offsets(main, HTTP_ROUTE_FORMAT)) != 1:
        return False
    if not _modified_rc4_binding_proven(stage, main):
        return False
    immediate_a88 = sum(
        1
        for instruction in main
        for operand in instruction.operands
        if operand.type == X86_OP_IMM and int(operand.imm) == WEBIO_CONFIG_SIZE
    )
    if immediate_a88 < 3:
        return False
    format_calls: list[tuple[int, int]] = []
    for index, instruction in enumerate(main):
        if (
            instruction.mnemonic.casefold() != "call"
            or _direct_call_target(instruction) is not None
        ):
            continue
        url_disp = _recent_lea(main, index, "rcx", X86_REG_RBP)
        format_disp = _recent_lea(main, index, "rdx", X86_REG_RSP)
        if url_disp is None or format_disp is None:
            continue
        if (X86_REG_RSP, format_disp) not in _stack_literal_offsets(
            main, HTTP_ROUTE_FORMAT
        ):
            continue
        if not _recent_register_move(main, index, "r8", "rsi"):
            continue
        saw_port = False
        for prior in main[max(0, index - 12) : index]:
            operands = prior.operands
            if (
                prior.mnemonic.casefold() == "movzx"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and _register_name(prior, operands[0].reg) == "r9d"
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.base == X86_REG_RSI
                and int(operands[1].mem.disp) == 0x100
            ):
                saw_port = True
        if saw_port:
            format_calls.append((index, url_disp))
    if len(format_calls) != 1:
        return False
    format_index, url_disp = format_calls[0]
    downloader_calls: list[int] = []
    for index, instruction in enumerate(
        main[format_index + 1 :], start=format_index + 1
    ):
        target = _direct_call_target(instruction)
        if target is None or not _downloader_helper_proven(stage, target):
            continue
        if _recent_lea(main, index, "rcx", X86_REG_RBP) != url_disp:
            continue
        if not _recent_register_move(main, index, "rdx", "rax", window=8):
            continue
        downloader_calls.append(target)
    return len(downloader_calls) == 1


def _recover_route(
    context: _PeContext,
    binding: _RootBinding,
    dispatch: _DispatchProof,
) -> _RecoveredRoute | None:
    del dispatch
    blob = _fully_file_backed(
        context,
        binding.blob_rva,
        binding.blob_size,
        maximum_size=MAXIMUM_BLOB_SIZE,
    )
    if blob is None:
        return None
    try:
        prefix_skip, key, encrypted_stage, stage1_size = _parse_root_blob(blob)
        compressed_stage2 = _custom_cipher_transform(key, encrypted_stage)
        stage2 = _lznt1_decompress(
            compressed_stage2,
            output_limit=MAXIMUM_STAGE_SIZE,
        )
    except (IndexError, OverflowError, struct.error, ValueError):
        return None
    markers = _marker_offsets(stage2)
    if len(markers) != 1 or not _stage2_http_consumer_proven(stage2):
        return None
    marker_offset = markers[0]
    marker = stage2[marker_offset : marker_offset + 8]
    encrypted_size = struct.unpack_from("<I", stage2, marker_offset + 8)[0]
    encrypted_start = marker_offset + 12
    if (
        not 2 <= encrypted_size <= MAXIMUM_STAGE_SIZE
        or encrypted_start + encrypted_size != len(stage2)
    ):
        return None
    try:
        compressed_config = _xor_swap_stream_transform(
            marker,
            stage2[encrypted_start:],
        )
        config = _lznt1_decompress(
            compressed_config,
            output_limit=WEBIO_CONFIG_SIZE,
        )
    except (IndexError, OverflowError, struct.error, ValueError):
        return None
    decoded = _decode_config(config)
    if decoded is None:
        return None
    host, port, transport = decoded
    return _RecoveredRoute(
        host=host,
        port=port,
        transport=transport,
        prefix_skip=prefix_skip,
        source_blob_size=len(blob),
        stage1_size=stage1_size,
        key_size=len(key),
        encrypted_stage_size=len(encrypted_stage),
        stage2_size=len(stage2),
        marker_offset=marker_offset,
        encrypted_config_size=encrypted_size,
        config_size=len(config),
    )


def analyze_silverfox_webio_stage_loader(
    data: bytes,
) -> SilverFoxWebioStageRoute | None:
    """既知shapeから手動確認用候補を返す。validated routeには昇格しない。"""

    context = _load_pe(data)
    if context is None:
        return None
    bindings = _root_chain_candidates(context)
    if bindings is None or len(bindings) != 1:
        return None
    recovered: list[_RecoveredRoute] = []
    for binding in bindings:
        dispatch = _dispatch_proof(context, binding.decoder_rva)
        if dispatch is None:
            continue
        item = _recover_route(context, binding, dispatch)
        if item is not None:
            recovered.append(item)
    unique = {
        (
            item.host,
            item.port,
            item.transport,
            item.source_blob_size,
            item.stage1_size,
            item.stage2_size,
            item.marker_offset,
        ): item
        for item in recovered
    }
    if len(unique) != 1:
        return None
    item = next(iter(unique.values()))
    evidence = {
        "root_blob_shape_observed": True,
        "first_lznt1_output_observed": True,
        "key_payload_schema_observed": True,
        "dispatch_slot_two_shape_observed": CUSTOM_CIPHER_SLOT == 2,
        "second_lznt1_output_observed": True,
        "unique_marker_observed": True,
        "decoded_config_size_observed": item.config_size == WEBIO_CONFIG_SIZE,
        "decoded_host_port_candidate_observed": True,
        "getinstall64_literal_observed": True,
        "entrypoint_reachable_root_chain_proven": False,
        "root_cfg_and_dataflow_proven": False,
        "runtime_dispatch_slot_two_binding_proven": False,
        "hardcoded_cipher_to_runtime_dispatch_bound": False,
        "marker_to_xor_swap_key_dataflow_proven": False,
        "config_to_http_get_consumer_dataflow_proven": False,
        "end_to_end_route_lineage_proven": False,
        "root_plaintext_endpoint_candidates_used": False,
    }
    observation: dict[str, object] = {
        "schema_version": 1,
        "status": "unverified_silverfox_webio_manual_route_candidate",
        "matched": False,
        "candidate_recovered": True,
        "automatic_route_eligible": False,
        "manual_review_required": True,
        "route_validated": False,
        "static_config_recovered": False,
        "component_profile": "silverfox_webio_manual_route_candidate",
        "loader_lineage": "silverfox_style_candidate",
        "family": None,
        "family_attribution": "unresolved_manual_loader_candidate",
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "final_rat_confirmed": False,
        "command_c2_confirmed": False,
        "liveness_confirmed": False,
        "qualified": False,
        "contacted": False,
        "candidate_only": True,
        "route": {
            "method": "GET",
            "path": "/getinstall64",
            "endpoint": {
                "host": item.host,
                "port": item.port,
                "transport": item.transport.lower(),
                "role": "stage_acquisition_route_candidate",
                "evidence": "unverified_decoded_value_without_complete_cfg_dataflow_binding",
            },
            "downloaded_bundle_recovered": False,
            "downloaded_bundle_executed": False,
        },
        "decoders": {
            "source_blob_size": item.source_blob_size,
            "prefix_skip": item.prefix_skip,
            "stage1_size": item.stage1_size,
            "key_size": item.key_size,
            "encrypted_stage_size": item.encrypted_stage_size,
            "stage2_size": item.stage2_size,
            "marker_offset": item.marker_offset,
            "encrypted_config_size": item.encrypted_config_size,
            "config_size": item.config_size,
            "raw_key_included": False,
            "raw_stage_included": False,
            "raw_config_included": False,
        },
        "evidence_boundary": evidence,
        "endpoint_values_included": True,
        "raw_key_included": False,
        "raw_stage_included": False,
        "raw_config_included": False,
        "hash_or_filename_rule_used": False,
        "external_label_used": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    return SilverFoxWebioStageRoute(observation)


def probe_silverfox_webio_stage_loader(data: bytes) -> dict[str, object]:
    """手動確認用に成功・拒否とも安全境界を固定した辞書を返す。"""

    result = analyze_silverfox_webio_stage_loader(data)
    if result is not None:
        return result.observation
    return {
        "schema_version": 1,
        "status": "not_matched",
        "matched": False,
        "candidate_recovered": False,
        "automatic_route_eligible": False,
        "manual_review_required": True,
        "route_validated": False,
        "static_config_recovered": False,
        "component_profile": "silverfox_webio_manual_route_candidate",
        "family": None,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "final_rat_confirmed": False,
        "command_c2_confirmed": False,
        "liveness_confirmed": False,
        "qualified": False,
        "contacted": False,
        "endpoint_values_included": False,
        "raw_key_included": False,
        "raw_stage_included": False,
        "raw_config_included": False,
        "hash_or_filename_rule_used": False,
        "external_label_used": False,
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "SilverFoxWebioStageRoute",
    "analyze_silverfox_webio_stage_loader",
    "probe_silverfox_webio_stage_loader",
]
