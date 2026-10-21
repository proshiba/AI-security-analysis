"""高entropy RCDATAからHHSTG stage取得loader候補を静的に復元する。

検体や復元物は実行せず、外部通信もしない。外側resource変換、proxy DLLと
hostのimport／export／実配置名結合、host entrypoint差替え、復号候補、HHSTG
設定／到達可能CFG、受信stage内AppConfig patch構造までを有界に候補化する。
proxy exportからentrypoint patch、config tailからconnect、registry readからChaCha引数の
完全なproducer-consumer bindingは未確認なため、得られたendpointは手動確認用の
stage取得route候補であり、confirmed C2またはfamily確定に使用しない。
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import struct
from dataclasses import dataclass
from itertools import pairwise

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsError
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AL,
    X86_REG_CX,
    X86_REG_EAX,
    X86_REG_EBX,
    X86_REG_ECX,
    X86_REG_EDI,
    X86_REG_EDX,
    X86_REG_GS,
    X86_REG_INVALID,
    X86_REG_R8,
    X86_REG_R8D,
    X86_REG_R9D,
    X86_REG_R12,
    X86_REG_R13,
    X86_REG_RAX,
    X86_REG_RBP,
    X86_REG_RBX,
    X86_REG_RCX,
    X86_REG_RDI,
    X86_REG_RDX,
    X86_REG_RIP,
    X86_REG_RSP,
    X86_REG_XMM0,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

MAXIMUM_INPUT_SIZE = 32 * 1024 * 1024
MAXIMUM_COMPONENT_SIZE = 16 * 1024 * 1024
MAXIMUM_RESOURCE_COUNT = 64
MAXIMUM_RESOURCE_TOTAL_SIZE = 32 * 1024 * 1024
MAXIMUM_SECTION_COUNT = 64
MAXIMUM_RUNTIME_FUNCTION_COUNT = 16_384
MAXIMUM_RUNTIME_FUNCTION_SIZE = 0x20_000
MAXIMUM_RUNTIME_FUNCTION_BYTES = 16 * 1024 * 1024
MAXIMUM_INSTRUCTION_COUNT = 500_000
MAXIMUM_SHELLCODE_SIZE = 4 * 1024 * 1024
MAXIMUM_SHELLCODE_INSTRUCTIONS = 100_000
HHSTG_CONFIG_SIZE = 0x11A
RESOURCE_TAIL_OFFSET = 0xEBE

_TRANSFORM_LOOP = re.compile(
    rb"\x8d\x47\xf2\xff\xc7\x83\xe0\x1f\x48\x8d\x0d(?P<disp>.{4})"
    rb"\x8a\x0c\x08\x41\x32\x0c\x28\x80\xf1\xee\x41\x88\x08"
    rb"\x49\xff\xc0\x3b\xfe\x72\xdd",
    re.DOTALL,
)
_DOMAIN = re.compile(
    r"(?i)(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\Z"
)
_CAMPAIGN = re.compile(r"[A-Za-z0-9_.-]{1,63}\Z")
_BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_HHSTG_MARKER = b"HHSTG\0\0\0"
_HELLO = b"HHv2\x01\x00\x01"
_PORT_STORE_SIGNATURE = bytes.fromhex("b9bb01000066898c04c0030000")


@dataclass(frozen=True)
class StageEndpoint:
    """静的に復元したstage取得route候補slot。"""

    host: str
    port: int
    source: str
    slot_index: int

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class HhstgResourceRecovery:
    """公開可能な集計と、手動確認用のstage取得候補slotを保持する。"""

    endpoints: tuple[StageEndpoint, ...]
    configured_route_count: int
    embedded_fallback_count: int
    export_binding_count: int
    campaign_present: bool


@dataclass(frozen=True)
class _Function:
    start_rva: int
    end_rva: int
    instructions: tuple[object, ...]
    complete: bool


@dataclass(frozen=True)
class _PeContext:
    data: bytes
    image: object
    image_base: int
    functions: tuple[_Function, ...]


@dataclass(frozen=True)
class _HhstgConfig:
    primary_host: str
    primary_port: int
    route_endpoints: tuple[tuple[str, int], ...]
    campaign: str
    key: bytes


@dataclass(frozen=True)
class _InstructionGraph:
    """明示的なentryから到達する命令と、その有界CFG edge。"""

    instructions: tuple[object, ...]
    successors: dict[int, tuple[int, ...]]
    entry_address: int = 0


def _read_rva(context: _PeContext, rva: int, size: int) -> bytes | None:
    if rva < 0 or not 0 < size <= MAXIMUM_COMPONENT_SIZE:
        return None
    try:
        offset = int(context.image.get_offset_from_rva(rva))
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return None
    if not 0 <= offset <= len(context.data) - size:
        return None
    return context.data[offset : offset + size]


def _decode_runtime_functions(
    data: bytes, image: object
) -> tuple[_Function, ...] | None:
    """AMD64 exception tableにより境界づけたcodeだけを逆アセンブルする。"""

    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        entries = list(image.DIRECTORY_ENTRY_EXCEPTION)
        sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if (
        not 1 <= len(entries) <= MAXIMUM_RUNTIME_FUNCTION_COUNT
        or not 1 <= len(sections) <= MAXIMUM_SECTION_COUNT
    ):
        return None
    executable: list[tuple[int, int]] = []
    for section in sections:
        try:
            if int(section.Characteristics) & 0x20000000 == 0:
                continue
            start = int(section.VirtualAddress)
            raw_size = int(section.SizeOfRawData)
            raw_offset = int(section.PointerToRawData)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if (
            start < 0
            or raw_size <= 0
            or raw_offset < 0
            or raw_offset + raw_size > len(data)
        ):
            return None
        executable.append((start, start + raw_size))
    if not executable:
        return None
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
    except CsError:
        return None
    functions: list[_Function] = []
    total_bytes = 0
    total_instructions = 0
    for entry in entries:
        try:
            start = int(entry.struct.BeginAddress)
            end = int(entry.struct.EndAddress)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        size = end - start
        if (
            start < 0
            or not 0 < size <= MAXIMUM_RUNTIME_FUNCTION_SIZE
            or sum(begin <= start and end <= finish for begin, finish in executable)
            != 1
        ):
            return None
        try:
            offset = int(image.get_offset_from_rva(start))
            final_offset = int(image.get_offset_from_rva(end - 1))
        except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
            return None
        if offset < 0 or final_offset != offset + size - 1 or offset + size > len(data):
            return None
        total_bytes += size
        if total_bytes > MAXIMUM_RUNTIME_FUNCTION_BYTES:
            return None
        try:
            instructions = tuple(
                disassembler.disasm(data[offset : offset + size], image_base + start)
            )
        except CsError:
            return None
        total_instructions += len(instructions)
        if (
            not instructions
            or total_instructions > MAXIMUM_INSTRUCTION_COUNT
            or instructions[0].address != image_base + start
        ):
            return None
        complete = instructions[-1].address + instructions[-1].size == image_base + end
        functions.append(_Function(start, end, instructions, complete))
    functions.sort(key=lambda item: item.start_rva)
    if any(left.end_rva > right.start_rva for left, right in pairwise(functions)):
        return None
    return tuple(functions)


def _runtime_function_graph(function: _Function) -> _InstructionGraph | None:
    """runtime functionを先頭entryからの到達可能CFGに限定する。"""

    if not function.complete or not function.instructions:
        return None
    decoded = function.instructions
    by_address = {int(item.address): item for item in decoded}
    if len(by_address) != len(decoded):
        return None
    entry_address = int(decoded[0].address)
    all_successors: dict[int, tuple[int, ...]] = {}
    for instruction in decoded:
        address = int(instruction.address)
        following = address + int(instruction.size)
        mnemonic = instruction.mnemonic.casefold()
        try:
            operands = instruction.operands
        except (AttributeError, CsError):
            return None
        immediate_target = (
            int(operands[0].imm)
            if len(operands) == 1 and operands[0].type == X86_OP_IMM
            else None
        )
        if mnemonic == "jmp":
            candidates = (
                (immediate_target,)
                if immediate_target is not None and immediate_target in by_address
                else ()
            )
        elif mnemonic.startswith("j") and mnemonic != "jmp":
            if immediate_target is None or immediate_target not in by_address:
                return None
            candidates = tuple(
                value for value in (immediate_target, following) if value in by_address
            )
        elif mnemonic == "call":
            candidates = (following,) if following in by_address else ()
        elif mnemonic.startswith("ret") or mnemonic in {"int3", "ud2", "hlt"}:
            candidates = ()
        else:
            candidates = (following,) if following in by_address else ()
        all_successors[address] = tuple(dict.fromkeys(candidates))

    pending = [entry_address]
    queued = {entry_address}
    reachable: set[int] = set()
    cursor = 0
    while cursor < len(pending):
        if len(pending) > MAXIMUM_INSTRUCTION_COUNT:
            return None
        address = pending[cursor]
        cursor += 1
        if address in reachable:
            continue
        reachable.add(address)
        for target in all_successors.get(address, ()):
            if target not in reachable and target not in queued:
                pending.append(target)
                queued.add(target)
    instructions = tuple(item for item in decoded if int(item.address) in reachable)
    successors = {
        address: tuple(
            target for target in all_successors[address] if target in reachable
        )
        for address in sorted(reachable)
    }
    return _InstructionGraph(instructions, successors, entry_address)


def _reachable_runtime_function(function: _Function) -> _Function | None:
    """dead codeを除いたruntime functionを返す。"""

    graph = _runtime_function_graph(function)
    if graph is None:
        return None
    return _Function(
        function.start_rva,
        function.end_rva,
        graph.instructions,
        True,
    )


def _load_x64_pe(data: bytes) -> _PeContext | None:
    if (
        not isinstance(data, bytes)
        or not 1 <= len(data) <= MAXIMUM_INPUT_SIZE
        or not data.startswith(b"MZ")
    ):
        return None
    try:
        image = pefile.PE(data=data, fast_load=False)
        machine = int(image.FILE_HEADER.Machine)
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
    except (
        pefile.PEFormatError,
        AttributeError,
        TypeError,
        ValueError,
        OverflowError,
    ):
        return None
    if machine != 0x8664 or image_base <= 0:
        return None
    functions = _decode_runtime_functions(data, image)
    if functions is None:
        return None
    return _PeContext(data, image, image_base, functions)


def _function_for_rva(context: _PeContext, rva: int) -> _Function | None:
    matches = [
        item for item in context.functions if item.start_rva <= rva < item.end_rva
    ]
    return matches[0] if len(matches) == 1 else None


def _resource_leaves(context: _PeContext) -> dict[int, bytes] | None:
    root = getattr(context.image, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return None
    leaves: dict[int, bytes] = {}
    count = 0
    total = 0
    try:
        type_entries = list(root.entries)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    for type_entry in type_entries:
        try:
            type_id = int(type_entry.id)
            name_entries = list(type_entry.directory.entries)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if type_id != 10:
            continue
        for name_entry in name_entries:
            try:
                identifier = int(name_entry.id)
                language_entries = list(name_entry.directory.entries)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None
            if identifier not in {101, 102, 103}:
                continue
            if len(language_entries) != 1 or identifier in leaves:
                return None
            language = language_entries[0]
            try:
                record = language.data.struct
                rva = int(record.OffsetToData)
                size = int(record.Size)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None
            count += 1
            total += size
            if (
                count > MAXIMUM_RESOURCE_COUNT
                or total > MAXIMUM_RESOURCE_TOTAL_SIZE
                or not 1 <= size <= MAXIMUM_COMPONENT_SIZE
            ):
                return None
            blob = _read_rva(context, rva, size)
            if blob is None:
                return None
            leaves[identifier] = blob
    return leaves if set(leaves) == {101, 102, 103} else None


def _direct_call_target(instruction: object) -> int | None:
    try:
        operands = instruction.operands
    except (AttributeError, CsError):
        return None
    if (
        instruction.mnemonic.casefold() == "call"
        and len(operands) == 1
        and operands[0].type == X86_OP_IMM
    ):
        return int(operands[0].imm) & 0xFFFFFFFFFFFFFFFF
    return None


def _register_immediate(instruction: object, register: int, value: int) -> bool:
    try:
        operands = instruction.operands
    except (AttributeError, CsError):
        return False
    return bool(
        instruction.mnemonic.casefold() == "mov"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[0].reg == register
        and operands[1].type == X86_OP_IMM
        and int(operands[1].imm) & 0xFFFFFFFFFFFFFFFF == value & 0xFFFFFFFFFFFFFFFF
    )


def _immediate_values(instruction: object) -> tuple[int, ...]:
    try:
        return tuple(
            int(operand.imm) & 0xFFFFFFFFFFFFFFFF
            for operand in instruction.operands
            if operand.type == X86_OP_IMM
        )
    except (AttributeError, CsError):
        return ()


def _operands(instruction: object) -> tuple[object, ...]:
    """Capstone operandを例外時は空tupleとして局所正規化する。"""

    try:
        return tuple(instruction.operands)
    except (AttributeError, CsError):
        return ()


def _memory_displacements(instruction: object) -> tuple[int, ...]:
    try:
        return tuple(
            int(operand.mem.disp)
            for operand in instruction.operands
            if operand.type == X86_OP_MEM
        )
    except (AttributeError, CsError):
        return ()


def _rip_memory_target(instruction: object, operand: object) -> int | None:
    try:
        if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
            return None
        return int(instruction.address + instruction.size + operand.mem.disp)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def _resource_call(function: _Function, identifier: int) -> int | None:
    matches: list[int] = []
    instructions = function.instructions
    for index, instruction in enumerate(instructions):
        if not _register_immediate(instruction, X86_REG_ECX, identifier):
            continue
        for following in instructions[index + 1 : index + 6]:
            target = _direct_call_target(following)
            if target is not None:
                matches.append(target)
                break
    return matches[0] if len(matches) == 1 else None


def _register_binary_operation(
    instruction: object,
    mnemonic: str,
    destination: int,
    source: int,
) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == mnemonic
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[0].reg == destination
        and operands[1].type == X86_OP_REG
        and operands[1].reg == source
    )


def _indirect_rip_call_target(instruction: object) -> int | None:
    operands = _operands(instruction)
    if not (
        instruction.mnemonic.casefold() == "call"
        and len(operands) == 1
        and operands[0].type == X86_OP_MEM
        and operands[0].mem.base == X86_REG_RIP
        and operands[0].mem.index == X86_REG_INVALID
    ):
        return None
    return _rip_memory_target(instruction, operands[0])


def _outer_resource103_registry_write_binding(
    function: _Function,
    loader_target: int,
) -> bool:
    """resource 103のtail pointer／長さが二つのregistry writeへ連結するか確認する。"""

    graph = _runtime_function_graph(function)
    if graph is None:
        return False
    instructions = graph.instructions
    resource_calls = [
        index
        for index, instruction in enumerate(instructions)
        if _direct_call_target(instruction) == loader_target
        and any(
            _register_immediate(item, X86_REG_ECX, 103)
            for item in instructions[max(0, index - 5) : index]
        )
    ]
    if len(resource_calls) != 1:
        return False
    call_index = resource_calls[0]
    tail_window = instructions[call_index + 1 : call_index + 12]
    length_loads = [
        call_index + 1 + index
        for index, item in enumerate(tail_window)
        if _stack_load(item, X86_REG_EDI, 0x60)
    ]
    tail_pointers: list[int] = []
    length_adjustments: list[int] = []
    for index, item in enumerate(tail_window, start=call_index + 1):
        operands = _operands(item)
        if (
            item.mnemonic.casefold() == "lea"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_R13
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.base == X86_REG_RAX
            and operands[1].mem.index == X86_REG_INVALID
            and operands[1].mem.disp == RESOURCE_TAIL_OFFSET
        ):
            tail_pointers.append(index)
        if (
            item.mnemonic.casefold() == "add"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_EDI
            and operands[1].type == X86_OP_IMM
            and int(operands[1].imm) & 0xFFFFFFFF
            == (-RESOURCE_TAIL_OFFSET) & 0xFFFFFFFF
        ):
            length_adjustments.append(index)
    if not (
        len(length_loads) == len(tail_pointers) == len(length_adjustments) == 1
        and call_index < length_loads[0] < tail_pointers[0] < length_adjustments[0]
    ):
        return False

    first_writes: list[tuple[int, int]] = []
    second_writes: list[tuple[int, int]] = []
    previous_indirect_call = length_adjustments[0]
    for index in range(length_adjustments[0] + 1, len(instructions)):
        target = _indirect_rip_call_target(instructions[index])
        if target is None:
            continue
        before = instructions[max(previous_indirect_call + 1, index - 12) : index]
        if (
            any(_stack_load(item, X86_REG_RCX, 0x50) for item in before)
            and any(
                _register_binary_operation(item, "mov", X86_REG_EBX, X86_REG_EDI)
                for item in before
            )
            and any(
                item.mnemonic.casefold() == "shr"
                and len(_operands(item)) == 2
                and _operands(item)[0].type == X86_OP_REG
                and _operands(item)[0].reg == X86_REG_EBX
                and _operands(item)[1].type == X86_OP_IMM
                and int(_operands(item)[1].imm) == 1
                for item in before
            )
            and any(_stack_store(item, 0x28, X86_REG_EBX) for item in before)
            and any(_stack_store(item, 0x20, X86_REG_R13) for item in before)
        ):
            first_writes.append((index, target))
        if (
            any(_stack_load(item, X86_REG_RCX, 0x50) for item in before)
            and any(
                _register_binary_operation(item, "sub", X86_REG_EDI, X86_REG_EBX)
                for item in before
            )
            and any(
                _register_binary_operation(item, "add", X86_REG_RBX, X86_REG_R13)
                for item in before
            )
            and any(_stack_store(item, 0x28, X86_REG_EDI) for item in before)
            and any(_stack_store(item, 0x20, X86_REG_RBX) for item in before)
        ):
            second_writes.append((index, target))
        previous_indirect_call = index
    if not (
        len(first_writes) == len(second_writes) == 1
        and first_writes[0][0] < second_writes[0][0] <= first_writes[0][0] + 16
        and first_writes[0][1] == second_writes[0][1]
    ):
        return False
    anchors = (
        call_index,
        length_loads[0],
        tail_pointers[0],
        length_adjustments[0],
        first_writes[0][0],
        second_writes[0][0],
    )
    if not _ordered_cfg_path(graph, anchors):
        return False
    return all(
        _cfg_dominates(
            graph,
            int(instructions[left].address),
            int(instructions[right].address),
        )
        for left, right in pairwise(anchors)
    )


def _outer_transform(
    context: _PeContext,
    resources: dict[int, bytes],
) -> tuple[bytes, bytes, _Function, int] | None:
    matches = list(_TRANSFORM_LOOP.finditer(context.data))
    if len(matches) != 1:
        return None
    match = matches[0]
    try:
        match_rva = int(context.image.get_rva_from_offset(match.start()))
        displacement = struct.unpack_from("<i", match.group("disp"))[0]
    except (pefile.PEFormatError, struct.error, TypeError, ValueError, OverflowError):
        return None
    transform_function = _function_for_rva(context, match_rva)
    transform_function = (
        _reachable_runtime_function(transform_function)
        if transform_function is not None
        else None
    )
    match_va = context.image_base + match_rva
    if transform_function is None or not any(
        int(item.address) == match_va for item in transform_function.instructions
    ):
        return None
    key_rva = match_rva + 15 + displacement
    key = _read_rva(context, key_rva, 32)
    if key is None or len(set(key)) < 4:
        return None
    main_candidates: list[_Function] = []
    transform_va = context.image_base + transform_function.start_rva
    for raw_function in context.functions:
        function = _reachable_runtime_function(raw_function)
        if function is None:
            continue
        first = _resource_call(function, 101)
        second = _resource_call(function, 102)
        third = _resource_call(function, 103)
        if (
            first != transform_va
            or second != transform_va
            or third is None
            or third == transform_va
        ):
            continue
        if _outer_resource103_registry_write_binding(function, third):
            main_candidates.append(function)
    if len(main_candidates) != 1:
        return None
    first_resource = resources[101]
    second_resource = resources[102]
    if (
        len(first_resource) < 64
        or len(second_resource) < 64
        or first_resource[:16] != second_resource[:16]
        or len(resources[103]) <= RESOURCE_TAIL_OFFSET
    ):
        return None

    def decode(blob: bytes) -> bytes:
        return bytes(
            value ^ key[(index - 14) & 31] ^ 0xEE for index, value in enumerate(blob)
        )

    first_decoded = decode(first_resource)
    second_decoded = decode(second_resource)
    if not first_decoded.startswith(b"MZ") or not second_decoded.startswith(b"MZ"):
        return None
    return first_decoded, second_decoded, main_candidates[0], transform_va


def _dll_identity(value: object) -> str | None:
    """PE directory由来DLL名をpathなしの比較用identityへ限定する。"""

    if not isinstance(value, bytes) or not 5 <= len(value) <= 128:
        return None
    try:
        name = value.decode("ascii", errors="strict")
    except UnicodeError:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.[Dd][Ll][Ll]", name):
        return None
    return name.casefold()


def _rva_is_executable(context: _PeContext, rva: int) -> bool:
    matches = 0
    try:
        sections = list(context.image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False
    for section in sections:
        try:
            start = int(section.VirtualAddress)
            size = int(section.SizeOfRawData)
            offset = int(section.PointerToRawData)
            executable = bool(int(section.Characteristics) & 0x20000000)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return False
        if start <= rva < start + size:
            if not executable or not 0 <= offset + (rva - start) < len(context.data):
                return False
            matches += 1
    return matches == 1


def _named_exports(context: _PeContext) -> tuple[tuple[str, ...], int, str] | None:
    directory = getattr(context.image, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return None
    try:
        symbols = list(directory.symbols)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    identity = _dll_identity(getattr(directory, "name", None))
    if identity is None:
        return None
    names: list[str] = []
    addresses: set[int] = set()
    if not 8 <= len(symbols) <= 128:
        return None
    for symbol in symbols:
        raw_name = getattr(symbol, "name", None)
        forwarder = getattr(symbol, "forwarder", None)
        try:
            address = int(symbol.address)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if (
            not isinstance(raw_name, bytes)
            or not 1 <= len(raw_name) <= 128
            or forwarder
        ):
            return None
        try:
            name = raw_name.decode("ascii", errors="strict")
        except UnicodeError:
            return None
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@$?]{0,127}", name):
            return None
        names.append(name)
        addresses.add(address)
    if len(set(names)) != len(names) or len(addresses) != 1:
        return None
    common_rva = addresses.pop()
    if not _rva_is_executable(context, common_rva):
        return None
    return tuple(sorted(names)), common_rva, identity


def _host_import_binding(host: _PeContext, exports: tuple[str, ...]) -> str | None:
    expected = set(exports)
    matches = 0
    matched_identity: str | None = None
    try:
        descriptors = list(host.image.DIRECTORY_ENTRY_IMPORT)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not 1 <= len(descriptors) <= 256:
        return None
    for descriptor in descriptors:
        try:
            imports = list(descriptor.imports)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        descriptor_identity = _dll_identity(getattr(descriptor, "dll", None))
        names: set[str] = set()
        for item in imports:
            raw_name = getattr(item, "name", None)
            if raw_name is None:
                continue
            if not isinstance(raw_name, bytes) or not 1 <= len(raw_name) <= 128:
                return None
            try:
                names.add(raw_name.decode("ascii", errors="strict"))
            except UnicodeError:
                return None
        if (
            descriptor_identity is not None
            and names == expected
            and len(imports) == len(expected)
        ):
            matches += 1
            matched_identity = descriptor_identity
    return matched_identity if matches == 1 else None


def _register_move(instruction: object, destination: int, source: int) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == "mov"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[0].reg == destination
        and operands[1].type == X86_OP_REG
        and operands[1].reg == source
    )


def _lea_stack_frame(instruction: object, destination: int, displacement: int) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == "lea"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[0].reg == destination
        and operands[1].type == X86_OP_MEM
        and operands[1].mem.base == X86_REG_RBP
        and operands[1].mem.index == X86_REG_INVALID
        and operands[1].mem.disp == displacement
    )


def _outer_proxy_file_binding(
    outer: _PeContext,
    main: _Function,
    identity: str,
    transform_va: int,
) -> bool:
    """resource 101の復号bufferがhost import DLL名へ書かれるdata-flowを確認する。"""

    needle = identity.encode("ascii")
    offsets = [
        offset
        for offset in range(len(outer.data) - len(needle) + 1)
        if outer.data[offset : offset + len(needle)].lower() == needle
    ]
    if len(offsets) != 1:
        return False
    try:
        identity_va = outer.image_base + int(
            outer.image.get_rva_from_offset(offsets[0])
        )
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return False
    graph = _runtime_function_graph(main)
    if graph is None:
        return False
    instructions = graph.instructions
    resource_bindings: list[int] = []
    identity_references: list[int] = []
    for index, instruction in enumerate(instructions):
        if (
            _direct_call_target(instruction) == transform_va
            and any(
                _register_immediate(item, X86_REG_ECX, 101)
                for item in instructions[max(0, index - 5) : index]
            )
            and any(
                _register_move(item, X86_REG_R12, X86_REG_RAX)
                for item in instructions[index + 1 : index + 5]
            )
        ):
            resource_bindings.append(index)
        if any(
            _rip_memory_target(instruction, operand) == identity_va
            for operand in _operands(instruction)
        ):
            identity_references.append(index)
    if len(resource_bindings) != 1 or len(identity_references) != 1:
        return False
    binding_index = resource_bindings[0]
    identity_index = identity_references[0]
    if identity_index <= binding_index:
        return False
    path_window = instructions[identity_index : identity_index + 5]
    identity_operands = _operands(instructions[identity_index])
    if not (
        len(path_window) == 5
        and instructions[identity_index].mnemonic.casefold() == "lea"
        and len(identity_operands) == 2
        and identity_operands[0].type == X86_OP_REG
        and identity_operands[0].reg == X86_REG_R8
        and _rip_memory_target(instructions[identity_index], identity_operands[1])
        == identity_va
    ):
        return False
    if not (
        any(_lea_stack_frame(item, X86_REG_RDX, 0x190) for item in path_window)
        and any(_lea_stack_frame(item, X86_REG_RCX, 0x3B0) for item in path_window)
        and any(_direct_call_target(item) is not None for item in path_window)
    ):
        return False
    create_candidates: list[int] = []
    for index in range(identity_index + 1, len(instructions)):
        if _direct_call_target(instructions[index]) is not None:
            continue
        operands = _operands(instructions[index])
        if not (
            instructions[index].mnemonic.casefold() == "call"
            and len(operands) == 1
            and operands[0].type == X86_OP_MEM
        ):
            continue
        before = instructions[max(identity_index, index - 10) : index]
        if any(_lea_stack_frame(item, X86_REG_RCX, 0x3B0) for item in before) and any(
            _register_immediate(item, X86_REG_EDX, 0x40000000) for item in before
        ):
            create_candidates.append(index)
    if len(create_candidates) != 1:
        return False
    create_index = create_candidates[0]
    write_candidates: list[int] = []
    for index in range(create_index + 1, min(len(instructions), create_index + 20)):
        operands = _operands(instructions[index])
        if not (
            instructions[index].mnemonic.casefold() == "call"
            and len(operands) == 1
            and operands[0].type == X86_OP_MEM
        ):
            continue
        before = instructions[max(create_index + 1, index - 6) : index]
        if any(
            _register_move(item, X86_REG_RDX, X86_REG_R12) for item in before
        ) and _register_move(instructions[index - 1], X86_REG_RCX, X86_REG_RAX):
            write_candidates.append(index)
    if len(write_candidates) != 1:
        return False
    anchors = (binding_index, identity_index, create_index, write_candidates[0])
    if not _ordered_cfg_path(graph, anchors):
        return False
    return all(
        _cfg_dominates(
            graph,
            int(instructions[left].address),
            int(instructions[right].address),
        )
        for left, right in pairwise(anchors)
    )


def _certificate_table_region_present(host: _PeContext) -> bool:
    """certificate tableのfile範囲だけを確認し、署名の真正性は主張しない。"""

    try:
        directory = host.image.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        offset = int(directory.VirtualAddress)
        size = int(directory.Size)
    except (AttributeError, IndexError, TypeError, ValueError, OverflowError):
        return False
    return offset > 0 and size >= 8 and offset + size <= len(host.data)


def _direct_calls(function: _Function) -> tuple[int, ...]:
    return tuple(
        target
        for instruction in function.instructions
        if (target := _direct_call_target(instruction)) is not None
    )


def _entry_patch_lineage(proxy: _PeContext) -> _Function | None:
    """host entrypoint差替え先からregistry/ChaCha workerを一意に得る。"""

    patch_candidates: list[tuple[_Function, int]] = []
    for raw_function in proxy.functions:
        function = _reachable_runtime_function(raw_function)
        if function is None:
            continue
        instructions = function.instructions
        immediates = {
            value & 0xFFFFFFFFFFFFFFFF
            for instruction in instructions
            for value in _immediate_values(instruction)
        }
        displacements = {
            value
            for instruction in instructions
            for value in _memory_displacements(instruction)
        }
        try:
            has_peb = any(
                any(
                    operand.type == X86_OP_MEM
                    and operand.mem.segment == X86_REG_GS
                    and operand.mem.disp == 0x60
                    for operand in instruction.operands
                )
                for instruction in instructions
            )
        except (AttributeError, CsError):
            continue
        if not (
            has_peb
            and {0x5A4D, 0x4550, 0xC, 0xB848, 0xE0FF}.issubset(immediates)
            and {0x10, 0x3C, 0x28, 0xA}.issubset(displacements)
        ):
            continue
        indirect_targets: list[int] = []
        rip_lea_targets: list[int] = []
        for instruction in instructions:
            try:
                operands = instruction.operands
            except (AttributeError, CsError):
                continue
            if instruction.mnemonic.casefold() == "call" and len(operands) == 1:
                target = _rip_memory_target(instruction, operands[0])
                if target is not None:
                    indirect_targets.append(target)
            if (
                instruction.mnemonic.casefold() == "lea"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and operands[0].reg == X86_REG_RAX
            ):
                target = _rip_memory_target(instruction, operands[1])
                target_function = (
                    _function_for_rva(proxy, target - proxy.image_base)
                    if target is not None
                    else None
                )
                target_function = (
                    _reachable_runtime_function(target_function)
                    if target_function is not None
                    else None
                )
                if (
                    target_function is not None
                    and target_function.instructions
                    and int(target_function.instructions[0].address) == target
                ):
                    rip_lea_targets.append(target)
        if (
            len(indirect_targets) == 2
            and len(set(indirect_targets)) == 1
            and len(rip_lea_targets) == 1
        ):
            patch_candidates.append((function, rip_lea_targets[0]))
    if len(patch_candidates) != 1:
        return None
    bootstrap = _function_for_rva(proxy, patch_candidates[0][1] - proxy.image_base)
    bootstrap = (
        _reachable_runtime_function(bootstrap) if bootstrap is not None else None
    )
    if bootstrap is None:
        return None
    worker_targets: list[int] = []
    for index, instruction in enumerate(bootstrap.instructions):
        try:
            operands = instruction.operands
        except (AttributeError, CsError):
            continue
        if not (
            instruction.mnemonic.casefold() == "lea"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_R8
        ):
            continue
        target = _rip_memory_target(instruction, operands[1])
        target_function = (
            _function_for_rva(proxy, target - proxy.image_base)
            if target is not None
            else None
        )
        target_function = (
            _reachable_runtime_function(target_function)
            if target_function is not None
            else None
        )
        if (
            target_function is None
            or not target_function.instructions
            or int(target_function.instructions[0].address) != target
        ):
            continue
        later = bootstrap.instructions[index + 1 : index + 9]
        if any(item.mnemonic.casefold() == "call" for item in later):
            worker_targets.append(target)
    if len(worker_targets) != 1:
        return None
    worker = _function_for_rva(proxy, worker_targets[0] - proxy.image_base)
    return _reachable_runtime_function(worker) if worker is not None else None


def _operand_memory(
    instruction: object,
    *,
    base: int | None = None,
    index: int | None = None,
    displacement: int | None = None,
) -> bool:
    try:
        for operand in instruction.operands:
            if operand.type != X86_OP_MEM:
                continue
            if base is not None and operand.mem.base != base:
                continue
            if index is not None and operand.mem.index != index:
                continue
            if displacement is not None and operand.mem.disp != displacement:
                continue
            return True
    except (AttributeError, CsError):
        return False
    return False


def _validate_chacha_function(function: _Function) -> bool:
    if not function.complete:
        return False
    immediates = [
        value & 0xFFFFFFFF
        for instruction in function.instructions
        for value in _immediate_values(instruction)
    ]
    rotations: dict[int, int] = {16: 0, 20: 0, 24: 0, 25: 0}
    for instruction in function.instructions:
        if instruction.mnemonic.casefold() not in {"ror", "rol"}:
            continue
        values = _immediate_values(instruction)
        if values and values[-1] in rotations:
            rotations[values[-1]] += 1
    return bool(
        {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574}.issubset(immediates)
        and 10 in immediates
        and rotations == {16: 8, 20: 8, 24: 8, 25: 8}
    )


def _unique_crypto_offsets(
    key_sources: list[int],
    f8_targets: list[int],
    nonce_sources: list[int],
) -> tuple[int, int, int] | None:
    """decoyを許容せず、連続するkey／nonceと単一maskだけを採用する。"""

    if len(key_sources) != 1 or len(f8_targets) != 1 or len(nonce_sources) != 1:
        return None
    key_rva = key_sources[0]
    nonce_rva = nonce_sources[0]
    if nonce_rva != key_rva + 32:
        return None
    return key_rva, nonce_rva, f8_targets[0]


def _worker_crypto_material(
    proxy: _PeContext, worker: _Function
) -> tuple[bytes, bytes] | None:
    """同一workerのBase64→key/nonce→ChaCha→XOR sinkを検証する。"""

    worker = _reachable_runtime_function(worker)
    if worker is None:
        return None
    instructions = worker.instructions
    base_leas: list[int] = []
    for index, instruction in enumerate(instructions):
        try:
            operands = instruction.operands
        except (AttributeError, CsError):
            continue
        if not (
            instruction.mnemonic.casefold() == "lea"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_RDX
            and _rip_memory_target(instruction, operands[1]) == proxy.image_base
        ):
            continue
        base_leas.append(index)
    if len(base_leas) != 1:
        return None
    start = base_leas[0]
    window = instructions[start : start + 24]
    key_sources: list[int] = []
    f8_targets: list[int] = []
    nonce_sources: list[int] = []
    for instruction in window:
        try:
            operands = instruction.operands
        except (AttributeError, CsError):
            continue
        if (
            instruction.mnemonic.casefold() == "movdqu"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_XMM0
            and operands[1].type == X86_OP_MEM
            and {operands[1].mem.base, operands[1].mem.index}
            == {X86_REG_RAX, X86_REG_RDX}
        ):
            key_sources.append(int(operands[1].mem.disp))
        if (
            instruction.mnemonic.casefold() == "xorps"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_XMM0
        ):
            target = _rip_memory_target(instruction, operands[1])
            if target is not None:
                f8_targets.append(target)
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_AL
            and operands[1].type == X86_OP_MEM
            and {operands[1].mem.base, operands[1].mem.index}
            == {X86_REG_RCX, X86_REG_RDX}
        ):
            nonce_sources.append(int(operands[1].mem.disp))
    offsets = _unique_crypto_offsets(key_sources, f8_targets, nonce_sources)
    if offsets is None:
        return None
    key_rva, nonce_rva, f8_target = offsets
    f8_rva = f8_target - proxy.image_base
    if _read_rva(proxy, f8_rva, 16) != b"\xf8" * 16:
        return None
    window_immediates = {
        value & 0xFFFFFFFFFFFFFFFF
        for instruction in window
        for value in _immediate_values(instruction)
    }
    if not {0x10, 0x20, 0xC, 0xF8}.issubset(window_immediates):
        return None
    raw_key = _read_rva(proxy, key_rva, 32)
    raw_nonce = _read_rva(proxy, nonce_rva, 12)
    if raw_key is None or raw_nonce is None:
        return None
    key = bytes(value ^ 0xF8 for value in raw_key)
    nonce = bytes(value ^ 0xF8 for value in raw_nonce)
    if len(set(key)) < 4 or len(set(nonce)) < 3:
        return None

    alphabet_offsets = [
        offset
        for offset in range(len(proxy.data) - len(_BASE64_ALPHABET) + 1)
        if proxy.data.startswith(_BASE64_ALPHABET, offset)
    ]
    if len(alphabet_offsets) != 1:
        return None
    try:
        alphabet_rva = int(proxy.image.get_rva_from_offset(alphabet_offsets[0]))
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return None
    alphabet_references = 0
    for instruction in instructions:
        try:
            operands = instruction.operands
        except (AttributeError, CsError):
            continue
        if instruction.mnemonic.casefold() != "lea" or len(operands) != 2:
            continue
        if (
            _rip_memory_target(instruction, operands[1])
            == proxy.image_base + alphabet_rva
        ):
            alphabet_references += 1
    worker_immediates = {
        value & 0xFFFFFFFFFFFFFFFF
        for instruction in instructions
        for value in _immediate_values(instruction)
    }
    if alphabet_references != 1 or not {0x3D, 0x40, 6, 8}.issubset(worker_immediates):
        return None

    called_functions: list[_Function] = []
    for target in _direct_calls(worker):
        candidate = _function_for_rva(proxy, target - proxy.image_base)
        candidate = (
            _reachable_runtime_function(candidate) if candidate is not None else None
        )
        if (
            candidate is not None
            and candidate.instructions
            and int(candidate.instructions[0].address) == target
            and _validate_chacha_function(candidate)
        ):
            called_functions.append(candidate)
    if len({item.start_rva for item in called_functions}) != 1:
        return None
    chacha = called_functions[0]
    call_indices = [
        index
        for index, instruction in enumerate(instructions)
        if _direct_call_target(instruction) == proxy.image_base + chacha.start_rva
    ]
    if len(call_indices) != 1:
        return None
    call_index = call_indices[0]
    before = instructions[max(0, call_index - 12) : call_index]
    after = instructions[call_index + 1 : call_index + 24]
    has_key_argument = any(
        _operand_memory(item, base=X86_REG_RSP, displacement=0x30) for item in before
    )
    has_nonce_argument = any(
        _operand_memory(item, base=X86_REG_RSP, displacement=0x20) for item in before
    )
    has_zero_counter = any(
        item.mnemonic.casefold() == "xor"
        and len(_operands(item)) == 2
        and item.operands[0].type == X86_OP_REG
        and item.operands[0].reg == X86_REG_EDI
        and item.operands[1].type == X86_OP_REG
        and item.operands[1].reg == X86_REG_EDI
        for item in instructions[max(0, call_index - 40) : call_index]
    ) and any(
        item.mnemonic.casefold() == "mov"
        and len(_operands(item)) == 2
        and item.operands[0].type == X86_OP_REG
        and item.operands[0].reg == X86_REG_R9D
        and item.operands[1].type == X86_OP_REG
        and item.operands[1].reg == X86_REG_EDI
        for item in before
    )
    has_xor_sink = any(
        item.mnemonic.casefold() == "xor"
        and any(operand.type == X86_OP_MEM for operand in _operands(item))
        for item in after
    )
    if not (
        has_key_argument and has_nonce_argument and has_zero_counter and has_xor_sink
    ):
        return None
    return key, nonce


def _decode_chacha(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes | None:
    if (
        not 1 <= len(ciphertext) <= MAXIMUM_SHELLCODE_SIZE
        or len(key) != 32
        or len(nonce) != 12
    ):
        return None
    try:
        cipher = Cipher(
            algorithms.ChaCha20(key, struct.pack("<I", 0) + nonce),
            mode=None,
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except (TypeError, ValueError):
        return None
    return plaintext if len(plaintext) == len(ciphertext) else None


def _strict_ascii_slot(data: bytes, offset: int, size: int) -> str | None:
    field = data[offset : offset + size]
    if len(field) != size:
        return None
    terminator = field.find(b"\0")
    if terminator <= 0 or any(field[terminator + 1 :]):
        return None
    try:
        value = field[:terminator].decode("ascii", errors="strict")
    except UnicodeError:
        return None
    return value if all(0x20 <= ord(character) <= 0x7E for character in value) else None


def _valid_host(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return bool(_DOMAIN.fullmatch(value))
    return (
        address.version == 4 and not address.is_unspecified and not address.is_multicast
    )


def _parse_endpoint(value: str) -> tuple[str, int] | None:
    if value.count(":") != 1:
        return None
    host, raw_port = value.rsplit(":", 1)
    if not raw_port.isdigit() or not _valid_host(host):
        return None
    port = int(raw_port)
    return (host, port) if 1 <= port <= 65535 else None


def _parse_hhstg_config(shellcode: bytes, marker: int) -> _HhstgConfig | None:
    if marker < 0 or marker + HHSTG_CONFIG_SIZE != len(shellcode):
        return None
    config = shellcode[marker:]
    if config[:8] != _HHSTG_MARKER:
        return None
    primary_host = _strict_ascii_slot(config, 0x08, 0x40)
    route = _strict_ascii_slot(config, 0x5A, 0x80)
    campaign = _strict_ascii_slot(config, 0xDA, 0x40)
    if primary_host is None or route is None or campaign is None:
        return None
    if not _valid_host(primary_host) or not _CAMPAIGN.fullmatch(campaign):
        return None
    try:
        primary_port = struct.unpack_from("<H", config, 0x48)[0]
    except struct.error:
        return None
    if not 1 <= primary_port <= 65535:
        return None
    key = config[0x4A:0x5A]
    if len(key) != 16 or len(set(key)) < 4:
        return None
    route_endpoints: list[tuple[str, int]] = []
    if route:
        parts = route.split("||")
        if not 1 <= len(parts) <= 2 or any(not item for item in parts):
            return None
        for part in parts:
            endpoint = _parse_endpoint(part)
            if endpoint is None or endpoint in route_endpoints:
                return None
            route_endpoints.append(endpoint)
        if route_endpoints[0] != (primary_host, primary_port):
            return None
    else:
        route_endpoints.append((primary_host, primary_port))
    return _HhstgConfig(
        primary_host,
        primary_port,
        tuple(route_endpoints),
        campaign,
        key,
    )


def _decode_shellcode(shellcode: bytes, marker: int) -> _InstructionGraph | None:
    if not 512 <= marker <= len(shellcode) <= MAXIMUM_SHELLCODE_SIZE:
        return None
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
        decoded = tuple(disassembler.disasm(shellcode[:marker], 0))
    except CsError:
        return None
    if (
        not decoded
        or len(decoded) > MAXIMUM_SHELLCODE_INSTRUCTIONS
        or decoded[0].address != 0
        or decoded[-1].address + decoded[-1].size != marker
        or sum(item.size for item in decoded) != marker
    ):
        return None
    by_address = {int(item.address): item for item in decoded}
    if len(by_address) != len(decoded):
        return None
    all_successors: dict[int, tuple[int, ...]] = {}
    for instruction in decoded:
        address = int(instruction.address)
        following = address + int(instruction.size)
        mnemonic = instruction.mnemonic.casefold()
        direct = _direct_call_target(instruction)
        if mnemonic == "jmp":
            try:
                operands = instruction.operands
            except (AttributeError, CsError):
                operands = ()
            target = (
                int(operands[0].imm)
                if len(operands) == 1 and operands[0].type == X86_OP_IMM
                else None
            )
            candidates = (
                (target,) if target is not None and 0 <= target < marker else ()
            )
        elif mnemonic.startswith("j") or mnemonic in {"loop", "loope", "loopne"}:
            try:
                operands = instruction.operands
            except (AttributeError, CsError):
                return None
            target = (
                int(operands[0].imm)
                if len(operands) == 1
                and operands[0].type == X86_OP_IMM
                and 0 <= int(operands[0].imm) < marker
                else None
            )
            candidates = tuple(
                value
                for value in (target, following)
                if value is not None and value != marker
            )
        elif mnemonic == "call":
            candidates = tuple(
                value
                for value in (
                    following,
                    direct if direct is not None and 0 <= direct < marker else None,
                )
                if value is not None and value != marker
            )
        elif mnemonic.startswith("ret") or mnemonic in {"int3", "ud2", "hlt"}:
            candidates = ()
        else:
            candidates = () if following == marker else (following,)
        if any(value not in by_address for value in candidates):
            return None
        all_successors[address] = tuple(dict.fromkeys(candidates))

    pending = [0]
    queued = {0}
    reachable: set[int] = set()
    cursor = 0
    while cursor < len(pending):
        if len(pending) > MAXIMUM_SHELLCODE_INSTRUCTIONS:
            return None
        address = pending[cursor]
        cursor += 1
        if address in reachable:
            continue
        reachable.add(address)
        if len(reachable) > MAXIMUM_SHELLCODE_INSTRUCTIONS:
            return None
        for target in all_successors[address]:
            if target not in reachable and target not in queued:
                pending.append(target)
                queued.add(target)
    instructions = tuple(item for item in decoded if int(item.address) in reachable)
    successors = {
        address: tuple(
            target for target in all_successors[address] if target in reachable
        )
        for address in sorted(reachable)
    }
    return _InstructionGraph(instructions, successors)


def _path_reaches(graph: _InstructionGraph, start: int, finish: int) -> bool:
    """CFG上で二つのanchorが同一実行pathへ連結することを有界に確認する。"""

    if start == finish:
        return True
    pending = [start]
    queued = {start}
    visited: set[int] = set()
    cursor = 0
    while cursor < len(pending):
        if len(pending) > MAXIMUM_SHELLCODE_INSTRUCTIONS:
            return False
        address = pending[cursor]
        cursor += 1
        if address in visited:
            continue
        visited.add(address)
        for target in graph.successors.get(address, ()):
            if target == finish:
                return True
            if target not in visited and target not in queued:
                pending.append(target)
                queued.add(target)
    return False


def _cfg_dominates(graph: _InstructionGraph, dominator: int, node: int) -> bool:
    """entryから指定nodeへdominatorを避ける経路がないことを有界に確認する。"""

    if dominator == node:
        return dominator in graph.successors
    if not _path_reaches(graph, dominator, node):
        return False
    pending = [graph.entry_address]
    queued = {graph.entry_address}
    cursor = 0
    while cursor < len(pending):
        if len(pending) > MAXIMUM_SHELLCODE_INSTRUCTIONS:
            return False
        address = pending[cursor]
        cursor += 1
        for target in graph.successors.get(address, ()):
            if target == dominator:
                continue
            if target == node:
                return False
            if target not in queued:
                pending.append(target)
                queued.add(target)
    return True


def _direct_stack_literals(
    instructions: tuple[object, ...],
) -> tuple[tuple[int, int, bytes], ...]:
    writes: list[tuple[int, int, int, int]] = []
    for index, instruction in enumerate(instructions):
        try:
            operands = instruction.operands
        except (AttributeError, CsError):
            continue
        if not (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].size == 1
            and operands[0].mem.base == X86_REG_RSP
            and operands[0].mem.index == X86_REG_INVALID
            and operands[1].type == X86_OP_IMM
        ):
            continue
        writes.append(
            (
                index,
                int(instruction.address),
                int(operands[0].mem.disp),
                int(operands[1].imm) & 0xFF,
            )
        )
    runs: list[tuple[int, int, bytes]] = []
    cursor = 0
    while cursor < len(writes):
        start = cursor
        while (
            cursor + 1 < len(writes)
            and writes[cursor + 1][0] == writes[cursor][0] + 1
            and writes[cursor + 1][2] == writes[cursor][2] + 1
            and writes[cursor + 1][1] - writes[cursor][1] <= 16
        ):
            cursor += 1
        group = writes[start : cursor + 1]
        if len(group) >= 3:
            runs.append((group[0][0], group[0][2], bytes(item[3] for item in group)))
        cursor += 1
    return tuple(runs)


def _stack_destination(instruction: object, displacement: int) -> bool:
    operands = _operands(instruction)
    return bool(
        operands
        and operands[0].type == X86_OP_MEM
        and operands[0].mem.base == X86_REG_RSP
        and operands[0].mem.index == X86_REG_INVALID
        and operands[0].mem.disp == displacement
    )


def _scaled_register(
    instruction: object,
    register: int,
    scale: int,
) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == "imul"
        and len(operands) == 3
        and operands[0].type == X86_OP_REG
        and operands[0].reg == register
        and operands[1].type == X86_OP_REG
        and operands[1].reg == register
        and operands[2].type == X86_OP_IMM
        and int(operands[2].imm) == scale
    )


def _indexed_stack_lea(
    instruction: object,
    destination: int,
    index: int,
    displacement: int,
) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == "lea"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[0].reg == destination
        and operands[1].type == X86_OP_MEM
        and operands[1].mem.base == X86_REG_RSP
        and operands[1].mem.index == index
        and operands[1].mem.disp == displacement
    )


def _fallback_route_write_anchors(
    instructions: tuple[object, ...],
    source_displacement: int,
    graph: _InstructionGraph,
) -> tuple[int, ...]:
    """同じcopy counterでliteral byteをroute tableへ書く固定data-flowを得る。"""

    matches: list[int] = []
    for index, instruction in enumerate(instructions):
        operands = _operands(instruction)
        if not (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].size == 1
            and operands[0].mem.base == X86_REG_RCX
            and operands[0].mem.index == X86_REG_RDX
            and operands[0].mem.disp == 0
            and operands[1].type == X86_OP_REG
            and operands[1].reg == X86_REG_AL
        ):
            continue
        data_flow_matches = 0
        for start in range(max(0, index - 12), max(0, index - 5)):
            window = instructions[start : start + 6]
            if len(window) != 6:
                continue
            first_operands = _operands(window[0])
            source_operands = _operands(window[5])
            if not (
                len(first_operands) == 2
                and first_operands[1].type == X86_OP_MEM
                and first_operands[1].mem.base == X86_REG_RSP
                and first_operands[1].mem.index == X86_REG_INVALID
                and 0 <= first_operands[1].mem.disp <= 0x400
            ):
                continue
            counter_displacement = int(first_operands[1].mem.disp)
            if (
                _stack_load(window[0], X86_REG_RAX, counter_displacement)
                and _stack_load(window[1], X86_REG_RCX, 0x38)
                and _scaled_register(window[2], X86_REG_RCX, 0x42)
                and _indexed_stack_lea(window[3], X86_REG_RCX, X86_REG_RCX, 0x380)
                and _stack_load(window[4], X86_REG_RDX, counter_displacement)
                and len(source_operands) == 2
                and source_operands[0].type == X86_OP_REG
                and source_operands[0].reg == X86_REG_AL
                and source_operands[1].type == X86_OP_MEM
                and source_operands[1].mem.base == X86_REG_RSP
                and source_operands[1].mem.index == X86_REG_RAX
                and source_operands[1].mem.disp == source_displacement
                and _ordered_cfg_path(
                    graph,
                    (*range(start, start + 6), index),
                )
                and all(
                    _cfg_dominates(
                        graph,
                        int(instructions[left].address),
                        int(instructions[right].address),
                    )
                    for left, right in pairwise((*range(start, start + 6), index))
                )
            ):
                data_flow_matches += 1
        if data_flow_matches == 1:
            matches.append(index)
    return tuple(matches)


def _fallback_port_store_anchors(
    instructions: tuple[object, ...],
) -> tuple[int, ...]:
    matches: list[int] = []
    for index, instruction in enumerate(instructions):
        operands = _operands(instruction)
        if not (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].size == 2
            and operands[0].mem.base == X86_REG_RSP
            and operands[0].mem.index == X86_REG_RAX
            and operands[0].mem.disp == 0x3C0
            and operands[1].type == X86_OP_REG
            and operands[1].reg == X86_REG_CX
            and index >= 3
        ):
            continue
        window = instructions[index - 3 : index]
        if (
            _stack_load(window[0], X86_REG_RAX, 0x38)
            and _scaled_register(window[1], X86_REG_RAX, 0x42)
            and _register_immediate(window[2], X86_REG_ECX, 443)
        ):
            matches.append(index)
    return tuple(matches)


def _fallback_slots(
    shellcode: bytes,
    instructions: tuple[object, ...],
    runs: tuple[tuple[int, int, bytes], ...],
    graph: _InstructionGraph,
    connect_addresses: tuple[int, ...],
) -> tuple[tuple[str, int], ...] | None:
    candidates: list[tuple[int, int, str]] = []
    for index, displacement, raw in runs:
        if not raw.endswith(b"\0"):
            continue
        try:
            value = raw[:-1].decode("ascii", errors="strict")
        except UnicodeError:
            continue
        if _DOMAIN.fullmatch(value) and not value.casefold().endswith(".dll"):
            candidates.append((index, displacement, value))
    if len(candidates) != 2 or candidates[0][2] == candidates[1][2]:
        return None
    port_offsets = [
        offset
        for offset in range(len(shellcode) - len(_PORT_STORE_SIGNATURE) + 1)
        if shellcode.startswith(_PORT_STORE_SIGNATURE, offset)
    ]
    port_anchors = _fallback_port_store_anchors(instructions)
    if (
        len(port_offsets) != 2
        or len(port_anchors) != 2
        or {int(instructions[index - 1].address) for index in port_anchors}
        != set(port_offsets)
    ):
        return None
    result: list[tuple[str, int]] = []
    used_ports: set[int] = set()
    connect_indexes = {
        int(instruction.address): index
        for index, instruction in enumerate(instructions)
        if int(instruction.address) in connect_addresses
    }
    if set(connect_indexes) != set(connect_addresses):
        return None
    for run_index, displacement, host in candidates:
        literal_final_index = run_index + len(host.encode("ascii"))
        if not 0 <= literal_final_index < len(instructions):
            return None
        route_anchors = _fallback_route_write_anchors(
            instructions,
            displacement,
            graph,
        )
        if len(route_anchors) != 1:
            return None
        route_index = route_anchors[0]
        literal_address = int(instructions[literal_final_index].address)
        route_address = int(instructions[route_index].address)
        validated: list[tuple[int, int]] = []
        for port_index in port_anchors:
            if port_index <= route_index or any(
                _stack_destination(item, 0x38)
                for item in instructions[route_index + 1 : port_index]
            ):
                continue
            port_address = int(instructions[port_index].address)
            if (
                port_address - int(instructions[run_index].address) > 2048
                or not _cfg_dominates(graph, literal_address, route_address)
                or not _cfg_dominates(graph, literal_address, port_address)
            ):
                continue
            for connect_address in connect_addresses:
                connect_index = connect_indexes[connect_address]
                if _ordered_cfg_path(
                    graph,
                    (
                        literal_final_index,
                        route_index,
                        port_index,
                        connect_index,
                    ),
                ):
                    validated.append((port_index, connect_address))
        if len(validated) != 1 or validated[0][0] in used_ports:
            return None
        used_ports.add(validated[0][0])
        result.append((host, 443))
    return tuple(result) if len(used_ports) == len(port_anchors) else None


def _indexed_hello(instructions: tuple[object, ...]) -> bytes:
    values: list[int] = []
    for instruction in instructions:
        try:
            operands = instruction.operands
        except (AttributeError, CsError):
            continue
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].size == 1
            and operands[0].mem.base == X86_REG_RSP
            and operands[0].mem.index == X86_REG_RAX
            and operands[0].mem.disp == 0x114
            and operands[1].type == X86_OP_IMM
        ):
            values.append(int(operands[1].imm) & 0xFF)
    return bytes(values)


def _instruction_has_immediate(instruction: object, value: int) -> bool:
    return value & 0xFFFFFFFFFFFFFFFF in _immediate_values(instruction)


def _indirect_stack_call(instruction: object, displacement: int) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == "call"
        and len(operands) == 1
        and operands[0].type == X86_OP_MEM
        and operands[0].mem.base == X86_REG_RSP
        and operands[0].mem.index == X86_REG_INVALID
        and operands[0].mem.disp == displacement
    )


def _stack_load(instruction: object, register: int, displacement: int) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() in {"mov", "movzx", "movsx", "movsxd"}
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[0].reg == register
        and operands[1].type == X86_OP_MEM
        and operands[1].mem.base == X86_REG_RSP
        and operands[1].mem.index == X86_REG_INVALID
        and operands[1].mem.disp == displacement
    )


def _stack_lea(instruction: object, register: int, displacement: int) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == "lea"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[0].reg == register
        and operands[1].type == X86_OP_MEM
        and operands[1].mem.base == X86_REG_RSP
        and operands[1].mem.disp == displacement
    )


def _stack_store(instruction: object, displacement: int, register: int) -> bool:
    operands = _operands(instruction)
    return bool(
        instruction.mnemonic.casefold() == "mov"
        and len(operands) == 2
        and operands[0].type == X86_OP_MEM
        and operands[0].mem.base == X86_REG_RSP
        and operands[0].mem.index == X86_REG_INVALID
        and operands[0].mem.disp == displacement
        and operands[1].type == X86_OP_REG
        and operands[1].reg == register
    )


def _copy_loop_anchors(
    instructions: tuple[object, ...],
    *,
    source_slot: int,
    source_displacement: int,
    destination_displacement: int,
) -> tuple[int, ...]:
    matches: list[int] = []
    for index, instruction in enumerate(instructions):
        operands = _operands(instruction)
        if not (
            instruction.mnemonic.casefold() == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].mem.base == X86_REG_RDX
            and operands[0].mem.index == X86_REG_RCX
            and operands[1].type == X86_OP_REG
            and operands[1].reg == X86_REG_AL
        ):
            continue
        window = instructions[max(0, index - 16) : index + 1]
        source_loads = [
            item
            for item in window
            if item.mnemonic.casefold() == "mov"
            and len(_operands(item)) == 2
            and _operands(item)[0].type == X86_OP_REG
            and _operands(item)[0].reg == X86_REG_RDI
        ]
        has_source_load = bool(
            source_loads and _stack_load(source_loads[-1], X86_REG_RDI, source_slot)
        )
        has_output_load = any(_stack_load(item, X86_REG_RDX, 0x50) for item in window)
        destination_leas = [
            item
            for item in window
            if item.mnemonic.casefold() == "lea"
            and len(_operands(item)) == 2
            and _operands(item)[0].type == X86_OP_REG
            and _operands(item)[0].reg in {X86_REG_RCX, X86_REG_ECX}
        ]
        has_destination = bool(
            destination_leas
            and destination_displacement in _memory_displacements(destination_leas[-1])
        )
        has_source_byte = any(
            item.mnemonic.casefold() in {"mov", "movzx", "movsx"}
            and any(
                operand.type == X86_OP_MEM
                and operand.mem.base == X86_REG_RDI
                and operand.mem.index == X86_REG_RAX
                and operand.mem.disp == source_displacement
                for operand in _operands(item)
            )
            for item in window
        )
        if has_source_load and has_output_load and has_destination and has_source_byte:
            matches.append(index)
    return tuple(matches)


def _ordered_cfg_path(graph: _InstructionGraph, indexes: tuple[int, ...]) -> bool:
    instructions = graph.instructions
    if not indexes or any(not 0 <= index < len(instructions) for index in indexes):
        return False
    return all(
        _path_reaches(
            graph,
            int(instructions[left].address),
            int(instructions[right].address),
        )
        for left, right in pairwise(indexes)
    )


def _any_index_dominates(
    graph: _InstructionGraph,
    candidate_indexes: tuple[int, ...],
    sink_index: int,
) -> bool:
    """近傍命令でなく、sinkを支配する引数producerだけを採用する。"""

    instructions = graph.instructions
    sink_address = int(instructions[sink_index].address)
    return any(
        _cfg_dominates(
            graph,
            int(instructions[index].address),
            sink_address,
        )
        for index in candidate_indexes
    )


def _index_dominates_any(
    graph: _InstructionGraph,
    source_index: int,
    candidate_indexes: tuple[int, ...],
) -> bool:
    """source callが支配するresult consumerだけを採用する。"""

    instructions = graph.instructions
    source_address = int(instructions[source_index].address)
    return any(
        _cfg_dominates(
            graph,
            source_address,
            int(instructions[index].address),
        )
        for index in candidate_indexes
    )


def _validate_hhstg_transport(
    graph: _InstructionGraph,
    runs: tuple[tuple[int, int, bytes], ...],
) -> tuple[int, ...] | None:
    instructions = graph.instructions
    literal_values = {raw for _, _, raw in runs}
    if not {b"ntdll\0", b"ws2_32.dll\0", b"AppConfig\0"}.issubset(literal_values):
        return None
    if _indexed_hello(instructions) != _HELLO:
        return None
    if not any(_register_immediate(item, X86_REG_CX, 0x202) for item in instructions):
        return None
    colon_comparisons = sum(
        item.mnemonic.casefold() == "cmp" and _instruction_has_immediate(item, 0x3A)
        for item in instructions
    )
    backup_comparisons = sum(
        item.mnemonic.casefold() == "cmp" and _instruction_has_immediate(item, 0x7C)
        for item in instructions
    )
    has_route_stride = any(
        item.mnemonic.casefold() == "imul" and _instruction_has_immediate(item, 0x42)
        for item in instructions
    )
    has_eight_slot_bound = any(
        item.mnemonic.casefold() == "cmp"
        and _instruction_has_immediate(item, 8)
        and 0x38 in _memory_displacements(item)
        for item in instructions
    )
    if (
        colon_comparisons < 2
        or backup_comparisons < 2
        or not has_route_stride
        or not has_eight_slot_bound
    ):
        return None

    socket_calls: list[int] = []
    connect_calls: list[int] = []
    send_calls: list[int] = []
    recv_calls: list[int] = []
    allocation_calls: list[int] = []
    copy_calls: list[int] = []
    protect_calls: list[int] = []
    thread_calls: list[int] = []
    for index, instruction in enumerate(instructions):
        before_indexes = tuple(range(max(0, index - 12), index))
        after_indexes = tuple(range(index + 1, min(len(instructions), index + 5)))
        if _indirect_stack_call(instruction, 0x238) and (
            _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_immediate(instructions[candidate], X86_REG_R8D, 6)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_immediate(instructions[candidate], X86_REG_EDX, 1)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_immediate(instructions[candidate], X86_REG_ECX, 2)
                ),
                index,
            )
            and _index_dominates_any(
                graph,
                index,
                tuple(
                    candidate
                    for candidate in after_indexes
                    if _stack_store(instructions[candidate], 0x68, X86_REG_RAX)
                ),
            )
        ):
            socket_calls.append(index)
        if _indirect_stack_call(instruction, 0x248) and (
            _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_immediate(instructions[candidate], X86_REG_R8D, 0x10)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _stack_lea(instructions[candidate], X86_REG_RDX, 0x2E0)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _stack_load(instructions[candidate], X86_REG_RCX, 0x68)
                ),
                index,
            )
        ):
            connect_calls.append(index)
        if _indirect_stack_call(instruction, 0x2A8) and (
            _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_immediate(instructions[candidate], X86_REG_R8D, 7)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _stack_lea(instructions[candidate], X86_REG_RDX, 0x114)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _stack_load(instructions[candidate], X86_REG_RCX, 0x68)
                ),
                index,
            )
            and _index_dominates_any(
                graph,
                index,
                tuple(
                    candidate
                    for candidate in after_indexes
                    if instructions[candidate].mnemonic.casefold() == "cmp"
                    and _instruction_has_immediate(instructions[candidate], 7)
                ),
            )
        ):
            send_calls.append(index)
        if _indirect_stack_call(instruction, 0x250):
            recv_calls.append(index)
        if _indirect_stack_call(instruction, 0x200) and (
            _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_immediate(instructions[candidate], X86_REG_R9D, 4)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_immediate(instructions[candidate], X86_REG_R8D, 0x3000)
                ),
                index,
            )
            and _index_dominates_any(
                graph,
                index,
                tuple(
                    candidate
                    for candidate in after_indexes
                    if _stack_store(instructions[candidate], 0x50, X86_REG_RAX)
                ),
            )
        ):
            allocation_calls.append(index)
        if _indirect_stack_call(instruction, 0x208) and (
            _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _stack_load(instructions[candidate], X86_REG_EAX, 0x84)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_move(instructions[candidate], X86_REG_R8D, X86_REG_EAX)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _stack_load(instructions[candidate], X86_REG_RDX, 0x50)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _stack_load(instructions[candidate], X86_REG_RCX, 0xE8)
                ),
                index,
            )
        ):
            copy_calls.append(index)
        if _indirect_stack_call(instruction, 0x2B8) and (
            _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _register_immediate(instructions[candidate], X86_REG_R8D, 0x20)
                ),
                index,
            )
            and _any_index_dominates(
                graph,
                tuple(
                    candidate
                    for candidate in before_indexes
                    if _stack_load(instructions[candidate], X86_REG_RCX, 0xE8)
                ),
                index,
            )
        ):
            protect_calls.append(index)
        if _indirect_stack_call(instruction, 0x278) and _any_index_dominates(
            graph,
            tuple(
                candidate
                for candidate in before_indexes
                if _stack_load(instructions[candidate], X86_REG_R8, 0xE8)
            ),
            index,
        ):
            thread_calls.append(index)
    if not socket_calls or not connect_calls or len(send_calls) != 1:
        return None
    send_index = send_calls[0]
    length_compares = [
        index
        for index, item in enumerate(instructions)
        if item.mnemonic.casefold() == "cmp"
        and 4 in _immediate_values(item)
        and 0x48 in _memory_displacements(item)
        and _path_reaches(
            graph, int(instructions[send_index].address), int(item.address)
        )
    ]
    maximum_stages = [
        index
        for index, item in enumerate(instructions)
        if item.mnemonic.casefold() == "cmp" and 0xA00000 in _immediate_values(item)
    ]
    if (
        len(length_compares) != 1
        or len(maximum_stages) != 1
        or len(allocation_calls) != 1
    ):
        return None
    recv_length_candidates = [
        index
        for index in recv_calls
        if _ordered_cfg_path(
            graph, (send_index, length_compares[0], index, maximum_stages[0])
        )
        and any(
            0xA8 in _memory_displacements(item)
            for item in instructions[max(0, index - 10) : index]
        )
        and any(
            _stack_load(item, X86_REG_RCX, 0x68)
            for item in instructions[max(0, index - 10) : index]
        )
    ]
    payload_recv_candidates = [
        index
        for index in recv_calls
        if _ordered_cfg_path(graph, (allocation_calls[0], index))
        and any(
            0x50 in _memory_displacements(item)
            for item in instructions[max(0, index - 12) : index]
        )
        and any(
            _stack_load(item, X86_REG_RCX, 0x68)
            for item in instructions[max(0, index - 12) : index]
        )
    ]
    if len(recv_length_candidates) != 1 or len(payload_recv_candidates) != 1:
        return None

    xor_candidates: list[int] = []
    for index, item in enumerate(instructions):
        operands = _operands(item)
        if not (
            item.mnemonic.casefold() == "xor"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[0].reg == X86_REG_ECX
            and operands[1].type == X86_OP_REG
            and operands[1].reg == X86_REG_EAX
        ):
            continue
        before = instructions[max(0, index - 18) : index]
        after = instructions[index + 1 : index + 7]
        if (
            any(
                _register_immediate(candidate, X86_REG_ECX, 0x10)
                for candidate in before
            )
            and any(candidate.mnemonic.casefold() == "div" for candidate in before)
            and any(0x4A in _memory_displacements(candidate) for candidate in before)
            and any(_stack_load(candidate, X86_REG_RCX, 0x50) for candidate in before)
            and any(_stack_load(candidate, X86_REG_RDX, 0x2B0) for candidate in before)
            and any(
                candidate.mnemonic.casefold() == "mov"
                and any(operand.type == X86_OP_MEM for operand in _operands(candidate))
                for candidate in after
            )
        ):
            xor_candidates.append(index)
    if len(xor_candidates) != 1:
        return None

    app_run = next((item for item in runs if item[2] == b"AppConfig\0"), None)
    current_host = _copy_loop_anchors(
        instructions,
        source_slot=0x260,
        source_displacement=0,
        destination_displacement=0x20,
    )
    backup_host = _copy_loop_anchors(
        instructions,
        source_slot=0x270,
        source_displacement=0,
        destination_displacement=0x128,
    )
    campaign_copy = _copy_loop_anchors(
        instructions,
        source_slot=0xC8,
        source_displacement=0xDA,
        destination_displacement=0x694,
    )
    current_ports = [
        index
        for index, item in enumerate(instructions)
        if 0x124 in _memory_displacements(item)
        and any(
            _stack_load(candidate, X86_REG_RCX, 0x50)
            for candidate in instructions[max(0, index - 8) : index]
        )
        and any(
            _stack_load(candidate, X86_REG_EDX, 0x214)
            for candidate in instructions[max(0, index - 8) : index]
        )
    ]
    backup_ports = [
        index
        for index, item in enumerate(instructions)
        if 0x22C in _memory_displacements(item)
        and any(
            _stack_load(candidate, X86_REG_RCX, 0x50)
            for candidate in instructions[max(0, index - 8) : index]
        )
        and any(
            _stack_load(candidate, X86_REG_EDX, 0x1F8)
            for candidate in instructions[max(0, index - 8) : index]
        )
    ]
    if (
        app_run is None
        or len(current_host) != 1
        or len(backup_host) != 1
        or len(campaign_copy) != 1
        or len(current_ports) != 1
        or len(backup_ports) != 1
        or len(copy_calls) != 1
        or len(protect_calls) != 1
        or len(thread_calls) != 1
    ):
        return None
    fixed_chain = (
        send_index,
        length_compares[0],
        recv_length_candidates[0],
        maximum_stages[0],
        allocation_calls[0],
        payload_recv_candidates[0],
        xor_candidates[0],
        app_run[0],
        current_host[0],
        current_ports[0],
        backup_host[0],
        backup_ports[0],
        campaign_copy[0],
        copy_calls[0],
        protect_calls[0],
        thread_calls[0],
    )
    if not _ordered_cfg_path(graph, fixed_chain):
        return None
    connection_paths = [
        (socket_index, connect_index)
        for socket_index in socket_calls
        for connect_index in connect_calls
        if _ordered_cfg_path(graph, (socket_index, connect_index, send_index))
    ]
    if not connection_paths:
        return None
    return tuple(
        sorted({int(instructions[item[1]].address) for item in connection_paths})
    )


def _recover_hhstg_shellcode(
    shellcode: bytes,
) -> tuple[_HhstgConfig, tuple[tuple[str, int], ...]] | None:
    if (
        not isinstance(shellcode, bytes)
        or not 1 <= len(shellcode) <= MAXIMUM_SHELLCODE_SIZE
        or shellcode.count(_HHSTG_MARKER) != 1
    ):
        return None
    marker = shellcode.find(_HHSTG_MARKER)
    config = _parse_hhstg_config(shellcode, marker)
    if config is None:
        return None
    graph = _decode_shellcode(shellcode, marker)
    if graph is None:
        return None
    instructions = graph.instructions
    runs = _direct_stack_literals(instructions)
    connect_addresses = _validate_hhstg_transport(graph, runs)
    if connect_addresses is None:
        return None
    fallbacks = _fallback_slots(
        shellcode[:marker],
        instructions,
        runs,
        graph,
        connect_addresses,
    )
    if fallbacks is None or len(fallbacks) != 2:
        return None
    configured = set(config.route_endpoints)
    if any(item in configured for item in fallbacks):
        return None
    return config, fallbacks


def _resource_proxy_host_roles(
    resource_101: _PeContext,
    resource_102: _PeContext,
) -> tuple[_PeContext, _PeContext] | None:
    """外側loaderが実配置するresource 101だけをproxy DLLとして採用する。"""

    try:
        resource_101_is_dll = bool(
            int(resource_101.image.FILE_HEADER.Characteristics) & 0x2000
        )
        resource_102_is_dll = bool(
            int(resource_102.image.FILE_HEADER.Characteristics) & 0x2000
        )
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not resource_101_is_dll or resource_102_is_dll:
        return None
    return resource_101, resource_102


def recover_hhstg_resource(data: bytes) -> HhstgResourceRecovery | None:
    """HHSTG loader構造候補が一意な単一PEだけを手動確認用に復元する。"""

    outer = _load_x64_pe(data)
    if outer is None:
        return None
    resources = _resource_leaves(outer)
    if resources is None:
        return None
    decoded = _outer_transform(outer, resources)
    if decoded is None:
        return None
    first = _load_x64_pe(decoded[0])
    second = _load_x64_pe(decoded[1])
    if first is None or second is None:
        return None
    roles = _resource_proxy_host_roles(first, second)
    if roles is None:
        return None
    proxy, host = roles
    exports = _named_exports(proxy)
    proxy_identity = (
        _host_import_binding(host, exports[0]) if exports is not None else None
    )
    if (
        exports is None
        or proxy_identity is None
        or not _outer_proxy_file_binding(
            outer,
            decoded[2],
            proxy_identity,
            decoded[3],
        )
        or not _certificate_table_region_present(host)
    ):
        return None
    worker = _entry_patch_lineage(proxy)
    if worker is None:
        return None
    crypto = _worker_crypto_material(proxy, worker)
    if crypto is None:
        return None
    resource_tail = resources[103][RESOURCE_TAIL_OFFSET:]
    if (
        not 4 <= len(resource_tail) <= MAXIMUM_SHELLCODE_SIZE * 2
        or len(resource_tail) % 4
        or any(
            value
            not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            for value in resource_tail
        )
    ):
        return None
    try:
        ciphertext = base64.b64decode(resource_tail, validate=True)
    except (binascii.Error, ValueError):
        return None
    shellcode = _decode_chacha(ciphertext, crypto[0], crypto[1])
    if shellcode is None:
        return None
    terminal = _recover_hhstg_shellcode(shellcode)
    if terminal is None:
        return None
    config, fallbacks = terminal
    slots: list[StageEndpoint] = []
    for index, (host_name, port) in enumerate(config.route_endpoints):
        slots.append(StageEndpoint(host_name, port, "configured_route", index))
    for index, (host_name, port) in enumerate(fallbacks):
        slots.append(StageEndpoint(host_name, port, "embedded_fallback", index))
    if len({item.endpoint for item in slots}) != len(slots):
        return None
    return HhstgResourceRecovery(
        tuple(slots),
        len(config.route_endpoints),
        len(fallbacks),
        len(exports[0]),
        bool(config.campaign),
    )


def public_recovery_summary(recovery: HhstgResourceRecovery) -> dict[str, object]:
    """key、raw payload、IOCを含めず候補復元の証拠境界を公開する。"""

    return {
        "schema_version": 2,
        "profile": "single_pe_hhstg_resource_stage_loader",
        "loader_component_confirmed": False,
        "route_only": True,
        "automatic_route_eligible": False,
        "static_configuration_confirmed": False,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "outer_resource_transform_validated": True,
        "resource_101_proxy_role_validated": True,
        "resource_102_host_role_validated": True,
        "proxy_host_import_export_binding_validated": True,
        "proxy_host_runtime_dll_identity_binding_validated": True,
        "proxy_export_rva_executable_validated": True,
        "certificate_table_region_present": True,
        "host_entrypoint_patch_structure_present": True,
        "proxy_export_to_entry_patch_path_validated": False,
        "resource_103_registry_write_binding_validated": True,
        "registry_base64_chacha20_validated": False,
        "resource_103_registry_crypto_data_flow_validated": False,
        "unique_static_decode_candidate_recovered": True,
        "hhstg_entry_zero_reachable_cfg_validated": True,
        "hhstg_stage_acquisition_path_validated": False,
        "runtime_api_argument_data_flow_validated": False,
        "configured_route_data_flow_validated": False,
        "fallback_literal_route_port_connect_cfg_validated": True,
        "fallback_literal_dominance_validated": True,
        "appconfig_patch_structure_present": True,
        "appconfig_patch_data_flow_validated": False,
        "configured_route_slot_count": recovery.configured_route_count,
        "embedded_fallback_slot_count": recovery.embedded_fallback_count,
        "stage_acquisition_slot_count": len(recovery.endpoints),
        "proxy_export_binding_count": recovery.export_binding_count,
        "campaign_slot_present": recovery.campaign_present,
        "endpoint_role": "stage_acquisition_route_candidate",
        "endpoint_confirmation": "unverified_static_candidate",
        "command_c2_confirmed": False,
        "raw_key_included": False,
        "raw_payload_included": False,
        "raw_config_included": False,
        "raw_network_values_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "HhstgResourceRecovery",
    "StageEndpoint",
    "public_recovery_summary",
    "recover_hhstg_resource",
]
