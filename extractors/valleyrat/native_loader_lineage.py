"""native loaderからValleyRAT終端までを静的に証明する。

検体、復元component、CLRを実行せず、PE tableとfile-backed codeだけを扱う。
hash、resource名、出力file名、外部label、endpoint値は判定へ使用しない。
loader構造だけをfamily根拠にせず、終端componentで設定から
connect/send/recvおよびprotocolまで証明できた場合だけfamily確定を許す。
"""

from __future__ import annotations

import hashlib
import struct
from collections import deque
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Literal

import pefile
from capstone import (
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_64,
    Cs,
    CsError,
)
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_INVALID,
    X86_REG_RIP,
)
from extractors.valleyrat.run_dll_native_core import (
    probe_run_dll_native_core_config,
)
from extractors.valleyrat.wide_pipe_config import (
    probe_config as probe_wide_pipe_config,
)

MAXIMUM_INPUT_SIZE = 32 * 1024 * 1024
MAXIMUM_COMPONENT_SIZE = 16 * 1024 * 1024
MAXIMUM_RESOURCE_LEAVES = 128
MAXIMUM_FUNCTIONS = 8_192
MAXIMUM_INSTRUCTIONS = 250_000
MAXIMUM_LINEAGE_DEPTH = 4
MAXIMUM_RECOVERED_COMPONENTS = 32
MAXIMUM_FOLLOW_ON_COMPONENTS = 8
MAXIMUM_FOLLOW_ON_TOTAL_SIZE = 64 * 1024 * 1024
MAXIMUM_BUNDLE_RECORDS = 16
MAXIMUM_BUNDLE_NAME = 255
MAXIMUM_STRING_SIZE = 128

_EXECUTABLE = 0x20000000
_VOLATILE_X64 = frozenset({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})
_WIDE_PIPE_REQUIRED_GROUPS = frozenset(
    {
        "single_validated_winsock_descriptor",
        "external_root_launcher",
        "configuration_source_to_parser",
        "parser_field_schema_complete",
        "launcher_parser_before_worker",
        "runtime_endpoint_globals_referenced",
        "worker_transport_vtable_dispatch",
        "tcp_connect_send_receive_chain",
        "same_socket_field_connect_send_receive",
        "winos_framing_and_xor",
        "bootstrap_command_04",
        "winos_receive_dispatcher",
        "received_stage_memory_and_registry_path",
    }
)
_RUN_DLL_REQUIRED_PROOF = frozenset(
    {
        "run_thread_callback",
        "all_config_fields_referenced",
        "runtime_config_copy",
        "selector_one_transport_binding",
        "runtime_config_to_connect",
        "same_socket_connect_send_receive",
        "framed_send_receive",
        "periodic_keepalive",
        "callback_dispatcher",
        "registration_serializer",
    }
)


@dataclass(frozen=True)
class TerminalComponentProof:
    """後段の終端parserが返す、値を含まない証明要約。"""

    family: str
    static_config_recovered: bool
    terminal_family_confirmed: bool
    supports_family_attribution: bool
    terminal_network_lineage_proven: bool
    terminal_protocol_lineage_proven: bool
    endpoint_count: int
    candidate_only: bool = False


@dataclass(frozen=True)
class NativeLoaderLineage:
    """公開可能な観測と、後段利用専用の確定終端bytes。"""

    observation: dict[str, object]
    terminal_component: bytes | None
    recovered_components: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class _Value:
    kind: Literal["argument", "constant", "pointer", "return"]
    identity: int | str
    displacement: int = 0


@dataclass(frozen=True)
class _ApiCall:
    name: str
    address: int
    instruction_index: int
    arguments: tuple[_Value | None, ...]
    result: _Value


@dataclass(frozen=True)
class _XorLoop:
    address: int
    instruction_index: int
    key: int
    buffer: _Value


@dataclass
class _Trace:
    calls: list[_ApiCall] = field(default_factory=list)
    copies: list[tuple[_Value, _Value, int]] = field(default_factory=list)
    xor_loops: list[_XorLoop] = field(default_factory=list)


@dataclass(frozen=True)
class _Function:
    start: int
    end: int
    instructions: tuple[object, ...]


@dataclass(frozen=True)
class _ResourceLeaf:
    type_key: tuple[str, int | str]
    data: bytes


@dataclass(frozen=True)
class _PeContext:
    data: bytes
    image: pefile.PE
    image_base: int
    is_x64: bool
    imports: dict[int, str]
    functions: tuple[_Function, ...]
    reachable_functions: frozenset[int]
    resources: tuple[_ResourceLeaf, ...]


@dataclass(frozen=True)
class _Stage:
    kind: str
    executed_components: tuple[bytes, ...]
    recovered_component_count: int
    observation: dict[str, object]


@dataclass(frozen=True)
class _BundleRecord:
    encoded: bytes


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
    if name.startswith("r") and name.endswith(("b", "w", "d")) and name[1:-1].isdigit():
        return name[:-1]
    return name


def _register_name(instruction: object, register: int) -> str:
    return _canonical_register(str(instruction.reg_name(register)).casefold())


def _pointer_add(value: _Value | None, displacement: int) -> _Value | None:
    if value is None or value.kind != "pointer":
        return None
    return _Value("pointer", value.identity, value.displacement + displacement)


def _address_value(
    instruction: object,
    operand: object,
    registers: dict[str, _Value],
) -> _Value | None:
    if operand.type != X86_OP_MEM or operand.mem.index != X86_REG_INVALID:
        return None
    if operand.mem.base == X86_REG_RIP:
        return _Value(
            "pointer",
            "image",
            instruction.address + instruction.size + operand.mem.disp,
        )
    if operand.mem.base == X86_REG_INVALID:
        return _Value("pointer", "image", operand.mem.disp & 0xFFFFFFFFFFFFFFFF)
    return _pointer_add(
        registers.get(_register_name(instruction, operand.mem.base)),
        int(operand.mem.disp),
    )


def _operand_value(
    instruction: object,
    operand: object,
    registers: dict[str, _Value],
    memory: dict[_Value, _Value],
) -> _Value | None:
    if operand.type == X86_OP_REG:
        return registers.get(_register_name(instruction, operand.reg))
    if operand.type == X86_OP_IMM:
        return _Value("constant", int(operand.imm) & 0xFFFFFFFFFFFFFFFF)
    pointer = _address_value(instruction, operand, registers)
    return memory.get(pointer) if pointer is not None else None


def _write_value(
    instruction: object,
    operand: object,
    value: _Value | None,
    registers: dict[str, _Value],
    memory: dict[_Value, _Value],
) -> None:
    if operand.type == X86_OP_REG:
        name = _register_name(instruction, operand.reg)
        if value is None:
            registers.pop(name, None)
        else:
            registers[name] = value
        return
    pointer = _address_value(instruction, operand, registers)
    if pointer is None:
        return
    if value is None:
        memory.pop(pointer, None)
    else:
        memory[pointer] = value


def _iat_call_name(context: _PeContext, instruction: object) -> str | None:
    if instruction.mnemonic.casefold() != "call" or len(instruction.operands) != 1:
        return None
    operand = instruction.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    if (
        context.is_x64
        and operand.mem.base == X86_REG_RIP
        and operand.mem.index == X86_REG_INVALID
    ):
        target = instruction.address + instruction.size + operand.mem.disp
    elif (
        not context.is_x64
        and operand.mem.base == X86_REG_INVALID
        and operand.mem.index == X86_REG_INVALID
    ):
        target = operand.mem.disp & 0xFFFFFFFF
    else:
        return None
    return context.imports.get(target)


def _is_xor8_loop(
    function: _Function, index: int, instruction: object
) -> tuple[int, int] | None:
    if instruction.mnemonic.casefold() != "xor" or len(instruction.operands) != 2:
        return None
    destination, key_operand = instruction.operands
    if (
        destination.type != X86_OP_MEM
        or destination.size != 1
        or destination.mem.base == X86_REG_INVALID
        or destination.mem.index != X86_REG_INVALID
        or key_operand.type != X86_OP_IMM
        or not 0 <= int(key_operand.imm) <= 0xFF
        or index + 3 >= len(function.instructions)
    ):
        return None
    increment, decrement, branch = function.instructions[index + 1 : index + 4]
    base_name = _register_name(instruction, destination.mem.base)
    if (
        increment.mnemonic.casefold() != "inc"
        or not increment.operands
        or increment.operands[0].type != X86_OP_REG
        or _register_name(increment, increment.operands[0].reg) != base_name
        or decrement.mnemonic.casefold() not in {"dec", "sub"}
        or branch.mnemonic.casefold() not in {"jne", "jnz"}
        or not branch.operands
        or branch.operands[0].type != X86_OP_IMM
        or int(branch.operands[0].imm) != instruction.address
    ):
        return None
    return int(key_operand.imm), destination.mem.base


def _trace_function(
    context: _PeContext,
    function: _Function,
    *,
    callback_arguments: bool = False,
) -> _Trace:
    registers: dict[str, _Value] = {
        "rsp": _Value("pointer", f"stack:{function.start}", 0)
    }
    if callback_arguments and context.is_x64:
        for index, name in enumerate(("rcx", "rdx", "r8", "r9")):
            registers[name] = _Value("argument", index)
    memory: dict[_Value, _Value] = {}
    trace = _Trace()
    for index, instruction in enumerate(function.instructions):
        mnemonic = instruction.mnemonic.casefold()
        operands = instruction.operands
        loop = _is_xor8_loop(function, index, instruction)
        if loop is not None:
            key, base_register = loop
            buffer = registers.get(_register_name(instruction, base_register))
            if buffer is not None:
                trace.xor_loops.append(
                    _XorLoop(instruction.address, index, key, buffer)
                )
        api_name = _iat_call_name(context, instruction)
        if api_name is not None:
            arguments = tuple(
                registers.get(name) for name in ("rcx", "rdx", "r8", "r9")
            )
            result = _Value("return", instruction.address)
            trace.calls.append(
                _ApiCall(api_name, instruction.address, index, arguments, result)
            )
            if api_name in {"lstrcpya", "lstrcpyw", "strcpya", "strcpyw"}:
                destination, source = arguments[:2]
                if destination is not None and source is not None:
                    trace.copies.append((destination, source, index))
            for register in _VOLATILE_X64:
                registers.pop(register, None)
            registers["rax"] = result
            continue
        if instruction.group(CS_GRP_CALL):
            for register in _VOLATILE_X64:
                registers.pop(register, None)
            continue
        if mnemonic == "lea" and len(operands) == 2:
            _write_value(
                instruction,
                operands[0],
                _address_value(instruction, operands[1], registers),
                registers,
                memory,
            )
            continue
        if mnemonic in {"mov", "movzx", "movsx", "movsxd"} and len(operands) == 2:
            _write_value(
                instruction,
                operands[0],
                _operand_value(instruction, operands[1], registers, memory),
                registers,
                memory,
            )
            continue
        if (
            mnemonic == "xor"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_REG
            and _register_name(instruction, operands[0].reg)
            == _register_name(instruction, operands[1].reg)
        ):
            _write_value(
                instruction, operands[0], _Value("constant", 0), registers, memory
            )
            continue
        if mnemonic in {"push", "pop"}:
            delta = -8 if mnemonic == "push" else 8
            stack = _pointer_add(registers.get("rsp"), delta)
            if stack is not None:
                registers["rsp"] = stack
            continue
        if (
            mnemonic in {"add", "sub"}
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
        ):
            target_name = _register_name(instruction, operands[0].reg)
            if target_name == "rsp" and operands[1].type == X86_OP_IMM:
                delta = int(operands[1].imm) * (1 if mnemonic == "add" else -1)
                stack = _pointer_add(registers.get("rsp"), delta)
                if stack is not None:
                    registers["rsp"] = stack
            else:
                registers.pop(target_name, None)
            continue
        if (
            mnemonic
            in {
                "inc",
                "dec",
                "imul",
                "mul",
                "div",
                "idiv",
                "and",
                "or",
                "shl",
                "shr",
                "sar",
            }
            and operands
            and operands[0].type == X86_OP_REG
        ):
            registers.pop(_register_name(instruction, operands[0].reg), None)
    return trace


def _mapped_file_range(image: pefile.PE, data_size: int, start: int, end: int) -> bool:
    if start < 0 or end <= start:
        return False
    try:
        start_offset = int(image.get_offset_from_rva(start))
        end_offset = int(image.get_offset_from_rva(end - 1))
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return False
    return 0 <= start_offset <= end_offset < data_size


def _resource_key(entry: object) -> tuple[str, int | str] | None:
    name = getattr(entry, "name", None)
    if name is not None:
        text = str(name)
        return ("string", text) if 0 < len(text) <= MAXIMUM_STRING_SIZE else None
    try:
        identifier = int(entry.struct.Id)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    return ("id", identifier) if 0 <= identifier <= 0xFFFF else None


def _resource_leaves(image: pefile.PE, data: bytes) -> tuple[_ResourceLeaf, ...] | None:
    root = getattr(image, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return ()
    leaves: list[_ResourceLeaf] = []
    try:
        type_entries = list(root.entries)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    for type_entry in type_entries:
        type_key = _resource_key(type_entry)
        if type_key is None:
            return None
        try:
            name_entries = list(type_entry.directory.entries)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        for name_entry in name_entries:
            try:
                language_entries = list(name_entry.directory.entries)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None
            for language in language_entries:
                if len(leaves) >= MAXIMUM_RESOURCE_LEAVES:
                    return None
                try:
                    item = language.data.struct
                    size = int(item.Size)
                    offset = int(image.get_offset_from_rva(int(item.OffsetToData)))
                except (
                    AttributeError,
                    TypeError,
                    ValueError,
                    OverflowError,
                    pefile.PEFormatError,
                ):
                    return None
                if (
                    not 1 <= size <= MAXIMUM_COMPONENT_SIZE
                    or not 0 <= offset <= len(data) - size
                ):
                    return None
                leaves.append(_ResourceLeaf(type_key, data[offset : offset + size]))
    return tuple(leaves)


def _function_for_address(context: _PeContext, address: int) -> _Function | None:
    matches = [item for item in context.functions if item.start <= address < item.end]
    return matches[0] if len(matches) == 1 else None


def _direct_targets(function: _Function) -> set[int]:
    result: set[int] = set()
    for instruction in function.instructions:
        if (
            instruction.mnemonic.casefold() == "call"
            and len(instruction.operands) == 1
            and instruction.operands[0].type == X86_OP_IMM
        ):
            result.add(int(instruction.operands[0].imm) & 0xFFFFFFFFFFFFFFFF)
    return result


def _merge_runtime_fragments(fragments: list[_Function]) -> list[_Function]:
    """unwind用に分割された同一CFGのruntime function断片を結合する。"""

    parent = list(range(len(fragments)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = root(left)
        right_root = root(right)
        if left_root != right_root:
            parent[right_root] = left_root

    def containing(address: int) -> int | None:
        matches = [
            index
            for index, item in enumerate(fragments)
            if item.start <= address < item.end
        ]
        return matches[0] if len(matches) == 1 else None

    by_start = {item.start: index for index, item in enumerate(fragments)}
    for index, fragment in enumerate(fragments):
        for instruction in fragment.instructions:
            if (
                instruction.group(CS_GRP_JUMP)
                and instruction.operands
                and instruction.operands[0].type == X86_OP_IMM
            ):
                target = containing(int(instruction.operands[0].imm))
                if target is not None:
                    low = min(fragment.start, fragments[target].start)
                    high = max(fragment.end, fragments[target].end)
                    has_intervening_function = any(
                        other not in {index, target}
                        and low < candidate.start
                        and candidate.end < high
                        for other, candidate in enumerate(fragments)
                    )
                else:
                    has_intervening_function = True
                if (
                    target is not None
                    and high - low <= 0x1000
                    and not has_intervening_function
                ):
                    union(index, target)
        final = fragment.instructions[-1]
        following = by_start.get(fragment.end)
        if (
            following is not None
            and not final.group(CS_GRP_RET)
            and not (
                final.group(CS_GRP_JUMP)
                and final.mnemonic.casefold() in {"jmp", "ljmp"}
            )
        ):
            union(index, following)
    groups: dict[int, list[_Function]] = {}
    for index, fragment in enumerate(fragments):
        groups.setdefault(root(index), []).append(fragment)
    merged: list[_Function] = []
    for members in groups.values():
        members.sort(key=lambda item: item.start)
        instructions = tuple(
            instruction for member in members for instruction in member.instructions
        )
        merged.append(
            _Function(
                min(item.start for item in members),
                max(item.end for item in members),
                tuple(sorted(instructions, key=lambda item: item.address)),
            )
        )
    return sorted(merged, key=lambda item: item.start)


def _load_context(data: bytes) -> _PeContext | None:
    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAXIMUM_INPUT_SIZE
        or not data.startswith(b"MZ")
    ):
        return None
    try:
        image = pefile.PE(data=data, fast_load=False)
        machine = int(image.FILE_HEADER.Machine)
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        entry = image_base + int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    except (
        pefile.PEFormatError,
        AttributeError,
        TypeError,
        ValueError,
        OverflowError,
    ):
        return None
    if machine not in {0x14C, 0x8664} or image_base <= 0:
        return None
    imports: dict[int, str] = {}
    for descriptor in getattr(image, "DIRECTORY_ENTRY_IMPORT", ()):
        try:
            imported = list(descriptor.imports)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        for item in imported:
            raw_name = getattr(item, "name", None)
            if raw_name is None:
                continue
            if (
                not isinstance(raw_name, bytes)
                or not 1 <= len(raw_name) <= MAXIMUM_STRING_SIZE
            ):
                return None
            try:
                address = int(item.address)
                name = raw_name.decode("ascii", errors="strict").casefold()
            except (UnicodeError, TypeError, ValueError, OverflowError):
                return None
            if address in imports and imports[address] != name:
                return None
            imports[address] = name
    is_x64 = machine == 0x8664
    resources = _resource_leaves(image, data)
    if resources is None:
        return None
    route_context = _PeContext(
        data, image, image_base, is_x64, imports, (), frozenset(), resources
    )
    if not is_x64:
        return route_context
    imported_names = set(imports.values())
    needs_lineage_functions = bool(
        data.endswith(b"KBND")
        or (
            resources
            and imported_names & {"enumresourcenamesa", "enumresourcenamesw"}
            and imported_names & {"findresourcea", "findresourcew"}
        )
    )
    if not needs_lineage_functions:
        return route_context
    try:
        runtime_functions = list(image.DIRECTORY_ENTRY_EXCEPTION)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return route_context
    if not 1 <= len(runtime_functions) <= MAXIMUM_FUNCTIONS:
        return route_context
    try:
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
    except CsError:
        return route_context
    functions: list[_Function] = []
    total_instructions = 0
    for runtime in runtime_functions:
        try:
            start_rva = int(runtime.struct.BeginAddress)
            end_rva = int(runtime.struct.EndAddress)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return route_context
        if not _mapped_file_range(image, len(data), start_rva, end_rva):
            return route_context
        try:
            offset = int(image.get_offset_from_rva(start_rva))
        except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
            return route_context
        instructions = tuple(
            decoder.disasm(
                data[offset : offset + end_rva - start_rva], image_base + start_rva
            )
        )
        total_instructions += len(instructions)
        if not instructions or total_instructions > MAXIMUM_INSTRUCTIONS:
            return route_context
        functions.append(
            _Function(image_base + start_rva, image_base + end_rva, instructions)
        )
    functions.sort(key=lambda item: item.start)
    if any(left.end > right.start for left, right in pairwise(functions)):
        return route_context
    functions = _merge_runtime_fragments(functions)
    temporary = _PeContext(
        data, image, image_base, True, imports, tuple(functions), frozenset(), resources
    )
    entry_function = _function_for_address(temporary, entry)
    if entry_function is None:
        return route_context
    reachable: set[int] = set()
    pending = deque([entry_function.start])
    by_start = {item.start: item for item in functions}
    while pending and len(reachable) <= MAXIMUM_FUNCTIONS:
        current = pending.popleft()
        if current in reachable:
            continue
        reachable.add(current)
        function = by_start[current]
        for target in _direct_targets(function):
            callee = _function_for_address(temporary, target)
            if callee is not None and callee.start not in reachable:
                pending.append(callee.start)
    return _PeContext(
        data,
        image,
        image_base,
        True,
        imports,
        tuple(functions),
        frozenset(reachable),
        resources,
    )


def _pointer_va(value: _Value | None) -> int | None:
    if value is None or value.kind != "pointer" or value.identity != "image":
        return None
    return value.displacement


def _mapped_string_key(
    context: _PeContext, value: _Value | None
) -> tuple[str, int | str] | None:
    if value is not None and value.kind == "constant":
        number = int(value.identity)
        return ("id", number) if 0 <= number <= 0xFFFF else None
    address = _pointer_va(value)
    if address is None or address < context.image_base:
        return None
    try:
        offset = int(context.image.get_offset_from_rva(address - context.image_base))
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return None
    if not 0 <= offset < len(context.data):
        return None
    window = context.data[offset : offset + MAXIMUM_STRING_SIZE * 2 + 2]
    terminator = next(
        (
            index
            for index in range(0, len(window) - 1, 2)
            if window[index : index + 2] == b"\0\0"
        ),
        -1,
    )
    if terminator >= 2:
        try:
            text = window[:terminator].decode("utf-16le", errors="strict")
        except UnicodeError:
            text = ""
        if text and all(0x20 <= ord(character) <= 0x7E for character in text):
            return "string", text
    terminator = window.find(b"\0")
    if 1 <= terminator <= MAXIMUM_STRING_SIZE:
        try:
            text = window[:terminator].decode("ascii", errors="strict")
        except UnicodeError:
            return None
        if all(0x20 <= ord(character) <= 0x7E for character in text):
            return "string", text
    return None


def _valid_pe_component(data: bytes) -> bool:
    if not 0x200 <= len(data) <= MAXIMUM_COMPONENT_SIZE or not data.startswith(b"MZ"):
        return False
    try:
        image = pefile.PE(data=data, fast_load=False)
        machine = int(image.FILE_HEADER.Machine)
        sections = list(image.sections)
        entry = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    except (
        pefile.PEFormatError,
        AttributeError,
        TypeError,
        ValueError,
        OverflowError,
    ):
        return False
    if machine not in {0x14C, 0x8664} or not 1 <= len(sections) <= 96 or entry <= 0:
        return False
    mapped_entry = False
    for section in sections:
        try:
            raw = int(section.PointerToRawData)
            size = int(section.SizeOfRawData)
            virtual = int(section.VirtualAddress)
            virtual_size = int(section.Misc_VirtualSize) or size
        except (AttributeError, TypeError, ValueError, OverflowError):
            return False
        if raw < 0 or size < 0 or raw + size > len(data):
            return False
        if virtual <= entry < virtual + max(size, virtual_size):
            mapped_entry = True
    return mapped_entry


def _call_after(calls: list[_ApiCall], index: int, names: set[str]) -> list[_ApiCall]:
    return [
        item for item in calls if item.instruction_index > index and item.name in names
    ]


def _resource_callback_proven(context: _PeContext, function: _Function) -> bool:
    trace = _trace_function(context, function, callback_arguments=True)
    for find in (
        item for item in trace.calls if item.name in {"findresourcea", "findresourcew"}
    ):
        if find.arguments[:3] != (
            _Value("argument", 0),
            _Value("argument", 2),
            _Value("argument", 1),
        ):
            continue
        for load in _call_after(trace.calls, find.instruction_index, {"loadresource"}):
            if load.arguments[1] != find.result:
                continue
            locks = [
                item
                for item in _call_after(
                    trace.calls, load.instruction_index, {"lockresource"}
                )
                if item.arguments[0] == load.result
            ]
            sizes = [
                item
                for item in _call_after(
                    trace.calls, load.instruction_index, {"sizeofresource"}
                )
                if item.arguments[1] == find.result
            ]
            for lock in locks:
                for size in sizes:
                    for create in _call_after(
                        trace.calls,
                        size.instruction_index,
                        {"createfilea", "createfilew"},
                    ):
                        path = create.arguments[0]
                        if path is None or path.kind != "pointer":
                            continue
                        writes = [
                            item
                            for item in _call_after(
                                trace.calls, create.instruction_index, {"writefile"}
                            )
                            if item.arguments[:3]
                            == (create.result, lock.result, size.result)
                        ]
                        for write in writes:
                            for execute in _call_after(
                                trace.calls,
                                write.instruction_index,
                                {
                                    "createprocessa",
                                    "createprocessw",
                                    "shellexecutea",
                                    "shellexecutew",
                                },
                            ):
                                executed_path = (
                                    execute.arguments[0]
                                    if execute.name.startswith("createprocess")
                                    else execute.arguments[2]
                                )
                                if executed_path == path:
                                    return True
    return False


def _direct_resource_stage(context: _PeContext) -> _Stage | None:
    if not context.is_x64 or not context.resources:
        return None
    by_start = {item.start: item for item in context.functions}
    recovered: list[bytes] = []
    callback_count = 0
    enumerator_count = 0
    for start in sorted(context.reachable_functions):
        function = by_start[start]
        trace = _trace_function(context, function)
        for call in trace.calls:
            if call.name not in {"enumresourcenamesa", "enumresourcenamesw"}:
                continue
            callback_address = _pointer_va(call.arguments[2])
            type_key = _mapped_string_key(context, call.arguments[1])
            if callback_address is None or type_key is None:
                continue
            callback = _function_for_address(context, callback_address)
            if callback is None or not _resource_callback_proven(context, callback):
                continue
            leaves = [
                item.data for item in context.resources if item.type_key == type_key
            ]
            if not leaves or len(leaves) > MAXIMUM_RECOVERED_COMPONENTS:
                continue
            if not all(_valid_pe_component(item) for item in leaves):
                continue
            enumerator_count += 1
            callback_count += 1
            recovered.extend(leaves)
    unique: list[bytes] = []
    identities: set[bytes] = set()
    for component in recovered:
        identity = hashlib.sha256(component).digest()
        if identity not in identities:
            identities.add(identity)
            unique.append(component)
    if not unique or len(unique) > MAXIMUM_RECOVERED_COMPONENTS:
        return None
    return _Stage(
        kind="native_resource_copy_process",
        executed_components=tuple(unique),
        recovered_component_count=len(unique),
        observation={
            "status": "validated_resource_to_same_path_process_lineage",
            "resource_enumerator_site_count": enumerator_count,
            "validated_callback_count": callback_count,
            "executed_pe_component_count": len(unique),
            "resource_handle_to_locked_bytes": True,
            "resource_size_to_write_length": True,
            "locked_bytes_to_write_buffer": True,
            "written_path_to_process_start": True,
            "transform": "identity_resource_bytes",
            "resource_names_included": False,
            "output_paths_included": False,
            "raw_payload_included": False,
        },
    )


def _bundle_records(
    data: bytes, overlay_start: int
) -> tuple[_BundleRecord, ...] | None:
    if not 0 <= overlay_start <= len(data) - 12 or data[-4:] != b"KBND":
        return None
    encoded_size = struct.unpack_from("<I", data, len(data) - 8)[0]
    if encoded_size != len(data) - overlay_start - 8:
        return None
    cursor = overlay_start
    count = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4
    if not 1 <= count <= MAXIMUM_BUNDLE_RECORDS:
        return None
    records: list[_BundleRecord] = []
    for _index in range(count):
        if cursor + 8 > len(data) - 8:
            return None
        name_size = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        if (
            not 1 <= name_size <= MAXIMUM_BUNDLE_NAME
            or cursor + name_size + 4 > len(data) - 8
        ):
            return None
        name = data[cursor : cursor + name_size]
        cursor += name_size
        if b"\0" in name or any(value < 0x20 or value > 0x7E for value in name):
            return None
        payload_size = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        if (
            not 1 <= payload_size <= MAXIMUM_COMPONENT_SIZE
            or cursor + payload_size > len(data) - 8
        ):
            return None
        records.append(_BundleRecord(data[cursor : cursor + payload_size]))
        cursor += payload_size
    return tuple(records) if cursor == len(data) - 8 else None


def _references_kbnd_literal(context: _PeContext, function: _Function) -> bool:
    for index, instruction in enumerate(function.instructions):
        if instruction.mnemonic.casefold() != "lea" or len(instruction.operands) != 2:
            continue
        pointer = _address_value(instruction, instruction.operands[1], {})
        address = _pointer_va(pointer)
        if address is None or address < context.image_base:
            continue
        try:
            offset = int(
                context.image.get_offset_from_rva(address - context.image_base)
            )
        except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
            continue
        if context.data[offset : offset + 4] != b"KBND":
            continue
        neighborhood = function.instructions[max(0, index - 3) : index + 4]
        has_size = any(
            item.mnemonic.casefold() == "mov"
            and len(item.operands) == 2
            and item.operands[1].type == X86_OP_IMM
            and int(item.operands[1].imm) == 4
            for item in neighborhood
        )
        if has_size and any(item.group(CS_GRP_CALL) for item in neighborhood):
            return True
    return False


def _first_record_copy_guard(function: _Function, copy_index: int) -> bool:
    tested_register: str | None = None
    for index in range(max(0, copy_index - 12), copy_index):
        item = function.instructions[index]
        if (
            item.mnemonic.casefold() == "test"
            and len(item.operands) == 2
            and item.operands[0].type == X86_OP_REG
            and item.operands[1].type == X86_OP_REG
            and _register_name(item, item.operands[0].reg)
            == _register_name(item, item.operands[1].reg)
        ):
            candidate = _register_name(item, item.operands[0].reg)
            if index + 1 < len(function.instructions):
                branch = function.instructions[index + 1]
                if (
                    branch.mnemonic.casefold() in {"jne", "jnz"}
                    and branch.operands
                    and branch.operands[0].type == X86_OP_IMM
                    and int(branch.operands[0].imm)
                    > function.instructions[copy_index].address
                ):
                    tested_register = candidate
    if tested_register is None:
        return False
    incremented = False
    compared = False
    looped = False
    for item in function.instructions[copy_index + 1 : copy_index + 48]:
        if (
            item.mnemonic.casefold() == "inc"
            and item.operands
            and item.operands[0].type == X86_OP_REG
            and _register_name(item, item.operands[0].reg) == tested_register
        ):
            incremented = True
        if (
            item.mnemonic.casefold() == "cmp"
            and item.operands
            and item.operands[0].type == X86_OP_REG
            and _register_name(item, item.operands[0].reg) == tested_register
        ):
            compared = True
        if (
            item.mnemonic.casefold() in {"jb", "jc", "jnae"}
            and item.operands
            and item.operands[0].type == X86_OP_IMM
            and int(item.operands[0].imm) < function.instructions[copy_index].address
        ):
            looped = True
    return incremented and compared and looped


def _kbnd_function_proof(context: _PeContext, function: _Function, key: int) -> bool:
    trace = _trace_function(context, function)
    loops = [item for item in trace.xor_loops if item.key == key]
    if len(loops) != 1 or not _references_kbnd_literal(context, function):
        return False
    called_names = {item.name for item in trace.calls}
    if not {"getfilesize", "readfile"}.issubset(called_names) or not called_names & {
        "getmodulefilenamea",
        "getmodulefilenamew",
    }:
        return False
    loop = loops[0]
    creates = [
        item
        for item in trace.calls
        if item.instruction_index > loop.instruction_index
        and item.name in {"createfilea", "createfilew"}
    ]
    for create in creates:
        path = create.arguments[0]
        if path is None:
            continue
        writes = [
            item
            for item in trace.calls
            if item.instruction_index > create.instruction_index
            and item.name == "writefile"
            and item.arguments[0] == create.result
            and item.arguments[1] == loop.buffer
        ]
        for write in writes:
            for destination, source, copy_index in trace.copies:
                if copy_index <= write.instruction_index or source != path:
                    continue
                if not _first_record_copy_guard(function, copy_index):
                    continue
                for execute in trace.calls:
                    if (
                        execute.instruction_index > copy_index
                        and execute.name in {"shellexecutea", "shellexecutew"}
                        and execute.arguments[2] == destination
                    ):
                        return True
    return False


def _kbnd_stage(context: _PeContext) -> _Stage | None:
    if not context.is_x64:
        return None
    try:
        overlay_start = context.image.get_overlay_data_start_offset()
    except (AttributeError, TypeError, ValueError, OverflowError, pefile.PEFormatError):
        return None
    if not isinstance(overlay_start, int):
        return None
    records = _bundle_records(context.data, overlay_start)
    if records is None:
        return None
    by_start = {item.start: item for item in context.functions}
    candidates: list[tuple[int, tuple[bytes, ...]]] = []
    for start in sorted(context.reachable_functions):
        function = by_start[start]
        keys = {item.key for item in _trace_function(context, function).xor_loops}
        for key in keys:
            decoded = tuple(
                bytes(value ^ key for value in item.encoded) for item in records
            )
            if not _valid_pe_component(decoded[0]):
                continue
            if _kbnd_function_proof(context, function, key):
                candidates.append((key, decoded))
    identities = {
        (key, tuple(hashlib.sha256(item).digest() for item in decoded))
        for key, decoded in candidates
    }
    if len(identities) != 1:
        return None
    _key, decoded = candidates[0]
    return _Stage(
        kind="native_kbnd_xor_first_process",
        executed_components=(decoded[0],),
        recovered_component_count=len(decoded),
        observation={
            "status": "validated_kbnd_read_decode_write_first_process_lineage",
            "record_count": len(decoded),
            "executed_record_count": 1,
            "footer_length_binding": True,
            "self_file_read_to_bundle_parser": True,
            "code_derived_xor_loop": True,
            "decoded_buffer_to_write": True,
            "first_record_path_to_process_start": True,
            "transform": "code_proven_single_byte_xor_key_redacted",
            "record_names_included": False,
            "xor_key_included": False,
            "output_paths_included": False,
            "raw_payload_included": False,
        },
    )


def _structural_cluster(context: _PeContext) -> str | None:
    names = set(context.imports.values())
    libraries: set[str] = set()
    for descriptor in getattr(context.image, "DIRECTORY_ENTRY_IMPORT", ()):
        raw = getattr(descriptor, "dll", b"")
        if isinstance(raw, bytes):
            try:
                libraries.add(raw.decode("ascii", errors="strict").casefold())
            except UnicodeError:
                return None
    resource = {
        "find": bool(
            names
            & {"findresourcea", "findresourcew", "findresourceexa", "findresourceexw"}
        ),
        "load": "loadresource" in names,
        "lock": "lockresource" in names,
        "size": "sizeofresource" in names,
    }
    execute = bool(
        names & {"createprocessa", "createprocessw", "shellexecutea", "shellexecutew"}
    )
    if all(resource.values()) and "writefile" in names and execute:
        return "resource_copy_process_loader_candidate"
    if all(resource.values()) and execute:
        return "resource_process_loader_candidate"
    if {"virtualallocex", "writeprocessmemory", "createprocessw"}.issubset(names):
        return "remote_memory_process_loader_candidate"
    if "d3d11.dll" in libraries and "wevtapi.dll" in libraries:
        return "graphics_eventlog_context_loader_candidate"
    if "d3d11.dll" in libraries:
        return "graphics_probe_loader_candidate"
    if {"getthreadcontext", "setthreadcontext", "resumethread"}.issubset(names):
        return "thread_context_loader_candidate"
    debug_attribute_group = {
        "continuedebugevent",
        "deleteprocthreadattributelist",
        "initializeprocthreadattributelist",
        "updateprocthreadattribute",
        "waitfordebugevent",
    }
    if libraries == {"kernel32.dll"} and debug_attribute_group.issubset(names):
        return "debug_attribute_native_loader_candidate"
    if (
        libraries == {"kernel32.dll"}
        and "getprocaddress" in names
        and names & {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"}
    ):
        return "dynamic_resolution_native_loader_candidate"
    return None


def _strict_probe_base(probe: object) -> int | None:
    """family/config確定済みprobeから有界endpoint件数だけを取り出す。"""

    if not isinstance(probe, dict):
        return None
    config = probe.get("config")
    if (
        probe.get("matched") is not True
        or probe.get("family") != "valleyrat"
        or probe.get("supports_family_attribution") is not True
        or probe.get("terminal_family_confirmed") is not True
        or probe.get("static_config_recovered") is not True
        or not isinstance(config, dict)
    ):
        return None
    endpoint_count = config.get("endpoint_count")
    if type(endpoint_count) is not int or not 1 <= endpoint_count <= 64:
        return None
    return endpoint_count


def _wide_pipe_terminal_proof(probe: object) -> TerminalComponentProof | None:
    """wide-pipe probeのconfig/network/protocol全証明を再検証する。"""

    endpoint_count = _strict_probe_base(probe)
    if endpoint_count is None or not isinstance(probe, dict):
        return None
    evidence = probe.get("evidence")
    wide_pipe = evidence.get("wide_pipe_config") if isinstance(evidence, dict) else None
    lineage = wide_pipe.get("lineage") if isinstance(wide_pipe, dict) else None
    required = lineage.get("required_groups") if isinstance(lineage, dict) else None
    protocol = lineage.get("protocol") if isinstance(lineage, dict) else None
    if (
        not isinstance(required, dict)
        or not _WIDE_PIPE_REQUIRED_GROUPS.issubset(required)
        or any(required.get(group) is not True for group in _WIDE_PIPE_REQUIRED_GROUPS)
        or not isinstance(protocol, dict)
        or lineage.get("analysis_complete") is not True
        or lineage.get("terminal_network_lineage_proven") is not True
        or protocol.get("transport") != "tcp"
        or protocol.get("frame_prefix_size") != 4
        or protocol.get("header_size") != 10
        or protocol.get("payload_transform") != "header_derived_xor"
    ):
        return None
    return TerminalComponentProof(
        family="valleyrat",
        static_config_recovered=True,
        terminal_family_confirmed=True,
        supports_family_attribution=True,
        terminal_network_lineage_proven=True,
        terminal_protocol_lineage_proven=True,
        endpoint_count=endpoint_count,
    )


def _run_dll_terminal_proof(probe: object) -> TerminalComponentProof | None:
    """run-export probeの同一socket・framing・serializer証明を再検証する。"""

    endpoint_count = _strict_probe_base(probe)
    if endpoint_count is None or not isinstance(probe, dict):
        return None
    evidence = probe.get("evidence")
    lineage = (
        evidence.get("run_dll_terminal_lineage")
        if isinstance(evidence, dict)
        else None
    )
    proof = lineage.get("proof") if isinstance(lineage, dict) else None
    protocol = (
        evidence.get("terminal_protocol_contract")
        if isinstance(evidence, dict)
        else None
    )
    if (
        not isinstance(proof, dict)
        or not _RUN_DLL_REQUIRED_PROOF.issubset(proof)
        or any(proof.get(group) is not True for group in _RUN_DLL_REQUIRED_PROOF)
        or not isinstance(protocol, dict)
        or protocol.get("proven") is not True
        or lineage.get("analysis_complete") is not True
        or lineage.get("terminal_family_lineage_proven") is not True
    ):
        return None
    return TerminalComponentProof(
        family="valleyrat",
        static_config_recovered=True,
        terminal_family_confirmed=True,
        supports_family_attribution=True,
        terminal_network_lineage_proven=True,
        terminal_protocol_lineage_proven=True,
        endpoint_count=endpoint_count,
    )


def validate_terminal_component(data: bytes) -> TerminalComponentProof | None:
    """既存のstrict static probeを合議し、一意な終端証明だけを返す。"""

    if not isinstance(data, bytes) or not data.startswith(b"MZ"):
        return None
    proofs = [
        proof
        for proof in (
            _wide_pipe_terminal_proof(probe_wide_pipe_config(data)),
            _run_dll_terminal_proof(probe_run_dll_native_core_config(data)),
        )
        if proof is not None
    ]
    return proofs[0] if len(proofs) == 1 else None


def _strict_terminal(proof: object) -> bool:
    return bool(
        isinstance(proof, TerminalComponentProof)
        and isinstance(proof.family, str)
        and proof.family.casefold() == "valleyrat"
        and proof.static_config_recovered is True
        and proof.terminal_family_confirmed is True
        and proof.supports_family_attribution is True
        and proof.terminal_network_lineage_proven is True
        and proof.terminal_protocol_lineage_proven is True
        and type(proof.endpoint_count) is int
        and 1 <= proof.endpoint_count <= 64
        and proof.candidate_only is False
    )


def analyze_native_loader_lineage(
    data: bytes,
    *,
    terminal_proofs: dict[bytes, TerminalComponentProof | None] | None = None,
) -> NativeLoaderLineage | None:
    """loader chainを静的に辿り、完全な終端証明だけをfamily確定へ昇格する。"""

    if terminal_proofs is not None and type(terminal_proofs) is not dict:
        return None
    root = _load_context(data)
    if root is None:
        return None
    cluster = _structural_cluster(root)
    queue: deque[tuple[bytes, tuple[dict[str, object], ...], int]] = deque(
        [(data, (), 0)]
    )
    visited: set[bytes] = set()
    terminal_paths: list[
        tuple[bytes, tuple[dict[str, object], ...], TerminalComponentProof]
    ] = []
    matched_stage_count = 0
    recovered_component_count = 0
    ambiguous_stage_count = 0
    observed_stage_summaries: list[dict[str, object]] = []
    root_identity = hashlib.sha256(data).digest()
    follow_on_components: dict[bytes, bytes] = {}
    follow_on_total_size = 0
    follow_on_candidate_set_complete = True
    while queue and len(visited) < MAXIMUM_RECOVERED_COMPONENTS:
        current, stages, depth = queue.popleft()
        identity = hashlib.sha256(current).digest()
        if identity in visited:
            continue
        visited.add(identity)
        if depth > 0:
            try:
                terminal = (
                    validate_terminal_component(current)
                    if terminal_proofs is None
                    else terminal_proofs.get(current)
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                terminal = None
            if _strict_terminal(terminal):
                terminal_paths.append((current, stages, terminal))
                continue
        if depth >= MAXIMUM_LINEAGE_DEPTH:
            continue
        context = root if depth == 0 else _load_context(current)
        if context is None:
            continue
        stage_candidates = [
            item
            for item in (_direct_resource_stage(context), _kbnd_stage(context))
            if item is not None
        ]
        if len(stage_candidates) != 1:
            ambiguous_stage_count += int(len(stage_candidates) > 1)
            continue
        stage = stage_candidates[0]
        matched_stage_count += 1
        recovered_component_count += stage.recovered_component_count
        public_stage = {"kind": stage.kind, **stage.observation}
        if public_stage not in observed_stage_summaries:
            observed_stage_summaries.append(public_stage)
        next_stages = (*stages, public_stage)
        for component in stage.executed_components:
            if not isinstance(component, bytes) or not component:
                follow_on_candidate_set_complete = False
                continue
            component_identity = hashlib.sha256(component).digest()
            if (
                component_identity != root_identity
                and component_identity not in follow_on_components
            ):
                if (
                    len(follow_on_components) >= MAXIMUM_FOLLOW_ON_COMPONENTS
                    or follow_on_total_size + len(component)
                    > MAXIMUM_FOLLOW_ON_TOTAL_SIZE
                ):
                    follow_on_candidate_set_complete = False
                else:
                    follow_on_components[component_identity] = component
                    follow_on_total_size += len(component)
            queue.append((component, next_stages, depth + 1))
    if queue:
        follow_on_candidate_set_complete = False
    unique_terminals: dict[
        bytes,
        tuple[bytes, tuple[dict[str, object], ...], TerminalComponentProof],
    ] = {}
    for item in terminal_paths:
        unique_terminals[hashlib.sha256(item[0]).digest()] = item
    confirmed = (
        len(unique_terminals) == 1
        and ambiguous_stage_count == 0
        and not queue
    )
    selected = next(iter(unique_terminals.values())) if confirmed else None
    matched = bool(cluster is not None or matched_stage_count)
    if not matched:
        return None
    missing: list[str] = []
    if matched_stage_count == 0:
        missing.append("native_loader_transform_lineage_unproven")
    if not unique_terminals:
        missing.append("valleyrat_terminal_component_unproven")
    if len(unique_terminals) > 1:
        missing.append("multiple_terminal_component_paths_ambiguous")
    if ambiguous_stage_count:
        missing.append("multiple_loader_stage_interpretations_ambiguous")
    if queue:
        missing.append("native_loader_lineage_component_limit_exhausted")
    if not follow_on_candidate_set_complete:
        missing.append("follow_on_candidate_set_incomplete")
    if selected is not None:
        _terminal_bytes, selected_stages, terminal = selected
        stage_summaries: list[dict[str, object]] = list(selected_stages)
        terminal_summary: dict[str, object] = {
            "family": "valleyrat",
            "static_config_recovered": True,
            "endpoint_count": terminal.endpoint_count,
            "config_to_connect_send_receive": True,
            "terminal_protocol_lineage_proven": True,
            "candidate_only": False,
            "endpoint_values_included": False,
        }
    else:
        stage_summaries = observed_stage_summaries
        terminal_summary = {
            "family": None,
            "static_config_recovered": False,
            "endpoint_count": 0,
            "config_to_connect_send_receive": False,
            "terminal_protocol_lineage_proven": False,
            "candidate_only": True,
            "endpoint_values_included": False,
        }
    observation = {
        "schema_version": 1,
        "status": (
            "validated_native_loader_to_valleyrat_terminal_lineage"
            if confirmed
            else "native_loader_candidate_terminal_unproven"
        ),
        "matched": True,
        "structural_cluster": cluster,
        "loader_stage_count": matched_stage_count,
        "recovered_component_count": recovered_component_count,
        "follow_on_component_count": (
            len(follow_on_components)
            if follow_on_candidate_set_complete
            else 0
        ),
        "follow_on_candidate_set_complete": follow_on_candidate_set_complete,
        "follow_on_components_truncated": not follow_on_candidate_set_complete,
        "maximum_follow_on_components": MAXIMUM_FOLLOW_ON_COMPONENTS,
        "maximum_follow_on_total_size": MAXIMUM_FOLLOW_ON_TOTAL_SIZE,
        "lineage_depth": len(stage_summaries),
        "stages": stage_summaries,
        "terminal": terminal_summary,
        "missing_proof_codes": missing,
        "supports_family_attribution": confirmed,
        "terminal_family_confirmed": confirmed,
        "terminal_network_lineage_proven": confirmed,
        "terminal_protocol_lineage_proven": confirmed,
        "hash_or_filename_rule_used": False,
        "external_label_used": False,
        "endpoint_values_included": False,
        "raw_payload_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    return NativeLoaderLineage(
        observation=observation,
        terminal_component=selected[0] if selected is not None else None,
        recovered_components=(
            tuple(
                component
                for identity, component in follow_on_components.items()
                if selected is None
                or identity != hashlib.sha256(selected[0]).digest()
            )
            if follow_on_candidate_set_complete
            else ()
        ),
    )


__all__ = [
    "MAXIMUM_FOLLOW_ON_COMPONENTS",
    "MAXIMUM_FOLLOW_ON_TOTAL_SIZE",
    "MAXIMUM_INPUT_SIZE",
    "NativeLoaderLineage",
    "TerminalComponentProof",
    "analyze_native_loader_lineage",
    "validate_terminal_component",
]
