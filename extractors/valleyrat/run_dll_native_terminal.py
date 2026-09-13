"""``run`` export型x86 DLLの終端通信lineageを静的に検証する。

検体は実行せず、外部通信も行わない。設定値や絶対addressそのものではなく、
固定幅設定sourceからruntime buffer、selector=1で選択されるTCP transport、
同一socketを使うconnect/send/recv、14 byte frame、受信dispatcher、初回登録
serializerまでのproducer-consumer関係を確認する。どれか一つでも曖昧なら
family確定には使わず、欠落した証明codeを返す。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_32, Cs, CsError
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EAX,
    X86_REG_EBP,
    X86_REG_ECX,
    X86_REG_INVALID,
)

MAXIMUM_INPUT_SIZE = 1024 * 1024
MAXIMUM_SECTION_COUNT = 32
MAXIMUM_IMPORT_COUNT = 4096
MAXIMUM_FUNCTION_BYTES = 0x8000
MAXIMUM_INSTRUCTIONS = 12_000
MAXIMUM_MAIN_BYTES = 0x6000
MAXIMUM_DIRECT_TARGETS = 512


@dataclass(frozen=True)
class _Section:
    address: int
    raw_start: int
    raw_end: int
    executable: bool

    def contains(self, address: int) -> bool:
        return self.address <= address < self.address + self.raw_end - self.raw_start


@dataclass(frozen=True)
class _ApiCall:
    index: int
    name: str


@dataclass(frozen=True)
class _RuntimeConfig:
    copy_helper: int
    host_destination: int
    port_destination: int
    selector_destination: int


@dataclass(frozen=True)
class _Transport:
    constructor: int
    vtable: int
    close_method: int
    send_method: int
    callback_setter: int
    connect_method: int
    socket_displacement: int
    marker_displacement: int
    callback_displacement: int
    receive_worker: int
    frame_parser: int


@dataclass
class _DecodeCoverage:
    """命令上限で切り捨てたdecodeを終端証拠へ使わせない。"""

    instruction_limit_exceeded_count: int = 0

    @property
    def complete(self) -> bool:
        return self.instruction_limit_exceeded_count == 0


def _empty(status: str, missing: list[str]) -> dict[str, object]:
    """値やaddressを含めない固定shapeのfail-closed結果を返す。"""

    return {
        "schema_version": 1,
        "status": status,
        "analysis_complete": False,
        "terminal_family_lineage_proven": False,
        "proof": {
            "run_thread_callback": False,
            "all_config_fields_referenced": False,
            "runtime_config_copy": False,
            "selector_one_transport_binding": False,
            "runtime_config_to_connect": False,
            "same_socket_connect_send_receive": False,
            "framed_send_receive": False,
            "periodic_keepalive": False,
            "callback_dispatcher": False,
            "registration_serializer": False,
        },
        "missing_proof_codes": missing,
        "coverage": {
            "source_count": 0,
            "referenced_source_count": 0,
            "transport_candidate_count": 0,
            "dispatcher_capability_group_count": 0,
            "registration_inventory_group_count": 0,
        },
        "protocol": {
            "transport": None,
            "length_prefix_size": None,
            "session_header_size": None,
            "frame_header_size": None,
            "marker": None,
            "initial_registration_command": None,
            "raw_frame_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
        "raw_addresses_included": False,
        "raw_config_included": False,
    }


def _decode_limit_result(coverage: _DecodeCoverage) -> dict[str, object]:
    """命令集合が不完全な場合は部分proofを一切含めない。"""

    result = _empty(
        "analysis_incomplete",
        ["run_dll_instruction_decode_limit_exceeded"],
    )
    result["coverage"]["instruction_decode_complete"] = False
    result["coverage"]["instruction_decode_limit_exceeded_count"] = (
        coverage.instruction_limit_exceeded_count
    )
    return result


def _sections(data: bytes, image: object) -> tuple[_Section, ...] | None:
    try:
        image_base = image.OPTIONAL_HEADER.ImageBase
        source_sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if (
        type(image_base) is not int
        or not 0 <= image_base <= 0xFFFFFFFF
        or not 1 <= len(source_sections) <= MAXIMUM_SECTION_COUNT
    ):
        return None
    result: list[_Section] = []
    for section in source_sections:
        try:
            raw_start = section.PointerToRawData
            raw_size = section.SizeOfRawData
            rva = section.VirtualAddress
            characteristics = section.Characteristics
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if any(
            type(value) is not int
            for value in (raw_start, raw_size, rva, characteristics)
        ):
            return None
        raw_end = raw_start + raw_size
        address = image_base + rva
        if (
            raw_start < 0
            or raw_size < 0
            or raw_end < raw_start
            or raw_end > len(data)
            or not 0 <= address <= 0xFFFFFFFF
            or address + raw_size > 0x1_0000_0000
        ):
            return None
        result.append(
            _Section(
                address=address,
                raw_start=raw_start,
                raw_end=raw_end,
                executable=bool(characteristics & 0x20000000),
            )
        )
    return tuple(result)


def _imports(image: object) -> dict[int, str] | None:
    try:
        descriptors = list(image.DIRECTORY_ENTRY_IMPORT)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    result: dict[int, str] = {}
    count = 0
    for descriptor in descriptors:
        try:
            entries = list(descriptor.imports)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        for entry in entries:
            count += 1
            if count > MAXIMUM_IMPORT_COUNT:
                return None
            try:
                address = entry.address
                raw_name = entry.name
            except AttributeError:
                return None
            if (
                type(address) is not int
                or not 0 <= address <= 0xFFFFFFFF
                or not isinstance(raw_name, bytes)
                or not 1 <= len(raw_name) <= 128
            ):
                return None
            try:
                name = raw_name.decode("ascii", errors="strict")
            except UnicodeError:
                return None
            if address in result or not name:
                return None
            result[address] = name
    return result


def _section_for_address(
    sections: tuple[_Section, ...],
    address: int,
    *,
    executable: bool | None = None,
) -> _Section | None:
    matches = [
        section
        for section in sections
        if section.contains(address)
        and (executable is None or section.executable is executable)
    ]
    return matches[0] if len(matches) == 1 else None


def _read_u32(
    data: bytes,
    sections: tuple[_Section, ...],
    address: int,
) -> int | None:
    section = _section_for_address(sections, address)
    if section is None or not section.contains(address + 3):
        return None
    offset = section.raw_start + address - section.address
    return struct.unpack_from("<I", data, offset)[0]


def _decode(
    data: bytes,
    sections: tuple[_Section, ...],
    address: int,
    *,
    coverage: _DecodeCoverage,
    maximum_bytes: int = MAXIMUM_FUNCTION_BYTES,
) -> list[object]:
    section = _section_for_address(sections, address, executable=True)
    if section is None or maximum_bytes <= 0:
        return []
    offset = section.raw_start + address - section.address
    size = min(maximum_bytes, section.raw_end - offset)
    try:
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        decoded = decoder.disasm(data[offset : offset + size], address)
    except CsError:
        return []
    instructions: list[object] = []
    return_then_padding = False
    padding_count = 0
    try:
        for instruction in decoded:
            # ``MAXIMUM_INSTRUCTIONS + 1``個目を観測して初めて切捨てとする。
            # したがって、入力が上限ちょうどで自然終了した場合は完全である。
            if len(instructions) >= MAXIMUM_INSTRUCTIONS:
                coverage.instruction_limit_exceeded_count += 1
                break
            instructions.append(instruction)
            if instruction.mnemonic.startswith("ret"):
                return_then_padding = True
                padding_count = 0
            elif return_then_padding and instruction.mnemonic == "int3":
                padding_count += 1
                if padding_count >= 2:
                    break
            elif return_then_padding:
                return_then_padding = False
                padding_count = 0
    except CsError:
        return []
    return instructions


def _absolute_memory(operand: object) -> int | None:
    if operand.type != X86_OP_MEM:
        return None
    memory = operand.mem
    if memory.base != X86_REG_INVALID or memory.index != X86_REG_INVALID:
        return None
    return memory.disp & 0xFFFFFFFF


def _immediate(operand: object) -> int | None:
    return (operand.imm & 0xFFFFFFFF) if operand.type == X86_OP_IMM else None


def _api_calls(instructions: list[object], imports: dict[int, str]) -> list[_ApiCall]:
    """direct IAT callとIATをregisterへロードしたcallを解決する。"""

    register_imports: dict[int, str] = {}
    result: list[_ApiCall] = []
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        if (
            instruction.mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
        ):
            address = _absolute_memory(operands[1])
            if address in imports:
                register_imports[operands[0].reg] = imports[address]
            else:
                register_imports.pop(operands[0].reg, None)
        if instruction.mnemonic != "call" or len(operands) != 1:
            continue
        operand = operands[0]
        name: str | None = None
        address = _absolute_memory(operand)
        if address is not None:
            name = imports.get(address)
        elif operand.type == X86_OP_REG:
            name = register_imports.get(operand.reg)
        if name is not None:
            result.append(_ApiCall(index=index, name=name))
        # x86 API callはcaller-saved registerを保存する保証がない。
        for register in (X86_REG_EAX, X86_REG_ECX):
            register_imports.pop(register, None)
    return result


def _direct_targets(
    instructions: list[object],
    sections: tuple[_Section, ...],
) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic != "call" or len(instruction.operands) != 1:
            continue
        target = _immediate(instruction.operands[0])
        if target is not None and _section_for_address(
            sections, target, executable=True
        ):
            result.append((index, target))
            if len(result) >= MAXIMUM_DIRECT_TARGETS:
                break
    return result


def _preceding_pushes(
    instructions: list[object],
    call_index: int,
    *,
    count: int,
    maximum_scan: int = 20,
) -> list[object]:
    pushes: list[object] = []
    lower = max(-1, call_index - maximum_scan - 1)
    for index in range(call_index - 1, lower, -1):
        instruction = instructions[index]
        if instruction.mnemonic.startswith("ret") or instruction.mnemonic == "call":
            break
        if instruction.mnemonic == "push" and len(instruction.operands) == 1:
            pushes.append(instruction.operands[0])
            if len(pushes) == count:
                break
    return pushes


def _vcall_displacements(instructions: list[object]) -> list[tuple[int, int]]:
    """``mov reg,[vtable+slot]; call reg``と直接memory callを列挙する。"""

    loaded_slots: dict[int, int] = {}
    result: list[tuple[int, int]] = []
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        if (
            instruction.mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
        ):
            source = operands[1]
            if (
                source.type == X86_OP_MEM
                and source.mem.base != X86_REG_INVALID
                and source.mem.index == X86_REG_INVALID
                and 0 <= source.mem.disp <= 0x100
            ):
                loaded_slots[operands[0].reg] = source.mem.disp
            else:
                loaded_slots.pop(operands[0].reg, None)
        if instruction.mnemonic != "call" or len(operands) != 1:
            continue
        operand = operands[0]
        if (
            operand.type == X86_OP_MEM
            and operand.mem.base != X86_REG_INVALID
            and operand.mem.index == X86_REG_INVALID
            and 0 <= operand.mem.disp <= 0x100
        ):
            result.append((index, operand.mem.disp))
        elif operand.type == X86_OP_REG and operand.reg in loaded_slots:
            result.append((index, loaded_slots[operand.reg]))
        for register in (X86_REG_EAX, X86_REG_ECX):
            loaded_slots.pop(register, None)
    return result


def _operand_references(operand: object, address: int) -> bool:
    immediate = _immediate(operand)
    return immediate == address or _absolute_memory(operand) == address


def _referenced_sources(
    instructions: list[object], sources: tuple[object, ...]
) -> set[str]:
    result: set[str] = set()
    for source in sources:
        for instruction in instructions:
            if any(
                _operand_references(operand, source.address)
                for operand in instruction.operands
            ):
                result.add(source.name)
                break
    return result


def _run_callback(
    instructions: list[object],
    imports: dict[int, str],
    sections: tuple[_Section, ...],
) -> int | None:
    for api_call in _api_calls(instructions, imports):
        if api_call.name != "CreateThread":
            continue
        pushes = _preceding_pushes(
            instructions, api_call.index, count=6, maximum_scan=16
        )
        if len(pushes) != 6:
            continue
        candidate = _immediate(pushes[2])
        if candidate is not None and _section_for_address(
            sections, candidate, executable=True
        ):
            return candidate
    return None


def _runtime_config(
    instructions: list[object],
    sources: tuple[object, ...],
    sections: tuple[_Section, ...],
) -> _RuntimeConfig | None:
    by_address = {source.address: source for source in sources}
    copies: dict[int, list[tuple[str, int, int]]] = {}
    for call_index, target in _direct_targets(instructions, sections):
        pushes = _preceding_pushes(instructions, call_index, count=3, maximum_scan=8)
        if len(pushes) != 3:
            continue
        destination = _immediate(pushes[0])
        capacity = _immediate(pushes[1])
        source_address = _immediate(pushes[2])
        source = by_address.get(source_address)
        if source is None or destination is None or capacity is None:
            continue
        expected = (
            0xFF if source.kind == "host" else 0x1E if source.kind == "port" else None
        )
        if capacity != expected:
            continue
        copies.setdefault(target, []).append((source.name, destination, capacity))

    host_names = {source.name for source in sources if source.kind == "host"}
    port_names = {source.name for source in sources if source.kind == "port"}
    chosen: tuple[int, int, int] | None = None
    for helper, entries in copies.items():
        host_entries = [entry for entry in entries if entry[0] in host_names]
        port_entries = [entry for entry in entries if entry[0] in port_names]
        if (
            {entry[0] for entry in host_entries} == host_names
            and {entry[0] for entry in port_entries} == port_names
            and len({entry[1] for entry in host_entries}) == 1
            and len({entry[1] for entry in port_entries}) == 1
        ):
            candidate = (helper, host_entries[0][1], port_entries[0][1])
            if chosen is not None and chosen != candidate:
                return None
            chosen = candidate
    if chosen is None:
        return None

    selector_sources = [source for source in sources if source.kind == "selector"]
    selector_destinations: list[set[int]] = []
    for source in selector_sources:
        candidates: set[int] = set()
        for index, instruction in enumerate(instructions):
            if not any(
                _operand_references(operand, source.address)
                for operand in instruction.operands
            ):
                continue
            for later in instructions[index + 1 : index + 17]:
                if later.mnemonic != "mov" or len(later.operands) != 2:
                    continue
                destination = _absolute_memory(later.operands[0])
                if destination is not None and later.operands[1].type == X86_OP_REG:
                    candidates.add(destination)
        selector_destinations.append(candidates)
    if len(selector_destinations) != 3:
        return None
    common = set.intersection(*selector_destinations)
    if len(common) != 1:
        return None
    return _RuntimeConfig(
        copy_helper=chosen[0],
        host_destination=chosen[1],
        port_destination=chosen[2],
        selector_destination=common.pop(),
    )


def _vtable_from_constructor(
    data: bytes,
    sections: tuple[_Section, ...],
    instructions: list[object],
) -> tuple[int, tuple[int, ...]] | None:
    for instruction in instructions:
        operands = instruction.operands
        if instruction.mnemonic != "mov" or len(operands) != 2:
            continue
        destination, source = operands
        if (
            destination.type != X86_OP_MEM
            or destination.mem.base == X86_REG_INVALID
            or destination.mem.index != X86_REG_INVALID
            or destination.mem.disp != 0
        ):
            continue
        vtable = _immediate(source)
        if vtable is None:
            continue
        entries = tuple(
            _read_u32(data, sections, vtable + index * 4) or 0 for index in range(6)
        )
        if all(
            _section_for_address(sections, entry, executable=True) for entry in entries
        ):
            return vtable, entries
    return None


def _first_argument_displacement(
    instructions: list[object], call_index: int
) -> int | None:
    pushes = _preceding_pushes(instructions, call_index, count=1, maximum_scan=12)
    if len(pushes) != 1 or pushes[0].type != X86_OP_MEM:
        return None
    memory = pushes[0].mem
    if memory.base == X86_REG_INVALID or memory.index != X86_REG_INVALID:
        return None
    return memory.disp


def _socket_store_displacement(
    instructions: list[object], call_index: int
) -> int | None:
    for instruction in instructions[call_index + 1 : call_index + 13]:
        operands = instruction.operands
        if instruction.mnemonic != "mov" or len(operands) != 2:
            continue
        destination, source = operands
        if (
            destination.type == X86_OP_MEM
            and destination.mem.base != X86_REG_INVALID
            and destination.mem.index == X86_REG_INVALID
            and source.type == X86_OP_REG
            and source.reg == X86_REG_EAX
            and 0 < destination.mem.disp <= 0x400
        ):
            return destination.mem.disp
    return None


def _word_marker_displacement(instructions: list[object]) -> int | None:
    for instruction in instructions:
        operands = instruction.operands
        if instruction.mnemonic != "mov" or len(operands) != 2:
            continue
        destination, source = operands
        if (
            destination.type == X86_OP_MEM
            and destination.size == 2
            and destination.mem.base != X86_REG_INVALID
            and destination.mem.index == X86_REG_INVALID
            and _immediate(source) == 0xCA
            and 0 < destination.mem.disp <= 0x100
        ):
            return destination.mem.disp
    return None


def _callback_displacement(instructions: list[object]) -> int | None:
    reads_argument = any(
        operand.type == X86_OP_MEM
        and operand.mem.base == X86_REG_EBP
        and operand.mem.disp == 8
        for instruction in instructions
        for operand in instruction.operands
    )
    if not reads_argument:
        return None
    for instruction in instructions:
        operands = instruction.operands
        if instruction.mnemonic != "mov" or len(operands) != 2:
            continue
        destination = operands[0]
        if (
            destination.type == X86_OP_MEM
            and destination.mem.base == X86_REG_ECX
            and destination.mem.index == X86_REG_INVALID
            and 0 < destination.mem.disp <= 0x100
        ):
            return destination.mem.disp
    return None


def _has_immediate(instructions: list[object], value: int) -> bool:
    return any(
        _immediate(operand) == value
        for instruction in instructions
        for operand in instruction.operands
    )


def _has_memory_displacement(instructions: list[object], displacement: int) -> bool:
    return any(
        operand.type == X86_OP_MEM
        and operand.mem.base != X86_REG_INVALID
        and operand.mem.index == X86_REG_INVALID
        and operand.mem.disp == displacement
        for instruction in instructions
        for operand in instruction.operands
    )


def _has_indirect_call(instructions: list[object], displacement: int) -> bool:
    return any(
        slot == displacement for _index, slot in _vcall_displacements(instructions)
    )


def _frame_parser_proven(
    instructions: list[object],
    marker_displacement: int,
    callback_displacement: int,
) -> bool:
    return bool(
        _has_immediate(instructions, 0xE)
        and _has_memory_displacement(instructions, marker_displacement)
        and _has_memory_displacement(instructions, callback_displacement)
        and _has_indirect_call(instructions, 0)
    )


def _send_frame_proven(instructions: list[object], marker_displacement: int) -> bool:
    return bool(
        _has_immediate(instructions, 0xE)
        and _has_immediate(instructions, 0xA)
        and _has_memory_displacement(instructions, marker_displacement)
        and _has_memory_displacement(instructions, marker_displacement - 8)
    )


def _window_contains(
    data: bytes,
    sections: tuple[_Section, ...],
    address: int,
    needle: bytes,
    *,
    maximum_bytes: int,
) -> bool:
    """file-backed code窓に安価な必須byte列があるか確認する。"""

    section = _section_for_address(sections, address, executable=True)
    if section is None or not needle or maximum_bytes <= 0:
        return False
    offset = section.raw_start + address - section.address
    size = min(maximum_bytes, section.raw_end - offset)
    return needle in data[offset : offset + size]


def _transport(
    data: bytes,
    sections: tuple[_Section, ...],
    imports: dict[int, str],
    main: list[object],
    coverage: _DecodeCoverage,
) -> tuple[_Transport | None, int]:
    candidates: list[_Transport] = []
    constructor_count = 0
    wsastartup_iats = {
        address for address, name in imports.items() if name == "WSAStartup"
    }
    for _call_index, constructor in _direct_targets(main, sections):
        if not any(
            _window_contains(
                data,
                sections,
                constructor,
                struct.pack("<I", address),
                maximum_bytes=0x900,
            )
            for address in wsastartup_iats
        ):
            continue
        constructor_instructions = _decode(
            data,
            sections,
            constructor,
            coverage=coverage,
            maximum_bytes=0x900,
        )
        if "WSAStartup" not in {
            call.name for call in _api_calls(constructor_instructions, imports)
        }:
            continue
        vtable_contract = _vtable_from_constructor(
            data, sections, constructor_instructions
        )
        if vtable_contract is None:
            continue
        constructor_count += 1
        vtable, entries = vtable_contract
        close_method, _status, send_method, callback_setter, connect_method, _wait = (
            entries
        )
        connect_instructions = _decode(
            data,
            sections,
            connect_method,
            coverage=coverage,
            maximum_bytes=0x1000,
        )
        connect_calls = _api_calls(connect_instructions, imports)
        names = {call.name for call in connect_calls}
        if not {"socket", "gethostbyname", "htons", "connect"}.issubset(names):
            continue
        socket_calls = [call for call in connect_calls if call.name == "socket"]
        connect_api_calls = [call for call in connect_calls if call.name == "connect"]
        if len(socket_calls) != 1 or len(connect_api_calls) != 1:
            continue
        socket_displacement = _socket_store_displacement(
            connect_instructions, socket_calls[0].index
        )
        if (
            socket_displacement is None
            or _first_argument_displacement(
                connect_instructions, connect_api_calls[0].index
            )
            != socket_displacement
        ):
            continue
        marker_displacement = _word_marker_displacement(connect_instructions)
        if marker_displacement is None or marker_displacement < 8:
            continue
        setter_instructions = _decode(
            data,
            sections,
            callback_setter,
            coverage=coverage,
            maximum_bytes=0x100,
        )
        callback_displacement = _callback_displacement(setter_instructions)
        if callback_displacement is None:
            continue

        executable_immediates = {
            immediate
            for instruction in connect_instructions
            for operand in instruction.operands
            if (immediate := _immediate(operand)) is not None
            and _section_for_address(sections, immediate, executable=True)
        }
        receive_worker = 0
        frame_parser = 0
        for candidate in executable_immediates:
            worker = _decode(
                data,
                sections,
                candidate,
                coverage=coverage,
                maximum_bytes=0x1000,
            )
            receive_calls = [
                call for call in _api_calls(worker, imports) if call.name == "recv"
            ]
            if not receive_calls or not any(
                _first_argument_displacement(worker, call.index) == socket_displacement
                for call in receive_calls
            ):
                continue
            for _index, parser_candidate in _direct_targets(worker, sections):
                parser = _decode(
                    data,
                    sections,
                    parser_candidate,
                    coverage=coverage,
                    maximum_bytes=0x1200,
                )
                if _frame_parser_proven(
                    parser, marker_displacement, callback_displacement
                ):
                    receive_worker = candidate
                    frame_parser = parser_candidate
                    break
            if receive_worker:
                break
        if not receive_worker:
            continue

        send_instructions = _decode(
            data,
            sections,
            send_method,
            coverage=coverage,
            maximum_bytes=0x1200,
        )
        send_calls = [
            call
            for call in _api_calls(send_instructions, imports)
            if call.name == "send"
        ]
        if not send_calls or not any(
            _first_argument_displacement(send_instructions, call.index)
            == socket_displacement
            for call in send_calls
        ):
            continue
        if not _send_frame_proven(send_instructions, marker_displacement):
            continue
        candidates.append(
            _Transport(
                constructor=constructor,
                vtable=vtable,
                close_method=close_method,
                send_method=send_method,
                callback_setter=callback_setter,
                connect_method=connect_method,
                socket_displacement=socket_displacement,
                marker_displacement=marker_displacement,
                callback_displacement=callback_displacement,
                receive_worker=receive_worker,
                frame_parser=frame_parser,
            )
        )
    if len(candidates) != 1:
        return None, constructor_count
    return candidates[0], constructor_count


def _selector_binding(
    main: list[object],
    runtime: _RuntimeConfig,
    transport: _Transport,
    selector_values: tuple[int, ...],
) -> int | None:
    if len(selector_values) != 3 or any(value != 1 for value in selector_values):
        return None
    constructor_calls = [
        index
        for index, instruction in enumerate(main)
        if instruction.mnemonic == "call"
        and len(instruction.operands) == 1
        and _immediate(instruction.operands[0]) == transport.constructor
    ]
    for constructor_call in constructor_calls:
        captured_registers = {
            instruction.operands[0].reg
            for instruction in main[constructor_call + 1 : constructor_call + 9]
            if instruction.mnemonic == "mov"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_REG
            and instruction.operands[1].type == X86_OP_REG
            and instruction.operands[1].reg == X86_REG_EAX
        }
        if not captured_registers:
            continue
        for index, instruction in enumerate(
            main[constructor_call + 1 :], start=constructor_call + 1
        ):
            operands = instruction.operands
            if (
                instruction.mnemonic != "cmp"
                or len(operands) != 2
                or _immediate(operands[1]) != 1
            ):
                continue
            selector_register = (
                operands[0].reg if operands[0].type == X86_OP_REG else None
            )
            if selector_register is None:
                continue
            loaded = any(
                previous.mnemonic == "mov"
                and len(previous.operands) == 2
                and previous.operands[0].type == X86_OP_REG
                and previous.operands[0].reg == selector_register
                and _absolute_memory(previous.operands[1])
                == runtime.selector_destination
                for previous in main[max(0, index - 10) : index]
            )
            if not loaded:
                continue
            for cmov_index in range(index + 1, min(len(main), index + 10)):
                cmov = main[cmov_index]
                if cmov.mnemonic not in {"cmove", "cmovz"} or len(cmov.operands) != 2:
                    continue
                if (
                    cmov.operands[0].type != X86_OP_REG
                    or cmov.operands[1].type != X86_OP_REG
                ):
                    continue
                if cmov.operands[1].reg not in captured_registers:
                    continue
                selected_register = cmov.operands[0].reg
                for store in main[cmov_index + 1 : cmov_index + 7]:
                    if (
                        store.mnemonic == "mov"
                        and len(store.operands) == 2
                        and (destination := _absolute_memory(store.operands[0]))
                        is not None
                        and store.operands[1].type == X86_OP_REG
                        and store.operands[1].reg == selected_register
                    ):
                        return destination
    return None


def _runtime_connect(
    main: list[object],
    runtime: _RuntimeConfig,
    transport_global: int,
) -> bool:
    # parser候補はここではcall immediateを直接扱う。
    direct_calls = {
        index: _immediate(instruction.operands[0])
        for index, instruction in enumerate(main)
        if instruction.mnemonic == "call"
        and len(instruction.operands) == 1
        and _immediate(instruction.operands[0]) is not None
    }
    vcalls = dict(_vcall_displacements(main))
    for parser_index in direct_calls:
        pushes = _preceding_pushes(main, parser_index, count=1, maximum_scan=5)
        if len(pushes) != 1 or _immediate(pushes[0]) != runtime.port_destination:
            continue
        for call_index in range(parser_index + 1, min(len(main), parser_index + 16)):
            if vcalls.get(call_index) != 0x10:
                continue
            window = main[parser_index + 1 : call_index]
            has_host = any(
                instruction.mnemonic == "push"
                and _immediate(instruction.operands[0]) == runtime.host_destination
                for instruction in window
            )
            has_port_result = any(
                instruction.mnemonic == "push"
                and instruction.operands[0].type == X86_OP_REG
                and instruction.operands[0].reg == X86_REG_EAX
                for instruction in window
            )
            has_selected_transport = any(
                _absolute_memory(operand) == transport_global
                for instruction in main[max(0, parser_index - 8) : call_index]
                for operand in instruction.operands
            )
            if has_host and has_port_result and has_selected_transport:
                return True
    return False


def _keepalive_proven(
    data: bytes,
    sections: tuple[_Section, ...],
    connect_instructions: list[object],
    coverage: _DecodeCoverage,
) -> bool:
    candidates = {
        immediate
        for instruction in connect_instructions
        for operand in instruction.operands
        if (immediate := _immediate(operand)) is not None
        and _section_for_address(sections, immediate, executable=True)
    }
    for candidate in candidates:
        instructions = _decode(
            data,
            sections,
            candidate,
            coverage=coverage,
            maximum_bytes=0x900,
        )
        if all(
            _has_immediate(instructions, value) for value in (0xC9, 0xA, 0x3E8, 0xEA60)
        ) and _has_indirect_call(instructions, 8):
            return True
    return False


_DISPATCH_GROUPS = {
    "process": {"CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW"},
    "file": {"CreateFileW", "WriteFile"},
    "registry": {"RegCreateKeyW", "RegDeleteValueW", "RegSetValueExW"},
    "event_log": {"OpenEventLogW", "ClearEventLogW"},
}

_REGISTRATION_GROUPS = {
    "network_identity": {"gethostname", "gethostbyname"},
    "system": {"GetSystemInfo"},
    "memory": {"GlobalMemoryStatusEx"},
    "drive": {"GetDriveTypeW", "GetLogicalDriveStringsW"},
    "interactive": {"GetForegroundWindow", "GetWindowTextW", "GetLastInputInfo"},
}


def _api_group_count(names: set[str], groups: dict[str, set[str]]) -> int:
    return sum(bool(names & members) for members in groups.values())


def _dispatcher(
    data: bytes,
    sections: tuple[_Section, ...],
    imports: dict[int, str],
    main: list[object],
    coverage: _DecodeCoverage,
) -> tuple[bool, int]:
    setter_calls = [index for index, slot in _vcall_displacements(main) if slot == 0xC]
    if not setter_calls:
        return False, 0
    best_groups = 0
    for index, instruction in enumerate(main):
        operands = instruction.operands
        if (
            instruction.mnemonic != "mov"
            or len(operands) != 2
            or operands[0].type != X86_OP_MEM
            or operands[0].mem.base == X86_REG_INVALID
            or operands[1].type != X86_OP_IMM
            or not any(setter_index < index for setter_index in setter_calls)
        ):
            continue
        table = _immediate(operands[1])
        if table is None:
            continue
        handler = _read_u32(data, sections, table)
        if (
            handler is None
            or _section_for_address(sections, handler, executable=True) is None
        ):
            continue
        instructions = _decode(data, sections, handler, coverage=coverage)
        names = {call.name for call in _api_calls(instructions, imports)}
        groups = _api_group_count(names, _DISPATCH_GROUPS)
        best_groups = max(best_groups, groups)
        bounded_command = any(
            instruction.mnemonic == "cmp"
            and any(_immediate(operand) == 0xCA for operand in instruction.operands)
            for instruction in instructions
        )
        indexed_jump = any(
            instruction.mnemonic == "jmp"
            and any(
                operand.type == X86_OP_MEM
                and operand.mem.index != X86_REG_INVALID
                and operand.mem.scale == 4
                for operand in instruction.operands
            )
            for instruction in instructions
        )
        if (
            bounded_command
            and indexed_jump
            and groups >= 3
            and _has_indirect_call(instructions, 8)
        ):
            return True, groups
    return False, best_groups


def _registration(
    data: bytes,
    sections: tuple[_Section, ...],
    imports: dict[int, str],
    main: list[object],
    coverage: _DecodeCoverage,
) -> tuple[bool, int]:
    best_groups = 0
    for _call_index, target in _direct_targets(main, sections):
        if not _window_contains(
            data,
            sections,
            target,
            struct.pack("<I", 0x124A),
            maximum_bytes=MAXIMUM_FUNCTION_BYTES,
        ):
            continue
        instructions = _decode(data, sections, target, coverage=coverage)
        if not _has_immediate(instructions, 0x124A):
            continue
        command_six = any(
            instruction.mnemonic == "mov"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_MEM
            and instruction.operands[0].size == 1
            and _immediate(instruction.operands[1]) == 6
            for instruction in instructions
        )
        names = {call.name for call in _api_calls(instructions, imports)}
        groups = _api_group_count(names, _REGISTRATION_GROUPS)
        best_groups = max(best_groups, groups)
        if command_six and groups >= 4 and _has_indirect_call(instructions, 8):
            return True, groups
    return False, best_groups


def analyze_run_dll_terminal_lineage(
    data: bytes,
    image: object,
    *,
    run_export: int,
    sources: tuple[object, ...],
    selector_values: tuple[int, ...],
) -> dict[str, object]:
    """設定sourceから初回登録送信までの終端lineageをfail-closedで検証する。"""

    if not isinstance(sources, tuple):
        return _empty("invalid_input", ["run_dll_terminal_input_contract_rejected"])
    try:
        source_names = tuple(source.name for source in sources)
        source_kinds = tuple(source.kind for source in sources)
        invalid_source = any(
            type(source.address) is not int
            or type(source.size) is not int
            or not 0 <= source.address <= 0xFFFFFFFF
            or not 1 <= source.size <= 0x10000
            or source.kind not in {"host", "port", "selector"}
            for source in sources
        )
    except AttributeError:
        return _empty("invalid_input", ["run_dll_terminal_input_contract_rejected"])
    if (
        not isinstance(data, bytes)
        or not 1 <= len(data) <= MAXIMUM_INPUT_SIZE
        or type(run_export) is not int
        or not 0 <= run_export <= 0xFFFFFFFF
        or len(sources) != 9
        or len(set(source_names)) != 9
        or invalid_source
        or set(source_kinds) != {"host", "port", "selector"}
        or any(source_kinds.count(kind) != 3 for kind in ("host", "port", "selector"))
    ):
        return _empty("invalid_input", ["run_dll_terminal_input_contract_rejected"])
    sections = _sections(data, image)
    imports = _imports(image)
    if sections is None or imports is None:
        return _empty("pe_mapping_rejected", ["run_dll_terminal_pe_mapping_rejected"])
    decode_coverage = _DecodeCoverage()
    run = _decode(
        data,
        sections,
        run_export,
        coverage=decode_coverage,
        maximum_bytes=0x400,
    )
    if not decode_coverage.complete:
        return _decode_limit_result(decode_coverage)
    callback = _run_callback(run, imports, sections)
    if callback is None:
        return _empty(
            "run_callback_unproven", ["run_dll_create_thread_callback_unproven"]
        )
    main = _decode(
        data,
        sections,
        callback,
        coverage=decode_coverage,
        maximum_bytes=MAXIMUM_MAIN_BYTES,
    )
    referenced = _referenced_sources(main, sources)
    runtime = _runtime_config(main, sources, sections)
    transport, transport_candidates = _transport(
        data,
        sections,
        imports,
        main,
        decode_coverage,
    )

    selector_binding = False
    runtime_connect = False
    same_socket = False
    framed = False
    keepalive = False
    if transport is not None and runtime is not None:
        transport_global = _selector_binding(main, runtime, transport, selector_values)
        selector_binding = transport_global is not None
        if transport_global is not None:
            runtime_connect = _runtime_connect(main, runtime, transport_global)
        connect_instructions = _decode(
            data,
            sections,
            transport.connect_method,
            coverage=decode_coverage,
            maximum_bytes=0x1000,
        )
        keepalive = _keepalive_proven(
            data,
            sections,
            connect_instructions,
            decode_coverage,
        )
        same_socket = True
        framed = True

    dispatcher, dispatcher_groups = _dispatcher(
        data,
        sections,
        imports,
        main,
        decode_coverage,
    )
    registration, registration_groups = _registration(
        data,
        sections,
        imports,
        main,
        decode_coverage,
    )
    if not decode_coverage.complete:
        return _decode_limit_result(decode_coverage)
    proof = {
        "run_thread_callback": True,
        "all_config_fields_referenced": len(referenced) == len(sources),
        "runtime_config_copy": runtime is not None,
        "selector_one_transport_binding": selector_binding,
        "runtime_config_to_connect": runtime_connect,
        "same_socket_connect_send_receive": same_socket,
        "framed_send_receive": framed,
        "periodic_keepalive": keepalive,
        "callback_dispatcher": dispatcher,
        "registration_serializer": registration,
    }
    proof_codes = {
        "run_thread_callback": "run_dll_create_thread_callback_unproven",
        "all_config_fields_referenced": "run_dll_all_config_sources_unreferenced",
        "runtime_config_copy": "run_dll_runtime_config_copy_unproven",
        "selector_one_transport_binding": "run_dll_selector_one_tcp_binding_unproven",
        "runtime_config_to_connect": "run_dll_runtime_config_to_connect_unproven",
        "same_socket_connect_send_receive": "run_dll_same_socket_lineage_unproven",
        "framed_send_receive": "run_dll_14_byte_ca_frame_unproven",
        "periodic_keepalive": "run_dll_periodic_keepalive_unproven",
        "callback_dispatcher": "run_dll_receive_dispatcher_unproven",
        "registration_serializer": "run_dll_initial_registration_serializer_unproven",
    }
    missing = [proof_codes[name] for name, value in proof.items() if not value]
    terminal = not missing
    return {
        "schema_version": 1,
        "status": "validated_terminal_lineage"
        if terminal
        else "terminal_lineage_incomplete",
        "analysis_complete": True,
        "terminal_family_lineage_proven": terminal,
        "proof": proof,
        "missing_proof_codes": missing,
        "coverage": {
            "source_count": len(sources),
            "referenced_source_count": len(referenced),
            "transport_candidate_count": transport_candidates,
            "dispatcher_capability_group_count": dispatcher_groups,
            "registration_inventory_group_count": registration_groups,
            "instruction_decode_complete": True,
            "instruction_decode_limit_exceeded_count": 0,
        },
        "protocol": {
            "transport": "tcp" if transport is not None else None,
            "length_prefix_size": 4 if framed else None,
            "session_header_size": 10 if framed else None,
            "frame_header_size": 14 if framed else None,
            "marker": "uint16_0x00ca" if framed else None,
            "initial_registration_command": 6 if registration else None,
            "raw_frame_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
        "raw_addresses_included": False,
        "raw_config_included": False,
    }


__all__ = ["MAXIMUM_INPUT_SIZE", "analyze_run_dll_terminal_lineage"]
