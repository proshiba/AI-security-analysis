"""x64直結型Winos／ValleyRAT終端の設定と通信lineageを静的に検証する。

検体は実行せず、外部通信も行わない。UTF-16LEの設定値だけでは帰属せず、
設定初期化、runtime endpoint、TCP client vtable、同一socketのconnect／send／
recv、14 byte frame、受信callback dispatcher、初回登録serializerまでが同じ
component内で閉じる場合だけValleyRAT familyとC2設定を確定する。
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass
from itertools import pairwise

import pefile
from capstone import (
    CS_AC_WRITE,
    CS_ARCH_X86,
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
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RIP,
)

from extractors.valleyrat.wide_pipe_config import (
    _mapped_instruction as _mapped_x64_instruction,
)

MINIMUM_INPUT_SIZE = 32 * 1024
MAXIMUM_INPUT_SIZE = 16 * 1024 * 1024
MAXIMUM_SECTION_COUNT = 48
MAXIMUM_IMPORT_COUNT = 8_192
MAXIMUM_FUNCTION_COUNT = 8_192
MAXIMUM_FUNCTION_BYTES = 0x8000
MAXIMUM_FUNCTION_INSTRUCTIONS = 16_384
MAXIMUM_FUNCTION_FRAGMENTS = 64
MAXIMUM_SUMMARY_FUNCTION_BYTES = 4 * 1024 * 1024
MAXIMUM_SUMMARY_VALUES_PER_FUNCTION = 4_096
MAXIMUM_SUMMARY_VALUES = 65_536
MAXIMUM_DETAILED_FUNCTION_COUNT = 512
MAXIMUM_DETAILED_FUNCTION_BYTES = 1024 * 1024
MAXIMUM_DETAILED_INSTRUCTIONS = 65_536
MAXIMUM_DETAILED_LEAF_ATTEMPTS = 64
MAXIMUM_DETAILED_LEAF_BYTES = 4 * 1024
MAXIMUM_DETAILED_LEAF_INSTRUCTIONS = 1_024
MAXIMUM_LEAF_FUNCTION_BYTES = 64
MAXIMUM_LEAF_FUNCTION_INSTRUCTIONS = 16
MAXIMUM_VTABLE_CANDIDATES = 2_048
MAXIMUM_TRANSPORT_SCAN_BYTES = 4 * 1024 * 1024
MAXIMUM_TRANSPORT_SCAN_WINDOWS = 262_144
MAXIMUM_TRANSPORT_POINTER_LOOKUPS = 1_572_864
MAXIMUM_DEALLOCATOR_THUNK_HOPS = 4
MAXIMUM_WIDE_STRINGS = 32_768
MAXIMUM_CONFIG_CLUSTERS = 64
MAXIMUM_DIRECT_TARGETS = 2_048
MAXIMUM_REACHING_VALUE_NODES = MAXIMUM_FUNCTION_INSTRUCTIONS
MAXIMUM_REACHING_VALUE_TOTAL_NODES = 262_144
MAXIMUM_GRAPH_PATH_STATES = 4_096
MAXIMUM_CONNECT_REFERENCED_ROOTS = 64
MAXIMUM_SWITCH_TARGETS = 256
MAXIMUM_SWITCH_REACHING_TOTAL_NODES = 262_144
MAXIMUM_SWITCH_REACHING_TOTAL_EDGES = 524_288

_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){2,255}\x00\x00")
_DOMAIN = re.compile(
    r"(?i)(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\Z"
)


@dataclass(frozen=True)
class _Section:
    name: str
    address: int
    raw_start: int
    raw_end: int
    executable: bool
    writable: bool
    virtual_size: int = 0

    @property
    def size(self) -> int:
        return self.raw_end - self.raw_start

    @property
    def mapped_size(self) -> int:
        return max(self.size, self.virtual_size)

    def contains_address(self, address: int, size: int = 1) -> bool:
        return self.address <= address and address + size <= self.address + self.size

    def offset(self, address: int) -> int:
        return self.raw_start + address - self.address


@dataclass(frozen=True)
class _WideString:
    address: int
    value: str


@dataclass(frozen=True)
class _ConfigSlot:
    host: str
    port: int
    host_address: int
    port_address: int
    loopback: bool


@dataclass(frozen=True)
class _ConfigCluster:
    slots: tuple[_ConfigSlot, ...]
    addresses: tuple[int, ...]

    @property
    def external_slots(self) -> tuple[_ConfigSlot, ...]:
        return tuple(slot for slot in self.slots if not slot.loopback)


@dataclass(frozen=True)
class _Transport:
    vtable: int
    constructor: int
    send_method: int
    callback_setter: int
    connect_method: int
    receive_worker: int
    frame_parser: int
    keepalive_worker: int
    socket_displacement: int
    marker_displacement: int
    marker_value: int
    callback_displacement: int


@dataclass(frozen=True)
class _CopyCall:
    index: int
    target: int
    destination: int | None
    source: int | None
    capacity: int | None


@dataclass(frozen=True)
class _SocketLocation:
    displacement: int
    object_origin: str
    store_address: int


@dataclass(frozen=True)
class _InstructionGraph:
    predecessors: tuple[frozenset[int], ...]
    successors: tuple[frozenset[int], ...]


@dataclass(frozen=True)
class _MainLineage:
    main: int
    selected_client_global: int
    runtime_host_global: int
    runtime_port_global: int
    dispatcher: int
    config_reference_count: int
    initialized_source_count: int


@dataclass(frozen=True)
class _FunctionRange:
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class _FunctionSummary:
    api_names: frozenset[str]
    immediates: frozenset[int]
    direct_targets: frozenset[int]
    vcall_slots: frozenset[int]
    rip_targets: frozenset[int]
    memory_displacements: frozenset[int]


@dataclass
class _DecodeCoverage:
    truncated_function_count: int = 0
    rejected_function_range_count: int = 0
    summary_budget_exhausted_count: int = 0
    summary_decode_incomplete_count: int = 0
    detailed_budget_exhausted_count: int = 0
    detailed_decode_incomplete_count: int = 0
    unresolved_direct_branch_count: int = 0
    transport_scan_budget_exhausted_count: int = 0

    @property
    def complete(self) -> bool:
        return all(
            count == 0
            for count in (
                self.truncated_function_count,
                self.rejected_function_range_count,
                self.summary_budget_exhausted_count,
                self.summary_decode_incomplete_count,
                self.detailed_budget_exhausted_count,
                self.detailed_decode_incomplete_count,
                self.unresolved_direct_branch_count,
                self.transport_scan_budget_exhausted_count,
            )
        )

    @property
    def missing_proof_codes(self) -> list[str]:
        result: list[str] = []
        if self.rejected_function_range_count:
            result.append("direct_native_function_range_rejected")
        if self.truncated_function_count:
            result.append("direct_native_per_function_decode_limit_exceeded")
        if self.summary_budget_exhausted_count:
            result.append("direct_native_summary_budget_exceeded")
        if self.summary_decode_incomplete_count:
            result.append("direct_native_summary_decode_incomplete")
        if self.detailed_budget_exhausted_count:
            result.append("direct_native_detailed_decode_budget_exceeded")
        if self.detailed_decode_incomplete_count:
            result.append("direct_native_detailed_decode_incomplete")
        if self.unresolved_direct_branch_count:
            result.append("direct_native_reachable_direct_branch_unresolved")
        if self.transport_scan_budget_exhausted_count:
            result.append("direct_native_transport_scan_budget_exceeded")
        return result


def _section_contains(section: _Section, address: int, size: int = 1) -> bool:
    """file-backed sectionの有界範囲だけを副作用なしで判定する。"""

    return (
        size > 0
        and section.address <= address
        and address + size <= section.address + section.size
    )


def _virtual_section_contains(
    section: _Section,
    address: int,
    size: int = 1,
) -> bool:
    """PE loaderが割り当てるvirtual section範囲だけを判定する。"""

    return (
        size > 0
        and section.address <= address
        and address + size <= section.address + section.mapped_size
    )


def _register_name(instruction: object, register: int) -> str:
    """Capstone命令objectのregister IDを正規名へ限定変換する。"""

    try:
        return instruction.reg_name(register) or ""
    except CsError:
        return ""


def _written_register_names(instruction: object) -> set[str]:
    """Capstoneが報告する書込みregister名だけを局所集合へ正規化する。"""

    try:
        return {
            name
            for register in instruction.regs_access()[1]
            if (name := instruction.reg_name(register))
        }
    except CsError:
        return set()


_REGISTER_FAMILIES = {
    "rax": frozenset({"rax", "eax", "ax", "al", "ah"}),
    "rcx": frozenset({"rcx", "ecx", "cx", "cl", "ch"}),
    "rdx": frozenset({"rdx", "edx", "dx", "dl", "dh"}),
    "r8": frozenset({"r8", "r8d", "r8w", "r8b"}),
}

_GENERAL_REGISTER_FAMILIES = {
    **_REGISTER_FAMILIES,
    "rbx": frozenset({"rbx", "ebx", "bx", "bl", "bh"}),
    "rbp": frozenset({"rbp", "ebp", "bp", "bpl"}),
    "rsi": frozenset({"rsi", "esi", "si", "sil"}),
    "rdi": frozenset({"rdi", "edi", "di", "dil"}),
    "rsp": frozenset({"rsp", "esp", "sp", "spl"}),
    "r9": frozenset({"r9", "r9d", "r9w", "r9b"}),
    "r10": frozenset({"r10", "r10d", "r10w", "r10b"}),
    "r11": frozenset({"r11", "r11d", "r11w", "r11b"}),
    "r12": frozenset({"r12", "r12d", "r12w", "r12b"}),
    "r13": frozenset({"r13", "r13d", "r13w", "r13b"}),
    "r14": frozenset({"r14", "r14d", "r14w", "r14b"}),
    "r15": frozenset({"r15", "r15d", "r15w", "r15b"}),
}

_VOLATILE_REGISTER_FAMILIES = frozenset(
    {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
)


def _register_family(instruction: object, register: int) -> str:
    name = _register_name(instruction, register).casefold()
    return next(
        (family for family, names in _REGISTER_FAMILIES.items() if name in names),
        name,
    )


def _written_register_families(instruction: object) -> set[str]:
    written = {name.casefold() for name in _written_register_names(instruction)}
    return {
        family
        for family, names in _REGISTER_FAMILIES.items()
        if written & names
    }


def _general_register_family(instruction: object, register: int) -> str:
    name = _register_name(instruction, register).casefold()
    return next(
        (
            family
            for family, names in _GENERAL_REGISTER_FAMILIES.items()
            if name in names
        ),
        name,
    )


def _written_general_register_families(instruction: object) -> set[str]:
    written = {name.casefold() for name in _written_register_names(instruction)}
    return {
        family
        for family, names in _GENERAL_REGISTER_FAMILIES.items()
        if written & names
    }


def _instruction_graph(instructions: list[object]) -> _InstructionGraph:
    """address gapをfallthroughにせず、明示CFG edgeだけを構築する。"""

    address_to_index = {
        instruction.address: index for index, instruction in enumerate(instructions)
    }
    if len(address_to_index) != len(instructions):
        return _InstructionGraph((), ())
    successors: list[set[int]] = [set() for _instruction in instructions]
    for index, instruction in enumerate(instructions):
        mnemonic = instruction.mnemonic.casefold()
        next_index = address_to_index.get(instruction.address + instruction.size)
        if instruction.group(CS_GRP_JUMP):
            target = next(
                (
                    _immediate(operand)
                    for operand in instruction.operands
                    if _immediate(operand) is not None
                ),
                None,
            )
            target_index = address_to_index.get(target)
            if target_index is not None:
                successors[index].add(target_index)
            if mnemonic not in {"jmp", "ljmp"} and next_index is not None:
                successors[index].add(next_index)
        elif not instruction.group(CS_GRP_RET) and mnemonic not in {
            "hlt",
            "int3",
            "ud2",
        }:
            if next_index is not None:
                successors[index].add(next_index)
    predecessors: list[set[int]] = [set() for _instruction in instructions]
    for index, targets in enumerate(successors):
        for target in targets:
            predecessors[target].add(index)
    return _InstructionGraph(
        tuple(frozenset(items) for items in predecessors),
        tuple(frozenset(items) for items in successors),
    )


def _reaching_register_fact(
    instructions: list[object],
    graph: _InstructionGraph,
    target_index: int,
    *,
    family: str,
    kind: str,
    imports: dict[int, str] | None = None,
    mnemonic: str | None = None,
    maximum_nodes: int = MAXIMUM_REACHING_VALUE_NODES,
    coverage: _DecodeCoverage | None = None,
) -> object | None:
    """全到達predecessorで一致するregister定義だけを返す。"""

    if (
        not graph.predecessors
        or not 0 <= target_index < len(instructions)
        or maximum_nodes <= 0
    ):
        return None
    pending = list(graph.predecessors[target_index])
    if not pending:
        return None
    visited: set[int] = set()
    values: set[object | None] = set()
    while pending:
        index = pending.pop()
        if index in visited:
            continue
        visited.add(index)
        if len(visited) > maximum_nodes:
            if coverage is not None:
                coverage.detailed_decode_incomplete_count += 1
            return None
        instruction = instructions[index]
        if family in _written_general_register_families(instruction):
            value: object | None = None
            operands = instruction.operands
            if (
                len(operands) == 2
                and operands[0].type == X86_OP_REG
                and _register_family(instruction, operands[0].reg) == family
            ):
                if kind == "import" and instruction.mnemonic in {"mov", "lea"}:
                    target = _rip_target(instruction, operands[1])
                    value = imports.get(target) if imports is not None else None
                elif kind == "vcall" and instruction.mnemonic == "mov":
                    source = operands[1]
                    if (
                        source.type == X86_OP_MEM
                        and source.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
                        and source.mem.index == X86_REG_INVALID
                        and 0 <= source.mem.disp <= 0x400
                    ):
                        value = source.mem.disp
                elif kind == "rip" and instruction.mnemonic == mnemonic:
                    value = _rip_target(instruction, operands[1])
                elif kind == "immediate" and instruction.mnemonic == "mov":
                    value = _immediate(operands[1])
                elif (
                    kind == "immediate"
                    and instruction.mnemonic == "xor"
                    and len(operands) == 2
                    and operands[1].type == X86_OP_REG
                    and _general_register_family(instruction, operands[1].reg)
                    == family
                ):
                    value = 0
                elif kind == "address":
                    value = _rip_target(instruction, operands[1])
                    if value is None:
                        value = _immediate(operands[1])
                elif kind == "local_address" and instruction.mnemonic == "lea":
                    source = operands[1]
                    if (
                        source.type == X86_OP_MEM
                        and source.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
                        and source.mem.index == X86_REG_INVALID
                    ):
                        base_family = _general_register_family(
                            instruction,
                            source.mem.base,
                        )
                        if base_family in {"rsp", "rbp"} and abs(
                            source.mem.disp
                        ) <= 0x4000:
                            value = (base_family, source.mem.disp)
            values.add(value)
            continue
        if instruction.mnemonic == "call":
            values.add(None)
            continue
        incoming = graph.predecessors[index]
        if not incoming:
            values.add(None)
            continue
        pending.extend(incoming)
    return next(iter(values)) if len(values) == 1 and None not in values else None


def _register_origin(
    instructions: list[object],
    graph: _InstructionGraph,
    target_index: int,
    family: str,
    *,
    maximum_nodes: int = MAXIMUM_REACHING_VALUE_NODES,
) -> str | None:
    """registerが関数entryのどのGPRから来たかを全pathで照合する。"""

    if not graph.predecessors or not 0 <= target_index < len(instructions):
        return None
    initial = graph.predecessors[target_index]
    pending: list[tuple[int, str]] = [(index, family) for index in initial]
    if not pending:
        return f"entry:{family}"
    visited: set[tuple[int, str]] = set()
    origins: set[str | None] = set()
    while pending:
        index, current_family = pending.pop()
        state = (index, current_family)
        if state in visited:
            continue
        visited.add(state)
        if len(visited) > maximum_nodes:
            return None
        instruction = instructions[index]
        if current_family in _written_general_register_families(instruction):
            operands = instruction.operands
            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and _general_register_family(instruction, operands[0].reg)
                == current_family
                and operands[1].type == X86_OP_REG
            ):
                source_family = _general_register_family(instruction, operands[1].reg)
                incoming = graph.predecessors[index]
                if incoming:
                    pending.extend((item, source_family) for item in incoming)
                else:
                    origins.add(f"entry:{source_family}")
            else:
                origins.add(None)
            continue
        if (
            instruction.mnemonic == "call"
            and current_family in _VOLATILE_REGISTER_FAMILIES
        ):
            origins.add(None)
            continue
        incoming = graph.predecessors[index]
        if incoming:
            pending.extend((item, current_family) for item in incoming)
        else:
            origins.add(f"entry:{current_family}")
    return next(iter(origins)) if len(origins) == 1 and None not in origins else None


def _is_reachable(
    graph: _InstructionGraph,
    start_index: int,
    target_index: int,
    *,
    maximum_nodes: int = MAXIMUM_REACHING_VALUE_NODES,
) -> bool:
    if not graph.successors:
        return False
    pending = [start_index]
    visited: set[int] = set()
    while pending:
        index = pending.pop()
        if index == target_index:
            return True
        if index in visited:
            continue
        visited.add(index)
        if len(visited) > maximum_nodes:
            return False
        pending.extend(graph.successors[index])
    return False


def _reachable_avoiding(
    graph: _InstructionGraph,
    start_index: int,
    target_index: int,
    excluded_index: int,
    *,
    maximum_nodes: int = MAXIMUM_REACHING_VALUE_NODES,
) -> bool | None:
    """指定nodeを通らないpathの有無を有界探索し、打切りはunknownにする。"""

    if not graph.successors or excluded_index == start_index:
        return False
    pending = [start_index]
    visited: set[int] = set()
    while pending:
        index = pending.pop()
        if index == excluded_index or index in visited:
            continue
        if index == target_index:
            return True
        visited.add(index)
        if len(visited) > maximum_nodes:
            return None
        pending.extend(graph.successors[index])
    return False


def _all_paths_end_at_unique_return(
    instructions: list[object],
    graph: _InstructionGraph,
    return_index: int,
    *,
    maximum_nodes: int = MAXIMUM_GRAPH_PATH_STATES,
) -> bool:
    """entryから到達する有限CFGの唯一のsinkが指定RETかを確認する。"""

    if (
        not instructions
        or not graph.successors
        or not 0 <= return_index < len(instructions)
        or graph.successors[return_index]
    ):
        return False
    pending = [0]
    reachable: set[int] = set()
    while pending:
        index = pending.pop()
        if index in reachable:
            continue
        reachable.add(index)
        if len(reachable) > maximum_nodes:
            return False
        pending.extend(graph.successors[index])
    if reachable != set(range(len(instructions))):
        return False
    if any(
        index != return_index and not graph.successors[index]
        for index in reachable
    ):
        return False
    indegree = {index: 0 for index in reachable}
    for index in reachable:
        for successor in graph.successors[index]:
            if successor in indegree:
                indegree[successor] += 1
    ready = [index for index, count in indegree.items() if count == 0]
    consumed = 0
    while ready:
        index = ready.pop()
        consumed += 1
        for successor in graph.successors[index]:
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)
    return consumed == len(reachable)


def _dominates(
    graph: _InstructionGraph,
    dominator_index: int,
    target_index: int,
    *,
    start_index: int = 0,
    maximum_nodes: int = MAXIMUM_REACHING_VALUE_NODES,
) -> bool:
    """entryからtargetへの全既知pathがdominatorを通る場合だけ真を返す。"""

    if (
        not graph.successors
        or not 0 <= start_index < len(graph.successors)
        or not 0 <= dominator_index < len(graph.successors)
        or not 0 <= target_index < len(graph.successors)
    ):
        return False

    def reachable(*, excluded: int | None) -> bool | None:
        if excluded == start_index:
            return False
        pending = [start_index]
        visited: set[int] = set()
        while pending:
            index = pending.pop()
            if index == excluded or index in visited:
                continue
            if index == target_index:
                return True
            visited.add(index)
            if len(visited) > maximum_nodes:
                return None
            pending.extend(graph.successors[index])
        return False

    reaches_target = reachable(excluded=None)
    bypasses_dominator = reachable(excluded=dominator_index)
    return reaches_target is True and bypasses_dominator is False


def _reachable_indices(
    graph: _InstructionGraph,
    start_index: int,
    *,
    maximum_nodes: int,
) -> set[int] | None:
    if not graph.successors or not 0 <= start_index < len(graph.successors):
        return None
    pending = [(index, 1) for index in graph.successors[start_index]]
    minimum_depth: dict[int, int] = {}
    while pending:
        index, depth = pending.pop()
        if depth > maximum_nodes:
            continue
        previous_depth = minimum_depth.get(index)
        if previous_depth is not None and previous_depth <= depth:
            continue
        minimum_depth[index] = depth
        if len(minimum_depth) > MAXIMUM_GRAPH_PATH_STATES:
            return None
        pending.extend(
            (successor, depth + 1) for successor in graph.successors[index]
        )
    return set(minimum_depth)


def _empty(status: str, missing: list[str] | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "matched": False,
        "family": None,
        "variant": "direct_native_x64_terminal_candidate",
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "static_config_recovered": False,
        "candidate_config_recovered": False,
        "attribution_scope": "component_handler_route",
        "endpoints": [],
        "slots": [],
        "excluded_placeholder_defaults": [],
        "missing_proof_codes": list(missing or []),
        "evidence": {
            "status": status,
            "profile": "direct_native_x64_winos",
            "analysis_complete": False,
            "terminal_family_lineage_proven": False,
            "proof": {
                "unique_three_slot_config": False,
                "config_initializer_to_runtime_endpoint": False,
                "tcp_vtable_constructor": False,
                "same_socket_connect_send_receive": False,
                "framed_send_receive": False,
                "callback_dispatcher": False,
                "registration_serializer": False,
                "same_client_connect_and_registration": False,
                "periodic_keepalive": False,
            },
            "raw_addresses_included": False,
            "raw_config_included": False,
            "raw_payload_included": False,
            "sample_executed": False,
            "network_contacted": False,
        },
        "config": {
            "endpoint_count": 0,
            "configured_slot_count": 0,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _sections(data: bytes, image: object) -> tuple[_Section, ...] | None:
    try:
        image_base = image.OPTIONAL_HEADER.ImageBase
        image_size = image.OPTIONAL_HEADER.SizeOfImage
        source_sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if (
        type(image_base) is not int
        or type(image_size) is not int
        or not 0 <= image_base <= 0xFFFFFFFFFFFFFFFF
        or not 1 <= image_size <= 0xFFFFFFFF
        or image_base + image_size > 0x1_0000_0000_0000_0000
        or not 1 <= len(source_sections) <= MAXIMUM_SECTION_COUNT
    ):
        return None
    result: list[_Section] = []
    for source in source_sections:
        try:
            raw_start = source.PointerToRawData
            raw_size = source.SizeOfRawData
            virtual_size = source.Misc_VirtualSize
            rva = source.VirtualAddress
            characteristics = source.Characteristics
            raw_name = bytes(source.Name).rstrip(b"\x00")
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if any(
            type(value) is not int
            for value in (raw_start, raw_size, virtual_size, rva, characteristics)
        ):
            return None
        raw_end = raw_start + raw_size
        address = image_base + rva
        if (
            raw_start < 0
            or raw_size < 0
            or virtual_size < 0
            or rva < 0
            or rva > 0xFFFFFFFF
            or raw_end < raw_start
            or raw_end > len(data)
            or address < image_base
            or rva + max(raw_size, virtual_size) > image_size
            or address + max(raw_size, virtual_size)
            > 0x1_0000_0000_0000_0000
        ):
            return None
        try:
            name = raw_name.decode("ascii", errors="strict")[:32]
        except UnicodeError:
            return None
        result.append(
            _Section(
                name=name,
                address=address,
                raw_start=raw_start,
                raw_end=raw_end,
                executable=bool(characteristics & 0x20000000),
                writable=bool(characteristics & 0x80000000),
                virtual_size=virtual_size,
            )
        )
    file_backed = [section for section in result if section.size]
    by_raw = sorted(file_backed, key=lambda section: section.raw_start)
    mapped = [section for section in result if section.mapped_size]
    by_address = sorted(mapped, key=lambda section: section.address)
    if any(
        previous.raw_end > current.raw_start
        for previous, current in pairwise(by_raw)
    ) or any(
        previous.address + previous.mapped_size > current.address
        for previous, current in pairwise(by_address)
    ):
        return None
    return tuple(result)


def _imports(image: object) -> tuple[dict[int, str], set[str]] | None:
    try:
        descriptors = list(image.DIRECTORY_ENTRY_IMPORT)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    result: dict[int, str] = {}
    libraries: set[str] = set()
    count = 0
    for descriptor in descriptors:
        try:
            library = bytes(descriptor.dll).decode("ascii", errors="strict").casefold()
            entries = list(descriptor.imports)
        except (AttributeError, TypeError, ValueError, OverflowError, UnicodeError):
            return None
        if not library or len(library) > 128:
            return None
        libraries.add(library)
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
                or not 0 <= address <= 0xFFFFFFFFFFFFFFFF
                or not isinstance(raw_name, bytes)
                or not 1 <= len(raw_name) <= 128
            ):
                continue
            try:
                name = raw_name.decode("ascii", errors="strict")
            except UnicodeError:
                continue
            if address in result:
                return None
            result[address] = name
    return result, libraries


def _section_for_address(
    sections: tuple[_Section, ...],
    address: int,
    *,
    executable: bool | None = None,
) -> _Section | None:
    matches = [
        section
        for section in sections
        if _section_contains(section, address)
        and (executable is None or section.executable is executable)
    ]
    return matches[0] if len(matches) == 1 else None


def _virtual_section_for_address(
    sections: tuple[_Section, ...],
    address: int,
    *,
    executable: bool | None = None,
) -> _Section | None:
    """raw未初期化領域を含む一意なvirtual sectionを返す。"""

    matches = [
        section
        for section in sections
        if _virtual_section_contains(section, address)
        and (executable is None or section.executable is executable)
    ]
    return matches[0] if len(matches) == 1 else None


def _read_u64(
    data: bytes,
    sections: tuple[_Section, ...],
    address: int,
) -> int | None:
    section = _section_for_address(sections, address)
    if section is None or not _section_contains(section, address, 8):
        return None
    offset = section.raw_start + address - section.address
    return struct.unpack_from("<Q", data, offset)[0]


def _read_bytes(
    data: bytes,
    sections: tuple[_Section, ...],
    address: int,
    size: int,
) -> bytes | None:
    if not 0 < size <= MAXIMUM_FUNCTION_BYTES:
        return None
    section = _section_for_address(sections, address)
    if section is None or not _section_contains(section, address, size):
        return None
    offset = section.raw_start + address - section.address
    return data[offset : offset + size]


def _immediate(operand: object) -> int | None:
    return operand.imm & 0xFFFFFFFFFFFFFFFF if operand.type == X86_OP_IMM else None


def _rip_target(instruction: object, operand: object) -> int | None:
    if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
        return None
    return (instruction.address + instruction.size + operand.mem.disp) & 0xFFFFFFFFFFFFFFFF


def _memory_displacements(instructions: list[object]) -> set[int]:
    return {
        operand.mem.disp
        for instruction in instructions
        for operand in instruction.operands
        if operand.type == X86_OP_MEM
        and operand.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
        and operand.mem.index == X86_REG_INVALID
    }


def _has_immediate(instructions: list[object], value: int) -> bool:
    return any(
        _immediate(operand) == value
        for instruction in instructions
        for operand in instruction.operands
    )


def _api_calls(instructions: list[object], imports: dict[int, str]) -> list[tuple[int, str]]:
    graph = _instruction_graph(instructions)
    result: list[tuple[int, str]] = []
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        if instruction.mnemonic == "call" and len(operands) == 1:
            target = _rip_target(instruction, operands[0])
            name = imports.get(target) if target is not None else None
            if name is None and operands[0].type == X86_OP_REG:
                family = _register_family(instruction, operands[0].reg)
                if family in _REGISTER_FAMILIES:
                    fact = _reaching_register_fact(
                        instructions,
                        graph,
                        index,
                        family=family,
                        kind="import",
                        imports=imports,
                    )
                    name = fact if isinstance(fact, str) else None
            if name is not None:
                result.append((index, name))
    return result


def _direct_targets(
    instructions: list[object],
    sections: tuple[_Section, ...],
    coverage: _DecodeCoverage | None = None,
) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic != "call" or len(instruction.operands) != 1:
            continue
        target = _immediate(instruction.operands[0])
        if target is not None and _section_for_address(
            sections, target, executable=True
        ):
            if len(result) >= MAXIMUM_DIRECT_TARGETS:
                if coverage is not None:
                    coverage.detailed_decode_incomplete_count += 1
                return []
            result.append((index, target))
    return result


def _vcall_slots(instructions: list[object]) -> list[tuple[int, int]]:
    graph = _instruction_graph(instructions)
    result: list[tuple[int, int]] = []
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        if instruction.mnemonic != "call" or len(operands) != 1:
            continue
        operand = operands[0]
        if (
            operand.type == X86_OP_MEM
            and operand.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
            and operand.mem.index == X86_REG_INVALID
            and 0 <= operand.mem.disp <= 0x400
        ):
            result.append((index, operand.mem.disp))
        elif operand.type == X86_OP_REG:
            family = _register_family(instruction, operand.reg)
            if family in _REGISTER_FAMILIES:
                slot = _reaching_register_fact(
                    instructions,
                    graph,
                    index,
                    family=family,
                    kind="vcall",
                )
                if isinstance(slot, int):
                    result.append((index, slot))
    return result


def _function_ranges(
    image: object, sections: tuple[_Section, ...]
) -> tuple[_FunctionRange, ...] | None:
    """AMD64 RUNTIME_FUNCTIONを重複のないfile-backed実行範囲へ正規化する。"""

    try:
        image_base = image.OPTIONAL_HEADER.ImageBase
        entries = list(image.DIRECTORY_ENTRY_EXCEPTION)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if (
        type(image_base) is not int
        or not 0 <= image_base <= 0xFFFFFFFFFFFFFFFF
        or not 1 <= len(entries) <= MAXIMUM_FUNCTION_COUNT
    ):
        return None
    ranges: list[_FunctionRange] = []
    for entry in entries:
        try:
            begin_rva = entry.struct.BeginAddress
            end_rva = entry.struct.EndAddress
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if (
            type(begin_rva) is not int
            or type(end_rva) is not int
            or not 0 <= begin_rva < end_rva <= 0xFFFFFFFF
        ):
            return None
        start = image_base + begin_rva
        end = image_base + end_rva
        if not image_base <= start < end <= 0x1_0000_0000_0000_0000:
            return None
        section = _section_for_address(sections, start, executable=True)
        if section is None or not _section_contains(section, start, end - start):
            return None
        ranges.append(_FunctionRange(start, end))
    ordered = tuple(sorted(ranges, key=lambda item: (item.start, item.end)))
    if any(previous.end > current.start for previous, current in pairwise(ordered)):
        return None
    if len({item.start for item in ordered}) != len(ordered):
        return None
    return ordered


class _Analyzer:
    def __init__(
        self,
        data: bytes,
        image: object,
        sections: tuple[_Section, ...],
        imports: dict[int, str],
    ) -> None:
        self.data = data
        self.image = image
        self.sections = sections
        self.imports = imports
        self.coverage = _DecodeCoverage()
        self._cache: dict[int, list[object]] = {}
        self._failed_decodes: set[int] = set()
        self._detailed_function_count = 0
        self._detailed_function_bytes = 0
        self._detailed_instruction_count = 0
        self._leaf_cache: dict[int, list[object]] = {}
        self._failed_leaf_decodes: set[int] = set()
        self._fast_fail_leaf_cache: dict[int, bool] = {}
        self._tail_thunk_cache: dict[int, int] = {}
        self._failed_tail_thunks: set[int] = set()
        self._leaf_attempt_count = 0
        self._leaf_attempt_bytes = 0
        self._leaf_attempt_instructions = 0
        self._switch_reaching_nodes = 0
        self._switch_reaching_edges = 0
        self._unresolved_direct_branches: set[tuple[int, int]] = set()
        ranges = _function_ranges(image, sections)
        if ranges is None:
            self.coverage.rejected_function_range_count += 1
            ranges = ()
        self.function_ranges = ranges
        self._ranges = {item.start: item for item in ranges}
        self._range_starts = tuple(item.start for item in ranges)
        self._range_owner: dict[int, int] = {}
        self.function_starts = tuple(item.start for item in ranges)
        self.summaries: dict[int, _FunctionSummary] = {}
        self._build_summaries()

    def _function_bytes(self, function: _FunctionRange) -> bytes | None:
        section = _section_for_address(self.sections, function.start, executable=True)
        if section is None or not _section_contains(section, function.start, function.size):
            return None
        offset = section.raw_start + function.start - section.address
        return self.data[offset : offset + function.size]

    def _summarize(
        self,
        function: _FunctionRange,
    ) -> _FunctionSummary | None:
        raw = self._function_bytes(function)
        if raw is None:
            self.coverage.summary_decode_incomplete_count += 1
            return None
        if function.size > MAXIMUM_FUNCTION_BYTES:
            self.coverage.truncated_function_count += 1
            return None
        api_names: set[str] = set()
        immediates: set[int] = set()
        direct_targets: set[int] = set()
        vcall_slots: set[int] = set()
        rip_targets: set[int] = set()
        memory_displacements: set[int] = set()
        interesting_immediates = (0xA, 0xC9, 0x3E8, 0x1250, 0xEA60)
        for value in interesting_immediates:
            encoded = value.to_bytes(4, "little")
            if encoded in raw or encoded[:2] in raw:
                immediates.add(value)
        for slot in (0, 0x10, 0x18, 0x20):
            if bytes((slot,)) in raw:
                vcall_slots.add(slot)
        image_base = self.image.OPTIONAL_HEADER.ImageBase
        for offset in range(max(0, len(raw) - 3)):
            displacement = int.from_bytes(
                raw[offset : offset + 4],
                "little",
                signed=True,
            )
            target = (
                function.start + offset + 4 + displacement
            ) & 0xFFFFFFFFFFFFFFFF
            imported = self.imports.get(target)
            if imported is not None:
                api_names.add(imported)
            target_section = _section_for_address(self.sections, target)
            if target_section is not None and not target_section.executable:
                rip_targets.add(target)
            unsigned = int.from_bytes(raw[offset : offset + 4], "little")
            if _section_for_address(self.sections, image_base + unsigned) is not None:
                memory_displacements.add(unsigned)
            if raw[offset] == 0xE8 and offset + 5 <= len(raw):
                direct = (
                    function.start
                    + offset
                    + 5
                    + int.from_bytes(
                        raw[offset + 1 : offset + 5],
                        "little",
                        signed=True,
                    )
                ) & 0xFFFFFFFFFFFFFFFF
                if _section_for_address(self.sections, direct, executable=True):
                    direct_targets.add(direct)
            if any(
                len(values) > MAXIMUM_SUMMARY_VALUES_PER_FUNCTION
                for values in (
                    api_names,
                    direct_targets,
                    rip_targets,
                    memory_displacements,
                )
            ):
                self.coverage.summary_budget_exhausted_count += 1
                return None
        return _FunctionSummary(
            api_names=frozenset(api_names),
            immediates=frozenset(immediates),
            direct_targets=frozenset(direct_targets),
            vcall_slots=frozenset(vcall_slots),
            rip_targets=frozenset(rip_targets),
            memory_displacements=frozenset(memory_displacements),
        )

    def _build_summaries(self) -> None:
        total_bytes = 0
        total_values = 0
        for function in self.function_ranges:
            if total_bytes + function.size > MAXIMUM_SUMMARY_FUNCTION_BYTES:
                self.coverage.summary_budget_exhausted_count += 1
                return
            summary = self._summarize(function)
            total_bytes += function.size
            if summary is None:
                return
            value_count = sum(
                len(values)
                for values in (
                    summary.api_names,
                    summary.immediates,
                    summary.direct_targets,
                    summary.vcall_slots,
                    summary.rip_targets,
                    summary.memory_displacements,
                )
            )
            if total_values + value_count > MAXIMUM_SUMMARY_VALUES:
                self.coverage.summary_budget_exhausted_count += 1
                return
            total_values += value_count
            self.summaries[function.start] = summary

    def _range_index(self, address: int) -> int | None:
        return _function_range_index(
            self.function_ranges,
            self._range_starts,
            address,
        )

    def _reaching_rip_value(
        self,
        function: _FunctionRange,
        target: int,
        register_family: int,
        decoded_context: list[object],
    ) -> int | None:
        """全ての既知CFG predecessorで一致するRIP相対LEA値だけを返す。"""

        instructions = {
            instruction.address: instruction
            for instruction in decoded_context
            if function.start <= instruction.address < function.end
        }
        if target not in instructions:
            return None
        predecessors: dict[int, set[int]] = {
            address: set() for address in instructions
        }
        for address, instruction in instructions.items():
            successors: set[int] = set()
            next_address = address + instruction.size
            if instruction.group(CS_GRP_JUMP):
                direct_target = next(
                    (
                        _immediate(operand)
                        for operand in instruction.operands
                        if _immediate(operand) is not None
                    ),
                    None,
                )
                if direct_target in instructions:
                    successors.add(direct_target)
                if (
                    instruction.mnemonic.casefold() not in {"jmp", "ljmp"}
                    and next_address in instructions
                ):
                    successors.add(next_address)
            elif not instruction.group(CS_GRP_RET) and instruction.mnemonic.casefold() not in {
                "hlt",
                "int3",
                "ud2",
            }:
                if next_address in instructions:
                    successors.add(next_address)
            for successor in successors:
                predecessors[successor].add(address)

        edge_count = sum(len(items) for items in predecessors.values())
        if (
            self._switch_reaching_nodes + len(instructions)
            > MAXIMUM_SWITCH_REACHING_TOTAL_NODES
            or self._switch_reaching_edges + edge_count
            > MAXIMUM_SWITCH_REACHING_TOTAL_EDGES
        ):
            self.coverage.detailed_budget_exhausted_count += 1
            return None
        self._switch_reaching_nodes += len(instructions)
        self._switch_reaching_edges += edge_count

        pending = list(predecessors[target])
        if not pending:
            return None
        visited: set[int] = set()
        values: set[int] = set()
        while pending:
            address = pending.pop()
            if address in visited:
                continue
            visited.add(address)
            if len(visited) > MAXIMUM_REACHING_VALUE_NODES:
                self.coverage.detailed_budget_exhausted_count += 1
                return None
            instruction = instructions[address]
            if instruction.mnemonic == "call":
                return None
            if register_family in _written_register_families(instruction):
                if (
                    instruction.mnemonic != "lea"
                    or len(instruction.operands) != 2
                    or instruction.operands[0].type != X86_OP_REG
                    or _register_family(instruction, instruction.operands[0].reg)
                    != register_family
                ):
                    return None
                value = _rip_target(instruction, instruction.operands[1])
                if value is None:
                    return None
                values.add(value)
                continue
            incoming = predecessors[address]
            if not incoming:
                return None
            pending.extend(incoming)
        if len(values) != 1:
            return None
        return next(iter(values))

    def _indexed_switch_targets(
        self,
        function: _FunctionRange,
        block: list[object],
        decoded_context: list[object],
    ) -> tuple[int, ...] | None:
        """MSVC型の2段byte/RVA switch tableを完全検証してcase先を返す。"""

        semantic = [
            instruction
            for instruction in block
            if instruction.mnemonic.casefold() not in {"endbr64", "nop"}
        ]
        if len(semantic) < 8:
            return None
        jump = semantic[-1]
        if (
            jump.mnemonic.casefold() not in {"jmp", "ljmp"}
            or len(jump.operands) != 1
            or jump.operands[0].type != X86_OP_REG
        ):
            return None
        target_family = _register_family(jump, jump.operands[0].reg)
        add = semantic[-2]
        dword_lookup = semantic[-3]
        byte_lookup = semantic[-4]
        if (
            add.mnemonic != "add"
            or len(add.operands) != 2
            or add.operands[0].type != X86_OP_REG
            or _register_family(add, add.operands[0].reg) != target_family
            or add.operands[1].type != X86_OP_REG
        ):
            return None
        base_family = _register_family(add, add.operands[1].reg)
        if target_family not in _REGISTER_FAMILIES or base_family not in _REGISTER_FAMILIES:
            return None
        if (
            dword_lookup.mnemonic != "mov"
            or len(dword_lookup.operands) != 2
            or dword_lookup.operands[0].type != X86_OP_REG
            or _register_family(dword_lookup, dword_lookup.operands[0].reg)
            != target_family
            or dword_lookup.operands[1].type != X86_OP_MEM
            or dword_lookup.operands[1].size != 4
        ):
            return None
        dword_memory = dword_lookup.operands[1].mem
        if (
            _register_family(dword_lookup, dword_memory.base) != base_family
            or dword_memory.index == X86_REG_INVALID
            or dword_memory.scale != 4
        ):
            return None
        index_family = _register_family(dword_lookup, dword_memory.index)
        if (
            byte_lookup.mnemonic != "movzx"
            or len(byte_lookup.operands) != 2
            or byte_lookup.operands[0].type != X86_OP_REG
            or _register_family(byte_lookup, byte_lookup.operands[0].reg)
            != index_family
            or byte_lookup.operands[1].type != X86_OP_MEM
            or byte_lookup.operands[1].size != 1
        ):
            return None
        byte_memory = byte_lookup.operands[1].mem
        if (
            _register_family(byte_lookup, byte_memory.base) != base_family
            or byte_memory.index == X86_REG_INVALID
            or _register_family(byte_lookup, byte_memory.index) != index_family
            or byte_memory.scale != 1
        ):
            return None

        byte_lookup_index = len(semantic) - 4
        compare_index = None
        bound = None
        for index in range(byte_lookup_index - 2, -1, -1):
            compare = semantic[index]
            branch = semantic[index + 1]
            if compare.mnemonic != "cmp" or branch.mnemonic.casefold() not in {
                "ja",
                "jnbe",
            }:
                continue
            register_operands = [
                operand
                for operand in compare.operands
                if operand.type == X86_OP_REG
                and _register_family(compare, operand.reg) == index_family
            ]
            immediate_operands = [
                value
                for operand in compare.operands
                if (value := _immediate(operand)) is not None
            ]
            branch_target = next(
                (
                    _immediate(operand)
                    for operand in branch.operands
                    if _immediate(operand) is not None
                ),
                None,
            )
            if (
                len(register_operands) == 1
                and len(immediate_operands) == 1
                and 0 <= immediate_operands[0] < MAXIMUM_SWITCH_TARGETS
                and branch_target is not None
                and function.start <= branch_target < function.end
            ):
                compare_index = index
                bound = immediate_operands[0]
                break
        if compare_index is None or bound is None:
            return None

        command_load = None
        for previous in reversed(semantic[:compare_index]):
            if index_family not in _written_register_families(previous):
                if previous.mnemonic == "call":
                    return None
                continue
            if (
                previous.mnemonic == "movzx"
                and len(previous.operands) == 2
                and previous.operands[0].type == X86_OP_REG
                and _register_family(previous, previous.operands[0].reg)
                == index_family
                and previous.operands[1].type == X86_OP_MEM
                and previous.operands[1].size == 1
            ):
                command_load = previous
            break
        if command_load is None:
            return None

        base_assignment = None
        for previous in reversed(semantic[:byte_lookup_index]):
            if base_family not in _written_register_families(previous):
                if previous.mnemonic == "call":
                    return None
                continue
            if (
                previous.mnemonic == "lea"
                and len(previous.operands) == 2
                and previous.operands[0].type == X86_OP_REG
                and _register_family(previous, previous.operands[0].reg)
                == base_family
            ):
                base_assignment = _rip_target(previous, previous.operands[1])
            break
        image_base = self.image.OPTIONAL_HEADER.ImageBase
        if base_assignment is None:
            # switch blockへ入る全ての既知pathで、同じRIP相対LEAが届く場合だけ
            # predecessor側の定義を採用する。別branchの無関係な代入は混同しない。
            base_assignment = self._reaching_rip_value(
                function,
                block[0].address,
                base_family,
                decoded_context,
            )
        if base_assignment != image_base:
            return None

        byte_table = image_base + byte_memory.disp
        byte_values = _read_bytes(
            self.data,
            self.sections,
            byte_table,
            bound + 1,
        )
        if not byte_values:
            return None
        maximum_index = max(byte_values)
        if maximum_index >= MAXIMUM_SWITCH_TARGETS:
            return None
        dword_table = image_base + dword_memory.disp
        dword_size = (maximum_index + 1) * 4
        if dword_table + dword_size != byte_table:
            return None
        encoded_targets = _read_bytes(
            self.data,
            self.sections,
            dword_table,
            dword_size,
        )
        if encoded_targets is None:
            return None
        targets = tuple(
            image_base + struct.unpack_from("<I", encoded_targets, offset)[0]
            for offset in range(0, dword_size, 4)
        )
        if (
            len(set(targets)) != maximum_index + 1
            or any(
                not function.start <= target < function.end
                or _section_for_address(self.sections, target, executable=True) is None
                or dword_table <= target < byte_table + len(byte_values)
                for target in targets
            )
        ):
            return None
        return tuple(sorted(targets))

    def _decode_fragment(
        self,
        index: int,
        disassembler: Cs,
    ) -> list[object] | None:
        function = self.function_ranges[index]
        decoded: dict[int, object] = {}
        claimed = bytearray(function.size)
        pending = [function.start]
        pending_index = 0
        queued = {function.start}
        while pending_index < len(pending):
            expected = pending[pending_index]
            pending_index += 1
            block: list[object] = []
            while function.start <= expected < function.end:
                if expected in decoded:
                    break
                relative = expected - function.start
                if claimed[relative]:
                    return None
                instruction = _mapped_x64_instruction(
                    self.data,
                    self.sections,
                    disassembler,
                    expected,
                )
                if (
                    instruction is None
                    or instruction.address != expected
                    or instruction.size <= 0
                    or instruction.address + instruction.size > function.end
                ):
                    return None
                end_relative = relative + instruction.size
                if any(claimed[relative:end_relative]):
                    return None
                claimed[relative:end_relative] = b"\x01" * instruction.size
                decoded[expected] = instruction
                block.append(instruction)
                if len(decoded) > MAXIMUM_FUNCTION_INSTRUCTIONS:
                    return None
                next_address = instruction.address + instruction.size
                if instruction.group(CS_GRP_JUMP):
                    target = next(
                        (
                            _immediate(operand)
                            for operand in instruction.operands
                            if _immediate(operand) is not None
                        ),
                        None,
                    )
                    if (
                        target is not None
                        and function.start <= target < function.end
                        and target not in queued
                    ):
                        pending.append(target)
                        queued.add(target)
                    if target is None:
                        switch_targets = self._indexed_switch_targets(
                            function,
                            block,
                            list(decoded.values()),
                        )
                        if switch_targets is None:
                            return None
                        for switch_target in switch_targets:
                            if switch_target not in queued:
                                pending.append(switch_target)
                                queued.add(switch_target)
                    if instruction.mnemonic.casefold() in {"jmp", "ljmp"}:
                        break
                if (
                    instruction.group(CS_GRP_RET)
                    or instruction.mnemonic.casefold() in {"hlt", "int3", "ud2"}
                ):
                    break
                expected = next_address
        return [decoded[address] for address in sorted(decoded)] or None

    def _fragment_targets(
        self,
        index: int,
        instructions: list[object],
    ) -> set[int]:
        targets: set[int] = set()
        function = self.function_ranges[index]
        for instruction in instructions:
            if (
                instruction.group(CS_GRP_JUMP)
                and instruction.operands
                and instruction.operands[0].type == X86_OP_IMM
            ):
                target = self._range_index(
                    int(instruction.operands[0].imm) & 0xFFFFFFFFFFFFFFFF
                )
                if (
                    target is not None
                    and target != index
                ):
                    targets.add(target)
                elif target is None:
                    branch_target = (
                        int(instruction.operands[0].imm) & 0xFFFFFFFFFFFFFFFF
                    )
                    if (
                        instruction is instructions[-1]
                        and instruction.mnemonic.casefold() in {"jmp", "ljmp"}
                        and self._is_stack_cookie_fast_fail_leaf(branch_target)
                    ):
                        continue
                    branch = (instruction.address, branch_target)
                    if branch not in self._unresolved_direct_branches:
                        self._unresolved_direct_branches.add(branch)
                        self.coverage.unresolved_direct_branch_count += 1
                        self.coverage.detailed_decode_incomplete_count += 1
        following = index + 1
        final = instructions[-1]
        if (
            following < len(self.function_ranges)
            and self.function_ranges[following].start == function.end
            and not final.group(CS_GRP_RET)
            and not (
                final.group(CS_GRP_JUMP)
                and final.mnemonic.casefold() in {"jmp", "ljmp"}
            )
            and final.mnemonic.casefold() not in {"hlt", "int3", "ud2"}
        ):
            targets.add(following)
        return targets

    def _is_stack_cookie_fast_fail_leaf(self, address: int) -> bool:
        """pdata外のMSVC stack-cookie fail-fast leafだけを厳密に許容する。"""

        cached = self._fast_fail_leaf_cache.get(address)
        if cached is not None:
            return cached
        self._fast_fail_leaf_cache[address] = False
        if self._range_index(address) is not None:
            return False
        section = _section_for_address(self.sections, address, executable=True)
        if section is None or not _section_contains(section, address, 7):
            return False
        maximum_bytes = min(16, section.address + section.size - address)
        if (
            self._leaf_attempt_count + 1 > MAXIMUM_DETAILED_LEAF_ATTEMPTS
            or self._leaf_attempt_bytes + maximum_bytes
            > MAXIMUM_DETAILED_LEAF_BYTES
            or self._leaf_attempt_instructions + 2
            > MAXIMUM_DETAILED_LEAF_INSTRUCTIONS
        ):
            self.coverage.detailed_budget_exhausted_count += 1
            return False
        self._leaf_attempt_count += 1
        self._leaf_attempt_bytes += maximum_bytes
        self._leaf_attempt_instructions += 2
        try:
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
            disassembler.detail = True
            first = _mapped_x64_instruction(
                self.data,
                self.sections,
                disassembler,
                address,
            )
            if first is None:
                return False
            second = _mapped_x64_instruction(
                self.data,
                self.sections,
                disassembler,
                first.address + first.size,
            )
        except (CsError, AttributeError, TypeError, ValueError, OverflowError):
            return False
        if second is None:
            return False
        if (
            first.address != address
            or first.mnemonic != "mov"
            or len(first.operands) != 2
            or first.operands[0].type != X86_OP_REG
            or _register_name(first, first.operands[0].reg).casefold() != "ecx"
            or _immediate(first.operands[1]) != 2
            or second.address != first.address + first.size
            or second.mnemonic != "int"
            or len(second.operands) != 1
            or _immediate(second.operands[0]) != 0x29
        ):
            return False
        decoded_bytes = second.address + second.size - address
        if (
            self._detailed_function_count + 1 > MAXIMUM_DETAILED_FUNCTION_COUNT
            or self._detailed_function_bytes + decoded_bytes
            > MAXIMUM_DETAILED_FUNCTION_BYTES
            or self._detailed_instruction_count + 2
            > MAXIMUM_DETAILED_INSTRUCTIONS
        ):
            self.coverage.detailed_budget_exhausted_count += 1
            return False
        self._detailed_function_count += 1
        self._detailed_function_bytes += decoded_bytes
        self._detailed_instruction_count += 2
        self._fast_fail_leaf_cache[address] = True
        return True

    def _direct_tail_thunk_target(self, address: int) -> int | None:
        return _direct_tail_thunk_target(self, address)

    def _canonical_seed(
        self,
        seed: int,
        disassembler: Cs,
    ) -> int | None:
        """連続pdata rangeの実fallthroughを有界に逆探索してrootへ正規化する。"""

        current = seed
        fragment_count = 1
        total_bytes = self.function_ranges[seed].size
        total_instructions = 0
        while current > 0:
            previous = current - 1
            previous_range = self.function_ranges[previous]
            current_range = self.function_ranges[current]
            if previous_range.end != current_range.start:
                break
            if (
                fragment_count + 1 > MAXIMUM_FUNCTION_FRAGMENTS
                or total_bytes + previous_range.size > MAXIMUM_FUNCTION_BYTES
                or self.function_ranges[seed].end - previous_range.start
                > MAXIMUM_FUNCTION_BYTES
            ):
                self.coverage.truncated_function_count += 1
                return None
            fragment = self._decode_fragment(previous, disassembler)
            if not fragment:
                break
            total_instructions += len(fragment)
            if total_instructions > MAXIMUM_FUNCTION_INSTRUCTIONS:
                self.coverage.truncated_function_count += 1
                return None
            final = fragment[-1]
            if (
                final.group(CS_GRP_RET)
                or (
                    final.group(CS_GRP_JUMP)
                    and final.mnemonic.casefold() in {"jmp", "ljmp"}
                )
                or final.mnemonic.casefold() in {"hlt", "int3", "ud2"}
            ):
                break
            current = previous
            fragment_count += 1
            total_bytes += previous_range.size
        return current

    def decode(self, address: int) -> list[object]:
        cached = self._cache.get(address)
        if cached is not None:
            return cached
        if address in self._failed_decodes:
            return []
        seed = self._range_index(address)
        if seed is None:
            return self.decode_leaf_setter(address)
        if self.function_ranges[seed].start != address:
            self._failed_decodes.add(address)
            return []
        try:
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
            disassembler.detail = True
        except CsError:
            self.coverage.detailed_decode_incomplete_count += 1
            self._failed_decodes.add(address)
            return []
        try:
            seed = self._canonical_seed(seed, disassembler)
            if seed is None:
                self._failed_decodes.add(address)
                return []
            owner = self._range_owner.get(seed)
            if owner is not None:
                return self._cache[owner]
            members: set[int] = set()
            fragments: dict[int, list[object]] = {}
            pending = [seed]
            pending_index = 0
            while pending_index < len(pending):
                index = pending[pending_index]
                pending_index += 1
                if index in members:
                    continue
                if index in self._range_owner:
                    self.coverage.detailed_decode_incomplete_count += 1
                    self._failed_decodes.add(address)
                    return []
                if len(members) >= MAXIMUM_FUNCTION_FRAGMENTS:
                    self.coverage.truncated_function_count += 1
                    self._failed_decodes.add(address)
                    return []
                prospective_members = members | {index}
                prospective_bytes = sum(
                    self.function_ranges[item].size
                    for item in prospective_members
                )
                prospective_span = (
                    max(
                        self.function_ranges[item].end
                        for item in prospective_members
                    )
                    - min(
                        self.function_ranges[item].start
                        for item in prospective_members
                    )
                )
                if (
                    prospective_bytes > MAXIMUM_FUNCTION_BYTES
                    or prospective_span > MAXIMUM_FUNCTION_BYTES
                ):
                    self.coverage.truncated_function_count += 1
                    self._failed_decodes.add(address)
                    return []
                fragment = self._decode_fragment(index, disassembler)
                if not fragment:
                    self.coverage.detailed_decode_incomplete_count += 1
                    self._failed_decodes.add(address)
                    return []
                members.add(index)
                fragments[index] = fragment
                pending.extend(
                    target
                    for target in sorted(self._fragment_targets(index, fragment))
                    if target not in members
                )
            function_bytes = sum(
                self.function_ranges[index].size for index in members
            )
            instruction_count = sum(len(fragments[index]) for index in members)
            span = (
                max(self.function_ranges[index].end for index in members)
                - min(self.function_ranges[index].start for index in members)
            )
            if (
                function_bytes > MAXIMUM_FUNCTION_BYTES
                or span > MAXIMUM_FUNCTION_BYTES
                or instruction_count > MAXIMUM_FUNCTION_INSTRUCTIONS
            ):
                self.coverage.truncated_function_count += 1
                self._failed_decodes.add(address)
                return []
            if (
                self._detailed_function_count + 1 > MAXIMUM_DETAILED_FUNCTION_COUNT
                or self._detailed_function_bytes + function_bytes
                > MAXIMUM_DETAILED_FUNCTION_BYTES
                or self._detailed_instruction_count + instruction_count
                > MAXIMUM_DETAILED_INSTRUCTIONS
            ):
                self.coverage.detailed_budget_exhausted_count += 1
                self._failed_decodes.add(address)
                return []
        except (CsError, AttributeError, TypeError, ValueError, OverflowError):
            self.coverage.detailed_decode_incomplete_count += 1
            self._failed_decodes.add(address)
            return []
        instructions = [
            instruction
            for index in sorted(members)
            for instruction in fragments[index]
        ]
        self._detailed_function_count += 1
        self._detailed_function_bytes += function_bytes
        self._detailed_instruction_count += instruction_count
        canonical_address = self.function_ranges[seed].start
        self._cache[canonical_address] = instructions
        for index in members:
            self._range_owner[index] = canonical_address
        return instructions

    def decode_leaf_setter(self, address: int) -> list[object]:
        """pdata外の分岐なしleaf setterだけを、ret終端まで有界decodeする。"""

        cached = self._leaf_cache.get(address)
        if cached is not None:
            return cached
        if address in self._failed_leaf_decodes or self._range_index(address) is not None:
            return []
        section = _section_for_address(self.sections, address, executable=True)
        if section is None:
            self._failed_leaf_decodes.add(address)
            return []
        available = min(
            MAXIMUM_LEAF_FUNCTION_BYTES,
            section.address + section.size - address,
        )
        if available <= 0:
            self._failed_leaf_decodes.add(address)
            return []
        offset = section.offset(address)
        raw = self.data[offset : offset + available]
        # x64 unwind metadataを持たないleaf setterは短いret終端でなければならない。
        # byte prefilterで無関係なvtable候補へのCapstone decodeを避ける。
        if b"\xc3" not in raw:
            self._failed_leaf_decodes.add(address)
            return []
        if (
            self._leaf_attempt_count + 1 > MAXIMUM_DETAILED_LEAF_ATTEMPTS
            or self._leaf_attempt_bytes + available > MAXIMUM_DETAILED_LEAF_BYTES
        ):
            self.coverage.detailed_budget_exhausted_count += 1
            self._failed_leaf_decodes.add(address)
            return []
        self._leaf_attempt_count += 1
        self._leaf_attempt_bytes += available
        try:
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
            disassembler.detail = True
            instructions: list[object] = []
            expected = address
            while expected < address + available:
                instruction = _mapped_x64_instruction(
                    self.data,
                    self.sections,
                    disassembler,
                    expected,
                )
                if (
                    instruction is None
                    or instruction.address != expected
                    or instruction.size <= 0
                    or instruction.address + instruction.size > address + available
                ):
                    self._failed_leaf_decodes.add(address)
                    return []
                instructions.append(instruction)
                expected = instruction.address + instruction.size
                self._leaf_attempt_instructions += 1
                if (
                    len(instructions) > MAXIMUM_LEAF_FUNCTION_INSTRUCTIONS
                    or self._leaf_attempt_instructions
                    > MAXIMUM_DETAILED_LEAF_INSTRUCTIONS
                ):
                    self.coverage.detailed_budget_exhausted_count += 1
                    self._failed_leaf_decodes.add(address)
                    return []
                if instruction.group(CS_GRP_RET):
                    break
                if (
                    instruction.group(CS_GRP_JUMP)
                    or instruction.mnemonic.casefold()
                    not in {"endbr64", "lea", "mov", "nop"}
                ):
                    self._failed_leaf_decodes.add(address)
                    return []
        except (CsError, AttributeError, TypeError, ValueError, OverflowError):
            self._failed_leaf_decodes.add(address)
            return []
        if (
            not instructions
            or not instructions[-1].group(CS_GRP_RET)
        ):
            self._failed_leaf_decodes.add(address)
            return []
        semantic = [
            instruction
            for instruction in instructions[:-1]
            if instruction.mnemonic.casefold() not in {"endbr64", "nop"}
        ]
        if len(semantic) != 1 or _setter_displacement(semantic) is None:
            self._failed_leaf_decodes.add(address)
            return []
        instruction_count = len(instructions)
        decoded_bytes = expected - address
        if (
            self._detailed_function_count + 1 > MAXIMUM_DETAILED_FUNCTION_COUNT
            or self._detailed_function_bytes + decoded_bytes
            > MAXIMUM_DETAILED_FUNCTION_BYTES
            or self._detailed_instruction_count + instruction_count
            > MAXIMUM_DETAILED_INSTRUCTIONS
        ):
            self.coverage.detailed_budget_exhausted_count += 1
            self._failed_leaf_decodes.add(address)
            return []
        self._detailed_function_count += 1
        self._detailed_function_bytes += decoded_bytes
        self._detailed_instruction_count += instruction_count
        self._leaf_cache[address] = instructions
        return instructions


def _function_range_index(
    function_ranges: tuple[_FunctionRange, ...],
    range_starts: tuple[int, ...],
    address: int,
) -> int | None:
    """addressを含むpdata rangeを副作用なしで二分探索する。"""

    lower = 0
    upper = len(range_starts)
    while lower < upper:
        middle = (lower + upper) // 2
        if range_starts[middle] <= address:
            lower = middle + 1
        else:
            upper = middle
    index = lower - 1
    if index < 0:
        return None
    function = function_ranges[index]
    return index if function.start <= address < function.end else None


def _direct_tail_thunk_target(analyzer: _Analyzer, address: int) -> int | None:
    """pdata外の単一5-byte direct JMP thunkだけを有界に復号する。"""

    cached = analyzer._tail_thunk_cache.get(address)
    if cached is not None:
        return cached
    range_index = _function_range_index(
        analyzer.function_ranges,
        analyzer._range_starts,
        address,
    )
    if address in analyzer._failed_tail_thunks or range_index is not None:
        return None
    analyzer._failed_tail_thunks.add(address)
    section = _section_for_address(analyzer.sections, address, executable=True)
    if section is None or not _section_contains(section, address, 5):
        return None
    if (
        analyzer._leaf_attempt_count + 1 > MAXIMUM_DETAILED_LEAF_ATTEMPTS
        or analyzer._leaf_attempt_bytes + 5 > MAXIMUM_DETAILED_LEAF_BYTES
        or analyzer._leaf_attempt_instructions + 1
        > MAXIMUM_DETAILED_LEAF_INSTRUCTIONS
        or analyzer._detailed_function_count + 1 > MAXIMUM_DETAILED_FUNCTION_COUNT
        or analyzer._detailed_function_bytes + 5 > MAXIMUM_DETAILED_FUNCTION_BYTES
        or analyzer._detailed_instruction_count + 1 > MAXIMUM_DETAILED_INSTRUCTIONS
    ):
        analyzer.coverage.detailed_budget_exhausted_count += 1
        return None
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
        instruction = _mapped_x64_instruction(
            analyzer.data,
            analyzer.sections,
            disassembler,
            address,
        )
    except (CsError, AttributeError, TypeError, ValueError, OverflowError):
        return None
    if (
        instruction is None
        or instruction.address != address
        or instruction.size != 5
        or instruction.mnemonic.casefold() not in {"jmp", "ljmp"}
        or len(instruction.operands) != 1
    ):
        return None
    target = _immediate(instruction.operands[0])
    if (
        target is None
        or target == address
        or _section_for_address(analyzer.sections, target, executable=True) is None
    ):
        return None
    analyzer._leaf_attempt_count += 1
    analyzer._leaf_attempt_bytes += 5
    analyzer._leaf_attempt_instructions += 1
    analyzer._detailed_function_count += 1
    analyzer._detailed_function_bytes += 5
    analyzer._detailed_instruction_count += 1
    analyzer._failed_tail_thunks -= {address}
    analyzer._tail_thunk_cache[address] = target
    return target


def _wide_strings(
    data: bytes, sections: tuple[_Section, ...]
) -> tuple[_WideString, ...] | None:
    result: list[_WideString] = []
    for section in sections:
        if section.executable:
            continue
        raw = data[section.raw_start : section.raw_end]
        for match in _WIDE.finditer(raw):
            if len(result) >= MAXIMUM_WIDE_STRINGS:
                return None
            try:
                value = match.group()[:-2].decode("utf-16le", errors="strict")
            except UnicodeError:
                continue
            result.append(_WideString(section.address + match.start(), value))
    return tuple(sorted(result, key=lambda item: item.address))


def _host(value: str) -> tuple[str, bool] | None:
    candidate = value.strip().rstrip(".").casefold()
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        if _DOMAIN.fullmatch(candidate) is None:
            return None
        return candidate, False
    if parsed.is_unspecified or parsed.is_multicast:
        return None
    return parsed.compressed, parsed.is_loopback


def _port(value: str) -> int | None:
    return int(value) if value.isdigit() and 1 <= int(value) <= 65535 else None


def _config_clusters(strings: tuple[_WideString, ...]) -> tuple[_ConfigCluster, ...]:
    candidates: dict[tuple[tuple[str, int, bool], ...], _ConfigCluster] = {}
    for index in range(max(0, len(strings) - 5)):
        window = strings[index : index + 6]
        if len(window) != 6:
            continue
        if any(
            next_item.address - item.address > 96
            for item, next_item in pairwise(window)
        ):
            continue
        slots: list[_ConfigSlot] = []
        valid = True
        for offset in range(0, 6, 2):
            port = _port(window[offset].value)
            host = _host(window[offset + 1].value)
            if port is None or host is None:
                valid = False
                break
            normalized_host, loopback = host
            slots.append(
                _ConfigSlot(
                    host=normalized_host,
                    port=port,
                    host_address=window[offset + 1].address,
                    port_address=window[offset].address,
                    loopback=loopback,
                )
            )
        if not valid:
            continue
        external = [slot for slot in slots if not slot.loopback]
        loopbacks = [slot for slot in slots if slot.loopback]
        if len(external) != 2 or len(loopbacks) != 1:
            continue
        identity = tuple((slot.host, slot.port, slot.loopback) for slot in slots)
        if identity not in candidates:
            candidates[identity] = _ConfigCluster(
                slots=tuple(slots),
                addresses=tuple(item.address for item in window),
            )
        if len(candidates) > MAXIMUM_CONFIG_CLUSTERS:
            return ()
    return tuple(candidates.values())


def _socket_store_displacement(
    instructions: list[object], call_index: int
) -> _SocketLocation | None:
    graph = _instruction_graph(instructions)
    if not graph.successors or not 0 <= call_index < len(instructions):
        return None
    pending = [(index, 1) for index in graph.successors[call_index]]
    visited: set[int] = set()
    locations: set[_SocketLocation] = set()
    while pending:
        index, depth = pending.pop()
        if index in visited:
            continue
        visited.add(index)
        if depth > 16 or len(visited) > MAXIMUM_REACHING_VALUE_NODES:
            return None
        instruction = instructions[index]
        operands = instruction.operands
        if instruction.mnemonic == "mov" and len(operands) == 2:
            destination, source = operands
            if (
                destination.type == X86_OP_MEM
                and destination.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
                and destination.mem.index == X86_REG_INVALID
                and source.type == X86_OP_REG
                and _register_family(instruction, source.reg) == "rax"
                and 0 < destination.mem.disp <= 0x800
            ):
                base_family = _general_register_family(
                    instruction,
                    destination.mem.base,
                )
                origin = _register_origin(
                    instructions,
                    graph,
                    index,
                    base_family,
                )
                if origin == "entry:rcx":
                    locations.add(
                        _SocketLocation(
                            destination.mem.disp,
                            origin,
                            instruction.address,
                        )
                    )
                continue
        if instruction.mnemonic == "call" or "rax" in _written_register_families(
            instruction
        ):
            continue
        pending.extend((successor, depth + 1) for successor in graph.successors[index])
    return next(iter(locations)) if len(locations) == 1 else None


def _call_uses_socket(
    instructions: list[object], call_index: int, location: _SocketLocation
) -> bool:
    graph = _instruction_graph(instructions)
    if not graph.predecessors or not 0 <= call_index < len(instructions):
        return False
    pending = list(graph.predecessors[call_index])
    if not pending:
        return False
    visited: set[int] = set()
    facts: set[tuple[int, str] | None] = set()
    load_indices: set[int] = set()
    while pending:
        index = pending.pop()
        if index in visited:
            continue
        visited.add(index)
        if len(visited) > MAXIMUM_REACHING_VALUE_NODES:
            return False
        instruction = instructions[index]
        if "rcx" in _written_register_families(instruction):
            operands = instruction.operands
            fact: tuple[int, str] | None = None
            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and _register_family(instruction, operands[0].reg) == "rcx"
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.base not in {X86_REG_INVALID, X86_REG_RIP}
                and operands[1].mem.index == X86_REG_INVALID
            ):
                base_family = _general_register_family(
                    instruction,
                    operands[1].mem.base,
                )
                origin = _register_origin(
                    instructions,
                    graph,
                    index,
                    base_family,
                )
                if origin is not None:
                    fact = (operands[1].mem.disp, origin)
                    load_indices.add(index)
            facts.add(fact)
            continue
        if instruction.mnemonic == "call":
            facts.add(None)
            continue
        incoming = graph.predecessors[index]
        if incoming:
            pending.extend(incoming)
        else:
            facts.add(None)
    expected = (location.displacement, location.object_origin)
    if facts != {expected}:
        return False
    address_to_index = {
        instruction.address: index for index, instruction in enumerate(instructions)
    }
    store_index = address_to_index.get(location.store_address)
    return store_index is None or all(
        _is_reachable(graph, store_index, load_index)
        and _dominates(graph, store_index, load_index)
        for load_index in load_indices
    )


def _marker(instructions: list[object]) -> tuple[int, int] | None:
    for instruction in instructions:
        operands = instruction.operands
        if instruction.mnemonic != "mov" or len(operands) != 2:
            continue
        destination, source = operands
        value = _immediate(source)
        if (
            destination.type == X86_OP_MEM
            and destination.size == 2
            and destination.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
            and destination.mem.index == X86_REG_INVALID
            and value is not None
            and value & 0xFF == 0xCA
            and 8 <= destination.mem.disp <= 0x200
        ):
            return destination.mem.disp, value & 0xFFFF
    return None


def _setter_displacement(instructions: list[object]) -> int | None:
    semantic = [
        instruction
        for instruction in instructions
        if instruction.mnemonic.casefold()
        not in {"endbr64", "int3", "nop", "ret", "retn"}
    ]
    if len(semantic) != 1:
        return None
    instruction = semantic[0]
    operands = instruction.operands
    if instruction.mnemonic != "mov" or len(operands) != 2:
        return None
    destination, source = operands
    if (
        destination.type == X86_OP_MEM
        and destination.mem.base == X86_REG_RCX
        and destination.mem.index == X86_REG_INVALID
        and 0 < destination.mem.disp <= 0x200
        and source.type == X86_OP_REG
        and _register_family(instruction, source.reg) == "rdx"
    ):
        return destination.mem.disp
    return None


def _references_address(instructions: list[object], address: int, image_base: int) -> bool:
    rva = address - image_base
    for instruction in instructions:
        for operand in instruction.operands:
            if _immediate(operand) == address or _rip_target(instruction, operand) == address:
                return True
            if (
                operand.type == X86_OP_MEM
                and operand.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
                and operand.mem.disp == rva
            ):
                return True
    return False


def _parser_frame_proof(
    instructions: list[object],
    *,
    marker_displacement: int,
    callback_displacement: int,
) -> bool:
    """14 byte headerの照合とcallback転送が同じobjectに属することを確認する。"""

    if marker_displacement < 8:
        return False
    graph = _instruction_graph(instructions)
    vcall_zero = {
        index for index, slot in _vcall_slots(instructions) if slot == 0
    }
    for index, instruction in enumerate(instructions):
        if (
            instruction.mnemonic != "lea"
            or len(instruction.operands) < 2
            or instruction.operands[0].type != X86_OP_REG
            or instruction.operands[1].type != X86_OP_MEM
        ):
            continue
        destination = instruction.operands[0].reg
        source = instruction.operands[1].mem
        if (
            source.base in {X86_REG_INVALID, X86_REG_RIP}
            or source.disp != marker_displacement - 8
        ):
            continue
        destination_family = _general_register_family(instruction, destination)
        source_family = _general_register_family(instruction, source.base)
        pending: list[
            tuple[
                int,
                int,
                frozenset[int],
                tuple[tuple[str, int], ...],
                bool,
                bool,
                bool,
                bool,
                bool,
            ]
        ] = [
            (
                successor,
                1,
                frozenset(),
                (),
                False,
                False,
                False,
                True,
                True,
            )
            for successor in graph.successors[index]
        ]
        visited: set[tuple[object, ...]] = set()
        while pending:
            (
                candidate_index,
                depth,
                header_offsets,
                encoded_buffer_offsets,
                callback_on_same_object,
                vcall_on_path,
                header_size_on_path,
                destination_live,
                source_live,
            ) = pending.pop()
            if depth > 96 or len(visited) >= MAXIMUM_GRAPH_PATH_STATES:
                continue
            state_key = (
                candidate_index,
                header_offsets,
                encoded_buffer_offsets,
                callback_on_same_object,
                vcall_on_path,
                header_size_on_path,
                destination_live,
                source_live,
            )
            if state_key in visited:
                continue
            visited.add(state_key)
            candidate = instructions[candidate_index]
            next_header_offsets = set(header_offsets)
            buffer_offsets = dict(encoded_buffer_offsets)
            next_callback = callback_on_same_object
            for operand in candidate.operands:
                if operand.type != X86_OP_MEM:
                    continue
                memory = operand.mem
                if memory.base in {X86_REG_INVALID, X86_REG_RIP}:
                    continue
                memory_family = _general_register_family(candidate, memory.base)
                if (
                    destination_live
                    and memory_family == destination_family
                    and memory.disp in {0, 8}
                ):
                    next_header_offsets.add(memory.disp)
                if memory.disp in {4, 0xC}:
                    mask = buffer_offsets.get(memory_family, 0)
                    buffer_offsets[memory_family] = mask | (
                        1 if memory.disp == 4 else 2
                    )
                if (
                    source_live
                    and memory_family == source_family
                    and memory.disp == callback_displacement
                ):
                    next_callback = True
            next_vcall = vcall_on_path or candidate_index in vcall_zero
            next_header_size = header_size_on_path or any(
                _immediate(operand) == 0xE for operand in candidate.operands
            )
            if (
                {0, 8}.issubset(next_header_offsets)
                and any(mask == 3 for mask in buffer_offsets.values())
                and next_callback
                and next_vcall
                and next_header_size
            ):
                return True
            written = _written_general_register_families(candidate)
            next_destination_live = destination_live and destination_family not in written
            next_source_live = source_live and source_family not in written
            if candidate.mnemonic == "call":
                if destination_family in _VOLATILE_REGISTER_FAMILIES:
                    next_destination_live = False
                if source_family in _VOLATILE_REGISTER_FAMILIES:
                    next_source_live = False
                for family in _VOLATILE_REGISTER_FAMILIES:
                    buffer_offsets.pop(family, None)
            for family in written:
                buffer_offsets.pop(family, None)
            encoded_next_offsets = tuple(sorted(buffer_offsets.items()))
            pending.extend(
                (
                    successor,
                    depth + 1,
                    frozenset(next_header_offsets),
                    encoded_next_offsets,
                    next_callback,
                    next_vcall,
                    next_header_size,
                    next_destination_live,
                    next_source_live,
                )
                for successor in graph.successors[candidate_index]
            )
    return False


def _send_frame_path_proof(
    instructions: list[object],
    call_index: int,
    *,
    marker_displacement: int,
    coverage: _DecodeCoverage | None = None,
) -> bool:
    """send callへ至る単一CFG path上でframe構築証拠が揃うことを確認する。"""

    if marker_displacement < 8 or not 0 <= call_index < len(instructions):
        return False
    graph = _instruction_graph(instructions)
    if not graph.successors:
        return False
    marker_header = marker_displacement - 8
    required = 0b111
    pending: list[tuple[int, int]] = [(0, 0)]
    visited: set[tuple[int, int]] = set()
    while pending:
        index, mask = pending.pop()
        state = (index, mask)
        if state in visited:
            continue
        visited.add(state)
        if len(visited) > MAXIMUM_GRAPH_PATH_STATES:
            if coverage is not None:
                coverage.detailed_decode_incomplete_count += 1
            return False
        if index == call_index:
            if mask == required:
                return True
            continue
        instruction = instructions[index]
        next_mask = mask
        if any(
            operand.type == X86_OP_MEM
            and operand.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
            and operand.mem.index == X86_REG_INVALID
            and operand.mem.disp == marker_header
            for operand in instruction.operands
        ):
            next_mask |= 0b001
        if any(
            (
                operand.type == X86_OP_MEM
                and operand.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
                and operand.mem.index == X86_REG_INVALID
                and operand.mem.disp == 0xE
            )
            or _immediate(operand) == 0xE
            for operand in instruction.operands
        ):
            next_mask |= 0b010
        if any(_immediate(operand) == 0xA for operand in instruction.operands):
            next_mask |= 0b100
        pending.extend(
            (successor, next_mask) for successor in graph.successors[index]
        )
    return False


def _thread_entry_roots(
    analyzer: _Analyzer,
    instructions: list[object],
) -> list[int] | None:
    """thread helperのR8へ渡すRIP-relative pdata rootだけを列挙する。"""

    roots: list[int] = []
    for instruction in instructions:
        operands = instruction.operands
        if (
            instruction.mnemonic != "lea"
            or len(operands) != 2
            or operands[0].type != X86_OP_REG
            or _register_family(instruction, operands[0].reg) != "r8"
        ):
            continue
        target = _rip_target(instruction, operands[1])
        if target not in analyzer._ranges or target in roots:
            continue
        roots.append(target)
        if len(roots) > MAXIMUM_CONNECT_REFERENCED_ROOTS:
            analyzer.coverage.detailed_budget_exhausted_count += 1
            return None
    return roots


def _transport(analyzer: _Analyzer) -> tuple[_Transport | None, int]:
    candidates: list[_Transport] = []
    vtable_candidates = 0
    scan_sections = tuple(
        section
        for section in analyzer.sections
        if not section.executable and not section.writable and section.size >= 48
    )
    if sum(section.size for section in scan_sections) > MAXIMUM_TRANSPORT_SCAN_BYTES:
        analyzer.coverage.transport_scan_budget_exhausted_count += 1
        return None, 0
    executable_sections = tuple(
        section for section in analyzer.sections if section.executable
    )
    scanned_windows = 0
    pointer_lookups = 0
    for section in scan_sections:
        for address in range(section.address, section.address + section.size - 47, 8):
            scanned_windows += 1
            pointer_lookups += 6
            if (
                scanned_windows > MAXIMUM_TRANSPORT_SCAN_WINDOWS
                or pointer_lookups > MAXIMUM_TRANSPORT_POINTER_LOOKUPS
            ):
                analyzer.coverage.transport_scan_budget_exhausted_count += 1
                return None, vtable_candidates
            raw_offset = section.raw_start + address - section.address
            entries = struct.unpack_from("<6Q", analyzer.data, raw_offset)
            if not all(
                type(entry) is int
                and any(
                    _section_contains(executable_section, entry)
                    for executable_section in executable_sections
                )
                for entry in entries
            ):
                continue
            vtable_candidates += 1
            if vtable_candidates > MAXIMUM_VTABLE_CANDIDATES:
                analyzer.coverage.transport_scan_budget_exhausted_count += 1
                return None, vtable_candidates
            assert all(isinstance(entry, int) for entry in entries)
            _close, _status, send_method, setter, connect_method, _wait = entries
            send = analyzer.decode(send_method)
            connect = analyzer.decode(connect_method)
            setter_instructions = analyzer.decode(setter)
            connect_calls = _api_calls(connect, analyzer.imports)
            send_calls = _api_calls(send, analyzer.imports)
            connect_names = {name for _index, name in connect_calls}
            if not {"socket", "connect"}.issubset(connect_names):
                continue
            socket_calls = [index for index, name in connect_calls if name == "socket"]
            connect_api_calls = [index for index, name in connect_calls if name == "connect"]
            if len(socket_calls) != 1 or len(connect_api_calls) != 1:
                continue
            socket_location = _socket_store_displacement(connect, socket_calls[0])
            if (
                socket_location is None
                or not _call_uses_socket(
                    connect, connect_api_calls[0], socket_location
                )
            ):
                continue
            marker = _marker(connect)
            callback_displacement = _setter_displacement(setter_instructions)
            if marker is None or callback_displacement is None:
                continue
            marker_displacement, marker_value = marker
            send_api_calls = [index for index, name in send_calls if name == "send"]
            if (
                not send_api_calls
                or not any(
                    _call_uses_socket(send, call_index, socket_location)
                    and _send_frame_path_proof(
                        send,
                        call_index,
                        marker_displacement=marker_displacement,
                        coverage=analyzer.coverage,
                    )
                    for call_index in send_api_calls
                )
            ):
                continue
            # connect methodがthread entryとして直接参照するpdata rootを先にdecodeする。
            # rootから明示branchで到達するfragmentを同じlogical functionへ統合することで、
            # fragment側のsummaryだけをreceive workerと誤って先取りしない。
            referenced_roots = _thread_entry_roots(analyzer, connect)
            if referenced_roots is None:
                return None, vtable_candidates
            summarized_receive = [
                candidate
                for candidate, summary in analyzer.summaries.items()
                if "recv" in summary.api_names and candidate not in referenced_roots
            ]
            worker_starts = referenced_roots + summarized_receive
            receive_worker = 0
            frame_parser = 0
            for worker_start in worker_starts:
                worker = analyzer.decode(worker_start)
                receive_calls = [
                    index
                    for index, name in _api_calls(worker, analyzer.imports)
                    if name == "recv"
                ]
                if not receive_calls or not any(
                    _call_uses_socket(worker, call_index, socket_location)
                    for call_index in receive_calls
                ):
                    continue
                for _call_index, parser_start in _direct_targets(
                    worker, analyzer.sections, analyzer.coverage
                ):
                    parser = analyzer.decode(parser_start)
                    if _parser_frame_proof(
                        parser,
                        marker_displacement=marker_displacement,
                        callback_displacement=callback_displacement,
                    ):
                        receive_worker = worker_start
                        frame_parser = parser_start
                        break
                if receive_worker:
                    break
            if not receive_worker or not _references_address(
                connect,
                receive_worker,
                analyzer.image.OPTIONAL_HEADER.ImageBase,
            ):
                continue
            keepalive_worker = 0
            for candidate in referenced_roots:
                if candidate == receive_worker:
                    continue
                keepalive = analyzer.decode(candidate)
                if (
                    all(
                        _has_immediate(keepalive, value)
                        for value in (0xC9, 0xA, 0x3E8, 0xEA60)
                    )
                    and any(
                        slot == 0x10
                        for _index, slot in _vcall_slots(keepalive)
                    )
                ):
                    keepalive_worker = candidate
                    break
            for candidate, candidate_summary in analyzer.summaries.items():
                if keepalive_worker:
                    break
                if candidate == receive_worker or not _references_address(
                    connect,
                    candidate,
                    analyzer.image.OPTIONAL_HEADER.ImageBase,
                ):
                    continue
                if not {0xC9, 0xA, 0x3E8, 0xEA60}.issubset(
                    candidate_summary.immediates
                ) or 0x10 not in candidate_summary.vcall_slots:
                    continue
                keepalive = analyzer.decode(candidate)
                if (
                    all(_has_immediate(keepalive, value) for value in (0xC9, 0xA, 0x3E8, 0xEA60))
                    and any(slot == 0x10 for _index, slot in _vcall_slots(keepalive))
                ):
                    keepalive_worker = candidate
                    break
            constructors = []
            for candidate, candidate_summary in analyzer.summaries.items():
                if (
                    "WSAStartup" not in candidate_summary.api_names
                    or (
                        address not in candidate_summary.rip_targets
                        and address - analyzer.image.OPTIONAL_HEADER.ImageBase
                        not in candidate_summary.memory_displacements
                    )
                ):
                    continue
                instructions = analyzer.decode(candidate)
                names = {name for _index, name in _api_calls(instructions, analyzer.imports)}
                if "WSAStartup" in names and _references_address(
                    instructions,
                    address,
                    analyzer.image.OPTIONAL_HEADER.ImageBase,
                ):
                    constructors.append(candidate)
            if len(constructors) != 1 or not keepalive_worker:
                continue
            candidates.append(
                _Transport(
                    vtable=address,
                    constructor=constructors[0],
                    send_method=send_method,
                    callback_setter=setter,
                    connect_method=connect_method,
                    receive_worker=receive_worker,
                    frame_parser=frame_parser,
                    keepalive_worker=keepalive_worker,
                    socket_displacement=socket_location.displacement,
                    marker_displacement=marker_displacement,
                    marker_value=marker_value,
                    callback_displacement=callback_displacement,
                )
            )
    unique = {candidate.vtable: candidate for candidate in candidates}
    return (next(iter(unique.values())), vtable_candidates) if len(unique) == 1 else (None, vtable_candidates)


_DISPATCH_GROUPS = {
    "process": {"CreateProcessW", "TerminateProcess", "Process32FirstW", "Process32NextW"},
    "file": {"CreateFileW", "WriteFile"},
    "registry": {"RegCreateKeyW", "RegDeleteValueW", "RegSetValueExW"},
    "event_log": {"OpenEventLogW", "ClearEventLogW"},
}

_REGISTRATION_GROUPS = {
    "network_identity": {"gethostname", "gethostbyname"},
    "system": {"GetSystemInfo", "GetCurrentHwProfileW"},
    "memory": {"GlobalMemoryStatusEx"},
    "drive": {"GetDriveTypeW", "GetLogicalDriveStringsW", "GetDiskFreeSpaceExW"},
    "interactive": {"GetForegroundWindow", "GetWindowTextW", "GetLastInputInfo"},
}


def _api_group_count(names: set[str], groups: dict[str, set[str]]) -> int:
    return sum(bool(names & members) for members in groups.values())


def _dispatcher_shape(analyzer: _Analyzer, address: int) -> tuple[bool, int]:
    instructions = analyzer.decode(address)
    names = {name for _index, name in _api_calls(instructions, analyzer.imports)}
    groups = _api_group_count(names, _DISPATCH_GROUPS)
    bounded = any(
        instruction.mnemonic == "cmp"
        and any(_immediate(operand) == 0xCA for operand in instruction.operands)
        for instruction in instructions
    )
    indexed_jump = any(
        instruction.mnemonic == "jmp"
        and any(
            operand.type == X86_OP_REG
            or (
                operand.type == X86_OP_MEM
                and operand.mem.index != X86_REG_INVALID
                and operand.mem.scale in {4, 8}
            )
            for operand in instruction.operands
        )
        for instruction in instructions
    )
    return (
        bounded
        and indexed_jump
        and groups >= 3
        and any(slot == 0x10 for _index, slot in _vcall_slots(instructions)),
        groups,
    )


def _stack_local_store(instruction: object) -> tuple[tuple[str, int], str] | None:
    """8 byte pointerをframe localへ保存する単純storeだけを返す。"""

    operands = instruction.operands
    if (
        instruction.mnemonic != "mov"
        or len(operands) != 2
        or operands[0].type != X86_OP_MEM
        or operands[0].size != 8
        or operands[1].type != X86_OP_REG
    ):
        return None
    destination = operands[0]
    if (
        destination.mem.base in {X86_REG_INVALID, X86_REG_RIP}
        or destination.mem.index != X86_REG_INVALID
        or abs(destination.mem.disp) > 0x4000
    ):
        return None
    base_family = _general_register_family(instruction, destination.mem.base)
    source_family = _general_register_family(instruction, operands[1].reg)
    if base_family not in {"rbp", "rsp"} or source_family not in (
        _GENERAL_REGISTER_FAMILIES
    ):
        return None
    return (base_family, destination.mem.disp), source_family


def _stack_slot_is_clean_between(
    instructions: list[object],
    graph: _InstructionGraph,
    store_index: int,
    consumer_index: int,
    slot: tuple[str, int],
) -> bool:
    """storeからconsumerまでlocal slotとframe baseが不変の場合だけ真にする。"""

    if not graph.successors or not graph.predecessors:
        return False
    pending = [consumer_index]
    ancestors: set[int] = set()
    while pending:
        index = pending.pop()
        if index in ancestors:
            continue
        ancestors.add(index)
        if len(ancestors) > MAXIMUM_GRAPH_PATH_STATES:
            return False
        if index != store_index:
            pending.extend(graph.predecessors[index])
    if store_index not in ancestors:
        return False
    base_family, displacement = slot
    pending = list(graph.successors[store_index])
    visited: set[int] = set()
    reaches_consumer = False
    while pending:
        index = pending.pop()
        if index not in ancestors or index in visited:
            continue
        if index == consumer_index:
            reaches_consumer = True
            continue
        visited.add(index)
        if len(visited) > MAXIMUM_GRAPH_PATH_STATES:
            return False
        instruction = instructions[index]
        if base_family in _written_general_register_families(instruction):
            return False
        for operand in instruction.operands:
            if (
                operand.type == X86_OP_MEM
                and operand.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
                and operand.mem.index == X86_REG_INVALID
                and _general_register_family(instruction, operand.mem.base)
                == base_family
                and operand.mem.disp == displacement
                and instruction.mnemonic != "lea"
            ):
                return False
        pending.extend(graph.successors[index])
    return reaches_consumer


def _unique_reachable_return_sink(
    instructions: list[object],
    graph: _InstructionGraph,
    return_index: int,
) -> bool:
    """loopを許しつつ全命令が到達し、唯一のsinkがRETであることを確認する。"""

    if (
        not instructions
        or not graph.successors
        or not 0 <= return_index < len(instructions)
        or graph.successors[return_index]
    ):
        return False
    pending = [0]
    reachable: set[int] = set()
    while pending:
        index = pending.pop()
        if index in reachable:
            continue
        reachable.add(index)
        if len(reachable) > MAXIMUM_GRAPH_PATH_STATES:
            return False
        pending.extend(graph.successors[index])
    sinks = {index for index in reachable if not graph.successors[index]}
    return reachable == set(range(len(instructions))) and sinks == {return_index}


def _register_written_on_all_paths(
    instructions: list[object],
    graph: _InstructionGraph,
    target_index: int,
    family: str,
) -> bool:
    """entryからtargetまでの全CFG pathでGPRが定義済みかmust解析する。"""

    if (
        not instructions
        or not graph.predecessors
        or not 0 <= target_index < len(instructions)
    ):
        return False
    incoming = [True] * len(instructions)
    outgoing = [True] * len(instructions)
    incoming[0] = False
    outgoing[0] = family in _written_general_register_families(instructions[0])
    changed = True
    passes = 0
    while changed:
        changed = False
        passes += 1
        if passes > len(instructions) + 1:
            return False
        for index, instruction in enumerate(instructions):
            value = (
                False
                if index == 0 or not graph.predecessors[index]
                else all(outgoing[item] for item in graph.predecessors[index])
            )
            result = value or family in _written_general_register_families(instruction)
            if incoming[index] != value or outgoing[index] != result:
                incoming[index] = value
                outgoing[index] = result
                changed = True
    return incoming[target_index] or family in _written_general_register_families(
        instructions[target_index]
    )


def _control_calls_are_accounted(
    instructions: list[object],
    direct_calls: list[tuple[int, int]],
    api_calls: list[tuple[int, str]],
) -> bool:
    """全CALLがdirect executable targetか既知IAT APIとして解決済みかを確認する。"""

    accounted = {index for index, _value in direct_calls}
    accounted.update(index for index, _value in api_calls)
    return all(
        instruction.mnemonic != "call" or index in accounted
        for index, instruction in enumerate(instructions)
    )


def _has_unresolved_jump(instructions: list[object]) -> bool:
    return any(
        instruction.group(CS_GRP_JUMP)
        and not any(_immediate(operand) is not None for operand in instruction.operands)
        for instruction in instructions
    )


def _has_nonstack_memory_write(instructions: list[object]) -> bool:
    """明示memory writeがstack外へ向く場合だけ真にする。"""

    for instruction in instructions:
        for operand in instruction.operands:
            if operand.type != X86_OP_MEM or not operand.access & CS_AC_WRITE:
                continue
            base = _general_register_family(instruction, operand.mem.base)
            if base not in {"rsp", "rbp"}:
                return True
    return False


def _error_mapping_helper_shape(analyzer: _Analyzer, address: int) -> bool:
    """GetLastError値を副作用なしでerrno値へ写像する有界helperを検証する。"""

    instructions = analyzer.decode(address)
    if not 1 <= len(instructions) <= 128:
        return False
    graph = _instruction_graph(instructions)
    returns = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.group(CS_GRP_RET)
    ]
    api_calls = _api_calls(instructions, analyzer.imports)
    direct_calls = _direct_targets(
        instructions,
        analyzer.sections,
        analyzer.coverage,
    )
    backward_edges = [
        (index, successor)
        for index, successors in enumerate(graph.successors)
        for successor in successors
        if successor <= index
    ]
    rip_sections: list[_Section] = []
    for instruction in instructions:
        for operand in instruction.operands:
            target = _rip_target(instruction, operand)
            if target is None:
                continue
            section = _virtual_section_for_address(analyzer.sections, target)
            if section is None:
                return False
            rip_sections.append(section)
    bounded_compare = any(
        instruction.mnemonic == "cmp"
        and any(
            isinstance(value := _immediate(operand), int) and 0 < value <= 0x100
            for operand in instruction.operands
        )
        for instruction in instructions
    )
    returns_with_rax = (
        _register_written_on_all_paths(instructions, graph, returns[0], "rax")
        if len(returns) == 1
        else False
    )
    return (
        len(returns) == 1
        and _unique_reachable_return_sink(instructions, graph, returns[0])
        and not api_calls
        and not direct_calls
        and _control_calls_are_accounted(instructions, direct_calls, api_calls)
        and not _vcall_slots(instructions)
        and not _has_unresolved_jump(instructions)
        and not _has_nonstack_memory_write(instructions)
        and bool(rip_sections)
        and all(not section.executable and not section.writable for section in rip_sections)
        and len(backward_edges) <= 4
        and all(
            instructions[index].mnemonic not in {"jmp", "ljmp"}
            for index, _successor in backward_edges
        )
        and sum(instruction.mnemonic == "cmp" for instruction in instructions) >= 2
        and any(instruction.mnemonic.startswith("cmov") for instruction in instructions)
        and bounded_compare
        and returns_with_rax
    )


def _tls_state_helper_shape(analyzer: _Analyzer, address: int) -> bool:
    """errno accessorが呼ぶ有限TLS state helperを保守的に検証する。"""

    instructions = analyzer.decode(address)
    if not 1 <= len(instructions) <= 128:
        return False
    graph = _instruction_graph(instructions)
    returns = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.group(CS_GRP_RET)
    ]
    api_calls = _api_calls(instructions, analyzer.imports)
    direct_calls = _direct_targets(
        instructions,
        analyzer.sections,
        analyzer.coverage,
    )
    return (
        len(returns) == 1
        and _all_paths_end_at_unique_return(instructions, graph, returns[0])
        and {name for _index, name in api_calls} == {"GetLastError", "SetLastError"}
        and 1 <= len(direct_calls) <= 8
        and _control_calls_are_accounted(instructions, direct_calls, api_calls)
        and not _vcall_slots(instructions)
        and not _has_unresolved_jump(instructions)
    )


def _errno_accessor_shape(analyzer: _Analyzer, address: int) -> bool:
    """TLS stateからerrno格納先pointerを返す薄いaccessorを検証する。"""

    instructions = analyzer.decode(address)
    if not 1 <= len(instructions) <= 32:
        return False
    graph = _instruction_graph(instructions)
    returns = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.group(CS_GRP_RET)
    ]
    api_calls = _api_calls(instructions, analyzer.imports)
    direct_calls = _direct_targets(
        instructions,
        analyzer.sections,
        analyzer.coverage,
    )
    if not (
        len(returns) == 1
        and _all_paths_end_at_unique_return(instructions, graph, returns[0])
        and not api_calls
        and len(direct_calls) == 1
        and _control_calls_are_accounted(instructions, direct_calls, api_calls)
        and _tls_state_helper_shape(analyzer, direct_calls[0][1])
        and not _vcall_slots(instructions)
        and not _has_unresolved_jump(instructions)
        and not _has_nonstack_memory_write(instructions)
    ):
        return False
    provider_index = direct_calls[0][0]
    if provider_index + 1 >= len(instructions):
        return False
    provider_copy = instructions[provider_index + 1]
    copy_operands = provider_copy.operands
    if (
        provider_copy.mnemonic != "mov"
        or len(copy_operands) != 2
        or copy_operands[0].type != X86_OP_REG
        or copy_operands[1].type != X86_OP_REG
        or _general_register_family(provider_copy, copy_operands[0].reg) != "rcx"
        or _general_register_family(provider_copy, copy_operands[1].reg) != "rax"
        or instructions[provider_index].address + instructions[provider_index].size
        != provider_copy.address
    ):
        return False
    fallback_records: list[tuple[int, str, int]] = []
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        if (
            instruction.mnemonic != "lea"
            or len(operands) != 2
            or operands[0].type != X86_OP_REG
        ):
            continue
        fallback = _rip_target(instruction, operands[1])
        family = _general_register_family(instruction, operands[0].reg)
        section = (
            _virtual_section_for_address(analyzer.sections, fallback)
            if fallback is not None
            else None
        )
        if section is not None and section.writable and not section.executable:
            fallback_records.append((index, family, fallback))
    add_indices = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic == "add"
        and len(instruction.operands) == 2
        and instruction.operands[0].type == X86_OP_REG
        and _general_register_family(instruction, instruction.operands[0].reg) == "rax"
        and isinstance(_immediate(instruction.operands[1]), int)
        and 0 < _immediate(instruction.operands[1]) <= 0x400
        and _immediate(instruction.operands[1]) % 4 == 0
    ]
    test_indices = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic == "test"
        and len(instruction.operands) == 2
        and all(operand.type == X86_OP_REG for operand in instruction.operands)
        and all(
            _general_register_family(instruction, operand.reg) == "rcx"
            for operand in instruction.operands
        )
    ]
    for fallback_index, fallback_family, _fallback in fallback_records:
        for add_index in add_indices:
            for test_index in test_indices:
                if not provider_index < fallback_index < add_index < test_index:
                    continue
                for cmov_index in range(test_index + 1, len(instructions)):
                    cmov = instructions[cmov_index]
                    operands = cmov.operands
                    if (
                        not cmov.mnemonic.startswith("cmov")
                        or len(operands) != 2
                        or any(operand.type != X86_OP_REG for operand in operands)
                        or _general_register_family(cmov, operands[0].reg) != "rax"
                        or _general_register_family(cmov, operands[1].reg)
                        != fallback_family
                        or not _dominates(graph, provider_index, cmov_index)
                        or not _dominates(graph, cmov_index, returns[0])
                    ):
                        continue
                    return True
    return False


def _heap_deallocator_terminal_shape(analyzer: _Analyzer, address: int) -> bool:
    """bounded thunk終端がHeapFreeへ収束する有限deallocatorかを検証する。"""

    instructions = analyzer.decode(address)
    if not instructions:
        return False
    graph = _instruction_graph(instructions)
    return_indices = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.group(CS_GRP_RET)
    ]
    if (
        len(return_indices) != 1
        or _vcall_slots(instructions)
        or not _all_paths_end_at_unique_return(
            instructions,
            graph,
            return_indices[0],
        )
    ):
        return False
    address_indices = {
        instruction.address: index
        for index, instruction in enumerate(instructions)
    }
    for instruction in instructions:
        if not instruction.group(CS_GRP_JUMP):
            continue
        target = next(
            (
                _immediate(operand)
                for operand in instruction.operands
                if _immediate(operand) is not None
            ),
            None,
        )
        if target not in address_indices:
            return False
    api_calls = _api_calls(instructions, analyzer.imports)
    heap_calls = [index for index, name in api_calls if name == "HeapFree"]
    error_calls = [index for index, name in api_calls if name == "GetLastError"]
    if (
        len(heap_calls) != 1
        or len(error_calls) > 1
        or any(name not in {"HeapFree", "GetLastError"} for _index, name in api_calls)
    ):
        return False
    heap_index = heap_calls[0]
    heap_global = _reaching_register_fact(
        instructions,
        graph,
        heap_index,
        family="rcx",
        kind="rip",
        mnemonic="mov",
        coverage=analyzer.coverage,
    )
    if (
        _register_origin(instructions, graph, heap_index, "r8") != "entry:rcx"
        or _reaching_register_fact(
            instructions,
            graph,
            heap_index,
            family="rdx",
            kind="immediate",
            coverage=analyzer.coverage,
        )
        != 0
        or not isinstance(heap_global, int)
    ):
        return False
    heap_section = _virtual_section_for_address(analyzer.sections, heap_global)
    if heap_section is None or heap_section.executable:
        return False
    return_index = return_indices[0]
    guarded = False
    for test_index, test in enumerate(instructions[:-1]):
        operands = test.operands
        if (
            test.mnemonic != "test"
            or len(operands) != 2
            or any(operand.type != X86_OP_REG for operand in operands)
            or any(
                _general_register_family(test, operand.reg) != "rcx"
                for operand in operands
            )
        ):
            continue
        branch_index = test_index + 1
        branch = instructions[branch_index]
        if (
            test.address + test.size != branch.address
            or not branch.group(CS_GRP_JUMP)
            or branch.mnemonic in {"jmp", "ljmp"}
            or len(graph.successors[branch_index]) != 2
            or not _dominates(graph, branch_index, heap_index)
            or not _dominates(graph, branch_index, return_index)
            or not _is_reachable(graph, heap_index, return_index)
        ):
            continue
        bypass = _reachable_avoiding(
            graph,
            branch_index,
            return_index,
            heap_index,
        )
        if bypass is True:
            guarded = True
            break
    if not guarded:
        return False
    direct_targets = _direct_targets(
        instructions,
        analyzer.sections,
        analyzer.coverage,
    )
    if not error_calls:
        return not direct_targets
    if len(error_calls) != 1 or len(direct_targets) != 2:
        return False
    error_index = error_calls[0]
    (mapper_index, mapper_target), (accessor_index, accessor_target) = direct_targets
    expected = (error_index + 1, error_index + 2, error_index + 3, error_index + 4)
    if (
        expected
        != (mapper_index - 1, mapper_index, accessor_index - 1, accessor_index)
        or accessor_index + 1 >= len(instructions)
    ):
        return False
    error_copy = instructions[error_index + 1]
    mapper_call = instructions[mapper_index]
    saved_copy = instructions[mapper_index + 1]
    accessor_call = instructions[accessor_index]
    error_store = instructions[accessor_index + 1]
    saved_operands = saved_copy.operands
    error_copy_operands = error_copy.operands
    store_operands = error_store.operands
    if (
        error_copy.mnemonic != "mov"
        or len(error_copy_operands) != 2
        or error_copy_operands[0].type != X86_OP_REG
        or error_copy_operands[1].type != X86_OP_REG
        or _general_register_family(error_copy, error_copy_operands[0].reg) != "rcx"
        or _general_register_family(error_copy, error_copy_operands[1].reg) != "rax"
        or saved_copy.mnemonic != "mov"
        or len(saved_operands) != 2
        or saved_operands[0].type != X86_OP_REG
        or saved_operands[1].type != X86_OP_REG
        or _general_register_family(saved_copy, saved_operands[1].reg) != "rax"
    ):
        return False
    saved_family = _general_register_family(saved_copy, saved_operands[0].reg)
    if saved_family in _VOLATILE_REGISTER_FAMILIES or saved_family in {"rsp", "rbp"}:
        return False
    if (
        error_store.mnemonic != "mov"
        or len(store_operands) != 2
        or store_operands[0].type != X86_OP_MEM
        or store_operands[0].size != 4
        or store_operands[0].mem.index != X86_REG_INVALID
        or store_operands[0].mem.disp != 0
        or _general_register_family(error_store, store_operands[0].mem.base) != "rax"
        or store_operands[1].type != X86_OP_REG
        or _general_register_family(error_store, store_operands[1].reg) != saved_family
    ):
        return False
    chain = [
        error_index,
        error_index + 1,
        mapper_index,
        mapper_index + 1,
        accessor_index,
        accessor_index + 1,
    ]
    if any(
        left.address + left.size != right.address
        for left, right in pairwise(instructions[index] for index in chain)
    ):
        return False
    if (
        graph.successors[mapper_index] != frozenset({mapper_index + 1})
        or graph.successors[accessor_index] != frozenset({accessor_index + 1})
        or not _is_reachable(graph, heap_index, error_index)
        or not _is_reachable(graph, accessor_index + 1, return_index)
        or not _dominates(graph, error_index, mapper_index)
        or not _dominates(graph, error_index, accessor_index)
        or not _dominates(graph, error_index, accessor_index + 1)
        or _reachable_avoiding(graph, heap_index, return_index, error_index) is not True
        or not _error_mapping_helper_shape(analyzer, mapper_target)
        or not _errno_accessor_shape(analyzer, accessor_target)
    ):
        return False
    return mapper_call.mnemonic == "call" and accessor_call.mnemonic == "call"


def _deallocator_helper_shape(analyzer: _Analyzer, address: int) -> bool:
    """最大4段のdirect tail thunkからHeapFree終端までを静的に結ぶ。"""

    current = address
    visited: set[int] = set()
    for hop in range(MAXIMUM_DEALLOCATOR_THUNK_HOPS + 1):
        if current in visited:
            return False
        visited.add(current)
        range_index = _function_range_index(
            analyzer.function_ranges,
            analyzer._range_starts,
            current,
        )
        if range_index is not None:
            if analyzer.function_ranges[range_index].start != current:
                return False
            return _heap_deallocator_terminal_shape(analyzer, current)
        if hop == MAXIMUM_DEALLOCATOR_THUNK_HOPS:
            return False
        target = _direct_tail_thunk_target(analyzer, current)
        if target is None:
            return False
        current = target
    return False


def _callback_destructor_shape(analyzer: _Analyzer, address: int) -> bool:
    """2-slot callback tableのdeleting destructorを厳格に検証する。"""

    instructions = analyzer.decode(address)
    if not instructions:
        return False
    api_calls = _api_calls(instructions, analyzer.imports)
    if [name for _index, name in api_calls] != ["CloseHandle"]:
        return False
    return_indices = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.group(CS_GRP_RET)
    ]
    if len(return_indices) != 1:
        return False
    if _vcall_slots(instructions):
        return False
    if any(
        instruction.group(CS_GRP_JUMP)
        and not any(_immediate(operand) is not None for operand in instruction.operands)
        for instruction in instructions
    ):
        return False
    direct_targets = _direct_targets(
        instructions,
        analyzer.sections,
        analyzer.coverage,
    )
    if len(direct_targets) != 1:
        return False
    graph = _instruction_graph(instructions)
    return_index = return_indices[0]
    if not _all_paths_end_at_unique_return(
        instructions,
        graph,
        return_index,
    ):
        return False
    helper_index, helper_target = direct_targets[0]
    if (
        _register_origin(instructions, graph, helper_index, "rcx") != "entry:rcx"
        or not _deallocator_helper_shape(analyzer, helper_target)
        or not _is_reachable(graph, helper_index, return_index)
        or len(graph.successors[helper_index]) != 1
    ):
        return False
    helper_successor = next(iter(graph.successors[helper_index]))
    if (
        helper_successor != helper_index + 1
        or instructions[helper_index].address + instructions[helper_index].size
        != instructions[helper_successor].address
    ):
        return False
    flagged_helper = False
    for index, instruction in enumerate(instructions):
        if (
            not instruction.group(CS_GRP_JUMP)
            or instruction.mnemonic in {"jmp", "ljmp"}
            or len(graph.successors[index]) != 2
            or index == 0
        ):
            continue
        previous = instructions[index - 1]
        previous_operands = previous.operands
        if (
            previous.address + previous.size != instruction.address
            or previous.mnemonic != "test"
            or len(previous_operands) != 2
            or previous_operands[0].type != X86_OP_REG
            or _immediate(previous_operands[1]) != 1
            or _register_origin(
                instructions,
                graph,
                index - 1,
                _general_register_family(previous, previous_operands[0].reg),
            )
            != "entry:rdx"
            or not _is_reachable(graph, index, helper_index)
            or not _dominates(graph, index, helper_index)
            or not _dominates(graph, index, return_index)
        ):
            continue
        bypass = _reachable_avoiding(
            graph,
            index,
            return_index,
            helper_index,
        )
        if bypass is True:
            flagged_helper = True
            break
    if not flagged_helper:
        return False
    restored_vtable = None
    for index, instruction in enumerate(instructions):
        operands = instruction.operands
        if (
            instruction.mnemonic != "mov"
            or len(operands) != 2
            or operands[0].type != X86_OP_MEM
            or operands[0].size != 8
            or operands[0].mem.index != X86_REG_INVALID
            or operands[0].mem.disp != 0
            or operands[1].type != X86_OP_REG
            or _general_register_family(instruction, operands[0].mem.base) != "rcx"
        ):
            continue
        source_family = _general_register_family(instruction, operands[1].reg)
        candidate = _reaching_register_fact(
            instructions,
            graph,
            index,
            family=source_family,
            kind="rip",
            mnemonic="lea",
            coverage=analyzer.coverage,
        )
        if isinstance(candidate, int):
            restored_vtable = candidate
            break
    if restored_vtable is None:
        return False
    restored_section = _section_for_address(analyzer.sections, restored_vtable)
    if (
        restored_section is None
        or restored_section.executable
        or restored_section.writable
    ):
        return False
    first_method = _read_u64(analyzer.data, analyzer.sections, restored_vtable)
    return first_method is not None and _section_for_address(
        analyzer.sections,
        first_method,
        executable=True,
    ) is not None


def _callback_table_handler(analyzer: _Analyzer, table: int) -> int | None:
    """2-slot callback tableと直後のRTTI COL境界を検証する。"""

    table_section = _section_for_address(analyzer.sections, table)
    if (
        table_section is None
        or table_section.executable
        or table_section.writable
        or not _section_contains(table_section, table, 24)
    ):
        return None
    handler = _read_u64(analyzer.data, analyzer.sections, table)
    destructor = _read_u64(analyzer.data, analyzer.sections, table + 8)
    col_pointer = _read_u64(analyzer.data, analyzer.sections, table + 16)
    if (
        handler is None
        or destructor is None
        or col_pointer is None
        or handler == destructor
        or _section_for_address(analyzer.sections, handler, executable=True) is None
        or _section_for_address(analyzer.sections, destructor, executable=True) is None
    ):
        return None
    col_section = _section_for_address(analyzer.sections, col_pointer)
    raw_col = _read_bytes(analyzer.data, analyzer.sections, col_pointer, 24)
    if col_section is None or col_section.executable or raw_col is None:
        return None
    signature, offset, cd_offset, type_rva, class_rva, self_rva = struct.unpack(
        "<IIIIII", raw_col
    )
    image_base = analyzer.image.OPTIONAL_HEADER.ImageBase
    if (
        signature != 1
        or offset != 0
        or cd_offset != 0
        or image_base + self_rva != col_pointer
        or _section_for_address(analyzer.sections, image_base + type_rva) is None
        or _section_for_address(analyzer.sections, image_base + class_rva) is None
        or not _callback_destructor_shape(analyzer, destructor)
    ):
        return None
    return handler


def _registration_candidates(analyzer: _Analyzer) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for address, summary in analyzer.summaries.items():
        if 0x1250 not in summary.immediates or 0x10 not in summary.vcall_slots:
            continue
        instructions = analyzer.decode(address)
        if not _has_immediate(instructions, 0x1250):
            continue
        command_six = any(
            instruction.mnemonic == "mov"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_MEM
            and instruction.operands[0].size == 1
            and _immediate(instruction.operands[1]) == 6
            for instruction in instructions[:64]
        )
        send_calls = [index for index, slot in _vcall_slots(instructions) if slot == 0x10]
        exact_size_send = any(
            _previous_immediate_assignment(
                instructions,
                index,
                family="r8",
                value=0x1250,
            )
            for index in send_calls
        )
        names = {name for _index, name in _api_calls(instructions, analyzer.imports)}
        groups = _api_group_count(names, _REGISTRATION_GROUPS)
        if command_six and exact_size_send and groups >= 4:
            result.append((address, groups))
    return result


def _previous_rip_assignment(
    instructions: list[object],
    index: int,
    *,
    register: int,
    mnemonic: str,
    maximum_scan: int = 20,
) -> int | None:
    family = _register_family(instructions[index], register)
    value = _reaching_register_fact(
        instructions,
        _instruction_graph(instructions),
        index,
        family=family,
        kind="rip",
        mnemonic=mnemonic,
        maximum_nodes=maximum_scan,
    )
    return value if isinstance(value, int) else None


def _previous_immediate_assignment(
    instructions: list[object],
    index: int,
    *,
    family: str,
    value: int,
    maximum_scan: int = 16,
) -> bool:
    """call直前のregister値をclobber境界内だけで厳格に照合する。"""

    observed = _reaching_register_fact(
        instructions,
        _instruction_graph(instructions),
        index,
        family=family,
        kind="immediate",
        maximum_nodes=maximum_scan,
    )
    return observed == value


def _copy_calls(
    instructions: list[object],
    sections: tuple[_Section, ...],
    coverage: _DecodeCoverage | None = None,
) -> list[_CopyCall]:
    graph = _instruction_graph(instructions)
    if not graph.predecessors:
        return []
    predecessors = graph.predecessors

    traversal_incomplete = False
    total_visited_nodes = 0

    def reaching_value(call_index: int, register_names: set[str]) -> int | None:
        nonlocal total_visited_nodes, traversal_incomplete
        pending = list(predecessors[call_index])
        visited: set[int] = set()
        values: set[int | None] = set()
        while (
            pending
            and len(visited) < MAXIMUM_REACHING_VALUE_NODES
            and total_visited_nodes < MAXIMUM_REACHING_VALUE_TOTAL_NODES
        ):
            index = pending.pop()
            if index in visited:
                continue
            visited.add(index)
            total_visited_nodes += 1
            instruction = instructions[index]
            written = _written_register_names(instruction)
            if written & register_names:
                value = None
                if len(instruction.operands) >= 2:
                    value = _rip_target(instruction, instruction.operands[1])
                    if value is None:
                        value = _immediate(instruction.operands[1])
                values.add(value)
                continue
            if instruction.mnemonic == "call":
                values.add(None)
                continue
            pending.extend(predecessors[index])
        if pending:
            traversal_incomplete = True
            return None
        return next(iter(values)) if len(values) == 1 and None not in values else None

    result: list[_CopyCall] = []
    for index, target in _direct_targets(instructions, sections, coverage):
        destination = reaching_value(index, {"rcx", "ecx", "cx", "cl", "ch"})
        source = reaching_value(index, {"r8", "r8d", "r8w", "r8b"})
        capacity = reaching_value(index, {"rdx", "edx", "dx", "dl", "dh"})
        if destination is not None and capacity in {0xFF, 0x1E}:
            result.append(_CopyCall(index, target, destination, source, capacity))
    if traversal_incomplete and coverage is not None:
        coverage.detailed_decode_incomplete_count += 1
    return result


def _dispatcher_from_main(
    analyzer: _Analyzer, instructions: list[object]
) -> tuple[int | None, int]:
    setters = [index for index, slot in _vcall_slots(instructions) if slot == 0x18]
    graph = _instruction_graph(instructions)
    direct_calls = dict(
        _direct_targets(instructions, analyzer.sections, analyzer.coverage)
    )
    best_groups = 0
    for setter_index in setters:
        reachable = _reachable_indices(graph, setter_index, maximum_nodes=48)
        if reachable is None:
            continue
        stores: list[tuple[int, tuple[str, int], int]] = []
        for store_index in sorted(reachable):
            store = _stack_local_store(instructions[store_index])
            if store is None:
                continue
            slot, source_family = store
            table = _reaching_register_fact(
                instructions,
                graph,
                store_index,
                family=source_family,
                kind="rip",
                mnemonic="lea",
                maximum_nodes=48,
                coverage=analyzer.coverage,
            )
            if not isinstance(table, int):
                continue
            handler = _callback_table_handler(analyzer, table)
            if handler is not None:
                stores.append((store_index, slot, handler))
        for call_index in direct_calls:
            if call_index not in reachable:
                continue
            local = _reaching_register_fact(
                instructions,
                graph,
                call_index,
                family="rcx",
                kind="local_address",
                maximum_nodes=48,
                coverage=analyzer.coverage,
            )
            if not isinstance(local, tuple):
                continue
            for store_index, slot, handler in stores:
                if local != slot or not _dominates(
                    graph,
                    store_index,
                    call_index,
                    start_index=setter_index,
                    maximum_nodes=48,
                ):
                    continue
                if not _stack_slot_is_clean_between(
                    instructions,
                    graph,
                    store_index,
                    call_index,
                    slot,
                ):
                    continue
                matched, groups = _dispatcher_shape(analyzer, handler)
                best_groups = max(best_groups, groups)
                if matched:
                    return handler, groups
    return None, best_groups


def _main_lineage(
    analyzer: _Analyzer,
    cluster: _ConfigCluster,
    transport: _Transport,
    registration: int,
) -> tuple[_MainLineage | None, int]:
    image_base = analyzer.image.OPTIONAL_HEADER.ImageBase
    best_dispatch_groups = 0
    for address, summary in analyzer.summaries.items():
        if not {registration, transport.constructor}.issubset(summary.direct_targets):
            continue
        instructions = analyzer.decode(address)
        direct_targets = _direct_targets(
            instructions,
            analyzer.sections,
            analyzer.coverage,
        )
        if registration not in {target for _index, target in direct_targets}:
            continue
        if transport.constructor not in {target for _index, target in direct_targets}:
            continue
        connect_calls = [index for index, slot in _vcall_slots(instructions) if slot == 0x20]
        setter_calls = [index for index, slot in _vcall_slots(instructions) if slot == 0x18]
        if len(connect_calls) != 1 or not setter_calls:
            continue
        connect_index = connect_calls[0]
        selected_global = _previous_rip_assignment(
            instructions, connect_index, register=X86_REG_RCX, mnemonic="mov"
        )
        runtime_host = _previous_rip_assignment(
            instructions, connect_index, register=X86_REG_RDX, mnemonic="lea"
        )
        if selected_global is None or runtime_host is None:
            continue
        runtime_port = None
        for call_index, _target in reversed(direct_targets):
            if call_index >= connect_index or connect_index - call_index > 24:
                continue
            candidate = _previous_rip_assignment(
                instructions, call_index, register=X86_REG_RCX, mnemonic="lea"
            )
            if candidate is not None:
                runtime_port = candidate
                break
        if runtime_port is None:
            continue
        registration_indices = [
            index for index, target in direct_targets if target == registration
        ]
        same_client_registration = any(
            _previous_rip_assignment(
                instructions, index, register=X86_REG_RCX, mnemonic="mov"
            )
            == selected_global
            for index in registration_indices
        )
        if not same_client_registration:
            continue
        copies = _copy_calls(instructions, analyzer.sections, analyzer.coverage)
        by_target: dict[int, list[_CopyCall]] = {}
        for copy in copies:
            records = by_target.get(copy.target)
            if records is None:
                records = []
                by_target[copy.target] = records
            records.append(copy)
        copy_contract = None
        for target, records in by_target.items():
            host_sources = {
                record.source
                for record in records
                if record.destination == runtime_host
                and record.capacity == 0xFF
                and record.source is not None
            }
            port_sources = {
                record.source
                for record in records
                if record.destination == runtime_port
                and record.capacity == 0x1E
                and record.source is not None
            }
            if (
                len(host_sources) != len(cluster.slots)
                or len(port_sources) != len(cluster.slots)
            ):
                continue
            initialized = {
                record.destination
                for record in records
                if record.destination in host_sources | port_sources
                and record.capacity
                == (0xFF if record.destination in host_sources else 0x1E)
                and record.index < connect_index
            }
            if initialized == host_sources | port_sources:
                copy_contract = (target, initialized)
                break
        if copy_contract is None:
            continue
        reference_count = sum(
            _references_address(instructions, source, image_base)
            for source in cluster.addresses
        )
        if reference_count < 5:
            continue
        dispatcher, groups = _dispatcher_from_main(analyzer, instructions)
        best_dispatch_groups = max(best_dispatch_groups, groups)
        if dispatcher is None:
            continue
        return (
            _MainLineage(
                main=address,
                selected_client_global=selected_global,
                runtime_host_global=runtime_host,
                runtime_port_global=runtime_port,
                dispatcher=dispatcher,
                config_reference_count=reference_count,
                initialized_source_count=len(copy_contract[1]),
            ),
            groups,
        )
    return None, best_dispatch_groups


def probe_direct_native_terminal_config(data: bytes) -> dict[str, object]:
    """x64直結型終端を静的producer-consumer証拠だけで確定する。"""

    if (
        not isinstance(data, bytes)
        or not MINIMUM_INPUT_SIZE <= len(data) <= MAXIMUM_INPUT_SIZE
        or not data.startswith(b"MZ")
    ):
        return _empty("input_profile_mismatch")
    try:
        image = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return _empty("invalid_pe")
    try:
        try:
            machine = image.FILE_HEADER.Machine
            magic = image.OPTIONAL_HEADER.Magic
            subsystem = image.OPTIONAL_HEADER.Subsystem
            function_count = len(image.DIRECTORY_ENTRY_EXCEPTION)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return _empty("invalid_pe_headers")
        if (
            machine != 0x8664
            or magic != 0x20B
            or subsystem != 2
            or not 1 <= function_count <= MAXIMUM_FUNCTION_COUNT
        ):
            return _empty("profile_mismatch")
        sections = _sections(data, image)
        imported = _imports(image)
        if sections is None or imported is None:
            return _empty("pe_mapping_rejected")
        imports, libraries = imported
        required = {"WSAStartup", "socket", "connect", "send", "recv"}
        if not required.issubset(set(imports.values())) or not any(
            library in {"ws2_32.dll", "wsock32.dll"} for library in libraries
        ):
            return _empty("network_import_profile_mismatch")
        strings = _wide_strings(data, sections)
        if strings is None:
            return _empty(
                "analysis_incomplete", ["direct_native_wide_string_limit_exceeded"]
            )
        clusters = _config_clusters(strings)
        if len(clusters) != 1:
            return _empty(
                "ambiguous_or_missing_config_cluster",
                ["direct_native_unique_three_slot_config_unproven"],
            )
        cluster = clusters[0]
        analyzer = _Analyzer(data, image, sections, imports)
        if not analyzer.coverage.complete:
            return _empty(
                "analysis_incomplete",
                analyzer.coverage.missing_proof_codes,
            )
        transport, vtable_candidates = _transport(analyzer)
        registrations = _registration_candidates(analyzer)
        if not analyzer.coverage.complete:
            return _empty(
                "analysis_incomplete",
                analyzer.coverage.missing_proof_codes,
            )
        if transport is None:
            return _empty(
                "transport_lineage_incomplete",
                ["direct_native_same_socket_framed_transport_unproven"],
            )
        if len(registrations) != 1:
            return _empty(
                "registration_lineage_incomplete",
                ["direct_native_unique_registration_serializer_unproven"],
            )
        registration, registration_groups = registrations[0]
        main, dispatcher_groups = _main_lineage(
            analyzer, cluster, transport, registration
        )
        if not analyzer.coverage.complete:
            return _empty(
                "analysis_incomplete",
                analyzer.coverage.missing_proof_codes,
            )
        if main is None:
            return _empty(
                "main_lineage_incomplete",
                ["direct_native_config_connect_dispatch_registration_lineage_unproven"],
            )
        external_slots = cluster.external_slots
        endpoints = []
        slots = []
        for index, slot in enumerate(cluster.slots, start=1):
            if slot.loopback:
                continue
            endpoint = f"{slot.host}:{slot.port}"
            endpoints.append(endpoint)
            slots.append(
                {
                    "slot": index,
                    "host": slot.host,
                    "port": slot.port,
                    "transport_selector": 1,
                    "transport": "tcp",
                    "role": "primary" if len(slots) == 0 else "alternate",
                }
            )
        proof = {
            "unique_three_slot_config": True,
            "config_initializer_to_runtime_endpoint": True,
            "tcp_vtable_constructor": True,
            "same_socket_connect_send_receive": True,
            "framed_send_receive": True,
            "callback_dispatcher": True,
            "registration_serializer": True,
            "same_client_connect_and_registration": True,
            "periodic_keepalive": True,
        }
        return {
            "schema_version": 1,
            "status": "validated_terminal_family_config",
            "matched": True,
            "family": "valleyrat",
            "variant": "direct_native_x64_winos_terminal",
            "supports_family_attribution": True,
            "terminal_family_confirmed": True,
            "static_config_recovered": True,
            "candidate_config_recovered": False,
            "attribution_scope": "terminal_payload",
            "family_attribution_basis": (
                "unique_three_slot_config_to_same_client_framed_tcp_dispatch_and_registration"
            ),
            "classification_confidence": "confirmed_static_terminal_lineage",
            "endpoints": endpoints,
            "slots": slots,
            "excluded_placeholder_defaults": ["loopback_slot_3"],
            "missing_proof_codes": [],
            "evidence": {
                "status": "validated_terminal_family_config",
                "profile": "direct_native_x64_winos",
                "analysis_complete": True,
                "terminal_family_lineage_proven": True,
                "proof": proof,
                "configured_slot_count": len(cluster.slots),
                "external_endpoint_count": len(external_slots),
                "excluded_loopback_slot_count": 1,
                "unique_configuration_count": 1,
                "config_literal_reference_count": main.config_reference_count,
                "initialized_runtime_source_count": main.initialized_source_count,
                "validated_transport_count": 1,
                "vtable_candidate_count": vtable_candidates,
                "registration_inventory_group_count": registration_groups,
                "dispatcher_capability_group_count": dispatcher_groups,
                "instruction_decode_complete": True,
                "protocol": {
                    "transport": "tcp",
                    "length_prefix_size": 4,
                    "session_header_size": 10,
                    "frame_header_size": 14,
                    "marker": f"uint16_0x{transport.marker_value:04x}",
                    "initial_registration_command": 6,
                    "registration_structure_size": 0x1250,
                    "dispatcher_max_command": 0xCA,
                    "periodic_keepalive_command": 0xC9,
                    "raw_frame_included": False,
                },
                "raw_addresses_included": False,
                "raw_config_included": False,
                "raw_payload_included": False,
                "sample_executed": False,
                "network_contacted": False,
            },
            "config": {
                "endpoint_count": len(endpoints),
                "configured_slot_count": len(cluster.slots),
                "raw_config_included": False,
                "raw_network_values_included": False,
            },
            "sample_executed": False,
            "network_contacted": False,
        }
    finally:
        del image


__all__ = [
    "MAXIMUM_INPUT_SIZE",
    "MINIMUM_INPUT_SIZE",
    "probe_direct_native_terminal_config",
]
