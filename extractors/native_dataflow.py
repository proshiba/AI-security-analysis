"""有界なnative x86 source-to-network data-flow evaluator。

一般的なsymbolic executionは行わない。file-backed executable section内の
direct call、IAT call、既知APIへ渡る静的callbackだけを辿り、局所的に一意な
register・stack frame・socket identityだけを評価する。不明なalias、間接制御
移譲、またはbudget超過がある場合はfamily確定用の証明をfail-closedにする。
"""

from __future__ import annotations

import itertools
from collections import deque
from dataclasses import dataclass, field
from typing import Literal

from capstone import (
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_32,
    Cs,
    CsError,
)
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AH,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_EAX,
    X86_REG_EBP,
    X86_REG_ECX,
    X86_REG_EDX,
    X86_REG_ESP,
    X86_REG_INVALID,
)

SourceKind = Literal["host", "port", "selector", "opaque"]
_Value = frozenset[str]


@dataclass(frozen=True)
class NativeSource:
    """解析対象の静的source範囲。値そのものは保持しない。"""

    name: str
    address: int
    size: int
    kind: SourceKind = "opaque"


@dataclass(frozen=True)
class CallbackRule:
    """IAT APIの引数から直接code pointerを復元する規則。"""

    api_name: str
    argument_index: int
    argument_count: int


@dataclass(frozen=True)
class NetworkApiSpec:
    """x86 stdcall/cdeclの先頭引数だけで評価できるnetwork API集合。"""

    name_resolvers: frozenset[str] = frozenset({"gethostbyname"})
    port_converters: frozenset[str] = frozenset({"htons"})
    socket_creators: frozenset[str] = frozenset({"socket"})
    connectors: frozenset[str] = frozenset({"connect"})
    senders: frozenset[str] = frozenset({"send"})
    receivers: frozenset[str] = frozenset({"recv"})
    callback_rules: tuple[CallbackRule, ...] = (CallbackRule("CreateThread", 2, 6),)


@dataclass(frozen=True)
class NativeFlowLimits:
    """解析量を外部入力から独立に制限する。"""

    max_functions: int = 768
    max_instructions: int = 60_000
    max_instructions_per_function: int = 4_096
    max_block_states: int = 100_000
    max_memory_cells: int = 128
    max_value_tokens: int = 32


@dataclass(frozen=True)
class _ExecutableSection:
    address: int
    raw_start: int
    raw_end: int

    def contains(self, address: int) -> bool:
        return self.address <= address < self.address + (self.raw_end - self.raw_start)

    def offset(self, address: int) -> int:
        return self.raw_start + address - self.address


@dataclass
class _Runtime:
    limits: NativeFlowLimits
    instruction_count: int = 0
    block_state_count: int = 0
    direct_edge_count: int = 0
    callback_edge_count: int = 0
    conditional_branch_count: int = 0
    branch_rejected_sink_count: int = 0
    ambiguous_join_count: int = 0
    unresolved_indirect_count: int = 0
    invalid_decode_count: int = 0
    alias_unknown: bool = False
    budget_exhausted: bool = False
    reachable_apis: set[str] = field(default_factory=set)
    referenced_sources: set[str] = field(default_factory=set)
    transformed_host_sources: set[str] = field(default_factory=set)
    transformed_port_sources: set[str] = field(default_factory=set)
    config_connect_sockets: set[str] = field(default_factory=set)
    sent_sockets: set[str] = field(default_factory=set)
    received_sockets: set[str] = field(default_factory=set)


@dataclass
class _State:
    registers: dict[int, _Value] = field(default_factory=dict)
    memory: dict[str, _Value] = field(default_factory=dict)
    pushes: list[_Value] = field(default_factory=list)
    path_has_unknown_branch: bool = False

    def clone(self) -> _State:
        return _State(
            registers=dict(self.registers),
            memory=dict(self.memory),
            pushes=list(self.pushes),
            path_has_unknown_branch=self.path_has_unknown_branch,
        )

    def fingerprint(self) -> tuple[object, ...]:
        return (
            tuple(
                sorted(
                    (key, tuple(sorted(value))) for key, value in self.registers.items()
                )
            ),
            tuple(
                sorted(
                    (key, tuple(sorted(value))) for key, value in self.memory.items()
                )
            ),
            tuple(tuple(sorted(value)) for value in self.pushes),
            self.path_has_unknown_branch,
        )


def _empty_result(status: str, missing: list[str]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "analysis_complete": False,
        "terminal_network_lineage_proven": False,
        "proof": {
            "root_mapped": False,
            "callback_lineage_reached": False,
            "all_config_fields_referenced": False,
            "host_source_to_name_resolution": False,
            "port_source_to_network_conversion": False,
            "config_source_to_connect": False,
            "same_socket_connect_send_receive": False,
        },
        "missing_proof_codes": missing,
        "coverage": {
            "function_count": 0,
            "instruction_count": 0,
            "direct_edge_count": 0,
            "callback_edge_count": 0,
            "reachable_api_groups": [],
            "referenced_source_count": 0,
            "source_count": 0,
            "conditional_branch_count": 0,
            "branch_rejected_sink_count": 0,
            "ambiguous_join_count": 0,
            "unresolved_indirect_count": 0,
            "invalid_decode_count": 0,
            "budget_exhausted": False,
        },
        "raw_addresses_included": False,
        "raw_source_values_included": False,
    }


def _validated_sources(sources: tuple[NativeSource, ...]) -> bool:
    names: set[str] = set()
    ranges: list[tuple[int, int]] = []
    for source in sources:
        if (
            not source.name
            or source.name in names
            or type(source.address) is not int
            or type(source.size) is not int
            or not 0 <= source.address <= 0xFFFFFFFF
            or not 1 <= source.size <= 0x10000
            or source.address + source.size > 0x1_0000_0000
        ):
            return False
        names.add(source.name)
        ranges.append((source.address, source.address + source.size))
    ranges.sort()
    return all(
        previous[1] <= current[0] for previous, current in itertools.pairwise(ranges)
    )


def _executable_sections(
    data: bytes,
    image: object,
) -> tuple[int, tuple[_ExecutableSection, ...]] | None:
    try:
        image_base = image.OPTIONAL_HEADER.ImageBase
        sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if type(image_base) is not int or not 0 <= image_base <= 0xFFFFFFFF:
        return None
    result: list[_ExecutableSection] = []
    for section in sections:
        try:
            raw_start = section.PointerToRawData
            raw_size = section.SizeOfRawData
            virtual_address = section.VirtualAddress
            characteristics = section.Characteristics
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if any(
            type(value) is not int
            for value in (raw_start, raw_size, virtual_address, characteristics)
        ):
            return None
        raw_end = raw_start + raw_size
        address = image_base + virtual_address
        if (
            raw_start < 0
            or raw_size < 0
            or raw_end < raw_start
            or raw_end > len(data)
            or not 0 <= address <= 0xFFFFFFFF
            or address + raw_size > 0x1_0000_0000
        ):
            return None
        if characteristics & 0x20000000 and raw_size:
            result.append(_ExecutableSection(address, raw_start, raw_end))
    result.sort(key=lambda item: item.address)
    if not result or any(
        previous.address + (previous.raw_end - previous.raw_start) > current.address
        for previous, current in itertools.pairwise(result)
    ):
        return None
    return image_base, tuple(result)


def _import_map(image: object) -> dict[int, str] | None:
    try:
        descriptors = list(image.DIRECTORY_ENTRY_IMPORT)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    result: dict[int, str] = {}
    count = 0
    for descriptor in descriptors:
        try:
            imported_symbols = list(descriptor.imports)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        for imported in imported_symbols:
            count += 1
            if count > 4_096:
                return None
            try:
                address = imported.address
                raw_name = imported.name
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
            if address in result and result[address].casefold() != name.casefold():
                return None
            result[address] = name
    return result


def _section_for_address(
    sections: tuple[_ExecutableSection, ...],
    address: int,
) -> _ExecutableSection | None:
    for section in sections:
        if section.contains(address):
            return section
    return None


def _source_at(address: int, sources: tuple[NativeSource, ...]) -> NativeSource | None:
    normalized = address & 0xFFFFFFFF
    for source in sources:
        if source.address <= normalized < source.address + source.size:
            return source
    return None


def _source_value(source: NativeSource, form: Literal["address", "data"]) -> _Value:
    return frozenset(
        {
            f"source:{source.name}",
            f"source-kind:{source.kind}",
            f"source-{form}:{source.name}",
        }
    )


def _constant_value(value: int) -> _Value:
    return frozenset({f"constant:{value & 0xFFFFFFFF}"})


def _bounded_union(runtime: _Runtime, *values: _Value) -> _Value:
    merged: _Value = frozenset()
    for value in values:
        merged = merged | value
        if len(merged) > runtime.limits.max_value_tokens:
            runtime.alias_unknown = True
            return frozenset()
    return merged


def _pointer_token(base: str, displacement: int) -> str:
    return f"pointer:{base}:{displacement}"


def _memory_key(base: str, displacement: int) -> str:
    return f"memory:{base}:{displacement}"


def _pointer_parts(token: str) -> tuple[str, int] | None:
    if not token.startswith("pointer:"):
        return None
    try:
        _prefix, base, displacement = token.split(":", 2)
        return base, int(displacement)
    except (TypeError, ValueError):
        return None


def _memory_parts(token: str) -> tuple[str, int] | None:
    if not token.startswith("memory:"):
        return None
    try:
        _prefix, base, displacement = token.split(":", 2)
        return base, int(displacement)
    except (TypeError, ValueError):
        return None


def _memory_keys(operand: object, state: _State) -> tuple[str, ...]:
    memory = operand.mem
    if memory.index != X86_REG_INVALID:
        return ()
    if memory.base == X86_REG_EBP:
        return (_memory_key("ebp", memory.disp),)
    if memory.base == X86_REG_ESP:
        return (_memory_key("esp", memory.disp),)
    if memory.base == X86_REG_INVALID:
        return (_memory_key("absolute", memory.disp & 0xFFFFFFFF),)
    keys: list[str] = []
    for token in state.registers.get(memory.base, frozenset()):
        parts = _pointer_parts(token)
        if parts is not None:
            base, displacement = parts
            keys.append(_memory_key(base, displacement + memory.disp))
    return tuple(sorted(set(keys)))


def _canonical_register(register: int) -> int:
    """追跡対象のx86 subregisterを32-bit親registerへ寄せる。"""

    if register in {X86_REG_AH, X86_REG_AL, X86_REG_AX}:
        return X86_REG_EAX
    return register


def _operand_value(
    operand: object,
    state: _State,
    sources: tuple[NativeSource, ...],
    runtime: _Runtime,
    *,
    address_only: bool = False,
) -> _Value:
    if operand.type == X86_OP_IMM:
        source = _source_at(operand.imm, sources)
        if source is not None:
            runtime.referenced_sources.add(source.name)
            return _bounded_union(
                runtime,
                _source_value(source, "address"),
                frozenset({_pointer_token("source", source.address)}),
            )
        return _constant_value(operand.imm)
    if operand.type == X86_OP_REG:
        return state.registers.get(_canonical_register(operand.reg), frozenset())
    if operand.type != X86_OP_MEM:
        return frozenset()
    memory = operand.mem
    if memory.base == X86_REG_INVALID and memory.index == X86_REG_INVALID:
        source = _source_at(memory.disp, sources)
        if source is not None:
            runtime.referenced_sources.add(source.name)
            source_data = _source_value(
                source,
                "address" if address_only else "data",
            )
            if address_only:
                return _bounded_union(
                    runtime,
                    source_data,
                    frozenset({_pointer_token("source", source.address)}),
                )
            return source_data
    keys = _memory_keys(operand, state)
    if address_only:
        return frozenset(
            _pointer_token(*parts)
            for key in keys
            if (parts := _memory_parts(key)) is not None
        )
    values = [state.memory.get(key, frozenset()) for key in keys]
    base_value = state.registers.get(memory.base, frozenset())
    # hostentのようなAPI戻り値の有界dereferenceはtaintだけを維持する。
    if base_value and not keys:
        values.append(base_value)
    return _bounded_union(runtime, *values) if values else frozenset()


def _write_operand(
    operand: object,
    value: _Value,
    state: _State,
    runtime: _Runtime,
) -> None:
    if operand.type == X86_OP_REG:
        state.registers[_canonical_register(operand.reg)] = value
        return
    if operand.type != X86_OP_MEM:
        runtime.alias_unknown = True
        return
    keys = _memory_keys(operand, state)
    if len(keys) != 1:
        runtime.alias_unknown = True
        return
    if (
        keys[0] not in state.memory
        and len(state.memory) >= runtime.limits.max_memory_cells
    ):
        runtime.budget_exhausted = True
        return
    state.memory[keys[0]] = value


def _source_names(
    value: _Value, sources_by_name: dict[str, NativeSource], kind: SourceKind
) -> set[str]:
    result: set[str] = set()
    for token in value:
        if not token.startswith("source:"):
            continue
        name = token.removeprefix("source:")
        source = sources_by_name.get(name)
        if source is not None and source.kind == kind:
            result.add(name)
    return result


def _source_form_names(
    value: _Value,
    sources_by_name: dict[str, NativeSource],
    kind: SourceKind,
    form: Literal["address", "data"],
) -> set[str]:
    result: set[str] = set()
    prefix = f"source-{form}:"
    for token in value:
        if not token.startswith(prefix):
            continue
        name = token.removeprefix(prefix)
        source = sources_by_name.get(name)
        if source is not None and source.kind == kind:
            result.add(name)
    return result


def _constant_from_value(value: _Value) -> int | None:
    constants = {
        int(token.removeprefix("constant:"))
        for token in value
        if token.startswith("constant:")
    }
    return next(iter(constants)) if len(constants) == 1 else None


def _expand_pointer(
    value: _Value,
    state: _State,
    runtime: _Runtime,
    span: int,
) -> _Value:
    values: list[_Value] = [value]
    if not 1 <= span <= 128:
        runtime.alias_unknown = True
        return frozenset()
    for token in value:
        pointer = _pointer_parts(token)
        if pointer is None:
            continue
        base, start = pointer
        for key, content in state.memory.items():
            memory = _memory_parts(key)
            if memory is None:
                continue
            memory_base, displacement = memory
            if memory_base == base and start <= displacement < start + span:
                values.append(content)
    return _bounded_union(runtime, *values)


def _api_groups(api_names: set[str], spec: NetworkApiSpec) -> list[str]:
    folded = {name.casefold() for name in api_names}
    groups: list[str] = []
    for group, candidates in (
        ("name_resolution", spec.name_resolvers),
        ("port_conversion", spec.port_converters),
        ("socket_create", spec.socket_creators),
        ("connect", spec.connectors),
        ("send", spec.senders),
        ("receive", spec.receivers),
    ):
        if folded & {candidate.casefold() for candidate in candidates}:
            groups.append(group)
    return groups


def _call_arguments(state: _State, count: int) -> list[_Value] | None:
    if count < 0 or len(state.pushes) < count:
        return None
    return list(reversed(state.pushes[-count:]))


def _consume_arguments(state: _State, count: int) -> None:
    if count > 0 and len(state.pushes) >= count:
        del state.pushes[-count:]
    else:
        state.pushes.clear()


def _socket_tokens(value: _Value) -> set[str]:
    return {token for token in value if token.startswith("socket:")}


def _api_argument_count(api_name: str, spec: NetworkApiSpec) -> int | None:
    folded = api_name.casefold()
    if folded in {name.casefold() for name in spec.name_resolvers}:
        return 1
    if folded in {name.casefold() for name in spec.port_converters}:
        return 1
    if folded in {name.casefold() for name in spec.socket_creators}:
        return 3
    if folded in {name.casefold() for name in spec.connectors}:
        return 3
    if folded in {name.casefold() for name in spec.senders}:
        return 4
    if folded in {name.casefold() for name in spec.receivers}:
        return 4
    for rule in spec.callback_rules:
        if folded == rule.api_name.casefold():
            return rule.argument_count
    return None


def _apply_api_call(
    api_name: str,
    instruction_address: int,
    state: _State,
    sources_by_name: dict[str, NativeSource],
    runtime: _Runtime,
    spec: NetworkApiSpec,
) -> tuple[int, ...]:
    runtime.reachable_apis.add(api_name)
    folded = api_name.casefold()
    argument_count = _api_argument_count(api_name, spec)
    arguments = (
        _call_arguments(state, argument_count) if argument_count is not None else None
    )
    callback_targets: list[int] = []
    for rule in spec.callback_rules:
        if folded != rule.api_name.casefold() or arguments is None:
            continue
        callback_value = arguments[rule.argument_index]
        callback_target = _constant_from_value(callback_value)
        if callback_target is not None:
            callback_targets.append(callback_target)

    result: _Value = frozenset()
    if folded in {name.casefold() for name in spec.name_resolvers} and arguments:
        names = _source_form_names(
            arguments[0],
            sources_by_name,
            "host",
            "address",
        )
        if names:
            runtime.transformed_host_sources.update(names)
            result = _bounded_union(
                runtime,
                arguments[0],
                frozenset({"transform:name-resolution"}),
            )
    elif folded in {name.casefold() for name in spec.port_converters} and arguments:
        names = _source_form_names(
            arguments[0],
            sources_by_name,
            "port",
            "data",
        )
        if names:
            runtime.transformed_port_sources.update(names)
            result = _bounded_union(
                runtime,
                arguments[0],
                frozenset({"transform:port-conversion"}),
            )
    elif folded in {name.casefold() for name in spec.socket_creators}:
        result = frozenset({f"socket:{instruction_address}"})
    elif folded in {name.casefold() for name in spec.connectors} and arguments:
        socket_ids = _socket_tokens(arguments[0])
        span = _constant_from_value(arguments[2])
        address_value = (
            _expand_pointer(arguments[1], state, runtime, span)
            if span is not None
            else frozenset()
        )
        host_names = _source_names(address_value, sources_by_name, "host")
        port_names = _source_names(address_value, sources_by_name, "port")
        lineage_ready = bool(
            socket_ids
            and host_names
            and port_names
            and "transform:name-resolution" in address_value
            and "transform:port-conversion" in address_value
        )
        if lineage_ready and state.path_has_unknown_branch:
            runtime.branch_rejected_sink_count += 1
        elif lineage_ready:
            runtime.config_connect_sockets.update(socket_ids)
    elif folded in {name.casefold() for name in spec.senders} and arguments:
        socket_ids = _socket_tokens(arguments[0])
        if socket_ids and state.path_has_unknown_branch:
            runtime.branch_rejected_sink_count += 1
        elif socket_ids:
            runtime.sent_sockets.update(socket_ids)
    elif folded in {name.casefold() for name in spec.receivers} and arguments:
        socket_ids = _socket_tokens(arguments[0])
        if socket_ids and state.path_has_unknown_branch:
            runtime.branch_rejected_sink_count += 1
        elif socket_ids:
            runtime.received_sockets.update(socket_ids)

    if argument_count is None:
        state.pushes.clear()
    else:
        _consume_arguments(state, argument_count)
    for register in (X86_REG_EAX, X86_REG_ECX, X86_REG_EDX):
        state.registers.pop(register, None)
    if result:
        state.registers[X86_REG_EAX] = result
    return tuple(callback_targets)


def _apply_instruction(
    instruction: object,
    state: _State,
    sources: tuple[NativeSource, ...],
    runtime: _Runtime,
) -> None:
    mnemonic = instruction.mnemonic.casefold()
    operands = instruction.operands
    if mnemonic == "push" and operands:
        state.pushes.append(_operand_value(operands[0], state, sources, runtime))
        return
    if mnemonic == "pop" and operands:
        value = state.pushes.pop() if state.pushes else frozenset()
        _write_operand(operands[0], value, state, runtime)
        return
    if mnemonic == "lea" and len(operands) >= 2:
        value = _operand_value(
            operands[1],
            state,
            sources,
            runtime,
            address_only=True,
        )
        _write_operand(operands[0], value, state, runtime)
        return
    if mnemonic in {"mov", "movzx", "movsx", "movsxd"} and len(operands) >= 2:
        value = _operand_value(operands[1], state, sources, runtime)
        _write_operand(operands[0], value, state, runtime)
        return
    if (
        mnemonic == "xor"
        and len(operands) >= 2
        and operands[0].type == X86_OP_REG
        and operands[1].type == X86_OP_REG
        and operands[0].reg == operands[1].reg
    ):
        _write_operand(operands[0], frozenset(), state, runtime)
        return
    if (
        mnemonic in {"add", "sub", "and", "or", "xor", "shl", "shr", "rol", "ror"}
        and len(operands) >= 2
    ):
        left = _operand_value(operands[0], state, sources, runtime)
        right = _operand_value(operands[1], state, sources, runtime)
        _write_operand(
            operands[0], _bounded_union(runtime, left, right), state, runtime
        )
        return
    # 未対応命令でもsource address operandの参照自体は記録する。
    for operand in operands:
        _operand_value(operand, state, sources, runtime)


def _iat_api(instruction: object, import_addresses: dict[int, str]) -> str | None:
    if not instruction.operands:
        return None
    operand = instruction.operands[0]
    if (
        operand.type == X86_OP_MEM
        and operand.mem.base == X86_REG_INVALID
        and operand.mem.index == X86_REG_INVALID
    ):
        return import_addresses.get(operand.mem.disp & 0xFFFFFFFF)
    return None


def _direct_target(instruction: object) -> int | None:
    if not instruction.operands or instruction.operands[0].type != X86_OP_IMM:
        return None
    return instruction.operands[0].imm & 0xFFFFFFFF


def _import_thunk(
    data: bytes,
    address: int,
    sections: tuple[_ExecutableSection, ...],
    imports: dict[int, str],
    disassembler: Cs,
) -> str | None:
    section = _section_for_address(sections, address)
    if section is None:
        return None
    offset = section.offset(address)
    try:
        instruction = next(
            disassembler.disasm(
                data[offset : min(section.raw_end, offset + 15)], address, count=1
            ),
            None,
        )
    except CsError:
        return None
    if instruction is None or instruction.mnemonic.casefold() != "jmp":
        return None
    return _iat_api(instruction, imports)


def _analyze_function(
    data: bytes,
    start: int,
    sections: tuple[_ExecutableSection, ...],
    imports: dict[int, str],
    sources: tuple[NativeSource, ...],
    sources_by_name: dict[str, NativeSource],
    runtime: _Runtime,
    spec: NetworkApiSpec,
    disassembler: Cs,
) -> tuple[set[int], set[int]]:
    direct_targets: set[int] = set()
    callback_targets: set[int] = set()
    worklist: deque[tuple[int, _State]] = deque([(start, _State())])
    observed_states: dict[int, tuple[object, ...]] = {}
    function_instruction_count = 0
    while worklist and not runtime.budget_exhausted:
        block_start, state = worklist.popleft()
        runtime.block_state_count += 1
        if runtime.block_state_count > runtime.limits.max_block_states:
            runtime.budget_exhausted = True
            break
        fingerprint = state.fingerprint()
        prior = observed_states.get(block_start)
        if prior is not None:
            if prior != fingerprint:
                runtime.ambiguous_join_count += 1
                runtime.alias_unknown = True
            continue
        observed_states[block_start] = fingerprint
        address = block_start
        while not runtime.budget_exhausted:
            section = _section_for_address(sections, address)
            if section is None:
                break
            offset = section.offset(address)
            try:
                instruction = next(
                    disassembler.disasm(
                        data[offset : min(section.raw_end, offset + 15)],
                        address,
                        count=1,
                    ),
                    None,
                )
            except CsError:
                instruction = None
            if (
                instruction is None
                or instruction.address != address
                or instruction.size <= 0
            ):
                runtime.invalid_decode_count += 1
                break
            runtime.instruction_count += 1
            function_instruction_count += 1
            if (
                runtime.instruction_count > runtime.limits.max_instructions
                or function_instruction_count
                > runtime.limits.max_instructions_per_function
            ):
                runtime.budget_exhausted = True
                break
            next_address = address + instruction.size
            if instruction.group(CS_GRP_CALL):
                api_name = _iat_api(instruction, imports)
                target = _direct_target(instruction)
                if api_name is None and target is not None:
                    api_name = _import_thunk(
                        data, target, sections, imports, disassembler
                    )
                if api_name is not None:
                    for callback in _apply_api_call(
                        api_name,
                        instruction.address,
                        state,
                        sources_by_name,
                        runtime,
                        spec,
                    ):
                        if _section_for_address(sections, callback) is not None:
                            callback_targets.add(callback)
                elif (
                    target is not None
                    and _section_for_address(sections, target) is not None
                ):
                    direct_targets.add(target)
                    state.pushes.clear()
                    for register in (X86_REG_EAX, X86_REG_ECX, X86_REG_EDX):
                        state.registers.pop(register, None)
                else:
                    runtime.unresolved_indirect_count += 1
                    state.pushes.clear()
                    state.registers.clear()
                address = next_address
                continue
            if instruction.group(CS_GRP_RET) or instruction.mnemonic.casefold() in {
                "int3",
                "ud2",
                "hlt",
            }:
                break
            if instruction.group(CS_GRP_JUMP):
                target = _direct_target(instruction)
                if target is None or _section_for_address(sections, target) is None:
                    api_name = _iat_api(instruction, imports)
                    if api_name is not None:
                        runtime.reachable_apis.add(api_name)
                    else:
                        runtime.unresolved_indirect_count += 1
                    break
                if instruction.mnemonic.casefold() == "jmp":
                    worklist.append((target, state.clone()))
                    break
                runtime.conditional_branch_count += 1
                branched = state.clone()
                branched.path_has_unknown_branch = True
                fallthrough = state.clone()
                fallthrough.path_has_unknown_branch = True
                worklist.append((target, branched))
                worklist.append((next_address, fallthrough))
                break
            _apply_instruction(instruction, state, sources, runtime)
            address = next_address
    return direct_targets, callback_targets


def analyze_x86_pe_dataflow(
    data: bytes,
    image: object,
    *,
    roots: tuple[int, ...],
    sources: tuple[NativeSource, ...],
    api_spec: NetworkApiSpec | None = None,
    limits: NativeFlowLimits | None = None,
    require_callback: bool = False,
) -> dict[str, object]:
    """direct/IAT/callback限定で設定からsocket sinkまでを静的に証明する。"""

    if not isinstance(data, bytes) or not data:
        return _empty_result("invalid_input", ["native_flow_invalid_input"])
    if not roots or any(
        type(root) is not int or not 0 <= root <= 0xFFFFFFFF for root in roots
    ):
        return _empty_result("invalid_roots", ["native_flow_invalid_roots"])
    if not sources or not _validated_sources(sources):
        return _empty_result("invalid_sources", ["native_flow_invalid_sources"])
    spec = api_spec or NetworkApiSpec()
    analysis_limits = limits or NativeFlowLimits()
    if any(
        type(value) is not int or value <= 0
        for value in (
            analysis_limits.max_functions,
            analysis_limits.max_instructions,
            analysis_limits.max_instructions_per_function,
            analysis_limits.max_block_states,
            analysis_limits.max_memory_cells,
            analysis_limits.max_value_tokens,
        )
    ):
        return _empty_result("invalid_limits", ["native_flow_invalid_limits"])
    executable = _executable_sections(data, image)
    imports = _import_map(image)
    if executable is None or imports is None:
        return _empty_result("invalid_pe_view", ["native_flow_invalid_pe_view"])
    _image_base, sections = executable
    mapped_roots = tuple(
        root for root in roots if _section_for_address(sections, root) is not None
    )
    if len(mapped_roots) != len(roots):
        return _empty_result("unmapped_root", ["native_flow_root_unmapped"])

    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
    except CsError:
        return _empty_result(
            "disassembler_unavailable", ["native_flow_disassembler_unavailable"]
        )

    runtime = _Runtime(analysis_limits)
    sources_by_name = {source.name: source for source in sources}
    pending: deque[tuple[int, str]] = deque((root, "root") for root in mapped_roots)
    analyzed: set[int] = set()
    while pending and not runtime.budget_exhausted:
        function, edge_kind = pending.popleft()
        if function in analyzed:
            continue
        if len(analyzed) >= analysis_limits.max_functions:
            runtime.budget_exhausted = True
            break
        analyzed.add(function)
        if edge_kind == "callback":
            runtime.callback_edge_count += 1
        direct_targets, callback_targets = _analyze_function(
            data,
            function,
            sections,
            imports,
            sources,
            sources_by_name,
            runtime,
            spec,
            disassembler,
        )
        runtime.direct_edge_count += len(direct_targets)
        pending.extend((target, "direct") for target in sorted(direct_targets))
        pending.extend((target, "callback") for target in sorted(callback_targets))

    source_names = {source.name for source in sources}
    host_names = {source.name for source in sources if source.kind == "host"}
    port_names = {source.name for source in sources if source.kind == "port"}
    common_sockets = (
        runtime.config_connect_sockets & runtime.sent_sockets & runtime.received_sockets
    )
    all_fields_referenced = runtime.referenced_sources == source_names
    callback_reached = runtime.callback_edge_count > 0
    host_transformed = bool(runtime.transformed_host_sources & host_names)
    port_transformed = bool(runtime.transformed_port_sources & port_names)
    config_to_connect = bool(runtime.config_connect_sockets)
    same_socket = bool(common_sockets)
    analysis_complete = not (
        runtime.budget_exhausted
        or runtime.alias_unknown
        or runtime.unresolved_indirect_count
        or runtime.invalid_decode_count
    )
    callback_gate = callback_reached or not require_callback
    terminal = bool(
        analysis_complete
        and callback_gate
        and all_fields_referenced
        and host_transformed
        and port_transformed
        and config_to_connect
        and same_socket
    )

    missing: list[str] = []
    if require_callback and not callback_reached:
        missing.append("native_flow_root_callback_lineage_unproven")
    if not all_fields_referenced:
        missing.append("native_flow_config_field_references_incomplete")
    if not host_transformed:
        missing.append("native_flow_host_to_name_resolution_unproven")
    if not port_transformed:
        missing.append("native_flow_port_to_conversion_unproven")
    if not config_to_connect:
        missing.append("native_flow_config_to_connect_unproven")
    if not same_socket:
        missing.append("native_flow_same_socket_connect_send_receive_unproven")
    if runtime.unresolved_indirect_count:
        missing.append("native_flow_unresolved_indirect_control_flow")
    if runtime.invalid_decode_count:
        missing.append("native_flow_invalid_instruction_boundary")
    if runtime.branch_rejected_sink_count:
        missing.append("native_flow_unknown_branch_on_sink_lineage")
    if runtime.alias_unknown:
        missing.append("native_flow_alias_or_branch_join_unknown")
    if runtime.budget_exhausted:
        missing.append("native_flow_budget_exhausted")

    return {
        "schema_version": 1,
        "status": "terminal_network_lineage_proven"
        if terminal
        else "incomplete_terminal_network_lineage",
        "analysis_complete": analysis_complete,
        "terminal_network_lineage_proven": terminal,
        "proof": {
            "root_mapped": True,
            "callback_lineage_reached": callback_reached,
            "all_config_fields_referenced": all_fields_referenced,
            "host_source_to_name_resolution": host_transformed,
            "port_source_to_network_conversion": port_transformed,
            "config_source_to_connect": config_to_connect,
            "same_socket_connect_send_receive": same_socket,
        },
        "missing_proof_codes": missing,
        "coverage": {
            "function_count": len(analyzed),
            "instruction_count": runtime.instruction_count,
            "direct_edge_count": runtime.direct_edge_count,
            "callback_edge_count": runtime.callback_edge_count,
            "reachable_api_groups": _api_groups(runtime.reachable_apis, spec),
            "referenced_source_count": len(runtime.referenced_sources),
            "source_count": len(sources),
            "conditional_branch_count": runtime.conditional_branch_count,
            "branch_rejected_sink_count": runtime.branch_rejected_sink_count,
            "ambiguous_join_count": runtime.ambiguous_join_count,
            "unresolved_indirect_count": runtime.unresolved_indirect_count,
            "invalid_decode_count": runtime.invalid_decode_count,
            "budget_exhausted": runtime.budget_exhausted,
        },
        "raw_addresses_included": False,
        "raw_source_values_included": False,
    }


__all__ = [
    "CallbackRule",
    "NativeFlowLimits",
    "NativeSource",
    "NetworkApiSpec",
    "analyze_x86_pe_dataflow",
]
