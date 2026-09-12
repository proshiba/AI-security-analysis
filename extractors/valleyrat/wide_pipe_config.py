"""plaintext UTF-16LE pipe設定を持つWinos bootstrapを静的に検証する。

本moduleはPEをload／実行せず、file-backed section、x86命令、import／export
tableだけを扱う。設定文字列だけではValleyRATへ帰属しない。外部rootからの
field parser、実際にworkerが読む重複global、TCP vtable、同一socket fieldの
connect／send／recv、Winos固有frameと受信dispatcherまでを一つの静的系譜で
確認できた場合だけfamilyと設定を確定する。
"""

from __future__ import annotations

import hashlib
import itertools
import re
import struct
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

import pefile
from capstone import (
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_32,
    Cs,
    CsError,
)
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID

from extractors.valleyrat.nvml_dat import normalize_host, render_endpoint

MAXIMUM_INPUT_SIZE = 16 * 1024 * 1024
MAXIMUM_SECTIONS = 96
MAXIMUM_IMPORT_DESCRIPTORS = 1_024
MAXIMUM_IMPORTS = 65_536
MAXIMUM_IMPORT_NAME = 128
MAXIMUM_EXPORTS = 4_096
MAXIMUM_CONFIG_CODE_UNITS = 4_096
MAXIMUM_CONFIG_CANDIDATES = 32
MAXIMUM_VALUE_OCCURRENCES = 64
MAXIMUM_FUNCTION_INSTRUCTIONS = 8_192
MAXIMUM_FUNCTIONS_PER_CLOSURE = 128
MAXIMUM_CLOSURE_DEPTH = 6

_EXECUTABLE = 0x20000000
_WRITABLE = 0x80000000
_CONFIG_MARKER = "|p1:".encode("utf-16le")
_NETWORK_KEYS = (
    "p1",
    "o1",
    "t1",
    "p2",
    "o2",
    "t2",
    "p3",
    "o3",
    "t3",
    "dd",
    "cl",
    "fz",
)
_BEHAVIOUR_KEYS = ("bb", "bz", "jp", "bh", "ll", "dl", "sh", "kl", "bd")
_BOOLEAN_KEYS = frozenset({"dd", "cl", "jp", "sx", "bh", "ll", "dl", "sh", "kl", "bd"})
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "0.0.0.0", "::1"})
_SAFE_BUILD_TEXT = re.compile(r"[\w .-]{1,64}\Z", re.UNICODE)


class WidePipeConfigError(ValueError):
    """設定または静的系譜を安全に評価できない場合の例外。"""


@dataclass(frozen=True)
class WidePipeSlot:
    """検証済みendpoint slot。"""

    index: int
    host: str
    port: int
    transport: int
    endpoint: str | None


@dataclass(frozen=True)
class WidePipeConfigRecovery:
    """公開可能な値と、生値を除いた静的証拠を保持する。"""

    endpoints: tuple[str, ...]
    slots: tuple[WidePipeSlot, ...]
    configuration_identity_sha256: str
    candidate_count: int
    terminal_family_confirmed: bool
    evidence: dict[str, object]

    def public_summary(self) -> dict[str, object]:
        return public_recovery_summary(self)


@dataclass(frozen=True)
class _Section:
    name: str
    address: int
    raw_start: int
    raw_end: int
    executable: bool
    writable: bool

    @property
    def size(self) -> int:
        return self.raw_end - self.raw_start

    def contains_address(self, address: int, size: int = 1) -> bool:
        return self.address <= address and address + size <= self.address + self.size

    def contains_offset(self, offset: int, size: int = 1) -> bool:
        return self.raw_start <= offset and offset + size <= self.raw_end

    def offset(self, address: int) -> int:
        return self.raw_start + address - self.address


@dataclass(frozen=True)
class _ConfigCandidate:
    address: int
    raw_start: int
    raw_end: int
    values: tuple[tuple[str, str], ...]
    slots: tuple[WidePipeSlot, ...]
    identity: tuple[tuple[str, str], ...]

    @property
    def fields(self) -> dict[str, str]:
        return dict(self.values)


@dataclass(frozen=True)
class _Function:
    start: int
    instructions: tuple[object, ...]
    direct_calls: tuple[int, ...]
    direct_call_sites: tuple[tuple[int, int], ...]
    api_call_sites: tuple[tuple[int, str], ...]
    immediate_values: tuple[int, ...]
    indirect_call_offsets: tuple[int, ...]
    complete: bool

    def site_for_direct_call(self, target: int) -> tuple[int, ...]:
        return tuple(site for site, value in self.direct_call_sites if value == target)


def _empty_probe() -> dict[str, object]:
    return {
        "matched": False,
        "family": None,
        "variant": None,
        "supports_family_attribution": False,
        "static_config_recovered": False,
        "candidate_config_recovered": False,
        "evidence": {},
        "config": {},
        "sample_executed": False,
        "network_contacted": False,
    }


def _sections(image: object, data: bytes) -> tuple[_Section, ...] | None:
    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        raw_sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not 1 <= len(raw_sections) <= MAXIMUM_SECTIONS:
        return None
    result: list[_Section] = []
    for raw in raw_sections:
        try:
            name = bytes(raw.Name).rstrip(b"\0").decode("ascii", errors="replace")[:8]
            raw_start = int(raw.PointerToRawData)
            raw_size = int(raw.SizeOfRawData)
            virtual_size = int(raw.Misc_VirtualSize)
            virtual_address = int(raw.VirtualAddress)
            characteristics = int(raw.Characteristics)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        mapped_size = min(raw_size, virtual_size or raw_size)
        executable = bool(characteristics & _EXECUTABLE)
        writable = bool(characteristics & _WRITABLE)
        # 一部の実検体は末尾.relocのraw bodyだけを切り落としている。解析対象の
        # code／writable dataではない、file末尾ちょうどから始まる未格納sectionは
        # 無関係なvirtual-only領域として除外する。それ以外の欠損は拒否する。
        if raw_start == len(data) and mapped_size and not executable and not writable:
            continue
        if (
            raw_start < 0
            or mapped_size < 0
            or raw_start + mapped_size > len(data)
            or not 0 <= image_base + virtual_address <= 0xFFFFFFFF
            or image_base + virtual_address + mapped_size > 0x1_0000_0000
        ):
            return None
        if mapped_size:
            result.append(
                _Section(
                    name=name,
                    address=image_base + virtual_address,
                    raw_start=raw_start,
                    raw_end=raw_start + mapped_size,
                    executable=executable,
                    writable=writable,
                )
            )
    by_raw = sorted(result, key=lambda item: item.raw_start)
    by_address = sorted(result, key=lambda item: item.address)
    if not result or any(
        left.raw_end > right.raw_start for left, right in itertools.pairwise(by_raw)
    ):
        return None
    if any(
        left.address + left.size > right.address
        for left, right in itertools.pairwise(by_address)
    ):
        return None
    return tuple(by_address)


def _section_for_address(
    sections: tuple[_Section, ...], address: int, *, executable: bool | None = None
) -> _Section | None:
    for section in sections:
        if section.contains_address(address) and (
            executable is None or section.executable is executable
        ):
            return section
    return None


def _external_roots(
    image: object, sections: tuple[_Section, ...]
) -> tuple[tuple[int, ...], int] | None:
    """forwarderを除くexportからfile-backed x86 rootを名称非依存で得る。"""

    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        symbols = list(image.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        return (), 0
    except (TypeError, ValueError, OverflowError):
        return None
    if not 1 <= len(symbols) <= MAXIMUM_EXPORTS:
        return None
    roots: list[int] = []
    for symbol in symbols:
        try:
            rva = int(symbol.address)
            forwarder = getattr(symbol, "forwarder", None)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if forwarder:
            continue
        address = image_base + rva
        if _section_for_address(sections, address, executable=True) is None:
            return None
        roots.append(address)
    return tuple(dict.fromkeys(roots)), len(symbols)


def _decode_utf16z(data: bytes, start: int, end: int) -> tuple[str, int] | None:
    units: list[bytes] = []
    cursor = start
    for _index in range(MAXIMUM_CONFIG_CODE_UNITS):
        if cursor + 2 > end:
            return None
        unit = data[cursor : cursor + 2]
        cursor += 2
        if unit == b"\0\0":
            try:
                return b"".join(units).decode("utf-16le", errors="strict"), cursor
            except UnicodeError:
                return None
        units.append(unit)
    return None


def _parse_candidate(
    text: str, *, address: int, raw_start: int, raw_end: int
) -> _ConfigCandidate | None:
    if not text.startswith("|p1:") or not text.endswith("|"):
        return None
    if any(ord(character) < 0x20 for character in text):
        return None
    segments = text.split("|")[1:-1]
    values: list[tuple[str, str]] = []
    seen: set[str] = set()
    for segment in segments:
        if ":" not in segment:
            return None
        key, value = segment.split(":", 1)
        key = key.casefold()
        if not re.fullmatch(r"[a-z][a-z0-9]?", key) or key in seen:
            return None
        seen.add(key)
        values.append((key, value.strip()))
    keys = tuple(key for key, _value in values)
    if keys[: len(_NETWORK_KEYS)] != _NETWORK_KEYS:
        return None
    tail = keys[len(_NETWORK_KEYS) :]
    if tail not in (_BEHAVIOUR_KEYS, ("bb", "bz", "jp", "sx", *_BEHAVIOUR_KEYS[3:])):
        return None
    fields = dict(values)
    if any(fields.get(key) not in {"0", "1"} for key in _BOOLEAN_KEYS & fields.keys()):
        return None
    if not fields["fz"] or len(fields["fz"]) > 64:
        return None
    if not _SAFE_BUILD_TEXT.fullmatch(fields["bb"]) or not _SAFE_BUILD_TEXT.fullmatch(
        fields["bz"]
    ):
        return None
    slots: list[WidePipeSlot] = []
    external_count = 0
    for index in (1, 2, 3):
        raw_host = fields[f"p{index}"]
        raw_port = fields[f"o{index}"]
        raw_transport = fields[f"t{index}"]
        if raw_transport not in {"0", "1"}:
            return None
        if bool(raw_host) != bool(raw_port):
            return None
        if not raw_host:
            slots.append(WidePipeSlot(index, "", 0, int(raw_transport), None))
            continue
        host = normalize_host(raw_host)
        if host is None or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
            return None
        endpoint = (
            None if host in _LOOPBACK_HOSTS else render_endpoint(host, int(raw_port))
        )
        if endpoint is None and host not in _LOOPBACK_HOSTS:
            return None
        external_count += int(endpoint is not None)
        slots.append(
            WidePipeSlot(index, host, int(raw_port), int(raw_transport), endpoint)
        )
    if external_count == 0:
        return None
    return _ConfigCandidate(
        address=address,
        raw_start=raw_start,
        raw_end=raw_end,
        values=tuple(values),
        slots=tuple(slots),
        identity=tuple(values),
    )


def _config_candidates(
    data: bytes, sections: tuple[_Section, ...]
) -> tuple[_ConfigCandidate, int, bool]:
    candidates: list[_ConfigCandidate] = []
    observed = 0
    complete = True
    for section in sections:
        if section.executable or not section.writable:
            continue
        cursor = section.raw_start
        while True:
            offset = data.find(_CONFIG_MARKER, cursor, section.raw_end)
            if offset < 0:
                break
            cursor = offset + 2
            if (offset - section.raw_start) % 2:
                continue
            observed += 1
            if observed > MAXIMUM_CONFIG_CANDIDATES:
                return (), observed, False
            decoded = _decode_utf16z(data, offset, section.raw_end)
            if decoded is None:
                complete = False
                continue
            text, end = decoded
            candidate = _parse_candidate(
                text,
                address=section.address + offset - section.raw_start,
                raw_start=offset,
                raw_end=end,
            )
            if candidate is not None:
                candidates.append(candidate)
    return tuple(candidates), observed, complete


def _import_map(image: object) -> tuple[dict[int, str], dict[str, object]] | None:
    descriptors = list(getattr(image, "DIRECTORY_ENTRY_IMPORT", ()))
    if not 1 <= len(descriptors) <= MAXIMUM_IMPORT_DESCRIPTORS:
        return None
    mapping: dict[int, str] = {}
    winsock_sets: list[set[str]] = []
    all_names: set[str] = set()
    count = 0
    for descriptor in descriptors:
        try:
            library = bytes(descriptor.dll).decode("ascii", errors="strict").casefold()
            imports = list(descriptor.imports)
        except (AttributeError, TypeError, UnicodeError, ValueError, OverflowError):
            return None
        descriptor_names: set[str] = set()
        for item in imports:
            count += 1
            if count > MAXIMUM_IMPORTS:
                return None
            raw_name = getattr(item, "name", None)
            if raw_name is None:
                continue
            if (
                not isinstance(raw_name, bytes)
                or not 1 <= len(raw_name) <= MAXIMUM_IMPORT_NAME
            ):
                return None
            try:
                name = raw_name.decode("ascii", errors="strict").casefold()
                address = int(item.address)
            except (UnicodeError, TypeError, ValueError, OverflowError):
                return None
            if not 0 < address <= 0xFFFFFFFF or (
                address in mapping and mapping[address] != name
            ):
                return None
            mapping[address] = name
            descriptor_names.add(name)
            all_names.add(name)
        if library in {"ws2_32.dll", "wsock32.dll"}:
            winsock_sets.append(descriptor_names)
    required = {
        "startup": {"wsastartup"},
        "socket": {"socket", "wsasocketa", "wsasocketw"},
        "resolve": {"gethostbyname", "getaddrinfo", "getaddrinfow"},
        "port": {"htons", "ntohs"},
        "connect": {"connect", "wsaconnect"},
        "send": {"send", "wsasend"},
        "receive": {"recv", "wsarecv"},
    }
    validated = [
        names
        for names in winsock_sets
        if all(bool(names & choices) for choices in required.values())
    ]
    evidence = {
        "import_descriptor_count": len(descriptors),
        "import_count": count,
        "winsock_descriptor_count": len(winsock_sets),
        "validated_winsock_descriptor_count": len(validated),
        "required_groups": {
            key: len(validated) == 1 and bool(validated[0] & choices)
            for key, choices in required.items()
        },
        "stage_memory_api_present": "virtualalloc" in all_names,
        "registry_write_api_present": "regsetvalueexw" in all_names,
        "thread_api_present": "createthread" in all_names,
    }
    if len(validated) != 1:
        return mapping, evidence
    return mapping, evidence


def _mapped_instruction(
    data: bytes, sections: tuple[_Section, ...], disassembler: Cs, address: int
) -> object | None:
    section = _section_for_address(sections, address, executable=True)
    if section is None:
        return None
    offset = section.offset(address)
    window = data[offset : min(section.raw_end, offset + 15)]
    try:
        return next(disassembler.disasm(window, address, count=1), None)
    except CsError:
        return None


def _direct_target(instruction: object) -> int | None:
    try:
        operands = instruction.operands
    except (AttributeError, CsError):
        return None
    if len(operands) == 1 and operands[0].type == X86_OP_IMM:
        return int(operands[0].imm) & 0xFFFFFFFF
    return None


def _iat_api(instruction: object, imports: dict[int, str]) -> str | None:
    try:
        operands = instruction.operands
    except (AttributeError, CsError):
        return None
    if len(operands) != 1 or operands[0].type != X86_OP_MEM:
        return None
    memory = operands[0].mem
    if memory.base != X86_REG_INVALID or memory.index != X86_REG_INVALID:
        return None
    return imports.get(int(memory.disp) & 0xFFFFFFFF)


def _decode_function(
    data: bytes,
    sections: tuple[_Section, ...],
    imports: dict[int, str],
    disassembler: Cs,
    start: int,
) -> _Function:
    if _section_for_address(sections, start, executable=True) is None:
        return _Function(start, (), (), (), (), (), (), False)
    pending: deque[int] = deque([start])
    queued: set[int] = {start}
    instructions: dict[int, object] = {}
    direct_calls: list[int] = []
    direct_sites: list[tuple[int, int]] = []
    api_sites: list[tuple[int, str]] = []
    immediates: list[int] = []
    indirect_offsets: list[int] = []
    complete = True
    while pending:
        address = pending.popleft()
        queued.discard(address)
        while address not in instructions:
            if len(instructions) >= MAXIMUM_FUNCTION_INSTRUCTIONS:
                complete = False
                pending.clear()
                break
            instruction = _mapped_instruction(data, sections, disassembler, address)
            if instruction is None:
                complete = False
                break
            instructions[address] = instruction
            try:
                operands = instruction.operands
            except (AttributeError, CsError):
                complete = False
                break
            for operand in operands:
                if operand.type == X86_OP_IMM:
                    immediates.append(int(operand.imm) & 0xFFFFFFFF)
                elif operand.type == X86_OP_MEM:
                    memory = operand.mem
                    if (
                        memory.base == X86_REG_INVALID
                        and memory.index == X86_REG_INVALID
                    ):
                        immediates.append(int(memory.disp) & 0xFFFFFFFF)
            next_address = address + int(instruction.size)
            try:
                is_call = instruction.group(CS_GRP_CALL)
                is_jump = instruction.group(CS_GRP_JUMP)
                is_return = instruction.group(CS_GRP_RET)
            except CsError:
                complete = False
                break
            if is_call:
                target = _direct_target(instruction)
                if (
                    target is not None
                    and _section_for_address(sections, target, executable=True)
                    is not None
                ):
                    direct_calls.append(target)
                    direct_sites.append((address, target))
                else:
                    api = _iat_api(instruction, imports)
                    if api is not None:
                        api_sites.append((address, api))
                    elif operands and operands[0].type == X86_OP_MEM:
                        indirect_offsets.append(int(operands[0].mem.disp))
                address = next_address
                continue
            if is_return:
                break
            if is_jump:
                target = _direct_target(instruction)
                conditional = instruction.mnemonic.casefold() != "jmp"
                if (
                    target is not None
                    and _section_for_address(sections, target, executable=True)
                    is not None
                ):
                    if target not in instructions and target not in queued:
                        pending.append(target)
                        queued.add(target)
                elif not conditional:
                    break
                if conditional:
                    if next_address not in instructions and next_address not in queued:
                        pending.append(next_address)
                        queued.add(next_address)
                break
            address = next_address
    ordered = tuple(instructions[key] for key in sorted(instructions))
    # MSVCのvirtual callは ``mov edx,[eax+0x10]; call edx`` のように
    # vtable slotをregisterへ一度移す。call operandがmemoryの場合だけでなく、
    # 同じbasic block内の直前loadもslot dispatchとして回収する。
    ordered_view = _Function(start, ordered, (), (), (), (), (), complete)
    for instruction in ordered:
        try:
            operands = instruction.operands
        except (AttributeError, CsError):
            continue
        if (
            not instruction.group(CS_GRP_CALL)
            or len(operands) != 1
            or operands[0].type != X86_OP_REG
        ):
            continue
        call_register = operands[0].reg
        for previous in reversed(
            _previous_contiguous(ordered_view, instruction.address, 16)
        ):
            try:
                previous_operands = previous.operands
            except (AttributeError, CsError):
                continue
            if (
                previous.mnemonic.casefold() == "mov"
                and len(previous_operands) == 2
                and previous_operands[0].type == X86_OP_REG
                and previous_operands[0].reg == call_register
                and previous_operands[1].type == X86_OP_MEM
            ):
                indirect_offsets.append(int(previous_operands[1].mem.disp))
                break
        # recv等をIATからcallee-saved registerへ一度読み、その後 ``call edi``
        # するbuildもある。直前128命令内の最近傍の明示writeだけを採用し、
        # 別writeや曖昧なaliasを越えて推測しない。
        preceding = [item for item in ordered if item.address < instruction.address]
        for previous in reversed(preceding[-128:]):
            try:
                previous_operands = previous.operands
            except (AttributeError, CsError):
                continue
            if (
                not previous_operands
                or previous_operands[0].type != X86_OP_REG
                or previous_operands[0].reg != call_register
            ):
                continue
            if (
                previous.mnemonic.casefold() == "mov"
                and len(previous_operands) == 2
                and previous_operands[1].type == X86_OP_MEM
                and previous_operands[1].mem.base == X86_REG_INVALID
                and previous_operands[1].mem.index == X86_REG_INVALID
                and (
                    api := imports.get(int(previous_operands[1].mem.disp) & 0xFFFFFFFF)
                )
                is not None
            ):
                api_sites.append((instruction.address, api))
            break
    return _Function(
        start=start,
        instructions=ordered,
        direct_calls=tuple(dict.fromkeys(direct_calls)),
        direct_call_sites=tuple(direct_sites),
        api_call_sites=tuple(api_sites),
        immediate_values=tuple(immediates),
        indirect_call_offsets=tuple(indirect_offsets),
        complete=complete,
    )


def _previous_contiguous(
    function: _Function, site: int, count: int = 20
) -> list[object]:
    instructions = list(function.instructions)
    index = next((i for i, item in enumerate(instructions) if item.address == site), -1)
    if index < 0:
        return []
    result: list[object] = []
    current = site
    for item in reversed(instructions[max(0, index - count) : index]):
        if item.address + item.size != current:
            break
        result.append(item)
        current = item.address
    result.reverse()
    return result


def _pushed_callback(
    function: _Function, site: int, sections: tuple[_Section, ...]
) -> int | None:
    pushes: list[int | None] = []
    for instruction in _previous_contiguous(function, site, 24):
        if instruction.mnemonic.casefold() != "push":
            continue
        target = _direct_target(instruction)
        pushes.append(target)
    if len(pushes) < 6:
        return None
    callback = pushes[-3]
    if (
        callback is None
        or _section_for_address(sections, callback, executable=True) is None
    ):
        return None
    return callback


def _create_thread_callbacks(
    function: _Function, sections: tuple[_Section, ...]
) -> tuple[tuple[int, int], ...]:
    return tuple(
        (site, callback)
        for site, api in function.api_call_sites
        if api == "createthread"
        and (callback := _pushed_callback(function, site, sections)) is not None
    )


def _exact_wide_addresses(
    data: bytes, sections: tuple[_Section, ...], value: str
) -> tuple[int, ...]:
    needle = value.encode("utf-16le") + b"\0\0"
    result: list[int] = []
    for section in sections:
        if section.executable:
            continue
        cursor = section.raw_start
        while len(result) <= MAXIMUM_VALUE_OCCURRENCES:
            offset = data.find(needle, cursor, section.raw_end)
            if offset < 0:
                break
            cursor = offset + 2
            if (offset - section.raw_start) % 2 == 0:
                result.append(section.address + offset - section.raw_start)
        if len(result) > MAXIMUM_VALUE_OCCURRENCES:
            return ()
    return tuple(result)


def _tag_addresses(
    data: bytes, sections: tuple[_Section, ...], keys: Iterable[str]
) -> dict[str, tuple[int, ...]]:
    return {key: _exact_wide_addresses(data, sections, f"{key}:") for key in keys}


def _closure(
    roots: Iterable[int],
    *,
    data: bytes,
    sections: tuple[_Section, ...],
    imports: dict[int, str],
    disassembler: Cs,
    cache: dict[int, _Function],
    depth_limit: int = MAXIMUM_CLOSURE_DEPTH,
) -> tuple[_Function, ...] | None:
    pending: deque[tuple[int, int]] = deque((root, 0) for root in roots)
    queued = {root for root in roots}
    result: list[_Function] = []
    seen: set[int] = set()
    while pending:
        address, depth = pending.popleft()
        queued.discard(address)
        if address in seen:
            continue
        if depth > depth_limit:
            continue
        if len(seen) >= MAXIMUM_FUNCTIONS_PER_CLOSURE:
            return None
        seen.add(address)
        function = cache.setdefault(
            address, _decode_function(data, sections, imports, disassembler, address)
        )
        if not function.complete:
            return None
        result.append(function)
        if depth >= depth_limit:
            continue
        for target in function.direct_calls:
            if target not in seen and target not in queued:
                pending.append((target, depth + 1))
                queued.add(target)
    return tuple(result)


def _closure_apis(functions: Iterable[_Function]) -> set[str]:
    return {api for function in functions for _site, api in function.api_call_sites}


def _closure_constants(functions: Iterable[_Function]) -> set[int]:
    return {value for function in functions for value in function.immediate_values}


def _read_vtable(
    data: bytes,
    sections: tuple[_Section, ...],
    address: int,
    *,
    minimum_entries: int,
    maximum_entries: int = 12,
) -> tuple[int, ...] | None:
    section = _section_for_address(sections, address, executable=False)
    if section is None or not section.contains_address(address, minimum_entries * 4):
        return None
    offset = section.offset(address)
    entries: list[int] = []
    for index in range(maximum_entries):
        if offset + (index + 1) * 4 > section.raw_end:
            break
        value = struct.unpack_from("<I", data, offset + index * 4)[0]
        if _section_for_address(sections, value, executable=True) is None:
            break
        entries.append(value)
    if len(entries) < minimum_entries:
        return None
    return tuple(entries)


def _vtable_candidates(
    function: _Function,
    data: bytes,
    sections: tuple[_Section, ...],
    *,
    minimum_entries: int,
) -> tuple[tuple[int, ...], ...]:
    result: list[tuple[int, ...]] = []
    for value in dict.fromkeys(function.immediate_values):
        table = _read_vtable(data, sections, value, minimum_entries=minimum_entries)
        if table is not None and table not in result:
            result.append(table)
    return tuple(result)


def _api_socket_fields(functions: Iterable[_Function], api_name: str) -> set[int]:
    fields: set[int] = set()
    for function in functions:
        for site, api in function.api_call_sites:
            if api != api_name:
                continue
            for instruction in _previous_contiguous(function, site, 12):
                try:
                    operands = instruction.operands
                except (AttributeError, CsError):
                    continue
                for operand in operands:
                    if operand.type != X86_OP_MEM:
                        continue
                    displacement = int(operand.mem.disp)
                    if (
                        operand.mem.base != X86_REG_INVALID
                        and 0x20 <= displacement <= 0x400
                    ):
                        fields.add(displacement)
    return fields


def _wrapper_callbacks(
    function: _Function,
    *,
    data: bytes,
    sections: tuple[_Section, ...],
    imports: dict[int, str],
    disassembler: Cs,
    cache: dict[int, _Function],
) -> tuple[int, ...]:
    callbacks: list[int] = []
    for site, target in function.direct_call_sites:
        wrapper = cache.setdefault(
            target,
            _decode_function(data, sections, imports, disassembler, target),
        )
        if not wrapper.complete or "createthread" not in {
            api for _site, api in wrapper.api_call_sites
        }:
            continue
        callback = _pushed_callback(function, site, sections)
        if callback is not None:
            callbacks.append(callback)
    return tuple(dict.fromkeys(callbacks))


def _required_lineage_groups(
    import_evidence: dict[str, object],
) -> dict[str, bool]:
    """単一launcher/worker branchで閉じる証明groupを初期化する。"""

    return {
        "single_validated_winsock_descriptor": import_evidence.get(
            "validated_winsock_descriptor_count"
        )
        == 1,
        "external_root_launcher": False,
        "configuration_source_to_parser": False,
        "parser_field_schema_complete": False,
        "launcher_parser_before_worker": False,
        "runtime_endpoint_globals_referenced": False,
        "worker_transport_vtable_dispatch": False,
        "tcp_connect_send_receive_chain": False,
        "same_socket_field_connect_send_receive": False,
        "winos_framing_and_xor": False,
        "bootstrap_command_04": False,
        "winos_receive_dispatcher": False,
        "received_stage_memory_and_registry_path": False,
    }


def _proof_score(required: dict[str, bool]) -> int:
    """公開値を使わず、同一branch内で成立したgroup数だけを数える。"""

    return sum(1 for proven in required.values() if proven)


def _analyze_lineage(
    data: bytes,
    image: object,
    sections: tuple[_Section, ...],
    imports: dict[int, str],
    import_evidence: dict[str, object],
    candidate: _ConfigCandidate,
) -> dict[str, object]:
    required = _required_lineage_groups(import_evidence)
    coverage: dict[str, object] = {
        "external_root_count": 0,
        "export_root_count": 0,
        "parser_field_reference_count": 0,
        "configuration_reference_count": 0,
        "runtime_field_reference_count": 0,
        "socket_vtable_candidate_count": 0,
        "receive_callback_count": 0,
        "manager_vtable_candidate_count": 0,
        "evaluated_socket_table_branch_count": 0,
        "evaluated_manager_table_branch_count": 0,
        "launcher_worker_candidate_count": 0,
        "analyzed_launcher_worker_branch_count": 0,
        "complete_launcher_worker_branch_count": 0,
        "proof_combined_across_branches": False,
        "proof_scope": "single_launcher_worker_socket_and_manager_lineage",
        "analyzed_function_count": 0,
        "budget_exhausted": False,
    }
    external = _external_roots(image, sections)
    if external is None or not external[0]:
        return _lineage_result(required, coverage, import_evidence)
    external_roots, export_count = external
    coverage["external_root_count"] = len(external_roots)
    coverage["export_root_count"] = export_count
    required["external_root_launcher"] = bool(external_roots)
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
    except CsError:
        return _lineage_result(required, coverage, import_evidence)
    cache: dict[int, _Function] = {}

    keys = tuple(key for key, _value in candidate.values)
    tags = _tag_addresses(data, sections, keys)
    if any(not addresses for addresses in tags.values()):
        return _lineage_result(required, coverage, import_evidence)

    parser_functions: dict[int, _Function] = {}
    launchers: list[tuple[_Function, _Function, int, int]] = []
    for root in external_roots:
        launcher = cache.setdefault(
            root, _decode_function(data, sections, imports, disassembler, root)
        )
        if not launcher.complete:
            continue
        callbacks = _create_thread_callbacks(launcher, sections)
        for parser_target in launcher.direct_calls:
            parser = cache.setdefault(
                parser_target,
                _decode_function(data, sections, imports, disassembler, parser_target),
            )
            if not parser.complete:
                continue
            tag_ref_count = sum(
                any(address in parser.immediate_values for address in addresses)
                for addresses in tags.values()
            )
            config_ref_count = parser.immediate_values.count(candidate.address)
            if config_ref_count < len(keys) or tag_ref_count != len(keys):
                continue
            parser_functions[parser_target] = parser
            coverage["parser_field_reference_count"] = max(
                int(coverage["parser_field_reference_count"]), tag_ref_count
            )
            coverage["configuration_reference_count"] = max(
                int(coverage["configuration_reference_count"]), config_ref_count
            )
            required["configuration_source_to_parser"] = True
            required["parser_field_schema_complete"] = True
            for callback_site, callback in callbacks:
                parser_sites = launcher.site_for_direct_call(parser_target)
                if any(site < callback_site for site in parser_sites):
                    launchers.append((launcher, parser, callback_site, callback))
    if not launchers:
        return _lineage_result(required, coverage, import_evidence)
    required["launcher_parser_before_worker"] = True
    coverage["launcher_worker_candidate_count"] = len(launchers)

    fields = candidate.fields
    source_addresses: dict[str, tuple[int, ...]] = {}
    for index in (1, 2, 3):
        for prefix in ("p", "o"):
            key = f"{prefix}{index}"
            value = fields[key]
            if not value:
                continue
            addresses = tuple(
                address
                for address in _exact_wide_addresses(data, sections, value)
                if not candidate.address
                <= address
                < candidate.address + (candidate.raw_end - candidate.raw_start)
            )
            source_addresses[key] = addresses

    best_required = required
    best_budget_exhausted = False
    best_score = -1
    for _launcher, _parser, _site, worker_address in launchers:
        branch_required = _required_lineage_groups(import_evidence)
        for group in (
            "external_root_launcher",
            "configuration_source_to_parser",
            "parser_field_schema_complete",
            "launcher_parser_before_worker",
        ):
            branch_required[group] = True
        branch_budget_exhausted = False
        coverage["analyzed_launcher_worker_branch_count"] = (
            int(coverage["analyzed_launcher_worker_branch_count"]) + 1
        )
        worker = cache.setdefault(
            worker_address,
            _decode_function(data, sections, imports, disassembler, worker_address),
        )
        if worker.complete:
            referenced = {
                key
                for key, addresses in source_addresses.items()
                if addresses
                and any(address in worker.immediate_values for address in addresses)
            }
            coverage["runtime_field_reference_count"] = max(
                int(coverage["runtime_field_reference_count"]), len(referenced)
            )
            if referenced == source_addresses.keys():
                branch_required["runtime_endpoint_globals_referenced"] = True
                dispatch_offsets = set(worker.indirect_call_offsets)
                branch_required["worker_transport_vtable_dispatch"] = {
                    0x08,
                    0x10,
                    0x14,
                }.issubset(dispatch_offsets)
                worker_constants = set(worker.immediate_values)
                branch_required["bootstrap_command_04"] = (
                    4 in worker_constants
                    and 2 in worker_constants
                    and 0x08 in dispatch_offsets
                )

                socket_tables: list[tuple[int, ...]] = []
                manager_tables: list[tuple[int, ...]] = []
                for target in worker.direct_calls:
                    function = cache.setdefault(
                        target,
                        _decode_function(data, sections, imports, disassembler, target),
                    )
                    if not function.complete:
                        continue
                    direct_apis = {api for _site, api in function.api_call_sites}
                    if "wsastartup" in direct_apis:
                        socket_tables.extend(
                            _vtable_candidates(
                                function,
                                data,
                                sections,
                                minimum_entries=6,
                            )
                        )
                    manager_tables.extend(
                        _vtable_candidates(
                            function,
                            data,
                            sections,
                            minimum_entries=1,
                        )
                    )
                socket_tables = list(dict.fromkeys(socket_tables))
                manager_tables = [
                    table
                    for table in dict.fromkeys(manager_tables)
                    if table not in socket_tables
                ]
                coverage["socket_vtable_candidate_count"] = max(
                    int(coverage["socket_vtable_candidate_count"]),
                    len(socket_tables),
                )
                coverage["manager_vtable_candidate_count"] = max(
                    int(coverage["manager_vtable_candidate_count"]),
                    len(manager_tables),
                )
                coverage["evaluated_socket_table_branch_count"] = int(
                    coverage["evaluated_socket_table_branch_count"]
                ) + len(socket_tables)
                coverage["evaluated_manager_table_branch_count"] = int(
                    coverage["evaluated_manager_table_branch_count"]
                ) + len(manager_tables)

                socket_required = {
                    "tcp_connect_send_receive_chain": False,
                    "same_socket_field_connect_send_receive": False,
                    "winos_framing_and_xor": False,
                }
                socket_score = 0
                socket_budget_exhausted = False
                for table in socket_tables:
                    table_required = {
                        "tcp_connect_send_receive_chain": False,
                        "same_socket_field_connect_send_receive": False,
                        "winos_framing_and_xor": False,
                    }
                    connect_root, send_root = table[4], table[2]
                    connect_function = cache.setdefault(
                        connect_root,
                        _decode_function(
                            data,
                            sections,
                            imports,
                            disassembler,
                            connect_root,
                        ),
                    )
                    connect_functions = (
                        (connect_function,) if connect_function.complete else None
                    )
                    send_functions = _closure(
                        (send_root,),
                        data=data,
                        sections=sections,
                        imports=imports,
                        disassembler=disassembler,
                        cache=cache,
                        depth_limit=2,
                    )
                    if connect_functions is None or send_functions is None:
                        socket_budget_exhausted = True
                        continue
                    connect_apis = _closure_apis(connect_functions)
                    send_apis = _closure_apis(send_functions)
                    connect_required = {
                        "socket",
                        "gethostbyname",
                        "connect",
                    }.issubset(connect_apis) and bool({"htons", "ntohs"} & connect_apis)
                    if not connect_required or "send" not in send_apis:
                        continue
                    receive_roots = _wrapper_callbacks(
                        connect_function,
                        data=data,
                        sections=sections,
                        imports=imports,
                        disassembler=disassembler,
                        cache=cache,
                    )
                    receive_functions = _closure(
                        receive_roots,
                        data=data,
                        sections=sections,
                        imports=imports,
                        disassembler=disassembler,
                        cache=cache,
                        depth_limit=3,
                    )
                    if not receive_roots or receive_functions is None:
                        continue
                    coverage["receive_callback_count"] = max(
                        int(coverage["receive_callback_count"]),
                        len(receive_roots),
                    )
                    receive_apis = _closure_apis(receive_functions)
                    if "recv" not in receive_apis:
                        continue
                    table_required["tcp_connect_send_receive_chain"] = True
                    common_fields = (
                        _api_socket_fields(connect_functions, "connect")
                        & _api_socket_fields(send_functions, "send")
                        & _api_socket_fields(receive_functions, "recv")
                    )
                    table_required["same_socket_field_connect_send_receive"] = (
                        len(common_fields) == 1
                    )
                    send_constants = _closure_constants(send_functions)
                    send_mnemonics = {
                        instruction.mnemonic.casefold()
                        for function in send_functions
                        for instruction in function.instructions
                    }
                    table_required["winos_framing_and_xor"] = {
                        4,
                        10,
                        14,
                        0x36,
                        0x1C8,
                    }.issubset(send_constants) and "xor" in send_mnemonics
                    table_score = _proof_score(table_required)
                    if table_score > socket_score:
                        socket_required = table_required
                        socket_score = table_score
                    if table_score == len(table_required):
                        break
                branch_required.update(socket_required)
                if socket_score < len(socket_required) and socket_budget_exhausted:
                    branch_budget_exhausted = True

                manager_required = {
                    "winos_receive_dispatcher": False,
                    "received_stage_memory_and_registry_path": False,
                }
                manager_score = 0
                for table in manager_tables:
                    handler = cache.setdefault(
                        table[0],
                        _decode_function(
                            data,
                            sections,
                            imports,
                            disassembler,
                            table[0],
                        ),
                    )
                    if not handler.complete:
                        continue
                    constants = set(handler.immediate_values)
                    apis = {api for _site, api in handler.api_call_sites}
                    table_required = {
                        "winos_receive_dispatcher": {
                            0xC9,
                            0x65,
                        }.issubset(constants),
                        "received_stage_memory_and_registry_path": (
                            {0xC9, 0x65}.issubset(constants)
                            and "virtualalloc" in apis
                            and "regsetvalueexw" in apis
                        ),
                    }
                    table_score = _proof_score(table_required)
                    if table_score > manager_score:
                        manager_required = table_required
                        manager_score = table_score
                    if table_score == len(table_required):
                        break
                branch_required.update(manager_required)

        branch_complete = all(branch_required.values()) and not branch_budget_exhausted
        branch_score = _proof_score(branch_required)
        if branch_complete:
            best_required = branch_required
            best_budget_exhausted = False
            coverage["complete_launcher_worker_branch_count"] = 1
            break
        if branch_score > best_score or (
            branch_score == best_score
            and best_budget_exhausted
            and not branch_budget_exhausted
        ):
            best_required = branch_required
            best_budget_exhausted = branch_budget_exhausted
            best_score = branch_score
    required = best_required
    coverage["budget_exhausted"] = best_budget_exhausted
    coverage["analyzed_function_count"] = len(cache)
    return _lineage_result(required, coverage, import_evidence)


def _lineage_result(
    required: dict[str, bool],
    coverage: dict[str, object],
    import_evidence: dict[str, object],
) -> dict[str, object]:
    matched = all(required.values()) and coverage.get("budget_exhausted") is False
    return {
        "status": (
            "terminal_winos_bootstrap_lineage_proven"
            if matched
            else "incomplete_wide_pipe_lineage"
        ),
        "analysis_complete": coverage.get("budget_exhausted") is False,
        "terminal_network_lineage_proven": matched,
        "required_groups": required,
        "coverage": coverage,
        "import_corroboration": import_evidence,
        "protocol": {
            "transport": "tcp",
            "frame_prefix_size": 4,
            "header_size": 10,
            "payload_offset": 14,
            "payload_transform": "header_derived_xor",
            "initial_command": "0x0004",
            "dispatcher_command_marker": "0xc9",
            "raw_payload_included": False,
        },
        "raw_addresses_included": False,
        "raw_config_included": False,
        "raw_network_values_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def recover_config(data: bytes) -> WidePipeConfigRecovery | None:
    """一意なpipe設定を復元し、完全なWinos系譜なら終端確定する。"""

    if (
        not isinstance(data, bytes)
        or not data.startswith(b"MZ")
        or len(data) > MAXIMUM_INPUT_SIZE
    ):
        return None
    try:
        image = pefile.PE(data=data, fast_load=False)
        machine = int(image.FILE_HEADER.Machine)
    except (pefile.PEFormatError, AttributeError, TypeError, ValueError, OverflowError):
        return None
    if machine != 0x14C:
        return None
    sections = _sections(image, data)
    if sections is None:
        return None
    candidates, observed, scan_complete = _config_candidates(data, sections)
    if not scan_complete or not candidates:
        return None
    identities = {candidate.identity for candidate in candidates}
    if len(identities) != 1:
        return None
    candidate = candidates[0]
    imported = _import_map(image)
    if imported is None:
        return None
    imports, import_evidence = imported
    lineage = _analyze_lineage(
        data, image, sections, imports, import_evidence, candidate
    )
    endpoints = tuple(
        dict.fromkeys(
            slot.endpoint for slot in candidate.slots if slot.endpoint is not None
        )
    )
    identity_blob = "\n".join(
        f"{key}|{value}" for key, value in candidate.identity
    ).encode("utf-8")
    return WidePipeConfigRecovery(
        endpoints=endpoints,
        slots=candidate.slots,
        configuration_identity_sha256=hashlib.sha256(identity_blob).hexdigest(),
        candidate_count=len(candidates),
        terminal_family_confirmed=lineage["terminal_network_lineage_proven"] is True,
        evidence={
            "status": (
                "decoded_static_config"
                if lineage["terminal_network_lineage_proven"] is True
                else "decoded_candidate_config"
            ),
            "configuration_style": "winos_plaintext_utf16_pipe",
            "candidate_count": len(candidates),
            "observed_marker_count": observed,
            "unique_configuration_count": 1,
            "configured_slot_count": len(candidate.slots),
            "external_endpoint_count": len(endpoints),
            "excluded_loopback_slot_count": sum(
                slot.endpoint is None and bool(slot.host) for slot in candidate.slots
            ),
            "tcp_slot_count": sum(slot.transport == 1 for slot in candidate.slots),
            "udp_slot_count": sum(slot.transport == 0 for slot in candidate.slots),
            "field_count": len(candidate.values),
            "lineage": lineage,
            "raw_config_included": False,
            "raw_network_values_included": False,
            "raw_build_metadata_included": False,
            "sample_executed": False,
            "network_contacted": False,
        },
    )


def public_recovery_summary(recovery: WidePipeConfigRecovery) -> dict[str, object]:
    """endpointはcaller側へ残し、構造・系譜だけの公開要約を返す。"""

    return dict(recovery.evidence)


def probe_config(data: bytes) -> dict[str, object]:
    """detector向けにendpoint値を含めない静的probe結果を返す。"""

    recovery = recover_config(data)
    if recovery is None:
        return _empty_probe()
    terminal = recovery.terminal_family_confirmed
    return {
        "matched": True,
        "family": "valleyrat" if terminal else None,
        "variant": (
            "winos_plaintext_pipe_bootstrap_terminal"
            if terminal
            else "winos_plaintext_pipe_config_candidate"
        ),
        "supports_family_attribution": terminal,
        "attribution_scope": (
            "validated_winos_bootstrap_component"
            if terminal
            else "component_handler_route"
        ),
        "terminal_family_confirmed": terminal,
        "family_attribution_basis": (
            "unique_pipe_config_parser_runtime_globals_tcp_vtable_winos_frame_dispatcher"
            if terminal
            else "unique_plaintext_pipe_config_without_complete_network_lineage"
        ),
        "classification_confidence": (
            "high_structural_decoded_config"
            if terminal
            else "medium_candidate_decoded_config"
        ),
        "static_config_recovered": terminal,
        "candidate_config_recovered": not terminal,
        "evidence": {"wide_pipe_config": public_recovery_summary(recovery)},
        "config": {
            "endpoint_count": len(recovery.endpoints),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "MAXIMUM_INPUT_SIZE",
    "WidePipeConfigError",
    "WidePipeConfigRecovery",
    "WidePipeSlot",
    "probe_config",
    "public_recovery_summary",
    "recover_config",
]
