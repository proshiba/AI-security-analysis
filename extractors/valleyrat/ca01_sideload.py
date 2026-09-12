"""CA01系x64 VulkanサイドロードDLLの設定を実行せず復元する。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

import pefile
from capstone import CS_AC_WRITE, CS_ARCH_X86, CS_MODE_64, Cs, CsError, x86_const
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EAX,
    X86_REG_EBP,
    X86_REG_ECX,
    X86_REG_EDX,
    X86_REG_ESP,
    X86_REG_INVALID,
    X86_REG_R8,
    X86_REG_R8D,
    X86_REG_R9,
    X86_REG_R9D,
    X86_REG_RAX,
    X86_REG_RBP,
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RIP,
    X86_REG_RSP,
)

MAXIMUM_INPUT_SIZE = 32 * 1024 * 1024
MAXIMUM_SECTION_COUNT = 96
MAXIMUM_EXECUTABLE_BYTES = 8 * 1024 * 1024
MAXIMUM_SCANNED_DATA_BYTES = 16 * 1024 * 1024
MAXIMUM_IMPORT_DESCRIPTORS = 1_024
MAXIMUM_IMPORTS = 65_536
MAXIMUM_IMPORT_NAME_LENGTH = 128
MAXIMUM_IMPORT_DLL_NAME_LENGTH = 128
MAXIMUM_EXPORTS = 4_096
MAXIMUM_EXPORT_NAME_LENGTH = 256
MAXIMUM_BASE64_RUNS = 4_096
MAXIMUM_BASE64_RUN_BYTES = 2 * 1024 * 1024
MAXIMUM_BASE64_TOKEN_LENGTH = 256
MAXIMUM_FUNCTION_INSTRUCTIONS = 16_384
MAXIMUM_TOTAL_INSTRUCTIONS = 200_000
MAXIMUM_MAIN_CALLEES = 512
MAXIMUM_THREAD_CALLEES = 128
MAXIMUM_LINKED_CODE_REFERENCES = 32
MAXIMUM_FUNCTION_CODE_REFERENCES = 512
MAXIMUM_UNRESOLVED_CONTROL_FLOW = 32
MAXIMUM_PRODUCER_CANDIDATES = 32
MAXIMUM_DECODER_TABLE_WRITES = 256
MAXIMUM_TOKEN_REFERENCES_PER_CANDIDATE = 64
MAXIMUM_LITERAL_COPY_CANDIDATES = 64
MAXIMUM_OBJECT_COPY_CANDIDATES = 64
MAXIMUM_WINDOW_DIRECT_CALLS = 256
MAXIMUM_CONSUMER_PREPARATION_CALLS = 64
MAXIMUM_POST_CALLS = 32
MAXIMUM_CFG_EDGE_COUNT = 65_536
MAXIMUM_EVENT_SEQUENCE_LENGTH = 128
MAXIMUM_REGISTER_SOURCE_STATES = 4_096
MAXIMUM_DECODER_LINEAGES = 32
MAXIMUM_COPY_HELPER_INSTRUCTIONS = 2_048
MAXIMUM_CONSUMER_INSTRUCTIONS = 1_024
MAXIMUM_CEF_EXPORTS = 512

_X64_MACHINE = 0x8664
_EXECUTABLE_SECTION = 0x20000000
_RESOURCE_DIRECTORY_INDEX = 2
_SECURITY_DIRECTORY_INDEX = 4
_VULKAN_EXPORT = b"vkEnumerateInstanceVersion"
_REQUIRED_KERNEL_APIS = frozenset({"createthread", "virtualprotect", "sleep"})
_ALLOWED_KERNEL_DLLS = frozenset({"kernel32.dll", "kernelbase.dll"})
_ALLOWED_BEGINTHREADEX_DLLS = frozenset(
    {"api-ms-win-crt-runtime-l1-1-0.dll", "ucrtbase.dll"}
)
_VULKAN_OUTER_PROFILE = "vulkan_export_create_thread"
_CEF_OUTER_PROFILE = "cef_alias_export_beginthreadex"
_CEF_EXPORT_DLL_NAME = b"IndCode.dll"
_REQUIRED_CEF_EXPORTS = frozenset(
    {
        b"cef_api_hash",
        b"cef_browser_host_create_browser",
        b"cef_do_message_loop_work",
        b"cef_execute_process",
        b"cef_initialize",
        b"cef_shutdown",
    }
)
_CEF_LOADER_MARKERS = (
    "OpenraVPN",
    "Loader.exe",
    "RemoteController_Outbound_Rule",
    "RemoteController_Inbound_Rule",
    "ServiceController",
    "--portability",
    "-onlyctrl",
    "-reonlyctrl",
    "ip-api.com",
    "RunCodeTask",
)
_REVIEWED_CA01_OUTER_PROFILES = {
    "22d1b5576ccb3c425a94e405076a0665efa0dd2d59325bfb561b6b16969e267f": (
        _VULKAN_OUTER_PROFILE
    ),
}
_REVIEWED_CA01_OUTER_SHA256 = next(iter(_REVIEWED_CA01_OUTER_PROFILES))
_VULKAN_STRUCTURAL_EVIDENCE_KEYS = frozenset(
    {
        "vulkan_export_count",
        "export_reachable_thread_config_lineage_present",
        "create_thread_wrapper_reachable",
    }
)
_CEF_STRUCTURAL_EVIDENCE_KEYS = frozenset(
    {
        "cef_export_count",
        "cef_named_export_count",
        "cef_export_count_with_prefix",
        "cef_required_export_count",
        "coalesced_export_target_count",
        "coalesced_export_peak_count",
        "export_dll_name_matches_indcode",
        "mapped_loader_marker_count",
        "mapped_loader_marker_set_complete",
        "export_reachable_beginthreadex_config_lineage_present",
        "beginthreadex_wrapper_reachable",
    }
)
_VULKAN_LINEAGE_EVIDENCE_KEYS = frozenset(
    {
        "main_to_thread_factory_direct_call_count",
        "thread_factory_to_create_thread_wrapper_count",
    }
)
_CEF_LINEAGE_EVIDENCE_KEYS = frozenset(
    {
        "main_to_beginthreadex_wrapper_direct_call_count",
        "beginthreadex_api_call_count",
        "producer_pointer_store_count",
        "callback_trampoline_indirect_call_count",
    }
)
_BASE64_RUN = re.compile(
    rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{16,256}(?![A-Za-z0-9+/=])"
)
_HOSTNAME = re.compile(
    r"(?i)(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_REGISTER_FAMILY_BY_ID = {
    x86_const.X86_REG_RAX: "rax",
    x86_const.X86_REG_EAX: "rax",
    x86_const.X86_REG_RBX: "rbx",
    x86_const.X86_REG_EBX: "rbx",
    x86_const.X86_REG_RCX: "rcx",
    x86_const.X86_REG_ECX: "rcx",
    x86_const.X86_REG_RDX: "rdx",
    x86_const.X86_REG_EDX: "rdx",
    x86_const.X86_REG_RSI: "rsi",
    x86_const.X86_REG_ESI: "rsi",
    x86_const.X86_REG_RDI: "rdi",
    x86_const.X86_REG_EDI: "rdi",
    x86_const.X86_REG_RBP: "rbp",
    x86_const.X86_REG_EBP: "rbp",
    x86_const.X86_REG_RSP: "rsp",
    x86_const.X86_REG_ESP: "rsp",
    x86_const.X86_REG_R8: "r8",
    x86_const.X86_REG_R8D: "r8",
    x86_const.X86_REG_R9: "r9",
    x86_const.X86_REG_R9D: "r9",
    x86_const.X86_REG_R10: "r10",
    x86_const.X86_REG_R10D: "r10",
    x86_const.X86_REG_R11: "r11",
    x86_const.X86_REG_R11D: "r11",
    x86_const.X86_REG_R12: "r12",
    x86_const.X86_REG_R12D: "r12",
    x86_const.X86_REG_R13: "r13",
    x86_const.X86_REG_R13D: "r13",
    x86_const.X86_REG_R14: "r14",
    x86_const.X86_REG_R14D: "r14",
    x86_const.X86_REG_R15: "r15",
    x86_const.X86_REG_R15D: "r15",
}


class Ca01SideloadError(ValueError):
    """CA01設定または外層data-flowの検証に失敗した場合の例外。"""


@dataclass(frozen=True)
class _Section:
    """重複のないfile-backed PE section。"""

    name: str
    virtual_start: int
    virtual_end: int
    raw_start: int
    raw_end: int
    executable: bool
    resource: bool


@dataclass(frozen=True)
class _TokenCandidate:
    """非公開の二重Base64候補。"""

    address: int
    length: int
    host: str


@dataclass(frozen=True)
class _CefExportProfile:
    """同一stubへ集約されたCEF互換export facade。"""

    root: int
    export_count: int
    cef_export_count: int


@dataclass(frozen=True)
class _CefCallbackLineage:
    """CEF alias stubから_beginthreadex callbackへ至る一意なlineage。"""

    producer: int
    export_to_main_direct_call_count: int
    main_to_beginthreadex_wrapper_direct_call_count: int
    beginthreadex_api_call_count: int
    producer_pointer_store_count: int
    callback_trampoline_indirect_call_count: int


@dataclass
class _FunctionSummary:
    """1 function rootから有界CFGで得た静的要約。"""

    start: int
    instructions: dict[int, Any]
    direct_calls: set[int]
    direct_call_counts: dict[int, int]
    executable_references: set[int]
    api_calls: list[tuple[int, str]]
    unresolved_control_flow_count: int = 0
    raw_predecessors: dict[int, tuple[int, ...]] | None = None
    predecessors: dict[int, tuple[int, ...]] | None = None
    reachable_addresses: frozenset[int] | None = None


@dataclass(frozen=True)
class _LiteralCopy:
    """stack stringへの静的literal copy。"""

    instruction_index: int
    call_address: int
    target: int
    destination: tuple[str, int]
    value: str
    length: int


@dataclass(frozen=True)
class _ObjectCopy:
    """stack string間のcopy。"""

    instruction_index: int
    call_address: int
    target: int
    destination: tuple[str, int]
    source: tuple[str, int]


@dataclass(frozen=True)
class Ca01SideloadRecovery:
    """CA01外層と同一lineageで検証した設定。"""

    outer_sha256: str
    config: dict[str, object]
    structural_evidence: dict[str, object]


def _unmatched_probe() -> dict[str, object]:
    return {
        "matched": False,
        "family": None,
        "variant": None,
        "supports_family_attribution": False,
        "static_config_recovered": False,
        "evidence": {},
        "config": {},
        "sample_executed": False,
        "network_contacted": False,
    }


def _sections(image: pefile.PE, data: bytes) -> tuple[list[_Section], int] | None:
    """file-backed sectionを検証し、overlayとresourceを明示的に除外可能にする。"""

    try:
        raw_sections = list(image.sections)
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not raw_sections or len(raw_sections) > MAXIMUM_SECTION_COUNT:
        return None

    resource_start = resource_end = 0
    try:
        directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[_RESOURCE_DIRECTORY_INDEX]
        resource_rva = int(directory.VirtualAddress)
        resource_size = int(directory.Size)
        if resource_rva > 0 and resource_size > 0:
            resource_start = image_base + resource_rva
            resource_end = resource_start + resource_size
    except (AttributeError, IndexError, TypeError, ValueError, OverflowError):
        resource_start = resource_end = 0

    result: list[_Section] = []
    executable_bytes = 0
    scanned_data_bytes = 0
    for raw_section in raw_sections:
        try:
            raw_name = raw_section.Name
            virtual_address = int(raw_section.VirtualAddress)
            virtual_size = int(raw_section.Misc_VirtualSize)
            raw_start = int(raw_section.PointerToRawData)
            raw_size = int(raw_section.SizeOfRawData)
            characteristics = int(raw_section.Characteristics)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if (
            not isinstance(raw_name, bytes)
            or min(virtual_address, virtual_size, raw_start, raw_size) < 0
        ):
            return None
        mapped_size = min(raw_size, virtual_size or raw_size)
        if mapped_size <= 0:
            continue
        raw_end = raw_start + mapped_size
        virtual_start = image_base + virtual_address
        virtual_end = virtual_start + mapped_size
        if raw_end > len(data) or virtual_end <= virtual_start:
            return None
        name = raw_name.rstrip(b"\0").decode("ascii", errors="replace").casefold()
        executable = bool(characteristics & _EXECUTABLE_SECTION)
        resource = name == ".rsrc" or (
            resource_end > resource_start
            and virtual_start < resource_end
            and resource_start < virtual_end
        )
        if executable:
            executable_bytes += mapped_size
            if executable_bytes > MAXIMUM_EXECUTABLE_BYTES:
                return None
        elif not resource:
            scanned_data_bytes += mapped_size
            if scanned_data_bytes > MAXIMUM_SCANNED_DATA_BYTES:
                return None
        result.append(
            _Section(
                name=name,
                virtual_start=virtual_start,
                virtual_end=virtual_end,
                raw_start=raw_start,
                raw_end=raw_end,
                executable=executable,
                resource=resource,
            )
        )

    if not result:
        return None
    for index, section in enumerate(result):
        for other in result[index + 1 :]:
            if (
                section.raw_start < other.raw_end and other.raw_start < section.raw_end
            ) or (
                section.virtual_start < other.virtual_end
                and other.virtual_start < section.virtual_end
            ):
                return None
    return result, image_base


def _section_for_address(
    sections: list[_Section],
    address: int,
    *,
    executable: bool | None = None,
) -> _Section | None:
    matches = [
        section
        for section in sections
        if section.virtual_start <= address < section.virtual_end
        and (executable is None or section.executable is executable)
    ]
    return matches[0] if len(matches) == 1 else None


def _raw_offset(sections: list[_Section], address: int, length: int = 1) -> int | None:
    section = _section_for_address(sections, address)
    if section is None or length < 0 or address + length > section.virtual_end:
        return None
    offset = section.raw_start + address - section.virtual_start
    return offset if offset + length <= section.raw_end else None


def _import_addresses(image: pefile.PE) -> dict[int, str] | None:
    """IAT VAを正規化名へ対応付け、alias conflictを拒否する。"""

    try:
        entries = list(image.DIRECTORY_ENTRY_IMPORT)
    except AttributeError:
        return None
    if not entries or len(entries) > MAXIMUM_IMPORT_DESCRIPTORS:
        return None
    result: dict[int, str] = {}
    import_count = 0
    required_descriptors: list[frozenset[str]] = []
    required_counts = {name: 0 for name in _REQUIRED_KERNEL_APIS}
    for entry in entries:
        try:
            imports = list(entry.imports)
            raw_dll = entry.dll
        except AttributeError:
            return None
        if (
            not isinstance(raw_dll, bytes)
            or len(raw_dll) > MAXIMUM_IMPORT_DLL_NAME_LENGTH
        ):
            return None
        try:
            dll = raw_dll.decode("ascii", errors="strict").casefold()
        except UnicodeError:
            return None
        import_count += len(imports)
        if import_count > MAXIMUM_IMPORTS:
            return None
        descriptor_required: set[str] = set()
        for item in imports:
            try:
                raw_name = item.name
                address = int(item.address)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None
            if raw_name is None:
                continue
            if (
                not isinstance(raw_name, bytes)
                or len(raw_name) > MAXIMUM_IMPORT_NAME_LENGTH
                or address <= 0
            ):
                return None
            try:
                name = raw_name.decode("ascii", errors="strict").casefold()
            except UnicodeError:
                return None
            previous = result.get(address)
            if previous is not None and previous != name:
                return None
            result[address] = name
            if name in _REQUIRED_KERNEL_APIS:
                if dll not in _ALLOWED_KERNEL_DLLS:
                    return None
                descriptor_required.add(name)
                required_counts[name] += 1
        if descriptor_required:
            required_descriptors.append(frozenset(descriptor_required))
    if (
        len(required_descriptors) != 1
        or required_descriptors[0] != _REQUIRED_KERNEL_APIS
        or any(required_counts[name] != 1 for name in _REQUIRED_KERNEL_APIS)
    ):
        return None
    return result


def _cef_import_addresses(image: pefile.PE) -> dict[int, str] | None:
    """CEF profileのKERNEL APIと_beginthreadex所有元を個別に検証する。"""

    try:
        entries = list(image.DIRECTORY_ENTRY_IMPORT)
    except AttributeError:
        return None
    if not entries or len(entries) > MAXIMUM_IMPORT_DESCRIPTORS:
        return None
    result: dict[int, str] = {}
    import_count = 0
    required_counts = {
        "virtualprotect": 0,
        "sleep": 0,
        "_beginthreadex": 0,
    }
    kernel_descriptors: list[frozenset[str]] = []
    beginthreadex_descriptors: list[frozenset[str]] = []
    for entry in entries:
        try:
            imports = list(entry.imports)
            raw_dll = entry.dll
        except AttributeError:
            return None
        if (
            not isinstance(raw_dll, bytes)
            or len(raw_dll) > MAXIMUM_IMPORT_DLL_NAME_LENGTH
        ):
            return None
        try:
            dll = raw_dll.decode("ascii", errors="strict").casefold()
        except UnicodeError:
            return None
        import_count += len(imports)
        if import_count > MAXIMUM_IMPORTS:
            return None
        descriptor_kernel: set[str] = set()
        descriptor_beginthreadex: set[str] = set()
        for item in imports:
            try:
                raw_name = item.name
                address = int(item.address)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None
            if raw_name is None:
                continue
            if (
                not isinstance(raw_name, bytes)
                or len(raw_name) > MAXIMUM_IMPORT_NAME_LENGTH
                or address <= 0
            ):
                return None
            try:
                name = raw_name.decode("ascii", errors="strict").casefold()
            except UnicodeError:
                return None
            previous = result.get(address)
            if previous is not None and previous != name:
                return None
            result[address] = name
            if name in {"virtualprotect", "sleep"}:
                if dll not in _ALLOWED_KERNEL_DLLS:
                    return None
                required_counts[name] += 1
                descriptor_kernel.add(name)
            elif name == "_beginthreadex":
                if dll not in _ALLOWED_BEGINTHREADEX_DLLS:
                    return None
                required_counts[name] += 1
                descriptor_beginthreadex.add(name)
        if descriptor_kernel:
            kernel_descriptors.append(frozenset(descriptor_kernel))
        if descriptor_beginthreadex:
            beginthreadex_descriptors.append(frozenset(descriptor_beginthreadex))
    if (
        len(kernel_descriptors) != 1
        or kernel_descriptors[0] != frozenset({"virtualprotect", "sleep"})
        or len(beginthreadex_descriptors) != 1
        or beginthreadex_descriptors[0] != frozenset({"_beginthreadex"})
        or any(count != 1 for count in required_counts.values())
        or "createthread" in result.values()
    ):
        return None
    return result


def _export_roots(
    image: pefile.PE, sections: list[_Section], image_base: int
) -> list[int] | None:
    """対象Vulkan exportを一意に解決する。"""

    try:
        symbols = list(image.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        return None
    if not symbols or len(symbols) > MAXIMUM_EXPORTS:
        return None
    roots: list[int] = []
    for symbol in symbols:
        try:
            name = symbol.name
            rva = int(symbol.address)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if name is None:
            continue
        if not isinstance(name, bytes) or len(name) > MAXIMUM_EXPORT_NAME_LENGTH:
            return None
        if name != _VULKAN_EXPORT:
            continue
        address = image_base + rva
        if _section_for_address(sections, address, executable=True) is None:
            return None
        roots.append(address)
    return sorted(set(roots)) if len(set(roots)) == 1 else None


def _cef_export_profile(
    image: pefile.PE,
    sections: list[_Section],
    image_base: int,
) -> _CefExportProfile | None:
    """CEF互換名が一つの実行stubへ集約される既知facadeだけを受理する。"""

    try:
        export_directory = image.DIRECTORY_ENTRY_EXPORT
        symbols = list(export_directory.symbols)
        dll_name = export_directory.name
    except AttributeError:
        return None
    if (
        dll_name != _CEF_EXPORT_DLL_NAME
        or not 128 <= len(symbols) <= MAXIMUM_CEF_EXPORTS
    ):
        return None
    names: set[bytes] = set()
    targets: set[int] = set()
    cef_export_count = 0
    for symbol in symbols:
        try:
            name = symbol.name
            rva = int(symbol.address)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if (
            not isinstance(name, bytes)
            or not name
            or len(name) > MAXIMUM_EXPORT_NAME_LENGTH
            or name in names
            or rva <= 0
        ):
            return None
        address = image_base + rva
        if _section_for_address(sections, address, executable=True) is None:
            return None
        names.add(name)
        targets.add(address)
        if name.startswith(b"cef_"):
            cef_export_count += 1
    if (
        not _REQUIRED_CEF_EXPORTS <= names
        or cef_export_count < 128
        or cef_export_count < len(symbols) - 16
        or len(targets) != 1
    ):
        return None
    return _CefExportProfile(
        root=next(iter(targets)),
        export_count=len(symbols),
        cef_export_count=cef_export_count,
    )


def _cef_loader_markers_present(data: bytes, sections: list[_Section]) -> bool:
    """mapped非resource領域にレビュー済みloader markerが全てあるか確認する。"""

    mapped = [
        data[section.raw_start : section.raw_end]
        for section in sections
        if not section.resource
    ]
    return bool(mapped) and all(
        any(marker.encode("utf-16le") in region for region in mapped)
        for marker in _CEF_LOADER_MARKERS
    )


def _operand_address(instruction: Any, operand: Any) -> int | None:
    if operand.type == X86_OP_IMM:
        return int(operand.imm) & 0xFFFFFFFFFFFFFFFF
    if operand.type != X86_OP_MEM:
        return None
    displacement = int(operand.mem.disp)
    if operand.mem.base == X86_REG_RIP:
        return int(instruction.address + instruction.size + displacement)
    if operand.mem.base == X86_REG_INVALID and operand.mem.index == X86_REG_INVALID:
        return displacement & 0xFFFFFFFFFFFFFFFF
    return None


def _decode_instruction(
    data: bytes,
    sections: list[_Section],
    disassembler: Cs,
    address: int,
) -> tuple[Any, Any] | None:
    section = _section_for_address(sections, address, executable=True)
    if section is None:
        return None
    raw = section.raw_start + address - section.virtual_start
    maximum = min(15, section.raw_end - raw)
    if maximum <= 0:
        return None
    try:
        decoded = list(disassembler.disasm(data[raw : raw + maximum], address, 1))
    except CsError:
        return None
    return decoded[0] if decoded else None


def _function_summary(
    data: bytes,
    sections: list[_Section],
    disassembler: Cs,
    start: int,
    imports: dict[int, str],
) -> _FunctionSummary | None:
    """intraprocedural CFGを命令境界で歩く。上限到達・未復号edgeは失敗とする。"""

    if _section_for_address(sections, start, executable=True) is None:
        return None
    pending = [start]
    visited: set[int] = set()
    instructions: dict[int, Any] = {}
    direct_calls: set[int] = set()
    direct_call_counts: dict[int, int] = {}
    executable_references: set[int] = set()
    api_calls: list[tuple[int, str]] = []
    unresolved_control_flow_count = 0
    unresolved_control_flow_addresses: set[int] = set()

    while pending:
        address = pending.pop()
        if address in visited:
            continue
        if len(visited) >= MAXIMUM_FUNCTION_INSTRUCTIONS:
            return None
        instruction = _decode_instruction(data, sections, disassembler, address)
        if instruction is None:
            return None
        visited.add(address)
        instructions[address] = instruction
        operands = list(instruction.operands)
        targets = [
            target
            for operand in operands
            if (target := _operand_address(instruction, operand)) is not None
        ]
        direct_target = (
            targets[0]
            if operands and operands[0].type == X86_OP_IMM and targets
            else None
        )
        import_target = (
            _operand_address(instruction, operands[0])
            if operands
            and operands[0].type == X86_OP_MEM
            and instruction.mnemonic in {"call", "jmp"}
            else None
        )
        if import_target in imports:
            api_calls.append((address, imports[import_target]))

        if instruction.mnemonic not in {"call", "jmp"}:
            for target in targets:
                if _section_for_address(sections, target, executable=True) is not None:
                    executable_references.add(target)
                    if len(executable_references) > MAXIMUM_FUNCTION_CODE_REFERENCES:
                        return None

        next_address = int(instruction.address + instruction.size)
        if instruction.mnemonic == "call":
            if (
                direct_target is not None
                and _section_for_address(sections, direct_target, executable=True)
                is not None
            ):
                direct_calls.add(direct_target)
                direct_call_counts[direct_target] = (
                    direct_call_counts.get(direct_target, 0) + 1
                )
                if len(direct_calls) > MAXIMUM_THREAD_CALLEES:
                    return None
            pending.append(next_address)
            continue
        if instruction.mnemonic == "jmp":
            if direct_target is not None:
                if (
                    _section_for_address(sections, direct_target, executable=True)
                    is not None
                ):
                    pending.append(direct_target)
                elif direct_target not in imports:
                    return None
            elif import_target not in imports:
                unresolved_control_flow_count += 1
                unresolved_control_flow_addresses.add(address)
                if unresolved_control_flow_count > MAXIMUM_UNRESOLVED_CONTROL_FLOW:
                    return None
            continue
        if instruction.mnemonic.startswith(("ret", "iret")) or instruction.mnemonic in {
            "int3",
            "ud2",
            "hlt",
        }:
            continue
        if instruction.mnemonic.startswith("j") or instruction.mnemonic.startswith(
            "loop"
        ):
            if direct_target is None:
                return None
            if _section_for_address(sections, direct_target, executable=True) is None:
                return None
            pending.append(direct_target)
            pending.append(next_address)
            continue
        pending.append(next_address)

    candidate = _FunctionSummary(
        start=start,
        instructions=instructions,
        direct_calls=direct_calls,
        direct_call_counts=direct_call_counts,
        executable_references=executable_references,
        api_calls=api_calls,
        unresolved_control_flow_count=unresolved_control_flow_count,
    )
    reachable = _reachable_instruction_addresses(candidate)
    if reachable is None:
        return None
    filtered_instructions = {
        address: instruction
        for address, instruction in instructions.items()
        if address in reachable
    }
    filtered_direct_calls: set[int] = set()
    filtered_direct_call_counts: dict[int, int] = {}
    filtered_executable_references: set[int] = set()
    for instruction in filtered_instructions.values():
        operands = list(instruction.operands)
        targets = [
            target
            for operand in operands
            if (target := _operand_address(instruction, operand)) is not None
        ]
        direct_target = (
            targets[0]
            if operands and operands[0].type == X86_OP_IMM and targets
            else None
        )
        if (
            instruction.mnemonic == "call"
            and direct_target is not None
            and _section_for_address(sections, direct_target, executable=True)
            is not None
        ):
            filtered_direct_calls.add(direct_target)
            filtered_direct_call_counts[direct_target] = (
                filtered_direct_call_counts.get(direct_target, 0) + 1
            )
        if instruction.mnemonic not in {"call", "jmp"}:
            filtered_executable_references.update(
                target
                for target in targets
                if _section_for_address(sections, target, executable=True) is not None
            )
    if (
        len(filtered_direct_calls) > MAXIMUM_THREAD_CALLEES
        or len(filtered_executable_references) > MAXIMUM_FUNCTION_CODE_REFERENCES
    ):
        return None
    return _FunctionSummary(
        start=start,
        instructions=filtered_instructions,
        direct_calls=filtered_direct_calls,
        direct_call_counts=filtered_direct_call_counts,
        executable_references=filtered_executable_references,
        api_calls=[item for item in api_calls if item[0] in reachable],
        unresolved_control_flow_count=len(
            unresolved_control_flow_addresses & reachable
        ),
    )


def _normalize_host(value: bytes) -> str | None:
    try:
        text = value.decode("ascii", errors="strict").strip().casefold().rstrip(".")
    except UnicodeError:
        return None
    if not text or len(text) > 253 or any(character.isspace() for character in text):
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return text if _HOSTNAME.fullmatch(text) else None
    if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast:
        return None
    return str(parsed)


def _strict_base64(value: bytes) -> bytes | None:
    if (
        len(value) < 4
        or len(value) > MAXIMUM_BASE64_TOKEN_LENGTH
        or len(value) % 4 != 0
        or value.count(b"=") > 2
        or b"=" in value[:-2]
    ):
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if base64.b64encode(decoded) == value else None


def _double_base64_candidates(
    data: bytes,
    sections: list[_Section],
) -> list[_TokenCandidate] | None:
    """mapped非resource dataから二重Base64 hostだけを有界に列挙する。"""

    candidates: list[_TokenCandidate] = []
    run_count = 0
    run_bytes = 0
    for section in sections:
        if section.executable or section.resource:
            continue
        raw = data[section.raw_start : section.raw_end]
        for match in _BASE64_RUN.finditer(raw):
            run_count += 1
            run_bytes += len(match.group())
            if run_count > MAXIMUM_BASE64_RUNS or run_bytes > MAXIMUM_BASE64_RUN_BYTES:
                return None
            encoded = match.group()
            if match.end() >= len(raw) or raw[match.end()] != 0:
                continue
            once = _strict_base64(encoded)
            if once is None:
                continue
            twice = _strict_base64(once)
            if twice is None:
                continue
            host = _normalize_host(twice)
            if host is None:
                continue
            candidates.append(
                _TokenCandidate(
                    address=section.virtual_start + match.start(),
                    length=len(encoded),
                    host=host,
                )
            )
            if len(candidates) > MAXIMUM_PRODUCER_CANDIDATES:
                return None
    return candidates


def _direct_call_target(instruction: Any, sections: list[_Section]) -> int | None:
    operands = list(instruction.operands)
    if instruction.mnemonic != "call" or not operands or operands[0].type != X86_OP_IMM:
        return None
    target = _operand_address(instruction, operands[0])
    return (
        target
        if target is not None
        and _section_for_address(sections, target, executable=True) is not None
        else None
    )


def _stack_key(operand: Any) -> tuple[str, int] | None:
    if operand.type != X86_OP_MEM or operand.mem.index != X86_REG_INVALID:
        return None
    if operand.mem.base in {X86_REG_RBP, X86_REG_EBP}:
        base = "bp"
    elif operand.mem.base in {X86_REG_RSP, X86_REG_ESP}:
        base = "sp"
    else:
        return None
    return base, int(operand.mem.disp)


def _register_family(instruction: Any, register: int) -> str | None:
    """部分registerを同じx64 general-purpose registerへ正規化する。"""

    del instruction
    return _REGISTER_FAMILY_BY_ID.get(int(register))


def _register_families(
    summary: _FunctionSummary, registers: set[int]
) -> frozenset[str]:
    if not summary.instructions:
        return frozenset()
    representative = next(iter(summary.instructions.values()))
    return frozenset(
        family
        for register in registers
        if (family := _register_family(representative, register)) is not None
    )


def _instruction_writes_families(instruction: Any, families: frozenset[str]) -> bool:
    if not families:
        return False
    return any(
        operand.type == X86_OP_REG
        and int(operand.access) & CS_AC_WRITE
        and _register_family(instruction, int(operand.reg)) in families
        for operand in instruction.operands
    )


def _raw_instruction_successors(
    summary: _FunctionSummary,
    instruction: Any,
) -> tuple[int, ...]:
    """定数評価前のintraprocedural CFG edgeを返す。"""

    operands = list(instruction.operands)
    next_address = int(instruction.address + instruction.size)
    immediate_target = (
        int(operands[0].imm) & 0xFFFFFFFFFFFFFFFF
        if operands and operands[0].type == X86_OP_IMM
        else None
    )
    candidates: list[int] = []
    if instruction.mnemonic == "call":
        candidates.append(next_address)
    elif instruction.mnemonic == "jmp":
        if immediate_target is not None:
            candidates.append(immediate_target)
    elif instruction.mnemonic.startswith(("ret", "iret")) or instruction.mnemonic in {
        "int3",
        "ud2",
        "hlt",
    }:
        pass
    elif instruction.mnemonic.startswith("j") or instruction.mnemonic.startswith(
        "loop"
    ):
        if immediate_target is not None:
            candidates.append(immediate_target)
        candidates.append(next_address)
    else:
        candidates.append(next_address)
    return tuple(
        dict.fromkeys(
            candidate for candidate in candidates if candidate in summary.instructions
        )
    )


def _raw_predecessor_map(
    summary: _FunctionSummary,
) -> dict[int, tuple[int, ...]] | None:
    if summary.raw_predecessors is not None:
        return summary.raw_predecessors
    predecessors: dict[int, list[int]] = {
        address: [] for address in summary.instructions
    }
    edge_count = 0
    for address, instruction in summary.instructions.items():
        for successor in _raw_instruction_successors(summary, instruction):
            edge_count += 1
            if edge_count > MAXIMUM_CFG_EDGE_COUNT:
                return None
            predecessors[successor].append(address)
    result = {
        address: tuple(dict.fromkeys(items)) for address, items in predecessors.items()
    }
    summary.raw_predecessors = result
    return result


def _linear_predecessor(summary: _FunctionSummary, address: int) -> Any | None:
    """他edgeが合流しない直前の1命令だけを返す。"""

    predecessors = _raw_predecessor_map(summary)
    if predecessors is None or len(predecessors.get(address, ())) != 1:
        return None
    predecessor = summary.instructions[predecessors[address][0]]
    return (
        predecessor if int(predecessor.address + predecessor.size) == address else None
    )


def _known_register_value_before(
    summary: _FunctionSummary, address: int, family: str
) -> int | None:
    """一意な直前定義が即値または自己zero化の場合だけ値を返す。"""

    instruction = _linear_predecessor(summary, address)
    if instruction is None:
        return None
    operands = list(instruction.operands)
    if (
        instruction.mnemonic == "mov"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and _register_family(instruction, operands[0].reg) == family
        and operands[1].type == X86_OP_IMM
    ):
        return int(operands[1].imm) & 0xFFFFFFFFFFFFFFFF
    if (
        instruction.mnemonic in {"xor", "sub"}
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[1].type == X86_OP_REG
        and _register_family(instruction, operands[0].reg) == family
        and _register_family(instruction, operands[1].reg) == family
    ):
        return 0
    return None


def _constant_zero_flag(summary: _FunctionSummary, branch: Any) -> bool | None:
    """合流のない局所的なflag定義からZFだけを安全に評価する。"""

    instruction = _linear_predecessor(summary, int(branch.address))
    if instruction is None:
        return None
    operands = list(instruction.operands)
    if len(operands) != 2 or operands[0].type != X86_OP_REG:
        return None
    left = _register_family(instruction, operands[0].reg)
    if left is None:
        return None
    if operands[1].type == X86_OP_REG:
        right = _register_family(instruction, operands[1].reg)
        if right != left:
            return None
        if instruction.mnemonic in {"cmp", "sub", "xor"}:
            return True
        if instruction.mnemonic in {"test", "or"}:
            value = _known_register_value_before(
                summary, int(instruction.address), left
            )
            return value == 0 if value is not None else None
    if operands[1].type == X86_OP_IMM:
        value = _known_register_value_before(summary, int(instruction.address), left)
        if value is None:
            return None
        immediate = int(operands[1].imm) & 0xFFFFFFFFFFFFFFFF
        if instruction.mnemonic == "cmp":
            return value == immediate
        if instruction.mnemonic == "test":
            return value & immediate == 0
    return None


def _constant_branch_taken(summary: _FunctionSummary, instruction: Any) -> bool | None:
    if instruction.mnemonic not in {"je", "jz", "jne", "jnz"}:
        return None
    zero = _constant_zero_flag(summary, instruction)
    if zero is None:
        return None
    return zero if instruction.mnemonic in {"je", "jz"} else not zero


def _instruction_successors(
    summary: _FunctionSummary,
    instruction: Any,
) -> tuple[int, ...]:
    """call先へ入らず、定数dead branchを除いたCFG edgeだけを返す。"""

    successors = _raw_instruction_successors(summary, instruction)
    decision = _constant_branch_taken(summary, instruction)
    if decision is None or len(successors) != 2:
        return successors
    operands = list(instruction.operands)
    target = (
        int(operands[0].imm) & 0xFFFFFFFFFFFFFFFF
        if operands and operands[0].type == X86_OP_IMM
        else None
    )
    next_address = int(instruction.address + instruction.size)
    selected = target if decision else next_address
    return (selected,) if selected in successors else ()


def _predecessor_map(
    summary: _FunctionSummary,
) -> dict[int, tuple[int, ...]] | None:
    if summary.predecessors is not None:
        return summary.predecessors
    predecessors: dict[int, list[int]] = {
        address: [] for address in summary.instructions
    }
    edge_count = 0
    for address, instruction in summary.instructions.items():
        for successor in _instruction_successors(summary, instruction):
            edge_count += 1
            if edge_count > MAXIMUM_CFG_EDGE_COUNT:
                return None
            predecessors[successor].append(address)
    result = {
        address: tuple(dict.fromkeys(items)) for address, items in predecessors.items()
    }
    summary.predecessors = result
    return result


def _reachable_instruction_addresses(
    summary: _FunctionSummary,
) -> set[int] | None:
    if summary.reachable_addresses is not None:
        return set(summary.reachable_addresses)
    if summary.start not in summary.instructions:
        return None
    pending = [summary.start]
    visited: set[int] = set()
    edge_count = 0
    while pending:
        address = pending.pop()
        if address in visited:
            continue
        visited.add(address)
        if len(visited) > MAXIMUM_FUNCTION_INSTRUCTIONS:
            return None
        for successor in _instruction_successors(
            summary, summary.instructions[address]
        ):
            edge_count += 1
            if edge_count > MAXIMUM_CFG_EDGE_COUNT:
                return None
            if successor not in visited:
                pending.append(successor)
    summary.reachable_addresses = frozenset(visited)
    return visited


def _ordered_reachable_instructions(
    summary: _FunctionSummary,
) -> list[Any] | None:
    reachable = _reachable_instruction_addresses(summary)
    if reachable is None:
        return None
    return [summary.instructions[address] for address in sorted(reachable)]


def _latest_register_source(
    summary: _FunctionSummary,
    before_address: int,
    registers: set[int],
    *,
    maximum_back: int = 12,
) -> Any | None:
    """全到達predecessorで同じregister定義に収束する場合だけ返す。"""

    if not 1 <= maximum_back <= MAXIMUM_REGISTER_SOURCE_STATES:
        return None
    reachable = _reachable_instruction_addresses(summary)
    predecessors = _predecessor_map(summary)
    families = _register_families(summary, registers)
    if (
        reachable is None
        or predecessors is None
        or before_address not in reachable
        or not families
    ):
        return None
    pending = list(predecessors[before_address])
    if not pending:
        return None
    visited: set[int] = set()
    resolved: list[tuple[int, Any, Any]] = []
    while pending:
        address = pending.pop()
        if address in visited:
            continue
        visited.add(address)
        if len(visited) > min(MAXIMUM_REGISTER_SOURCE_STATES, maximum_back):
            return None
        if address not in reachable:
            return None
        instruction = summary.instructions[address]
        if instruction.mnemonic == "call" and families & frozenset(
            {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
        ):
            return None
        if _instruction_writes_families(instruction, families):
            operands = list(instruction.operands)
            if not (
                instruction.mnemonic in {"lea", "mov"}
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and _register_family(instruction, operands[0].reg) in families
            ):
                return None
            resolved.append((address, instruction, operands[1]))
            continue
        incoming = predecessors[address]
        if not incoming:
            return None
        pending.extend(incoming)
    if (
        not resolved
        or len({address for address, _instruction, _operand in resolved}) != 1
    ):
        return None
    _address, instruction, operand = resolved[0]
    return instruction, operand


def _call_result_moved_between(
    summary: _FunctionSummary,
    source_call: int,
    destination_event: int,
    destination_registers: set[int],
    source_registers: set[int],
    *,
    maximum_back: int = 16,
) -> bool:
    """source callの返値だけがdestination registerへ届くことを確認する。"""

    definition = _latest_register_source(
        summary,
        destination_event,
        destination_registers,
        maximum_back=maximum_back,
    )
    source_families = _register_families(summary, source_registers)
    if (
        definition is None
        or definition[1].type != X86_OP_REG
        or _register_family(definition[0], definition[1].reg) not in source_families
    ):
        return False
    definition_address = int(definition[0].address)
    if not _events_form_reachable_path(
        summary, [source_call, definition_address, destination_event]
    ):
        return False
    predecessors = _predecessor_map(summary)
    if predecessors is None:
        return False
    pending = list(predecessors[definition_address])
    visited: set[int] = set()
    reached_source = False
    while pending:
        address = pending.pop()
        if address in visited:
            continue
        visited.add(address)
        if len(visited) > min(MAXIMUM_REGISTER_SOURCE_STATES, maximum_back):
            return False
        if address == source_call:
            reached_source = True
            continue
        instruction = summary.instructions[address]
        if instruction.mnemonic == "call" or _instruction_writes_families(
            instruction, source_families
        ):
            return False
        incoming = predecessors[address]
        if not incoming:
            return False
        pending.extend(incoming)
    return reached_source


def _events_form_reachable_path(
    summary: _FunctionSummary,
    addresses: list[int],
) -> bool:
    """相反branchの証拠をunionしないよう、各event間のCFG到達性を確認する。"""

    if (
        not addresses
        or len(addresses) > MAXIMUM_EVENT_SEQUENCE_LENGTH
        or any(address not in summary.instructions for address in addresses)
    ):
        return False
    reachable = _reachable_instruction_addresses(summary)
    if reachable is None or any(address not in reachable for address in addresses):
        return False
    for source, destination in pairwise(addresses):
        if source == destination:
            continue
        pending = list(_instruction_successors(summary, summary.instructions[source]))
        visited = {source}
        found = False
        while pending:
            address = pending.pop()
            if address == destination:
                found = True
                break
            if address in visited:
                continue
            visited.add(address)
            if len(visited) > min(
                len(summary.instructions), MAXIMUM_REGISTER_SOURCE_STATES
            ):
                return False
            pending.extend(
                successor
                for successor in _instruction_successors(
                    summary, summary.instructions[address]
                )
                if successor not in visited
            )
        if not found:
            return False
    return True


def _register_value_preserved_between(
    summary: _FunctionSummary,
    source_event: int,
    destination_event: int,
    family: str,
    *,
    maximum_back: int = 32,
) -> bool:
    """全predecessorでsource後のregister identityが保持されることを確認する。"""

    if (
        not 1 <= maximum_back <= MAXIMUM_REGISTER_SOURCE_STATES
        or source_event == destination_event
        or not _events_form_reachable_path(
            summary,
            [source_event, destination_event],
        )
    ):
        return False
    predecessors = _predecessor_map(summary)
    if predecessors is None:
        return False
    pending = list(predecessors.get(destination_event, ()))
    visited: set[int] = set()
    reached_source = False
    while pending:
        address = pending.pop()
        if address == source_event:
            reached_source = True
            continue
        if address in visited:
            continue
        visited.add(address)
        if len(visited) > min(MAXIMUM_REGISTER_SOURCE_STATES, maximum_back):
            return False
        instruction = summary.instructions.get(address)
        if instruction is None:
            return False
        if instruction.mnemonic == "call" or _instruction_writes_families(
            instruction,
            frozenset({family}),
        ):
            return False
        incoming = predecessors.get(address, ())
        if not incoming:
            return False
        pending.extend(incoming)
    return reached_source


def _entry_register_preserved_before(
    summary: _FunctionSummary,
    destination_event: int,
    family: str,
    *,
    maximum_back: int = 32,
) -> bool:
    """全entry pathで最初のcallまで引数registerが未変更か確認する。"""

    if not 1 <= maximum_back <= MAXIMUM_REGISTER_SOURCE_STATES:
        return False
    if destination_event == summary.start:
        return True
    predecessors = _predecessor_map(summary)
    reachable = _reachable_instruction_addresses(summary)
    if (
        predecessors is None
        or reachable is None
        or destination_event not in reachable
    ):
        return False
    pending = list(predecessors.get(destination_event, ()))
    visited: set[int] = set()
    reached_entry = False
    while pending:
        address = pending.pop()
        if address in visited:
            continue
        visited.add(address)
        if len(visited) > min(MAXIMUM_REGISTER_SOURCE_STATES, maximum_back):
            return False
        instruction = summary.instructions.get(address)
        if instruction is None:
            return False
        if instruction.mnemonic == "call" or _instruction_writes_families(
            instruction,
            frozenset({family}),
        ):
            return False
        incoming = predecessors.get(address, ())
        if not incoming:
            if address != summary.start:
                return False
            reached_entry = True
            continue
        pending.extend(incoming)
    return reached_entry


def _event_dominates_targets(
    summary: _FunctionSummary,
    event: int,
    targets: list[int],
) -> bool:
    """定数dead edge除外後の全entry→target pathがeventを通るか確認する。"""

    if not targets or len(targets) > MAXIMUM_POST_CALLS:
        return False
    predecessors = _predecessor_map(summary)
    reachable = _reachable_instruction_addresses(summary)
    if (
        predecessors is None
        or reachable is None
        or event not in reachable
        or any(target not in reachable for target in targets)
    ):
        return False
    for target in targets:
        pending = [target]
        visited: set[int] = set()
        while pending:
            address = pending.pop()
            if address == event:
                continue
            if address in visited:
                continue
            visited.add(address)
            if len(visited) > min(
                len(summary.instructions),
                MAXIMUM_REGISTER_SOURCE_STATES,
            ):
                return False
            if address == summary.start:
                return False
            incoming = predecessors.get(address, ())
            if not incoming:
                return False
            pending.extend(incoming)
    return True


def _cef_callback_lineage(
    sections: list[_Section],
    export_root: int,
    summary_resolver: Callable[[int], _FunctionSummary | None],
) -> _CefCallbackLineage | None:
    """alias exportから_beginthreadex経由producerまでの引数flowを検証する。"""

    export_summary = summary_resolver(export_root)
    if (
        export_summary is None
        or export_summary.unresolved_control_flow_count
        or len(export_summary.direct_calls) != 1
    ):
        return None
    main = next(iter(export_summary.direct_calls))
    if export_summary.direct_call_counts.get(main) != 1:
        return None
    main_summary = summary_resolver(main)
    if (
        main_summary is None
        or main_summary.unresolved_control_flow_count
        or len(main_summary.direct_calls) > MAXIMUM_MAIN_CALLEES
    ):
        return None

    wrappers: list[tuple[int, _FunctionSummary, int]] = []
    for candidate in sorted(main_summary.direct_calls):
        candidate_summary = summary_resolver(candidate)
        if candidate_summary is None:
            return None
        if candidate_summary.unresolved_control_flow_count:
            continue
        calls = [
            address
            for address, name in candidate_summary.api_calls
            if name == "_beginthreadex"
        ]
        if len(calls) == 1 and main_summary.direct_call_counts.get(candidate) == 1:
            wrappers.append((candidate, candidate_summary, calls[0]))
    if len(wrappers) != 1:
        return None
    wrapper, wrapper_summary, beginthreadex_call = wrappers[0]
    instructions = _ordered_reachable_instructions(wrapper_summary)
    if instructions is None:
        return None
    index_by_address = {
        int(instruction.address): index
        for index, instruction in enumerate(instructions)
    }
    beginthreadex_index = index_by_address.get(beginthreadex_call)
    if beginthreadex_index is None:
        return None

    trampoline_source = _latest_register_source(
        wrapper_summary,
        beginthreadex_call,
        {X86_REG_R8, X86_REG_R8D},
        maximum_back=16,
    )
    argument_source = _latest_register_source(
        wrapper_summary,
        beginthreadex_call,
        {X86_REG_R9, X86_REG_R9D},
        maximum_back=16,
    )
    if (
        trampoline_source is None
        or argument_source is None
        or argument_source[1].type != X86_OP_REG
    ):
        return None
    trampoline = _operand_address(trampoline_source[0], trampoline_source[1])
    container_family = _register_family(argument_source[0], argument_source[1].reg)
    if (
        trampoline is None
        or _section_for_address(sections, trampoline, executable=True) is None
        or container_family is None
    ):
        return None

    argument_index = index_by_address.get(int(argument_source[0].address))
    if argument_index is None or argument_index >= beginthreadex_index:
        return None
    stores: list[tuple[int, Any]] = []
    for index in range(max(0, argument_index - 16), argument_index):
        instruction = instructions[index]
        operands = list(instruction.operands)
        if (
            instruction.mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].mem.index == X86_REG_INVALID
            and int(operands[0].mem.disp) == 0
            and _register_family(instruction, operands[0].mem.base)
            == container_family
            and operands[1].type == X86_OP_REG
        ):
            stores.append((index, instruction))
    if len(stores) != 1:
        return None
    store_index, store = stores[0]
    producer_family = _register_family(store, list(store.operands)[1].reg)
    if producer_family is None:
        return None
    producer_source = _latest_register_source(
        wrapper_summary,
        int(store.address),
        {
            register
            for register, family in _REGISTER_FAMILY_BY_ID.items()
            if family == producer_family
        },
        maximum_back=8,
    )
    if producer_source is None:
        return None
    producer = _operand_address(producer_source[0], producer_source[1])
    if (
        producer is None
        or _section_for_address(sections, producer, executable=True) is None
        or len({export_root, main, wrapper, trampoline, producer}) != 5
    ):
        return None

    allocator_calls: list[Any] = []
    for instruction in instructions[max(0, store_index - 8) : store_index]:
        if _direct_call_target_from_summary(instruction, wrapper_summary) is not None:
            allocator_calls.append(instruction)
    if len(allocator_calls) != 1:
        return None
    allocator_call = allocator_calls[0]
    allocator_address = int(allocator_call.address)
    store_address = int(store.address)
    argument_address = int(argument_source[0].address)
    if (
        container_family != "rax"
        or _known_register_value_before(
            wrapper_summary,
            allocator_address,
            "rcx",
        )
        != 8
        or not _register_value_preserved_between(
            wrapper_summary,
            allocator_address,
            store_address,
            container_family,
        )
        or not _register_value_preserved_between(
            wrapper_summary,
            store_address,
            argument_address,
            container_family,
        )
        or not _events_form_reachable_path(
            wrapper_summary,
            [
                allocator_address,
                int(producer_source[0].address),
                store_address,
                argument_address,
                int(trampoline_source[0].address),
                beginthreadex_call,
            ],
        )
    ):
        return None

    trampoline_summary = summary_resolver(trampoline)
    trampoline_instructions = (
        _ordered_reachable_instructions(trampoline_summary)
        if trampoline_summary is not None
        else None
    )
    if (
        trampoline_summary is None
        or trampoline_instructions is None
        or trampoline_summary.unresolved_control_flow_count
    ):
        return None
    api_call_addresses = {address for address, _name in trampoline_summary.api_calls}
    unclassified_indirect_calls = []
    for instruction in trampoline_instructions:
        if instruction.mnemonic != "call":
            continue
        address = int(instruction.address)
        if (
            address in api_call_addresses
            or _direct_call_target_from_summary(instruction, trampoline_summary)
            is not None
        ):
            continue
        unclassified_indirect_calls.append(instruction)
    if len(unclassified_indirect_calls) != 1:
        return None
    callback_call = unclassified_indirect_calls[0]
    callback_operands = list(callback_call.operands)
    if not (
        len(callback_operands) == 1
        and callback_operands[0].type == X86_OP_MEM
        and callback_operands[0].mem.base == X86_REG_RCX
        and callback_operands[0].mem.index == X86_REG_INVALID
        and int(callback_operands[0].mem.disp) == 0
        and _entry_register_preserved_before(
            trampoline_summary,
            int(callback_call.address),
            "rcx",
        )
    ):
        return None
    returns = [
        instruction
        for instruction in trampoline_instructions
        if instruction.mnemonic.startswith("ret")
    ]
    return_addresses = [int(instruction.address) for instruction in returns]
    if not (
        1 <= len(returns) <= MAXIMUM_POST_CALLS
        and _event_dominates_targets(
            trampoline_summary,
            int(callback_call.address),
            return_addresses,
        )
        and all(
            _events_form_reachable_path(
                trampoline_summary,
                [int(callback_call.address), return_address],
            )
            for return_address in return_addresses
        )
    ):
        return None
    return _CefCallbackLineage(
        producer=producer,
        export_to_main_direct_call_count=1,
        main_to_beginthreadex_wrapper_direct_call_count=1,
        beginthreadex_api_call_count=1,
        producer_pointer_store_count=1,
        callback_trampoline_indirect_call_count=1,
    )


def _read_wide_literal(
    data: bytes,
    sections: list[_Section],
    address: int,
    length: int,
) -> str | None:
    if not 1 <= length <= 64:
        return None
    section = _section_for_address(sections, address, executable=False)
    if section is None or section.resource:
        return None
    raw = _raw_offset(sections, address, length * 2 + 2)
    if raw is None or data[raw + length * 2 : raw + length * 2 + 2] != b"\0\0":
        return None
    try:
        value = data[raw : raw + length * 2].decode("utf-16le", errors="strict")
    except UnicodeError:
        return None
    return value if "\0" not in value and len(value) == length else None


def _literal_copy_call(
    data: bytes,
    sections: list[_Section],
    summary: _FunctionSummary,
    instructions: list[Any],
    index: int,
) -> _LiteralCopy | None:
    instruction = instructions[index]
    target = _direct_call_target(instruction, sections)
    if target is None:
        return None
    length_operand = _latest_register_source(
        summary, int(instruction.address), {X86_REG_R8, X86_REG_R8D}
    )
    data_operand = _latest_register_source(
        summary, int(instruction.address), {X86_REG_RDX, X86_REG_EDX}
    )
    destination_operand = _latest_register_source(
        summary, int(instruction.address), {X86_REG_RCX, X86_REG_ECX}
    )
    if (
        length_operand is None
        or length_operand[1].type != X86_OP_IMM
        or data_operand is None
        or destination_operand is None
    ):
        return None
    length = int(length_operand[1].imm)
    address = _operand_address(data_operand[0], data_operand[1])
    destination = _stack_key(destination_operand[1])
    if address is None or destination is None:
        return None
    value = _read_wide_literal(data, sections, address, length)
    if value is None:
        return None
    return _LiteralCopy(
        instruction_index=index,
        call_address=int(instruction.address),
        target=target,
        destination=destination,
        value=value,
        length=length,
    )


def _object_copy_call(
    sections: list[_Section],
    summary: _FunctionSummary,
    instructions: list[Any],
    index: int,
) -> _ObjectCopy | None:
    instruction = instructions[index]
    target = _direct_call_target(instruction, sections)
    if target is None:
        return None
    source_operand = _latest_register_source(
        summary,
        int(instruction.address),
        {X86_REG_RDX, X86_REG_EDX},
        maximum_back=8,
    )
    destination_operand = _latest_register_source(
        summary,
        int(instruction.address),
        {X86_REG_RCX, X86_REG_ECX},
        maximum_back=8,
    )
    if source_operand is None or destination_operand is None:
        return None
    source = _stack_key(source_operand[1])
    destination = _stack_key(destination_operand[1])
    if source is None or destination is None or source == destination:
        return None
    return _ObjectCopy(
        instruction_index=index,
        call_address=int(instruction.address),
        target=target,
        destination=destination,
        source=source,
    )


def _copy_helper_evidence(
    summary: _FunctionSummary, *, literal: bool
) -> dict[str, object] | None:
    """entry引数を実際に消費する有界copy helperだけを受理する。"""

    instructions = _ordered_reachable_instructions(summary)
    if (
        instructions is None
        or summary.unresolved_control_flow_count
        or not 16 <= len(instructions) <= MAXIMUM_COPY_HELPER_INSTRUCTIONS
    ):
        return None
    required = {"rcx", "rdx", "r8"} if literal else {"rcx", "rdx"}
    aliases: dict[str, set[str]] = {family: set() for family in required}
    setup_addresses: list[int] = []
    for instruction in instructions[:32]:
        if instruction.mnemonic == "call" or instruction.mnemonic.startswith("j"):
            break
        operands = list(instruction.operands)
        if not (
            instruction.mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_REG
        ):
            continue
        source = _register_family(instruction, operands[1].reg)
        destination = _register_family(instruction, operands[0].reg)
        if source in required and destination is not None and destination != source:
            aliases[source].add(destination)
            setup_addresses.append(int(instruction.address))
    if any(len(items) != 1 for items in aliases.values()):
        return None
    if not _events_form_reachable_path(
        summary, [summary.start] + sorted(set(setup_addresses))
    ):
        return None

    destination_families = frozenset({"rcx"} | aliases["rcx"])
    source_families = frozenset({"rdx"} | aliases["rdx"])
    destination_field_writes = 0
    source_field_reads = 0
    for instruction in instructions:
        operands = list(instruction.operands)
        for index, operand in enumerate(operands):
            if operand.type != X86_OP_MEM:
                continue
            family = _register_family(instruction, operand.mem.base)
            if index == 0 and instruction.mnemonic.startswith("mov"):
                if family in destination_families:
                    destination_field_writes += 1
            elif family in source_families:
                source_field_reads += 1
    if destination_field_writes < 2 or (not literal and source_field_reads < 2):
        return None

    source_alias = next(iter(aliases["rdx"]))
    length_alias = next(iter(aliases["r8"])) if literal else None
    copy_call_candidates: list[int] = []
    for index, instruction in enumerate(instructions):
        call_address = int(instruction.address)
        if _direct_call_target_from_summary(instruction, summary) is None:
            continue
        window = instructions[max(0, index - 16) : index]
        source_moves = []
        length_moves = []
        for previous in window:
            operands = list(previous.operands)
            if not (
                previous.mnemonic in {"lea", "mov"}
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
            ):
                continue
            destination = _register_family(previous, operands[0].reg)
            if operands[1].type == X86_OP_REG:
                source = _register_family(previous, operands[1].reg)
                if destination == "rdx" and source == source_alias:
                    source_moves.append(int(previous.address))
                if literal and destination == "r8" and source == length_alias:
                    length_moves.append(int(previous.address))
            elif literal and operands[1].type == X86_OP_MEM:
                if (
                    destination == "r8"
                    and _register_family(previous, operands[1].mem.base) == length_alias
                ):
                    length_moves.append(int(previous.address))
        if not source_moves or (literal and not length_moves):
            continue
        events = [source_moves[-1]]
        if literal:
            events.append(length_moves[-1])
        events.append(call_address)
        events.sort()
        if _events_form_reachable_path(summary, events):
            copy_call_candidates.append(call_address)
            if len(copy_call_candidates) > MAXIMUM_POST_CALLS:
                return None
    if not copy_call_candidates:
        return None
    returns = [
        int(instruction.address)
        for instruction in instructions
        if instruction.mnemonic.startswith("ret")
    ]
    if not returns or not any(
        _events_form_reachable_path(
            summary, [summary.start, copy_call_candidates[0], return_address]
        )
        for return_address in returns[:MAXIMUM_POST_CALLS]
    ):
        return None
    return {
        "entry_argument_lineage_present": True,
        "destination_metadata_write_present": True,
        "source_data_use_present": True,
        "reachable_copy_call_present": True,
        "reachable_return_present": True,
    }


def _register_constant_before(
    summary: _FunctionSummary,
    before_address: int,
    family: str,
    *,
    maximum_back: int = 256,
) -> int | None:
    """全到達pathで同じ定数定義へ収束する場合だけ値を返す。"""

    if not 1 <= maximum_back <= MAXIMUM_REGISTER_SOURCE_STATES:
        return None
    reachable = _reachable_instruction_addresses(summary)
    predecessors = _predecessor_map(summary)
    if (
        reachable is None
        or predecessors is None
        or before_address not in reachable
        or not family
    ):
        return None
    pending = list(predecessors[before_address])
    visited: set[int] = set()
    values: list[int] = []
    volatile = family in {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
    while pending:
        address = pending.pop()
        if address in visited:
            continue
        visited.add(address)
        if len(visited) > min(MAXIMUM_REGISTER_SOURCE_STATES, maximum_back):
            return None
        instruction = summary.instructions[address]
        if instruction.mnemonic == "call" and volatile:
            return None
        families = frozenset({family})
        if _instruction_writes_families(instruction, families):
            operands = list(instruction.operands)
            value: int | None = None
            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and _register_family(instruction, operands[0].reg) == family
                and operands[1].type == X86_OP_IMM
            ):
                value = int(operands[1].imm) & 0xFFFFFFFFFFFFFFFF
            elif (
                instruction.mnemonic in {"xor", "sub"}
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and operands[1].type == X86_OP_REG
                and _register_family(instruction, operands[0].reg) == family
                and _register_family(instruction, operands[1].reg) == family
            ):
                value = 0
            if value is None:
                return None
            values.append(value)
            continue
        incoming = predecessors[address]
        if not incoming:
            return None
        pending.extend(incoming)
    return values[0] if values and len(set(values)) == 1 else None


def _table_write_value(
    summary: _FunctionSummary, instruction: Any, source: Any
) -> int | None:
    if source.type == X86_OP_IMM:
        value = int(source.imm)
    elif source.type == X86_OP_REG:
        family = _register_family(instruction, source.reg)
        if family is None:
            return None
        value = _register_constant_before(summary, int(instruction.address), family)
    else:
        return None
    return value if value is not None and 0 <= value <= 63 else None


def _base64_decoder_evidence(summary: _FunctionSummary) -> dict[str, object] | None:
    """allocationから64値tableと6-bit lookupまでの同一data-flowを検証する。"""

    instructions = _ordered_reachable_instructions(summary)
    if instructions is None:
        return None
    writes_by_base: dict[str, list[tuple[int, int, int]]] = {}
    base_registers: dict[str, int] = {}
    table_write_count = 0
    for instruction in instructions:
        operands = list(instruction.operands)
        if not (
            instruction.mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_MEM
            and operands[0].mem.base != X86_REG_INVALID
            and operands[0].mem.index == X86_REG_INVALID
        ):
            continue
        value = _table_write_value(summary, instruction, operands[1])
        if value is None:
            continue
        table_write_count += 1
        if table_write_count > MAXIMUM_DECODER_TABLE_WRITES:
            return None
        family = _register_family(instruction, operands[0].mem.base)
        if family is None:
            continue
        base_registers[family] = int(operands[0].mem.base)
        writes = writes_by_base.get(family)
        if writes is None:
            writes = []
            writes_by_base[family] = writes
        writes.append(
            (int(instruction.address), value, int(operands[0].mem.disp))
        )

    complete = [
        (family, writes)
        for family, writes in writes_by_base.items()
        if len(writes) == 64
        and {value for _address, value, _disp in writes} == set(range(64))
    ]
    if len(complete) != 1:
        return None
    family, table_writes = complete[0]
    table_writes.sort()
    first_write = table_writes[0][0]
    last_write = table_writes[-1][0]
    base_register = base_registers[family]

    allocation_lineages: list[int] = []
    for instruction in instructions:
        call_address = int(instruction.address)
        if not first_write - 0x200 <= call_address < first_write:
            continue
        if _direct_call_target_from_summary(instruction, summary) is None:
            continue
        size_source = _latest_register_source(
            summary,
            call_address,
            {X86_REG_RCX, X86_REG_ECX},
            maximum_back=12,
        )
        if (
            size_source is None
            or size_source[1].type != X86_OP_IMM
            or int(size_source[1].imm) != 0x400
        ):
            continue
        if _call_result_moved_between(
            summary,
            call_address,
            first_write,
            {base_register},
            {X86_REG_RAX, X86_REG_EAX},
            maximum_back=96,
        ):
            allocation_lineages.append(call_address)
            if len(allocation_lineages) > MAXIMUM_DECODER_LINEAGES:
                return None
    if len(allocation_lineages) != 1:
        return None
    allocation_call = allocation_lineages[0]

    lookup_candidates: list[tuple[Any, str]] = []
    for instruction in instructions:
        address = int(instruction.address)
        if not last_write < address <= last_write + 0x200:
            continue
        operands = list(instruction.operands)
        if not (
            instruction.mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_MEM
            and operands[1].mem.index != X86_REG_INVALID
            and int(operands[1].mem.scale) == 4
            and _register_family(instruction, operands[1].mem.base) == family
        ):
            continue
        destination_family = _register_family(instruction, operands[0].reg)
        if destination_family is not None:
            lookup_candidates.append((instruction, destination_family))
            if len(lookup_candidates) > MAXIMUM_DECODER_LINEAGES:
                return None

    accumulation_lineages: list[tuple[int, int, int]] = []
    for lookup, lookup_family in lookup_candidates:
        lookup_address = int(lookup.address)
        for shift in instructions:
            shift_address = int(shift.address)
            if shift_address <= lookup_address:
                continue
            if shift_address > lookup_address + 0x40:
                break
            shift_operands = list(shift.operands)
            if not (
                shift.mnemonic == "shl"
                and len(shift_operands) == 2
                and shift_operands[0].type == X86_OP_REG
                and shift_operands[1].type == X86_OP_IMM
                and int(shift_operands[1].imm) == 6
            ):
                continue
            accumulator_family = _register_family(shift, shift_operands[0].reg)
            for addition in instructions:
                addition_address = int(addition.address)
                if addition_address <= shift_address:
                    continue
                if addition_address > shift_address + 0x20:
                    break
                addition_operands = list(addition.operands)
                if not (
                    addition.mnemonic == "add"
                    and len(addition_operands) == 2
                    and addition_operands[0].type == X86_OP_REG
                    and addition_operands[1].type == X86_OP_REG
                    and _register_family(addition, addition_operands[0].reg)
                    == accumulator_family
                    and _register_family(addition, addition_operands[1].reg)
                    == lookup_family
                ):
                    continue
                if _events_form_reachable_path(
                    summary,
                    [lookup_address, shift_address, addition_address],
                ):
                    accumulation_lineages.append(
                        (lookup_address, shift_address, addition_address)
                    )
                    if len(accumulation_lineages) > MAXIMUM_DECODER_LINEAGES:
                        return None
    if len(accumulation_lineages) != 1:
        return None
    lookup_address, shift_address, addition_address = accumulation_lineages[0]
    all_table_addresses = [address for address, _value, _disp in table_writes]
    if not _events_form_reachable_path(
        summary,
        [allocation_call]
        + all_table_addresses
        + [lookup_address, shift_address, addition_address],
    ):
        return None
    return {
        "complete_base64_decode_table_count": 1,
        "base64_decode_table_entry_count": 64,
        "six_bit_accumulation_present": True,
        "bounded_decode_table_allocation_present": True,
        "allocation_table_lookup_dataflow_present": True,
    }


def _builder_decoder_evidence(
    summary: _FunctionSummary,
    decoder: int,
) -> dict[str, object] | None:
    """同一到達経路にある1～2組の二重decode chainだけを受理する。"""

    instructions = _ordered_reachable_instructions(summary)
    if instructions is None:
        return None
    call_indices = [
        index
        for index, instruction in enumerate(instructions)
        if _direct_call_target_from_summary(instruction, summary) == decoder
    ]
    all_decoder_call_count = sum(
        _direct_call_target_from_summary(instruction, summary) == decoder
        for instruction in summary.instructions.values()
    )
    if len(call_indices) not in {2, 4}:
        return None
    if all_decoder_call_count != len(call_indices):
        return None
    if not _events_form_reachable_path(
        summary,
        [int(instructions[index].address) for index in call_indices],
    ):
        return None

    converter_targets: list[int] = []
    for offset in range(0, len(call_indices), 2):
        first_index, second_index = call_indices[offset : offset + 2]
        first = instructions[first_index]
        second = instructions[second_index]
        if int(second.address) - int(
            first.address
        ) > 0x40 or not _call_result_moved_between(
            summary,
            int(first.address),
            int(second.address),
            {X86_REG_RDX, X86_REG_EDX},
            {X86_REG_RAX, X86_REG_EAX},
        ):
            return None
        converter: tuple[int, int] | None = None
        for index in range(first_index - 1, max(-1, first_index - 12), -1):
            instruction = instructions[index]
            if int(first.address) - int(instruction.address) > 0x40:
                break
            target = _direct_call_target_from_summary(instruction, summary)
            if target is not None:
                converter = index, target
                break
        if converter is None or converter[1] == decoder:
            return None
        if not _call_result_moved_between(
            summary,
            int(instructions[converter[0]].address),
            int(first.address),
            {X86_REG_RDX, X86_REG_EDX},
            {X86_REG_RAX, X86_REG_EAX},
        ) or not _events_form_reachable_path(
            summary,
            [
                int(instructions[converter[0]].address),
                int(first.address),
                int(second.address),
            ],
        ):
            return None
        converter_targets.append(converter[1])
    if len(set(converter_targets)) != 1:
        return None
    return {
        "double_decode_chain_count": len(call_indices) // 2,
        "same_decoder_call_count": len(call_indices),
        "shared_input_converter_present": True,
        "single_reachable_builder_path_present": True,
    }


def _latest_register_definition(
    summary: _FunctionSummary,
    before_address: int,
    registers: set[int],
    *,
    maximum_back: int = 12,
) -> Any | None:
    """全到達predecessorの最初のregister定義が一意な場合だけ返す。"""

    reachable = _reachable_instruction_addresses(summary)
    predecessors = _predecessor_map(summary)
    families = _register_families(summary, registers)
    if (
        reachable is None
        or predecessors is None
        or before_address not in reachable
        or not families
    ):
        return None
    pending = list(predecessors[before_address])
    visited: set[int] = set()
    definitions: list[Any] = []
    volatile = bool(
        families & frozenset({"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"})
    )
    while pending:
        address = pending.pop()
        if address in visited:
            continue
        visited.add(address)
        if len(visited) > min(MAXIMUM_REGISTER_SOURCE_STATES, maximum_back):
            return None
        instruction = summary.instructions[address]
        if instruction.mnemonic == "call" and volatile:
            return None
        if _instruction_writes_families(instruction, families):
            definitions.append(instruction)
            continue
        incoming = predecessors[address]
        if not incoming:
            return None
        pending.extend(incoming)
    return (
        definitions[0]
        if definitions
        and len({int(instruction.address) for instruction in definitions}) == 1
        else None
    )


def _stack_register_source(
    summary: _FunctionSummary,
    before_address: int,
    registers: set[int],
    *,
    maximum_back: int = 12,
) -> tuple[tuple[str, int], int] | None:
    source = _latest_register_source(
        summary, before_address, registers, maximum_back=maximum_back
    )
    if source is None:
        return None
    key = _stack_key(source[1])
    return (key, int(source[0].address)) if key is not None else None


def _protected_range_lineage(
    summary: _FunctionSummary, call_address: int
) -> tuple[tuple[str, int], tuple[str, int], int] | None:
    size_definition = _latest_register_definition(
        summary, call_address, {X86_REG_RDX, X86_REG_EDX}, maximum_back=12
    )
    if size_definition is None:
        return None
    operands = list(size_definition.operands)
    if not (
        size_definition.mnemonic == "sub"
        and len(operands) == 2
        and operands[0].type == X86_OP_REG
        and operands[1].type == X86_OP_REG
        and _register_family(size_definition, operands[0].reg) == "rdx"
        and _register_family(size_definition, operands[1].reg) == "rcx"
    ):
        return None
    size_address = int(size_definition.address)
    begin_source = _stack_register_source(
        summary, size_address, {X86_REG_RCX, X86_REG_ECX}, maximum_back=8
    )
    end_source = _stack_register_source(
        summary, size_address, {X86_REG_RDX, X86_REG_EDX}, maximum_back=8
    )
    if begin_source is None or end_source is None:
        return None
    begin, begin_address = begin_source
    end, end_address = end_source
    if begin[0] != end[0] or end[1] != begin[1] + 8:
        return None
    events = sorted([begin_address, end_address, size_address]) + [call_address]
    if len(set(events)) != 4 or not _events_form_reachable_path(summary, events):
        return None
    return begin, end, size_address


def _indirect_target_stack_key(
    summary: _FunctionSummary, instruction: Any
) -> tuple[str, int] | None:
    operands = list(instruction.operands)
    if instruction.mnemonic != "call" or not operands:
        return None
    target = operands[0]
    if target.type == X86_OP_MEM:
        return _stack_key(target)
    if target.type != X86_OP_REG:
        return None
    source = _latest_register_source(
        summary,
        int(instruction.address),
        {int(target.reg)},
        maximum_back=8,
    )
    return _stack_key(source[1]) if source is not None else None


def _consumer_evidence(summary: _FunctionSummary) -> dict[str, object] | None:
    """同一復元bufferの準備→実行許可→間接call→保護復帰を検証する。"""

    instructions = _ordered_reachable_instructions(summary)
    if instructions is None or len(instructions) > MAXIMUM_CONSUMER_INSTRUCTIONS:
        return None
    protect_indices = [
        index
        for index, instruction in enumerate(instructions)
        if any(
            address == int(instruction.address) and name == "virtualprotect"
            for address, name in summary.api_calls
        )
    ]
    if len(protect_indices) != 2:
        return None
    first, second = protect_indices
    first_protect = instructions[first]
    second_protect = instructions[second]
    first_address = int(first_protect.address)
    second_address = int(second_protect.address)
    first_range = _protected_range_lineage(summary, first_address)
    second_range = _protected_range_lineage(summary, second_address)
    if (
        first_range is None
        or second_range is None
        or first_range[:2] != second_range[:2]
    ):
        return None
    begin_key, _end_key, _size_address = first_range
    page_execute_source = _latest_register_source(
        summary, first_address, {X86_REG_R8, X86_REG_R8D}, maximum_back=8
    )
    first_old_source = _stack_register_source(
        summary, first_address, {X86_REG_R9, X86_REG_R9D}, maximum_back=8
    )
    restored_protection_source = _stack_register_source(
        summary, second_address, {X86_REG_R8, X86_REG_R8D}, maximum_back=8
    )
    second_old_source = _stack_register_source(
        summary, second_address, {X86_REG_R9, X86_REG_R9D}, maximum_back=8
    )
    if (
        page_execute_source is None
        or page_execute_source[1].type != X86_OP_IMM
        or int(page_execute_source[1].imm) != 0x40
        or first_old_source is None
        or restored_protection_source is None
        or second_old_source is None
        or first_old_source[0] != restored_protection_source[0]
        or first_old_source[0] != second_old_source[0]
    ):
        return None
    api_call_addresses = {address for address, _name in summary.api_calls}
    indirect_calls = []
    for instruction in instructions[first + 1 : second]:
        operands = list(instruction.operands)
        if (
            instruction.mnemonic == "call"
            and operands
            and operands[0].type in {X86_OP_MEM, X86_OP_REG}
            and int(instruction.address) not in api_call_addresses
        ):
            indirect_calls.append(instruction)
    direct_before = [
        instruction
        for instruction in instructions[:first]
        if _direct_call_target_from_summary(instruction, summary) is not None
    ]
    if len(direct_before) > MAXIMUM_CONSUMER_PREPARATION_CALLS:
        return None
    if len(direct_before) < 3:
        return None
    preparation = direct_before[-3:]
    if (
        len({_direct_call_target_from_summary(item, summary) for item in preparation})
        != 3
    ):
        return None
    preparation_addresses = [int(item.address) for item in preparation]
    destination_keys = [
        _stack_register_source(
            summary, address, {X86_REG_RCX, X86_REG_ECX}, maximum_back=8
        )
        for address in preparation_addresses
    ]
    if any(item is None for item in destination_keys):
        return None
    destinations = [item[0] for item in destination_keys if item is not None]
    second_input = _stack_register_source(
        summary,
        preparation_addresses[1],
        {X86_REG_RDX, X86_REG_EDX},
        maximum_back=8,
    )
    third_input = _stack_register_source(
        summary,
        preparation_addresses[2],
        {X86_REG_RDX, X86_REG_EDX},
        maximum_back=8,
    )
    first_input = _latest_register_source(
        summary,
        preparation_addresses[0],
        {X86_REG_RDX, X86_REG_EDX},
        maximum_back=8,
    )
    if (
        len(set(destinations)) != 3
        or destinations[-1] != begin_key
        or second_input is None
        or third_input is None
        or second_input[0] != destinations[0]
        or third_input[0] != destinations[1]
        or first_input is None
        or first_input[1].type != X86_OP_REG
        or _register_family(first_input[0], first_input[1].reg) != "rcx"
    ):
        return None
    reachable_preparation = _events_form_reachable_path(
        summary,
        [summary.start] + preparation_addresses + [first_address],
    )
    if (
        len(indirect_calls) != 1
        or not reachable_preparation
        or _indirect_target_stack_key(summary, indirect_calls[0]) != begin_key
        or not _events_form_reachable_path(
            summary,
            [
                int(page_execute_source[0].address),
                first_address,
            ],
        )
        or not _events_form_reachable_path(
            summary,
            [
                first_address,
                int(indirect_calls[0].address),
                second_address,
            ],
        )
    ):
        return None
    return {
        "minimum_reachable_preparation_direct_call_count": 3,
        "virtual_protect_call_count": 2,
        "page_execute_readwrite_transition_present": True,
        "recovered_buffer_indirect_call_present": True,
        "post_execution_virtual_protect_call_present": True,
        "protected_buffer_identity_preserved": True,
        "restored_protection_value_lineage_present": True,
    }


def _direct_call_target_from_summary(
    instruction: Any, summary: _FunctionSummary
) -> int | None:
    operands = list(instruction.operands)
    if instruction.mnemonic != "call" or not operands or operands[0].type != X86_OP_IMM:
        return None
    target = int(operands[0].imm) & 0xFFFFFFFFFFFFFFFF
    return target if target in summary.direct_calls else None


def _periodic_wait_present(summary: _FunctionSummary, consumer_call: int) -> bool:
    instructions = _ordered_reachable_instructions(summary)
    if instructions is None:
        return False
    for index, instruction in enumerate(instructions):
        if int(instruction.address) <= consumer_call:
            continue
        if not any(
            address == int(instruction.address) and name == "sleep"
            for address, name in summary.api_calls
        ):
            continue
        delay_present = False
        delay_instruction: Any | None = None
        for previous in instructions[max(0, index - 6) : index]:
            operands = list(previous.operands)
            if (
                previous.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and operands[0].reg in {X86_REG_RCX, X86_REG_ECX}
                and operands[1].type == X86_OP_IMM
                and int(operands[1].imm) == 1000
            ):
                delay_present = True
                delay_instruction = previous
        if (
            not delay_present
            or delay_instruction is None
            or not _events_form_reachable_path(
                summary,
                [int(delay_instruction.address), int(instruction.address)],
            )
            or index + 1 >= len(instructions)
        ):
            continue
        following = instructions[index + 1]
        operands = list(following.operands)
        if (
            following.mnemonic == "jmp"
            and operands
            and operands[0].type == X86_OP_IMM
            and int(operands[0].imm) <= int(instruction.address)
            and int(following.address) == int(instruction.address + instruction.size)
            and _events_form_reachable_path(
                summary,
                [consumer_call, int(instruction.address)],
            )
        ):
            return True
    return False


def _parse_producer(
    data: bytes,
    sections: list[_Section],
    disassembler: Cs,
    producer: int,
    token_candidates: list[_TokenCandidate],
    summary_resolver: Callable[[int], _FunctionSummary | None],
) -> tuple[dict[str, object], dict[str, object]] | None:
    summary = summary_resolver(producer)
    if summary is None or summary.unresolved_control_flow_count:
        return None
    instructions = _ordered_reachable_instructions(summary)
    if instructions is None:
        return None

    token_matches: list[tuple[_TokenCandidate, list[int]]] = []
    for candidate in token_candidates:
        references = []
        for index, instruction in enumerate(instructions):
            if any(
                candidate.address <= address < candidate.address + candidate.length
                for operand in instruction.operands
                if (address := _operand_address(instruction, operand)) is not None
            ):
                references.append(index)
                if len(references) > MAXIMUM_TOKEN_REFERENCES_PER_CANDIDATE:
                    return None
        if len(references) >= 2 and any(
            _operand_address(instructions[index], operand) == candidate.address
            for index in references
            for operand in instructions[index].operands
        ):
            token_matches.append((candidate, references))
    if len(token_matches) != 1:
        return None
    token, token_references = token_matches[0]
    first_reference = min(token_references)

    decode_calls: list[tuple[int, int]] = []
    reference_address = int(instructions[first_reference].address)
    for index in range(first_reference + 1, len(instructions)):
        instruction = instructions[index]
        if int(instruction.address) - reference_address > 0x80:
            break
        target = _direct_call_target(instruction, sections)
        if target is not None:
            decode_calls.append((index, target))
            if len(decode_calls) == 3:
                break
    if len(decode_calls) != 3:
        return None
    (
        (first_index, decoder),
        (second_index, decoder_again),
        (
            converter_index,
            converter,
        ),
    ) = decode_calls
    if decoder != decoder_again or converter == decoder:
        return None
    if not _events_form_reachable_path(
        summary,
        [
            reference_address,
            int(instructions[first_index].address),
            int(instructions[second_index].address),
            int(instructions[converter_index].address),
        ],
    ):
        return None
    if not _call_result_moved_between(
        summary,
        int(instructions[first_index].address),
        int(instructions[second_index].address),
        {X86_REG_RDX, X86_REG_EDX},
        {X86_REG_RAX, X86_REG_EAX},
    ) or not _call_result_moved_between(
        summary,
        int(instructions[second_index].address),
        int(instructions[converter_index].address),
        {X86_REG_RDX, X86_REG_EDX},
        {X86_REG_RAX, X86_REG_EAX},
    ):
        return None
    decoder_summary = summary_resolver(decoder)
    if decoder_summary is None or decoder_summary.unresolved_control_flow_count:
        return None
    decoder_evidence = _base64_decoder_evidence(decoder_summary)
    if decoder_evidence is None:
        return None
    host_destination_operand = _latest_register_source(
        summary,
        int(instructions[converter_index].address),
        {X86_REG_RCX, X86_REG_ECX},
        maximum_back=8,
    )
    host_destination = (
        _stack_key(host_destination_operand[1])
        if host_destination_operand is not None
        else None
    )
    if host_destination is None:
        return None

    literal_calls: list[_LiteralCopy] = []
    converter_address = int(instructions[converter_index].address)
    for index in range(converter_index + 1, len(instructions)):
        if int(instructions[index].address) - converter_address > 0x280:
            break
        call = _literal_copy_call(data, sections, summary, instructions, index)
        if call is not None:
            literal_calls.append(call)
            if len(literal_calls) > MAXIMUM_LITERAL_COPY_CANDIDATES:
                return None
    literal_sequences = [
        literal_calls[index : index + 5]
        for index in range(max(0, len(literal_calls) - 4))
        if len({item.target for item in literal_calls[index : index + 5]}) == 1
        and [item.length for item in literal_calls[index : index + 5]]
        == [3, 3, 1, 2, 2]
        and _events_form_reachable_path(
            summary,
            [converter_address]
            + [item.call_address for item in literal_calls[index : index + 5]],
        )
    ]
    if len(literal_sequences) != 1:
        return None
    literals = literal_sequences[0]
    literal_helper_summary = summary_resolver(literals[0].target)
    if literal_helper_summary is None:
        return None
    literal_helper_evidence = _copy_helper_evidence(
        literal_helper_summary, literal=True
    )
    if literal_helper_evidence is None:
        return None
    try:
        primary_port = int(literals[0].value, 10)
        alternate_port = int(literals[1].value, 10)
        selector = int(literals[2].value, 10)
    except ValueError:
        return None
    if (
        not 1 <= primary_port <= 65535
        or not 1 <= alternate_port <= 65535
        or primary_port == alternate_port
        or selector not in {0, 1}
        or not literals[3].value
        or not literals[4].value
        or literals[3].value == literals[4].value
    ):
        return None
    destinations = {item.destination for item in literals}
    if len(destinations) != 5 or host_destination in destinations:
        return None

    last_literal_address = literals[-1].call_address
    object_calls: list[_ObjectCopy] = []
    direct_call_indices: set[int] = set()
    for index, instruction in enumerate(instructions):
        if (
            not last_literal_address
            < int(instruction.address)
            <= last_literal_address + 0x300
        ):
            continue
        if _direct_call_target(instruction, sections) is not None:
            direct_call_indices.add(index)
            if len(direct_call_indices) > MAXIMUM_WINDOW_DIRECT_CALLS:
                return None
        call = _object_copy_call(sections, summary, instructions, index)
        if call is not None:
            object_calls.append(call)
            if len(object_calls) > MAXIMUM_OBJECT_COPY_CANDIDATES:
                return None
    object_sequences: list[list[_ObjectCopy]] = []
    for index in range(max(0, len(object_calls) - 10)):
        sequence = object_calls[index : index + 11]
        if len({item.target for item in sequence}) != 1:
            continue
        low = sequence[0].instruction_index
        high = sequence[-1].instruction_index
        if {item.instruction_index for item in sequence} != {
            item for item in direct_call_indices if low <= item <= high
        }:
            continue
        if not _events_form_reachable_path(
            summary,
            [last_literal_address] + [item.call_address for item in sequence],
        ):
            continue
        object_sequences.append(sequence)
    if len(object_sequences) != 1:
        return None
    copies = object_sequences[0]
    object_helper_summary = summary_resolver(copies[0].target)
    if object_helper_summary is None:
        return None
    object_helper_evidence = _copy_helper_evidence(object_helper_summary, literal=False)
    if object_helper_evidence is None:
        return None
    category = {
        host_destination: "host",
        literals[0].destination: "primary_port",
        literals[1].destination: "alternate_port",
        literals[2].destination: "selector",
        literals[3].destination: "label_a",
        literals[4].destination: "label_b",
    }
    try:
        source_order = [category[item.source] for item in copies]
    except KeyError:
        return None
    expected_tail = [
        "selector",
        "alternate_port",
        "host",
        "selector",
        "primary_port",
        "host",
        "selector",
        "primary_port",
        "host",
    ]
    if (
        set(source_order[:2]) != {"label_a", "label_b"}
        or source_order[2:] != expected_tail
    ):
        return None

    post_calls: list[tuple[int, int]] = []
    last_copy_address = copies[-1].call_address
    for index, instruction in enumerate(instructions):
        if (
            not last_copy_address
            < int(instruction.address)
            <= last_copy_address + 0x100
        ):
            continue
        target = _direct_call_target(instruction, sections)
        if target is not None:
            post_calls.append((index, target))
            if len(post_calls) > MAXIMUM_POST_CALLS:
                return None
    if len(post_calls) < 3:
        return None
    (
        (builder_index, builder),
        (_post_copy_index, post_copy),
        (
            consumer_index,
            consumer,
        ),
    ) = post_calls[:3]
    if len({builder, post_copy, consumer}) != 3:
        return None
    if not _events_form_reachable_path(
        summary,
        [
            int(instructions[builder_index].address),
            int(instructions[_post_copy_index].address),
            int(instructions[consumer_index].address),
        ],
    ):
        return None
    builder_summary = summary_resolver(builder)
    if builder_summary is None or builder_summary.unresolved_control_flow_count:
        return None
    builder_evidence = _builder_decoder_evidence(builder_summary, decoder)
    if builder_evidence is None:
        return None
    consumer_summary = summary_resolver(consumer)
    if consumer_summary is None or consumer_summary.unresolved_control_flow_count:
        return None
    consumer_evidence = _consumer_evidence(consumer_summary)
    if consumer_evidence is None:
        return None
    consumer_call = int(instructions[consumer_index].address)
    if not _periodic_wait_present(summary, consumer_call):
        return None

    transport = "tcp" if selector == 1 else "udp"
    slots = [
        {
            "index": 1,
            "host": token.host,
            "port": primary_port,
            "transport": transport,
            "transport_selector": selector,
            "role": "primary",
            "enabled": True,
        },
        {
            "index": 2,
            "host": token.host,
            "port": primary_port,
            "transport": transport,
            "transport_selector": selector,
            "role": "primary_duplicate",
            "enabled": True,
        },
        {
            "index": 3,
            "host": token.host,
            "port": alternate_port,
            "transport": transport,
            "transport_selector": selector,
            "role": "alternate",
            "enabled": True,
        },
    ]
    endpoints = [
        {
            "host": token.host,
            "port": primary_port,
            "transport": transport,
            "role": "primary",
        },
        {
            "host": token.host,
            "port": alternate_port,
            "transport": transport,
            "role": "alternate",
        },
    ]
    identity_material = "\n".join(
        f"{slot['index']}|{slot['host']}|{slot['port']}|"
        f"{slot['transport_selector']}|{slot['role']}"
        for slot in slots
    ).encode("utf-8")
    config: dict[str, object] = {
        "variant": "ca01_x64_double_base64_sideload_terminal",
        "slots": slots,
        "endpoints": endpoints,
        "configuration_identity_sha256": hashlib.sha256(identity_material).hexdigest(),
    }
    evidence: dict[str, object] = {
        "double_base64_decode_depth": 2,
        "encoded_host_reference_count": len(token_references),
        "decoder": decoder_evidence,
        "literal_copy_length_sequence": [3, 3, 1, 2, 2],
        "literal_copy_helper": literal_helper_evidence,
        "object_copy_helper": object_helper_evidence,
        "slot_copy_count": len(copies),
        "slot_count": len(slots),
        "unique_endpoint_count": len(endpoints),
        "primary_slot_count": 2,
        "alternate_slot_count": 1,
        "explicit_transport_selector_count": 3,
        "builder": builder_evidence,
        "consumer": consumer_evidence,
        "periodic_wait_after_consumer_present": True,
        "raw_encoded_token_included": False,
        "raw_network_values_included": False,
        "raw_labels_included": False,
        "raw_addresses_included": False,
    }
    return config, evidence


def _certificate_overlay_evidence(image: pefile.PE, data: bytes) -> dict[str, object]:
    """overlayがPE Security Directoryなら内容を公開せず区別する。"""

    try:
        overlay_start = image.get_overlay_data_start_offset()
        directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[_SECURITY_DIRECTORY_INDEX]
        security_offset = int(directory.VirtualAddress)
        security_size = int(directory.Size)
    except (AttributeError, IndexError, TypeError, ValueError, OverflowError):
        return {
            "overlay_present": False,
            "overlay_is_security_directory": False,
            "overlay_content_included": False,
        }
    overlay_size = len(data) - overlay_start if overlay_start is not None else 0
    return {
        "overlay_present": overlay_start is not None and overlay_size > 0,
        "overlay_size": overlay_size,
        "overlay_is_security_directory": bool(
            overlay_start is not None
            and security_size > 0
            and security_offset == overlay_start
            and security_size == overlay_size
        ),
        "overlay_content_included": False,
    }


def _recover(data: bytes) -> Ca01SideloadRecovery | None:
    if (
        not isinstance(data, bytes)
        or len(data) > MAXIMUM_INPUT_SIZE
        or not data.startswith(b"MZ")
    ):
        return None
    try:
        image = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, ValueError, TypeError, OverflowError):
        return None
    try:
        if int(image.FILE_HEADER.Machine) != _X64_MACHINE:
            return None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    section_result = _sections(image, data)
    if section_result is None:
        return None
    sections, image_base = section_result
    exports = _export_roots(image, sections, image_base)
    imports = _import_addresses(image)
    if exports is None or imports is None:
        return None
    import_names = set(imports.values())
    if not {"createthread", "virtualprotect", "sleep"} <= import_names:
        return None
    token_candidates = _double_base64_candidates(data, sections)
    if token_candidates is None or not token_candidates:
        return None
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
    except CsError:
        return None

    summaries: dict[int, _FunctionSummary] = {}
    total_instructions = 0

    def summary(address: int) -> _FunctionSummary | None:
        nonlocal total_instructions
        existing = summaries.get(address)
        if existing is not None:
            return existing
        item = _function_summary(data, sections, disassembler, address, imports)
        if item is None:
            return None
        total_instructions += len(item.instructions)
        if total_instructions > MAXIMUM_TOTAL_INSTRUCTIONS:
            return None
        summaries[address] = item
        return item

    export_summary = summary(exports[0])
    if (
        export_summary is None
        or export_summary.unresolved_control_flow_count
        or not export_summary.direct_calls
    ):
        return None
    if len(export_summary.direct_calls) > MAXIMUM_MAIN_CALLEES:
        return None

    recoveries: list[tuple[dict[str, object], dict[str, object]]] = []
    linkage_counts = {
        "export_to_main_direct_call_count": 0,
        "main_to_thread_factory_direct_call_count": 0,
        "thread_factory_to_create_thread_wrapper_count": 0,
    }
    producer_attempts = 0
    for main_target in sorted(export_summary.direct_calls):
        main_summary = summary(main_target)
        if main_summary is None:
            return None
        if main_summary.unresolved_control_flow_count:
            continue
        linkage_counts["export_to_main_direct_call_count"] += 1
        if len(main_summary.direct_calls) > MAXIMUM_MAIN_CALLEES:
            return None
        for thread_target in sorted(main_summary.direct_calls):
            thread_summary = summary(thread_target)
            if thread_summary is None:
                return None
            if thread_summary.unresolved_control_flow_count:
                continue
            if len(thread_summary.direct_calls) > MAXIMUM_THREAD_CALLEES:
                return None
            wrapper_calls: list[tuple[int, int]] = []
            for wrapper_target in sorted(thread_summary.direct_calls):
                wrapper_summary = summary(wrapper_target)
                if wrapper_summary is None:
                    return None
                if wrapper_summary.unresolved_control_flow_count:
                    continue
                if any(
                    name == "createthread"
                    for _address, name in wrapper_summary.api_calls
                ):
                    wrapper_calls.extend(
                        (int(instruction.address), wrapper_target)
                        for instruction in thread_summary.instructions.values()
                        if _direct_call_target(instruction, sections) == wrapper_target
                    )
            if len(wrapper_calls) != 1:
                continue
            linkage_counts["main_to_thread_factory_direct_call_count"] += 1
            linkage_counts["thread_factory_to_create_thread_wrapper_count"] += 1
            wrapper_call_address, _wrapper = wrapper_calls[0]
            linked_references = set()
            for instruction in thread_summary.instructions.values():
                address = int(instruction.address)
                if not wrapper_call_address - 96 <= address < wrapper_call_address:
                    continue
                for operand in instruction.operands:
                    candidate = _operand_address(instruction, operand)
                    if (
                        candidate is not None
                        and candidate in thread_summary.executable_references
                    ):
                        linked_references.add(candidate)
            if not 2 <= len(linked_references) <= MAXIMUM_LINKED_CODE_REFERENCES:
                continue
            for producer in sorted(linked_references):
                producer_attempts += 1
                if producer_attempts > MAXIMUM_PRODUCER_CANDIDATES:
                    return None
                parsed = _parse_producer(
                    data,
                    sections,
                    disassembler,
                    producer,
                    token_candidates,
                    summary,
                )
                if parsed is not None:
                    recoveries.append(parsed)

    if len(recoveries) != 1:
        return None
    config, producer_evidence = recoveries[0]
    structural_evidence: dict[str, object] = {
        "architecture": "x64",
        "outer_profile": _VULKAN_OUTER_PROFILE,
        "vulkan_export_count": 1,
        "export_reachable_thread_config_lineage_present": True,
        "create_thread_wrapper_reachable": True,
        "producer_candidate_count": 1,
        "lineage_counts": linkage_counts,
        "producer": producer_evidence,
        "overlay": _certificate_overlay_evidence(image, data),
        "sample_executed": False,
        "recovered_stage_executed": False,
        "network_contacted": False,
    }
    return Ca01SideloadRecovery(
        outer_sha256=hashlib.sha256(data).hexdigest(),
        config=config,
        structural_evidence=structural_evidence,
    )


def _recover_cef(data: bytes) -> Ca01SideloadRecovery | None:
    """CEF多重alias exportと_beginthreadex callback型CA01を復元する。"""

    if (
        not isinstance(data, bytes)
        or len(data) > MAXIMUM_INPUT_SIZE
        or not data.startswith(b"MZ")
    ):
        return None
    try:
        image = pefile.PE(data=data, fast_load=False)
        if int(image.FILE_HEADER.Machine) != _X64_MACHINE:
            return None
    except (
        AttributeError,
        pefile.PEFormatError,
        TypeError,
        ValueError,
        OverflowError,
    ):
        return None
    section_result = _sections(image, data)
    if section_result is None:
        return None
    sections, image_base = section_result
    export_profile = _cef_export_profile(image, sections, image_base)
    imports = _cef_import_addresses(image)
    if (
        export_profile is None
        or imports is None
        or not _cef_loader_markers_present(data, sections)
    ):
        return None
    token_candidates = _double_base64_candidates(data, sections)
    if token_candidates is None or not token_candidates:
        return None
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
    except CsError:
        return None

    summaries: dict[int, _FunctionSummary] = {}
    total_instructions = 0

    def summary(address: int) -> _FunctionSummary | None:
        nonlocal total_instructions
        existing = summaries.get(address)
        if existing is not None:
            return existing
        item = _function_summary(data, sections, disassembler, address, imports)
        if item is None:
            return None
        total_instructions += len(item.instructions)
        if total_instructions > MAXIMUM_TOTAL_INSTRUCTIONS:
            return None
        summaries[address] = item
        return item

    lineage = _cef_callback_lineage(sections, export_profile.root, summary)
    if lineage is None:
        return None
    parsed = _parse_producer(
        data,
        sections,
        disassembler,
        lineage.producer,
        token_candidates,
        summary,
    )
    if parsed is None:
        return None
    config, producer_evidence = parsed
    structural_evidence: dict[str, object] = {
        "architecture": "x64",
        "outer_profile": _CEF_OUTER_PROFILE,
        "cef_export_count": export_profile.export_count,
        "cef_named_export_count": export_profile.export_count,
        "cef_export_count_with_prefix": export_profile.cef_export_count,
        "cef_required_export_count": len(_REQUIRED_CEF_EXPORTS),
        "coalesced_export_target_count": 1,
        "coalesced_export_peak_count": export_profile.export_count,
        "export_dll_name_matches_indcode": True,
        "mapped_loader_marker_count": len(_CEF_LOADER_MARKERS),
        "mapped_loader_marker_set_complete": True,
        "export_reachable_beginthreadex_config_lineage_present": True,
        "beginthreadex_wrapper_reachable": True,
        "producer_candidate_count": 1,
        "lineage_counts": {
            "export_to_main_direct_call_count": (
                lineage.export_to_main_direct_call_count
            ),
            "main_to_beginthreadex_wrapper_direct_call_count": (
                lineage.main_to_beginthreadex_wrapper_direct_call_count
            ),
            "beginthreadex_api_call_count": lineage.beginthreadex_api_call_count,
            "producer_pointer_store_count": lineage.producer_pointer_store_count,
            "callback_trampoline_indirect_call_count": (
                lineage.callback_trampoline_indirect_call_count
            ),
        },
        "producer": producer_evidence,
        "overlay": _certificate_overlay_evidence(image, data),
        "sample_executed": False,
        "recovered_stage_executed": False,
        "network_contacted": False,
    }
    return Ca01SideloadRecovery(
        outer_sha256=hashlib.sha256(data).hexdigest(),
        config=config,
        structural_evidence=structural_evidence,
    )


def validate_recovery_contract(recovery: object) -> bool:
    """CA01復元器の内部schemaを公開・family判定の直前で再検証する。"""

    if not isinstance(recovery, Ca01SideloadRecovery):
        return False
    if re.fullmatch(r"[0-9a-f]{64}", recovery.outer_sha256) is None:
        return False
    config = recovery.config
    evidence = recovery.structural_evidence
    if (
        not isinstance(config, dict)
        or config.get("variant") != "ca01_x64_double_base64_sideload_terminal"
        or not isinstance(evidence, dict)
    ):
        return False

    slots = config.get("slots")
    endpoints = config.get("endpoints")
    if (
        not isinstance(slots, list)
        or len(slots) != 3
        or not isinstance(endpoints, list)
        or len(endpoints) != 2
    ):
        return False

    expected_roles = ("primary", "primary_duplicate", "alternate")
    normalized_slots: list[dict[str, object]] = []
    for expected_index, (item, expected_role) in enumerate(
        zip(slots, expected_roles, strict=True),
        start=1,
    ):
        if not isinstance(item, dict):
            return False
        index = item.get("index")
        host = item.get("host")
        port = item.get("port")
        selector = item.get("transport_selector")
        transport = item.get("transport")
        if (
            type(index) is not int
            or index != expected_index
            or not isinstance(host, str)
            or type(port) is not int
            or not 1 <= port <= 65_535
            or type(selector) is not int
            or selector not in {0, 1}
            or not isinstance(transport, str)
            or transport != ("tcp" if selector == 1 else "udp")
            or item.get("role") != expected_role
            or item.get("enabled") is not True
        ):
            return False
        try:
            normalized_host = _normalize_host(host.encode("ascii"))
        except UnicodeEncodeError:
            return False
        if normalized_host is None or normalized_host != host:
            return False
        normalized_slots.append(
            {
                "index": index,
                "host": normalized_host,
                "port": port,
                "transport": transport,
                "transport_selector": selector,
                "role": expected_role,
            }
        )

    first, duplicate, alternate = normalized_slots
    if (
        first["host"] != duplicate["host"]
        or first["host"] != alternate["host"]
        or first["port"] != duplicate["port"]
        or first["port"] == alternate["port"]
        or len({slot["transport_selector"] for slot in normalized_slots}) != 1
    ):
        return False

    expected_endpoints = (
        {
            "host": first["host"],
            "port": first["port"],
            "transport": first["transport"],
            "role": "primary",
        },
        {
            "host": alternate["host"],
            "port": alternate["port"],
            "transport": alternate["transport"],
            "role": "alternate",
        },
    )
    for item, expected in zip(endpoints, expected_endpoints, strict=True):
        if not isinstance(item, dict):
            return False
        if any(item.get(key) != value for key, value in expected.items()):
            return False

    identity_material = "\n".join(
        f"{slot['index']}|{slot['host']}|{slot['port']}|"
        f"{slot['transport_selector']}|{slot['role']}"
        for slot in normalized_slots
    ).encode("utf-8")
    if config.get("configuration_identity_sha256") != hashlib.sha256(
        identity_material
    ).hexdigest():
        return False

    outer_profile = evidence.get("outer_profile")
    reviewed_profile = _REVIEWED_CA01_OUTER_PROFILES.get(recovery.outer_sha256)
    lineage_counts = evidence.get("lineage_counts")
    producer = evidence.get("producer")
    if (
        evidence.get("architecture") != "x64"
        or outer_profile not in {_VULKAN_OUTER_PROFILE, _CEF_OUTER_PROFILE}
        or (reviewed_profile is not None and reviewed_profile != outer_profile)
        or type(evidence.get("producer_candidate_count")) is not int
        or evidence.get("producer_candidate_count") != 1
        or evidence.get("sample_executed") is not False
        or evidence.get("recovered_stage_executed") is not False
        or evidence.get("network_contacted") is not False
        or not isinstance(lineage_counts, dict)
        or not isinstance(producer, dict)
    ):
        return False
    if outer_profile == _VULKAN_OUTER_PROFILE:
        if (
            type(evidence.get("vulkan_export_count")) is not int
            or evidence.get("vulkan_export_count") != 1
            or evidence.get("export_reachable_thread_config_lineage_present")
            is not True
            or evidence.get("create_thread_wrapper_reachable") is not True
            or any(key in evidence for key in _CEF_STRUCTURAL_EVIDENCE_KEYS)
            or any(key in lineage_counts for key in _CEF_LINEAGE_EVIDENCE_KEYS)
        ):
            return False
        lineage_keys = (
            "export_to_main_direct_call_count",
            "main_to_thread_factory_direct_call_count",
            "thread_factory_to_create_thread_wrapper_count",
        )
        if any(
            type(lineage_counts.get(key)) is not int
            or not 1 <= lineage_counts[key] <= MAXIMUM_TOTAL_INSTRUCTIONS
            for key in lineage_keys
        ):
            return False
    else:
        export_count = evidence.get("cef_export_count")
        named_export_count = evidence.get("cef_named_export_count")
        prefix_count = evidence.get("cef_export_count_with_prefix")
        required_export_count = evidence.get("cef_required_export_count")
        target_count = evidence.get("coalesced_export_target_count")
        peak_count = evidence.get("coalesced_export_peak_count")
        marker_count = evidence.get("mapped_loader_marker_count")
        cef_contract = (
            type(export_count) is int
            and 128 <= export_count <= MAXIMUM_CEF_EXPORTS
            and type(named_export_count) is int
            and named_export_count == export_count
            and type(prefix_count) is int
            and 128 <= prefix_count <= export_count
            and prefix_count >= export_count - 16
            and type(required_export_count) is int
            and required_export_count == len(_REQUIRED_CEF_EXPORTS)
            and type(target_count) is int
            and target_count == 1
            and type(peak_count) is int
            and peak_count == export_count
            and evidence.get("export_dll_name_matches_indcode") is True
            and type(marker_count) is int
            and marker_count == len(_CEF_LOADER_MARKERS)
            and evidence.get("mapped_loader_marker_set_complete") is True
            and evidence.get(
                "export_reachable_beginthreadex_config_lineage_present"
            )
            is True
            and evidence.get("beginthreadex_wrapper_reachable") is True
            and not any(
                key in evidence for key in _VULKAN_STRUCTURAL_EVIDENCE_KEYS
            )
            and not any(
                key in lineage_counts for key in _VULKAN_LINEAGE_EVIDENCE_KEYS
            )
        )
        if not cef_contract:
            return False
        lineage_keys = (
            "export_to_main_direct_call_count",
            "main_to_beginthreadex_wrapper_direct_call_count",
            "beginthreadex_api_call_count",
            "producer_pointer_store_count",
            "callback_trampoline_indirect_call_count",
        )
        if any(
            type(lineage_counts.get(key)) is not int
            or lineage_counts[key] != 1
            for key in lineage_keys
        ):
            return False
    required_producer_values = {
        "double_base64_decode_depth": 2,
        "slot_count": 3,
        "unique_endpoint_count": 2,
        "primary_slot_count": 2,
        "alternate_slot_count": 1,
        "explicit_transport_selector_count": 3,
        "periodic_wait_after_consumer_present": True,
        "raw_encoded_token_included": False,
        "raw_network_values_included": False,
        "raw_labels_included": False,
        "raw_addresses_included": False,
    }
    return all(
        producer.get(key) == value for key, value in required_producer_values.items()
    )


def recover_config(data: bytes) -> Ca01SideloadRecovery | None:
    """一意なCA01外層lineageが成立する場合だけ設定を返す。"""

    if (
        not isinstance(data, bytes)
        or len(data) > MAXIMUM_INPUT_SIZE
        or not data.startswith(b"MZ")
    ):
        return None
    try:
        # 両profileのexport名はPE export tableへ平文ASCIIで必ず存在する。
        # marker不在の一般PEでpefile解析と二重のCFG復元を開始しない。
        profile_recoveries = []
        if _VULKAN_EXPORT in data:
            profile_recoveries.append(_recover(data))
        if all(marker in data for marker in _REQUIRED_CEF_EXPORTS):
            profile_recoveries.append(_recover_cef(data))
        recoveries = [
            recovery
            for recovery in profile_recoveries
            if recovery is not None and validate_recovery_contract(recovery)
        ]
        return recoveries[0] if len(recoveries) == 1 else None
    except (
        AttributeError,
        Ca01SideloadError,
        CsError,
        IndexError,
        KeyError,
        OverflowError,
        TypeError,
        ValueError,
    ):
        return None


def _public_scalar_projection(
    source: object,
    *,
    count_keys: tuple[str, ...] = (),
    flag_keys: tuple[str, ...] = (),
) -> dict[str, object]:
    """公開可能な非負件数と真偽値だけを明示keyで射影する。"""

    if not isinstance(source, dict):
        return {}
    projected: dict[str, object] = {}
    for key in count_keys:
        value = source.get(key)
        if type(value) is int and 0 <= value <= MAXIMUM_TOTAL_INSTRUCTIONS:
            projected[key] = value
    for key in flag_keys:
        projected[key] = source.get(key) is True
    return projected


def _public_structural_projection(source: object) -> dict[str, object]:
    """内部structural evidenceを秘密値なしの固定schemaへ縮約する。"""

    if not isinstance(source, dict):
        return {}
    outer_profile = source.get("outer_profile")
    if outer_profile not in {_VULKAN_OUTER_PROFILE, _CEF_OUTER_PROFILE}:
        outer_profile = "unknown"
    projected: dict[str, object] = {
        "architecture": "x64" if source.get("architecture") == "x64" else "unknown",
        "outer_profile": outer_profile,
        **_public_scalar_projection(
            source,
            count_keys=("producer_candidate_count",),
        ),
    }
    if outer_profile == _VULKAN_OUTER_PROFILE:
        projected.update(
            _public_scalar_projection(
                source,
                count_keys=("vulkan_export_count",),
                flag_keys=(
                    "export_reachable_thread_config_lineage_present",
                    "create_thread_wrapper_reachable",
                ),
            )
        )
        projected["lineage_counts"] = _public_scalar_projection(
            source.get("lineage_counts"),
            count_keys=(
                "export_to_main_direct_call_count",
                "main_to_thread_factory_direct_call_count",
                "thread_factory_to_create_thread_wrapper_count",
            ),
        )
    elif outer_profile == _CEF_OUTER_PROFILE:
        projected.update(
            _public_scalar_projection(
                source,
                count_keys=(
                    "cef_export_count",
                    "cef_named_export_count",
                    "cef_export_count_with_prefix",
                    "cef_required_export_count",
                    "coalesced_export_target_count",
                    "coalesced_export_peak_count",
                    "mapped_loader_marker_count",
                ),
                flag_keys=(
                    "export_dll_name_matches_indcode",
                    "mapped_loader_marker_set_complete",
                    "export_reachable_beginthreadex_config_lineage_present",
                    "beginthreadex_wrapper_reachable",
                ),
            )
        )
        projected["lineage_counts"] = _public_scalar_projection(
            source.get("lineage_counts"),
            count_keys=(
                "export_to_main_direct_call_count",
                "main_to_beginthreadex_wrapper_direct_call_count",
                "beginthreadex_api_call_count",
                "producer_pointer_store_count",
                "callback_trampoline_indirect_call_count",
            ),
        )
    else:
        projected["lineage_counts"] = {}
    producer = source.get("producer")
    public_producer = _public_scalar_projection(
        producer,
        count_keys=(
            "double_base64_decode_depth",
            "encoded_host_reference_count",
            "slot_copy_count",
            "slot_count",
            "unique_endpoint_count",
            "primary_slot_count",
            "alternate_slot_count",
            "explicit_transport_selector_count",
        ),
        flag_keys=("periodic_wait_after_consumer_present",),
    )
    if isinstance(producer, dict):
        sequence = producer.get("literal_copy_length_sequence")
        if (
            isinstance(sequence, list)
            and len(sequence) <= 8
            and all(type(item) is int and 0 <= item <= 64 for item in sequence)
        ):
            public_producer["literal_copy_length_sequence"] = list(sequence)
        public_producer["decoder"] = _public_scalar_projection(
            producer.get("decoder"),
            count_keys=(
                "complete_base64_decode_table_count",
                "base64_decode_table_entry_count",
            ),
            flag_keys=(
                "six_bit_accumulation_present",
                "bounded_decode_table_allocation_present",
                "allocation_table_lookup_dataflow_present",
            ),
        )
        for helper_name in ("literal_copy_helper", "object_copy_helper"):
            public_producer[helper_name] = _public_scalar_projection(
                producer.get(helper_name),
                flag_keys=(
                    "entry_argument_lineage_present",
                    "destination_metadata_write_present",
                    "source_data_use_present",
                    "reachable_copy_call_present",
                    "reachable_return_present",
                ),
            )
        public_producer["builder"] = _public_scalar_projection(
            producer.get("builder"),
            count_keys=("double_decode_chain_count", "same_decoder_call_count"),
            flag_keys=(
                "shared_input_converter_present",
                "single_reachable_builder_path_present",
            ),
        )
        public_producer["consumer"] = _public_scalar_projection(
            producer.get("consumer"),
            count_keys=(
                "minimum_reachable_preparation_direct_call_count",
                "virtual_protect_call_count",
            ),
            flag_keys=(
                "page_execute_readwrite_transition_present",
                "recovered_buffer_indirect_call_present",
                "post_execution_virtual_protect_call_present",
                "protected_buffer_identity_preserved",
                "restored_protection_value_lineage_present",
            ),
        )
    public_producer.update(
        {
            "raw_encoded_token_included": False,
            "raw_network_values_included": False,
            "raw_labels_included": False,
            "raw_addresses_included": False,
        }
    )
    projected["producer"] = public_producer
    projected["overlay"] = {
        **_public_scalar_projection(
            source.get("overlay"),
            count_keys=("overlay_size",),
            flag_keys=("overlay_present", "overlay_is_security_directory"),
        ),
        "overlay_content_included": False,
    }
    projected.update(
        {
            "sample_executed": False,
            "recovered_stage_executed": False,
            "network_contacted": False,
        }
    )
    return projected


def public_recovery_summary(recovery: Ca01SideloadRecovery) -> dict[str, object]:
    """endpoint、Base64 token、label、addressを含まない要約を返す。"""

    if not validate_recovery_contract(recovery):
        return {
            "status": "invalid_ca01_recovery_contract",
            "reviewed_exact_outer_sha256": False,
            "slot_count": 0,
            "endpoint_count": 0,
            "structural_evidence": {},
            "raw_config_included": False,
            "raw_network_values_included": False,
            "raw_encoded_token_included": False,
            "raw_labels_included": False,
            "raw_addresses_included": False,
            "raw_key_included": False,
            "sample_executed": False,
            "recovered_stage_executed": False,
            "network_contacted": False,
        }
    slots = recovery.config.get("slots", [])
    endpoints = recovery.config.get("endpoints", [])
    outer_profile = recovery.structural_evidence.get("outer_profile")
    reviewed_exact = (
        _REVIEWED_CA01_OUTER_PROFILES.get(recovery.outer_sha256) == outer_profile
    )
    return {
        "status": "validated_ca01_x64_double_base64_sideload_config",
        "outer_sha256": recovery.outer_sha256,
        "reviewed_exact_outer_sha256": reviewed_exact,
        "outer_profile": outer_profile,
        "architecture": "x64",
        "slot_count": len(slots) if isinstance(slots, list) else 0,
        "endpoint_count": len(endpoints) if isinstance(endpoints, list) else 0,
        "structural_evidence": _public_structural_projection(
            recovery.structural_evidence
        ),
        "raw_config_included": False,
        "raw_network_values_included": False,
        "raw_encoded_token_included": False,
        "raw_labels_included": False,
        "raw_addresses_included": False,
        "raw_key_included": False,
        "sample_executed": False,
        "recovered_stage_executed": False,
        "network_contacted": False,
    }


def probe_config(data: bytes) -> dict[str, object]:
    """detector向けに秘密値なしのCA01終端証拠だけを返す。"""

    recovery = recover_config(data)
    if recovery is None or not validate_recovery_contract(recovery):
        return _unmatched_probe()
    endpoints = recovery.config.get("endpoints")
    slots = recovery.config.get("slots")
    endpoint_count = len(endpoints) if isinstance(endpoints, list) else 0
    slot_count = len(slots) if isinstance(slots, list) else 0
    outer_profile = recovery.structural_evidence.get("outer_profile")
    reviewed_exact = (
        _REVIEWED_CA01_OUTER_PROFILES.get(recovery.outer_sha256) == outer_profile
    )
    reviewed_scope = (
        "reviewed_exact_cef_alias_loader_linked_config_and_memory_stage_consumer"
        if outer_profile == _CEF_OUTER_PROFILE
        else "reviewed_exact_loader_linked_config_and_memory_stage_consumer"
    )
    reviewed_basis = (
        "reviewed_exact_sha256_and_cef_alias_export_to_beginthreadex_callback_"
        "double_base64_three_slot_consumer_lineage"
        if outer_profile == _CEF_OUTER_PROFILE
        else "reviewed_exact_sha256_and_vulkan_export_to_thread_callback_"
        "double_base64_three_slot_consumer_lineage"
    )
    return {
        "matched": True,
        "family": "valleyrat" if reviewed_exact else None,
        "variant": "ca01_x64_double_base64_sideload_terminal",
        "outer_profile": outer_profile,
        "supports_family_attribution": reviewed_exact,
        "attribution_scope": (
            reviewed_scope
            if reviewed_exact
            else "component_handler_route"
        ),
        "terminal_family_confirmed": reviewed_exact,
        "family_attribution_basis": (
            reviewed_basis
            if reviewed_exact
            else "ca01_structure_without_reviewed_terminal_identity"
        ),
        "classification_confidence": (
            "high_structural_decoded_config"
            if reviewed_exact
            else "medium_structural_config_route"
        ),
        "static_config_recovered": True,
        "candidate_config_recovered": False,
        "evidence": public_recovery_summary(recovery),
        "config": {
            "endpoint_count": endpoint_count,
            "slot_count": slot_count,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "Ca01SideloadRecovery",
    "probe_config",
    "public_recovery_summary",
    "recover_config",
    "validate_recovery_contract",
]
