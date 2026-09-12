"""ZIP内のDLL side-loadからvvaS shellcodeまでを静的に復元する。

このmoduleは検体を実行せず、ZIP memberをmemory上だけで検査する。単一の
文字列やfile名では帰属せず、同一directoryのimport/export edge、proxy DLLの
entrypoint到達CFG、launcherのfile/carve/実行sink、carve後shellcodeの通信構造、
codemark設定の相関が全て揃う場合だけ終端設定を返す。
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import zipfile
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

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
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_FS

from extractors.valleyrat.nvml_dat import normalize_host, render_endpoint

MAXIMUM_ARCHIVE_SIZE = 64 * 1024 * 1024
MAXIMUM_MEMBER_COUNT = 128
MAXIMUM_MEMBER_SIZE = 64 * 1024 * 1024
MAXIMUM_TOTAL_MEMBER_SIZE = 256 * 1024 * 1024
MAXIMUM_COMPRESSION_RATIO = 100.0
MAXIMUM_PE_MEMBERS = 32
MAXIMUM_PE_IMPORT_DESCRIPTORS = 128
MAXIMUM_PE_IMPORTS = 8_192
MAXIMUM_PE_EXPORTS = 8_192
MAXIMUM_PE_SECTIONS = 96
MAXIMUM_CFG_INSTRUCTIONS = 100_000
MAXIMUM_CFG_PENDING_BLOCKS = 16_384
MAXIMUM_STRING_BACKTRACK = 1_024
MAXIMUM_CARRIER_SIZE = 16 * 1024 * 1024
MINIMUM_CARRIER_SIZE = 512
DELIMITER_SIZE = 8
MINIMUM_SHELLCODE_SIZE = 512
MAXIMUM_SHELLCODE_SIZE = 4 * 1024 * 1024
MINIMUM_SHELLCODE_CODE_SIZE = 512
MAXIMUM_WIDE_CANDIDATES = 32
MAXIMUM_WIDE_CHARACTERS = 64 * 1024
CODEMARK = b"codemark"
CODEMARK_HEADER_SIZE = 0x38

_WIDE_ASCII = re.compile(rb"(?:[\x20-\x7e]\x00){12,4096}")
_VVAS_FIELD = re.compile(r"(?:^|\|)([pot][123]):([^|]{0,255})(?=\||$)", re.IGNORECASE)
_POWERSHELL_PERSISTENCE_MARKERS = (
    b"powershell.exe",
    b"register-scheduledtask",
    b"new-scheduledtaskaction",
)
_PROXY_PROCESS_ENUMERATION_APIS = frozenset(
    {"createtoolhelp32snapshot", "process32first", "process32next"}
)
_PROXY_TOKEN_LAUNCH_APIS = frozenset(
    {"openprocesstoken", "duplicatetokenex", "createprocessasusera"}
)
_PROXY_LAUNCH_APIS = frozenset(
    {"createprocessa", "createprocessw", "createprocessasusera", "createprocessasuserw"}
)
_FILE_OPEN_APIS = frozenset({"fopen", "_wfopen", "createfilea", "createfilew"})
_FILE_READ_APIS = frozenset({"fread", "readfile"})
_FILE_SEEK_APIS = frozenset({"fseek", "setfilepointer", "setfilepointerex"})
_FILE_SIZE_APIS = frozenset({"ftell", "getfilesize", "getfilesizeex"})
_MEMORY_ALLOC_APIS = frozenset({"virtualalloc", "virtualallocex"})
_MEMORY_PROTECT_APIS = frozenset({"virtualprotect", "virtualprotectex"})
_MEMORY_COPY_APIS = frozenset({"memcpy", "rtlmovememory", "copymemory"})
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "0.0.0.0", "::1"})


class ZipSideloadShellcodeError(ValueError):
    """入力が境界または一意性契約を満たさない場合の例外。"""


@dataclass(frozen=True)
class _ArchiveMember:
    """検証済みZIP memberのmemory内表現。"""

    path: str
    parent: str
    basename: str
    data: bytes


@dataclass(frozen=True)
class _ImportedSymbol:
    """PE importの名前またはordinal。"""

    name: str | None
    ordinal: int | None


@dataclass
class _PeMember:
    """CFGとside-load graphで使うPE memberの有界view。"""

    member: _ArchiveMember
    image: pefile.PE
    image_base: int
    machine: int
    is_dll: bool
    imports: dict[str, tuple[_ImportedSymbol, ...]]
    export_names: frozenset[str]
    export_ordinals: frozenset[int]


@dataclass(frozen=True)
class _ReachabilityEvidence:
    """entrypointから到達したCFGの非公開addressを含む内部証拠。"""

    completed: bool
    instruction_count: int
    direct_edge_count: int
    api_names: frozenset[str]
    target_references: frozenset[str]
    referenced_data_addresses: tuple[int, ...]
    indirect_call_count: int


@dataclass(frozen=True)
class RawVvasShellcodeRecovery:
    """vvaS transport shellcodeと相関済み設定。"""

    data: bytes
    endpoints: tuple[str, ...]
    endpoint_slots: tuple[dict[str, Any], ...]
    shellcode_evidence: dict[str, Any]
    config_evidence: dict[str, Any]


@dataclass(frozen=True)
class ZipSideloadShellcodeRecovery:
    """ZIP rootから終端vvaS設定までの完全な静的lineage。"""

    source_size: int
    member_count: int
    pe_member_count: int
    import_binding_count: int
    proxy_reachability: _ReachabilityEvidence
    launcher_reachability: _ReachabilityEvidence
    delimiter_size: int
    carrier_offset: int
    shellcode: RawVvasShellcodeRecovery


def _normalized_member_path(value: str) -> tuple[str, str, str]:
    """ZIP member pathを相対POSIX pathへ正規化する。"""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise ZipSideloadShellcodeError("ZIP member名が不正です")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ZipSideloadShellcodeError("ZIP member pathが相対path境界外です")
    rendered = path.as_posix()
    parent = path.parent.as_posix().casefold()
    if parent == ".":
        parent = ""
    return rendered, parent, path.name.casefold()


def _read_archive_members(data: bytes) -> tuple[_ArchiveMember, ...]:
    """ZIPをdiskへ展開せず、size・ratio・pathを検証して読む。"""

    if not isinstance(data, bytes) or not 22 <= len(data) <= MAXIMUM_ARCHIVE_SIZE:
        raise ZipSideloadShellcodeError("ZIP入力sizeが上限外です")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ZipSideloadShellcodeError("ZIP構造を読めません") from exc
    with archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        if not 1 <= len(infos) <= MAXIMUM_MEMBER_COUNT:
            raise ZipSideloadShellcodeError("ZIP member数が上限外です")
        total_size = 0
        seen_paths: set[str] = set()
        prepared: list[tuple[zipfile.ZipInfo, str, str, str]] = []
        for info in infos:
            path, parent, basename = _normalized_member_path(info.filename)
            key = path.casefold()
            if key in seen_paths:
                raise ZipSideloadShellcodeError(
                    "大小文字を無視した重複memberがあります"
                )
            seen_paths.add(key)
            if info.flag_bits & 0x1:
                raise ZipSideloadShellcodeError("内側ZIPの暗号化memberは扱いません")
            unix_type = (int(info.external_attr) >> 16) & 0xF000
            if unix_type == 0xA000:
                raise ZipSideloadShellcodeError("symbolic link memberは扱いません")
            if not 0 <= info.file_size <= MAXIMUM_MEMBER_SIZE:
                raise ZipSideloadShellcodeError("ZIP member sizeが上限外です")
            if info.file_size and info.compress_size <= 0:
                raise ZipSideloadShellcodeError("ZIP圧縮sizeが不正です")
            if (
                info.compress_size
                and info.file_size / info.compress_size > MAXIMUM_COMPRESSION_RATIO
            ):
                raise ZipSideloadShellcodeError("ZIP圧縮率が上限を超えています")
            total_size += int(info.file_size)
            if total_size > MAXIMUM_TOTAL_MEMBER_SIZE:
                raise ZipSideloadShellcodeError("ZIP展開後総sizeが上限を超えています")
            prepared.append((info, path, parent, basename))
        members = []
        for info, path, parent, basename in prepared:
            try:
                payload = archive.read(info)
            except (
                OSError,
                RuntimeError,
                NotImplementedError,
                zipfile.BadZipFile,
            ) as exc:
                raise ZipSideloadShellcodeError("ZIP memberを安全に読めません") from exc
            if len(payload) != info.file_size:
                raise ZipSideloadShellcodeError("ZIP member sizeがheaderと一致しません")
            members.append(_ArchiveMember(path, parent, basename, payload))
    return tuple(members)


def _parse_pe_member(member: _ArchiveMember) -> _PeMember | None:
    """有効なx86 PEだけをside-load graph用に正規化する。"""

    if not member.data.startswith(b"MZ") or len(member.data) > MAXIMUM_MEMBER_SIZE:
        return None
    try:
        image = pefile.PE(data=member.data, fast_load=False)
    except (pefile.PEFormatError, OSError, OverflowError, ValueError):
        return None
    if (
        int(image.FILE_HEADER.Machine) != 0x14C
        or int(image.OPTIONAL_HEADER.Magic) != 0x10B
        or len(image.sections) > MAXIMUM_PE_SECTIONS
    ):
        return None
    descriptors = list(getattr(image, "DIRECTORY_ENTRY_IMPORT", []))
    if len(descriptors) > MAXIMUM_PE_IMPORT_DESCRIPTORS:
        return None
    imports: dict[str, tuple[_ImportedSymbol, ...]] = {}
    import_count = 0
    for descriptor in descriptors:
        raw_module = getattr(descriptor, "dll", None)
        if not isinstance(raw_module, bytes) or not raw_module:
            return None
        try:
            module = PurePosixPath(
                raw_module.decode("ascii").replace("\\", "/")
            ).name.casefold()
        except UnicodeDecodeError:
            return None
        symbols: list[_ImportedSymbol] = []
        for imported in getattr(descriptor, "imports", []):
            import_count += 1
            if import_count > MAXIMUM_PE_IMPORTS:
                return None
            raw_name = getattr(imported, "name", None)
            name = None
            if raw_name is not None:
                if not isinstance(raw_name, bytes) or len(raw_name) > 512:
                    return None
                try:
                    name = raw_name.decode("ascii").casefold()
                except UnicodeDecodeError:
                    return None
            raw_ordinal = getattr(imported, "ordinal", None)
            ordinal = int(raw_ordinal) if isinstance(raw_ordinal, int) else None
            if name is None and (ordinal is None or not 0 <= ordinal <= 0xFFFF):
                return None
            symbols.append(_ImportedSymbol(name, ordinal))
        imports[module] = tuple(symbols)
    export_names: set[str] = set()
    export_ordinals: set[int] = set()
    export_directory = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
    export_symbols = list(getattr(export_directory, "symbols", []))
    if len(export_symbols) > MAXIMUM_PE_EXPORTS:
        return None
    for exported in export_symbols:
        ordinal = getattr(exported, "ordinal", None)
        if isinstance(ordinal, int) and 0 <= ordinal <= 0xFFFF:
            export_ordinals.add(int(ordinal))
        raw_name = getattr(exported, "name", None)
        if isinstance(raw_name, bytes) and len(raw_name) <= 512:
            try:
                export_names.add(raw_name.decode("ascii").casefold())
            except UnicodeDecodeError:
                continue
    return _PeMember(
        member=member,
        image=image,
        image_base=int(image.OPTIONAL_HEADER.ImageBase),
        machine=int(image.FILE_HEADER.Machine),
        is_dll=bool(int(image.FILE_HEADER.Characteristics) & 0x2000),
        imports=imports,
        export_names=frozenset(export_names),
        export_ordinals=frozenset(export_ordinals),
    )


def _section_ranges(
    pe: _PeMember,
) -> tuple[list[tuple[int, int]], list[tuple[int, int, int, bool]]]:
    """実行VA範囲とfile-backed section対応を返す。"""

    executable: list[tuple[int, int]] = []
    mapped: list[tuple[int, int, int, bool]] = []
    for section in pe.image.sections:
        raw_start = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        virtual_start = pe.image_base + int(section.VirtualAddress)
        virtual_size = max(int(section.Misc_VirtualSize), raw_size)
        if raw_start < 0 or raw_size < 0 or raw_start + raw_size > len(pe.member.data):
            continue
        is_executable = bool(int(section.Characteristics) & 0x20000000)
        if virtual_size > 0 and is_executable:
            executable.append((virtual_start, virtual_start + virtual_size))
        if raw_size > 0:
            mapped.append(
                (virtual_start, virtual_start + raw_size, raw_start, is_executable)
            )
    return executable, mapped


def _in_ranges(address: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def _va_to_file_offset(
    pe: _PeMember, address: int, *, non_executable_only: bool = False
) -> int | None:
    """file-backed VAだけをraw offsetへ変換する。"""

    _executable, mapped = _section_ranges(pe)
    for start, end, raw_start, executable in mapped:
        if start <= address < end and (not non_executable_only or not executable):
            return raw_start + address - start
    return None


def _offset_to_va(
    pe: _PeMember, offset: int, *, non_executable_only: bool = True
) -> int | None:
    """file-backed raw offsetをVAへ変換する。"""

    _executable, mapped = _section_ranges(pe)
    for start, end, raw_start, executable in mapped:
        raw_end = raw_start + (end - start)
        if raw_start <= offset < raw_end and (
            not non_executable_only or not executable
        ):
            return start + offset - raw_start
    return None


def _c_string_target_addresses(pe: _PeMember, basename: str) -> frozenset[int]:
    """member basenameを含むbounded C文字列先頭のmapped VAを返す。"""

    if not basename or len(basename) > 260:
        return frozenset()
    result: set[int] = set()
    lowered = pe.member.data.lower()
    needle = basename.encode("ascii", "strict").lower()
    cursor = 0
    while True:
        found = lowered.find(needle, cursor)
        if found < 0:
            break
        start = found
        while (
            start > 0
            and found - start < MAXIMUM_STRING_BACKTRACK
            and 0x20 <= pe.member.data[start - 1] <= 0x7E
        ):
            start -= 1
        value_end = found + len(needle)
        while (
            value_end < len(pe.member.data)
            and value_end - start < MAXIMUM_STRING_BACKTRACK
            and 0x20 <= pe.member.data[value_end] <= 0x7E
        ):
            value_end += 1
        if value_end < len(pe.member.data) and pe.member.data[value_end] == 0:
            address = _offset_to_va(pe, start)
            if address is not None:
                result.add(address)
        cursor = found + 1

    wide_needle = basename.encode("utf-16le")
    cursor = 0
    while True:
        found = lowered.find(wide_needle.lower(), cursor)
        if found < 0:
            break
        start = found
        while start >= 2 and found - start < MAXIMUM_STRING_BACKTRACK:
            pair = pe.member.data[start - 2 : start]
            if len(pair) != 2 or pair[1] != 0 or not 0x20 <= pair[0] <= 0x7E:
                break
            start -= 2
        value_end = found + len(wide_needle)
        while (
            value_end + 1 < len(pe.member.data)
            and value_end - start < MAXIMUM_STRING_BACKTRACK
        ):
            pair = pe.member.data[value_end : value_end + 2]
            if pair[1] != 0 or not 0x20 <= pair[0] <= 0x7E:
                break
            value_end += 2
        if pe.member.data[value_end : value_end + 2] == b"\0\0":
            address = _offset_to_va(pe, start)
            if address is not None:
                result.add(address)
        cursor = found + 2
    return frozenset(result)


def _iat_map(pe: _PeMember) -> dict[int, str]:
    """IAT VAをlowercase API名へ結ぶ。"""

    result: dict[int, str] = {}
    for descriptor in getattr(pe.image, "DIRECTORY_ENTRY_IMPORT", []):
        raw_module = getattr(descriptor, "dll", b"")
        try:
            module = raw_module.decode("ascii").casefold()
        except (AttributeError, UnicodeDecodeError):
            continue
        for imported in getattr(descriptor, "imports", []):
            address = getattr(imported, "address", None)
            if not isinstance(address, int):
                continue
            raw_name = getattr(imported, "name", None)
            if isinstance(raw_name, bytes):
                try:
                    name = raw_name.decode("ascii").casefold()
                except UnicodeDecodeError:
                    continue
            else:
                ordinal = getattr(imported, "ordinal", None)
                name = f"#{ordinal}" if isinstance(ordinal, int) else "#unknown"
            result[int(address)] = f"{module}!{name}"
    return result


def _reachable_pe_evidence(
    pe: _PeMember,
    target_addresses: Mapping[str, frozenset[int]],
) -> _ReachabilityEvidence:
    """PE entrypointからdirect branch/callを辿る有界x86 CFGを作る。"""

    executable, _mapped = _section_ranges(pe)
    entry = pe.image_base + int(pe.image.OPTIONAL_HEADER.AddressOfEntryPoint)
    if not _in_ranges(entry, executable):
        return _ReachabilityEvidence(False, 0, 0, frozenset(), frozenset(), (), 0)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    iat = _iat_map(pe)
    pending: deque[int] = deque([entry])
    queued = {entry}
    seen: set[int] = set()
    apis: set[str] = set()
    target_refs: set[str] = set()
    data_refs: set[int] = set()
    direct_edges = 0
    indirect_calls = 0
    decode_failed = False
    limit_reached = False
    while pending:
        if len(pending) > MAXIMUM_CFG_PENDING_BLOCKS:
            limit_reached = True
            break
        address = pending.popleft()
        while _in_ranges(address, executable) and address not in seen:
            if len(seen) >= MAXIMUM_CFG_INSTRUCTIONS:
                limit_reached = True
                break
            offset = _va_to_file_offset(pe, address)
            if offset is None:
                decode_failed = True
                break
            try:
                instruction = next(
                    disassembler.disasm(
                        pe.member.data[offset : offset + 16], address, count=1
                    ),
                    None,
                )
            except CsError:
                instruction = None
            if instruction is None:
                decode_failed = True
                break
            seen.add(address)
            next_address = int(instruction.address + instruction.size)
            operand_values: list[int] = []
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM:
                    operand_values.append(int(operand.imm) & 0xFFFFFFFF)
                elif operand.type == X86_OP_MEM:
                    operand_values.append(int(operand.mem.disp) & 0xFFFFFFFF)
            for label, values in target_addresses.items():
                if any(value in values for value in operand_values):
                    target_refs.add(label)
            for value in operand_values:
                if _va_to_file_offset(pe, value, non_executable_only=True) is not None:
                    data_refs.add(value)
            transfer_target = operand_values[0] if operand_values else None
            is_call = bool(instruction.group(CS_GRP_CALL))
            is_jump = bool(instruction.group(CS_GRP_JUMP))
            if (is_call or is_jump) and transfer_target in iat:
                apis.add(iat[transfer_target])
            if is_call:
                if instruction.operands and instruction.operands[0].type == X86_OP_IMM:
                    if transfer_target is not None and _in_ranges(
                        transfer_target, executable
                    ):
                        direct_edges += 1
                        if transfer_target not in queued:
                            pending.append(transfer_target)
                            queued.add(transfer_target)
                elif transfer_target not in iat:
                    indirect_calls += 1
                address = next_address
                continue
            if is_jump:
                if (
                    instruction.operands
                    and instruction.operands[0].type == X86_OP_IMM
                    and transfer_target is not None
                    and _in_ranges(transfer_target, executable)
                ):
                    direct_edges += 1
                    if transfer_target not in queued:
                        pending.append(transfer_target)
                        queued.add(transfer_target)
                if instruction.mnemonic.casefold() == "jmp":
                    break
            if instruction.group(CS_GRP_RET) or instruction.mnemonic.casefold() in {
                "hlt",
                "int3",
                "ud2",
            }:
                break
            address = next_address
        if limit_reached:
            break
    return _ReachabilityEvidence(
        completed=not limit_reached and not decode_failed,
        instruction_count=len(seen),
        direct_edge_count=direct_edges,
        api_names=frozenset(apis),
        target_references=frozenset(target_refs),
        referenced_data_addresses=tuple(sorted(data_refs)),
        indirect_call_count=indirect_calls,
    )


def _api_leafs(evidence: _ReachabilityEvidence) -> frozenset[str]:
    return frozenset(value.rpartition("!")[2] for value in evidence.api_names)


def _imports_satisfied(host: _PeMember, proxy: _PeMember) -> int:
    """hostが同居DLLから要求するsymbolが全てexportされる場合の件数。"""

    requested = host.imports.get(proxy.member.basename)
    if requested is None or len(requested) < 3:
        return 0
    for symbol in requested:
        if symbol.name is not None:
            if symbol.name not in proxy.export_names:
                return 0
        elif symbol.ordinal is None or symbol.ordinal not in proxy.export_ordinals:
            return 0
    return len(requested)


def _proxy_lineage_evidence(
    proxy: _PeMember,
    launchers: tuple[_PeMember, ...],
) -> tuple[_ReachabilityEvidence, tuple[_PeMember, ...]] | None:
    """proxy entrypointから子EXE参照とprocess起動APIへの到達を証明する。"""

    targets = {
        f"launcher_{index}": _c_string_target_addresses(proxy, item.member.basename)
        for index, item in enumerate(launchers)
    }
    targets = {key: value for key, value in targets.items() if value}
    if not targets:
        return None
    evidence = _reachable_pe_evidence(proxy, targets)
    apis = _api_leafs(evidence)
    lowered = proxy.member.data.lower()
    if not (
        evidence.completed
        and evidence.instruction_count >= 64
        and _PROXY_PROCESS_ENUMERATION_APIS.issubset(apis)
        and _PROXY_TOKEN_LAUNCH_APIS.issubset(apis)
        and bool(_PROXY_LAUNCH_APIS & apis)
        and all(marker in lowered for marker in _POWERSHELL_PERSISTENCE_MARKERS)
    ):
        return None
    selected = tuple(
        launchers[index]
        for index in range(len(launchers))
        if f"launcher_{index}" in evidence.target_references
    )
    if not selected:
        return None
    return evidence, selected


def _looks_like_delimiter(value: bytes) -> bool:
    """一般header/文字列ではない8-byte delimiter候補だけを許可する。"""

    return (
        len(value) == DELIMITER_SIZE
        and len(set(value)) >= 6
        and any(byte < 0x20 or byte > 0x7E for byte in value)
        and value not in {b"\0" * DELIMITER_SIZE, b"\xff" * DELIMITER_SIZE}
    )


def _delimiter_recoveries(
    launcher: _PeMember,
    carrier: _ArchiveMember,
    reachability: _ReachabilityEvidence,
) -> tuple[tuple[bytes, int, bytes], ...]:
    """code参照済み定数とcarrierに一意なdelimiterだけでpayloadをcarveする。"""

    recoveries: dict[tuple[bytes, int, str], tuple[bytes, int, bytes]] = {}
    for address in reachability.referenced_data_addresses:
        offset = _va_to_file_offset(launcher, address, non_executable_only=True)
        if offset is None or offset + DELIMITER_SIZE > len(launcher.member.data):
            continue
        delimiter = launcher.member.data[offset : offset + DELIMITER_SIZE]
        if not _looks_like_delimiter(delimiter):
            continue
        if (
            launcher.member.data.count(delimiter) != 1
            or carrier.data.count(delimiter) != 1
        ):
            continue
        carrier_offset = carrier.data.find(delimiter)
        payload = carrier.data[carrier_offset + DELIMITER_SIZE :]
        if not MINIMUM_SHELLCODE_SIZE <= len(payload) <= MAXIMUM_SHELLCODE_SIZE:
            continue
        key = (delimiter, carrier_offset, hashlib.sha256(payload).hexdigest())
        recoveries[key] = (delimiter, carrier_offset, payload)
    return tuple(recoveries[key] for key in sorted(recoveries))


def _raw_x86_cfg(data: bytes, code_end: int) -> tuple[dict[int, Any], bool]:
    """offset 0からcodemark直前までのx86 CFGを有界に復号する。"""

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    pending: deque[int] = deque([0])
    queued = {0}
    instructions: dict[int, Any] = {}
    failed = False
    while pending:
        if len(pending) > MAXIMUM_CFG_PENDING_BLOCKS:
            return instructions, False
        address = pending.popleft()
        while 0 <= address < code_end and address not in instructions:
            if len(instructions) >= MAXIMUM_CFG_INSTRUCTIONS:
                return instructions, False
            try:
                instruction = next(
                    disassembler.disasm(
                        data[address : min(code_end, address + 16)], address, count=1
                    ),
                    None,
                )
            except CsError:
                instruction = None
            if instruction is None:
                failed = True
                break
            instructions[address] = instruction
            next_address = int(instruction.address + instruction.size)
            target = None
            if instruction.operands and instruction.operands[0].type == X86_OP_IMM:
                target = int(instruction.operands[0].imm) & 0xFFFFFFFF
            if instruction.group(CS_GRP_CALL):
                if (
                    target is not None
                    and 0 <= target < code_end
                    and target not in queued
                ):
                    pending.append(target)
                    queued.add(target)
                address = next_address
                continue
            if instruction.group(CS_GRP_JUMP):
                if (
                    target is not None
                    and 0 <= target < code_end
                    and target not in queued
                ):
                    pending.append(target)
                    queued.add(target)
                if instruction.mnemonic.casefold() == "jmp":
                    break
            if instruction.group(CS_GRP_RET) or instruction.mnemonic.casefold() in {
                "hlt",
                "int3",
                "ud2",
            }:
                break
            address = next_address
    return instructions, not failed


def _codemark_compare_present(instructions: Mapping[int, Any]) -> bool:
    """reachableなbyte比較列がcodemarkを直接照合することを確認する。"""

    comparisons: list[tuple[int, int]] = []
    for address in sorted(instructions):
        instruction = instructions[address]
        if instruction.mnemonic.casefold() != "cmp" or len(instruction.operands) != 2:
            continue
        first, second = instruction.operands
        if first.type == X86_OP_MEM and second.type == X86_OP_IMM:
            comparisons.append((address, int(second.imm) & 0xFF))
    for index in range(0, len(comparisons) - len(CODEMARK) + 1):
        window = comparisons[index : index + len(CODEMARK)]
        if (
            bytes(value for _address, value in window) == CODEMARK
            and window[-1][0] - window[0][0] <= 128
        ):
            return True
    return False


def _push_sequence_present(
    instructions: Mapping[int, Any], expected: tuple[int, ...]
) -> bool:
    pushes: list[tuple[int, int]] = []
    for address in sorted(instructions):
        instruction = instructions[address]
        if (
            instruction.mnemonic.casefold() == "push"
            and len(instruction.operands) == 1
            and instruction.operands[0].type == X86_OP_IMM
        ):
            pushes.append((address, int(instruction.operands[0].imm) & 0xFFFFFFFF))
    for index in range(0, len(pushes) - len(expected) + 1):
        window = pushes[index : index + len(expected)]
        if (
            tuple(value for _address, value in window) == expected
            and window[-1][0] - window[0][0] <= 32
        ):
            return True
    return False


def _shellcode_structure_evidence(data: bytes) -> dict[str, Any] | None:
    """vvaS bootstrapのmarker探索、resolver、socket、check-in構造を検証する。"""

    if data.count(CODEMARK) != 1:
        return None
    marker_offset = data.find(CODEMARK)
    if not MINIMUM_SHELLCODE_CODE_SIZE <= marker_offset < len(data):
        return None
    instructions, completed = _raw_x86_cfg(data, marker_offset)
    decoded_bytes = sum(int(item.size) for item in instructions.values())
    coverage = decoded_bytes / marker_offset if marker_offset else 0.0
    immediates = {
        int(operand.imm) & 0xFFFFFFFF
        for instruction in instructions.values()
        for operand in instruction.operands
        if operand.type == X86_OP_IMM
    }
    peb_read = any(
        operand.type == X86_OP_MEM
        and int(operand.mem.segment) == X86_REG_FS
        and int(operand.mem.disp) == 0x30
        for instruction in instructions.values()
        for operand in instruction.operands
    )
    indirect_calls = sum(
        bool(instruction.group(CS_GRP_CALL))
        and bool(instruction.operands)
        and instruction.operands[0].type != X86_OP_IMM
        for instruction in instructions.values()
    )
    code = data[:marker_offset]
    winsock_fragments = all(fragment in code for fragment in (b"Ws2_", b"32.d", b"ll"))
    required = {
        "bounded_cfg_complete": completed,
        "instruction_floor": len(instructions) >= 200,
        "instruction_coverage": coverage >= 0.95,
        "peb_fs30_resolver": peb_read,
        "codemark_byte_compare": _codemark_compare_present(instructions),
        "winsock_library_constructed": winsock_fragments,
        "wsa_startup_version": 0x202 in immediates,
        "tcp_socket_arguments": _push_sequence_present(instructions, (6, 1, 2)),
        "vvas_checkin_literal": 0x3233 in immediates,
        "executable_allocation_constants": {0x40, 0x3000}.issubset(immediates),
        "indirect_api_calls": indirect_calls >= 8,
    }
    if not all(required.values()):
        return None
    return {
        "architecture": "x86",
        "code_size": marker_offset,
        "reachable_instruction_count": len(instructions),
        "instruction_coverage": round(coverage, 6),
        "indirect_call_count": indirect_calls,
        "required_groups": required,
        "raw_code_included": False,
        "raw_addresses_included": False,
    }


def _decode_ascii_host(data: bytes, offset: int, length: int) -> tuple[str, int] | None:
    """codemark headerのNUL終端ASCII hostを境界検証する。"""

    if not 2 <= length <= 256 or offset < 0 or offset + length > len(data):
        return None
    raw = data[offset : offset + length]
    if raw[-1:] != b"\0" or b"\0" in raw[:-1]:
        return None
    try:
        decoded = raw[:-1].decode("ascii")
    except UnicodeDecodeError:
        return None
    host = normalize_host(decoded)
    if host is None:
        return None
    return host, offset + length


def _wide_candidates(data: bytes) -> tuple[str, ...] | None:
    """境界済みtailから反転UTF-16LE候補を上限付きで列挙する。"""

    values: list[str] = []
    total_characters = 0
    for alignment in (0, 1):
        for match in _WIDE_ASCII.finditer(data[alignment:]):
            if len(values) >= MAXIMUM_WIDE_CANDIDATES:
                return None
            try:
                decoded = match.group().decode("utf-16le")
            except UnicodeDecodeError:
                continue
            total_characters += len(decoded)
            if total_characters > MAXIMUM_WIDE_CHARACTERS:
                return None
            values.append(decoded)
    return tuple(values)


def _slot_fields(value: str) -> dict[str, str] | None:
    """1個の反転wide文字列からp/o/t fieldだけを一意に得る。"""

    if len(value) > 4096 or ":1p" not in value or ":1o" not in value:
        return None
    fields: dict[str, str] = {}
    for match in _VVAS_FIELD.finditer(value[::-1]):
        key = match.group(1).casefold()
        raw = match.group(2).strip()
        if key in fields and fields[key] != raw:
            return None
        fields[key] = raw
    required = {f"{prefix}{index}" for index in (1, 2, 3) for prefix in ("p", "o", "t")}
    return fields if required.issubset(fields) else None


def _parse_correlated_config(
    data: bytes, marker_offset: int
) -> tuple[tuple[str, ...], tuple[dict[str, Any], ...], dict[str, Any]] | None:
    """headerと末尾vvaS設定を相関し、欠落backupをendpointから除外する。"""

    if marker_offset + CODEMARK_HEADER_SIZE > len(data):
        return None
    values = struct.unpack_from("<IIIIII", data, marker_offset + 0x20)
    first_length, first_port, first_flag, second_length, second_port, second_flag = (
        values
    )
    if first_flag != 1 or second_flag not in {0, 1} or not 1 <= first_port <= 65535:
        return None
    first_offset = marker_offset + CODEMARK_HEADER_SIZE
    first = _decode_ascii_host(data, first_offset, first_length)
    if first is None:
        return None
    first_host, second_offset = first
    second = _decode_ascii_host(data, second_offset, second_length)
    if second is None:
        return None
    second_host, tail_offset = second
    candidates = _wide_candidates(data[tail_offset:])
    if candidates is None:
        return None
    configurations: dict[
        tuple[tuple[int, str, int, int, str], ...],
        tuple[tuple[str, ...], tuple[dict[str, Any], ...], int],
    ] = {}
    for candidate in candidates:
        fields = _slot_fields(candidate)
        if fields is None:
            continue
        if any(fields[f"t{index}"] not in {"0", "1"} for index in (1, 2, 3)):
            continue
        if (
            normalize_host(fields["p1"]) != first_host
            or not fields["o1"].isdigit()
            or int(fields["o1"]) != first_port
        ):
            continue
        if normalize_host(fields["p2"]) != second_host:
            continue
        if second_port == 0:
            if fields["o2"] != "" or second_host != first_host:
                continue
        elif not fields["o2"].isdigit() or int(fields["o2"]) != second_port:
            continue
        identity: list[tuple[int, str, int, int, str]] = []
        public_slots: list[dict[str, Any]] = []
        endpoints: list[str] = []
        incomplete = 0
        valid = True
        for index in (1, 2, 3):
            raw_host = fields[f"p{index}"]
            raw_port = fields[f"o{index}"]
            transport = int(fields[f"t{index}"])
            if index == 2 and second_port == 0 and raw_port == "":
                host = normalize_host(raw_host)
                if host is None:
                    valid = False
                    break
                state = "incomplete_backup_without_port"
                port = 0
                incomplete += 1
            elif raw_host == "" and raw_port == "":
                host = ""
                port = 0
                state = "empty_backup"
            else:
                host = normalize_host(raw_host)
                if (
                    host is None
                    or not raw_port.isdigit()
                    or not 1 <= int(raw_port) <= 65535
                ):
                    valid = False
                    break
                port = int(raw_port)
                state = (
                    "placeholder" if host in _LOOPBACK_HOSTS else "configured_external"
                )
                if state == "configured_external":
                    endpoint = render_endpoint(host, port)
                    if endpoint is None:
                        valid = False
                        break
                    endpoints.append(endpoint)
            identity.append((index, host, port, transport, state))
            slot: dict[str, Any] = {
                "slot": index,
                "transport": "tcp" if transport == 1 else "udp",
                "state": state,
            }
            if state == "configured_external":
                slot["endpoint"] = render_endpoint(host, port)
            public_slots.append(slot)
        if not valid or not endpoints:
            continue
        identity_tuple = tuple(identity)
        configurations[identity_tuple] = (
            tuple(dict.fromkeys(endpoints)),
            tuple(public_slots),
            incomplete,
        )
    if len(configurations) != 1:
        return None
    identity, (endpoints, slots, incomplete) = next(iter(configurations.items()))
    return (
        endpoints,
        slots,
        {
            "status": "decoded_unique_correlated_header_and_reversed_utf16le",
            "configured_slot_count": len(identity),
            "external_endpoint_count": len(endpoints),
            "incomplete_backup_slot_count": incomplete,
            "placeholder_slot_count": sum(
                item[4] == "placeholder" for item in identity
            ),
            "candidate_count": 1,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
    )


def recover_raw_vvas_shellcode(data: bytes) -> RawVvasShellcodeRecovery | None:
    """raw x86 shellcodeから通信構造と相関済みvvaS設定を復元する。"""

    if (
        not isinstance(data, bytes)
        or not MINIMUM_SHELLCODE_SIZE <= len(data) <= MAXIMUM_SHELLCODE_SIZE
        or data.startswith((b"MZ", b"PK\x03\x04", bytes.fromhex("d0cf11e0a1b11ae1")))
    ):
        return None
    structure = _shellcode_structure_evidence(data)
    if structure is None:
        return None
    marker_offset = data.find(CODEMARK)
    parsed = _parse_correlated_config(data, marker_offset)
    if parsed is None:
        return None
    endpoints, slots, config_evidence = parsed
    return RawVvasShellcodeRecovery(
        data=data,
        endpoints=endpoints,
        endpoint_slots=slots,
        shellcode_evidence=structure,
        config_evidence=config_evidence,
    )


def _launcher_lineage(
    launcher: _PeMember,
    carriers: tuple[_ArchiveMember, ...],
) -> (
    tuple[
        _ReachabilityEvidence,
        tuple[tuple[_ArchiveMember, bytes, int, RawVvasShellcodeRecovery], ...],
    ]
    | None
):
    """launcherのfile source、delimiter transform、memory sinkを同一CFGで結ぶ。"""

    targets = {
        f"carrier_{index}": _c_string_target_addresses(launcher, item.basename)
        for index, item in enumerate(carriers)
    }
    targets = {key: value for key, value in targets.items() if value}
    if not targets:
        return None
    evidence = _reachable_pe_evidence(launcher, targets)
    apis = _api_leafs(evidence)
    if not (
        evidence.completed
        and evidence.instruction_count >= 64
        and bool(_FILE_OPEN_APIS & apis)
        and bool(_FILE_READ_APIS & apis)
        and bool(_FILE_SEEK_APIS & apis)
        and bool(_FILE_SIZE_APIS & apis)
        and bool(_MEMORY_ALLOC_APIS & apis)
        and bool(_MEMORY_PROTECT_APIS & apis)
        and bool(_MEMORY_COPY_APIS & apis)
        and evidence.indirect_call_count >= 1
    ):
        return None
    recoveries = []
    for index, carrier in enumerate(carriers):
        if f"carrier_{index}" not in evidence.target_references:
            continue
        for delimiter, carrier_offset, payload in _delimiter_recoveries(
            launcher, carrier, evidence
        ):
            terminal = recover_raw_vvas_shellcode(payload)
            if terminal is not None:
                recoveries.append((carrier, delimiter, carrier_offset, terminal))
    if not recoveries:
        return None
    return evidence, tuple(recoveries)


def recover_zip_sideload_shellcode(data: bytes) -> ZipSideloadShellcodeRecovery | None:
    """ZIP→host/DLL→launcher→carrier→vvaS configの一意なlineageを復元する。"""

    try:
        members = _read_archive_members(data)
    except ZipSideloadShellcodeError:
        return None
    pe_members = tuple(filter(None, (_parse_pe_member(member) for member in members)))
    if not 3 <= len(pe_members) <= MAXIMUM_PE_MEMBERS:
        return None
    by_parent: dict[str, list[_PeMember]] = {}
    for item in pe_members:
        by_parent.setdefault(item.member.parent, []).append(item)
    recoveries: dict[tuple[str, str, str, str, str], ZipSideloadShellcodeRecovery] = {}
    for parent, group in by_parent.items():
        executables = tuple(item for item in group if not item.is_dll)
        libraries = tuple(item for item in group if item.is_dll)
        carriers = tuple(
            item
            for item in members
            if item.parent == parent
            and not item.data.startswith(b"MZ")
            and MINIMUM_CARRIER_SIZE <= len(item.data) <= MAXIMUM_CARRIER_SIZE
        )
        if len(executables) < 2 or not libraries or not carriers:
            continue
        for host in executables:
            for proxy in libraries:
                if host.machine != proxy.machine:
                    continue
                binding_count = _imports_satisfied(host, proxy)
                if binding_count < 3:
                    continue
                launcher_candidates = tuple(
                    item for item in executables if item is not host
                )
                proxy_lineage = _proxy_lineage_evidence(proxy, launcher_candidates)
                if proxy_lineage is None:
                    continue
                proxy_reachability, selected_launchers = proxy_lineage
                for launcher in selected_launchers:
                    launcher_lineage = _launcher_lineage(launcher, carriers)
                    if launcher_lineage is None:
                        continue
                    launcher_reachability, terminal_recoveries = launcher_lineage
                    for (
                        carrier,
                        delimiter,
                        carrier_offset,
                        terminal,
                    ) in terminal_recoveries:
                        key = (
                            host.member.path.casefold(),
                            proxy.member.path.casefold(),
                            launcher.member.path.casefold(),
                            carrier.path.casefold(),
                            hashlib.sha256(terminal.data).hexdigest(),
                        )
                        recoveries[key] = ZipSideloadShellcodeRecovery(
                            source_size=len(data),
                            member_count=len(members),
                            pe_member_count=len(pe_members),
                            import_binding_count=binding_count,
                            proxy_reachability=proxy_reachability,
                            launcher_reachability=launcher_reachability,
                            delimiter_size=len(delimiter),
                            carrier_offset=carrier_offset,
                            shellcode=terminal,
                        )
    if len(recoveries) != 1:
        return None
    return next(iter(recoveries.values()))


def public_raw_shellcode_summary(recovery: RawVvasShellcodeRecovery) -> dict[str, Any]:
    """raw configやendpoint本文を含まないshellcode構造要約を返す。"""

    return {
        "schema_version": 1,
        "status": "validated_vvas_codemark_transport_shellcode",
        "shellcode_size": len(recovery.data),
        "endpoint_count": len(recovery.endpoints),
        "shellcode_structure": dict(recovery.shellcode_evidence),
        "configuration_structure": dict(recovery.config_evidence),
        "shellcode_integrity_hash_included": False,
        "configuration_identity_included": False,
        "member_names_included": False,
        "raw_config_included": False,
        "raw_network_values_included": False,
    }


def public_recovery_summary(recovery: ZipSideloadShellcodeRecovery) -> dict[str, Any]:
    """個別file名、raw payload、endpoint本文を除いたlineage要約を返す。"""

    return {
        "schema_version": 1,
        "status": "validated_zip_sideload_carve_vvas_terminal",
        "source_size": recovery.source_size,
        "member_count": recovery.member_count,
        "pe_member_count": recovery.pe_member_count,
        "lineage": {
            "sibling_import_export_edge": {
                "same_directory": True,
                "bound_symbol_count": recovery.import_binding_count,
                "host_imports_proxy": True,
            },
            "proxy_to_launcher": {
                "entrypoint_cfg_complete": recovery.proxy_reachability.completed,
                "reachable_instruction_count": recovery.proxy_reachability.instruction_count,
                "reachable_process_and_token_groups": True,
                "reachable_launcher_reference": True,
                "scheduled_task_persistence_markers": True,
            },
            "launcher_to_carrier": {
                "entrypoint_cfg_complete": recovery.launcher_reachability.completed,
                "reachable_instruction_count": recovery.launcher_reachability.instruction_count,
                "reachable_file_source_group": True,
                "reachable_delimiter_reference": True,
                "reachable_memory_execution_sink_group": True,
                "delimiter_size": recovery.delimiter_size,
                "delimiter_identity_hash_included": False,
                "carrier_payload_offset": recovery.carrier_offset
                + recovery.delimiter_size,
            },
            "terminal_shellcode": public_raw_shellcode_summary(recovery.shellcode),
        },
        "member_names_included": False,
        "source_integrity_hash_included": False,
        "component_hashes_included": False,
        "raw_payload_included": False,
        "raw_config_included": False,
        "raw_network_values_included": False,
        "safety": {
            "sample_executed": False,
            "payload_executed": False,
            "network_contacted": False,
        },
    }


def probe_zip_sideload_shellcode(data: bytes) -> dict[str, Any]:
    """detector向けにendpointを伏せた完全lineageの有無だけを返す。"""

    recovery = recover_zip_sideload_shellcode(data)
    if recovery is None:
        return {
            "matched": False,
            "supports_family_attribution": False,
            "static_config_recovered": False,
            "evidence": {},
            "config": {},
            "sample_executed": False,
            "network_contacted": False,
        }
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "zip_sideload_shellcode_vvas_terminal",
        "supports_family_attribution": True,
        "terminal_family_confirmed": True,
        "attribution_scope": "validated_terminal_component_structure",
        "static_config_recovered": True,
        "evidence": {
            "source_transform_sink_lineage": True,
            "sibling_import_export_edge": True,
            "proxy_entrypoint_to_launcher": True,
            "launcher_file_carve_execution_path": True,
            "vvas_transport_shellcode": True,
            "configuration_identity_included": False,
            "component_hashes_included": False,
            "member_names_included": False,
            "raw_payload_included": False,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "config": {
            "endpoint_count": len(recovery.shellcode.endpoints),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def probe_raw_vvas_shellcode(data: bytes) -> dict[str, Any]:
    """raw shellcode単体を外層provenanceなしのroute-only候補として返す。"""

    recovery = recover_raw_vvas_shellcode(data)
    if recovery is None:
        return {
            "matched": False,
            "supports_family_attribution": False,
            "static_config_recovered": False,
            "evidence": {},
            "config": {},
            "sample_executed": False,
            "network_contacted": False,
        }
    return {
        "matched": True,
        "family": None,
        "variant": "raw_vvas_codemark_transport_candidate",
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "attribution_scope": "component_handler_route",
        "static_config_recovered": False,
        "candidate_config_recovered": True,
        "evidence": {
            "shellcode_structure": dict(recovery.shellcode_evidence),
            "configuration_structure": dict(recovery.config_evidence),
            "raw_payload_included": False,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "config": {
            "endpoint_count": len(recovery.endpoints),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "RawVvasShellcodeRecovery",
    "ZipSideloadShellcodeError",
    "ZipSideloadShellcodeRecovery",
    "probe_raw_vvas_shellcode",
    "probe_zip_sideload_shellcode",
    "public_raw_shellcode_summary",
    "public_recovery_summary",
    "recover_raw_vvas_shellcode",
    "recover_zip_sideload_shellcode",
]
