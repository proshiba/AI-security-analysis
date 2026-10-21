"""ZIP内のDLL side-loadからvvaS shellcodeまでを静的に復元する。

このmoduleは検体を実行せず、ZIP memberをmemory上だけで検査する。単一の
文字列やfile名では帰属せず、同一directoryのimport/export edge、loader DLLの
entrypoint到達CFG、carrierの静的変換、実行sink、復元shellcodeの通信構造、
marker設定の相関が全て揃う場合だけ終端設定を返す。
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import unicodedata
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
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AH,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BH,
    X86_REG_BL,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_CH,
    X86_REG_CL,
    X86_REG_CX,
    X86_REG_DH,
    X86_REG_DI,
    X86_REG_DL,
    X86_REG_DX,
    X86_REG_EAX,
    X86_REG_EBP,
    X86_REG_EBX,
    X86_REG_ECX,
    X86_REG_EDI,
    X86_REG_EDX,
    X86_REG_ESI,
    X86_REG_ESP,
    X86_REG_FS,
    X86_REG_SI,
    X86_REG_SP,
)

from extractors.valleyrat.nvml_dat import normalize_host, render_endpoint

MAXIMUM_ARCHIVE_SIZE = 64 * 1024 * 1024
MAXIMUM_VERIFIED_PARENT_SIZE = 128 * 1024 * 1024
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
MAXIMUM_REACHABLE_FUNCTIONS = 4_096
MAXIMUM_REACHABLE_FUNCTION_INSTRUCTIONS = 250_000
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
ODAKTOMK = b"odaktomk"
TERMINAL_MARKERS = (CODEMARK, ODAKTOMK)
CODEMARK_HEADER_SIZE = 0x38
_ODAKTOMK_API_HASHES = frozenset(
    {
        0x0148BE54,  # LoadLibraryA
        0x00293836,  # VirtualAlloc
        0x5EC13A5A,  # CreateThread
        0xC18BC488,  # WSAStartup
        0x9816ABED,  # socket
        0xABCE366B,  # getaddrinfo
        0xF9B83296,  # connect
        0x039BB598,  # send
        0xF4178B7A,  # recv
    }
)

_WIDE_ASCII = re.compile(rb"(?:[\x20-\x7e]\x00){12,4096}")
_VVAS_FIELD = re.compile(r"(?:^|\|)([potv][123]):([^|]{0,255})(?=\||$)", re.IGNORECASE)
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
_MAXIMUM_MEMBER_PATH_CHARACTERS = 1024
_MAXIMUM_MEMBER_COMPONENT_CHARACTERS = 255
_WINDOWS_RESERVED_BASENAMES = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_REGISTER_FAMILIES = {
    X86_REG_AH: "eax",
    X86_REG_AL: "eax",
    X86_REG_AX: "eax",
    X86_REG_EAX: "eax",
    X86_REG_BH: "ebx",
    X86_REG_BL: "ebx",
    X86_REG_BX: "ebx",
    X86_REG_EBX: "ebx",
    X86_REG_CH: "ecx",
    X86_REG_CL: "ecx",
    X86_REG_CX: "ecx",
    X86_REG_ECX: "ecx",
    X86_REG_DH: "edx",
    X86_REG_DL: "edx",
    X86_REG_DX: "edx",
    X86_REG_EDX: "edx",
    X86_REG_SI: "esi",
    X86_REG_ESI: "esi",
    X86_REG_DI: "edi",
    X86_REG_EDI: "edi",
    X86_REG_BP: "ebp",
    X86_REG_EBP: "ebp",
    X86_REG_SP: "esp",
    X86_REG_ESP: "esp",
}


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
    instructions: tuple[Any, ...]


@dataclass(frozen=True)
class _FunctionCfg:
    """direct callへ入らずentry function内だけを辿った命令CFG。"""

    entry_address: int
    completed: bool
    instructions: tuple[Any, ...]
    edges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class _ImmediateBasenameLineage:
    """即値書込みからC++ stream openへ届くbasename構築証拠。"""

    first_write: int
    last_write: int
    open_call: int
    object_signature: tuple[str | None, str | None, int, int]
    stream_signature: tuple[str | None, str | None, int, int]
    write_addresses: tuple[int, ...]


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


@dataclass(frozen=True)
class ZipDirectXorShellcodeRecovery:
    """ZIP rootからuniform-XOR carrierと終端設定までの完全な静的lineage。"""

    source_size: int
    member_count: int
    pe_member_count: int
    import_binding_count: int
    loader_reachability: _ReachabilityEvidence
    xor_evidence: dict[str, Any]
    shellcode: RawVvasShellcodeRecovery
    component_sha256: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ZipDirectXorRouteRecovery:
    """終端候補は復元済みだがcarrier読出しlineageが未証明のroute。"""

    source_size: int
    member_count: int
    pe_member_count: int
    import_binding_count: int
    loader_reachability: _ReachabilityEvidence
    xor_evidence: dict[str, Any]
    shellcode: RawVvasShellcodeRecovery


ZipTerminalRecovery = ZipSideloadShellcodeRecovery | ZipDirectXorShellcodeRecovery


@dataclass(frozen=True)
class VerifiedSiblingMember:
    """外部container reportでidentity検証済みの同居member。"""

    path: str
    data: bytes
    size: int
    sha256: str


@dataclass(frozen=True)
class VerifiedSiblingShellcodeRecovery:
    """container親からloader・carrier・終端までの非公開provenance。"""

    parent_sha256: str
    host_sha256: str
    loader_sha256: str
    carrier_sha256: str
    terminal_sha256: str
    recovery: ZipDirectXorShellcodeRecovery


def _normalized_member_path(
    value: str,
    *,
    directory: bool = False,
) -> tuple[str, str, str]:
    """ZIP member pathをWindows展開先と同じ名前空間へ正規化する。"""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAXIMUM_MEMBER_PATH_CHARACTERS + 1
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ZipSideloadShellcodeError("ZIP member名が不正です")
    normalized = unicodedata.normalize("NFKC", value).replace("\\", "/")
    if directory:
        if not normalized.endswith("/") or normalized.endswith("//"):
            raise ZipSideloadShellcodeError("ZIP directory名が不正です")
        normalized = normalized[:-1]
    elif normalized.endswith("/"):
        raise ZipSideloadShellcodeError("ZIP file名が不正です")
    parts = normalized.split("/")
    if (
        normalized.startswith("/")
        or not parts
        or any(
            part in {"", ".", ".."}
            or len(part) > _MAXIMUM_MEMBER_COMPONENT_CHARACTERS
            or ":" in part
            or part.rstrip(" .") != part
            or part.partition(".")[0].casefold() in _WINDOWS_RESERVED_BASENAMES
            for part in parts
        )
    ):
        raise ZipSideloadShellcodeError("ZIP member pathが相対path境界外です")
    path = PurePosixPath(*parts)
    rendered = path.as_posix()
    if path.is_absolute() or len(rendered) > _MAXIMUM_MEMBER_PATH_CHARACTERS:
        raise ZipSideloadShellcodeError("ZIP member pathが相対path境界外です")
    parent = path.parent.as_posix().casefold()
    if parent == ".":
        parent = ""
    return rendered, parent, path.name.casefold()


def _declared_zip_entry_count(data: bytes) -> int:
    """EOCDとcentral directoryを軽量走査し、実record件数を先に確定する。"""

    minimum_offset = max(0, len(data) - (22 + 0xFFFF))
    eocd_offset = data.rfind(_ZIP_EOCD_SIGNATURE, minimum_offset)
    while eocd_offset >= 0:
        if eocd_offset + 22 <= len(data):
            (
                _signature,
                disk_number,
                directory_disk,
                disk_entries,
                total_entries,
                directory_size,
                directory_offset,
                comment_size,
            ) = struct.unpack_from("<4s4H2IH", data, eocd_offset)
            if eocd_offset + 22 + comment_size == len(data):
                break
        eocd_offset = data.rfind(
            _ZIP_EOCD_SIGNATURE,
            minimum_offset,
            eocd_offset,
        )
    if eocd_offset < 0:
        raise ZipSideloadShellcodeError("ZIP EOCDを読めません")

    saturated = (
        disk_entries == 0xFFFF
        or total_entries == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    )
    if not saturated:
        if disk_number != 0 or directory_disk != 0 or disk_entries != total_entries:
            raise ZipSideloadShellcodeError("multi-disk ZIPは扱いません")
        declared_entries = int(total_entries)
        declared_directory_size = int(directory_size)
        declared_directory_offset = int(directory_offset)
        directory_end = eocd_offset
        zip64_record_offset = None
        zip64_relative_offset = None
    else:
        locator_offset = eocd_offset - 20
        if (
            locator_offset < 0
            or data[locator_offset : locator_offset + 4]
            != _ZIP64_LOCATOR_SIGNATURE
        ):
            raise ZipSideloadShellcodeError("ZIP64 locatorを読めません")
        _, locator_disk, zip64_relative_offset, disk_count = struct.unpack_from(
            "<4sIQI", data, locator_offset
        )
        zip64_record_offset = data.rfind(
            _ZIP64_EOCD_SIGNATURE,
            0,
            locator_offset,
        )
        if zip64_record_offset < 0 or zip64_record_offset + 12 > locator_offset:
            raise ZipSideloadShellcodeError("ZIP64 EOCDを読めません")
        record_size = struct.unpack_from("<Q", data, zip64_record_offset + 4)[0]
        if (
            record_size < 44
            or zip64_record_offset + 12 + record_size != locator_offset
        ):
            raise ZipSideloadShellcodeError("ZIP64 EOCD sizeが不正です")
        (
            _made_by,
            _needed,
            zip64_disk,
            zip64_directory_disk,
            zip64_disk_entries,
            zip64_total_entries,
            zip64_directory_size,
            zip64_directory_offset,
        ) = struct.unpack_from("<HHIIQQQQ", data, zip64_record_offset + 12)
        if (
            locator_disk != 0
            or disk_count != 1
            or zip64_disk != 0
            or zip64_directory_disk != 0
            or zip64_disk_entries != zip64_total_entries
        ):
            raise ZipSideloadShellcodeError("multi-disk ZIP64は扱いません")
        if (
            (disk_entries != 0xFFFF and disk_entries != zip64_disk_entries)
            or (total_entries != 0xFFFF and total_entries != zip64_total_entries)
            or (directory_size != 0xFFFFFFFF and directory_size != zip64_directory_size)
            or (
                directory_offset != 0xFFFFFFFF
                and directory_offset != zip64_directory_offset
            )
        ):
            raise ZipSideloadShellcodeError("ZIP64 EOCDの値が一致しません")
        declared_entries = int(zip64_total_entries)
        declared_directory_size = int(zip64_directory_size)
        declared_directory_offset = int(zip64_directory_offset)
        directory_end = zip64_record_offset

    if not 0 <= declared_directory_size <= directory_end:
        raise ZipSideloadShellcodeError("ZIP central directory sizeが不正です")
    directory_start = directory_end - declared_directory_size
    prefix_size = directory_start - declared_directory_offset
    if prefix_size < 0:
        raise ZipSideloadShellcodeError("ZIP central directory offsetが不正です")
    if (
        zip64_record_offset is not None
        and zip64_relative_offset != zip64_record_offset - prefix_size
    ):
        raise ZipSideloadShellcodeError("ZIP64 locator offsetが一致しません")

    cursor = directory_start
    observed_entries = 0
    while cursor < directory_end:
        if (
            directory_end - cursor < 46
            or data[cursor : cursor + 4] != b"PK\x01\x02"
        ):
            raise ZipSideloadShellcodeError("ZIP central directory recordが不正です")
        name_size, extra_size, member_comment_size = struct.unpack_from(
            "<HHH",
            data,
            cursor + 28,
        )
        record_size = 46 + name_size + extra_size + member_comment_size
        if record_size > directory_end - cursor:
            raise ZipSideloadShellcodeError("ZIP central directory recordが途切れています")
        observed_entries += 1
        if observed_entries > MAXIMUM_MEMBER_COUNT:
            raise ZipSideloadShellcodeError("ZIP member数が上限外です")
        cursor += record_size
    if observed_entries != declared_entries:
        raise ZipSideloadShellcodeError("ZIP member宣言数と実record数が一致しません")
    return observed_entries


def _validate_member_namespace(
    records: tuple[tuple[str, bool], ...],
) -> None:
    """大小文字・Unicode・file/directoryを含むWindows namespaceを検証する。"""

    seen: dict[str, bool] = {}
    for path, directory in records:
        key = path.casefold()
        if key in seen:
            raise ZipSideloadShellcodeError("正規化後に重複memberがあります")
        parts = key.split("/")
        for index in range(1, len(parts)):
            ancestor = "/".join(parts[:index])
            if seen.get(ancestor) is False:
                raise ZipSideloadShellcodeError("fileと子memberが衝突しています")
        if not directory and any(existing.startswith(f"{key}/") for existing in seen):
            raise ZipSideloadShellcodeError("fileと子memberが衝突しています")
        seen[key] = directory


def _read_archive_members(data: bytes) -> tuple[_ArchiveMember, ...]:
    """ZIPをdiskへ展開せず、size・ratio・pathを検証して読む。"""

    if not isinstance(data, bytes) or not 22 <= len(data) <= MAXIMUM_ARCHIVE_SIZE:
        raise ZipSideloadShellcodeError("ZIP入力sizeが上限外です")
    declared_entries = _declared_zip_entry_count(data)
    if not 1 <= declared_entries <= MAXIMUM_MEMBER_COUNT:
        raise ZipSideloadShellcodeError("ZIP member数が上限外です")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ZipSideloadShellcodeError("ZIP構造を読めません") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) != declared_entries:
            raise ZipSideloadShellcodeError("ZIP member数が上限外です")
        total_size = 0
        namespace_records: list[tuple[str, bool]] = []
        prepared: list[tuple[zipfile.ZipInfo, str, str, str, bool]] = []
        file_count = 0
        for info in infos:
            directory = info.is_dir()
            path, parent, basename = _normalized_member_path(
                info.filename,
                directory=directory,
            )
            namespace_records.append((path, directory))
            if info.flag_bits & 0x1:
                raise ZipSideloadShellcodeError("内側ZIPの暗号化memberは扱いません")
            unix_type = (int(info.external_attr) >> 16) & 0xF000
            if unix_type == 0xA000:
                raise ZipSideloadShellcodeError("symbolic link memberは扱いません")
            if directory:
                if info.file_size != 0 or info.compress_size != 0:
                    raise ZipSideloadShellcodeError("ZIP directory recordが不正です")
                prepared.append((info, path, parent, basename, True))
                continue
            file_count += 1
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
            prepared.append((info, path, parent, basename, False))
        if file_count < 1:
            raise ZipSideloadShellcodeError("ZIPにfile memberがありません")
        _validate_member_namespace(tuple(namespace_records))
        members = []
        for info, path, parent, basename, directory in prepared:
            if directory:
                members.append(_ArchiveMember(path, parent, basename, b""))
                continue
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
    try:
        needle = basename.encode("ascii", "strict").lower()
    except UnicodeEncodeError:
        return frozenset()
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


def _system_module_extension_key(pe: _PeMember, address: int) -> int | None:
    """GetModuleHandleAに渡すsystem DLL basenameから意図されたsuffix byteを導く。"""

    offset = _va_to_file_offset(pe, address, non_executable_only=True)
    if offset is None:
        return None
    end = pe.member.data.find(b"\0", offset, min(len(pe.member.data), offset + 261))
    if end < 0:
        return None
    raw = pe.member.data[offset:end]
    try:
        module = PurePosixPath(raw.decode("ascii").replace("\\", "/")).name
    except UnicodeDecodeError:
        return None
    if module.casefold() != "kernel32.dll":
        return None
    canonical_loaded_name = module.upper().encode("ascii")
    if len(canonical_loaded_name) < 3 or canonical_loaded_name[-4:] != b".DLL":
        return None
    key = canonical_loaded_name[-3] - 0x30
    return key if 1 <= key <= 0xFF else None


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
        return _ReachabilityEvidence(
            False,
            0,
            0,
            frozenset(),
            frozenset(),
            (),
            0,
            (),
        )
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    iat = _iat_map(pe)
    pending: deque[int] = deque([entry])
    queued = {entry}
    seen: set[int] = set()
    decoded: dict[int, Any] = {}
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
            decoded[address] = instruction
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
        instructions=tuple(decoded[address] for address in sorted(decoded)),
    )


def _intraprocedural_cfg(pe: _PeMember, entry: int) -> _FunctionCfg:
    """1 functionのjump/fallthroughだけを辿り、direct call先へ入らない。"""

    executable, _mapped = _section_ranges(pe)
    if not _in_ranges(entry, executable):
        return _FunctionCfg(entry, False, (), ())
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    pending = [entry]
    pending_index = 0
    queued = {entry}
    decoded: dict[int, Any] = {}
    edges: set[tuple[int, int]] = set()
    decode_failed = False
    limit_reached = False
    while pending_index < len(pending):
        if len(pending) - pending_index > MAXIMUM_CFG_PENDING_BLOCKS:
            limit_reached = True
            break
        address = pending[pending_index]
        pending_index += 1
        while _in_ranges(address, executable):
            if address in decoded:
                break
            if len(decoded) >= MAXIMUM_CFG_INSTRUCTIONS:
                limit_reached = True
                break
            offset = _va_to_file_offset(pe, address)
            if offset is None:
                decode_failed = True
                break
            try:
                decoded_instructions = tuple(
                    disassembler.disasm(
                        pe.member.data[offset : offset + 16], address, count=1
                    )
                )
            except CsError:
                decoded_instructions = ()
            instruction = (
                decoded_instructions[0]
                if len(decoded_instructions) == 1
                else None
            )
            if instruction is None:
                decode_failed = True
                break
            decoded[address] = instruction
            next_address = int(instruction.address + instruction.size)
            is_call = bool(instruction.group(CS_GRP_CALL))
            is_jump = bool(instruction.group(CS_GRP_JUMP))
            if instruction.group(CS_GRP_RET) or instruction.mnemonic.casefold() in {
                "hlt",
                "int3",
                "ud2",
            }:
                break
            if is_jump:
                direct_target = None
                if (
                    instruction.operands
                    and instruction.operands[0].type == X86_OP_IMM
                ):
                    direct_target = int(instruction.operands[0].imm) & 0xFFFFFFFF
                unconditional = instruction.mnemonic.casefold() == "jmp"
                if direct_target is not None and _in_ranges(direct_target, executable):
                    edges.add((address, direct_target))
                    if direct_target not in queued:
                        pending.append(direct_target)
                        queued.add(direct_target)
                if unconditional:
                    break
                if _in_ranges(next_address, executable):
                    edges.add((address, next_address))
                    address = next_address
                    continue
                break
            if _in_ranges(next_address, executable):
                edges.add((address, next_address))
                address = next_address
                continue
            if not is_call:
                break
        if limit_reached:
            break
    valid_edges = tuple(
        sorted(
            (source, target)
            for source, target in edges
            if source in decoded and target in decoded
        )
    )
    return _FunctionCfg(
        entry_address=entry,
        completed=not limit_reached and not decode_failed,
        instructions=tuple(decoded[address] for address in sorted(decoded)),
        edges=valid_edges,
    )


def _intraprocedural_entry_cfg(pe: _PeMember) -> _FunctionCfg:
    """PE entrypointを起点に1 functionのCFGを復元する。"""

    entry = pe.image_base + int(pe.image.OPTIONAL_HEADER.AddressOfEntryPoint)
    return _intraprocedural_cfg(pe, entry)


def _reachable_function_cfgs(pe: _PeMember) -> tuple[_FunctionCfg, ...]:
    """PE entrypointからdirect call graphで到達するfunction CFGを有界列挙する。"""

    executable, _mapped = _section_ranges(pe)
    entry = pe.image_base + int(pe.image.OPTIONAL_HEADER.AddressOfEntryPoint)
    pending = [entry]
    pending_index = 0
    queued = {entry}
    functions: list[_FunctionCfg] = []
    instruction_total = 0
    while pending_index < len(pending):
        if len(functions) >= MAXIMUM_REACHABLE_FUNCTIONS:
            return ()
        function_entry = pending[pending_index]
        pending_index += 1
        cfg = _intraprocedural_cfg(pe, function_entry)
        if not cfg.completed or not cfg.instructions:
            continue
        instruction_total += len(cfg.instructions)
        if instruction_total > MAXIMUM_REACHABLE_FUNCTION_INSTRUCTIONS:
            return ()
        functions.append(cfg)
        for instruction in cfg.instructions:
            if (
                not instruction.group(CS_GRP_CALL)
                or not instruction.operands
                or instruction.operands[0].type != X86_OP_IMM
            ):
                continue
            target = int(instruction.operands[0].imm) & 0xFFFFFFFF
            if target in queued or not _in_ranges(target, executable):
                continue
            pending.append(target)
            queued.add(target)
    return tuple(functions)


def _cfg_instruction_map(cfg: _FunctionCfg) -> dict[int, Any]:
    return {int(item.address): item for item in cfg.instructions}


def _cfg_dominators(cfg: _FunctionCfg) -> dict[int, frozenset[int]]:
    """有界CFGのdominator集合を固定点で求める。"""

    nodes = {int(item.address) for item in cfg.instructions}
    if cfg.entry_address not in nodes:
        return {}
    predecessors: dict[int, set[int]] = {node: set() for node in nodes}
    for source, target in cfg.edges:
        if source in nodes and target in nodes:
            predecessors[target].add(source)
    dominators: dict[int, set[int]] = {
        node: ({node} if node == cfg.entry_address else set(nodes))
        for node in nodes
    }
    for _iteration in range(len(nodes) + 1):
        changed = False
        for node in sorted(nodes):
            if node == cfg.entry_address:
                continue
            parents = predecessors[node]
            if not parents:
                updated = {node}
            else:
                parent_values = [dominators[parent] for parent in sorted(parents)]
                common = set(parent_values[0])
                for value in parent_values[1:]:
                    common = common & value
                updated = {node, *common}
            if updated != dominators[node]:
                dominators[node] = updated
                changed = True
        if not changed:
            return {key: frozenset(value) for key, value in dominators.items()}
    return {}


def _dominates_chain(
    dominators: Mapping[int, frozenset[int]], addresses: tuple[int, ...]
) -> bool:
    """各stepが次stepを支配する同一CFG chainだけを受理する。"""

    return bool(
        addresses
        and all(
            addresses[index] in dominators.get(addresses[index + 1], frozenset())
            for index in range(len(addresses) - 1)
        )
    )


def _cfg_path_exists(cfg: _FunctionCfg, source: int, target: int) -> bool:
    """同じfunction CFG内でsourceからtargetへ到達できるか有界確認する。"""

    instructions = _cfg_instruction_map(cfg)
    if source not in instructions or target not in instructions:
        return False
    successors: dict[int, set[int]] = {}
    for edge_source, edge_target in cfg.edges:
        if edge_source in instructions and edge_target in instructions:
            if edge_source not in successors:
                successors[edge_source] = set()
            successors[edge_source].add(edge_target)
    pending = [source]
    pending_index = 0
    seen = {source}
    while pending_index < len(pending) and len(seen) <= len(instructions):
        current = pending[pending_index]
        pending_index += 1
        if current == target:
            return True
        for candidate in sorted(successors.get(current, set())):
            if candidate not in seen:
                seen.add(candidate)
                pending.append(candidate)
    return False


def _cfg_path_exists_without_global_writes(
    cfg: _FunctionCfg,
    source: int,
    target: int,
    protected_addresses: frozenset[int],
) -> bool:
    """指定globalを書き換えないsource→target pathの存在を有界確認する。"""

    instructions = _cfg_instruction_map(cfg)
    if source not in instructions or target not in instructions:
        return False
    successors: dict[int, set[int]] = {}
    for edge_source, edge_target in cfg.edges:
        if edge_source in instructions and edge_target in instructions:
            edge_successors = successors.get(edge_source)
            if edge_successors is None:
                edge_successors = set()
                successors[edge_source] = edge_successors
            edge_successors.add(edge_target)
    pending = [source]
    pending_index = 0
    seen = {source}
    while pending_index < len(pending) and len(seen) <= len(instructions):
        current = pending[pending_index]
        pending_index += 1
        if current == target:
            return True
        for candidate in sorted(successors.get(current, set())):
            if candidate in seen:
                continue
            instruction = instructions[candidate]
            if any(
                _writes_absolute_memory(instruction, address)
                for address in protected_addresses
            ):
                continue
            seen.add(candidate)
            pending.append(candidate)
    return False


def _register_family(register: int) -> str | None:
    return _REGISTER_FAMILIES.get(register)


def _absolute_memory_address(operand: Any) -> int | None:
    """base/indexなしのx86 absolute memory operandを返す。"""

    if operand.type != X86_OP_MEM:
        return None
    memory = operand.mem
    if memory.base != 0 or memory.index != 0:
        return None
    return int(memory.disp) & 0xFFFFFFFF


def _function_api_calls(
    pe: _PeMember, cfg: _FunctionCfg
) -> dict[str, tuple[int, ...]]:
    """entry function内のIAT callだけをAPI leafへ結ぶ。"""

    iat = _iat_map(pe)
    positions: dict[str, list[int]] = {}
    for instruction in cfg.instructions:
        if not instruction.group(CS_GRP_CALL) or not instruction.operands:
            continue
        target = _absolute_memory_address(instruction.operands[0])
        api = iat.get(target) if target is not None else None
        if api is None:
            continue
        leaf = api.rpartition("!")[2]
        if leaf not in positions:
            positions[leaf] = []
        positions[leaf].append(int(instruction.address))
    return {key: tuple(sorted(value)) for key, value in positions.items()}


def _linear_predecessors(
    cfg: _FunctionCfg, address: int, *, maximum: int = 64
) -> tuple[Any, ...]:
    """call直前の分岐なしfallthrough列を逆向きに取得する。"""

    instructions = _cfg_instruction_map(cfg)
    predecessors: dict[int, list[int]] = {}
    for source, target in cfg.edges:
        if target not in predecessors:
            predecessors[target] = []
        predecessors[target].append(source)
    result: list[Any] = []
    cursor = address
    for _index in range(maximum):
        parents = [
            source
            for source in predecessors.get(cursor, [])
            if source in instructions
            and source + int(instructions[source].size) == cursor
        ]
        if len(parents) != 1:
            break
        instruction = instructions[parents[0]]
        if instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_JUMP):
            break
        result.append(instruction)
        cursor = int(instruction.address)
    return tuple(reversed(result))


def _linear_successors(
    cfg: _FunctionCfg, address: int, *, maximum: int = 64
) -> tuple[Any, ...]:
    """分岐なしfallthrough列を前向きに取得する。"""

    instructions = _cfg_instruction_map(cfg)
    successors: dict[int, list[int]] = {}
    for source, target in cfg.edges:
        if source not in successors:
            successors[source] = []
        successors[source].append(target)
    result: list[Any] = []
    cursor = address
    for _index in range(maximum):
        targets = [
            target
            for target in successors.get(cursor, [])
            if cursor in instructions
            and target == cursor + int(instructions[cursor].size)
            and target in instructions
        ]
        if len(targets) != 1:
            break
        instruction = instructions[targets[0]]
        result.append(instruction)
        cursor = int(instruction.address)
        if instruction.group(CS_GRP_JUMP) or instruction.group(CS_GRP_RET):
            break
    return tuple(result)


def _call_pushes(
    cfg: _FunctionCfg, call_address: int, *, maximum: int = 64
) -> tuple[Any, ...]:
    return tuple(
        instruction
        for instruction in _linear_predecessors(cfg, call_address, maximum=maximum)
        if instruction.mnemonic.casefold() == "push" and instruction.operands
    )


def _push_immediate(instruction: Any, value: int) -> bool:
    return bool(
        instruction.mnemonic.casefold() == "push"
        and instruction.operands
        and instruction.operands[0].type == X86_OP_IMM
        and (int(instruction.operands[0].imm) & 0xFFFFFFFF)
        == (value & 0xFFFFFFFF)
    )


def _push_absolute_memory(instruction: Any, address: int) -> bool:
    return bool(
        instruction.mnemonic.casefold() == "push"
        and instruction.operands
        and _absolute_memory_address(instruction.operands[0]) == address
    )


def _push_register(instruction: Any, family: str) -> bool:
    return bool(
        instruction.mnemonic.casefold() == "push"
        and instruction.operands
        and instruction.operands[0].type == X86_OP_REG
        and _register_family(instruction.operands[0].reg) == family
    )


def _push_target(instruction: Any, addresses: frozenset[int]) -> bool:
    return bool(
        instruction.mnemonic.casefold() == "push"
        and instruction.operands
        and instruction.operands[0].type == X86_OP_IMM
        and (int(instruction.operands[0].imm) & 0xFFFFFFFF) in addresses
    )


def _pushed_location_signature(
    cfg: _FunctionCfg,
    call_address: int,
    push_instruction: Any,
) -> tuple[str | None, str | None, int, int] | None:
    """pushしたmemory、または直前LEA由来registerのlocationを回復する。"""

    operand = push_instruction.operands[0]
    direct = _memory_signature(operand)
    if direct is not None:
        return direct
    if operand.type != X86_OP_REG:
        return None
    family = _register_family(operand.reg)
    if family is None:
        return None
    predecessors = _linear_predecessors(cfg, call_address, maximum=32)
    try:
        push_index = predecessors.index(push_instruction)
    except ValueError:
        return None
    for instruction in reversed(predecessors[:push_index]):
        if not _instruction_writes_register(instruction, family):
            continue
        if (
            instruction.mnemonic.casefold() == "lea"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_REG
            and _register_family(instruction.operands[0].reg) == family
        ):
            return _memory_signature(instruction.operands[1])
        return None
    return None


def _target_reference_positions(
    cfg: _FunctionCfg, targets: Mapping[str, frozenset[int]]
) -> dict[str, tuple[int, ...]]:
    result: dict[str, list[int]] = {key: [] for key in targets}
    for instruction in cfg.instructions:
        values: set[int] = set()
        for operand in instruction.operands:
            if operand.type == X86_OP_IMM:
                values.add(int(operand.imm) & 0xFFFFFFFF)
            else:
                address = _absolute_memory_address(operand)
                if address is not None:
                    values.add(address)
        for label, addresses in targets.items():
            if values & set(addresses):
                result[label].append(int(instruction.address))
    return {key: tuple(sorted(value)) for key, value in result.items()}


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


def _memory_signature(operand: Any) -> tuple[str | None, str | None, int, int] | None:
    if operand.type != X86_OP_MEM:
        return None
    return (
        _register_family(operand.mem.base),
        _register_family(operand.mem.index),
        int(operand.mem.scale),
        int(operand.mem.disp),
    )


def _instruction_writes_register(instruction: Any, family: str) -> bool:
    """明示writeとx86 ABIのcaller-saved call clobberを保守的に判定する。"""

    if instruction.group(CS_GRP_CALL):
        return family in {"eax", "ecx", "edx"}
    if instruction.mnemonic.casefold() in {
        "cmp",
        "jmp",
        "push",
        "test",
    } or instruction.mnemonic.casefold().startswith("j"):
        return False
    return bool(
        instruction.operands
        and instruction.operands[0].type == X86_OP_REG
        and _register_family(instruction.operands[0].reg) == family
    )


def _carrier_path_copy_lineages(
    cfg: _FunctionCfg, carrier_addresses: frozenset[int]
) -> tuple[tuple[int, int, str], ...]:
    """carrier basename先頭からruntime path pointerへのcopyを返す。"""

    matches: set[tuple[int, int, str]] = set()
    for instruction in cfg.instructions:
        if (
            instruction.mnemonic.casefold() != "mov"
            or len(instruction.operands) != 2
            or instruction.operands[0].type != X86_OP_REG
            or _absolute_memory_address(instruction.operands[1])
            not in carrier_addresses
        ):
            continue
        family = _register_family(instruction.operands[0].reg)
        if family is None:
            continue
        following = _linear_successors(cfg, int(instruction.address), maximum=5)
        for item in following:
            if not (
                item.mnemonic.casefold() == "mov"
                and len(item.operands) == 2
                and item.operands[0].type == X86_OP_MEM
                and item.operands[0].mem.index == 0
                and item.operands[1].type == X86_OP_REG
                and _register_family(item.operands[1].reg) == family
                and int(item.operands[0].size)
                == int(instruction.operands[1].size)
            ):
                continue
            path_family = _register_family(item.operands[0].mem.base)
            if path_family is not None:
                matches.add(
                    (
                        int(instruction.address),
                        int(item.address),
                        path_family,
                    )
                )
    return tuple(sorted(matches))


def _result_global_store_after_call(
    cfg: _FunctionCfg, call_address: int
) -> tuple[int, int] | None:
    """EAX戻り値を分岐・clobberなしでabsolute globalへ保存するmovを返す。"""

    for instruction in _linear_successors(cfg, call_address, maximum=4):
        if (
            instruction.group(CS_GRP_CALL)
            or instruction.group(CS_GRP_JUMP)
            or instruction.group(CS_GRP_RET)
        ):
            return None
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(instruction.operands) == 2
            and _absolute_memory_address(instruction.operands[0]) is not None
            and instruction.operands[1].type == X86_OP_REG
            and _register_family(instruction.operands[1].reg) == "eax"
        ):
            destination = _absolute_memory_address(instruction.operands[0])
            assert destination is not None
            return int(instruction.address), destination
        if _instruction_writes_register(instruction, "eax"):
            return None
    return None


def _writes_absolute_memory(instruction: Any, address: int) -> bool:
    return bool(
        instruction.mnemonic.casefold() not in {"cmp", "push", "test"}
        and instruction.operands
        and _absolute_memory_address(instruction.operands[0]) == address
    )


def _stack_local_signature(
    operand: Any,
) -> tuple[str | None, str | None, int, int] | None:
    """EBP基準の有界なstack localだけをlocation signatureとして返す。"""

    signature = _memory_signature(operand)
    if signature is None:
        return None
    base, index, scale, displacement = signature
    if base != "ebp" or index is not None or scale not in {0, 1}:
        return None
    if not -0x4000 <= displacement < 0:
        return None
    return signature


def _runtime_pointer_signature(
    operand: Any,
) -> tuple[tuple[str, ...], int] | None:
    """scale 1のruntime pointer加算をbase/index順序に依存せず正規化する。"""

    signature = _memory_signature(operand)
    if signature is None:
        return None
    base, index, scale, displacement = signature
    if scale != 1:
        return None
    families = tuple(sorted(value for value in (base, index) if value is not None))
    if not families or len(set(families)) != len(families):
        return None
    if any(value in {"ebp", "esp"} for value in families):
        return None
    return families, displacement


def _immediate_memory_write(
    instruction: Any,
) -> tuple[tuple[str, ...], int, bytes] | None:
    """runtime pointer先への1/2/4 byte即値writeを復元する。"""

    if not (
        instruction.mnemonic.casefold() == "mov"
        and len(instruction.operands) == 2
        and instruction.operands[0].type == X86_OP_MEM
        and instruction.operands[1].type == X86_OP_IMM
    ):
        return None
    pointer = _runtime_pointer_signature(instruction.operands[0])
    size = int(instruction.operands[0].size)
    if pointer is None or size not in {1, 2, 4}:
        return None
    families, displacement = pointer
    value = int(instruction.operands[1].imm) & ((1 << (size * 8)) - 1)
    return families, displacement, value.to_bytes(size, "little")


def _this_stack_signature(
    cfg: _FunctionCfg,
    call_address: int,
) -> tuple[str | None, str | None, int, int] | None:
    """direct call直前にECXへLEAされたstack objectを返す。"""

    for instruction in reversed(_linear_predecessors(cfg, call_address, maximum=48)):
        if not _instruction_writes_register(instruction, "ecx"):
            continue
        if not (
            instruction.mnemonic.casefold() == "lea"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_REG
            and _register_family(instruction.operands[0].reg) == "ecx"
        ):
            return None
        signature = _stack_local_signature(instruction.operands[1])
        if signature is not None:
            return signature
        return None

    instructions = _cfg_instruction_map(cfg)
    predecessors: dict[int, set[int]] = {address: set() for address in instructions}
    for source, target in cfg.edges:
        if source in instructions and target in instructions:
            predecessors[target].add(source)
    pending = sorted(predecessors.get(call_address, set()))
    seen: set[int] = set()
    definitions: set[tuple[str | None, str | None, int, int]] = set()
    unresolved = False
    while pending and len(seen) <= 256:
        address = pending.pop()
        if address in seen:
            continue
        seen.add(address)
        instruction = instructions[address]
        if _instruction_writes_register(instruction, "ecx"):
            if (
                instruction.mnemonic.casefold() == "lea"
                and len(instruction.operands) == 2
                and instruction.operands[0].type == X86_OP_REG
                and _register_family(instruction.operands[0].reg) == "ecx"
                and (
                    signature := _stack_local_signature(instruction.operands[1])
                )
                is not None
            ):
                definitions.add(signature)
            else:
                unresolved = True
            continue
        parents = predecessors.get(address, set())
        if not parents:
            unresolved = True
            continue
        pending.extend(sorted(parents))
    if pending or unresolved or len(definitions) != 1:
        return None
    return next(iter(definitions))


def _selected_string_pointer_push(
    cfg: _FunctionCfg,
    call_address: int,
    object_signature: tuple[str | None, str | None, int, int],
) -> int | None:
    """同じstd::string objectのSSO/heap選択後にpushしたregisterを返す。"""

    predecessors = _linear_predecessors(cfg, call_address, maximum=64)
    candidates: set[int] = set()
    for push_index, instruction in enumerate(predecessors):
        if not (
            instruction.mnemonic.casefold() == "push"
            and instruction.operands
            and instruction.operands[0].type == X86_OP_REG
        ):
            continue
        family = _register_family(instruction.operands[0].reg)
        if family is None:
            continue
        writers = [
            item
            for item in predecessors[:push_index]
            if _instruction_writes_register(item, family)
        ]
        if not writers:
            continue
        last = writers[-1]
        if not (
            last.mnemonic.casefold().startswith("cmov")
            and len(last.operands) == 2
            and last.operands[0].type == X86_OP_REG
            and _register_family(last.operands[0].reg) == family
            and _memory_signature(last.operands[1]) == object_signature
        ):
            continue
        prior = writers[:-1]
        if not prior:
            continue
        seed = prior[-1]
        if not (
            seed.mnemonic.casefold() == "lea"
            and len(seed.operands) == 2
            and seed.operands[0].type == X86_OP_REG
            and _register_family(seed.operands[0].reg) == family
            and _memory_signature(seed.operands[1]) == object_signature
        ):
            continue
        candidates.add(int(instruction.address))
    return next(iter(candidates)) if len(candidates) == 1 else None


def _immediate_built_basename_lineages(
    cfg: _FunctionCfg,
    basename: str,
) -> tuple[_ImmediateBasenameLineage, ...]:
    """即値構築basenameから同一objectのC++ stream openまでを証明する。"""

    if (
        not isinstance(basename, str)
        or not 3 <= len(basename) <= 128
        or any(character in basename for character in ("/", "\\", "\x00"))
    ):
        return ()
    try:
        expected_text = basename.encode("ascii")
    except UnicodeEncodeError:
        return ()
    expected_size = len(expected_text) + 1
    dominators = _cfg_dominators(cfg)
    if not dominators:
        return ()
    ordered = list(cfg.instructions)
    matches: dict[
        tuple[int, int, int, tuple[str | None, str | None, int, int]],
        _ImmediateBasenameLineage,
    ] = {}
    for first in cfg.instructions:
        first_write = _immediate_memory_write(first)
        if first_write is None:
            continue
        families, displacement, _chunk = first_write
        if displacement != 0:
            continue
        sequence = (first, *_linear_successors(cfg, int(first.address), maximum=48))
        reconstructed: dict[int, int] = {}
        write_addresses: list[int] = []
        last_write = int(first.address)
        invalid = False
        for instruction in sequence:
            parsed = _immediate_memory_write(instruction)
            if parsed is None:
                if instruction.group(CS_GRP_CALL):
                    break
                continue
            candidate_families, offset, chunk = parsed
            if candidate_families != families:
                continue
            if offset < 0 or offset + len(chunk) > expected_size:
                invalid = True
                break
            if any(offset + index in reconstructed for index in range(len(chunk))):
                invalid = True
                break
            for index, value in enumerate(chunk):
                reconstructed[offset + index] = value
            write_addresses.append(int(instruction.address))
            last_write = int(instruction.address)
            if len(reconstructed) == expected_size:
                break
        if invalid or set(reconstructed) != set(range(expected_size)):
            continue
        built = bytes(reconstructed[index] for index in range(expected_size))
        if built[-1] != 0 or b"\0" in built[:-1]:
            continue
        try:
            built_name = built[:-1].decode("ascii")
        except UnicodeDecodeError:
            continue
        if built_name.casefold() != basename.casefold():
            continue
        try:
            first_index = ordered.index(first)
        except ValueError:
            continue
        object_candidates: set[
            tuple[str | None, str | None, int, int]
        ] = set()
        for item in ordered[max(0, first_index - 96) : first_index]:
            if not (
                item.mnemonic.casefold() == "mov"
                and len(item.operands) == 2
                and item.operands[0].type == X86_OP_MEM
                and item.operands[1].type == X86_OP_REG
                and _register_family(item.operands[1].reg) in families
            ):
                continue
            signature = _stack_local_signature(item.operands[0])
            if (
                signature is not None
                and _cfg_path_exists(
                    cfg,
                    int(item.address),
                    int(first.address),
                )
            ):
                object_candidates.add(signature)
        if len(object_candidates) != 1:
            continue
        object_signature = next(iter(object_candidates))
        open_candidates: list[
            tuple[int, tuple[str | None, str | None, int, int]]
        ] = []
        for item in _linear_successors(cfg, last_write, maximum=64):
            if not (
                item.group(CS_GRP_CALL)
                and item.operands
                and item.operands[0].type == X86_OP_IMM
            ):
                continue
            call_address = int(item.address)
            pushes = _call_pushes(cfg, call_address, maximum=64)
            if (
                len(pushes) < 2
                or not any(
                    push.operands[0].type == X86_OP_IMM for push in pushes
                )
                or _selected_string_pointer_push(
                    cfg,
                    call_address,
                    object_signature,
                )
                is None
            ):
                continue
            stream_signature = _this_stack_signature(cfg, call_address)
            if stream_signature is None or stream_signature == object_signature:
                continue
            open_candidates.append((call_address, stream_signature))
        if len(open_candidates) != 1:
            continue
        open_call, stream_signature = open_candidates[0]
        lineage = _ImmediateBasenameLineage(
            first_write=int(first.address),
            last_write=last_write,
            open_call=open_call,
            object_signature=object_signature,
            stream_signature=stream_signature,
            write_addresses=tuple(write_addresses),
        )
        matches[
            (lineage.first_write, lineage.last_write, lineage.open_call, object_signature)
        ] = lineage
    return tuple(matches[key] for key in sorted(matches))


def _memory_base_displacement(
    operand: Any,
    family: str,
    displacement: int,
) -> bool:
    signature = _memory_signature(operand)
    return bool(
        signature is not None
        and signature[0] == family
        and signature[1] is None
        and signature[3] == displacement
    )


def _stream_size_arithmetic(
    cfg: _FunctionCfg,
    call_address: int,
) -> tuple[int, int, int, int] | None:
    """64-bit stream size objectをEDX:ECXへ加算する4命令を検証する。"""

    following = _linear_successors(cfg, call_address, maximum=16)
    for index in range(max(0, len(following) - 3)):
        first, second, third, fourth = following[index : index + 4]
        if not (
            first.mnemonic.casefold() == "mov"
            and len(first.operands) == 2
            and first.operands[0].type == X86_OP_REG
            and _register_family(first.operands[0].reg) == "edx"
            and _memory_base_displacement(first.operands[1], "eax", 8)
            and second.mnemonic.casefold() == "add"
            and len(second.operands) == 2
            and second.operands[0].type == X86_OP_REG
            and _register_family(second.operands[0].reg) == "edx"
            and _memory_base_displacement(second.operands[1], "eax", 0)
            and third.mnemonic.casefold() == "mov"
            and len(third.operands) == 2
            and third.operands[0].type == X86_OP_REG
            and _register_family(third.operands[0].reg) == "ecx"
            and _memory_base_displacement(third.operands[1], "eax", 12)
            and fourth.mnemonic.casefold() == "adc"
            and len(fourth.operands) == 2
            and fourth.operands[0].type == X86_OP_REG
            and _register_family(fourth.operands[0].reg) == "ecx"
            and _memory_base_displacement(fourth.operands[1], "eax", 4)
        ):
            continue
        return tuple(int(item.address) for item in (first, second, third, fourth))
    return None


def _stream_size_output_argument(
    cfg: _FunctionCfg,
    call_address: int,
) -> bool:
    """size callへstack local output objectが渡ることを検証する。"""

    candidates = {
        signature
        for push in _call_pushes(cfg, call_address, maximum=32)
        if (signature := _pushed_location_signature(cfg, call_address, push))
        is not None
        and signature[0] == "ebp"
        and signature[1] is None
        and -0x4000 <= signature[3] < 0
    }
    return len(candidates) == 1


def _stream_success_check(
    cfg: _FunctionCfg,
    read_call: int,
    before_address: int,
) -> tuple[int, int] | None:
    """read戻り値にdataflowで結ばれた成功判定だけを確認する。"""

    tainted_families = {"eax"}
    for instruction in _linear_successors(cfg, read_call, maximum=16):
        address = int(instruction.address)
        if address >= before_address:
            break
        if (
            instruction.group(CS_GRP_CALL)
            or instruction.group(CS_GRP_RET)
            or instruction.group(CS_GRP_JUMP)
        ):
            break
        mnemonic = instruction.mnemonic.casefold()
        operands = instruction.operands
        if mnemonic == "test" and len(operands) == 2:
            left = (
                _register_family(operands[0].reg)
                if operands[0].type == X86_OP_REG
                else None
            )
            right = (
                _register_family(operands[1].reg)
                if operands[1].type == X86_OP_REG
                else None
            )
            bound_check = left is not None and left == right and left in tainted_families
        elif mnemonic == "cmp" and len(operands) == 2:
            left = (
                _register_family(operands[0].reg)
                if operands[0].type == X86_OP_REG
                else None
            )
            bound_check = bool(
                left in tainted_families
                and operands[1].type == X86_OP_IMM
                and int(operands[1].imm) == 0
            )
        else:
            bound_check = False
        if bound_check:
            following = _linear_successors(cfg, address, maximum=2)
            if following:
                successor = following[0]
                mnemonic = successor.mnemonic.casefold()
                if successor.group(CS_GRP_JUMP) and mnemonic != "jmp":
                    return address, int(successor.address)
            return None

        propagated_family = None
        destination_family = None
        if operands and operands[0].type == X86_OP_REG:
            destination_family = _register_family(operands[0].reg)
        if (
            mnemonic == "mov"
            and len(operands) == 2
            and destination_family is not None
            and operands[1].type == X86_OP_REG
        ):
            source_family = _register_family(operands[1].reg)
            if source_family in tainted_families:
                propagated_family = destination_family
        if destination_family is not None and _instruction_writes_register(
            instruction, destination_family
        ):
            tainted_families = tainted_families - {destination_family}
        if propagated_family is not None:
            tainted_families.add(propagated_family)
        if not tainted_families:
            break
    return None


def _cpp_stream_carrier_read_lineages(
    cfg: _FunctionCfg,
    carrier: _ArchiveMember,
    before_address: int,
    dominators: Mapping[int, frozenset[int]],
) -> tuple[tuple[int, int, tuple[int, ...]], ...]:
    """即値basename→C++ stream→size/buffer/readのdef-useを復元する。"""

    basename_lineages = _immediate_built_basename_lineages(cfg, carrier.basename)
    if len(basename_lineages) != 1:
        return ()
    basename_lineage = basename_lineages[0]
    ordered = list(cfg.instructions)
    direct_calls = tuple(
        int(item.address)
        for item in ordered
        if item.group(CS_GRP_CALL)
        and item.operands
        and item.operands[0].type == X86_OP_IMM
    )
    size_candidates: list[tuple[int, tuple[int, int, int, int]]] = []
    for call in direct_calls:
        if not basename_lineage.open_call < call < before_address:
            continue
        if _this_stack_signature(cfg, call) != basename_lineage.stream_signature:
            continue
        arithmetic = _stream_size_arithmetic(cfg, call)
        if arithmetic is None or not _stream_size_output_argument(cfg, call):
            continue
        size_candidates.append((call, arithmetic))
    if len(size_candidates) != 1:
        return ()
    size_call, size_arithmetic = size_candidates[0]
    last_size = size_arithmetic[-1]
    length_stores: list[tuple[int, int]] = []
    for item in ordered:
        address = int(item.address)
        if not last_size < address < before_address:
            continue
        if not (
            item.mnemonic.casefold() == "mov"
            and len(item.operands) == 2
            and item.operands[1].type == X86_OP_REG
            and _register_family(item.operands[1].reg) == "edx"
            and (destination := _absolute_memory_address(item.operands[0]))
            is not None
        ):
            continue
        length_stores.append((address, destination))
    if len(length_stores) != 1:
        return ()
    length_store, length_global = length_stores[0]
    allocator_candidates: list[tuple[int, int, int]] = []
    for call in direct_calls:
        if not length_store < call < before_address:
            continue
        pushes = _call_pushes(cfg, call, maximum=24)
        if not any(_push_register(item, "edx") for item in pushes):
            continue
        buffer_store = _result_global_store_after_call(cfg, call)
        if buffer_store is None or buffer_store[1] == length_global:
            continue
        allocator_candidates.append((call, buffer_store[0], buffer_store[1]))
    if len(allocator_candidates) != 1:
        return ()
    allocator, buffer_store, buffer_global = allocator_candidates[0]
    seek_candidates: list[int] = []
    read_candidates: list[int] = []
    for call in direct_calls:
        if not buffer_store < call < before_address:
            continue
        if _this_stack_signature(cfg, call) != basename_lineage.stream_signature:
            continue
        pushes = _call_pushes(cfg, call, maximum=24)
        if len(pushes) >= 3 and all(
            _push_immediate(item, 0) for item in pushes[-3:]
        ):
            seek_candidates.append(call)
        if len(pushes) >= 3 and (
            _push_immediate(pushes[-3], 0)
            and _push_absolute_memory(pushes[-2], length_global)
            and _push_absolute_memory(pushes[-1], buffer_global)
        ):
            read_candidates.append(call)
    chains: set[tuple[int, int, tuple[int, ...]]] = set()
    for seek_call in seek_candidates:
        for read_call in read_candidates:
            if not seek_call < read_call < before_address:
                continue
            success_check = _stream_success_check(
                cfg,
                read_call,
                before_address,
            )
            if success_check is None:
                continue
            if any(
                _writes_absolute_memory(item, length_global)
                for item in ordered
                if length_store < int(item.address) < read_call
            ) or any(
                _writes_absolute_memory(item, buffer_global)
                for item in ordered
                if buffer_store < int(item.address) < read_call
            ):
                continue
            chain = (
                basename_lineage.first_write,
                basename_lineage.last_write,
                basename_lineage.open_call,
                size_call,
                *size_arithmetic,
                length_store,
                allocator,
                buffer_store,
                seek_call,
                read_call,
                *success_check,
                before_address,
            )
            if (
                _dominates_chain(dominators, chain[:-1])
                and _cfg_path_exists_without_global_writes(
                    cfg,
                    chain[-2],
                    before_address,
                    frozenset({length_global, buffer_global}),
                )
            ):
                chains.add((length_global, buffer_global, chain))
    return tuple(sorted(chains))


def _carrier_read_lineages(
    cfg: _FunctionCfg,
    api_calls: Mapping[str, tuple[int, ...]],
    carrier_addresses: frozenset[int],
    before_address: int,
    dominators: Mapping[int, frozenset[int]],
) -> tuple[tuple[int, int, tuple[int, ...]], ...]:
    """carrier path→CreateFile→GetFileSize→ReadFile chainを復元する。"""

    ordered = list(cfg.instructions)
    path_lineages = _carrier_path_copy_lineages(cfg, carrier_addresses)
    lineages: set[tuple[int, int, tuple[int, ...]]] = set()
    open_calls = tuple(
        sorted(
            address
            for name in ("createfilea", "createfilew")
            for address in api_calls.get(name, ())
        )
    )
    size_calls = api_calls.get("getfilesize", ())
    read_calls = api_calls.get("readfile", ())
    for copy_source, copy_store, path_family in path_lineages:
        for open_call in open_calls:
            if not copy_store < open_call < before_address:
                continue
            pushes = _call_pushes(cfg, open_call, maximum=16)
            if len(pushes) < 7:
                continue
            arguments = pushes[-7:]
            if not (
                _push_immediate(arguments[2], 3)
                and _push_immediate(arguments[5], 0x80000000)
                and _push_register(arguments[6], path_family)
                and not any(
                    _instruction_writes_register(item, path_family)
                    for item in ordered
                    if copy_store < int(item.address) < open_call
                )
            ):
                continue
            handle_result = _result_register_after_call(cfg, open_call)
            if handle_result is None:
                continue
            handle_transfer, handle_family = handle_result
            for size_call in size_calls:
                if not handle_transfer < size_call < before_address:
                    continue
                size_pushes = _call_pushes(cfg, size_call, maximum=8)
                if len(size_pushes) < 2 or not (
                    _push_immediate(size_pushes[-2], 0)
                    and _push_register(size_pushes[-1], handle_family)
                    and not any(
                        _instruction_writes_register(item, handle_family)
                        for item in ordered
                        if handle_transfer < int(item.address) < size_call
                    )
                ):
                    continue
                size_store = _result_global_store_after_call(cfg, size_call)
                if size_store is None:
                    continue
                size_store_address, length_global = size_store
                for allocator in ordered:
                    allocator_address = int(allocator.address)
                    if not (
                        size_store_address < allocator_address < before_address
                        and allocator.group(CS_GRP_CALL)
                        and allocator.operands
                        and allocator.operands[0].type == X86_OP_IMM
                        and any(
                            _push_absolute_memory(item, length_global)
                            for item in _call_pushes(
                                cfg, allocator_address, maximum=8
                            )
                        )
                    ):
                        continue
                    buffer_store = _result_global_store_after_call(
                        cfg, allocator_address
                    )
                    if buffer_store is None:
                        continue
                    buffer_store_address, buffer_global = buffer_store
                    for read_call in read_calls:
                        if not buffer_store_address < read_call < before_address:
                            continue
                        read_pushes = _call_pushes(cfg, read_call, maximum=12)
                        if len(read_pushes) < 5:
                            continue
                        read_arguments = read_pushes[-5:]
                        if not (
                            _push_immediate(read_arguments[0], 0)
                            and _push_absolute_memory(
                                read_arguments[2], length_global
                            )
                            and _push_absolute_memory(
                                read_arguments[3], buffer_global
                            )
                            and _push_register(
                                read_arguments[4], handle_family
                            )
                            and not any(
                                _instruction_writes_register(
                                    item, handle_family
                                )
                                for item in ordered
                                if handle_transfer
                                < int(item.address)
                                < read_call
                            )
                            and not any(
                                _writes_absolute_memory(item, length_global)
                                for item in ordered
                                if size_store_address
                                < int(item.address)
                                < read_call
                            )
                            and not any(
                                _writes_absolute_memory(item, buffer_global)
                                for item in ordered
                                if buffer_store_address
                                < int(item.address)
                                < read_call
                            )
                        ):
                            continue
                        chain = (
                            copy_source,
                            copy_store,
                            open_call,
                            handle_transfer,
                            size_call,
                            size_store_address,
                            allocator_address,
                            buffer_store_address,
                            read_call,
                            before_address,
                        )
                        if _dominates_chain(dominators, chain):
                            lineages.add(
                                (length_global, buffer_global, chain)
                            )
    return tuple(sorted(lineages))


def _module_path_key_lineages(
    pe: _PeMember,
    cfg: _FunctionCfg,
    api_calls: Mapping[str, tuple[int, ...]],
    key_module_addresses: frozenset[int],
    dominators: Mapping[int, frozenset[int]],
) -> tuple[tuple[int, dict[str, int | str]], ...]:
    """kernel32 path末尾3文字目からsub 30hで導くkeyを復元する。"""

    ordered = list(cfg.instructions)
    results: dict[
        tuple[int, ...], tuple[int, dict[str, int | str]]
    ] = {}
    for module_call in api_calls.get("getmodulehandlea", ()):
        module_pushes = _call_pushes(cfg, module_call, maximum=8)
        if not module_pushes or not _push_target(
            module_pushes[-1], key_module_addresses
        ):
            continue
        module_operand = module_pushes[-1].operands[0]
        module_address = int(module_operand.imm) & 0xFFFFFFFF
        derived_key = _system_module_extension_key(pe, module_address)
        if derived_key is None:
            continue
        for filename_call in api_calls.get("getmodulefilenamea", ()):
            if not _dominates_chain(dominators, (module_call, filename_call)):
                continue
            between = [
                item
                for item in ordered
                if module_call < int(item.address) < filename_call
            ]
            if any(_instruction_writes_register(item, "eax") for item in between):
                continue
            pushes = _call_pushes(cfg, filename_call, maximum=16)
            if len(pushes) < 3:
                continue
            arguments = pushes[-3:]
            if not (
                _push_immediate(arguments[0], 0x104)
                and arguments[1].operands[0].type == X86_OP_REG
                and _push_register(arguments[2], "eax")
            ):
                continue
            buffer_family = _register_family(arguments[1].operands[0].reg)
            if buffer_family is None:
                continue
            setup = _linear_predecessors(cfg, filename_call, maximum=16)
            scan_window = [
                item
                for item in ordered
                if filename_call < int(item.address) <= filename_call + 128
            ]
            buffer_leas = [
                item
                for item in setup
                if item.mnemonic.casefold() == "lea"
                and len(item.operands) == 2
                and item.operands[0].type == X86_OP_REG
                and _register_family(item.operands[0].reg) == buffer_family
                and item.operands[1].type == X86_OP_MEM
                and _register_family(item.operands[1].mem.base) == "ebp"
                and item.operands[1].mem.index == 0
                and int(item.address) < int(arguments[1].address)
                and not any(
                    _instruction_writes_register(candidate, buffer_family)
                    for candidate in setup
                    if int(item.address)
                    < int(candidate.address)
                    < int(arguments[1].address)
                )
            ]
            for buffer_lea in buffer_leas:
                buffer_displacement = int(buffer_lea.operands[1].mem.disp)
                scan_leas = [
                    item
                    for item in scan_window
                    if item.mnemonic.casefold() == "lea"
                    and len(item.operands) == 2
                    and item.operands[0].type == X86_OP_REG
                    and item.operands[1].type == X86_OP_MEM
                    and _register_family(item.operands[1].mem.base) == "ebp"
                    and item.operands[1].mem.index == 0
                    and int(item.operands[1].mem.disp) == buffer_displacement
                ]
                for scan_lea in scan_leas:
                    scan_family = _register_family(scan_lea.operands[0].reg)
                    if scan_family is None:
                        continue
                    base_leas = [
                        item
                        for item in scan_window
                        if int(item.address) > int(scan_lea.address)
                        and item.mnemonic.casefold() == "lea"
                        and len(item.operands) == 2
                        and item.operands[0].type == X86_OP_REG
                        and item.operands[1].type == X86_OP_MEM
                        and _register_family(item.operands[1].mem.base)
                        == scan_family
                        and item.operands[1].mem.index == 0
                        and int(item.operands[1].mem.disp) == 1
                    ]
                    for base_lea in base_leas:
                        base_family = _register_family(base_lea.operands[0].reg)
                        if base_family is None or base_family == scan_family:
                            continue
                        byte_loads = [
                            item
                            for item in scan_window
                            if int(item.address) > int(base_lea.address)
                            and item.mnemonic.casefold() == "mov"
                            and len(item.operands) == 2
                            and item.operands[0].type == X86_OP_REG
                            and item.operands[1].type == X86_OP_MEM
                            and _register_family(item.operands[1].mem.base)
                            == scan_family
                            and item.operands[1].mem.index == 0
                            and int(item.operands[1].size) == 1
                        ]
                        for byte_load in byte_loads:
                            loaded_family = _register_family(
                                byte_load.operands[0].reg
                            )
                            if loaded_family is None or loaded_family == scan_family:
                                continue
                            scan_index = scan_window.index(byte_load)
                            loop_tail = scan_window[scan_index + 1 : scan_index + 5]
                            increments = [
                                item
                                for item in loop_tail
                                if item.mnemonic.casefold() == "inc"
                                and item.operands
                                and item.operands[0].type == X86_OP_REG
                                and _register_family(item.operands[0].reg)
                                == scan_family
                            ]
                            tests = [
                                item
                                for item in loop_tail
                                if item.mnemonic.casefold() == "test"
                                and len(item.operands) == 2
                                and all(
                                    operand.type == X86_OP_REG
                                    and _register_family(operand.reg)
                                    == loaded_family
                                    for operand in item.operands
                                )
                            ]
                            back_edges = [
                                item
                                for item in loop_tail
                                if item.group(CS_GRP_JUMP)
                                and item.mnemonic.casefold() != "jmp"
                                and item.operands
                                and item.operands[0].type == X86_OP_IMM
                                and (int(item.operands[0].imm) & 0xFFFFFFFF)
                                == int(byte_load.address)
                            ]
                            for increment in increments:
                                for test in tests:
                                    for back_edge in back_edges:
                                        if not (
                                            int(increment.address)
                                            < int(test.address)
                                            < int(back_edge.address)
                                        ):
                                            continue
                                        subtract_lengths = [
                                            item
                                            for item in scan_window
                                            if int(item.address)
                                            > int(back_edge.address)
                                            and item.mnemonic.casefold() == "sub"
                                            and len(item.operands) == 2
                                            and item.operands[0].type == X86_OP_REG
                                            and _register_family(
                                                item.operands[0].reg
                                            )
                                            == scan_family
                                            and item.operands[1].type == X86_OP_REG
                                            and _register_family(
                                                item.operands[1].reg
                                            )
                                            == base_family
                                        ]
                                        for subtract_length in subtract_lengths:
                                            key_loads = [
                                                item
                                                for item in scan_window
                                                if int(item.address)
                                                > int(subtract_length.address)
                                                and item.mnemonic.casefold()
                                                in {"movsx", "movzx"}
                                                and len(item.operands) == 2
                                                and item.operands[0].type
                                                == X86_OP_REG
                                                and item.operands[1].type
                                                == X86_OP_MEM
                                                and _register_family(
                                                    item.operands[1].mem.base
                                                )
                                                == "ebp"
                                                and _register_family(
                                                    item.operands[1].mem.index
                                                )
                                                == scan_family
                                                and int(
                                                    item.operands[1].mem.disp
                                                )
                                                == buffer_displacement - 3
                                                and int(item.operands[1].size) == 1
                                            ]
                                            for key_load in key_loads:
                                                key_family = _register_family(
                                                    key_load.operands[0].reg
                                                )
                                                if key_family is None:
                                                    continue
                                                subtract_keys = [
                                                    item
                                                    for item in scan_window
                                                    if int(item.address)
                                                    > int(key_load.address)
                                                    and item.mnemonic.casefold()
                                                    == "sub"
                                                    and len(item.operands) == 2
                                                    and item.operands[0].type
                                                    == X86_OP_REG
                                                    and _register_family(
                                                        item.operands[0].reg
                                                    )
                                                    == key_family
                                                    and item.operands[1].type
                                                    == X86_OP_IMM
                                                    and int(item.operands[1].imm)
                                                    == 0x30
                                                ]
                                                for subtract_key in subtract_keys:
                                                    key_stores = [
                                                        item
                                                        for item in _linear_successors(
                                                            cfg,
                                                            int(
                                                                subtract_key.address
                                                            ),
                                                            maximum=4,
                                                        )
                                                        if item.mnemonic.casefold()
                                                        == "mov"
                                                        and len(item.operands) == 2
                                                        and item.operands[0].type
                                                        == X86_OP_MEM
                                                        and _register_family(
                                                            item.operands[0].mem.base
                                                        )
                                                        == "ebp"
                                                        and item.operands[0].mem.index
                                                        == 0
                                                        and item.operands[1].type
                                                        == X86_OP_REG
                                                        and _register_family(
                                                            item.operands[1].reg
                                                        )
                                                        == key_family
                                                    ]
                                                    for key_store in key_stores:
                                                        chain = (
                                                            module_call,
                                                            int(buffer_lea.address),
                                                            filename_call,
                                                            int(scan_lea.address),
                                                            int(base_lea.address),
                                                            int(byte_load.address),
                                                            int(increment.address),
                                                            int(test.address),
                                                            int(back_edge.address),
                                                            int(
                                                                subtract_length.address
                                                            ),
                                                            int(key_load.address),
                                                            int(subtract_key.address),
                                                            int(key_store.address),
                                                        )
                                                        if not _dominates_chain(
                                                            dominators, chain
                                                        ):
                                                            continue
                                                        identity = (
                                                            derived_key,
                                                            *chain,
                                                        )
                                                        results[identity] = (
                                                            derived_key,
                                                            {
                                                                "module_call": module_call,
                                                                "filename_call": filename_call,
                                                                "key_load": int(
                                                                    key_load.address
                                                                ),
                                                                "key_subtract": int(
                                                                    subtract_key.address
                                                                ),
                                                                "key_store": int(
                                                                    key_store.address
                                                                ),
                                                                "key_family": key_family,
                                                                "key_stack_displacement": int(
                                                                    key_store.operands[
                                                                        0
                                                                    ].mem.disp
                                                                ),
                                                            },
                                                        )
    return tuple(results[key] for key in sorted(results))


def _vector_key_definition(
    ordered: list[Any],
    *,
    key_store: int,
    key_family: str,
    key_stack_displacement: int,
    vector_seed: Any,
) -> int | None:
    """vector seed直前のkey registerが導出値または同じstack slot reloadか確認する。"""

    writes = [
        item
        for item in ordered
        if key_store < int(item.address) < int(vector_seed.address)
        and _instruction_writes_register(item, key_family)
    ]
    if not writes:
        return key_store
    latest = writes[-1]
    if not (
        latest.mnemonic.casefold() == "mov"
        and len(latest.operands) == 2
        and latest.operands[0].type == X86_OP_REG
        and _register_family(latest.operands[0].reg) == key_family
        and latest.operands[1].type == X86_OP_MEM
        and _register_family(latest.operands[1].mem.base) == "ebp"
        and latest.operands[1].mem.index == 0
        and int(latest.operands[1].mem.disp) == key_stack_displacement
    ):
        return None
    return int(latest.address)


def _instruction_writes_exact_register(
    instruction: Any, register: int
) -> bool:
    """明示writeまたはcallが指定vector registerを破壊するか判定する。"""

    if instruction.group(CS_GRP_CALL):
        return True
    if instruction.mnemonic.casefold() in {"cmp", "push", "test"} or (
        instruction.mnemonic.casefold().startswith("j")
    ):
        return False
    return bool(
        instruction.operands
        and instruction.operands[0].type == X86_OP_REG
        and instruction.operands[0].reg == register
    )


def _vector_key_broadcast_lineages(
    cfg: _FunctionCfg,
    ordered: list[Any],
    *,
    vector_seed: Any,
    dominators: Mapping[int, frozenset[int]],
) -> tuple[dict[str, int | str], ...]:
    """scalar keyをXMMへbroadcastし、同値GPRへ戻す一意候補を列挙する。"""

    seed_address = int(vector_seed.address)
    seed_register = vector_seed.operands[0].reg
    candidates: dict[tuple[int, ...], dict[str, int | str]] = {}
    broadcasts = [
        item
        for item in ordered
        if seed_address < int(item.address) <= seed_address + 96
        and item.mnemonic.casefold() == "pshufd"
        and len(item.operands) == 3
        and item.operands[0].type == X86_OP_REG
        and item.operands[0].reg == seed_register
        and item.operands[1].type == X86_OP_REG
        and item.operands[1].reg == seed_register
        and item.operands[2].type == X86_OP_IMM
        and int(item.operands[2].imm) == 0
    ]
    for broadcast in broadcasts:
        packs = [
            item
            for item in ordered
            if int(broadcast.address) < int(item.address) <= seed_address + 192
            and item.mnemonic.casefold() == "packuswb"
            and len(item.operands) == 2
            and all(
                operand.type == X86_OP_REG
                and operand.reg == seed_register
                for operand in item.operands
            )
        ]
        for first_index, first_pack in enumerate(packs):
            for second_pack in packs[first_index + 1 :]:
                allowed_writes = {
                    int(broadcast.address),
                    int(first_pack.address),
                    int(second_pack.address),
                }
                intervening = [
                    item
                    for item in ordered
                    if seed_address < int(item.address) < int(second_pack.address)
                    and _instruction_writes_exact_register(
                        item, seed_register
                    )
                    and int(item.address) not in allowed_writes
                ]
                if any(
                    item.mnemonic.casefold() != "andps"
                    or len(item.operands) != 2
                    or item.operands[0].type != X86_OP_REG
                    or item.operands[0].reg != seed_register
                    or item.operands[1].type != X86_OP_MEM
                    for item in intervening
                ):
                    continue
                stack_stores = [
                    item
                    for item in ordered
                    if int(second_pack.address)
                    < int(item.address)
                    <= int(second_pack.address) + 64
                    and item.mnemonic.casefold()
                    in {"movaps", "movups", "movdqa", "movdqu"}
                    and len(item.operands) == 2
                    and item.operands[0].type == X86_OP_MEM
                    and _register_family(item.operands[0].mem.base) == "ebp"
                    and item.operands[0].mem.index == 0
                    and item.operands[1].type == X86_OP_REG
                    and item.operands[1].reg == seed_register
                ]
                for stack_store in stack_stores:
                    stack_signature = _memory_signature(
                        stack_store.operands[0]
                    )
                    if stack_signature is None:
                        continue
                    key_loads = [
                        item
                        for item in ordered
                        if int(stack_store.address)
                        < int(item.address)
                        <= int(stack_store.address) + 32
                        and item.mnemonic.casefold() == "mov"
                        and len(item.operands) == 2
                        and item.operands[0].type == X86_OP_REG
                        and item.operands[1].type == X86_OP_MEM
                        and _memory_signature(item.operands[1])
                        == stack_signature
                    ]
                    for key_load in key_loads:
                        key_family = _register_family(
                            key_load.operands[0].reg
                        )
                        if key_family is None:
                            continue
                        chain = (
                            seed_address,
                            int(broadcast.address),
                            int(first_pack.address),
                            int(second_pack.address),
                            int(stack_store.address),
                            int(key_load.address),
                        )
                        if not _dominates_chain(dominators, chain):
                            continue
                        if any(
                            item.group(CS_GRP_CALL)
                            for item in ordered
                            if seed_address
                            < int(item.address)
                            < int(key_load.address)
                        ):
                            continue
                        candidates[chain] = {
                            "broadcast": int(broadcast.address),
                            "first_pack": int(first_pack.address),
                            "second_pack": int(second_pack.address),
                            "key_vector_register": seed_register,
                            "vector_key_load": int(key_load.address),
                            "vector_key_family": key_family,
                        }
    return tuple(candidates[key] for key in sorted(candidates))


def _vector_xor_blocks(
    cfg: _FunctionCfg,
    ordered: list[Any],
    *,
    start_address: int,
    end_address: int,
    pointer_family: str,
    key_family: str,
) -> tuple[tuple[int, int, int, int, tuple[str | None, str | None, int, int]], ...]:
    """同じkey-bearing XMMを使う4-byte buffer XOR blockを列挙する。"""

    blocks: set[
        tuple[int, int, int, int, tuple[str | None, str | None, int, int]]
    ] = set()
    for instruction in ordered:
        xor_address = int(instruction.address)
        if not (
            start_address < xor_address < end_address
            and instruction.mnemonic.casefold() in {"xorps", "pxor"}
            and len(instruction.operands) == 2
            and all(
                operand.type == X86_OP_REG for operand in instruction.operands
            )
            and instruction.operands[0].reg != instruction.operands[1].reg
        ):
            continue
        data_register = instruction.operands[0].reg
        key_register = instruction.operands[1].reg
        predecessors = _linear_predecessors(cfg, xor_address, maximum=6)
        data_definitions = [
            item
            for item in predecessors
            if _instruction_writes_exact_register(item, data_register)
        ]
        key_definitions = [
            item
            for item in predecessors
            if _instruction_writes_exact_register(item, key_register)
        ]
        if not data_definitions or not key_definitions:
            continue
        data_load = data_definitions[-1]
        key_load = key_definitions[-1]
        if not (
            data_load.mnemonic.casefold() == "movd"
            and len(data_load.operands) == 2
            and data_load.operands[0].type == X86_OP_REG
            and data_load.operands[0].reg == data_register
            and data_load.operands[1].type == X86_OP_MEM
            and _register_family(data_load.operands[1].mem.base)
            == pointer_family
            and data_load.operands[1].mem.index == 0
            and key_load.mnemonic.casefold() == "movd"
            and len(key_load.operands) == 2
            and key_load.operands[0].type == X86_OP_REG
            and key_load.operands[0].reg == key_register
            and key_load.operands[1].type == X86_OP_REG
            and _register_family(key_load.operands[1].reg) == key_family
            and int(data_load.address) < xor_address
            and int(key_load.address) < xor_address
        ):
            continue
        memory = _memory_signature(data_load.operands[1])
        if memory is None:
            continue
        stores = []
        for item in _linear_successors(cfg, xor_address, maximum=3):
            if not (
                item.mnemonic.casefold() == "movd"
                and len(item.operands) == 2
                and item.operands[0].type == X86_OP_MEM
                and item.operands[1].type == X86_OP_REG
                and item.operands[1].reg == data_register
            ):
                continue
            store_memory = _memory_signature(item.operands[0])
            if store_memory is None or store_memory[:3] != memory[:3]:
                continue
            pointer_adjustment = sum(
                int(candidate.operands[1].mem.disp)
                for candidate in ordered
                if int(data_load.address)
                < int(candidate.address)
                < int(item.address)
                and candidate.mnemonic.casefold() == "lea"
                and len(candidate.operands) == 2
                and candidate.operands[0].type == X86_OP_REG
                and _register_family(candidate.operands[0].reg)
                == pointer_family
                and candidate.operands[1].type == X86_OP_MEM
                and _register_family(candidate.operands[1].mem.base)
                == pointer_family
                and candidate.operands[1].mem.index == 0
            )
            if store_memory[3] == memory[3] - pointer_adjustment:
                stores.append(item)
        if len(stores) != 1:
            continue
        blocks.add(
            (
                int(data_load.address),
                int(key_load.address),
                xor_address,
                int(stores[0].address),
                memory,
            )
        )
    return tuple(sorted(blocks))


def _xor_lineage(
    cfg: _FunctionCfg,
    *,
    buffer_global: int,
    length_global: int,
    key_lineage: Mapping[str, int | str],
    dominators: Mapping[int, frozenset[int]],
) -> dict[str, int | str] | None:
    """loader由来の同一keyがvector/scalar XORへ届くことを確認する。"""

    ordered = list(cfg.instructions)
    key_subtract = int(key_lineage["key_subtract"])
    key_store = int(key_lineage["key_store"])
    key_family = str(key_lineage["key_family"])
    key_stack_displacement = int(key_lineage["key_stack_displacement"])
    key_load = int(key_lineage["key_load"])
    buffer_loads: list[tuple[int, str]] = []
    length_loads: list[tuple[int, str]] = []
    for instruction in ordered:
        address = int(instruction.address)
        if not int(key_lineage["filename_call"]) < address < key_load:
            continue
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_REG
        ):
            source = _absolute_memory_address(instruction.operands[1])
            family = _register_family(instruction.operands[0].reg)
            if source == buffer_global and family is not None:
                buffer_loads.append((address, family))
            if source == length_global and family is not None:
                length_loads.append((address, family))
    if len(buffer_loads) != 1 or len(length_loads) != 1:
        return None
    buffer_load, buffer_family = buffer_loads[0]
    length_load, length_family = length_loads[0]
    length_stack_stores = [
        item
        for item in _linear_successors(cfg, length_load, maximum=4)
        if item.mnemonic.casefold() == "mov"
        and len(item.operands) == 2
        and item.operands[0].type == X86_OP_MEM
        and _register_family(item.operands[0].mem.base) == "ebp"
        and item.operands[0].mem.index == 0
        and item.operands[1].type == X86_OP_REG
        and _register_family(item.operands[1].reg) == length_family
    ]
    if len(length_stack_stores) != 1:
        return None
    length_stack_displacement = int(length_stack_stores[0].operands[0].mem.disp)
    candidates: dict[tuple[int, ...], dict[str, int | str]] = {}
    vector_seeds = [
        item
        for item in ordered
        if key_subtract < int(item.address) < key_subtract + 512
        and item.mnemonic.casefold() == "movd"
        and len(item.operands) == 2
        and item.operands[1].type == X86_OP_REG
        and _register_family(item.operands[1].reg) == key_family
    ]
    for vector_seed in vector_seeds:
        key_definition = _vector_key_definition(
            ordered,
            key_store=key_store,
            key_family=key_family,
            key_stack_displacement=key_stack_displacement,
            vector_seed=vector_seed,
        )
        if key_definition is None:
            continue
        broadcasts = _vector_key_broadcast_lineages(
            cfg,
            ordered,
            vector_seed=vector_seed,
            dominators=dominators,
        )
        for broadcast in broadcasts:
            vector_key_load = int(broadcast["vector_key_load"])
            vector_key_family = str(broadcast["vector_key_family"])
            scalar_key_loads = [
                item
                for item in ordered
                if vector_key_load
                < int(item.address)
                <= int(vector_seed.address) + 512
                and item.mnemonic.casefold() == "mov"
                and len(item.operands) == 2
                and item.operands[0].type == X86_OP_REG
                and item.operands[1].type == X86_OP_MEM
                and _register_family(item.operands[1].mem.base) == "ebp"
                and item.operands[1].mem.index == 0
                and int(item.operands[1].mem.disp)
                == key_stack_displacement
            ]
            for scalar_key_load in scalar_key_loads:
                scalar_family = _register_family(
                    scalar_key_load.operands[0].reg
                )
                if scalar_family is None:
                    continue
                scalar_index = ordered.index(scalar_key_load)
                scalar_window = ordered[scalar_index + 1 : scalar_index + 9]
                vector_buffers = [
                    item
                    for item in ordered
                    if item.mnemonic.casefold() == "lea"
                    and len(item.operands) == 2
                    and item.operands[0].type == X86_OP_REG
                    and item.operands[1].type == X86_OP_MEM
                    and _register_family(item.operands[1].mem.base)
                    == buffer_family
                    and item.operands[1].mem.index == 0
                    and int(vector_seed.address)
                    < int(item.address)
                    < int(scalar_key_load.address)
                ]
                if len(vector_buffers) != 1:
                    continue
                vector_buffer = vector_buffers[0]
                pointer_family = _register_family(
                    vector_buffer.operands[0].reg
                )
                if pointer_family is None:
                    continue
                blocks = _vector_xor_blocks(
                    cfg,
                    ordered,
                    start_address=max(
                        int(vector_buffer.address), vector_key_load
                    ),
                    end_address=int(scalar_key_load.address),
                    pointer_family=pointer_family,
                    key_family=vector_key_family,
                )
                if (
                    len(blocks) != 4
                    or len({block[4] for block in blocks}) != 4
                    or any(
                        _instruction_writes_register(
                            item, vector_key_family
                        )
                        for item in ordered
                        if vector_key_load
                        < int(item.address)
                        < max(block[3] for block in blocks)
                    )
                ):
                    continue
                data_leas = [
                    item
                    for item in scalar_window
                    if item.mnemonic.casefold() == "lea"
                    and len(item.operands) == 2
                    and item.operands[0].type == X86_OP_REG
                    and item.operands[1].type == X86_OP_MEM
                    and _register_family(item.operands[1].mem.base)
                    == buffer_family
                    and item.operands[1].mem.index != 0
                ]
                for data_lea in data_leas:
                    data_family = _register_family(
                        data_lea.operands[0].reg
                    )
                    index_family = _register_family(
                        data_lea.operands[1].mem.index
                    )
                    if data_family is None or index_family is None:
                        continue
                    scalar_xors = [
                        item
                        for item in scalar_window
                        if int(item.address) > int(data_lea.address)
                        and item.mnemonic.casefold() == "xor"
                        and len(item.operands) == 2
                        and item.operands[0].type == X86_OP_MEM
                        and int(item.operands[0].size) == 1
                        and _register_family(item.operands[0].mem.base)
                        == data_family
                        and item.operands[0].mem.index == 0
                        and item.operands[1].type == X86_OP_REG
                        and _register_family(item.operands[1].reg)
                        == scalar_family
                    ]
                    increments = [
                        item
                        for item in scalar_window
                        if item.mnemonic.casefold() == "inc"
                        and item.operands
                        and item.operands[0].type == X86_OP_REG
                        and _register_family(item.operands[0].reg)
                        == index_family
                    ]
                    compares = [
                        item
                        for item in scalar_window
                        if item.mnemonic.casefold() == "cmp"
                        and len(item.operands) == 2
                        and item.operands[0].type == X86_OP_REG
                        and _register_family(item.operands[0].reg)
                        == index_family
                        and (
                            _absolute_memory_address(item.operands[1])
                            == length_global
                            or (
                                item.operands[1].type == X86_OP_MEM
                                and _register_family(
                                    item.operands[1].mem.base
                                )
                                == "ebp"
                                and item.operands[1].mem.index == 0
                                and int(item.operands[1].mem.disp)
                                == length_stack_displacement
                            )
                        )
                    ]
                    back_edges = [
                        item
                        for item in scalar_window
                        if item.group(CS_GRP_JUMP)
                        and item.mnemonic.casefold() != "jmp"
                        and item.operands
                        and item.operands[0].type == X86_OP_IMM
                        and (int(item.operands[0].imm) & 0xFFFFFFFF)
                        == int(scalar_key_load.address)
                    ]
                    for scalar_xor in scalar_xors:
                        for increment in increments:
                            for compare in compares:
                                for back_edge in back_edges:
                                    chain = (
                                        key_subtract,
                                        key_store,
                                        key_definition,
                                        int(vector_seed.address),
                                        int(scalar_key_load.address),
                                        int(data_lea.address),
                                        int(scalar_xor.address),
                                        int(increment.address),
                                        int(compare.address),
                                        int(back_edge.address),
                                    )
                                    first_vector_xor = min(
                                        block[2] for block in blocks
                                    )
                                    last_vector_store = max(
                                        block[3] for block in blocks
                                    )
                                    if not (
                                        int(data_lea.address)
                                        < int(scalar_xor.address)
                                        < int(increment.address)
                                        < int(compare.address)
                                        < int(back_edge.address)
                                        and _dominates_chain(
                                            dominators, chain
                                        )
                                        and _cfg_path_exists(
                                            cfg,
                                            int(broadcast["vector_key_load"]),
                                            first_vector_xor,
                                        )
                                        and _cfg_path_exists(
                                            cfg,
                                            last_vector_store,
                                            int(scalar_key_load.address),
                                        )
                                    ):
                                        continue
                                    identity = (
                                        *chain,
                                        int(broadcast["broadcast"]),
                                        int(broadcast["first_pack"]),
                                        int(broadcast["second_pack"]),
                                        int(vector_buffer.address),
                                        *(value for block in blocks for value in block[:4]),
                                    )
                                    candidates[identity] = {
                                        "buffer_load": buffer_load,
                                        "length_load": length_load,
                                        "key_store": key_store,
                                        "vector_seed": int(
                                            vector_seed.address
                                        ),
                                        "vector_xor": first_vector_xor,
                                        "scalar_xor": int(
                                            scalar_xor.address
                                        ),
                                        "buffer_family": buffer_family,
                                    }
    return next(iter(candidates.values())) if len(candidates) == 1 else None


def _result_register_after_call(
    cfg: _FunctionCfg, call_address: int
) -> tuple[int, str] | None:
    """callのEAX戻り値を分岐・clobberなしで保存する一意なmovを返す。"""

    for instruction in _linear_successors(cfg, call_address, maximum=4):
        if (
            instruction.group(CS_GRP_CALL)
            or instruction.group(CS_GRP_JUMP)
            or instruction.group(CS_GRP_RET)
        ):
            return None
        if (
            instruction.mnemonic.casefold() == "mov"
            and len(instruction.operands) == 2
            and instruction.operands[0].type == X86_OP_REG
            and instruction.operands[1].type == X86_OP_REG
            and _register_family(instruction.operands[1].reg) == "eax"
        ):
            family = _register_family(instruction.operands[0].reg)
            if family is None or family == "eax":
                return None
            return int(instruction.address), family
        if _instruction_writes_register(instruction, "eax"):
            return None
    return None


def _injection_lineage(
    cfg: _FunctionCfg,
    api_calls: Mapping[str, tuple[int, ...]],
    *,
    buffer_global: int,
    length_global: int,
    suspended_process_addresses: frozenset[int],
    write_module_addresses: frozenset[int],
    write_api_addresses: frozenset[int],
    after_address: int,
    dominators: Mapping[int, frozenset[int]],
) -> tuple[int, ...] | None:
    """同一CFG pathのsuspended-process注入引数とdata-flowを検証する。"""

    instructions = list(cfg.instructions)
    local_candidates: list[tuple[int, int, str]] = []
    for call in api_calls.get("virtualalloc", ()):
        if call <= after_address:
            continue
        pushes = _call_pushes(cfg, call, maximum=16)
        if len(pushes) < 4:
            continue
        args = pushes[-4:]
        if not (
            _push_immediate(args[0], 0x40)
            and _push_immediate(args[1], 0x3000)
            and _push_absolute_memory(args[2], length_global)
            and _push_immediate(args[3], 0)
        ):
            continue
        result = _result_register_after_call(cfg, call)
        if result is not None:
            transfer, result_family = result
            local_candidates.append((call, transfer, result_family))
    if len(local_candidates) != 1:
        return None
    local_alloc, local_transfer, local_family = local_candidates[0]
    copy_calls: list[int] = []
    for instruction in instructions:
        address = int(instruction.address)
        if not (
            local_alloc < address
            and instruction.group(CS_GRP_CALL)
            and instruction.operands
            and instruction.operands[0].type == X86_OP_IMM
        ):
            continue
        pushes = _call_pushes(cfg, address, maximum=16)
        if len(pushes) >= 3 and (
            _push_absolute_memory(pushes[-3], length_global)
            and _push_absolute_memory(pushes[-2], buffer_global)
            and _push_register(pushes[-1], local_family)
            and not any(
                _instruction_writes_register(item, local_family)
                for item in instructions
                if local_transfer < int(item.address) < address
            )
        ):
            copy_calls.append(address)
    if len(copy_calls) != 1:
        return None
    copy_call = copy_calls[0]
    process_candidates: list[
        tuple[int, tuple[str | None, str | None, int, int]]
    ] = []
    for call in api_calls.get("createprocessa", ()):
        if call <= copy_call:
            continue
        pushes = _call_pushes(cfg, call, maximum=32)
        if len(pushes) < 10:
            continue
        args = pushes[-10:]
        if not (
            _push_immediate(args[2], 0)
            and _push_immediate(args[3], 0)
            and _push_immediate(args[4], 4)
            and _push_immediate(args[5], 0)
            and _push_immediate(args[6], 0)
            and _push_immediate(args[7], 0)
            and _push_target(args[8], suspended_process_addresses)
            and _push_immediate(args[9], 0)
            and args[0].operands[0].type in {X86_OP_REG, X86_OP_MEM}
            and args[1].operands[0].type in {X86_OP_REG, X86_OP_MEM}
        ):
            continue
        process_info = _pushed_location_signature(cfg, call, args[0])
        startup_info = _pushed_location_signature(cfg, call, args[1])
        if process_info is None or startup_info is None or process_info == startup_info:
            continue
        process_candidates.append((call, process_info))
    if len(process_candidates) != 1:
        return None
    process, process_info = process_candidates[0]
    context_candidates: list[
        tuple[int, tuple[str | None, str | None, int, int], tuple[str | None, str | None, int, int]]
    ] = []
    for call in api_calls.get("getthreadcontext", ()):
        if call <= process:
            continue
        pushes = _call_pushes(cfg, call, maximum=12)
        if len(pushes) < 2:
            continue
        context_signature = _pushed_location_signature(
            cfg, call, pushes[-2]
        )
        thread_signature = _pushed_location_signature(cfg, call, pushes[-1])
        expected_thread = (
            process_info[0],
            process_info[1],
            process_info[2],
            process_info[3] + 4,
        )
        if (
            context_signature is not None
            and thread_signature == expected_thread
        ):
            context_candidates.append((call, context_signature, thread_signature))
    if len(context_candidates) != 1:
        return None
    context, context_signature, thread_signature = context_candidates[0]
    remote_candidates: list[
        tuple[int, int, str, tuple[str | None, str | None, int, int]]
    ] = []
    for call in api_calls.get("virtualallocex", ()):
        if call <= context:
            continue
        pushes = _call_pushes(cfg, call, maximum=16)
        if len(pushes) < 5:
            continue
        args = pushes[-5:]
        process_handle = _memory_signature(args[4].operands[0])
        if not (
            _push_immediate(args[0], 0x40)
            and _push_immediate(args[1], 0x3000)
            and _push_absolute_memory(args[2], length_global)
            and _push_immediate(args[3], 0)
            and process_handle == process_info
        ):
            continue
        result = _result_register_after_call(cfg, call)
        if result is not None:
            transfer, result_family = result
            remote_candidates.append(
                (call, transfer, result_family, process_handle)
            )
    if len(remote_candidates) != 1:
        return None
    remote_alloc, remote_transfer, remote_family, process_handle = (
        remote_candidates[0]
    )
    module_candidates: list[int] = []
    for call in api_calls.get("getmodulehandlea", ()):
        if call <= remote_alloc:
            continue
        pushes = _call_pushes(cfg, call, maximum=8)
        if pushes and _push_target(pushes[-1], write_module_addresses):
            module_candidates.append(call)
    if len(module_candidates) != 1:
        return None
    module_call = module_candidates[0]
    resolver_candidates: list[int] = []
    for call in api_calls.get("getprocaddress", ()):
        if call <= module_call:
            continue
        between = [
            item
            for item in instructions
            if module_call < int(item.address) < call
        ]
        pushes = _call_pushes(cfg, call, maximum=8)
        if (
            len(pushes) >= 2
            and _push_target(pushes[-2], write_api_addresses)
            and _push_register(pushes[-1], "eax")
            and not any(
                _instruction_writes_register(item, "eax") for item in between
            )
        ):
            resolver_candidates.append(call)
    if len(resolver_candidates) != 1:
        return None
    resolver = resolver_candidates[0]
    write_candidates: list[int] = []
    for instruction in instructions:
        address = int(instruction.address)
        if not (
            resolver < address <= resolver + 96
            and instruction.group(CS_GRP_CALL)
            and instruction.operands
            and instruction.operands[0].type == X86_OP_REG
            and _register_family(instruction.operands[0].reg) == "eax"
        ):
            continue
        pushes = _call_pushes(cfg, address, maximum=16)
        if len(pushes) < 5:
            continue
        between_resolver_and_call = [
            item
            for item in instructions
            if resolver < int(item.address) < address
        ]
        args = pushes[-5:]
        if (
            _push_immediate(args[0], 0)
            and _push_absolute_memory(args[1], length_global)
            and _push_register(args[2], local_family)
            and _push_register(args[3], remote_family)
            and _memory_signature(args[4].operands[0]) == process_handle
            and not any(
                _instruction_writes_register(item, "eax")
                for item in between_resolver_and_call
            )
            and not any(
                _instruction_writes_register(item, local_family)
                for item in instructions
                if local_transfer < int(item.address) < address
            )
            and not any(
                _instruction_writes_register(item, remote_family)
                for item in instructions
                if remote_transfer < int(item.address) < address
            )
        ):
            write_candidates.append(address)
    if len(write_candidates) != 1:
        return None
    indirect_write = write_candidates[0]
    context_writes = [
        item
        for item in instructions
        if indirect_write < int(item.address)
        and item.mnemonic.casefold() == "mov"
        and len(item.operands) == 2
        and item.operands[0].type == X86_OP_MEM
        and item.operands[1].type == X86_OP_REG
        and _register_family(item.operands[1].reg) == remote_family
        and _memory_signature(item.operands[0])
        == (
            context_signature[0],
            context_signature[1],
            context_signature[2],
            context_signature[3] + 0xB8,
        )
    ]
    if len(context_writes) != 1:
        return None
    context_write = context_writes[0]
    if any(
        _instruction_writes_register(item, remote_family)
        for item in instructions
        if remote_transfer
        < int(item.address)
        < int(context_write.address)
    ):
        return None
    set_candidates: list[int] = []
    for call in api_calls.get("setthreadcontext", ()):
        if call <= int(context_write.address):
            continue
        pushes = _call_pushes(cfg, call, maximum=12)
        if len(pushes) >= 2 and (
            _pushed_location_signature(cfg, call, pushes[-2]) == context_signature
            and _pushed_location_signature(cfg, call, pushes[-1])
            == thread_signature
        ):
            set_candidates.append(call)
    if len(set_candidates) != 1:
        return None
    set_context = set_candidates[0]
    resume_candidates: list[int] = []
    for call in api_calls.get("resumethread", ()):
        if call <= set_context:
            continue
        pushes = _call_pushes(cfg, call, maximum=8)
        if (
            pushes
            and _pushed_location_signature(cfg, call, pushes[-1])
            == thread_signature
        ):
            resume_candidates.append(call)
    if len(resume_candidates) != 1:
        return None
    resume = resume_candidates[0]
    chain = (
        after_address,
        local_alloc,
        local_transfer,
        copy_call,
        process,
        context,
        remote_alloc,
        remote_transfer,
        module_call,
        resolver,
        indirect_write,
        int(context_write.address),
        set_context,
        resume,
    )
    return chain if _dominates_chain(dominators, chain) else None


def _function_transform_injection_evidence(
    loader: _PeMember,
    carrier: _ArchiveMember,
    targets: Mapping[str, frozenset[int]],
    cfg: _FunctionCfg,
) -> tuple[int, _ReachabilityEvidence, dict[str, Any]] | None:
    """carrier read、exact key、XOR、injectionを同一1 function CFGで証明する。"""

    if not cfg.completed or len(cfg.instructions) < 256:
        return None
    dominators = _cfg_dominators(cfg)
    if not dominators:
        return None
    references = _target_reference_positions(cfg, targets)
    required_static_targets = {
        label: addresses
        for label, addresses in targets.items()
        if label != "carrier"
    }
    if any(not references.get(label) for label in required_static_targets):
        return None
    api_calls = _function_api_calls(loader, cfg)
    key_lineages = _module_path_key_lineages(
        loader,
        cfg,
        api_calls,
        targets["key_module"],
        dominators,
    )
    if len(key_lineages) != 1:
        return None
    derived_key, key_lineage = key_lineages[0]
    legacy_read_lineages = (
        _carrier_read_lineages(
            cfg,
            api_calls,
            targets["carrier"],
            int(key_lineage["module_call"]),
            dominators,
        )
        if targets.get("carrier")
        else ()
    )
    cpp_stream_read_lineages = _cpp_stream_carrier_read_lineages(
        cfg,
        carrier,
        int(key_lineage["module_call"]),
        dominators,
    )
    read_modes = tuple(
        (mode, item)
        for mode, values in (
            ("win32_api", legacy_read_lineages),
            ("cpp_stream", cpp_stream_read_lineages),
        )
        for item in values
    )
    if len(read_modes) != 1:
        return None
    read_mode, (length_global, buffer_global, read_chain) = read_modes[0]
    xor_lineage = _xor_lineage(
        cfg,
        buffer_global=buffer_global,
        length_global=length_global,
        key_lineage=key_lineage,
        dominators=dominators,
    )
    if xor_lineage is None:
        return None
    injection_chain = _injection_lineage(
        cfg,
        api_calls,
        buffer_global=buffer_global,
        length_global=length_global,
        suspended_process_addresses=targets["suspended_process"],
        write_module_addresses=targets["write_module"],
        write_api_addresses=targets["write_api"],
        after_address=int(xor_lineage["vector_seed"]),
        dominators=dominators,
    )
    if injection_chain is None:
        return None
    local_alloc = injection_chain[1]
    required_xor_paths = [int(xor_lineage["vector_xor"])]
    if len(carrier.data) % 16:
        required_xor_paths.append(int(xor_lineage["scalar_xor"]))
    if not all(
        _cfg_path_exists(cfg, xor_address, local_alloc)
        for xor_address in required_xor_paths
    ):
        return None
    post_read_chain = (
        int(key_lineage["module_call"]),
        int(key_lineage["filename_call"]),
        int(key_lineage["key_subtract"]),
        int(xor_lineage["vector_seed"]),
        local_alloc,
        *injection_chain[2:],
    )
    if read_mode == "cpp_stream":
        if not (
            _dominates_chain(dominators, read_chain[:-1])
            and _cfg_path_exists_without_global_writes(
                cfg,
                read_chain[-2],
                post_read_chain[0],
                frozenset({length_global, buffer_global}),
            )
            and _dominates_chain(dominators, post_read_chain)
        ):
            return None
    elif not _dominates_chain(
        dominators,
        (*read_chain[:-1], *post_read_chain),
    ):
        return None
    reachability = _ReachabilityEvidence(
        completed=True,
        instruction_count=len(cfg.instructions),
        direct_edge_count=len(cfg.edges),
        api_names=frozenset(
            f"entry_function!{name}" for name in sorted(api_calls)
        ),
        target_references=frozenset(
            {
                *(label for label, values in references.items() if values),
                "carrier",
            }
        ),
        referenced_data_addresses=(),
        indirect_call_count=sum(
            instruction.group(CS_GRP_CALL)
            and instruction.operands
            and instruction.operands[0].type == X86_OP_REG
            for instruction in cfg.instructions
        ),
        instructions=cfg.instructions,
    )
    return (
        derived_key,
        reachability,
        {
            "module_path_character_key_derivation": True,
            "kernel32_handle_to_filename_buffer_dataflow": True,
            "nul_scan_length_minus_three_byte_selection": True,
            "ascii_digit_offset_subtraction": True,
            "derived_key_uniquely_recovered": True,
            "derived_key_matches_carrier_transform": True,
            "carrier_literal_to_file_read_buffer_lineage": True,
            "carrier_createfile_getfilesize_readfile_dataflow": (
                read_mode == "win32_api"
            ),
            "carrier_immediate_built_basename_dataflow": (
                read_mode == "cpp_stream"
            ),
            "carrier_cpp_stream_open_size_buffer_read_dataflow": (
                read_mode == "cpp_stream"
            ),
            "carrier_read_lineage_mode": read_mode,
            "same_buffer_and_length_used_for_xor_and_injection": True,
            "bounded_uniform_byte_xor_loop": True,
            "vectorized_xor_loop": True,
            "vector_key_broadcast_and_buffer_xor_dataflow": True,
            "xor_paths_reach_local_allocation": True,
            "same_reachable_function_cfg": True,
            "dominator_ordered_injection_path": True,
            "local_executable_allocation_before_process_creation": True,
            "allocation_return_register_dataflow": True,
            "create_suspended_argument_position_validated": True,
            "suspended_process_creation": True,
            "remote_executable_allocation": True,
            "ntdll_exact_ntwritevirtualmemory_resolution": True,
            "resolved_remote_memory_write": True,
            "thread_context_handoff": True,
            "raw_key_included": False,
            "raw_addresses_included": False,
        },
    )


def _loader_transform_injection_evidence(
    loader: _PeMember,
    carrier: _ArchiveMember,
    targets: Mapping[str, frozenset[int]],
) -> tuple[int, _ReachabilityEvidence, dict[str, Any]] | None:
    """entrypointから到達し、全proofが同一1 functionにある候補だけを受理する。"""

    static_targets = {
        label: addresses for label, addresses in targets.items() if addresses
    }
    global_reachability = _reachable_pe_evidence(loader, static_targets)
    if (
        not global_reachability.completed
        or global_reachability.instruction_count < 256
        or global_reachability.target_references != frozenset(static_targets)
    ):
        return None
    recoveries: list[tuple[int, _ReachabilityEvidence, dict[str, Any]]] = []
    for cfg in _reachable_function_cfgs(loader):
        references = _target_reference_positions(cfg, targets)
        if any(
            not references.get(label)
            for label in targets
            if label != "carrier"
        ):
            continue
        recovery = _function_transform_injection_evidence(
            loader,
            carrier,
            targets,
            cfg,
        )
        if recovery is not None:
            recoveries.append(recovery)
            if len(recoveries) > 1:
                return None
    return recoveries[0] if len(recoveries) == 1 else None


def _function_transform_injection_route_evidence(
    loader: _PeMember,
    carrier: _ArchiveMember,
    targets: Mapping[str, frozenset[int]],
    cfg: _FunctionCfg,
) -> tuple[int, _ReachabilityEvidence, dict[str, Any]] | None:
    """file handoff以外のexact key／XOR／注入chainをroute用に証明する。"""

    if not cfg.completed or len(cfg.instructions) < 256:
        return None
    dominators = _cfg_dominators(cfg)
    if not dominators:
        return None
    references = _target_reference_positions(cfg, targets)
    if any(not references.get(label) for label in targets):
        return None
    carrier_references = references["carrier"]
    if len(carrier_references) != 1:
        return None
    api_calls = _function_api_calls(loader, cfg)
    key_lineages = _module_path_key_lineages(
        loader,
        cfg,
        api_calls,
        targets["key_module"],
        dominators,
    )
    if len(key_lineages) != 1:
        return None
    derived_key, key_lineage = key_lineages[0]
    filename_call = int(key_lineage["filename_call"])
    key_load = int(key_lineage["key_load"])
    global_loads = {
        source
        for instruction in cfg.instructions
        if filename_call < int(instruction.address) < key_load
        and instruction.mnemonic.casefold() == "mov"
        and len(instruction.operands) == 2
        and instruction.operands[0].type == X86_OP_REG
        and (source := _absolute_memory_address(instruction.operands[1]))
        is not None
    }
    if len(global_loads) != 2:
        return None
    candidates: list[
        tuple[int, _ReachabilityEvidence, dict[str, Any]]
    ] = []
    for length_global in sorted(global_loads):
        for buffer_global in sorted(global_loads - {length_global}):
            xor_lineage = _xor_lineage(
                cfg,
                buffer_global=buffer_global,
                length_global=length_global,
                key_lineage=key_lineage,
                dominators=dominators,
            )
            if xor_lineage is None:
                continue
            injection_chain = _injection_lineage(
                cfg,
                api_calls,
                buffer_global=buffer_global,
                length_global=length_global,
                suspended_process_addresses=targets["suspended_process"],
                write_module_addresses=targets["write_module"],
                write_api_addresses=targets["write_api"],
                after_address=int(xor_lineage["vector_seed"]),
                dominators=dominators,
            )
            if injection_chain is None:
                continue
            local_alloc = injection_chain[1]
            required_xor_paths = [int(xor_lineage["vector_xor"])]
            if len(carrier.data) % 16:
                required_xor_paths.append(int(xor_lineage["scalar_xor"]))
            if not all(
                _cfg_path_exists(cfg, xor_address, local_alloc)
                for xor_address in required_xor_paths
            ):
                continue
            chain = (
                carrier_references[0],
                int(key_lineage["module_call"]),
                filename_call,
                int(key_lineage["key_subtract"]),
                int(xor_lineage["vector_seed"]),
                local_alloc,
                *injection_chain[2:],
            )
            if not _dominates_chain(dominators, chain):
                continue
            reachability = _ReachabilityEvidence(
                completed=True,
                instruction_count=len(cfg.instructions),
                direct_edge_count=len(cfg.edges),
                api_names=frozenset(
                    f"entry_function!{name}" for name in sorted(api_calls)
                ),
                target_references=frozenset(
                    label for label, values in references.items() if values
                ),
                referenced_data_addresses=(),
                indirect_call_count=sum(
                    instruction.group(CS_GRP_CALL)
                    and instruction.operands
                    and instruction.operands[0].type == X86_OP_REG
                    for instruction in cfg.instructions
                ),
                instructions=cfg.instructions,
            )
            candidates.append(
                (
                    derived_key,
                    reachability,
                    {
                        "module_path_character_key_derivation": True,
                        "kernel32_handle_to_filename_buffer_dataflow": True,
                        "nul_scan_length_minus_three_byte_selection": True,
                        "ascii_digit_offset_subtraction": True,
                        "derived_key_uniquely_recovered": True,
                        "derived_key_matches_carrier_transform": True,
                        "carrier_literal_referenced_in_loader_function": True,
                        "carrier_literal_to_file_read_buffer_lineage": False,
                        "carrier_createfile_getfilesize_readfile_dataflow": False,
                        "same_buffer_and_length_used_for_xor_and_injection": True,
                        "bounded_uniform_byte_xor_loop": True,
                        "vectorized_xor_loop": True,
                        "vector_key_broadcast_and_buffer_xor_dataflow": True,
                        "xor_paths_reach_local_allocation": True,
                        "same_reachable_function_cfg": True,
                        "dominator_ordered_injection_path": True,
                        "local_executable_allocation_before_process_creation": True,
                        "allocation_return_register_dataflow": True,
                        "create_suspended_argument_position_validated": True,
                        "suspended_process_creation": True,
                        "remote_executable_allocation": True,
                        "ntdll_exact_ntwritevirtualmemory_resolution": True,
                        "resolved_remote_memory_write": True,
                        "thread_context_handoff": True,
                        "missing_proof_codes": [
                            "zip_loader_carrier_file_read_dataflow_unproven"
                        ],
                        "raw_key_included": False,
                        "raw_addresses_included": False,
                    },
                )
            )
    return candidates[0] if len(candidates) == 1 else None


def _loader_transform_injection_route_evidence(
    loader: _PeMember,
    carrier: _ArchiveMember,
    targets: Mapping[str, frozenset[int]],
) -> tuple[int, _ReachabilityEvidence, dict[str, Any]] | None:
    """entrypoint到達範囲にroute証拠を持つfunctionが一つだけなら返す。"""

    global_reachability = _reachable_pe_evidence(loader, targets)
    if (
        not global_reachability.completed
        or global_reachability.instruction_count < 256
        or global_reachability.target_references != frozenset(targets)
    ):
        return None
    recoveries: list[tuple[int, _ReachabilityEvidence, dict[str, Any]]] = []
    for cfg in _reachable_function_cfgs(loader):
        references = _target_reference_positions(cfg, targets)
        if any(not references.get(label) for label in targets):
            continue
        recovery = _function_transform_injection_route_evidence(
            loader,
            carrier,
            targets,
            cfg,
        )
        if recovery is not None:
            recoveries.append(recovery)
            if len(recoveries) > 1:
                return None
    return recoveries[0] if len(recoveries) == 1 else None


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


def _marker_compare_present(
    instructions: Mapping[int, Any], marker: bytes
) -> bool:
    """reachableなbyte比較列が設定markerを直接照合することを確認する。"""

    comparisons: list[tuple[int, int]] = []
    for address in sorted(instructions):
        instruction = instructions[address]
        if instruction.mnemonic.casefold() != "cmp" or len(instruction.operands) != 2:
            continue
        first, second = instruction.operands
        if first.type == X86_OP_MEM and second.type == X86_OP_IMM:
            comparisons.append((address, int(second.imm) & 0xFF))
    for index in range(len(comparisons) - len(marker) + 1):
        window = comparisons[index : index + len(marker)]
        if (
            bytes(value for _address, value in window) == marker
            and window[-1][0] - window[0][0] <= 128
        ):
            return True
    return False


def _terminal_marker(data: bytes) -> tuple[bytes, int] | None:
    """既知markerが全入力中で一意な場合だけmarkerとoffsetを返す。"""

    matches: list[tuple[bytes, int]] = []
    for marker in TERMINAL_MARKERS:
        cursor = 0
        while True:
            offset = data.find(marker, cursor)
            if offset < 0:
                break
            matches.append((marker, offset))
            if len(matches) > 1:
                return None
            cursor = offset + 1
    return matches[0] if len(matches) == 1 else None


def _fs18_to_peb30_present(instructions: Mapping[int, Any]) -> bool:
    """TEBをFS:[18h]から取り、同じregisterの+30hを読むvariantを確認する。"""

    ordered = [instructions[address] for address in sorted(instructions)]
    for index, instruction in enumerate(ordered):
        if (
            instruction.mnemonic.casefold() != "mov"
            or len(instruction.operands) != 2
            or instruction.operands[0].type != X86_OP_REG
            or instruction.operands[1].type != X86_OP_MEM
        ):
            continue
        target = instruction.operands[0].reg
        source = instruction.operands[1].mem
        if source.segment != X86_REG_FS or int(source.disp) != 0x18:
            continue
        for following in ordered[index + 1 : index + 5]:
            if int(following.address) - int(instruction.address) > 24:
                break
            if (
                following.mnemonic.casefold() == "mov"
                and len(following.operands) == 2
                and following.operands[0].type == X86_OP_REG
                and following.operands[0].reg == target
                and following.operands[1].type == X86_OP_MEM
                and following.operands[1].mem.base == target
                and int(following.operands[1].mem.disp) == 0x30
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
    for index in range(len(pushes) - len(expected) + 1):
        window = pushes[index : index + len(expected)]
        if (
            tuple(value for _address, value in window) == expected
            and window[-1][0] - window[0][0] <= 32
        ):
            return True
    return False


def _shellcode_structure_evidence(
    data: bytes, marker: bytes, marker_offset: int
) -> dict[str, Any] | None:
    """vvaS bootstrapのresolver、socket、check-in構造を検証する。"""

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
    fs30_peb_read = any(
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
    common_required = {
        "bounded_cfg_complete": completed,
        "instruction_floor": len(instructions) >= 200,
        "instruction_coverage": coverage >= 0.95,
        "winsock_library_constructed": winsock_fragments,
        "wsa_startup_version": 0x202 in immediates,
        "tcp_socket_arguments": _push_sequence_present(instructions, (6, 1, 2)),
        "vvas_checkin_literal": 0x3233 in immediates,
        "executable_allocation_constants": {0x40, 0x3000}.issubset(immediates),
        "indirect_api_calls": indirect_calls >= 8,
    }
    if marker == CODEMARK:
        required = {
            **common_required,
            "peb_fs30_resolver": fs30_peb_read,
            "codemark_byte_compare": _marker_compare_present(
                instructions, CODEMARK
            ),
        }
        marker_variant = "codemark"
    elif marker == ODAKTOMK:
        required = {
            **common_required,
            "peb_fs18_to_30_resolver": _fs18_to_peb30_present(instructions),
            "odaktomk_byte_compare": _marker_compare_present(
                instructions, ODAKTOMK
            ),
            "api_hash_cluster": _ODAKTOMK_API_HASHES.issubset(immediates),
            "staged_receive_constants": {0x4B00E, 0x9D}.issubset(immediates),
        }
        marker_variant = "odaktomk"
    else:
        return None
    if not all(required.values()):
        return None
    return {
        "architecture": "x86",
        "marker_variant": marker_variant,
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
    original_keys: set[str] = set()
    for match in _VVAS_FIELD.finditer(value[::-1]):
        original_key = match.group(1).casefold()
        if original_key.startswith("v") and original_key != "v3":
            return None
        key = "p3" if original_key == "v3" else original_key
        raw = match.group(2).strip()
        if original_key in original_keys or key in fields:
            return None
        if key == "p3" and ({"p3", "v3"} & original_keys):
            return None
        original_keys.add(original_key)
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
    marker = _terminal_marker(data)
    if marker is None:
        return None
    marker_value, marker_offset = marker
    structure = _shellcode_structure_evidence(data, marker_value, marker_offset)
    if structure is None:
        return None
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


def _single_byte_xor_terminal(
    carrier: _ArchiveMember,
    key: int,
) -> RawVvasShellcodeRecovery | None:
    """loader data-flowから一意に復元したexact keyだけで終端検証する。"""

    if (
        not MINIMUM_SHELLCODE_SIZE <= len(carrier.data) <= MAXIMUM_SHELLCODE_SIZE
        or type(key) is not int
        or not 1 <= key <= 0xFF
    ):
        return None
    decoded = bytes(byte ^ key for byte in carrier.data)
    return recover_raw_vvas_shellcode(decoded)


def _direct_xor_loader_lineage(
    loader: _PeMember,
    carrier: _ArchiveMember,
) -> tuple[_ReachabilityEvidence, dict[str, Any], RawVvasShellcodeRecovery] | None:
    """carrier読出し、uniform XOR、suspended process注入を同一CFGで証明する。"""

    targets = {
        "carrier": _c_string_target_addresses(loader, carrier.basename),
        "key_module": _c_string_target_addresses(loader, "kernel32.dll"),
        "suspended_process": _c_string_target_addresses(loader, "rundll32.exe"),
        "write_module": _c_string_target_addresses(loader, "ntdll.dll"),
        "write_api": _c_string_target_addresses(loader, "NtWriteVirtualMemory"),
    }
    if any(
        not value for label, value in targets.items() if label != "carrier"
    ):
        return None
    transform = _loader_transform_injection_evidence(loader, carrier, targets)
    if transform is None:
        return None
    key, evidence, public_transform = transform
    terminal = _single_byte_xor_terminal(carrier, key)
    if terminal is None:
        return None
    return evidence, public_transform, terminal


def _direct_xor_loader_route_lineage(
    loader: _PeMember,
    carrier: _ArchiveMember,
) -> tuple[_ReachabilityEvidence, dict[str, Any], RawVvasShellcodeRecovery] | None:
    """carrier file handoff未証明のままexact変換・注入・終端候補を返す。"""

    targets = {
        "carrier": _c_string_target_addresses(loader, carrier.basename),
        "key_module": _c_string_target_addresses(loader, "kernel32.dll"),
        "suspended_process": _c_string_target_addresses(loader, "rundll32.exe"),
        "write_module": _c_string_target_addresses(loader, "ntdll.dll"),
        "write_api": _c_string_target_addresses(loader, "NtWriteVirtualMemory"),
    }
    if any(not value for value in targets.values()):
        return None
    transform = _loader_transform_injection_route_evidence(
        loader,
        carrier,
        targets,
    )
    if transform is None:
        return None
    key, evidence, public_transform = transform
    terminal = _single_byte_xor_terminal(carrier, key)
    if terminal is None:
        return None
    return evidence, public_transform, terminal


def _recover_zip_proxy_carve_shellcode(
    members: tuple[_ArchiveMember, ...],
    pe_members: tuple[_PeMember, ...],
    source_size: int,
) -> ZipSideloadShellcodeRecovery | None:
    """従来のproxy→launcher→delimiter carve lineageを復元する。"""

    if not 3 <= len(pe_members) <= MAXIMUM_PE_MEMBERS:
        return None
    by_parent: dict[str, list[_PeMember]] = {}
    for item in pe_members:
        if item.member.parent not in by_parent:
            by_parent[item.member.parent] = []
        by_parent[item.member.parent].append(item)
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
                            source_size=source_size,
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


def _recover_zip_direct_xor_shellcode(
    members: tuple[_ArchiveMember, ...],
    pe_members: tuple[_PeMember, ...],
    source_size: int,
) -> ZipDirectXorShellcodeRecovery | None:
    """host→DLL loader→uniform-XOR carrier→終端設定を一意に復元する。"""

    if not 2 <= len(pe_members) <= MAXIMUM_PE_MEMBERS:
        return None
    by_parent: dict[str, list[_PeMember]] = {}
    for item in pe_members:
        if item.member.parent not in by_parent:
            by_parent[item.member.parent] = []
        by_parent[item.member.parent].append(item)
    recoveries: dict[tuple[str, str, str, str], ZipDirectXorShellcodeRecovery] = {}
    for parent, group in by_parent.items():
        executables = tuple(item for item in group if not item.is_dll)
        libraries = tuple(item for item in group if item.is_dll)
        carriers = tuple(
            item
            for item in members
            if item.parent == parent
            and not item.data.startswith(b"MZ")
            and MINIMUM_CARRIER_SIZE <= len(item.data) <= MAXIMUM_SHELLCODE_SIZE
        )
        if not executables or not libraries or not carriers:
            continue
        for host in executables:
            for loader in libraries:
                if host.machine != loader.machine:
                    continue
                binding_count = _imports_satisfied(host, loader)
                if binding_count < 3:
                    continue
                for carrier in carriers:
                    lineage = _direct_xor_loader_lineage(loader, carrier)
                    if lineage is None:
                        continue
                    reachability, xor_evidence, terminal = lineage
                    key = (
                        host.member.path.casefold(),
                        loader.member.path.casefold(),
                        carrier.path.casefold(),
                        hashlib.sha256(terminal.data).hexdigest(),
                    )
                    recoveries[key] = ZipDirectXorShellcodeRecovery(
                        source_size=source_size,
                        member_count=len(members),
                        pe_member_count=len(pe_members),
                        import_binding_count=binding_count,
                        loader_reachability=reachability,
                        xor_evidence=xor_evidence,
                        shellcode=terminal,
                        component_sha256=(
                            ("host", hashlib.sha256(host.member.data).hexdigest()),
                            ("loader", hashlib.sha256(loader.member.data).hexdigest()),
                            ("carrier", hashlib.sha256(carrier.data).hexdigest()),
                        ),
                    )
    return next(iter(recoveries.values())) if len(recoveries) == 1 else None


def _recover_zip_direct_xor_route(
    members: tuple[_ArchiveMember, ...],
    pe_members: tuple[_PeMember, ...],
    source_size: int,
) -> ZipDirectXorRouteRecovery | None:
    """完全file-read lineageを欠くdirect-XOR bundleをroute候補へ限定する。"""

    if not 2 <= len(pe_members) <= MAXIMUM_PE_MEMBERS:
        return None
    by_parent: dict[str, list[_PeMember]] = {}
    for item in pe_members:
        if item.member.parent not in by_parent:
            by_parent[item.member.parent] = []
        by_parent[item.member.parent].append(item)
    recoveries: dict[tuple[str, str, str, str], ZipDirectXorRouteRecovery] = {}
    for parent, group in by_parent.items():
        executables = tuple(item for item in group if not item.is_dll)
        libraries = tuple(item for item in group if item.is_dll)
        carriers = tuple(
            item
            for item in members
            if item.parent == parent
            and not item.data.startswith(b"MZ")
            and MINIMUM_CARRIER_SIZE <= len(item.data) <= MAXIMUM_SHELLCODE_SIZE
        )
        if not executables or not libraries or not carriers:
            continue
        for host in executables:
            for loader in libraries:
                if host.machine != loader.machine:
                    continue
                binding_count = _imports_satisfied(host, loader)
                if binding_count < 3:
                    continue
                for carrier in carriers:
                    lineage = _direct_xor_loader_route_lineage(loader, carrier)
                    if lineage is None:
                        continue
                    reachability, xor_evidence, terminal = lineage
                    key = (
                        host.member.path.casefold(),
                        loader.member.path.casefold(),
                        carrier.path.casefold(),
                        hashlib.sha256(terminal.data).hexdigest(),
                    )
                    recoveries[key] = ZipDirectXorRouteRecovery(
                        source_size=source_size,
                        member_count=len(members),
                        pe_member_count=len(pe_members),
                        import_binding_count=binding_count,
                        loader_reachability=reachability,
                        xor_evidence=xor_evidence,
                        shellcode=terminal,
                    )
    return next(iter(recoveries.values())) if len(recoveries) == 1 else None


def recover_verified_sibling_shellcode(
    *,
    parent_data: bytes,
    expected_parent_sha256: str,
    members: tuple[VerifiedSiblingMember, ...],
    declared_member_count: int,
    declared_total_size: int,
    collection_complete: bool,
) -> VerifiedSiblingShellcodeRecovery | None:
    """検証済み同居member集合からstrict direct-XOR lineageだけを復元する。

    この入口はarchive parserを迂回するため、callerが全member identityを結合した
    完全集合であることを明示し、ここでも親・子SHA-256、件数、size、pathを再検証
    する。file名やprovider labelは帰属条件に使わない。
    """

    if (
        collection_complete is not True
        or not isinstance(parent_data, bytes)
        or not 22 <= len(parent_data) <= MAXIMUM_VERIFIED_PARENT_SIZE
        or not isinstance(expected_parent_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_parent_sha256) is None
        or hashlib.sha256(parent_data).hexdigest() != expected_parent_sha256
        or isinstance(declared_member_count, bool)
        or not isinstance(declared_member_count, int)
        or declared_member_count != len(members)
        or not 2 <= declared_member_count <= MAXIMUM_MEMBER_COUNT
        or isinstance(declared_total_size, bool)
        or not isinstance(declared_total_size, int)
        or not 0 <= declared_total_size <= MAXIMUM_TOTAL_MEMBER_SIZE
    ):
        return None
    prepared: list[_ArchiveMember] = []
    seen_paths: set[str] = set()
    total_size = 0
    member_hashes: set[str] = set()
    for member in members:
        if not isinstance(member, VerifiedSiblingMember):
            return None
        try:
            path, parent, basename = _normalized_member_path(member.path)
        except ZipSideloadShellcodeError:
            return None
        collision_key = path.casefold()
        if collision_key in seen_paths:
            return None
        seen_paths.add(collision_key)
        if (
            not isinstance(member.data, bytes)
            or isinstance(member.size, bool)
            or not isinstance(member.size, int)
            or member.size != len(member.data)
            or not 0 <= member.size <= MAXIMUM_MEMBER_SIZE
            or not isinstance(member.sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", member.sha256) is None
            or hashlib.sha256(member.data).hexdigest() != member.sha256
        ):
            return None
        total_size += member.size
        if total_size > MAXIMUM_TOTAL_MEMBER_SIZE:
            return None
        member_hashes.add(member.sha256)
        prepared.append(_ArchiveMember(path, parent, basename, member.data))
    if total_size != declared_total_size:
        return None
    try:
        _validate_member_namespace(
            tuple((member.path, False) for member in prepared)
        )
    except ZipSideloadShellcodeError:
        return None
    archive_members = tuple(prepared)
    pe_members = tuple(
        filter(None, (_parse_pe_member(member) for member in archive_members))
    )
    if not 2 <= len(pe_members) <= MAXIMUM_PE_MEMBERS:
        return None
    recovery = _recover_zip_direct_xor_shellcode(
        archive_members,
        pe_members,
        len(parent_data),
    )
    if recovery is None:
        return None
    roles = dict(recovery.component_sha256)
    if set(roles) != {"host", "loader", "carrier"}:
        return None
    role_hashes = {roles["host"], roles["loader"], roles["carrier"]}
    if len(role_hashes) != 3 or not role_hashes.issubset(member_hashes):
        return None
    return VerifiedSiblingShellcodeRecovery(
        parent_sha256=expected_parent_sha256,
        host_sha256=roles["host"],
        loader_sha256=roles["loader"],
        carrier_sha256=roles["carrier"],
        terminal_sha256=hashlib.sha256(recovery.shellcode.data).hexdigest(),
        recovery=recovery,
    )


def recover_zip_sideload_shellcode(data: bytes) -> ZipTerminalRecovery | None:
    """ZIPから既知の厳格lineageを一意に満たす終端vvaS設定を復元する。"""

    try:
        members = _read_archive_members(data)
    except ZipSideloadShellcodeError:
        return None
    pe_members = tuple(filter(None, (_parse_pe_member(member) for member in members)))
    if not 2 <= len(pe_members) <= MAXIMUM_PE_MEMBERS:
        return None
    candidates = tuple(
        item
        for item in (
            _recover_zip_proxy_carve_shellcode(members, pe_members, len(data)),
            _recover_zip_direct_xor_shellcode(members, pe_members, len(data)),
        )
        if item is not None
    )
    return candidates[0] if len(candidates) == 1 else None


def recover_zip_sideload_shellcode_route(
    data: bytes,
) -> ZipDirectXorRouteRecovery | None:
    """family確定に不足するdirect-XOR bundleを未確認routeとして復元する。"""

    try:
        members = _read_archive_members(data)
    except ZipSideloadShellcodeError:
        return None
    pe_members = tuple(filter(None, (_parse_pe_member(member) for member in members)))
    if not 2 <= len(pe_members) <= MAXIMUM_PE_MEMBERS:
        return None
    if _recover_zip_direct_xor_shellcode(members, pe_members, len(data)) is not None:
        return None
    return _recover_zip_direct_xor_route(members, pe_members, len(data))


def public_raw_shellcode_summary(recovery: RawVvasShellcodeRecovery) -> dict[str, Any]:
    """raw configやendpoint本文を含まないshellcode構造要約を返す。"""

    marker_variant = recovery.shellcode_evidence.get("marker_variant")
    status = (
        "validated_vvas_odaktomk_transport_shellcode"
        if marker_variant == "odaktomk"
        else "validated_vvas_codemark_transport_shellcode"
    )
    return {
        "schema_version": 1,
        "status": status,
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


def public_recovery_summary(
    recovery: ZipTerminalRecovery | ZipDirectXorRouteRecovery,
) -> dict[str, Any]:
    """個別file名、raw payload、endpoint本文を除いたlineage要約を返す。"""

    if isinstance(recovery, ZipDirectXorRouteRecovery):
        return {
            "schema_version": 1,
            "status": "validated_zip_sideload_uniform_xor_command_c2_candidate",
            "lineage_profile": "sideload_loader_uniform_xor_route_candidate",
            "source_size": recovery.source_size,
            "member_count": recovery.member_count,
            "pe_member_count": recovery.pe_member_count,
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "used_for_family_resolution": False,
            "used_for_c2_confirmation": False,
            "lineage": {
                "sibling_import_export_edge": {
                    "same_directory": True,
                    "bound_symbol_count": recovery.import_binding_count,
                    "host_imports_loader": True,
                },
                "loader_to_carrier_candidate": {
                    "entrypoint_cfg_complete": recovery.loader_reachability.completed,
                    "reachable_instruction_count": recovery.loader_reachability.instruction_count,
                    "reachable_carrier_reference": True,
                    "carrier_file_read_handoff_confirmed": False,
                    **dict(recovery.xor_evidence),
                },
                "decoded_terminal_candidate": public_raw_shellcode_summary(
                    recovery.shellcode
                ),
            },
            "endpoint_role": "command_c2_candidate",
            "command_c2_confirmed": False,
            "final_rat_confirmed": False,
            "c2_liveness_confirmed": False,
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
    if isinstance(recovery, ZipDirectXorShellcodeRecovery):
        return {
            "schema_version": 1,
            "status": "validated_zip_sideload_uniform_xor_vvas_terminal",
            "lineage_profile": "sideload_loader_uniform_xor_suspended_process_injection",
            "source_size": recovery.source_size,
            "member_count": recovery.member_count,
            "pe_member_count": recovery.pe_member_count,
            "lineage": {
                "sibling_import_export_edge": {
                    "same_directory": True,
                    "bound_symbol_count": recovery.import_binding_count,
                    "host_imports_loader": True,
                },
                "loader_to_carrier": {
                    "entrypoint_cfg_complete": recovery.loader_reachability.completed,
                    "reachable_instruction_count": recovery.loader_reachability.instruction_count,
                    "reachable_carrier_reference": True,
                    "reachable_file_source_group": True,
                    **dict(recovery.xor_evidence),
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
    return {
        "schema_version": 1,
        "status": "validated_zip_sideload_carve_vvas_terminal",
        "lineage_profile": "proxy_launcher_delimiter_carve",
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
    """完全lineage、または非昇格のcommand C2 route候補を返す。"""

    recovery = recover_zip_sideload_shellcode(data)
    if recovery is None:
        route = recover_zip_sideload_shellcode_route(data)
        if route is None:
            return {
                "matched": False,
                "supports_family_attribution": False,
                "static_config_recovered": False,
                "evidence": {},
                "config": {},
                "sample_executed": False,
                "network_contacted": False,
            }
        endpoints = list(route.shellcode.endpoints)
        return {
            "matched": True,
            "family": None,
            "variant": "zip_sideload_uniform_xor_vvas_command_c2_candidate",
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "attribution_scope": "component_handler_route",
            "static_config_recovered": False,
            "candidate_config_recovered": True,
            "used_for_family_resolution": False,
            "used_for_c2_confirmation": False,
            "command_c2_confirmed": False,
            "final_rat_confirmed": False,
            "c2_liveness_confirmed": False,
            "evidence": {
                "status": "validated_zip_sideload_command_c2_route_candidate",
                "lineage_profile": "sideload_loader_uniform_xor_route_candidate",
                "source_transform_sink_lineage": False,
                "sibling_import_export_edge": True,
                "loader_exact_key_uniform_xor_injection_path": True,
                "carrier_file_read_handoff_confirmed": False,
                "vvas_transport_shellcode_candidate": True,
                "missing_proof_codes": [
                    "zip_loader_carrier_file_read_dataflow_unproven"
                ],
                "configuration_identity_included": False,
                "component_hashes_included": False,
                "member_names_included": False,
                "raw_payload_included": False,
                "raw_config_included": False,
                "raw_network_values_included": False,
            },
            "config": {
                "endpoint_count": len(endpoints),
                "endpoint_role": "command_c2_candidate",
                "raw_config_included": False,
                "raw_network_values_included": False,
            },
            "endpoints": endpoints,
            "c2_candidates": [
                {
                    "endpoint": endpoint,
                    "role": "command_c2_candidate",
                    "contacted": False,
                    "liveness_confirmed": False,
                    "qualified": False,
                }
                for endpoint in endpoints
            ],
            "sample_executed": False,
            "network_contacted": False,
        }
    direct_xor = isinstance(recovery, ZipDirectXorShellcodeRecovery)
    lineage_profile = (
        "sideload_loader_uniform_xor_suspended_process_injection"
        if direct_xor
        else "proxy_launcher_delimiter_carve"
    )
    lineage_evidence = (
        {
            "host_to_loader_import_export_edge": True,
            "loader_file_uniform_xor_injection_path": True,
        }
        if direct_xor
        else {
            "proxy_entrypoint_to_launcher": True,
            "launcher_file_carve_execution_path": True,
        }
    )
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "zip_sideload_shellcode_vvas_terminal",
        "supports_family_attribution": True,
        "terminal_family_confirmed": True,
        "attribution_scope": "validated_terminal_component_structure",
        "static_config_recovered": True,
        "evidence": {
            "lineage_profile": lineage_profile,
            "source_transform_sink_lineage": True,
            "sibling_import_export_edge": True,
            **lineage_evidence,
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
    marker_variant = recovery.shellcode_evidence.get("marker_variant")
    return {
        "matched": True,
        "family": None,
        "variant": f"raw_vvas_{marker_variant}_transport_candidate",
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
    "ZipDirectXorRouteRecovery",
    "ZipSideloadShellcodeError",
    "ZipSideloadShellcodeRecovery",
    "probe_raw_vvas_shellcode",
    "probe_zip_sideload_shellcode",
    "public_raw_shellcode_summary",
    "public_recovery_summary",
    "recover_raw_vvas_shellcode",
    "recover_zip_sideload_shellcode",
    "recover_zip_sideload_shellcode_route",
]
