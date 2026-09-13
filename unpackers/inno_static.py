"""Inno Setup一覧とinstall scriptから安全な静的復元計画を作る。"""

from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath

from unpackers.path_safety import safe_member_name

MAX_INNO_MEMBER_NAME_BYTES = 4096
MAX_INNO_INVENTORY_MEMBERS = 10_000
MAX_INNO_COMMAND_CHARACTERS = 16_000
MAX_INNO_SPLIT_ARCHIVE_SEGMENTS = 16
MAX_INNO_CANDIDATE_INPUT_BYTES = 256 * 1024 * 1024
MAX_INNO_SIGNAL_VALUES = 64
MAX_INNO_SIGNAL_CHARACTERS = 4096
MAX_INNO_PE_SECTIONS = 96
MAX_INNO_PE_HEADER_OFFSET = 4 * 1024 * 1024
MAX_INNO_RESOURCE_DIRECTORY_BYTES = 16 * 1024 * 1024
MAX_INNO_RESOURCE_TABLE_ENTRIES = 512
MAX_INNO_LOADER_RESOURCE_BYTES = 4096
MIN_INNOUNP_VERSION = (2, 71, 0)

_TOOL_VERSION = re.compile(
    r"\binnounp\b.*?\bversion\s+(\d+)\.(\d+)(?:\.(\d+))?\b",
    re.IGNORECASE,
)
_SETUP_VERSION = re.compile(
    r"^Inno Setup version detected:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE
)
_MEMBER_ROW = re.compile(r"^\s*(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(.+?)\s*$")
_LISTING_HEADER = re.compile(
    r"^\s*Size\s+Date/Time\s+Filename\s*$",
    re.IGNORECASE,
)
_LISTING_SEPARATOR = re.compile(r"^\s*-{8,}\s*$")
_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_FILENAME = re.compile(
    r"^\s*Filename\s*:\s*(?:\"([^\"]+)\"|([^;]+?))\s*(?:;|$)",
    re.IGNORECASE,
)
_ENCRYPTION = re.compile(r"^\s*;?\s*Encryption\s*=\s*(yes|true|1)\s*$", re.IGNORECASE)
_SCRIPT_TOOL_HEADER = re.compile(
    r'^\s*;\s*Created by "innounp" version\s+\d+\.\d+(?:\.\d+)?\s*$',
    re.IGNORECASE | re.MULTILINE,
)
_SCRIPT_SETUP_HEADER = re.compile(
    r"^\s*;\s*Inno Setup Version:\s*.+$", re.IGNORECASE | re.MULTILINE
)
_ZIP_EOCD = struct.Struct("<4sHHHHIIH")
_ZIP_LOCAL = struct.Struct("<4sHHHHHIIIHH")
_INNO_SETUP_DATA_PREFIX = b"Inno Setup Setup Data ("
_INNO_LOADER_VERSIONS = {
    b"rDlPtS02\x87eVx": (1, 2, 10),
    b"rDlPtS04\x87eVx": (4, 0, 0),
    b"rDlPtS05\x87eVx": (4, 0, 3),
    b"rDlPtS06\x87eVx": (4, 0, 10),
    b"rDlPtS07\x87eVx": (4, 1, 6),
    b"rDlPtS\xcd\xe6\xd7{\x0b*": (5, 1, 5),
    b"nS5W7dT\x83\xaa\x1b\x0fj": (5, 1, 5),
}

_EXECUTABLE_SUFFIXES = {
    ".com",
    ".dll",
    ".exe",
    ".ocx",
    ".pyd",
    ".scr",
    ".sys",
}
_SIDELOAD_SUFFIXES = {".dll", ".ocx", ".pyd"}
_PAYLOAD_SUFFIXES = _EXECUTABLE_SUFFIXES | {
    ".7z",
    ".a3x",
    ".asar",
    ".bat",
    ".bin",
    ".cab",
    ".cfg",
    ".cmd",
    ".conf",
    ".dat",
    ".hta",
    ".ini",
    ".jar",
    ".js",
    ".jse",
    ".json",
    ".log",
    ".pak",
    ".ps1",
    ".py",
    ".pyc",
    ".rar",
    ".sh",
    ".vbe",
    ".vbs",
    ".xml",
    ".zip",
}
_DEPENDENCY_DIRECTORIES = {
    "locales",
    "node_modules",
    "resources",
    "swiftshader",
}


@dataclass(frozen=True)
class InnoMember:
    """innounp一覧で検証済みの単一member。"""

    archive_name: str
    normalized_name: str
    size: int

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.normalized_name.lower()).suffix


@dataclass(frozen=True)
class InnoListing:
    """完全性を明示したInno inventory。"""

    status: str
    tool_version: str | None
    setup_version: str | None
    members: tuple[InnoMember, ...]
    invalid_member_count: int
    duplicate_member_count: int
    complete: bool


@dataclass(frozen=True)
class InnoScriptFacts:
    """復元済みinstall scriptから得た非機密の選択根拠。"""

    encrypted: bool
    decompiler_provenance: bool
    launch_targets: tuple[str, ...]
    dynamic_launch_target_count: int
    invalid_launch_target_count: int


@dataclass(frozen=True)
class InnoSelection:
    """抽出前に確定した有界member集合。"""

    members: tuple[InnoMember, ...]
    declared_size: int
    complete_archive: bool
    omitted_member_count: int
    limit_reasons: tuple[str, ...]
    launch_target_match_count: int


@dataclass(frozen=True)
class InnoSegmentedZip:
    """listing順の連続memberから厳格に再構築したZIP。"""

    status: str
    blob: bytes | None
    source_members: tuple[str, ...]
    archive_member_count: int
    declared_uncompressed_size: int
    crc_verified: bool
    reason: str | None = None


@dataclass(frozen=True)
class InnoCandidateAssessment:
    """外部の形式labelと入力内構造を分離したInno候補判定。"""

    status: str
    candidate: bool
    source_signals: tuple[str, ...]
    pe_structure_valid: bool
    loader_location: str | None
    loader_revision: int | None
    loader_crc_verified: bool
    setup_header_boundary_verified: bool
    reason: str | None = None


@dataclass(frozen=True)
class _PeSection:
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int


class _InnoStructureError(ValueError):
    """公開reportへraw parser例外を出さない内部検証失敗。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _bounded_source_signals(
    archive_types: object,
    packer_markers: object,
) -> tuple[tuple[str, ...], str | None]:
    labels: list[str] = []
    total_characters = 0
    for values, label, predicate in (
        (
            archive_types,
            "sevenzip_inno_archive_type",
            lambda value: "inno" in value.casefold(),
        ),
        (
            packer_markers,
            "inno_setup_pe_marker",
            lambda value: value.casefold() == "inno setup",
        ),
    ):
        if not isinstance(values, (list, tuple)):
            return (), "signal_collection_invalid"
        if len(values) > MAX_INNO_SIGNAL_VALUES:
            return (), "signal_count_limit"
        matched = False
        for value in values:
            if not isinstance(value, str):
                return (), "signal_value_invalid"
            total_characters += len(value)
            if total_characters > MAX_INNO_SIGNAL_CHARACTERS:
                return (), "signal_character_limit"
            matched = matched or predicate(value.strip())
        if matched:
            labels.append(label)
    return tuple(labels), None


def _rva_to_file_offset(
    data: bytes,
    sections: tuple[_PeSection, ...],
    rva: int,
    size: int,
) -> int:
    if size <= 0:
        raise _InnoStructureError("pe_rva_size_invalid")
    matches: list[int] = []
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if span == 0 or rva < section.virtual_address:
            continue
        delta = rva - section.virtual_address
        if delta >= span or delta > section.raw_size or size > section.raw_size - delta:
            continue
        offset = section.raw_address + delta
        if offset <= len(data) and size <= len(data) - offset:
            matches.append(offset)
    if len(matches) != 1:
        raise _InnoStructureError("pe_rva_mapping_ambiguous_or_invalid")
    return matches[0]


def _pe_layout(data: bytes) -> tuple[tuple[_PeSection, ...], int | None, int]:
    """必要最小限のPE headerとresource directory境界だけを検証する。"""

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise _InnoStructureError("not_pe")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if (
        pe_offset < 0x40
        or pe_offset > MAX_INNO_PE_HEADER_OFFSET
        or pe_offset + 24 > len(data)
        or data[pe_offset : pe_offset + 4] != b"PE\0\0"
    ):
        raise _InnoStructureError("pe_header_invalid")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    if not 0 < section_count <= MAX_INNO_PE_SECTIONS:
        raise _InnoStructureError("pe_section_count_limit")
    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    section_table_end = optional_end + section_count * 40
    if optional_end > len(data) or section_table_end > len(data):
        raise _InnoStructureError("pe_header_truncated")
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    if optional_magic == 0x10B:
        directory_count_offset = 92
        directory_offset = 96
    elif optional_magic == 0x20B:
        directory_count_offset = 108
        directory_offset = 112
    else:
        raise _InnoStructureError("pe_optional_header_invalid")
    if optional_size < directory_count_offset + 4:
        raise _InnoStructureError("pe_optional_header_truncated")
    directory_count = struct.unpack_from(
        "<I", data, optional_offset + directory_count_offset
    )[0]
    resource_rva = 0
    resource_size = 0
    if directory_count >= 3:
        if optional_size < directory_offset + 3 * 8:
            raise _InnoStructureError("pe_resource_directory_truncated")
        resource_entry = optional_offset + directory_offset + 2 * 8
        resource_rva, resource_size = struct.unpack_from("<II", data, resource_entry)
        if bool(resource_rva) != bool(resource_size):
            raise _InnoStructureError("pe_resource_directory_partial")
        if resource_size > MAX_INNO_RESOURCE_DIRECTORY_BYTES:
            raise _InnoStructureError("pe_resource_directory_too_large")

    sections: list[_PeSection] = []
    for index in range(section_count):
        offset = optional_end + index * 40
        virtual_size, virtual_address, raw_size, raw_address = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        if raw_size and (
            raw_address >= len(data) or raw_size > len(data) - raw_address
        ):
            raise _InnoStructureError("pe_section_raw_extent_invalid")
        sections.append(
            _PeSection(virtual_address, virtual_size, raw_address, raw_size)
        )
    resource_offset = (
        _rva_to_file_offset(
            data,
            tuple(sections),
            resource_rva,
            resource_size,
        )
        if resource_rva
        else None
    )
    return tuple(sections), resource_offset, resource_size


def _resource_entry(
    data: bytes,
    *,
    root_offset: int,
    root_size: int,
    table_relative_offset: int,
    resource_id: int | None,
) -> int | None:
    if (
        table_relative_offset < 0
        or table_relative_offset > root_size
        or 16 > root_size - table_relative_offset
    ):
        raise _InnoStructureError("resource_table_out_of_bounds")
    table_offset = root_offset + table_relative_offset
    named_count, id_count = struct.unpack_from("<HH", data, table_offset + 12)
    entry_count = named_count + id_count
    if entry_count > MAX_INNO_RESOURCE_TABLE_ENTRIES:
        raise _InnoStructureError("resource_entry_count_limit")
    entries_relative_end = table_relative_offset + 16 + entry_count * 8
    if entries_relative_end > root_size:
        raise _InnoStructureError("resource_entries_out_of_bounds")
    first_id_index = named_count
    if resource_id is None and id_count == 0:
        return None
    for index in range(first_id_index, entry_count):
        name, child = struct.unpack_from("<II", data, table_offset + 16 + index * 8)
        if name & 0x80000000:
            raise _InnoStructureError("resource_id_entry_is_named")
        if resource_id is None or name == resource_id:
            return child
    return None


def _inno_loader_resource(
    data: bytes,
    sections: tuple[_PeSection, ...],
    root_offset: int,
    root_size: int,
) -> tuple[int, int] | None:
    type_entry = _resource_entry(
        data,
        root_offset=root_offset,
        root_size=root_size,
        table_relative_offset=0,
        resource_id=10,
    )
    if type_entry is None:
        return None
    if not type_entry & 0x80000000:
        raise _InnoStructureError("rcdata_type_is_not_directory")
    name_entry = _resource_entry(
        data,
        root_offset=root_offset,
        root_size=root_size,
        table_relative_offset=type_entry & 0x7FFFFFFF,
        resource_id=11111,
    )
    if name_entry is None:
        return None
    if not name_entry & 0x80000000:
        raise _InnoStructureError("inno_resource_name_is_not_directory")
    language_entry = _resource_entry(
        data,
        root_offset=root_offset,
        root_size=root_size,
        table_relative_offset=name_entry & 0x7FFFFFFF,
        resource_id=None,
    )
    if language_entry is None or language_entry & 0x80000000:
        raise _InnoStructureError("inno_resource_language_leaf_invalid")
    leaf_relative = language_entry & 0x7FFFFFFF
    if leaf_relative > root_size or 16 > root_size - leaf_relative:
        raise _InnoStructureError("inno_resource_leaf_out_of_bounds")
    data_rva, data_size = struct.unpack_from("<II", data, root_offset + leaf_relative)
    if not 40 <= data_size <= MAX_INNO_LOADER_RESOURCE_BYTES:
        raise _InnoStructureError("inno_loader_resource_size_invalid")
    return _rva_to_file_offset(data, sections, data_rva, data_size), data_size


def _legacy_loader_offset(data: bytes) -> int | None:
    if len(data) < 0x3C or data[0x30:0x34] != b"Inno":
        return None
    offset, complement = struct.unpack_from("<II", data, 0x34)
    if offset != (~complement & 0xFFFFFFFF) or offset >= len(data):
        raise _InnoStructureError("legacy_loader_pointer_invalid")
    return offset


def _validate_setup_identifier(data: bytes, offset: int) -> bool:
    if offset >= len(data):
        return False
    probe = data[offset : min(len(data), offset + 64)]
    if not probe.startswith(_INNO_SETUP_DATA_PREFIX):
        return False
    terminator = probe.find(b"\0")
    identifier = probe if terminator < 0 else probe[:terminator]
    if not identifier.endswith(b")") or len(identifier) <= len(_INNO_SETUP_DATA_PREFIX):
        return False
    return all(0x20 <= value <= 0x7E for value in identifier)


def _validate_loader_table(
    data: bytes,
    offset: int,
    *,
    resource_size: int | None,
) -> tuple[int, bool] | None:
    if offset < 0 or offset + 12 > len(data):
        return None
    magic = data[offset : offset + 12]
    version = _INNO_LOADER_VERSIONS.get(magic)
    if version is None:
        return None
    cursor = offset + 12
    revision = 0
    if version >= (5, 1, 5):
        if cursor + 4 > len(data):
            return None
        revision = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        if revision not in {1, 2}:
            return None
    integer_size = 8 if revision == 2 else 4
    effective_version = (6, 5, 0) if revision == 2 else version

    def read_integer(size: int) -> int:
        nonlocal cursor
        if cursor > len(data) or size > len(data) - cursor:
            raise _InnoStructureError("loader_table_truncated")
        fmt = "<Q" if size == 8 else "<I"
        value = struct.unpack_from(fmt, data, cursor)[0]
        cursor += size
        return value

    try:
        total_size = read_integer(integer_size)
        executable_offset = read_integer(integer_size)
        if effective_version < (4, 1, 6):
            read_integer(4)
        executable_uncompressed_size = read_integer(4)
        read_integer(4)
        if effective_version < (4, 0, 0):
            read_integer(4)
        information_offset = read_integer(integer_size)
        data_offset = read_integer(integer_size)
        if revision == 2:
            read_integer(4)
    except _InnoStructureError:
        return None
    crc_verified = False
    if effective_version >= (4, 0, 10):
        if cursor + 4 > len(data):
            return None
        expected_crc = struct.unpack_from("<I", data, cursor)[0]
        if zlib.crc32(data[offset:cursor]) & 0xFFFFFFFF != expected_crc:
            return None
        crc_verified = True
        cursor += 4
    table_size = cursor - offset
    if resource_size is not None and resource_size != table_size:
        return None
    if (
        total_size == 0
        or total_size > len(data)
        or executable_uncompressed_size < 0x100
        or executable_offset == 0
        or executable_offset >= len(data)
        or information_offset == 0
        or information_offset >= len(data)
        or data_offset >= information_offset
        or total_size < max(executable_offset, information_offset, data_offset)
        or not _validate_setup_identifier(data, information_offset)
    ):
        return None
    return revision, crc_verified


def assess_inno_candidate(
    data: bytes,
    *,
    archive_types: object = (),
    packer_markers: object = (),
    max_input_size: int = MAX_INNO_CANDIDATE_INPUT_BYTES,
) -> InnoCandidateAssessment:
    """外部labelをInno loader構造・CRC・offset境界で再検証する。"""

    if (
        isinstance(max_input_size, bool)
        or not isinstance(max_input_size, int)
        or max_input_size <= 0
    ):
        raise ValueError("max_input_sizeは正の整数である必要があります")
    signals, signal_error = _bounded_source_signals(archive_types, packer_markers)
    if signal_error is not None:
        return InnoCandidateAssessment(
            "signal_limit_or_shape_blocked",
            False,
            (),
            False,
            None,
            None,
            False,
            False,
            signal_error,
        )
    if not signals:
        return InnoCandidateAssessment(
            "not_signaled", False, (), False, None, None, False, False
        )
    if not isinstance(data, bytes):
        return InnoCandidateAssessment(
            "input_shape_blocked",
            False,
            signals,
            False,
            None,
            None,
            False,
            False,
            "input_not_bytes",
        )
    if len(data) > max_input_size:
        return InnoCandidateAssessment(
            "input_size_blocked",
            False,
            signals,
            False,
            None,
            None,
            False,
            False,
            "input_size_limit",
        )
    try:
        sections, resource_root, resource_size = _pe_layout(data)
    except (struct.error, _InnoStructureError) as exc:
        reason = exc.reason if isinstance(exc, _InnoStructureError) else "pe_truncated"
        return InnoCandidateAssessment(
            "signal_without_validated_structure",
            False,
            signals,
            False,
            None,
            None,
            False,
            False,
            reason,
        )

    try:
        resource = (
            _inno_loader_resource(data, sections, resource_root, resource_size)
            if resource_root is not None
            else None
        )
        location = "pe_rcdata_11111"
        if resource is None:
            loader_offset = _legacy_loader_offset(data)
            loader_size = None
            location = "legacy_fixed_pointer"
        else:
            loader_offset, loader_size = resource
    except (struct.error, _InnoStructureError) as exc:
        reason = (
            exc.reason if isinstance(exc, _InnoStructureError) else "resource_truncated"
        )
        return InnoCandidateAssessment(
            "signal_without_validated_structure",
            False,
            signals,
            True,
            None,
            None,
            False,
            False,
            reason,
        )
    if loader_offset is None:
        return InnoCandidateAssessment(
            "signal_without_validated_structure",
            False,
            signals,
            True,
            None,
            None,
            False,
            False,
            "loader_structure_missing",
        )
    validated = _validate_loader_table(
        data,
        loader_offset,
        resource_size=loader_size,
    )
    if validated is None:
        return InnoCandidateAssessment(
            "signal_without_validated_structure",
            False,
            signals,
            True,
            location,
            None,
            False,
            False,
            "loader_table_or_offsets_invalid",
        )
    revision, crc_verified = validated
    return InnoCandidateAssessment(
        "candidate",
        True,
        signals,
        True,
        location,
        revision,
        crc_verified,
        True,
    )


def inno_candidate_public(assessment: InnoCandidateAssessment) -> dict[str, object]:
    """raw offsetや外部文字列を含めない候補判定reportを返す。"""

    report: dict[str, object] = {
        "status": assessment.status,
        "candidate": assessment.candidate,
        "source_signals": list(assessment.source_signals),
        "pe_structure_valid": assessment.pe_structure_valid,
        "loader_location": assessment.loader_location,
        "loader_revision": assessment.loader_revision,
        "loader_crc_verified": assessment.loader_crc_verified,
        "setup_header_boundary_verified": assessment.setup_header_boundary_verified,
        "executed": False,
        "sample_executed": False,
        "network_contacted": False,
        "terminal_promotion_eligible": False,
    }
    if assessment.reason is not None:
        report["reason"] = assessment.reason
    return report


def _normalized_inno_name(value: str) -> str:
    """Innoの仮想rootは保持し、separatorだけ正規化する。"""

    if len(value.encode("utf-8", errors="surrogatepass")) > MAX_INNO_MEMBER_NAME_BYTES:
        raise ValueError("Inno member名が上限を超えています")
    # innounpのmask引数へそのまま戻すため、wildcardは許可しない。
    if any(character in value for character in "*?[]\r\n\0"):
        raise ValueError("Inno member名に許可しない文字があります")
    collapsed = re.sub(r"[\\/]+", "/", value.strip())
    # archive_nameはinnounpのmask引数へ戻す。innounpに確実なoption終端・
    # response-file無効化契約がないため、option/response-file prefixを拒否する。
    if collapsed.startswith(("-", "@")):
        raise ValueError("Inno member名がoptionとして解釈される可能性があります")
    return safe_member_name(collapsed, kind="Inno")


def parse_innounp_listing(output: str, returncode: int) -> InnoListing:
    """locale非依存optionの完全な一覧だけを解析する。

    対応契約は ``Size Date/Time Filename`` header、開始separator、0件以上の
    member row、終了separatorの順である。header以後の未認識行、終了separator
    欠落、途中までのrowはinventoryを不完全にする。
    """

    version_match = _TOOL_VERSION.search(output)
    tool_version = (
        ".".join(value for value in version_match.groups() if value is not None)
        if version_match
        else None
    )
    setup_match = _SETUP_VERSION.search(output)
    setup_version = setup_match.group(1).strip() if setup_match else None
    if version_match is None:
        return InnoListing(
            status="tool_identity_unrecognized",
            tool_version=None,
            setup_version=setup_version,
            members=(),
            invalid_member_count=0,
            duplicate_member_count=0,
            complete=False,
        )
    version = tuple(int(value or 0) for value in version_match.groups())
    if version < MIN_INNOUNP_VERSION:
        return InnoListing(
            status="tool_version_unsupported",
            tool_version=tool_version,
            setup_version=setup_version,
            members=(),
            invalid_member_count=0,
            duplicate_member_count=0,
            complete=False,
        )
    if returncode != 0 or setup_version is None:
        lowered = output.lower()
        status = (
            "unsupported_setup_version"
            if "not supported" in lowered or "unknown inno setup version" in lowered
            else "encrypted_or_invalid"
            if "password" in lowered or "encrypted" in lowered
            else "not_inno_archive"
        )
        return InnoListing(
            status=status,
            tool_version=tool_version,
            setup_version=setup_version,
            members=(),
            invalid_member_count=0,
            duplicate_member_count=0,
            complete=False,
        )

    members: list[InnoMember] = []
    seen: set[str] = set()
    invalid = 0
    duplicates = 0
    row_count = 0
    listing_header_seen = False
    listing_body_started = False
    listing_footer_seen = False
    for line in output.splitlines():
        if not listing_header_seen:
            if _LISTING_HEADER.fullmatch(line):
                listing_header_seen = True
            continue
        if not listing_body_started:
            if not line.strip():
                continue
            if _LISTING_SEPARATOR.fullmatch(line):
                listing_body_started = True
            else:
                invalid += 1
            continue
        if listing_footer_seen:
            if line.strip():
                invalid += 1
            continue
        if _LISTING_SEPARATOR.fullmatch(line):
            listing_footer_seen = True
            continue
        if not line.strip():
            invalid += 1
            continue
        match = _MEMBER_ROW.match(line)
        if match is None:
            invalid += 1
            continue
        row_count += 1
        if row_count > MAX_INNO_INVENTORY_MEMBERS:
            invalid += 1
            continue
        try:
            size = int(match.group(1))
            normalized = _normalized_inno_name(match.group(2))
        except (TypeError, ValueError, UnicodeError):
            invalid += 1
            continue
        folded = normalized.casefold()
        if folded in seen:
            duplicates += 1
            continue
        seen.add(folded)
        members.append(
            InnoMember(
                archive_name=match.group(2).strip(),
                normalized_name=normalized,
                size=size,
            )
        )
    complete = bool(
        members
        and listing_header_seen
        and listing_body_started
        and listing_footer_seen
        and invalid == 0
        and duplicates == 0
    )
    return InnoListing(
        status="listed" if complete else "unsafe_or_truncated_inventory",
        tool_version=tool_version,
        setup_version=setup_version,
        members=tuple(members),
        invalid_member_count=invalid,
        duplicate_member_count=duplicates,
        complete=complete,
    )


def parse_install_script(blob: bytes) -> InnoScriptFacts:
    """install scriptを実行せず、暗号化指定と起動先だけを読む。"""

    text = blob.decode("utf-8-sig", errors="replace")
    decompiler_provenance = bool(
        _SCRIPT_TOOL_HEADER.search(text) and _SCRIPT_SETUP_HEADER.search(text)
    )
    encrypted = False
    section = ""
    targets: list[str] = []
    dynamic = 0
    invalid = 0
    for raw_line in text.splitlines():
        section_match = _SECTION.match(raw_line)
        if section_match:
            section = section_match.group(1).strip().casefold()
            continue
        if section == "setup" and decompiler_provenance and _ENCRYPTION.match(raw_line):
            encrypted = True
        if section not in {"run", "uninstallrun"}:
            continue
        match = _FILENAME.match(raw_line)
        if match is None:
            continue
        value = (match.group(1) or match.group(2) or "").strip()
        if "{code:" in value.casefold():
            # `{code:...}`は実行時式なので静的なarchive memberへ解決しない。
            dynamic += 1
            continue
        try:
            normalized = _normalized_inno_name(value)
        except ValueError:
            invalid += 1
            continue
        if normalized.casefold() not in {item.casefold() for item in targets}:
            targets.append(normalized)
    return InnoScriptFacts(
        encrypted=encrypted,
        decompiler_provenance=decompiler_provenance,
        launch_targets=tuple(targets),
        dynamic_launch_target_count=dynamic,
        invalid_launch_target_count=invalid,
    )


def _virtual_relative_parts(name: str) -> tuple[str, ...]:
    parts = PurePosixPath(name).parts
    if parts and parts[0].startswith("{") and parts[0].endswith("}"):
        return tuple(parts[1:])
    return tuple(parts)


def _selection_priority(
    member: InnoMember,
    *,
    launch_targets: set[str],
    launch_directories: set[str],
) -> int | None:
    folded = member.normalized_name.casefold()
    path = PurePosixPath(folded)
    relative_parts = _virtual_relative_parts(folded)
    directory = str(path.parent).casefold()
    dependency_path = any(part in _DEPENDENCY_DIRECTORIES for part in path.parts)
    if folded in launch_targets:
        return 0
    if directory in launch_directories and not dependency_path:
        if member.suffix in _SIDELOAD_SUFFIXES:
            return 1
        if member.suffix in _PAYLOAD_SUFFIXES or not member.suffix:
            return 2
    if member.normalized_name.casefold() == "install_script.iss":
        return 2
    if member.suffix in _EXECUTABLE_SUFFIXES and not dependency_path:
        return 3
    if (
        len(relative_parts) <= 2
        and not dependency_path
        and (member.suffix in _PAYLOAD_SUFFIXES or not member.suffix)
    ):
        return 4
    if member.suffix in _PAYLOAD_SUFFIXES and not dependency_path:
        return 5
    return None


def select_inno_members(
    listing: InnoListing,
    facts: InnoScriptFacts,
    *,
    max_members: int,
    max_member_size: int,
    max_total_size: int,
    max_command_characters: int = MAX_INNO_COMMAND_CHARACTERS,
) -> InnoSelection:
    """起動先・同階層・実行可能形式・浅いdataの順で有界選択する。"""

    for value, label in (
        (max_members, "max_members"),
        (max_member_size, "max_member_size"),
        (max_total_size, "max_total_size"),
        (max_command_characters, "max_command_characters"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{label}は正の整数である必要があります")
    if not listing.complete:
        return InnoSelection(
            (),
            0,
            False,
            len(listing.members),
            ("inventory_incomplete",),
            0,
        )

    full_declared_size = sum(member.size for member in listing.members)
    full_command_characters = sum(
        len(member.archive_name) + 3 for member in listing.members
    )
    if (
        len(listing.members) <= max_members
        and all(member.size <= max_member_size for member in listing.members)
        and full_declared_size <= max_total_size
        and full_command_characters <= max_command_characters
    ):
        selected_names = {
            member.normalized_name.casefold() for member in listing.members
        }
        return InnoSelection(
            members=listing.members,
            declared_size=full_declared_size,
            complete_archive=True,
            omitted_member_count=0,
            limit_reasons=(),
            launch_target_match_count=len(
                {value.casefold() for value in facts.launch_targets}.intersection(
                    selected_names
                )
            ),
        )

    targets = {value.casefold() for value in facts.launch_targets}
    launch_directories = {
        str(PurePosixPath(value).parent).casefold() for value in facts.launch_targets
    }
    ranked: list[tuple[int, str, InnoMember]] = []
    limit_reasons: set[str] = set()
    for member in listing.members:
        priority = _selection_priority(
            member,
            launch_targets=targets,
            launch_directories=launch_directories,
        )
        if priority is None:
            continue
        if member.size > max_member_size:
            limit_reasons.add("member_size_limit")
            continue
        ranked.append((priority, member.normalized_name.casefold(), member))

    # 小さい補助DLLだけで枠を使い切らないよう、同一priorityでは名前順で
    # 決定的にする。高価値の根拠は拡張子ではなく起動graphを最優先する。
    selected: list[InnoMember] = []
    total = 0
    command_characters = 0
    for _, _, member in sorted(ranked, key=lambda item: (item[0], item[1])):
        if len(selected) >= max_members:
            limit_reasons.add("member_count_limit")
            continue
        if total + member.size > max_total_size:
            limit_reasons.add("total_size_limit")
            continue
        projected_characters = command_characters + len(member.archive_name) + 3
        if projected_characters > max_command_characters:
            limit_reasons.add("command_length_limit")
            continue
        selected.append(member)
        total += member.size
        command_characters = projected_characters

    selected_names = {member.normalized_name.casefold() for member in selected}
    omitted = len(listing.members) - len(selected)
    complete_archive = omitted == 0 and not limit_reasons
    if omitted and not limit_reasons:
        limit_reasons.add("low_value_members_omitted")
    return InnoSelection(
        members=tuple(selected),
        declared_size=total,
        complete_archive=complete_archive,
        omitted_member_count=omitted,
        limit_reasons=tuple(sorted(limit_reasons)),
        launch_target_match_count=len(targets.intersection(selected_names)),
    )


def inno_listing_public(listing: InnoListing) -> dict[str, object]:
    """private member objectを含めない公開inventoryを返す。"""

    return {
        "status": listing.status,
        "tool_version": listing.tool_version,
        "setup_version": listing.setup_version,
        "inventory_complete": listing.complete,
        "member_count": len(listing.members),
        "declared_total_size": sum(item.size for item in listing.members),
        "invalid_member_count": listing.invalid_member_count,
        "duplicate_member_count": listing.duplicate_member_count,
    }


def inno_selection_public(selection: InnoSelection) -> dict[str, object]:
    """選択理由と上限だけを公開し、tool用生maskは返さない。"""

    return {
        "selected_member_count": len(selection.members),
        "selected_declared_size": selection.declared_size,
        "complete_archive_extraction": selection.complete_archive,
        "omitted_member_count": selection.omitted_member_count,
        "limit_reasons": list(selection.limit_reasons),
        "launch_target_match_count": selection.launch_target_match_count,
    }


def _validated_complete_zip(
    blob: bytes,
    *,
    max_members: int,
    max_member_size: int,
    max_total_size: int,
    max_compression_ratio: float,
) -> tuple[int, int] | None:
    """末尾EOCD・central/local境界・path・CRCが完全なZIPだけを受理する。"""

    if len(blob) < _ZIP_EOCD.size or not blob.startswith(b"PK\x03\x04"):
        return None
    eocd_offset = blob.rfind(
        b"PK\x05\x06", max(0, len(blob) - (0xFFFF + _ZIP_EOCD.size))
    )
    if eocd_offset < 0 or eocd_offset + _ZIP_EOCD.size > len(blob):
        return None
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = _ZIP_EOCD.unpack_from(blob, eocd_offset)
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or not 0 < total_entries <= max_members
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or eocd_offset + _ZIP_EOCD.size + comment_size != len(blob)
        or central_offset + central_size != eocd_offset
        or blob[central_offset : central_offset + 4] != b"PK\x01\x02"
    ):
        return None

    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            members = archive.infolist()
            if len(members) != total_entries or archive.start_dir != central_offset:
                return None
            seen_names: set[str] = set()
            declared_total = 0
            ranges: list[tuple[int, int]] = []
            for member in members:
                try:
                    normalized = safe_member_name(member.filename, kind="ZIP")
                except ValueError:
                    return None
                folded = normalized.casefold()
                unix_type = (member.external_attr >> 16) & 0o170000
                if (
                    folded in seen_names
                    or member.flag_bits & 0x1
                    or unix_type == 0o120000
                    or member.file_size > max_member_size
                    or member.compress_size < 0
                    or member.file_size
                    > max(1, member.compress_size) * max_compression_ratio
                    or member.header_offset < 0
                    or member.header_offset + _ZIP_LOCAL.size > central_offset
                    or blob[member.header_offset : member.header_offset + 4]
                    != b"PK\x03\x04"
                ):
                    return None
                seen_names.add(folded)
                declared_total += member.file_size
                if declared_total > max_total_size:
                    return None
                local = _ZIP_LOCAL.unpack_from(blob, member.header_offset)
                data_start = (
                    member.header_offset + _ZIP_LOCAL.size + local[-2] + local[-1]
                )
                data_end = data_start + member.compress_size
                if data_start > data_end or data_end > central_offset:
                    return None
                ranges.append((member.header_offset, data_end))
            previous_end = 0
            for start, end in sorted(ranges):
                if start < previous_end:
                    return None
                previous_end = end
            if archive.testzip() is not None:
                return None
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile):
        return None
    return len(members), declared_total


def recover_segmented_zip(
    payloads: tuple[tuple[InnoMember, bytes], ...],
    *,
    max_members: int,
    max_member_size: int,
    max_total_size: int,
    max_compression_ratio: float = 100.0,
    max_segments: int = MAX_INNO_SPLIT_ARCHIVE_SEGMENTS,
) -> InnoSegmentedZip:
    """listing順に分割されたZIPを、推測名なしで連続区間から再構築する。"""

    for value, label in (
        (max_members, "max_members"),
        (max_member_size, "max_member_size"),
        (max_total_size, "max_total_size"),
        (max_segments, "max_segments"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{label}は正の整数である必要があります")
    if (
        isinstance(max_compression_ratio, bool)
        or not isinstance(max_compression_ratio, (int, float))
        or max_compression_ratio <= 0
    ):
        raise ValueError("max_compression_ratioは正数である必要があります")
    if len(payloads) < 2:
        return InnoSegmentedZip("not_found", None, (), 0, 0, False)

    candidates: list[tuple[bytes, tuple[str, ...], int, int]] = []
    segment_limit_seen = False
    for start, (_member, first) in enumerate(payloads[:-1]):
        if not first.startswith(b"PK\x03\x04"):
            continue
        maximum_end = min(len(payloads), start + max_segments)
        if maximum_end < len(payloads):
            segment_limit_seen = True
        for end in range(start + 2, maximum_end + 1):
            final = payloads[end - 1][1]
            if b"PK\x05\x06" not in final[-(0xFFFF + _ZIP_EOCD.size) :]:
                continue
            parts = payloads[start:end]
            candidate_size = sum(len(blob) for _, blob in parts)
            if candidate_size > max_total_size:
                continue
            candidate = b"".join(blob for _, blob in parts)
            validation = _validated_complete_zip(
                candidate,
                max_members=max_members,
                max_member_size=max_member_size,
                max_total_size=max_total_size,
                max_compression_ratio=max_compression_ratio,
            )
            if validation is None:
                continue
            archive_members, declared_total = validation
            candidates.append(
                (
                    candidate,
                    tuple(member.normalized_name for member, _ in parts),
                    archive_members,
                    declared_total,
                )
            )
    if len(candidates) != 1:
        return InnoSegmentedZip(
            "ambiguous" if candidates else "not_found",
            None,
            (),
            0,
            0,
            False,
            "multiple_valid_contiguous_ranges"
            if candidates
            else "segment_limit"
            if segment_limit_seen
            else None,
        )
    blob, source_members, archive_members, declared_total = candidates[0]
    return InnoSegmentedZip(
        "recovered",
        blob,
        source_members,
        archive_members,
        declared_total,
        True,
    )


def inno_segmented_zip_public(result: InnoSegmentedZip) -> dict[str, object]:
    """再構築結果からraw archiveを除いた公開メタデータを返す。"""

    report: dict[str, object] = {
        "status": result.status,
        "source_member_count": len(result.source_members),
        "source_members": list(result.source_members),
        "archive_member_count": result.archive_member_count,
        "declared_uncompressed_size": result.declared_uncompressed_size,
        "crc_verified": result.crc_verified,
        "executed": False,
        "network_contacted": False,
    }
    if result.reason is not None:
        report["reason"] = result.reason
    return report
