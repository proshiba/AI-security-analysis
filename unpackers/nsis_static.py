"""7-ZipのNSIS inventoryを検証し、安全な静的抽出計画を作る。"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import PurePosixPath

from unpackers.path_safety import safe_member_name

MAX_NSIS_MEMBER_NAME_BYTES = 4096
MAX_NSIS_INVENTORY_MEMBERS = 10_000
MAX_NSIS_COMMAND_CHARACTERS = 16_000
MAX_NSIS_SCRIPT_ACTIONS = 1024
MAX_NSIS_ACTION_CHARACTERS = 4096
MAX_PE_SECTIONS = 96
MAX_WIN_CERTIFICATES = 1024
MIN_SEVENZIP_VERSION = (24, 0)

_TOOL_VERSION = re.compile(r"\b7-Zip\s+(\d+)\.(\d+)\b", re.IGNORECASE)
_KEY_VALUE = re.compile(r"^([^=]+?)\s*=\s*(.*)$")
_DRIVE_PATH = re.compile(r"^([A-Za-z]):/(.+)$")
_HEADER_KEYS = {
    "Method",
    "Offset",
    "Packed Size",
    "Path",
    "Physical Size",
    "Size",
    "SubType",
    "Tail Size",
    "Type",
}
_SCRIPT_PROVENANCE = re.compile(
    r"^\s*;\s*NSIS script(?:\s+\(UTF-8\))?\s+NSIS-\d+(?:\s+Unicode)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_SCRIPT_COMMAND = re.compile(
    r"^\s*(SetOutPath|File|ExecWait|Exec|ShellExec|nsExec::ExecToStack|"
    r"nsExec::Exec|CreateShortcut)\s+(.+?)\s*$",
    re.IGNORECASE,
)
_STRCPY = re.compile(r"^\s*StrCpy\s+(\$[A-Za-z0-9_]+)\s+(.+?)\s*$", re.IGNORECASE)
_NSIS_VARIABLE = re.compile(r"\$(?:R\d|\d|[A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)

_HIGH_VALUE_SUFFIXES = {
    ".7z",
    ".a3x",
    ".asar",
    ".bat",
    ".bin",
    ".cab",
    ".cfg",
    ".cmd",
    ".com",
    ".conf",
    ".dat",
    ".dll",
    ".exe",
    ".hta",
    ".ini",
    ".jar",
    ".js",
    ".jse",
    ".json",
    ".msi",
    ".ocx",
    ".ps1",
    ".pyd",
    ".py",
    ".pyc",
    ".rar",
    ".scr",
    ".sys",
    ".vbe",
    ".vbs",
    ".xml",
    ".zip",
}
_EXECUTABLE_SUFFIXES = {".com", ".dll", ".exe", ".msi", ".ocx", ".pyd", ".scr", ".sys"}
_SCRIPT_SUFFIXES = {
    ".bat",
    ".cmd",
    ".hta",
    ".js",
    ".jse",
    ".ps1",
    ".py",
    ".vbe",
    ".vbs",
}


@dataclass(frozen=True)
class NsisMember:
    """7-Zip SLT inventoryで検証済みのNSIS member。"""

    archive_name: str
    normalized_name: str
    output_name: str
    size: int | None
    packed_size: int | None
    crc32: str | None
    encrypted: bool
    attributes: str

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.normalized_name.casefold()).suffix

    @property
    def is_directory(self) -> bool:
        return "D" in self.attributes.upper()


@dataclass(frozen=True)
class NsisListing:
    """完全性と不足fieldを明示したNSIS inventory。"""

    status: str
    archive_type: str | None
    subtype: str | None
    method: str | None
    physical_size: int | None
    members: tuple[NsisMember, ...]
    invalid_member_count: int
    output_collision_count: int
    unknown_size_count: int
    crc_unavailable_count: int
    complete: bool
    container_envelope: NsisContainerEnvelope | None = None


@dataclass(frozen=True)
class NsisContainerEnvelope:
    """7-Zip inventoryと入力byteの双方で検証したNSISの格納範囲。"""

    kind: str
    outer_physical_size: int
    pe_section_raw_end: int | None
    embedded_offset: int | None
    embedded_size: int | None
    embedded_packed_size: int | None
    nsis_physical_size: int
    nsis_tail_size: int
    security_offset: int | None
    security_size: int | None
    win_certificate_count: int


@dataclass(frozen=True)
class _PeContainerLayout:
    section_raw_end: int
    security_offset: int | None
    security_size: int | None
    win_certificate_count: int


@dataclass(frozen=True)
class NsisSelection:
    """抽出前に確定した有界member集合。"""

    members: tuple[NsisMember, ...]
    known_declared_size: int
    complete_archive: bool
    omitted_member_count: int
    limit_reasons: tuple[str, ...]


def parse_sevenzip_version(output: str) -> tuple[str | None, bool]:
    """7-Zip versionをlocale非依存のbannerから読む。"""

    match = _TOOL_VERSION.search(output)
    if match is None:
        return None, False
    version = (int(match.group(1)), int(match.group(2)))
    return f"{version[0]}.{version[1]:02d}", version >= MIN_SEVENZIP_VERSION


def _normalized_nsis_name(value: str) -> str:
    """NSISの仮想pathを7-Zipの出力規則に合わせて安全に正規化する。"""

    if len(value.encode("utf-8", errors="surrogatepass")) > MAX_NSIS_MEMBER_NAME_BYTES:
        raise ValueError("NSIS member名が上限を超えています")
    if any(character in value for character in "*?\r\n\0"):
        # 7-Zipの選択引数ではwildcardになるため、literal memberとして扱わない。
        raise ValueError("NSIS member名に許可しない文字があります")
    normalized = re.sub(r"[\\/]+", "/", value.strip())
    drive = _DRIVE_PATH.fullmatch(normalized)
    if drive:
        # 7-Zipはabsolute driveをoutput root配下の `C_` へ写像する。
        normalized = f"{drive.group(1).upper()}_/{drive.group(2)}"
    if ":" in normalized:
        raise ValueError("NSIS member名に未解決のdrive指定があります")
    return safe_member_name(normalized, kind="NSIS")


def _autorenamed_output(name: str, occurrence: int) -> str:
    """7-Zip `-aou` と同じく重複名へ `_N` を付ける。"""

    if occurrence == 0:
        return name
    path = PurePosixPath(name)
    suffix = path.suffix
    basename = path.name
    stem = basename[: -len(suffix)] if suffix else basename
    renamed = f"{stem}_{occurrence}{suffix}"
    return str(path.parent / renamed) if str(path.parent) != "." else renamed


def _integer(value: str | None) -> int | None:
    if value is None or not value.strip().isdigit():
        return None
    return int(value.strip())


def _read_u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("PE uint16が入力境界を越えます")
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("PE uint32が入力境界を越えます")
    return struct.unpack_from("<I", data, offset)[0]


def _validate_win_certificate_table(data: bytes, offset: int, size: int) -> int:
    """SECURITY directoryを8-byte境界のWIN_CERTIFICATE構造として検証する。

    ここで確認するのは境界、header、alignment、領域の完全消費だけである。
    certificate blobのPKCS#7構文、Authenticode署名、signer、失効状態は検証しない。
    """

    if offset % 8 or size < 8 or offset + size != len(data):
        raise ValueError("WIN_CERTIFICATE領域が入力末尾と一致しません")
    cursor = offset
    end = offset + size
    count = 0
    while cursor < end:
        if count >= MAX_WIN_CERTIFICATES or end - cursor < 8:
            raise ValueError("WIN_CERTIFICATE inventoryが不正です")
        length = _read_u32(data, cursor)
        revision = _read_u16(data, cursor + 4)
        certificate_type = _read_u16(data, cursor + 6)
        if length < 8 or revision not in {0x0100, 0x0200} or certificate_type == 0:
            raise ValueError("WIN_CERTIFICATE headerが不正です")
        certificate_end = cursor + length
        aligned_end = cursor + ((length + 7) & ~7)
        if certificate_end > end or aligned_end > end:
            raise ValueError("WIN_CERTIFICATEがSECURITY directory境界を越えます")
        cursor = aligned_end
        count += 1
    if cursor != end or count == 0:
        raise ValueError("WIN_CERTIFICATE領域を完全消費できません")
    return count


def _inspect_pe_container_layout(data: bytes) -> _PeContainerLayout:
    """PE section末尾と構造上のSECURITY directory末尾を独立に検証する。"""

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("PE DOS headerがありません")
    pe_offset = _read_u32(data, 0x3C)
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise ValueError("PE header offsetが不正です")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("PE signatureがありません")

    section_count = _read_u16(data, pe_offset + 6)
    optional_size = _read_u16(data, pe_offset + 20)
    if not 1 <= section_count <= MAX_PE_SECTIONS:
        raise ValueError("PE section数が上限外です")
    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if optional_end > len(data):
        raise ValueError("PE optional headerが入力境界を越えます")
    magic = _read_u16(data, optional_offset)
    if magic == 0x10B:
        directory_count_offset = optional_offset + 92
        directory_offset = optional_offset + 96
    elif magic == 0x20B:
        directory_count_offset = optional_offset + 108
        directory_offset = optional_offset + 112
    else:
        raise ValueError("PE optional header magicが未対応です")
    if directory_count_offset + 4 > optional_end:
        raise ValueError("PE data directory countが入力境界を越えます")

    section_table = optional_end
    section_table_end = section_table + section_count * 40
    if section_table_end > len(data):
        raise ValueError("PE section tableが入力境界を越えます")
    size_of_headers = _read_u32(data, optional_offset + 60)
    if size_of_headers < section_table_end or size_of_headers > len(data):
        raise ValueError("PE SizeOfHeadersが不正です")

    raw_spans: list[tuple[int, int]] = []
    section_raw_end = size_of_headers
    for index in range(section_count):
        section = section_table + index * 40
        raw_size = _read_u32(data, section + 16)
        raw_offset = _read_u32(data, section + 20)
        if raw_size == 0:
            continue
        raw_end = raw_offset + raw_size
        if raw_offset < size_of_headers or raw_end > len(data):
            raise ValueError("PE section raw spanが入力境界外です")
        raw_spans.append((raw_offset, raw_end))
        section_raw_end = max(section_raw_end, raw_end)
    for previous, current in zip(
        sorted(raw_spans), sorted(raw_spans)[1:], strict=False
    ):
        if current[0] < previous[1]:
            raise ValueError("PE section raw spanが重複しています")

    directory_count = _read_u32(data, directory_count_offset)
    available_directories = max(0, (optional_end - directory_offset) // 8)
    if directory_count > available_directories:
        raise ValueError("PE data directory数がoptional headerを越えます")
    if directory_count <= 4:
        return _PeContainerLayout(section_raw_end, None, None, 0)

    security_entry = directory_offset + 4 * 8
    security_offset = _read_u32(data, security_entry)
    security_size = _read_u32(data, security_entry + 4)
    if bool(security_offset) != bool(security_size):
        raise ValueError("PE SECURITY offset/sizeの片方だけが0です")
    if security_offset == 0:
        return _PeContainerLayout(section_raw_end, None, None, 0)
    if security_offset < section_raw_end:
        raise ValueError("PE SECURITY directoryがsection raw領域と重複します")
    certificate_count = _validate_win_certificate_table(
        data, security_offset, security_size
    )
    return _PeContainerLayout(
        section_raw_end,
        security_offset,
        security_size,
        certificate_count,
    )


def _header_fields(
    output: str,
) -> tuple[tuple[dict[str, str], ...], list[dict[str, str]]] | None:
    normalized = output.replace("\r\n", "\n").replace("\r", "\n")
    marker = "\n----------\n"
    if marker not in normalized:
        return None
    header_text, member_text = normalized.split(marker, 1)
    header_groups: list[dict[str, str]] = []
    header: dict[str, str] = {}
    for line in header_text.splitlines():
        if re.fullmatch(r"-{2,}", line.strip()):
            if header:
                header_groups.append(header)
                header = {}
            continue
        match = _KEY_VALUE.match(line)
        if match:
            key, value = match.group(1).strip(), match.group(2).strip()
            if key not in _HEADER_KEYS:
                continue
            if key in header:
                return None
            header[key] = value
    if header:
        header_groups.append(header)
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in member_text.splitlines():
        match = _KEY_VALUE.match(line)
        if match is None:
            continue
        key, value = match.group(1).strip(), match.group(2).strip()
        if key == "Path":
            if current is not None:
                records.append(current)
            current = {"Path": value}
        elif current is not None:
            current[key] = value
    if current is not None:
        records.append(current)
    return tuple(header_groups), records


def _empty_nsis_listing(
    status: str,
    *,
    archive_type: str | None = None,
    subtype: str | None = None,
    method: str | None = None,
    physical_size: int | None = None,
    container_envelope: NsisContainerEnvelope | None = None,
) -> NsisListing:
    return NsisListing(
        status,
        archive_type,
        subtype,
        method,
        physical_size,
        (),
        0,
        0,
        0,
        0,
        False,
        container_envelope,
    )


def _direct_nsis_envelope(
    header: dict[str, str], source_size: int
) -> tuple[NsisContainerEnvelope | None, str | None]:
    physical_size = _integer(header.get("Physical Size"))
    if physical_size != source_size:
        return None, "physical_size_mismatch"
    return (
        NsisContainerEnvelope(
            kind="direct_nsis",
            outer_physical_size=source_size,
            pe_section_raw_end=None,
            embedded_offset=None,
            embedded_size=None,
            embedded_packed_size=None,
            nsis_physical_size=physical_size,
            nsis_tail_size=0,
            security_offset=None,
            security_size=None,
            win_certificate_count=0,
        ),
        None,
    )


def _pe_wrapped_nsis_envelope(
    groups: tuple[dict[str, str], ...],
    source_size: int,
    source_data: bytes | None,
) -> tuple[NsisContainerEnvelope | None, str | None]:
    if len(groups) != 3 or source_data is None or len(source_data) != source_size:
        return None, "container_envelope_mismatch"
    outer, extent, inner = groups
    if (
        outer.get("Type", "").casefold() != "pe"
        or inner.get("Type", "").casefold() != "nsis"
        or "Type" in extent
        or extent.get("Path") != inner.get("Path")
    ):
        return None, "container_envelope_mismatch"

    outer_size = _integer(outer.get("Physical Size"))
    embedded_offset = _integer(extent.get("Offset"))
    embedded_size = _integer(extent.get("Size"))
    embedded_packed_size = _integer(extent.get("Packed Size"))
    nsis_physical_size = _integer(inner.get("Physical Size"))
    tail_text = inner.get("Tail Size")
    nsis_tail_size = 0 if tail_text is None else _integer(tail_text)
    if (
        outer_size != source_size
        or embedded_offset is None
        or embedded_size is None
        or embedded_size <= 0
        or embedded_packed_size != embedded_size
        or nsis_physical_size is None
        or nsis_physical_size <= 0
        or nsis_tail_size is None
        or nsis_physical_size + nsis_tail_size != embedded_size
        or embedded_offset + embedded_size > source_size
    ):
        return None, "container_envelope_mismatch"

    try:
        layout = _inspect_pe_container_layout(source_data)
    except (OverflowError, struct.error, ValueError):
        return None, "container_envelope_mismatch"
    embedded_end = embedded_offset + embedded_size
    if embedded_offset != layout.section_raw_end:
        return None, "container_envelope_mismatch"
    if layout.security_offset is None:
        if embedded_end != source_size:
            return None, "container_envelope_mismatch"
    elif (
        embedded_end != layout.security_offset
        or layout.security_size is None
        or layout.security_offset + layout.security_size != source_size
    ):
        return None, "container_envelope_mismatch"

    return (
        NsisContainerEnvelope(
            kind="pe_wrapper",
            outer_physical_size=outer_size,
            pe_section_raw_end=layout.section_raw_end,
            embedded_offset=embedded_offset,
            embedded_size=embedded_size,
            embedded_packed_size=embedded_packed_size,
            nsis_physical_size=nsis_physical_size,
            nsis_tail_size=nsis_tail_size,
            security_offset=layout.security_offset,
            security_size=layout.security_size,
            win_certificate_count=layout.win_certificate_count,
        ),
        None,
    )


def parse_nsis_listing(
    output: str,
    returncode: int,
    source_size: int,
    *,
    source_data: bytes | None = None,
) -> NsisListing:
    """`7z l -slt`のNSIS inventoryをpath衝突まで含めて検証する。"""

    parsed = _header_fields(output)
    if returncode != 0 or parsed is None:
        lowered = output.casefold()
        status = (
            "encrypted_or_invalid"
            if "password" in lowered or "encrypted" in lowered
            else "not_nsis_archive"
        )
        return _empty_nsis_listing(status)
    header_groups, records = parsed
    if not header_groups:
        return _empty_nsis_listing("not_nsis_archive")

    header = header_groups[-1]
    archive_type = header.get("Type")
    physical_size = _integer(header.get("Physical Size"))
    if not archive_type or archive_type.casefold() != "nsis":
        return _empty_nsis_listing(
            "not_nsis_archive",
            archive_type=archive_type,
            subtype=header.get("SubType"),
            method=header.get("Method"),
            physical_size=physical_size,
        )

    if len(header_groups) == 1:
        envelope, envelope_error = _direct_nsis_envelope(header, source_size)
    else:
        envelope, envelope_error = _pe_wrapped_nsis_envelope(
            header_groups, source_size, source_data
        )
    if envelope_error is not None:
        return _empty_nsis_listing(
            envelope_error,
            archive_type=archive_type,
            subtype=header.get("SubType"),
            method=header.get("Method"),
            physical_size=physical_size,
        )

    members: list[NsisMember] = []
    occurrences: dict[str, int] = {}
    output_names: set[str] = set()
    invalid = 0
    collisions = 0
    unknown_sizes = 0
    crc_unavailable = 0
    for index, record in enumerate(records):
        if index >= MAX_NSIS_INVENTORY_MEMBERS:
            invalid += 1
            continue
        raw_name = record.get("Path", "")
        try:
            normalized = _normalized_nsis_name(raw_name)
        except (UnicodeError, ValueError):
            invalid += 1
            continue
        folded = normalized.casefold()
        occurrence = occurrences.get(folded, 0)
        occurrences[folded] = occurrence + 1
        output_name = _autorenamed_output(normalized, occurrence)
        output_folded = output_name.casefold()
        if output_folded in output_names:
            collisions += 1
            continue
        output_names.add(output_folded)
        size = _integer(record.get("Size"))
        packed_size = _integer(record.get("Packed Size"))
        crc = record.get("CRC")
        crc = crc.upper() if crc and re.fullmatch(r"[0-9A-Fa-f]{8}", crc) else None
        encrypted = record.get("Encrypted", "").strip() == "+"
        attributes = record.get("Attributes", "")
        if "D" not in attributes.upper() and size is None:
            unknown_sizes += 1
        if "D" not in attributes.upper() and crc is None:
            crc_unavailable += 1
        members.append(
            NsisMember(
                archive_name=raw_name,
                normalized_name=normalized,
                output_name=output_name,
                size=size,
                packed_size=packed_size,
                crc32=crc,
                encrypted=encrypted,
                attributes=attributes,
            )
        )
    files = tuple(member for member in members if not member.is_directory)
    encrypted = any(member.encrypted for member in files)
    complete = bool(files) and invalid == 0 and collisions == 0 and not encrypted
    status = (
        "encrypted_archive"
        if encrypted
        else "listed"
        if complete
        else "unsafe_or_truncated_inventory"
    )
    return NsisListing(
        status,
        archive_type,
        header.get("SubType"),
        header.get("Method"),
        physical_size,
        files,
        invalid,
        collisions,
        unknown_sizes,
        crc_unavailable,
        complete,
        envelope,
    )


def _selection_priority(member: NsisMember) -> int | None:
    path = PurePosixPath(member.normalized_name.casefold())
    if path.name == "[nsis].nsi":
        return 0
    if member.suffix in _SCRIPT_SUFFIXES:
        return 1
    if member.suffix in _EXECUTABLE_SUFFIXES:
        return 2
    if member.suffix in _HIGH_VALUE_SUFFIXES:
        return 3
    if not member.suffix and len(path.parts) <= 3:
        return 4
    return None


def select_nsis_members(
    listing: NsisListing,
    *,
    max_members: int,
    max_member_size: int,
    max_total_size: int,
    max_command_characters: int = MAX_NSIS_COMMAND_CHARACTERS,
) -> NsisSelection:
    """同名memberを分割せず、全件または高価値集合を決定的に選ぶ。"""

    for value, label in (
        (max_members, "max_members"),
        (max_member_size, "max_member_size"),
        (max_total_size, "max_total_size"),
        (max_command_characters, "max_command_characters"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{label}は正の整数である必要があります")
    if not listing.complete:
        return NsisSelection(
            (), 0, False, len(listing.members), ("inventory_incomplete",)
        )

    known_total = sum(member.size or 0 for member in listing.members)
    command_characters = sum(len(member.archive_name) + 3 for member in listing.members)
    if (
        len(listing.members) <= max_members
        and all(
            member.size is None or member.size <= max_member_size
            for member in listing.members
        )
        and known_total <= max_total_size
        and command_characters <= max_command_characters
    ):
        reasons = (
            ("unknown_sizes_bounded_during_extraction",)
            if listing.unknown_size_count
            else ()
        )
        return NsisSelection(listing.members, known_total, True, 0, reasons)

    grouped: dict[str, list[NsisMember]] = {}
    for member in listing.members:
        grouped.setdefault(member.archive_name.casefold(), []).append(member)
    ranked: list[tuple[int, str, list[NsisMember]]] = []
    for folded, members in grouped.items():
        priorities = [
            value
            for member in members
            if (value := _selection_priority(member)) is not None
        ]
        if priorities:
            ranked.append((min(priorities), folded, members))

    selected: list[NsisMember] = []
    selected_total = 0
    selected_command = 0
    reasons: set[str] = set()
    for _, _, group in sorted(ranked, key=lambda item: (item[0], item[1])):
        group_size = sum(member.size or 0 for member in group)
        if any(
            member.size is not None and member.size > max_member_size
            for member in group
        ):
            reasons.add("member_size_limit")
            continue
        if len(selected) + len(group) > max_members:
            reasons.add("member_count_limit")
            continue
        if selected_total + group_size > max_total_size:
            reasons.add("total_size_limit")
            continue
        group_command = len(group[0].archive_name) + 3
        if selected_command + group_command > max_command_characters:
            reasons.add("command_length_limit")
            continue
        selected.extend(group)
        selected_total += group_size
        selected_command += group_command
    omitted = len(listing.members) - len(selected)
    if omitted and not reasons:
        reasons.add("low_value_members_omitted")
    if any(member.size is None for member in selected):
        reasons.add("unknown_sizes_bounded_during_extraction")
    return NsisSelection(
        tuple(selected),
        selected_total,
        omitted == 0,
        omitted,
        tuple(sorted(reasons)),
    )


def _strip_comment(value: str) -> str:
    """quoted semicolonを壊さず、7-Zip decompilerの末尾commentだけを除く。"""

    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "$":
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            return value[:index].rstrip()
    return value.strip()


def _unquote(value: str) -> str:
    value = _strip_comment(value).strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _resolve_variables(value: str, variables: dict[str, str]) -> tuple[str, bool]:
    result = value
    for _ in range(16):
        changed = False

        def replace(match: re.Match[str]) -> str:
            nonlocal changed
            key = match.group(0).casefold()
            replacement = variables.get(key)
            if replacement is None:
                return match.group(0)
            changed = True
            return replacement

        result = _NSIS_VARIABLE.sub(replace, result)
        if not changed:
            break
    dynamic = bool(_NSIS_VARIABLE.search(result) or "${" in result)
    return result, dynamic


def parse_nsis_launch_graph(script: bytes) -> dict[str, object]:
    """decompiled scriptを実行せず、File配置と起動命令の順序graphを作る。"""

    text = script.decode("utf-8-sig", errors="replace")
    provenance = bool(_SCRIPT_PROVENANCE.search(text))
    variables: dict[str, str] = {}
    output_directory = ""
    actions: list[dict[str, object]] = []
    invalid = 0
    truncated = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        assignment = _STRCPY.match(raw_line)
        if assignment:
            value = _unquote(assignment.group(2))
            if len(value) <= MAX_NSIS_ACTION_CHARACTERS:
                resolved, _ = _resolve_variables(value, variables)
                variables[assignment.group(1).casefold()] = resolved
            continue
        command = _SCRIPT_COMMAND.match(raw_line)
        if command is None:
            continue
        if len(actions) >= MAX_NSIS_SCRIPT_ACTIONS:
            truncated = True
            break
        opcode, operand = command.group(1), _strip_comment(command.group(2))
        if not operand or len(operand) > MAX_NSIS_ACTION_CHARACTERS:
            invalid += 1
            continue
        raw_target = _unquote(operand)
        resolved, dynamic = _resolve_variables(raw_target, variables)
        kind = (
            "placement"
            if opcode.casefold() == "file"
            else "directory"
            if opcode.casefold() == "setoutpath"
            else "launch"
        )
        action: dict[str, object] = {
            "sequence": len(actions),
            "line": line_number,
            "kind": kind,
            "opcode": opcode,
            "raw_target": raw_target,
            "resolved_target": resolved,
            "dynamic": dynamic,
        }
        if kind == "directory":
            output_directory = resolved
        elif kind == "placement":
            action["output_directory"] = output_directory or None
        actions.append(action)
    placements = sum(action["kind"] == "placement" for action in actions)
    launches = sum(action["kind"] == "launch" for action in actions)
    dynamic_launches = sum(
        action["kind"] == "launch" and action["dynamic"] for action in actions
    )
    return {
        "status": "parsed" if provenance and not truncated else "partial",
        "decompiler_provenance": provenance,
        "action_count": len(actions),
        "placement_count": placements,
        "launch_count": launches,
        "dynamic_launch_count": dynamic_launches,
        "invalid_action_count": invalid,
        "truncated": truncated,
        "actions": actions,
        "executed": False,
        "network_contacted": False,
    }


def nsis_listing_public(listing: NsisListing) -> dict[str, object]:
    """raw tool recordを含めず、inventoryの完全性と上限情報を返す。"""

    envelope = listing.container_envelope
    return {
        "status": listing.status,
        "archive_types": [listing.archive_type] if listing.archive_type else [],
        "subtype": listing.subtype,
        "method": listing.method,
        "physical_size": listing.physical_size,
        "inventory_complete": listing.complete,
        "total_members": len(listing.members),
        "declared_total_size": sum(member.size or 0 for member in listing.members),
        "unknown_size_count": listing.unknown_size_count,
        "invalid_member_count": listing.invalid_member_count,
        "output_collision_count": listing.output_collision_count,
        "crc_unavailable_count": listing.crc_unavailable_count,
        "container_envelope": (
            {
                "kind": envelope.kind,
                "container_layout_validated": True,
                "outer_physical_size": envelope.outer_physical_size,
                "pe_section_raw_end": envelope.pe_section_raw_end,
                "embedded_offset": envelope.embedded_offset,
                "embedded_size": envelope.embedded_size,
                "embedded_packed_size": envelope.embedded_packed_size,
                "nsis_physical_size": envelope.nsis_physical_size,
                "nsis_tail_size": envelope.nsis_tail_size,
                "security_offset": envelope.security_offset,
                "security_size": envelope.security_size,
                "win_certificate_count": envelope.win_certificate_count,
                "certificate_table_structure_validated": (
                    envelope.security_offset is not None
                    and envelope.security_size is not None
                    and envelope.win_certificate_count > 0
                ),
                # WIN_CERTIFICATE表の構造検証は、暗号学的な署名検証ではない。
                "authenticode_signature_verified": False,
                "signer_verified": False,
                "revocation_checked": False,
            }
            if envelope is not None
            else None
        ),
    }


def nsis_selection_public(selection: NsisSelection) -> dict[str, object]:
    """tool用raw maskを除いた選択contractを返す。"""

    return {
        "enabled": not selection.complete_archive,
        "selected_member_count": len(selection.members),
        "selected_known_size": selection.known_declared_size,
        "complete_archive_extraction": selection.complete_archive,
        "omitted_member_count": selection.omitted_member_count,
        "limit_reasons": list(selection.limit_reasons),
    }
