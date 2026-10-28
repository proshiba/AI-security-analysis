"""ValleyRATの ``IpDate`` compact設定literalを静的に検証する。

Splunkの公開解析で報告された ``HKCU\\Software\\Console`` 配下の
``IpDate``／``IpDateInfo`` と ``i:<host>|p:<port>`` 形式を対象とする。
埋込みliteralだけでは実行時registry値、family、終端C2を確定できないため、
結果は追加静的解析へ渡すroute候補に限定する。
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

from extractors.valleyrat.nvml_dat import normalize_host, render_endpoint

SCHEMA_VERSION = 1
MAXIMUM_INPUT_SIZE = 64 * 1024 * 1024
MAXIMUM_SCANNED_BYTES = 32 * 1024 * 1024
MAXIMUM_SECTION_COUNT = 32
MAXIMUM_OPTIONAL_HEADER_SIZE = 0x400
MAXIMUM_STRING_COUNT = 16_384
MAXIMUM_STRING_LENGTH = 1_024
MAXIMUM_STRING_CHARACTERS = 2 * 1024 * 1024
MINIMUM_REGISTRY_VALUE_MARKERS = 2

_COMPACT_CONFIG = re.compile(
    r"i:([A-Za-z0-9.\-:\[\]]{1,255})\|p:([0-9]{1,5})\|?",
    re.ASCII,
)
_REGISTRY_BASE = "software\\console"
_REGISTRY_VALUES = {
    "ipdate": "IpDate",
    "ipdateinfo": "IpDateInfo",
    "selfpath": "SelfPath",
}
_REJECTED_DOMAIN_SUFFIXES = (".example", ".invalid", ".localhost", ".test")
_IPDATE_MARKER_HINTS = (
    b"IpDate",
    b"ipdate",
    b"IPDATE",
    "IpDate".encode("utf-16le"),
    "ipdate".encode("utf-16le"),
    "IPDATE".encode("utf-16le"),
)


class IpDateCompactConfigError(ValueError):
    """compact設定候補が厳格な構造条件を満たさない場合の例外。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _MappedSection:
    """走査対象にできるfile-backed PE section。"""

    name: str
    raw_start: int
    raw_end: int
    executable: bool


@dataclass(frozen=True)
class _StringRecord:
    """公開出力へ生文字列を含めない内部文字列record。"""

    value: str
    encoding: str
    section_name: str


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _mapped_sections(data: bytes) -> tuple[_MappedSection, ...]:
    """PE headerとsection境界を検証し、非resource raw範囲を返す。"""

    if len(data) < 0x100 or data[:2] != b"MZ":
        raise IpDateCompactConfigError("not_pe", "入力がPEではありません")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if not 0x40 <= e_lfanew <= len(data) - 24:
        raise IpDateCompactConfigError("pe_header_invalid", "e_lfanewが不正です")
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise IpDateCompactConfigError("pe_header_invalid", "PE signatureがありません")
    coff = e_lfanew + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    if machine not in {0x14C, 0x8664}:
        raise IpDateCompactConfigError(
            "pe_machine_unsupported", "PE machineが未対応です"
        )
    if not 1 <= section_count <= MAXIMUM_SECTION_COUNT:
        raise IpDateCompactConfigError(
            "section_count_limit", "section countが許容範囲外です"
        )
    if not 0x60 <= optional_size <= MAXIMUM_OPTIONAL_HEADER_SIZE:
        raise IpDateCompactConfigError(
            "optional_header_invalid", "optional header sizeが不正です"
        )
    optional = coff + 20
    optional_end = optional + optional_size
    if optional_end > len(data):
        raise IpDateCompactConfigError(
            "optional_header_invalid", "optional headerがfile境界を超えています"
        )
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in {0x10B, 0x20B}:
        raise IpDateCompactConfigError(
            "optional_header_invalid", "PE optional header magicが不正です"
        )
    section_alignment, file_alignment = struct.unpack_from("<II", data, optional + 32)
    image_size = struct.unpack_from("<I", data, optional + 56)[0]
    headers_size = struct.unpack_from("<I", data, optional + 60)[0]
    if (
        not _is_power_of_two(file_alignment)
        or not _is_power_of_two(section_alignment)
        or not 0x200 <= file_alignment <= 0x10000
        or not file_alignment <= section_alignment <= 0x100000
    ):
        raise IpDateCompactConfigError("pe_alignment_invalid", "PE alignmentが不正です")
    table_end = optional_end + section_count * 40
    if (
        table_end > len(data)
        or not table_end <= headers_size <= len(data)
        or headers_size % file_alignment
        or not headers_size < image_size
    ):
        raise IpDateCompactConfigError(
            "section_table_invalid", "PE section tableまたはimage境界が不正です"
        )

    mapped: list[_MappedSection] = []
    raw_ranges: list[tuple[int, int]] = []
    virtual_ranges: list[tuple[int, int]] = []
    executable_count = 0
    for index in range(section_count):
        offset = optional_end + index * 40
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii", errors="strict") or f"section_{index + 1}"
        except UnicodeDecodeError as exc:
            raise IpDateCompactConfigError(
                "section_name_invalid", "section名がASCIIではありません"
            ) from exc
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        virtual_span = max(virtual_size, raw_size)
        if not virtual_address or not virtual_span:
            raise IpDateCompactConfigError(
                "section_virtual_invalid", "sectionのvirtual範囲が空です"
            )
        if virtual_address + virtual_span > image_size:
            raise IpDateCompactConfigError(
                "section_virtual_invalid", "sectionがSizeOfImageを超えています"
            )
        virtual_ranges.append((virtual_address, virtual_address + virtual_span))
        executable = bool(characteristics & 0x20000000)
        executable_count += int(executable)
        if raw_size:
            raw_end = raw_pointer + raw_size
            if raw_pointer < headers_size or raw_end > len(data):
                raise IpDateCompactConfigError(
                    "section_raw_invalid", "sectionのraw範囲が不正です"
                )
            raw_ranges.append((raw_pointer, raw_end))
            if name.casefold() != ".rsrc":
                mapped.append(
                    _MappedSection(
                        name=name,
                        raw_start=raw_pointer,
                        raw_end=raw_end,
                        executable=executable,
                    )
                )
    for ranges in (raw_ranges, virtual_ranges):
        ordered = sorted(ranges)
        if any(left[1] > right[0] for left, right in pairwise(ordered)):
            raise IpDateCompactConfigError(
                "section_overlap", "PE section範囲が重複しています"
            )
    if not executable_count or not mapped:
        raise IpDateCompactConfigError(
            "mapped_sections_missing",
            "実行可能sectionまたは走査対象sectionがありません",
        )
    if (
        sum(section.raw_end - section.raw_start for section in mapped)
        > MAXIMUM_SCANNED_BYTES
    ):
        raise IpDateCompactConfigError(
            "mapped_scan_limit", "非resource mapped sectionが走査上限を超えています"
        )
    return tuple(mapped)


def _ascii_strings(blob: bytes) -> list[str]:
    """maximal ASCII runを上限付きで列挙する。"""

    values: list[str] = []
    cursor = 0
    while cursor < len(blob):
        if not 0x20 <= blob[cursor] <= 0x7E:
            cursor += 1
            continue
        start = cursor
        while cursor < len(blob) and 0x20 <= blob[cursor] <= 0x7E:
            cursor += 1
        length = cursor - start
        if length > MAXIMUM_STRING_LENGTH:
            raise IpDateCompactConfigError(
                "string_length_limit", "ASCII文字列が上限を超えています"
            )
        if length >= 4:
            values.append(blob[start:cursor].decode("ascii"))
    return values


def _utf16le_ascii_strings(blob: bytes) -> list[str]:
    """両alignmentのmaximal UTF-16LE ASCII runを上限付きで列挙する。"""

    values: list[str] = []
    for alignment in (0, 1):
        cursor = alignment
        while cursor + 1 < len(blob):
            if not (0x20 <= blob[cursor] <= 0x7E and blob[cursor + 1] == 0):
                cursor += 2
                continue
            start = cursor
            while (
                cursor + 1 < len(blob)
                and 0x20 <= blob[cursor] <= 0x7E
                and blob[cursor + 1] == 0
            ):
                cursor += 2
            character_count = (cursor - start) // 2
            if character_count > MAXIMUM_STRING_LENGTH:
                raise IpDateCompactConfigError(
                    "string_length_limit", "UTF-16LE文字列が上限を超えています"
                )
            if character_count >= 4:
                values.append(blob[start:cursor].decode("utf-16le"))
    return values


def _bounded_strings(
    data: bytes, sections: tuple[_MappedSection, ...]
) -> tuple[_StringRecord, ...]:
    """section名・encoding付きの文字列を全候補集合が完全な場合だけ返す。"""

    records: list[_StringRecord] = []
    character_count = 0
    for section in sections:
        blob = data[section.raw_start : section.raw_end]
        for encoding, values in (
            ("ascii", _ascii_strings(blob)),
            ("utf-16le", _utf16le_ascii_strings(blob)),
        ):
            for value in values:
                character_count += len(value)
                records.append(
                    _StringRecord(
                        value=value,
                        encoding=encoding,
                        section_name=section.name,
                    )
                )
                if (
                    len(records) > MAXIMUM_STRING_COUNT
                    or character_count > MAXIMUM_STRING_CHARACTERS
                ):
                    raise IpDateCompactConfigError(
                        "string_scan_limit", "文字列候補集合が走査上限を超えています"
                    )
    return tuple(records)


def _registry_evidence(records: tuple[_StringRecord, ...]) -> tuple[bool, set[str]]:
    """registry baseと独立したvalue名を同時に確認する。"""

    base_observed = False
    values: set[str] = set()
    for record in records:
        folded = record.value.casefold().replace("/", "\\").strip("\\")
        base_observed = base_observed or _REGISTRY_BASE in folded
        final_component = folded.rsplit("\\", 1)[-1]
        if final_component in _REGISTRY_VALUES:
            values.add(final_component)
    return base_observed, values


def _public_endpoint(raw_host: str, raw_port: str) -> str | None:
    """public IP/FQDNと有効portだけをcanonical endpointへ変換する。"""

    if any(character in raw_host for character in "/@?#"):
        return None
    host = normalize_host(raw_host.strip("[]"))
    if host is None or not raw_port.isdigit():
        return None
    port = int(raw_port)
    if not 1 <= port <= 65535:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        folded = host.casefold().rstrip(".")
        labels = folded.split(".")
        if (
            "." not in folded
            or folded.endswith(_REJECTED_DOMAIN_SUFFIXES)
            or any(
                not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
                for label in labels
            )
        ):
            return None
    else:
        if not address.is_global:
            return None
    return render_endpoint(host, port)


def extract_ipdate_compact_config(data: bytes) -> dict[str, Any]:
    """mapped PE内の一意なcompact設定をroute候補として返す。"""

    if type(data) is not bytes:
        raise IpDateCompactConfigError("input_type", "入力はbytesである必要があります")
    if not 0 < len(data) <= MAXIMUM_INPUT_SIZE:
        raise IpDateCompactConfigError(
            "input_size_limit", "入力sizeが64 MiB上限を超えています"
        )
    sections = _mapped_sections(data)
    if not any(marker in data for marker in _IPDATE_MARKER_HINTS):
        raise IpDateCompactConfigError(
            "registry_marker_hint_missing", "IpDate marker候補がありません"
        )
    records = _bounded_strings(data, sections)
    base_observed, registry_values = _registry_evidence(records)
    if not base_observed or len(registry_values) < MINIMUM_REGISTRY_VALUE_MARKERS:
        raise IpDateCompactConfigError(
            "registry_evidence_missing",
            "Software\\Consoleと複数のIpDate系value名を確認できません",
        )

    candidates: dict[str, list[_StringRecord]] = {}
    for record in records:
        match = _COMPACT_CONFIG.fullmatch(record.value)
        if match is None:
            continue
        endpoint = _public_endpoint(match.group(1), match.group(2))
        if endpoint is None:
            continue
        endpoint_records = candidates.get(endpoint)
        if endpoint_records is None:
            endpoint_records = []
            candidates[endpoint] = endpoint_records
        endpoint_records.append(record)
    if not candidates:
        raise IpDateCompactConfigError(
            "compact_literal_missing", "有効なcompact設定literalがありません"
        )
    if len(candidates) != 1:
        raise IpDateCompactConfigError(
            "compact_literal_ambiguous", "相反するcompact設定literalがあります"
        )
    endpoint, occurrences = next(iter(candidates.items()))
    marker_names = sorted(_REGISTRY_VALUES[value] for value in registry_values)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "validated_ipdate_compact_route_candidate",
        "variant": "ipdate_compact_embedded_literal_candidate",
        "family_role": "runtime_registry_config_candidate",
        "endpoint": endpoint,
        "endpoint_role": "interactive_c2_candidate",
        "candidate_config_recovered": True,
        "static_config_recovered": False,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "command_c2_confirmed": False,
        "liveness_confirmed": False,
        "evidence": {
            "input_format": "pe",
            "mapped_non_resource_sections_validated": True,
            "registry_base_observed": True,
            "registry_value_markers": marker_names,
            "registry_value_marker_count": len(marker_names),
            "compact_literal_occurrence_count": len(occurrences),
            "compact_literal_encodings": sorted(
                {record.encoding for record in occurrences}
            ),
            "compact_literal_section_count": len(
                {record.section_name for record in occurrences}
            ),
            "runtime_registry_value_observed": False,
            "config_to_network_consumer_dataflow_proven": False,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "registry_read_performed": False,
            "raw_config_included": False,
            "raw_strings_included": False,
        },
    }


def probe_ipdate_compact_config(data: bytes) -> dict[str, Any]:
    """detector向けにendpointを含めないroute候補要約を返す。"""

    try:
        recovered = extract_ipdate_compact_config(data)
    except (IndexError, OverflowError, struct.error, IpDateCompactConfigError) as exc:
        code = exc.code if isinstance(exc, IpDateCompactConfigError) else "parse_error"
        return {
            "matched": False,
            "status": "rejected",
            "reason_code": code,
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "candidate_config_recovered": False,
            "static_config_recovered": False,
            "endpoint_count": 0,
            "evidence": {},
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "registry_read_performed": False,
                "raw_config_included": False,
                "raw_strings_included": False,
            },
        }
    return {
        "matched": True,
        "status": recovered["status"],
        "variant": recovered["variant"],
        "family_role": recovered["family_role"],
        "endpoint_role": recovered["endpoint_role"],
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "candidate_config_recovered": True,
        "static_config_recovered": False,
        "endpoint_count": 1,
        "evidence": dict(recovered["evidence"]),
        "safety": dict(recovered["safety"]),
    }


__all__ = [
    "IpDateCompactConfigError",
    "extract_ipdate_compact_config",
    "probe_ipdate_compact_config",
]
