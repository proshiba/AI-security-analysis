"""OIS報告型 ``Server.log`` を全体RC4復号して静的に検証する。

このmoduleは、公開解析で確認された16-byte鍵を内部でだけ使用する。入力全体へ
標準RC4を適用し、復元物が境界の閉じたPE32 i386 DLLであること、export
``NtHandleCallback`` と一意な反転p/o/t設定を同時に確認した場合だけ返す。

外層 ``log.dll`` から当該fileへのdata-flowは、このroute単独では証明しない。
したがって結果は復元online module候補であり、family／C2確定には使用しない。
復元PEは実行せず、次の静的解析層へだけ渡す。
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import struct
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from extractors.valleyrat.nvml_dat import normalize_host, render_endpoint

SCHEMA_VERSION = 1
MINIMUM_INPUT_SIZE = 0x400
MAXIMUM_INPUT_SIZE = 32 * 1024 * 1024
MAXIMUM_SECTION_COUNT = 96
MAXIMUM_EXPORT_COUNT = 65_536
MAXIMUM_EXPORT_NAME_LENGTH = 256
MAXIMUM_DOS_STUB_SIZE = 1024 * 1024
MAXIMUM_CONFIG_CANDIDATES = 64
MAXIMUM_CONFIG_CHARACTERS = 8_192
MAXIMUM_SCANNED_SECTION_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_SCANNED_BYTES = 24 * 1024 * 1024

# 公開resultへはkeyそのものを含めない。
_SERVER_LOG_RC4_KEY = b"??Bid@locale@std"
_KNOWN_CONTAINER_MAGICS = (
    b"MZ",
    b"PK\x03\x04",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    bytes.fromhex("d0cf11e0a1b11ae1"),
    b"\x7fELF",
)
_BASE_FIELD_ORDER = (
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
    "bb",
    "bz",
    "jp",
    "bh",
    "ll",
    "dl",
    "sh",
    "kl",
    "bd",
)
_BOOLEAN_FIELDS = ("jp", "bh", "ll", "dl", "sh", "kl", "bd")
_VERSION = re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,5}){0,3}\Z")
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.IGNORECASE,
)


class ServerLogRc4Error(ValueError):
    """``Server.log`` routeの厳格な検証に失敗した場合の例外。"""


@dataclass(frozen=True)
class _Section:
    """検証済みPE sectionのfile-backed view。"""

    name: str
    virtual_start: int
    virtual_end: int
    raw_start: int
    raw_end: int
    executable: bool
    resource: bool


@dataclass(frozen=True)
class _PeSummary:
    """復元byteを含まないPE構造要約。"""

    e_lfanew: int
    section_count: int
    entrypoint_rva: int
    image_size: int
    headers_size: int
    named_export_count: int
    target_export_rva: int
    executable_section_count: int


@dataclass(frozen=True)
class _ConfigSummary:
    """設定本文を含まない、一意な反転設定の要約。"""

    identity_sha256: str
    observed_candidate_count: int
    valid_candidate_count: int
    slots: tuple[dict[str, object], ...]
    endpoints: tuple[str, ...]


@dataclass(frozen=True)
class ServerLogRc4Recovery:
    """公開metadataと、次段だけへ渡す非公開の復元PEを保持する。"""

    input_sha256: str
    input_size: int
    recovered_sha256: str
    recovered_size: int
    pe: _PeSummary
    config: _ConfigSummary
    recovered_payload: bytes = field(repr=False)

    def public_summary(self) -> dict[str, Any]:
        """鍵、暗号文、復元PE、完全設定を含まない要約を返す。"""

        return {
            "schema_version": SCHEMA_VERSION,
            "status": "validated_server_log_rc4_route_candidate",
            "matched": True,
            "candidate_config_recovered": True,
            "decrypted_config_recovered": True,
            "static_config_recovered": False,
            "family": None,
            "family_attribution": "unresolved_online_module_route",
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "command_c2_confirmed": False,
            "liveness_confirmed": False,
            "component_profile": "server_log_whole_file_standard_rc4",
            "input": {
                "sha256": self.input_sha256,
                "size": self.input_size,
                "whole_file_decrypted": True,
                "raw_ciphertext_included": False,
            },
            "recovered_pe": {
                "sha256": self.recovered_sha256,
                "size": self.recovered_size,
                "machine": "0x014c",
                "optional_header_magic": "0x010b",
                "dll": True,
                "e_lfanew": self.pe.e_lfanew,
                "section_count": self.pe.section_count,
                "entrypoint_rva": self.pe.entrypoint_rva,
                "image_size": self.pe.image_size,
                "headers_size": self.pe.headers_size,
                "named_export_count": self.pe.named_export_count,
                "required_export": "NtHandleCallback",
                "required_export_count": 1,
                "required_export_rva": self.pe.target_export_rva,
                "executable_section_count": self.pe.executable_section_count,
                "raw_pe_included": False,
            },
            "config": {
                "format": "whole_string_reversed_utf16le_pipe_fields",
                "identity_sha256": self.config.identity_sha256,
                "observed_candidate_count": self.config.observed_candidate_count,
                "valid_candidate_count": self.config.valid_candidate_count,
                "unique_configuration_count": 1,
                "slots": [dict(item) for item in self.config.slots],
                "endpoints": list(self.config.endpoints),
                "endpoint_role": "interactive_c2_candidate",
                "raw_configuration_included": False,
            },
            "transforms": {
                "cipher": "standard_rc4",
                "key_length": len(_SERVER_LOG_RC4_KEY),
                "ciphertext_range": "whole_input",
                "raw_key_included": False,
            },
            "evidence_boundary": {
                "whole_file_rc4_applied": True,
                "pe32_i386_dll_validated": True,
                "section_boundaries_validated": True,
                "nt_handle_callback_export_validated": True,
                "unique_reversed_config_validated": True,
                "outer_log_dll_binding_proven": False,
                "family_attribution_confirmed": False,
                "c2_confirmed": False,
            },
            "safety": {
                "sample_executed": False,
                "recovered_pe_executed": False,
                "network_contacted": False,
                "raw_key_included": False,
                "raw_ciphertext_included": False,
                "raw_pe_included": False,
                "raw_configuration_included": False,
            },
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _standard_rc4(data: bytes) -> bytes:
    """固定鍵で標準RC4 KSA／PRGAを入力全体へ適用する。"""

    state = list(range(0x100))
    swap_index = 0
    for index in range(0x100):
        swap_index = (
            swap_index
            + state[index]
            + _SERVER_LOG_RC4_KEY[index % len(_SERVER_LOG_RC4_KEY)]
        ) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]
    index = 0
    swap_index = 0
    output = bytearray(len(data))
    for offset, value in enumerate(data):
        index = (index + 1) & 0xFF
        swap_index = (swap_index + state[index]) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]
        key_byte = state[(state[index] + state[swap_index]) & 0xFF]
        output[offset] = value ^ key_byte
    return bytes(output)


def _read_ascii_z(data: bytes, offset: int, *, limit: int) -> str:
    if not 0 <= offset < len(data):
        raise ServerLogRc4Error("export name offsetがPE境界外です")
    end = data.find(b"\0", offset, min(len(data), offset + limit + 1))
    if end < 0 or end == offset:
        raise ServerLogRc4Error("export nameがNUL終端されていません")
    try:
        value = data[offset:end].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ServerLogRc4Error("export nameがASCIIではありません") from exc
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise ServerLogRc4Error("export nameに非表示文字があります")
    return value


def _rva_to_raw(
    rva: int,
    size: int,
    sections: tuple[_Section, ...],
) -> int:
    if size < 0:
        raise ServerLogRc4Error("RVA sizeが負です")
    for section in sections:
        raw_size = section.raw_end - section.raw_start
        delta = rva - section.virtual_start
        if 0 <= delta <= raw_size and size <= raw_size - delta:
            return section.raw_start + delta
    raise ServerLogRc4Error("RVAがfile-backed section境界外です")


def _parse_sections(
    data: bytes,
    *,
    section_table_offset: int,
    section_count: int,
    headers_size: int,
    image_size: int,
    resource_rva: int,
) -> tuple[_Section, ...]:
    table_end = section_table_offset + section_count * 40
    if table_end > len(data) or table_end > headers_size:
        raise ServerLogRc4Error("section tableがheader境界を超えています")
    sections: list[_Section] = []
    raw_ranges: list[tuple[int, int]] = []
    virtual_ranges: list[tuple[int, int]] = []
    for index in range(section_count):
        offset = section_table_offset + index * 40
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise ServerLogRc4Error("section名がASCIIではありません") from exc
        virtual_size, virtual_start, raw_size, raw_start = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        virtual_span = max(virtual_size, raw_size)
        if not virtual_start or not virtual_span:
            raise ServerLogRc4Error(f"section {index + 1}が空です")
        virtual_end = virtual_start + virtual_span
        if virtual_end <= virtual_start or virtual_end > image_size:
            raise ServerLogRc4Error(f"section {index + 1}のvirtual範囲が不正です")
        virtual_ranges.append((virtual_start, virtual_end))
        if raw_size:
            raw_end = raw_start + raw_size
            if (
                raw_start < headers_size
                or raw_end <= raw_start
                or raw_end > len(data)
            ):
                raise ServerLogRc4Error(f"section {index + 1}のraw範囲が不正です")
            raw_ranges.append((raw_start, raw_end))
        else:
            raw_end = raw_start
        resource = (
            name.casefold() == ".rsrc"
            or bool(resource_rva and virtual_start <= resource_rva < virtual_end)
        )
        sections.append(
            _Section(
                name=name,
                virtual_start=virtual_start,
                virtual_end=virtual_end,
                raw_start=raw_start,
                raw_end=raw_end,
                executable=bool(characteristics & 0x20000000),
                resource=resource,
            )
        )
    for ranges, label in ((raw_ranges, "raw"), (virtual_ranges, "virtual")):
        ordered = sorted(ranges)
        if any(left[1] > right[0] for left, right in pairwise(ordered)):
            raise ServerLogRc4Error(f"section {label}範囲が重複しています")
    if not any(section.executable for section in sections):
        raise ServerLogRc4Error("実行可能sectionがありません")
    return tuple(sections)


def _validate_exports(
    data: bytes,
    sections: tuple[_Section, ...],
    *,
    export_rva: int,
    export_size: int,
) -> tuple[int, int]:
    if export_size < 40:
        raise ServerLogRc4Error("export directoryが短すぎます")
    directory_offset = _rva_to_raw(export_rva, 40, sections)
    (
        _characteristics,
        _timestamp,
        _major,
        _minor,
        _name_rva,
        _base,
        function_count,
        name_count,
        functions_rva,
        names_rva,
        ordinals_rva,
    ) = struct.unpack_from("<IIHHIIIIIII", data, directory_offset)
    if (
        not 1 <= function_count <= MAXIMUM_EXPORT_COUNT
        or not 1 <= name_count <= function_count
        or name_count > MAXIMUM_EXPORT_COUNT
    ):
        raise ServerLogRc4Error("export countが許容範囲外です")
    functions_offset = _rva_to_raw(functions_rva, function_count * 4, sections)
    names_offset = _rva_to_raw(names_rva, name_count * 4, sections)
    ordinals_offset = _rva_to_raw(ordinals_rva, name_count * 2, sections)
    target_rvas: list[int] = []
    for index in range(name_count):
        name_rva = struct.unpack_from("<I", data, names_offset + index * 4)[0]
        name_offset = _rva_to_raw(name_rva, 1, sections)
        name = _read_ascii_z(
            data,
            name_offset,
            limit=MAXIMUM_EXPORT_NAME_LENGTH,
        )
        ordinal = struct.unpack_from("<H", data, ordinals_offset + index * 2)[0]
        if ordinal >= function_count:
            raise ServerLogRc4Error("export ordinalがfunction table境界外です")
        function_rva = struct.unpack_from(
            "<I", data, functions_offset + ordinal * 4
        )[0]
        if name == "NtHandleCallback":
            target_rvas.append(function_rva)
    if len(target_rvas) != 1:
        raise ServerLogRc4Error("NtHandleCallback exportが一意ではありません")
    target_rva = target_rvas[0]
    if export_rva <= target_rva < export_rva + export_size:
        raise ServerLogRc4Error("NtHandleCallbackがforwarded exportです")
    if not any(
        section.executable
        and section.virtual_start <= target_rva < section.virtual_end
        for section in sections
    ):
        raise ServerLogRc4Error("NtHandleCallbackが実行可能section内にありません")
    return name_count, target_rva


def _validate_pe(data: bytes) -> tuple[_PeSummary, tuple[_Section, ...]]:
    if len(data) < MINIMUM_INPUT_SIZE or not data.startswith(b"MZ"):
        raise ServerLogRc4Error("復号結果がMZ PEではありません")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if not 0x40 <= e_lfanew <= len(data) - 24:
        raise ServerLogRc4Error("e_lfanewがPE境界外です")
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ServerLogRc4Error("PE signatureがありません")
    coff_offset = e_lfanew + 4
    (
        machine,
        section_count,
        _timestamp,
        _symbol_table,
        _symbol_count,
        optional_size,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_offset)
    if machine != 0x14C:
        raise ServerLogRc4Error("復号PEがi386ではありません")
    if not 1 <= section_count <= MAXIMUM_SECTION_COUNT:
        raise ServerLogRc4Error("section countが許容範囲外です")
    if characteristics & 0x2000 == 0 or characteristics & 0x0002 == 0:
        raise ServerLogRc4Error("復号PEが実行可能DLLではありません")
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if optional_size < 0xE0 or optional_end > len(data):
        raise ServerLogRc4Error("PE32 optional headerが短いか切れています")
    if struct.unpack_from("<H", data, optional_offset)[0] != 0x10B:
        raise ServerLogRc4Error("復号PEがPE32ではありません")
    entrypoint_rva = struct.unpack_from("<I", data, optional_offset + 0x10)[0]
    section_alignment = struct.unpack_from("<I", data, optional_offset + 0x20)[0]
    file_alignment = struct.unpack_from("<I", data, optional_offset + 0x24)[0]
    image_size = struct.unpack_from("<I", data, optional_offset + 0x38)[0]
    headers_size = struct.unpack_from("<I", data, optional_offset + 0x3C)[0]
    directory_count = struct.unpack_from("<I", data, optional_offset + 0x5C)[0]
    if (
        not _is_power_of_two(file_alignment)
        or not _is_power_of_two(section_alignment)
        or not 0x200 <= file_alignment <= 0x10000
        or not file_alignment <= section_alignment <= 0x100000
    ):
        raise ServerLogRc4Error("PE alignmentが不正です")
    if (
        not headers_size <= len(data)
        or headers_size % file_alignment
        or not headers_size < image_size <= MAXIMUM_INPUT_SIZE
        or image_size % section_alignment
    ):
        raise ServerLogRc4Error("SizeOfHeadersまたはSizeOfImageが不正です")
    if directory_count < 3 or optional_size < 0x60 + min(directory_count, 16) * 8:
        raise ServerLogRc4Error("PE data directoryが不足しています")
    export_rva, export_size = struct.unpack_from(
        "<II", data, optional_offset + 0x60
    )
    resource_rva, _resource_size = struct.unpack_from(
        "<II", data, optional_offset + 0x60 + 2 * 8
    )
    if not export_rva or not export_size:
        raise ServerLogRc4Error("export directoryがありません")
    sections = _parse_sections(
        data,
        section_table_offset=optional_end,
        section_count=section_count,
        headers_size=headers_size,
        image_size=image_size,
        resource_rva=resource_rva,
    )
    if not entrypoint_rva or not any(
        section.executable
        and section.virtual_start <= entrypoint_rva < section.virtual_end
        for section in sections
    ):
        raise ServerLogRc4Error("entrypointが実行可能section内にありません")
    named_export_count, target_export_rva = _validate_exports(
        data,
        sections,
        export_rva=export_rva,
        export_size=export_size,
    )
    return (
        _PeSummary(
            e_lfanew=e_lfanew,
            section_count=section_count,
            entrypoint_rva=entrypoint_rva,
            image_size=image_size,
            headers_size=headers_size,
            named_export_count=named_export_count,
            target_export_rva=target_export_rva,
            executable_section_count=sum(
                section.executable for section in sections
            ),
        ),
        sections,
    )


def _is_public_host(value: str) -> str | None:
    normalized = normalize_host(value)
    if normalized is None:
        return None
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        folded = normalized.casefold().rstrip(".")
        if _DOMAIN.fullmatch(folded) is None:
            return None
        if folded.endswith((".example", ".invalid", ".localhost", ".test")):
            return None
        return folded
    if not address.is_global:
        return None
    return address.compressed


def _bounded_text(value: str, *, allow_empty: bool = False) -> bool:
    if not value:
        return allow_empty
    return len(value) <= 128 and all(
        character.isprintable() and character not in "|\r\n"
        for character in value
    )


def _parse_reversed_config(
    value: str,
) -> tuple[str, tuple[dict[str, object], ...], tuple[str, ...]] | None:
    if (
        not 16 <= len(value) <= MAXIMUM_CONFIG_CHARACTERS
        or value[0] != "|"
        or value[-1] != "|"
        or ":1p" not in value.casefold()
    ):
        return None
    plaintext = value[::-1]
    tokens = plaintext[1:-1].split("|")
    fields: list[tuple[str, str]] = []
    for token in tokens:
        if ":" not in token:
            return None
        key, raw = token.split(":", 1)
        fields.append((key.casefold(), raw.strip()))
    if tuple(key for key, _raw in fields) != _BASE_FIELD_ORDER:
        return None
    values = dict(fields)
    for field_name in ("dd", "cl"):
        raw = values[field_name]
        if not raw.isdigit() or not 0 <= int(raw) <= 0x7FFFFFFF:
            return None
    if _VERSION.fullmatch(values["bb"]) is None:
        return None
    if not _bounded_text(values["fz"]) or not _bounded_text(values["bz"]):
        return None
    if any(values[field] not in {"0", "1"} for field in _BOOLEAN_FIELDS):
        return None
    slots: list[dict[str, object]] = []
    endpoints: list[str] = []
    identity_slots: list[tuple[int, str, int, int]] = []
    for index in (1, 2, 3):
        raw_host = values[f"p{index}"]
        raw_port = values[f"o{index}"]
        selector = values[f"t{index}"]
        if selector not in {"0", "1"}:
            return None
        if bool(raw_host) != bool(raw_port):
            return None
        transport_selector = int(selector)
        if not raw_host:
            identity_slots.append((index, "", 0, transport_selector))
            slots.append(
                {
                    "slot": index,
                    "endpoint": None,
                    "transport": "tcp" if transport_selector == 1 else "udp",
                    "transport_selector": transport_selector,
                    "configured": False,
                }
            )
            continue
        host = _is_public_host(raw_host)
        if host is None or not raw_port.isdigit():
            return None
        port = int(raw_port)
        if not 1 <= port <= 65535:
            return None
        endpoint = render_endpoint(host, port)
        if endpoint is None:
            return None
        identity_slots.append((index, host, port, transport_selector))
        slots.append(
            {
                "slot": index,
                "endpoint": endpoint,
                "transport": "tcp" if transport_selector == 1 else "udp",
                "transport_selector": transport_selector,
                "configured": True,
            }
        )
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    if not endpoints:
        return None
    canonical = "\n".join(
        f"{index}|{host}|{port}|{selector}"
        for index, host, port, selector in identity_slots
    )
    canonical += "\n" + "\n".join(
        f"{field}={values[field]}"
        for field in _BASE_FIELD_ORDER[9:]
    )
    return (
        hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        tuple(slots),
        tuple(endpoints),
    )


def _utf16_config_candidates(
    data: bytes,
    sections: tuple[_Section, ...],
) -> tuple[str, ...]:
    candidates: list[str] = []
    seen: set[tuple[int, int]] = set()
    total_scanned = 0
    markers = (
        b":\x001\x00p\x00",
        b":\x001\x00P\x00",
    )
    for section in sections:
        if section.resource or section.raw_end <= section.raw_start:
            continue
        size = section.raw_end - section.raw_start
        if size > MAXIMUM_SCANNED_SECTION_BYTES:
            raise ServerLogRc4Error("設定候補sectionが走査上限を超えています")
        total_scanned += size
        if total_scanned > MAXIMUM_TOTAL_SCANNED_BYTES:
            raise ServerLogRc4Error("設定候補の総走査量が上限を超えています")
        raw = data[section.raw_start : section.raw_end]
        for marker in markers:
            cursor = 0
            while True:
                hit = raw.find(marker, cursor)
                if hit < 0:
                    break
                cursor = hit + 2
                alignment = hit & 1
                start = hit
                while start - 2 >= alignment and raw[start - 2 : start] != b"\0\0":
                    start -= 2
                    if hit - start > MAXIMUM_CONFIG_CHARACTERS * 2:
                        break
                end = hit + len(marker)
                while end + 2 <= len(raw) and raw[end : end + 2] != b"\0\0":
                    end += 2
                    if end - start > MAXIMUM_CONFIG_CHARACTERS * 2:
                        break
                if end - start > MAXIMUM_CONFIG_CHARACTERS * 2:
                    continue
                key = (section.raw_start + start, section.raw_start + end)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    value = raw[start:end].decode("utf-16le", errors="strict")
                except UnicodeDecodeError:
                    continue
                candidates.append(value)
                if len(candidates) > MAXIMUM_CONFIG_CANDIDATES:
                    raise ServerLogRc4Error("反転設定候補数が上限を超えています")
    return tuple(candidates)


def _recover_config(
    data: bytes,
    sections: tuple[_Section, ...],
) -> _ConfigSummary:
    candidates = _utf16_config_candidates(data, sections)
    valid: list[
        tuple[str, tuple[dict[str, object], ...], tuple[str, ...]]
    ] = []
    for candidate in candidates:
        parsed = _parse_reversed_config(candidate)
        if parsed is not None:
            valid.append(parsed)
    unique: dict[
        str,
        tuple[tuple[dict[str, object], ...], tuple[str, ...]],
    ] = {}
    for identity, slots, endpoints in valid:
        unique[identity] = (slots, endpoints)
    if len(unique) != 1:
        raise ServerLogRc4Error("一意な反転p/o/t設定を検証できません")
    identity, (slots, endpoints) = next(iter(unique.items()))
    return _ConfigSummary(
        identity_sha256=identity,
        observed_candidate_count=len(candidates),
        valid_candidate_count=len(valid),
        slots=slots,
        endpoints=endpoints,
    )


def recover_server_log_rc4(data: bytes) -> ServerLogRc4Recovery:
    """``Server.log`` 全体を復号し、厳格なroute-only証跡を返す。"""

    if type(data) is not bytes:
        raise ServerLogRc4Error("入力はbytesである必要があります")
    if not MINIMUM_INPUT_SIZE <= len(data) <= MAXIMUM_INPUT_SIZE:
        raise ServerLogRc4Error("Server.log sizeが許容範囲外です")
    if data.startswith(_KNOWN_CONTAINER_MAGICS):
        raise ServerLogRc4Error("既知の平文containerはServer.log routeで扱いません")
    # 全未知入力をPythonで全体復号しない。RC4 streamの先頭だけを独立に
    # 再生成し、DOS／COFF境界が成立した場合に限って入力全体へ進む。
    prefix = _standard_rc4(data[:0x40])
    if not prefix.startswith(b"MZ"):
        raise ServerLogRc4Error("RC4復号先頭がMZではありません")
    e_lfanew = struct.unpack_from("<I", prefix, 0x3C)[0]
    if not 0x40 <= e_lfanew <= min(len(data) - 24, MAXIMUM_DOS_STUB_SIZE):
        raise ServerLogRc4Error("RC4復号先頭のe_lfanewが許容範囲外です")
    header = _standard_rc4(data[: e_lfanew + 24])
    if header[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ServerLogRc4Error("RC4復号prefixにPE signatureがありません")
    machine, section_count = struct.unpack_from("<HH", header, e_lfanew + 4)
    optional_size, characteristics = struct.unpack_from(
        "<HH", header, e_lfanew + 20
    )
    if (
        machine != 0x14C
        or not 1 <= section_count <= MAXIMUM_SECTION_COUNT
        or optional_size < 0xE0
        or characteristics & 0x2002 != 0x2002
    ):
        raise ServerLogRc4Error("RC4復号prefixのCOFF構造が対象外です")
    recovered = _standard_rc4(data)
    pe, sections = _validate_pe(recovered)
    config = _recover_config(recovered, sections)
    return ServerLogRc4Recovery(
        input_sha256=_sha256(data),
        input_size=len(data),
        recovered_sha256=_sha256(recovered),
        recovered_size=len(recovered),
        pe=pe,
        config=config,
        recovered_payload=recovered,
    )


__all__ = [
    "MAXIMUM_INPUT_SIZE",
    "ServerLogRc4Error",
    "ServerLogRc4Recovery",
    "recover_server_log_rc4",
]
