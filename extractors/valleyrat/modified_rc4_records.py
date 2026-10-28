"""Forcepoint報告型のValleyRAT 3-record containerを静的に検証する。

このmoduleは検体を実行せず、外部通信も行わない。3個のlittle-endian長付き
record、115 byte鍵を伴うcore、XOR-swap型RC4、zero化されたPE識別子、
固定長configurationをすべて境界検証する。ただしouter loaderから当該container
への到達性と、復元configからsocket consumerまでのdata-flowは証明しないため、
結果はfamily／C2確定ではなくroute候補としてだけ返す。
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from extractors.common import endpoint_candidates
from extractors.valleyrat.nvml_dat import is_public_host, normalize_host, parse_endpoint

SCHEMA_VERSION = 1
RECORD_COUNT = 3
LENGTH_PREFIX_SIZE = 4
CORE_KEY_LENGTH = 0x73
CORE_PREFIX_SIZE = 1 + CORE_KEY_LENGTH
CONFIG_SIZE = 0xA88
CONFIG_KEY = b"\x01\x02\x03\x04\x05"
MAXIMUM_INPUT_SIZE = 16 * 1024 * 1024
MAXIMUM_RECORD_SIZE = 8 * 1024 * 1024
MAXIMUM_PE_SIZE = 8 * 1024 * 1024
MINIMUM_LOADER_SIZE = 32
MINIMUM_CORE_SIZE = 0x400
MAXIMUM_SECTION_COUNT = 32
MAXIMUM_OPTIONAL_HEADER_SIZE = 0x400
MAXIMUM_CONFIG_STRING_COUNT = 256
MAXIMUM_CONFIG_STRING_LENGTH = 512
_ASCII_STRING = re.compile(rb"[\x20-\x7e]{4,512}")
_UTF16LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){4,512}")
_PATH_OR_FILENAME = re.compile(
    r"(?:[A-Za-z]:\\|(?:^|[\\/])[^\\/]{1,128}\.(?:exe|dll|bin)\Z)",
    re.IGNORECASE,
)


class ModifiedRc4RecordError(ValueError):
    """3-record containerが厳格な構造検証を満たさない場合の例外。"""


@dataclass(frozen=True)
class _PeSummary:
    """復元byteを保持しないPE構造要約。"""

    assembled_size: int
    e_lfanew: int
    machine: int
    section_count: int
    optional_header_magic: int
    entrypoint_rva: int
    image_size: int
    headers_size: int
    executable_section_count: int
    decrypted_core_sha256: str
    reconstructed_pe_sha256: str
    reconstructed_pe: bytes = field(repr=False)


@dataclass(frozen=True)
class _ConfigSummary:
    """復号済みconfig本文を保持しないendpoint要約。"""

    decrypted_sha256: str
    string_count: int
    path_or_filename_marker_count: int
    endpoint_candidates: tuple[str, ...]


@dataclass(frozen=True)
class ModifiedRc4RecordRecovery:
    """公開可能なmetadataだけを保持する3-record検証結果。"""

    input_sha256: str
    input_size: int
    record_sizes: tuple[int, int, int]
    record_sha256: tuple[str, str, str]
    core: _PeSummary
    config: _ConfigSummary

    def public_summary(self) -> dict[str, Any]:
        """生鍵、復元PE、config本文を含まない候補要約を返す。"""

        endpoint_candidates = list(self.config.endpoint_candidates)
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "validated_modified_rc4_record_container_candidate",
            "matched": True,
            "candidate_config_recovered": bool(endpoint_candidates),
            "decrypted_config_recovered": True,
            "static_config_recovered": False,
            "automatic_route_eligible": False,
            "manual_review_required": True,
            "route_validated": False,
            "family": None,
            "family_attribution": "unresolved_container_candidate",
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "command_c2_confirmed": False,
            "liveness_confirmed": False,
            "component_profile": "modified_rc4_three_record_container",
            "input": {
                "sha256": self.input_sha256,
                "size": self.input_size,
                "record_count": RECORD_COUNT,
                "record_sizes": list(self.record_sizes),
                "record_sha256": list(self.record_sha256),
            },
            "core": {
                "core_key_length": CORE_KEY_LENGTH,
                "assembled_size": self.core.assembled_size,
                "e_lfanew": self.core.e_lfanew,
                "machine": f"0x{self.core.machine:04x}",
                "section_count": self.core.section_count,
                "optional_header_magic": f"0x{self.core.optional_header_magic:04x}",
                "entrypoint_rva": self.core.entrypoint_rva,
                "image_size": self.core.image_size,
                "headers_size": self.core.headers_size,
                "executable_section_count": self.core.executable_section_count,
                "decrypted_core_sha256": self.core.decrypted_core_sha256,
                "reconstructed_pe_sha256": self.core.reconstructed_pe_sha256,
                "mz_reconstructed": True,
                "pe_signature_reconstructed": True,
                "zeroed_pe_signature_observed": True,
                "raw_key_included": False,
                "raw_core_included": False,
                "reconstructed_pe_included": False,
            },
            "config": {
                "size": CONFIG_SIZE,
                "decrypted_sha256": self.config.decrypted_sha256,
                "string_count": self.config.string_count,
                "path_or_filename_marker_count": (
                    self.config.path_or_filename_marker_count
                ),
                "endpoint_candidates": endpoint_candidates,
                "endpoint_role": "command_c2_candidate",
                "evidence": (
                    "strict_container_and_decrypted_config_string_correlation_"
                    "without_consumer_dataflow"
                ),
                "raw_config_included": False,
            },
            "transforms": {
                "core": "rc4_ksa_xor_swap_prga",
                "config": "rc4_ksa_xor_swap_prga_fixed_five_byte_key",
                "config_key_length": len(CONFIG_KEY),
                "raw_key_included": False,
            },
            "evidence_boundary": {
                "three_exact_length_prefixed_records": True,
                "core_key_length_115_observed": True,
                "modified_prga_applied": True,
                "non_mz_record_prefix_observed": True,
                "zeroed_pe_reconstruction_validated": True,
                "coff_optional_header_and_sections_validated": True,
                "fixed_size_config_decrypted": True,
                "config_string_structure_validated": True,
                "explicit_endpoint_candidate_recovered": bool(endpoint_candidates),
                "outer_loader_binding_proven": False,
                "config_to_network_consumer_dataflow_proven": False,
                "family_attribution_confirmed": False,
                "c2_confirmed": False,
            },
            "safety": {
                "sample_executed": False,
                "core_executed": False,
                "network_contacted": False,
                "raw_key_included": False,
                "raw_core_included": False,
                "raw_config_included": False,
            },
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _modified_rc4(data: bytes, key: bytes) -> bytes:
    """標準KSAと ``S[i] XOR S[j]`` PRGAを有界に適用する。"""

    if not key or len(key) > 0x100:
        raise ModifiedRc4RecordError("modified RC4 key長が不正です")
    if len(data) > MAXIMUM_PE_SIZE:
        raise ModifiedRc4RecordError("modified RC4入力が上限を超えています")
    state = list(range(0x100))
    swap_index = 0
    for index in range(0x100):
        swap_index = (swap_index + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]
    index = 0
    swap_index = 0
    output = bytearray(data)
    for offset, value in enumerate(output):
        index = (index + 1) & 0xFF
        swap_index = (swap_index + state[index]) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]
        output[offset] = value ^ state[index] ^ state[swap_index]
    return bytes(output)


def _parse_records(data: bytes) -> tuple[bytes, bytes, bytes]:
    """3 recordと末尾zero-length sentinelを厳密に受理する。"""

    if type(data) is not bytes:
        raise ModifiedRc4RecordError("入力はbytesである必要があります")
    if not 4 * LENGTH_PREFIX_SIZE < len(data) <= MAXIMUM_INPUT_SIZE:
        raise ModifiedRc4RecordError("container sizeが許容範囲外です")
    offset = 0
    records: list[bytes] = []
    for index in range(RECORD_COUNT):
        if offset + LENGTH_PREFIX_SIZE > len(data):
            raise ModifiedRc4RecordError(f"record {index + 1}の長さfieldが切れています")
        size = struct.unpack_from("<I", data, offset)[0]
        offset += LENGTH_PREFIX_SIZE
        if not 0 < size <= MAXIMUM_RECORD_SIZE:
            raise ModifiedRc4RecordError(f"record {index + 1}のsizeが許容範囲外です")
        end = offset + size
        if end > len(data):
            raise ModifiedRc4RecordError(
                f"record {index + 1}がcontainer境界を超えています"
            )
        records.append(data[offset:end])
        offset = end
    if offset + LENGTH_PREFIX_SIZE != len(data):
        raise ModifiedRc4RecordError(
            "3 recordの後ろにzero-length sentinel以外のdataがあります"
        )
    if struct.unpack_from("<I", data, offset)[0] != 0:
        raise ModifiedRc4RecordError("3 record末尾のzero-length sentinelがありません")
    loader, core, config = records
    if not MINIMUM_LOADER_SIZE <= len(loader) <= MAXIMUM_RECORD_SIZE:
        raise ModifiedRc4RecordError("record 1のloader sizeが不正です")
    if not MINIMUM_CORE_SIZE <= len(core) <= MAXIMUM_PE_SIZE:
        raise ModifiedRc4RecordError("record 2のcore sizeが不正です")
    if len(config) != CONFIG_SIZE:
        raise ModifiedRc4RecordError("record 3のconfig sizeが0xA88ではありません")
    return loader, core, config


def _validate_section_ranges(
    pe: bytes,
    *,
    section_table_offset: int,
    section_count: int,
    image_size: int,
    headers_size: int,
) -> int:
    """section table、raw範囲、virtual範囲、重複を検証する。"""

    table_end = section_table_offset + section_count * 40
    if table_end > len(pe) or headers_size < table_end:
        raise ModifiedRc4RecordError("section tableがheader境界を超えています")
    raw_ranges: list[tuple[int, int]] = []
    virtual_ranges: list[tuple[int, int]] = []
    executable_count = 0
    for index in range(section_count):
        offset = section_table_offset + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", pe, offset + 8
        )
        characteristics = struct.unpack_from("<I", pe, offset + 36)[0]
        virtual_span = max(virtual_size, raw_size)
        if not virtual_address or not virtual_span:
            raise ModifiedRc4RecordError(f"section {index + 1}のvirtual範囲が空です")
        if virtual_address + virtual_span > image_size:
            raise ModifiedRc4RecordError(
                f"section {index + 1}がSizeOfImageを超えています"
            )
        virtual_ranges.append((virtual_address, virtual_address + virtual_span))
        if raw_size:
            if raw_pointer < headers_size or raw_pointer + raw_size > len(pe):
                raise ModifiedRc4RecordError(f"section {index + 1}のraw範囲が不正です")
            raw_ranges.append((raw_pointer, raw_pointer + raw_size))
        if characteristics & 0x20000000:
            executable_count += 1
    for ranges, name in ((raw_ranges, "raw"), (virtual_ranges, "virtual")):
        ordered = sorted(ranges)
        if any(left[1] > right[0] for left, right in pairwise(ordered)):
            raise ModifiedRc4RecordError(f"section {name}範囲が重複しています")
    if not executable_count:
        raise ModifiedRc4RecordError("実行可能sectionがありません")
    return executable_count


def _recover_core(record: bytes) -> _PeSummary:
    """record 2を復号し、zero化されたPEを再構築して境界検証する。"""

    if record[0] != CORE_KEY_LENGTH:
        raise ModifiedRc4RecordError("record 2のkey lengthが0x73ではありません")
    key_end = CORE_PREFIX_SIZE
    if len(record) <= key_end:
        raise ModifiedRc4RecordError("record 2にciphertextがありません")
    key = record[1:key_end]
    decrypted = _modified_rc4(record[key_end:], key)
    assembled = record[:key_end] + decrypted
    if len(assembled) > MAXIMUM_PE_SIZE or len(assembled) < MINIMUM_CORE_SIZE:
        raise ModifiedRc4RecordError("復元core sizeが許容範囲外です")
    if assembled.startswith(b"MZ"):
        raise ModifiedRc4RecordError(
            "Forcepoint型coreのlength／key prefix形状ではありません"
        )
    if len(assembled) < 0x40:
        raise ModifiedRc4RecordError("coreにe_lfanew fieldがありません")
    e_lfanew = struct.unpack_from("<I", assembled, 0x3C)[0]
    if not CORE_PREFIX_SIZE <= e_lfanew <= len(assembled) - 24:
        raise ModifiedRc4RecordError("key領域のe_lfanewがcore境界外です")
    if assembled[e_lfanew : e_lfanew + 4] != b"\0\0\0\0":
        raise ModifiedRc4RecordError("zero化されたPE signatureを確認できません")
    reconstructed = bytearray(assembled)
    reconstructed[0:2] = b"MZ"
    reconstructed[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    pe = bytes(reconstructed)

    coff_offset = e_lfanew + 4
    (
        machine,
        section_count,
        _timestamp,
        _symbol_table,
        _symbol_count,
        optional_size,
        _characteristics,
    ) = struct.unpack_from("<HHIIIHH", pe, coff_offset)
    if machine != 0x8664:
        raise ModifiedRc4RecordError("coreのCOFF machineがAMD64ではありません")
    if not 1 <= section_count <= MAXIMUM_SECTION_COUNT:
        raise ModifiedRc4RecordError("coreのsection countが許容範囲外です")
    if not 0x70 <= optional_size <= MAXIMUM_OPTIONAL_HEADER_SIZE:
        raise ModifiedRc4RecordError("optional header sizeが許容範囲外です")
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if optional_end > len(pe):
        raise ModifiedRc4RecordError("optional headerがcore境界を超えています")
    optional_magic = struct.unpack_from("<H", pe, optional_offset)[0]
    if optional_magic != 0x20B:
        raise ModifiedRc4RecordError("coreがPE32+ではありません")
    if optional_size < 0x70:
        raise ModifiedRc4RecordError("PE32+ optional headerが短すぎます")
    entrypoint_rva = struct.unpack_from("<I", pe, optional_offset + 0x10)[0]
    section_alignment = struct.unpack_from("<I", pe, optional_offset + 0x20)[0]
    file_alignment = struct.unpack_from("<I", pe, optional_offset + 0x24)[0]
    image_size = struct.unpack_from("<I", pe, optional_offset + 0x38)[0]
    headers_size = struct.unpack_from("<I", pe, optional_offset + 0x3C)[0]
    if (
        not _is_power_of_two(file_alignment)
        or not _is_power_of_two(section_alignment)
        or not 0x200 <= file_alignment <= 0x10000
        or not file_alignment <= section_alignment <= 0x100000
    ):
        raise ModifiedRc4RecordError("PE alignmentが不正です")
    if not headers_size <= len(pe) or headers_size % file_alignment:
        raise ModifiedRc4RecordError("SizeOfHeadersが不正です")
    if (
        not headers_size < image_size <= MAXIMUM_PE_SIZE
        or image_size % section_alignment
    ):
        raise ModifiedRc4RecordError("SizeOfImageが不正です")
    if entrypoint_rva >= image_size:
        raise ModifiedRc4RecordError("entrypoint RVAがSizeOfImageを超えています")
    executable_count = _validate_section_ranges(
        pe,
        section_table_offset=optional_end,
        section_count=section_count,
        image_size=image_size,
        headers_size=headers_size,
    )
    return _PeSummary(
        assembled_size=len(assembled),
        e_lfanew=e_lfanew,
        machine=machine,
        section_count=section_count,
        optional_header_magic=optional_magic,
        entrypoint_rva=entrypoint_rva,
        image_size=image_size,
        headers_size=headers_size,
        executable_section_count=executable_count,
        decrypted_core_sha256=_sha256(assembled),
        reconstructed_pe_sha256=_sha256(pe),
        reconstructed_pe=pe,
    )


def _bounded_config_strings(config: bytes) -> tuple[str, ...]:
    """復号configからASCII/UTF-16LE文字列を重複なく有界抽出する。"""

    values: list[str] = []
    seen: set[str] = set()
    for pattern, encoding in ((_ASCII_STRING, "ascii"), (_UTF16LE_STRING, "utf-16le")):
        for match in pattern.finditer(config):
            try:
                value = match.group().decode(encoding, errors="strict")
            except UnicodeDecodeError:
                continue
            if not 4 <= len(value) <= MAXIMUM_CONFIG_STRING_LENGTH or value in seen:
                continue
            values.append(value)
            seen.add(value)
            if len(values) > MAXIMUM_CONFIG_STRING_COUNT:
                raise ModifiedRc4RecordError("config文字列数が上限を超えています")
    return tuple(values)


def _public_endpoint_candidates(strings: tuple[str, ...]) -> tuple[str, ...]:
    """明示的なhost:portだけを抽出し、placeholderを除外する。"""

    results: set[str] = set()
    for value in endpoint_candidates(strings):
        parsed = parse_endpoint(value)
        if parsed is None:
            continue
        host, _port = parsed
        normalized = normalize_host(host)
        if normalized is None:
            continue
        if not is_public_host(normalized):
            continue
        results.add(value)
    return tuple(sorted(results))


def _recover_config(record: bytes) -> _ConfigSummary:
    """固定5 byte鍵でconfigを復号し、文字列構造とendpoint候補を検証する。"""

    if len(record) != CONFIG_SIZE:
        raise ModifiedRc4RecordError("config record sizeが0xA88ではありません")
    config = _modified_rc4(record, CONFIG_KEY)
    strings = _bounded_config_strings(config)
    path_or_filename_count = sum(
        _PATH_OR_FILENAME.search(value) is not None for value in strings
    )
    endpoints = _public_endpoint_candidates(strings)
    # 公開解析で確認された設定はinstall path、companion filename、C2を含む。
    # 固定offsetを推測せず、少なくとも複数文字列とpath/filenameまたは明示的
    # endpointの相関がある場合だけ、固定鍵による復号成功と扱う。
    if len(strings) < 2 or not (path_or_filename_count or endpoints):
        raise ModifiedRc4RecordError("復号configの文字列構造を検証できません")
    return _ConfigSummary(
        decrypted_sha256=_sha256(config),
        string_count=len(strings),
        path_or_filename_marker_count=path_or_filename_count,
        endpoint_candidates=endpoints,
    )


def recover_modified_rc4_records(data: bytes) -> ModifiedRc4RecordRecovery:
    """厳格な3-record containerだけを静的復元し、metadataを返す。"""

    loader, core_record, config_record = _parse_records(data)
    core = _recover_core(core_record)
    config = _recover_config(config_record)
    records = (loader, core_record, config_record)
    return ModifiedRc4RecordRecovery(
        input_sha256=_sha256(data),
        input_size=len(data),
        record_sizes=tuple(len(item) for item in records),
        record_sha256=tuple(_sha256(item) for item in records),
        core=core,
        config=config,
    )


def probe_modified_rc4_records(data: bytes) -> dict[str, Any] | None:
    """形式不一致を例外化せず、公開可能な候補要約または ``None`` を返す。"""

    try:
        recovery = recover_modified_rc4_records(data)
    except (IndexError, OverflowError, struct.error, ModifiedRc4RecordError):
        return None
    return recovery.public_summary()


__all__ = [
    "CONFIG_KEY",
    "CONFIG_SIZE",
    "CORE_KEY_LENGTH",
    "ModifiedRc4RecordError",
    "ModifiedRc4RecordRecovery",
    "probe_modified_rc4_records",
    "recover_modified_rc4_records",
]
