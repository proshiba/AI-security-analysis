#!/usr/bin/env python3
"""full process dumpから実行せずにPE候補を回収する。

入力全体の ``MZ`` を走査し、PEヘッダー、section、``SizeOfImage`` を
境界付きで検証する。通常のfile-layoutとmapped-layoutに加え、メモリ上に
しか存在しないsectionを保存する ``expanded_memory_sections`` モードを
提供する。検体の実行、エミュレーション、外部通信は一切行わない。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import pefile

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from common.safe_private_output import (
    reject_existing_reparse_components,
    write_private_outputs,
)

DEFAULT_MAX_INPUT_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_CANDIDATES = 4096
DEFAULT_MAX_CANDIDATE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_SECTIONS = 96
MAX_E_LFANEW = 1024 * 1024
INVALID_CANDIDATE_HASH_WINDOW = 4096
REPORT_NAME = "recovery-report.json"

DOS_HEADER_SIZE = 0x40
COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B
KNOWN_MACHINES = frozenset(
    {
        0x014C,  # I386
        0x01C0,  # ARM
        0x01C4,  # ARMNT
        0x0200,  # IA64
        0x8664,  # AMD64
        0xAA64,  # ARM64
        0xA641,  # ARM64EC
    }
)

MappedMode = Literal["auto", "original_raw", "expanded_memory_sections", "both"]


class ProcessDumpPEError(ValueError):
    """安全上の制約または回収処理の失敗を表す。"""


class CandidateRejected(ValueError):
    """1つのMZ候補が構造検証を満たさないことを表す。"""


@dataclass(frozen=True)
class SectionInfo:
    """検証済みPE section header。"""

    index: int
    name: str
    header_offset: int
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int


@dataclass(frozen=True)
class PEInfo:
    """回収に必要な検証済みPEヘッダー情報。"""

    machine: int
    section_count: int
    optional_magic: int
    image_base: int
    entrypoint_rva: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    section_table_end: int
    file_span: int
    security_directory_field_offset: int | None
    security_offset: int
    security_size: int
    sections: tuple[SectionInfo, ...]


@dataclass
class LayoutAttempt:
    """1つのlayoutで復元した候補と選択用の静的証拠。"""

    payload: bytes
    layout: str
    mapped_mode: str | None
    source_span: int
    score: int
    entrypoint_backed: bool
    evidence: dict[str, Any]


@dataclass(frozen=True)
class RecoveredPE:
    """書き込み前の復元PEと公開可能なメタデータ。"""

    payload: bytes
    metadata: dict[str, Any]


def _positive(value: int, name: str) -> int:
    if value <= 0:
        raise ProcessDumpPEError(f"{name}は正の整数で指定してください")
    return value


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _align_up(value: int, alignment: int) -> int:
    if value < 0 or not _is_power_of_two(alignment):
        raise CandidateRejected("alignmentまたは対象サイズが不正です")
    return (value + alignment - 1) & ~(alignment - 1)


def _read_u16(data: bytes, offset: int, end: int, label: str) -> int:
    if offset < 0 or offset + 2 > end:
        raise CandidateRejected(f"{label}が入力境界を越えています")
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int, end: int, label: str) -> int:
    if offset < 0 or offset + 4 > end:
        raise CandidateRejected(f"{label}が入力境界を越えています")
    return struct.unpack_from("<I", data, offset)[0]


def _read_u64(data: bytes, offset: int, end: int, label: str) -> int:
    if offset < 0 or offset + 8 > end:
        raise CandidateRejected(f"{label}が入力境界を越えています")
    return struct.unpack_from("<Q", data, offset)[0]


def _decode_section_name(value: bytes) -> str:
    return value.rstrip(b"\0").decode("latin-1", errors="replace")


def _check_non_overlapping(
    ranges: list[tuple[int, int, str]],
    *,
    label: str,
) -> None:
    ordered = sorted((start, end, name) for start, end, name in ranges if end > start)
    previous_end = -1
    previous_name = ""
    for start, end, name in ordered:
        if start < previous_end:
            raise CandidateRejected(
                f"{label}が重複しています: {previous_name!r}と{name!r}"
            )
        previous_end = end
        previous_name = name


def _parse_pe_header(
    data: bytes,
    candidate_offset: int,
    *,
    max_candidate_bytes: int,
) -> PEInfo:
    """候補位置のPE構造を、入力とcandidate budgetの両方で検証する。"""

    if candidate_offset < 0 or candidate_offset + DOS_HEADER_SIZE > len(data):
        raise CandidateRejected("DOS headerが途中で切れています")
    if data[candidate_offset : candidate_offset + 2] != b"MZ":
        raise CandidateRejected("MZ signatureがありません")

    candidate_end = min(len(data), candidate_offset + max_candidate_bytes)
    e_lfanew = _read_u32(data, candidate_offset + 0x3C, candidate_end, "e_lfanew")
    if e_lfanew < DOS_HEADER_SIZE or e_lfanew > MAX_E_LFANEW:
        raise CandidateRejected(f"e_lfanewが許容範囲外です: 0x{e_lfanew:x}")
    pe_offset = candidate_offset + e_lfanew
    if pe_offset + 4 + COFF_HEADER_SIZE > candidate_end:
        raise CandidateRejected("PE/COFF headerが途中で切れています")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise CandidateRejected("PE signatureがありません")

    coff = pe_offset + 4
    machine = _read_u16(data, coff, candidate_end, "Machine")
    section_count = _read_u16(data, coff + 2, candidate_end, "NumberOfSections")
    optional_size = _read_u16(data, coff + 16, candidate_end, "SizeOfOptionalHeader")
    if machine not in KNOWN_MACHINES:
        raise CandidateRejected(f"未対応または不正なMachineです: 0x{machine:04x}")
    if not 1 <= section_count <= MAX_SECTIONS:
        raise CandidateRejected(f"section数が許容範囲外です: {section_count}")
    if not 0 < optional_size <= 0x1000:
        raise CandidateRejected(f"optional headerサイズが不正です: {optional_size}")

    optional = coff + COFF_HEADER_SIZE
    optional_end = optional + optional_size
    if optional_end > candidate_end:
        raise CandidateRejected("optional headerが途中で切れています")
    optional_magic = _read_u16(data, optional, optional_end, "OptionalHeader.Magic")
    if optional_magic == PE32_MAGIC:
        minimum_optional_size = 96
        image_base = _read_u32(data, optional + 28, optional_end, "ImageBase")
        number_of_rva_offset = optional + 92
        data_directory_offset = optional + 96
    elif optional_magic == PE32_PLUS_MAGIC:
        minimum_optional_size = 112
        image_base = _read_u64(data, optional + 24, optional_end, "ImageBase")
        number_of_rva_offset = optional + 108
        data_directory_offset = optional + 112
    else:
        raise CandidateRejected(f"OptionalHeader.MagicがPE32/PE32+ではありません: 0x{optional_magic:04x}")
    if optional_size < minimum_optional_size:
        raise CandidateRejected("optional headerが必要フィールドより短いです")

    entrypoint_rva = _read_u32(data, optional + 16, optional_end, "AddressOfEntryPoint")
    section_alignment = _read_u32(data, optional + 32, optional_end, "SectionAlignment")
    file_alignment = _read_u32(data, optional + 36, optional_end, "FileAlignment")
    size_of_image = _read_u32(data, optional + 56, optional_end, "SizeOfImage")
    size_of_headers = _read_u32(data, optional + 60, optional_end, "SizeOfHeaders")
    if not _is_power_of_two(file_alignment) or file_alignment > 0x10000:
        raise CandidateRejected(f"FileAlignmentが不正です: 0x{file_alignment:x}")
    if not _is_power_of_two(section_alignment):
        raise CandidateRejected(f"SectionAlignmentが不正です: 0x{section_alignment:x}")
    if section_alignment < 0x1000:
        if section_alignment != file_alignment:
            raise CandidateRejected("小さいSectionAlignmentとFileAlignmentが一致しません")
    elif section_alignment < file_alignment:
        raise CandidateRejected("SectionAlignmentがFileAlignmentより小さいです")
    if size_of_image <= 0 or size_of_image > max_candidate_bytes:
        raise CandidateRejected(
            f"SizeOfImageがcandidate budget外です: {size_of_image} > {max_candidate_bytes}"
        )
    if size_of_image % section_alignment != 0:
        raise CandidateRejected("SizeOfImageがSectionAlignment境界にありません")
    if size_of_headers <= 0 or size_of_headers > size_of_image:
        raise CandidateRejected("SizeOfHeadersがSizeOfImageの範囲外です")
    if size_of_headers % file_alignment != 0:
        raise CandidateRejected("SizeOfHeadersがFileAlignment境界にありません")
    if entrypoint_rva >= size_of_image:
        raise CandidateRejected("entry point RVAがSizeOfImageの範囲外です")

    section_table = optional_end
    section_table_end = section_table + section_count * SECTION_HEADER_SIZE
    if section_table_end > candidate_end:
        raise CandidateRejected("section tableが途中で切れています")
    if section_table_end - candidate_offset > size_of_headers:
        raise CandidateRejected("section tableがSizeOfHeadersの範囲外です")

    sections: list[SectionInfo] = []
    virtual_ranges: list[tuple[int, int, str]] = []
    raw_ranges: list[tuple[int, int, str]] = []
    file_span = size_of_headers
    for index in range(section_count):
        absolute_header = section_table + index * SECTION_HEADER_SIZE
        relative_header = absolute_header - candidate_offset
        name = _decode_section_name(data[absolute_header : absolute_header + 8])
        virtual_size = _read_u32(data, absolute_header + 8, candidate_end, "VirtualSize")
        virtual_address = _read_u32(data, absolute_header + 12, candidate_end, "VirtualAddress")
        raw_size = _read_u32(data, absolute_header + 16, candidate_end, "SizeOfRawData")
        raw_offset = _read_u32(data, absolute_header + 20, candidate_end, "PointerToRawData")
        characteristics = _read_u32(data, absolute_header + 36, candidate_end, "Characteristics")
        display_name = name or f"section_{index}"

        if virtual_address % section_alignment != 0:
            raise CandidateRejected(f"{display_name}のVirtualAddressがalignment境界にありません")
        if raw_size:
            if raw_offset < size_of_headers or raw_offset % file_alignment != 0:
                raise CandidateRejected(f"{display_name}のraw offsetが不正です")
            if raw_size % file_alignment != 0:
                raise CandidateRejected(f"{display_name}のraw sizeがFileAlignment境界にありません")
            raw_end = raw_offset + raw_size
            if raw_end > max_candidate_bytes:
                raise CandidateRejected(f"{display_name}のraw範囲がcandidate budgetを越えます")
            raw_ranges.append((raw_offset, raw_end, display_name))
            file_span = max(file_span, raw_end)
        elif raw_offset not in {0, size_of_headers}:
            # RawSize=0ではPointerToRawDataは参照されない。異常値は証拠として
            # 残せるが、memory-only sectionの回収を妨げないため拒否しない。
            pass

        memory_size = max(virtual_size, raw_size)
        if memory_size:
            virtual_end = virtual_address + memory_size
            if virtual_end > size_of_image:
                raise CandidateRejected(f"{display_name}のvirtual範囲がSizeOfImageを越えます")
            virtual_ranges.append((virtual_address, virtual_end, display_name))

        sections.append(
            SectionInfo(
                index=index,
                name=display_name,
                header_offset=relative_header,
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                raw_size=raw_size,
                raw_offset=raw_offset,
                characteristics=characteristics,
            )
        )

    _check_non_overlapping(virtual_ranges, label="section virtual範囲")
    _check_non_overlapping(raw_ranges, label="section raw範囲")

    security_directory_field_offset: int | None = None
    security_offset = 0
    security_size = 0
    if number_of_rva_offset + 4 <= optional_end:
        directory_count = _read_u32(data, number_of_rva_offset, optional_end, "NumberOfRvaAndSizes")
        if directory_count > 4 and data_directory_offset + 5 * 8 <= optional_end:
            security_directory_field_offset = data_directory_offset + 4 * 8 - candidate_offset
            security_offset = _read_u32(
                data,
                candidate_offset + security_directory_field_offset,
                optional_end,
                "SecurityDirectory.FileOffset",
            )
            security_size = _read_u32(
                data,
                candidate_offset + security_directory_field_offset + 4,
                optional_end,
                "SecurityDirectory.Size",
            )
            if bool(security_offset) != bool(security_size):
                raise CandidateRejected("security directoryのoffset/sizeの片方だけが0です")
            if security_size:
                security_end = security_offset + security_size
                if security_offset < size_of_headers or security_end > max_candidate_bytes:
                    raise CandidateRejected("security directoryがcandidate budget外です")
                file_span = max(file_span, security_end)

    if file_span > max_candidate_bytes:
        raise CandidateRejected(f"file-layout候補がcandidate budgetを越えます: {file_span}")

    return PEInfo(
        machine=machine,
        section_count=section_count,
        optional_magic=optional_magic,
        image_base=image_base,
        entrypoint_rva=entrypoint_rva,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        section_table_end=section_table_end - candidate_offset,
        file_span=file_span,
        security_directory_field_offset=security_directory_field_offset,
        security_offset=security_offset,
        security_size=security_size,
        sections=tuple(sections),
    )


def _entrypoint_source_offset(info: PEInfo, layout: str) -> int | None:
    if info.entrypoint_rva == 0:
        return None
    if layout == "mapped":
        return info.entrypoint_rva
    for section in info.sections:
        extent = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= info.entrypoint_rva < section.virtual_address + extent:
            relative = info.entrypoint_rva - section.virtual_address
            if relative < section.raw_size:
                return section.raw_offset + relative
    return None


def _content_score(
    data: bytes,
    candidate_offset: int,
    info: PEInfo,
    *,
    layout: str,
) -> tuple[int, bool, list[dict[str, Any]]]:
    """実データの存在だけを用い、file/mappedの優先度を比較する。"""

    score = 0
    section_evidence: list[dict[str, Any]] = []
    for section in info.sections:
        if layout == "mapped":
            source_offset = section.virtual_address
            content_size = section.virtual_size if section.virtual_size else section.raw_size
        else:
            source_offset = section.raw_offset
            content_size = section.raw_size
        sample_size = min(content_size, 4096)
        sample = data[
            candidate_offset + source_offset : candidate_offset + source_offset + sample_size
        ]
        nonzero = sum(byte != 0 for byte in sample)
        score += nonzero
        section_evidence.append(
            {
                "name": section.name,
                "source_offset": source_offset,
                "sample_size": len(sample),
                "sample_nonzero_bytes": nonzero,
            }
        )

    entrypoint_offset = _entrypoint_source_offset(info, layout)
    entrypoint_backed = False
    if entrypoint_offset is not None and candidate_offset + entrypoint_offset < len(data):
        entrypoint_backed = data[candidate_offset + entrypoint_offset] != 0
        if entrypoint_backed:
            score += 1_000_000
    return score, entrypoint_backed, section_evidence


def _verify_recovered_pe(payload: bytes, info: PEInfo) -> dict[str, Any]:
    """復元後PEを独立に再解析し、主要フィールドの不変条件を確認する。"""

    try:
        parsed = pefile.PE(data=payload, fast_load=True)
    except pefile.PEFormatError as exc:
        raise CandidateRejected(f"復元後PEを再解析できません: {exc}") from exc
    try:
        observed_sections = len(parsed.sections)
        observed_image_size = int(parsed.OPTIONAL_HEADER.SizeOfImage)
        observed_machine = int(parsed.FILE_HEADER.Machine)
        if observed_sections != info.section_count:
            raise CandidateRejected("復元後PEのsection数が変化しました")
        if observed_image_size != info.size_of_image:
            raise CandidateRejected("復元後PEのSizeOfImageが変化しました")
        if observed_machine != info.machine:
            raise CandidateRejected("復元後PEのMachineが変化しました")
        for section in parsed.sections:
            raw_offset = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
            if raw_size and raw_offset + raw_size > len(payload):
                raise CandidateRejected("復元後PEのsection raw範囲が出力境界を越えます")
    finally:
        parsed.close()
    return {
        "pefile_reparse": True,
        "machine": f"0x{observed_machine:04x}",
        "section_count": observed_sections,
        "size_of_image": observed_image_size,
        "section_raw_ranges_within_output": True,
    }


def _file_layout_attempt(data: bytes, candidate_offset: int, info: PEInfo) -> LayoutAttempt:
    end = candidate_offset + info.file_span
    if end > len(data):
        raise CandidateRejected(
            f"file-layoutが途中で切れています: 必要={info.file_span} 残り={len(data) - candidate_offset}"
        )
    payload = bytes(data[candidate_offset:end])
    score, entrypoint_backed, section_evidence = _content_score(
        data,
        candidate_offset,
        info,
        layout="file",
    )
    validation = _verify_recovered_pe(payload, info)
    return LayoutAttempt(
        payload=payload,
        layout="file",
        mapped_mode=None,
        source_span=info.file_span,
        score=score,
        entrypoint_backed=entrypoint_backed,
        evidence={
            **validation,
            "source_layout": "file",
            "source_span": info.file_span,
            "entrypoint_backed": entrypoint_backed,
            "section_content_samples": section_evidence,
            "security_directory_preserved": bool(info.security_size),
        },
    )


def _zero_security_directory(output: bytearray, info: PEInfo) -> bool:
    if info.security_directory_field_offset is None:
        return False
    field = info.security_directory_field_offset
    if field < 0 or field + 8 > len(output):
        raise CandidateRejected("security directory fieldが出力header境界を越えます")
    output[field : field + 8] = bytes(8)
    return bool(info.security_size)


def _mapped_original_raw_attempt(
    data: bytes,
    candidate_offset: int,
    info: PEInfo,
) -> LayoutAttempt:
    if candidate_offset + info.size_of_image > len(data):
        raise CandidateRejected(
            f"mapped-layoutが途中で切れています: 必要={info.size_of_image} 残り={len(data) - candidate_offset}"
        )
    output_size = max(
        info.size_of_headers,
        *(section.raw_offset + section.raw_size for section in info.sections),
    )
    output = bytearray(output_size)
    output[: info.size_of_headers] = data[
        candidate_offset : candidate_offset + info.size_of_headers
    ]
    copied_sections: list[dict[str, Any]] = []
    for section in info.sections:
        if not section.raw_size:
            copied_sections.append(
                {
                    "name": section.name,
                    "copied_bytes": 0,
                    "memory_only_not_preserved": section.virtual_size > 0,
                }
            )
            continue
        source_start = candidate_offset + section.virtual_address
        source_end = source_start + section.raw_size
        if source_end > candidate_offset + info.size_of_image:
            raise CandidateRejected(f"{section.name}のmapped sourceがSizeOfImageを越えます")
        output[section.raw_offset : section.raw_offset + section.raw_size] = data[
            source_start:source_end
        ]
        copied_sections.append(
            {
                "name": section.name,
                "copied_bytes": section.raw_size,
                "source_rva": section.virtual_address,
                "raw_offset": section.raw_offset,
                "raw_size": section.raw_size,
                "memory_only_not_preserved": False,
            }
        )
    security_removed = _zero_security_directory(output, info)
    payload = bytes(output)
    score, entrypoint_backed, section_evidence = _content_score(
        data,
        candidate_offset,
        info,
        layout="mapped",
    )
    validation = _verify_recovered_pe(payload, info)
    return LayoutAttempt(
        payload=payload,
        layout="mapped",
        mapped_mode="original_raw",
        source_span=info.size_of_image,
        score=score,
        entrypoint_backed=entrypoint_backed,
        evidence={
            **validation,
            "source_layout": "mapped",
            "mapped_mode": "original_raw",
            "source_span": info.size_of_image,
            "entrypoint_backed": entrypoint_backed,
            "section_content_samples": section_evidence,
            "sections": copied_sections,
            "security_directory_zeroed": security_removed,
        },
    )


def _mapped_expanded_attempt(
    data: bytes,
    candidate_offset: int,
    info: PEInfo,
    *,
    max_output_bytes: int,
) -> LayoutAttempt:
    """VirtualSize全体を新しいraw範囲へ割り当ててmemory-only sectionを保存する。"""

    if candidate_offset + info.size_of_image > len(data):
        raise CandidateRejected(
            f"mapped-layoutが途中で切れています: 必要={info.size_of_image} 残り={len(data) - candidate_offset}"
        )

    next_raw = _align_up(info.size_of_headers, info.file_alignment)
    plans: list[tuple[SectionInfo, int, int, int]] = []
    for section in info.sections:
        memory_size = max(section.virtual_size, section.raw_size)
        if not memory_size:
            plans.append((section, 0, 0, 0))
            continue
        if section.virtual_address + memory_size > info.size_of_image:
            raise CandidateRejected(f"{section.name}のmemory bytesがSizeOfImageを越えます")
        raw_offset = _align_up(next_raw, info.file_alignment)
        raw_size = _align_up(memory_size, info.file_alignment)
        next_raw = raw_offset + raw_size
        if next_raw > max_output_bytes:
            raise CandidateRejected(
                f"expanded_memory_sections出力がbudgetを越えます: {next_raw} > {max_output_bytes}"
            )
        plans.append((section, memory_size, raw_offset, raw_size))

    output = bytearray(next_raw)
    output[: info.size_of_headers] = data[
        candidate_offset : candidate_offset + info.size_of_headers
    ]
    expanded_sections: list[dict[str, Any]] = []
    for section, memory_size, raw_offset, raw_size in plans:
        header = section.header_offset
        if header < 0 or header + SECTION_HEADER_SIZE > info.size_of_headers:
            raise CandidateRejected(f"{section.name}のsection headerがSizeOfHeaders外です")
        struct.pack_into("<I", output, header + 16, raw_size)
        struct.pack_into("<I", output, header + 20, raw_offset)
        if memory_size:
            source_start = candidate_offset + section.virtual_address
            source_end = source_start + memory_size
            output[raw_offset : raw_offset + memory_size] = data[source_start:source_end]
        expanded_sections.append(
            {
                "name": section.name,
                "source_rva": section.virtual_address,
                "virtual_size": section.virtual_size,
                "original_raw_offset": section.raw_offset,
                "original_raw_size": section.raw_size,
                "copied_memory_bytes": memory_size,
                "new_raw_offset": raw_offset,
                "new_raw_size": raw_size,
                "memory_only_section_recovered": section.raw_size == 0 and memory_size > 0,
            }
        )
    security_removed = _zero_security_directory(output, info)
    payload = bytes(output)
    score, entrypoint_backed, section_evidence = _content_score(
        data,
        candidate_offset,
        info,
        layout="mapped",
    )
    validation = _verify_recovered_pe(payload, info)
    return LayoutAttempt(
        payload=payload,
        layout="mapped",
        mapped_mode="expanded_memory_sections",
        source_span=info.size_of_image,
        score=score,
        entrypoint_backed=entrypoint_backed,
        evidence={
            **validation,
            "source_layout": "mapped",
            "mapped_mode": "expanded_memory_sections",
            "source_span": info.size_of_image,
            "entrypoint_backed": entrypoint_backed,
            "section_content_samples": section_evidence,
            "sections": expanded_sections,
            "memory_only_sections_recovered": sum(
                item[0].raw_size == 0 and item[1] > 0 for item in plans
            ),
            "security_directory_zeroed": security_removed,
        },
    )


def _header_evidence(info: PEInfo) -> dict[str, Any]:
    return {
        "dos_signature": True,
        "pe_signature": True,
        "machine": f"0x{info.machine:04x}",
        "optional_magic": f"0x{info.optional_magic:04x}",
        "section_count": info.section_count,
        "section_table_within_headers": True,
        "section_ranges_non_overlapping": True,
        "section_alignment": info.section_alignment,
        "file_alignment": info.file_alignment,
        "size_of_headers": info.size_of_headers,
        "size_of_image": info.size_of_image,
        "entrypoint_rva": info.entrypoint_rva,
        "preferred_image_base": info.image_base,
    }


def _candidate_hash_window(data: bytes, offset: int) -> tuple[str, int]:
    window = data[offset : min(len(data), offset + INVALID_CANDIDATE_HASH_WINDOW)]
    return hashlib.sha256(window).hexdigest(), len(window)


def _build_attempts(
    data: bytes,
    offset: int,
    info: PEInfo,
    *,
    mapped_mode: MappedMode,
    max_output_bytes: int,
) -> tuple[list[LayoutAttempt], list[dict[str, Any]]]:
    attempts: list[LayoutAttempt] = []
    failures: list[dict[str, Any]] = []

    builders: list[tuple[str, Any]] = [("file", lambda: _file_layout_attempt(data, offset, info))]
    selected_mapped_modes: list[str]
    if mapped_mode == "auto":
        has_unrepresented_memory = any(
            section.virtual_size > section.raw_size for section in info.sections
        )
        selected_mapped_modes = [
            "expanded_memory_sections" if has_unrepresented_memory else "original_raw"
        ]
    elif mapped_mode == "both":
        selected_mapped_modes = ["original_raw", "expanded_memory_sections"]
    else:
        selected_mapped_modes = [mapped_mode]

    for mode in selected_mapped_modes:
        if mode == "original_raw":
            builders.append(
                ("mapped/original_raw", lambda: _mapped_original_raw_attempt(data, offset, info))
            )
        else:
            builders.append(
                (
                    "mapped/expanded_memory_sections",
                    lambda: _mapped_expanded_attempt(
                        data,
                        offset,
                        info,
                        max_output_bytes=max_output_bytes,
                    ),
                )
            )

    for label, builder in builders:
        try:
            attempts.append(builder())
        except CandidateRejected as exc:
            failures.append({"layout": label, "status": "rejected", "reason": str(exc)})

    by_hash: dict[str, LayoutAttempt] = {}
    for attempt in attempts:
        digest = hashlib.sha256(attempt.payload).hexdigest()
        current = by_hash.get(digest)
        if current is None or attempt.score > current.score:
            by_hash[digest] = attempt
    attempts = list(by_hash.values())
    if not attempts:
        return [], failures

    if mapped_mode == "both":
        mapped_attempts = [attempt for attempt in attempts if attempt.layout == "mapped"]
        if mapped_attempts:
            best_file = max(
                (attempt for attempt in attempts if attempt.layout == "file"),
                key=lambda item: item.score,
                default=None,
            )
            selected = list(mapped_attempts)
            if best_file is not None and best_file.score > max(item.score for item in mapped_attempts):
                selected.append(best_file)
            return selected, failures

    best = max(
        attempts,
        key=lambda item: (
            item.score,
            item.entrypoint_backed,
            item.mapped_mode == "expanded_memory_sections",
            item.layout == "file",
        ),
    )
    for attempt in attempts:
        if attempt is not best:
            failures.append(
                {
                    "layout": attempt.layout,
                    "mapped_mode": attempt.mapped_mode,
                    "status": "not_selected",
                    "reason": "静的content scoreが選択候補より低いか、同点時の安全な優先順位で除外されました",
                    "score": attempt.score,
                }
            )
    return [best], failures


def recover_process_dump_bytes(
    data: bytes,
    *,
    source_name: str = "<memory>",
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    max_candidate_bytes: int = DEFAULT_MAX_CANDIDATE_BYTES,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    mapped_mode: MappedMode = "auto",
) -> tuple[list[RecoveredPE], dict[str, Any]]:
    """process dumpの全MZ候補を走査し、重複排除済みPEとJSON情報を返す。"""

    _positive(max_input_bytes, "max_input_bytes")
    _positive(max_candidates, "max_candidates")
    _positive(max_candidate_bytes, "max_candidate_bytes")
    _positive(max_output_bytes, "max_output_bytes")
    if mapped_mode not in {"auto", "original_raw", "expanded_memory_sections", "both"}:
        raise ProcessDumpPEError(f"mapped_modeが不正です: {mapped_mode}")
    if len(data) > max_input_bytes:
        raise ProcessDumpPEError(
            f"入力サイズがbudgetを越えています: {len(data)} > {max_input_bytes}"
        )

    source_sha256 = hashlib.sha256(data).hexdigest()
    candidate_records: list[dict[str, Any]] = []
    recovered: list[RecoveredPE] = []
    output_by_sha256: dict[str, dict[str, Any]] = {}
    total_output_bytes = 0
    cursor = 0
    mz_count = 0

    while True:
        offset = data.find(b"MZ", cursor)
        if offset < 0:
            break
        cursor = offset + 1
        mz_count += 1
        if mz_count > max_candidates:
            raise ProcessDumpPEError(
                f"MZ候補数がbudgetを越えています: {mz_count} > {max_candidates}"
            )

        window_sha256, window_size = _candidate_hash_window(data, offset)
        record: dict[str, Any] = {
            "index": mz_count,
            "offset": offset,
            "offset_hex": f"0x{offset:x}",
            "header_window_sha256": window_sha256,
            "header_window_size": window_size,
            "status": "rejected",
            "attempts": [],
        }
        try:
            info = _parse_pe_header(
                data,
                offset,
                max_candidate_bytes=max_candidate_bytes,
            )
        except CandidateRejected as exc:
            record["reason"] = str(exc)
            candidate_records.append(record)
            continue

        record["base"] = info.image_base
        record["base_hex"] = f"0x{info.image_base:x}"
        record["header_validation"] = _header_evidence(info)
        attempts, failures = _build_attempts(
            data,
            offset,
            info,
            mapped_mode=mapped_mode,
            max_output_bytes=max_output_bytes,
        )
        record["attempts"].extend(failures)
        if not attempts:
            record["reason"] = "file-layoutとmapped-layoutのいずれも安全に復元できませんでした"
            candidate_records.append(record)
            continue

        unique_for_candidate = 0
        duplicate_for_candidate = 0
        for attempt in attempts:
            candidate_slice = data[offset : offset + attempt.source_span]
            candidate_sha256 = hashlib.sha256(candidate_slice).hexdigest()
            output_sha256 = hashlib.sha256(attempt.payload).hexdigest()
            attempt_record: dict[str, Any] = {
                "layout": attempt.layout,
                "mapped_mode": attempt.mapped_mode,
                "score": attempt.score,
                "source_span": attempt.source_span,
                "candidate_sha256": candidate_sha256,
                "output_sha256": output_sha256,
                "output_size": len(attempt.payload),
                "validation_evidence": attempt.evidence,
            }
            if output_sha256 == source_sha256:
                attempt_record["status"] = "duplicate_of_source"
                duplicate_for_candidate += 1
                record["attempts"].append(attempt_record)
                continue
            existing = output_by_sha256.get(output_sha256)
            if existing is not None:
                attempt_record["status"] = "duplicate_output"
                attempt_record["duplicate_of"] = existing["output_name"]
                duplicate_for_candidate += 1
                record["attempts"].append(attempt_record)
                continue
            if len(attempt.payload) > max_output_bytes - total_output_bytes:
                raise ProcessDumpPEError(
                    "出力合計サイズがbudgetを越えます: "
                    f"現在={total_output_bytes} 追加={len(attempt.payload)} 上限={max_output_bytes}"
                )

            output_name = f"pe_{len(recovered) + 1:04d}_{output_sha256[:16]}.bin"
            metadata = {
                "output_name": output_name,
                "source_sha256": source_sha256,
                "candidate_sha256": candidate_sha256,
                "output_sha256": output_sha256,
                "offset": offset,
                "offset_hex": f"0x{offset:x}",
                "base": info.image_base,
                "base_hex": f"0x{info.image_base:x}",
                "layout": attempt.layout,
                "mapped_mode": attempt.mapped_mode,
                "candidate_size": attempt.source_span,
                "output_size": len(attempt.payload),
                "validation_evidence": {
                    "header": _header_evidence(info),
                    "layout": attempt.evidence,
                },
                "executed": False,
                "emulated": False,
                "network_contacted": False,
            }
            recovered_item = RecoveredPE(payload=attempt.payload, metadata=metadata)
            recovered.append(recovered_item)
            output_by_sha256[output_sha256] = metadata
            total_output_bytes += len(attempt.payload)
            unique_for_candidate += 1
            attempt_record["status"] = "recovered"
            attempt_record["output_name"] = output_name
            record["attempts"].append(attempt_record)

        if unique_for_candidate:
            record["status"] = "recovered"
        elif duplicate_for_candidate:
            record["status"] = "duplicate"
        else:
            record["status"] = "rejected"
        candidate_records.append(record)

    report = {
        "schema_version": 1,
        "analysis": "full_process_dump_pe_recovery",
        "source": {
            "name": source_name,
            "size": len(data),
            "sha256": source_sha256,
        },
        "budgets": {
            "max_input_bytes": max_input_bytes,
            "max_candidates": max_candidates,
            "max_candidate_bytes": max_candidate_bytes,
            "max_output_bytes": max_output_bytes,
        },
        "mapped_mode": mapped_mode,
        "summary": {
            "mz_candidates": mz_count,
            "recovered_outputs": len(recovered),
            "rejected_candidates": sum(item["status"] == "rejected" for item in candidate_records),
            "duplicate_candidates": sum(item["status"] == "duplicate" for item in candidate_records),
            "total_output_bytes": total_output_bytes,
        },
        "candidates": candidate_records,
        "outputs": [item.metadata for item in recovered],
        "safety": {
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "all_mz_scanned": True,
            "sha256_deduplicated": True,
        },
    }
    return recovered, report


def _read_input_file(path: Path, max_input_bytes: int) -> tuple[bytes, os.stat_result]:
    """reparse/hardlinkと読み込み中の差し替えを拒否して入力を読む。"""

    _positive(max_input_bytes, "max_input_bytes")
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        reject_existing_reparse_components(absolute)
    except (OSError, ValueError) as exc:
        raise ProcessDumpPEError(f"入力pathにreparse pointがあります: {absolute}") from exc
    try:
        path_metadata = absolute.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ProcessDumpPEError(f"入力ファイルがありません: {absolute}") from exc
    if not stat.S_ISREG(path_metadata.st_mode):
        raise ProcessDumpPEError(f"入力は通常ファイルである必要があります: {absolute}")
    if path_metadata.st_nlink != 1:
        raise ProcessDumpPEError(
            f"入力ハードリンクは拒否します: link_count={path_metadata.st_nlink} path={absolute}"
        )
    if path_metadata.st_size > max_input_bytes:
        raise ProcessDumpPEError(
            f"入力サイズがbudgetを越えています: {path_metadata.st_size} > {max_input_bytes}"
        )

    with absolute.open("rb") as handle:
        opened_metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened_metadata.st_mode):
            raise ProcessDumpPEError("openした入力が通常ファイルではありません")
        if opened_metadata.st_nlink != 1:
            raise ProcessDumpPEError("openした入力がハードリンクへ変更されました")
        if not os.path.samestat(path_metadata, opened_metadata):
            raise ProcessDumpPEError("入力pathとopenしたファイルのidentityが一致しません")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = handle.read(min(1024 * 1024, max_input_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_input_bytes:
                raise ProcessDumpPEError(
                    f"読み込み中に入力サイズがbudgetを越えました: {total} > {max_input_bytes}"
                )
            chunks.append(chunk)
        final_metadata = os.fstat(handle.fileno())
        if not os.path.samestat(opened_metadata, final_metadata):
            raise ProcessDumpPEError("読み込み中に入力ファイルのidentityが変化しました")
        if final_metadata.st_size != total or path_metadata.st_size != total:
            raise ProcessDumpPEError("読み込み中に入力ファイルのサイズが変化しました")
        if final_metadata.st_nlink != 1:
            raise ProcessDumpPEError("読み込み中に入力がハードリンク化されました")

    try:
        reject_existing_reparse_components(absolute)
        current_metadata = absolute.stat(follow_symlinks=False)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ProcessDumpPEError("読み込み後に入力pathを再検証できません") from exc
    if not os.path.samestat(path_metadata, current_metadata):
        raise ProcessDumpPEError("読み込み後に入力pathのidentityが変化しました")
    return b"".join(chunks), path_metadata


def recover_process_dump_file(
    input_path: Path,
    output_dir: Path,
    *,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    max_candidate_bytes: int = DEFAULT_MAX_CANDIDATE_BYTES,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    mapped_mode: MappedMode = "auto",
) -> dict[str, Any]:
    """入力dumpを読み、明示されたdirectoryへPEとJSONを排他的に保存する。"""

    input_absolute = Path(os.path.abspath(os.fspath(input_path)))
    output_absolute = Path(os.path.abspath(os.fspath(output_dir)))
    if os.path.normcase(os.fspath(input_absolute)) == os.path.normcase(os.fspath(output_absolute)):
        raise ProcessDumpPEError("入力ファイルと出力directoryに同じpathは指定できません")
    data, input_metadata = _read_input_file(input_absolute, max_input_bytes)
    recovered, report = recover_process_dump_bytes(
        data,
        source_name=os.fspath(input_absolute),
        max_input_bytes=max_input_bytes,
        max_candidates=max_candidates,
        max_candidate_bytes=max_candidate_bytes,
        max_output_bytes=max_output_bytes,
        mapped_mode=mapped_mode,
    )
    report["source"]["file_identity"] = {
        "size": input_metadata.st_size,
        "link_count": input_metadata.st_nlink,
    }

    report_bytes = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    planned: list[tuple[Path, bytes, str]] = []
    for item in recovered:
        destination = output_absolute / item.metadata["output_name"]
        if destination == input_absolute:
            raise ProcessDumpPEError("復元PEの出力pathが入力pathと重複します")
        planned.append((destination, item.payload, item.metadata["output_sha256"]))
    report_path = output_absolute / REPORT_NAME
    if report_path == input_absolute:
        raise ProcessDumpPEError("JSON出力pathが入力pathと重複します")
    planned.append((report_path, report_bytes, hashlib.sha256(report_bytes).hexdigest()))

    try:
        written = write_private_outputs(
            planned,
            allowed_root=output_absolute,
            create_root=True,
        )
    except (OSError, ValueError) as exc:
        raise ProcessDumpPEError(f"出力を安全に保存できません: {exc}") from exc

    for path in written:
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ProcessDumpPEError(f"作成した出力が単一リンクの通常ファイルではありません: {path}")
        if os.path.samestat(input_metadata, metadata):
            raise ProcessDumpPEError(f"作成した出力と入力のfile identityが重複しています: {path}")
    return report


def _positive_cli(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("正の整数を指定してください") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("正の整数を指定してください")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="full process dumpの入力ファイル")
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help=f"復元PEと{REPORT_NAME}を新規保存する明示的なdirectory",
    )
    parser.add_argument("--max-input-bytes", type=_positive_cli, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-candidates", type=_positive_cli, default=DEFAULT_MAX_CANDIDATES)
    parser.add_argument(
        "--max-candidate-bytes",
        type=_positive_cli,
        default=DEFAULT_MAX_CANDIDATE_BYTES,
    )
    parser.add_argument("--max-output-bytes", type=_positive_cli, default=DEFAULT_MAX_OUTPUT_BYTES)
    parser.add_argument(
        "--mapped-mode",
        choices=("auto", "original_raw", "expanded_memory_sections", "both"),
        default="auto",
        help=(
            "mapped imageの復元方式。autoはVirtualSizeがRawSizeを越える場合に"
            "expanded_memory_sectionsを選びます"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = recover_process_dump_file(
            args.input,
            args.output_dir,
            max_input_bytes=args.max_input_bytes,
            max_candidates=args.max_candidates,
            max_candidate_bytes=args.max_candidate_bytes,
            max_output_bytes=args.max_output_bytes,
            mapped_mode=args.mapped_mode,
        )
    except (ProcessDumpPEError, OSError) as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
