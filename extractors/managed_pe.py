"""managed PE判定とmetadata parser診断の共通・非実行ヘルパー。"""

from __future__ import annotations

import struct

_MAXIMUM_PE_SECTIONS = 96
_CLR_DIRECTORY_INDEX = 14
_MINIMUM_CLR_HEADER_SIZE = 0x48


def _rva_range_to_file_offset(
    data_size: int,
    rva: int,
    span: int,
    size_of_headers: int,
    sections: list[tuple[int, int, int, int]],
) -> int | None:
    """検証済みsection表を使い、file上に全体が存在するRVA範囲を変換する。"""

    if span < 0 or rva < 0:
        return None
    if (
        rva < size_of_headers
        and span <= size_of_headers - rva
        and rva <= data_size
        and span <= data_size - rva
    ):
        return rva
    for virtual_address, virtual_size, raw_size, raw_offset in sections:
        mapped_size = max(virtual_size, raw_size)
        if not virtual_address <= rva < virtual_address + mapped_size:
            continue
        delta = rva - virtual_address
        if (
            delta >= raw_size
            or span > raw_size - delta
            or raw_offset > data_size
            or delta > data_size - raw_offset
        ):
            return None
        offset = raw_offset + delta
        return offset if span <= data_size - offset else None
    return None


def has_clr_metadata(data: bytes) -> bool:
    """PE/CLR directoryとmetadata signatureを境界内で確認する。

    ``dnfile`` や ``pefile`` を起動する前の安価なcontent prefilterとして使う。
    section内容やmanaged codeを解釈せず、検体を実行しない。
    """

    if not isinstance(data, bytes) or len(data) < 0x40 or data[:2] != b"MZ":
        return False
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset > len(data) - 24 or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return False
        coff_offset = pe_offset + 4
        section_count = struct.unpack_from("<H", data, coff_offset + 2)[0]
        optional_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
        if not 1 <= section_count <= _MAXIMUM_PE_SECTIONS:
            return False
        optional_offset = coff_offset + 20
        optional_end = optional_offset + optional_size
        if optional_end > len(data):
            return False
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        if magic == 0x10B:
            directory_count_offset = optional_offset + 92
            directory_offset = optional_offset + 96
        elif magic == 0x20B:
            directory_count_offset = optional_offset + 108
            directory_offset = optional_offset + 112
        else:
            return False
        clr_entry = directory_offset + (_CLR_DIRECTORY_INDEX * 8)
        if directory_count_offset + 4 > optional_end or clr_entry + 8 > optional_end:
            return False
        directory_count = struct.unpack_from("<I", data, directory_count_offset)[0]
        if directory_count <= _CLR_DIRECTORY_INDEX:
            return False
        clr_rva, clr_size = struct.unpack_from("<II", data, clr_entry)
        if clr_rva == 0 or clr_size < _MINIMUM_CLR_HEADER_SIZE:
            return False
        size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
        section_table_offset = optional_end
        section_table_end = section_table_offset + section_count * 40
        if (
            section_table_end > len(data)
            or size_of_headers < section_table_end
            or size_of_headers > len(data)
        ):
            return False
        sections: list[tuple[int, int, int, int]] = []
        for index in range(section_count):
            section_offset = section_table_offset + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, section_offset + 8
            )
            sections.append((virtual_address, virtual_size, raw_size, raw_offset))
        clr_offset = _rva_range_to_file_offset(
            len(data),
            clr_rva,
            _MINIMUM_CLR_HEADER_SIZE,
            size_of_headers,
            sections,
        )
        if clr_offset is None:
            return False
        clr_header_size = struct.unpack_from("<I", data, clr_offset)[0]
        if not _MINIMUM_CLR_HEADER_SIZE <= clr_header_size <= clr_size:
            return False
        if (
            _rva_range_to_file_offset(
                len(data),
                clr_rva,
                clr_header_size,
                size_of_headers,
                sections,
            )
            != clr_offset
        ):
            return False
        metadata_rva, metadata_size = struct.unpack_from("<II", data, clr_offset + 8)
        if metadata_rva == 0 or metadata_size < 4:
            return False
        metadata_offset = _rva_range_to_file_offset(
            len(data), metadata_rva, metadata_size, size_of_headers, sections
        )
        return bool(
            metadata_offset is not None
            and metadata_offset <= len(data) - 4
            and data[metadata_offset : metadata_offset + 4] == b"BSJB"
        )
    except (OverflowError, struct.error):
        return False
