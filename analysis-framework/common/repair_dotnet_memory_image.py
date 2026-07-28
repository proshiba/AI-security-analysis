#!/usr/bin/env python3
"""アンチダンプで壊された.NETメモリ配置PEを静的解析用に修復する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

import pefile

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from common.rebuild_mapped_pe import (
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
    MappedPEError,
    _read_bounded,
    _reject_reparse_components,
)

CLR_HEADER_SIZE = 72
METADATA_MAGIC = b"BSJB"
MAX_METADATA_CANDIDATES = 16


class DotNetMemoryRepairError(MappedPEError):
    """CLRヘッダーを安全に修復できない入力を表す。"""


def find_metadata_rvas(data: bytes) -> list[int]:
    """上限付きでCLR metadata root候補を列挙する。"""

    candidates: list[int] = []
    cursor = 0
    while len(candidates) < MAX_METADATA_CANDIDATES:
        found = data.find(METADATA_MAGIC, cursor)
        if found < 0:
            break
        candidates.append(found)
        cursor = found + len(METADATA_MAGIC)
    return candidates


def _metadata_root_size(data: bytes, metadata_rva: int) -> int:
    """metadata stream表を検証し、root全体の正確なbyte長を返す。"""

    if metadata_rva + 20 > len(data):
        raise DotNetMemoryRepairError("metadata root headerが入力境界外です")
    version_length = struct.unpack_from("<I", data, metadata_rva + 12)[0]
    if not 0 < version_length <= 1024:
        raise DotNetMemoryRepairError("metadata version長が不正です")
    cursor = (metadata_rva + 16 + version_length + 3) & ~3
    if cursor + 4 > len(data):
        raise DotNetMemoryRepairError("metadata stream数が入力境界外です")
    _flags, stream_count = struct.unpack_from("<HH", data, cursor)
    cursor += 4
    if not 0 < stream_count <= 32:
        raise DotNetMemoryRepairError("metadata stream数が上限外です")

    maximum_end = cursor - metadata_rva
    for _ in range(stream_count):
        if cursor + 8 > len(data):
            raise DotNetMemoryRepairError("metadata stream headerが入力境界外です")
        stream_offset, stream_size = struct.unpack_from("<II", data, cursor)
        cursor += 8
        name_end = data.find(b"\0", cursor, min(len(data), cursor + 64))
        if name_end < 0:
            raise DotNetMemoryRepairError("metadata stream名が終端されていません")
        cursor = (name_end + 1 + 3) & ~3
        stream_end = stream_offset + stream_size
        if stream_end < stream_offset or metadata_rva + stream_end > len(data):
            raise DotNetMemoryRepairError("metadata stream範囲が入力境界外です")
        maximum_end = max(maximum_end, stream_end)
    return maximum_end


def _section_table_to_mapped_layout(
    output: bytearray,
    image: pefile.PE,
) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for section in image.sections:
        virtual_address = int(section.VirtualAddress)
        virtual_size = int(section.Misc_VirtualSize)
        raw_size = int(section.SizeOfRawData)
        if virtual_address < 0 or virtual_size < 0 or raw_size < 0:
            raise DotNetMemoryRepairError("sectionに負の値があります")
        if virtual_address >= len(output):
            raise DotNetMemoryRepairError(f"section RVAが入力境界外です: {section.Name!r}")
        mapped_size = min(max(virtual_size, raw_size), len(output) - virtual_address)
        section_offset = int(section.get_file_offset())
        if section_offset + 24 > len(output):
            raise DotNetMemoryRepairError("section headerが入力境界外です")
        struct.pack_into("<I", output, section_offset + 16, mapped_size)
        struct.pack_into("<I", output, section_offset + 20, virtual_address)
        sections.append(
            {
                "name": bytes(section.Name).rstrip(b"\0").decode("latin-1"),
                "virtual_address": virtual_address,
                "mapped_size": mapped_size,
            }
        )
    return sections


def repair_dotnet_memory_image(
    data: bytes,
    *,
    metadata_rva: int | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[bytes, dict[str, Any]]:
    """破壊されたCLR headerとsection raw配置だけを解析用に修復する。"""

    if len(data) > max_output_bytes:
        raise DotNetMemoryRepairError(f"出力サイズが上限を超えます: {len(data)} > {max_output_bytes}")
    try:
        image = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise DotNetMemoryRepairError(f"PEヘッダーを解析できません: {exc}") from exc
    image_size = int(image.OPTIONAL_HEADER.SizeOfImage)
    if not 0 < image_size <= len(data):
        raise DotNetMemoryRepairError("入力長がSizeOfImageを満たしていません")
    if len(image.OPTIONAL_HEADER.DATA_DIRECTORY) <= 14:
        raise DotNetMemoryRepairError("CLR data directoryがありません")
    clr_directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    clr_rva = int(clr_directory.VirtualAddress)
    if clr_rva <= 0 or clr_rva + CLR_HEADER_SIZE > len(data):
        raise DotNetMemoryRepairError("CLR header RVAが入力境界外です")

    candidates = find_metadata_rvas(data)
    if metadata_rva is None:
        if len(candidates) != 1:
            raise DotNetMemoryRepairError(f"metadata root候補を一意に決定できません: {len(candidates)}件")
        metadata_rva = candidates[0]
    if metadata_rva < 0 or metadata_rva + 4 > len(data):
        raise DotNetMemoryRepairError("metadata RVAが入力境界外です")
    if data[metadata_rva : metadata_rva + 4] != METADATA_MAGIC:
        raise DotNetMemoryRepairError("指定metadata RVAにBSJB magicがありません")

    output = bytearray(data)
    metadata_size = _metadata_root_size(data, metadata_rva)
    first_section_rva = min(
        (int(section.VirtualAddress) for section in image.sections),
        default=len(output),
    )
    repaired_header_size = int(image.OPTIONAL_HEADER.SizeOfHeaders)
    if metadata_rva < first_section_rva:
        if metadata_rva + metadata_size > first_section_rva:
            raise DotNetMemoryRepairError("metadataがheaderとsectionの境界をまたぎます")
        file_alignment = max(1, int(image.OPTIONAL_HEADER.FileAlignment))
        repaired_header_size = ((metadata_rva + metadata_size + file_alignment - 1) // file_alignment) * file_alignment
        repaired_header_size = min(repaired_header_size, first_section_rva)
        header_offset = int(image.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfHeaders"))
        struct.pack_into("<I", output, header_offset, repaired_header_size)
    sections = _section_table_to_mapped_layout(output, image)
    struct.pack_into(
        "<IHHII",
        output,
        clr_rva,
        CLR_HEADER_SIZE,
        2,
        5,
        metadata_rva,
        metadata_size,
    )
    struct.pack_into("<II", output, clr_rva + 16, 1, 0)
    output[clr_rva + 24 : clr_rva + CLR_HEADER_SIZE] = bytes(48)

    repaired = bytes(output)
    report = {
        "schema_version": 1,
        "analysis": "dotnet_memory_image_repair",
        "status": "repaired_for_static_analysis",
        "input_size": len(data),
        "output_size": len(repaired),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "output_sha256": hashlib.sha256(repaired).hexdigest(),
        "clr_header_rva": clr_rva,
        "metadata_rva": metadata_rva,
        "metadata_size": metadata_size,
        "size_of_headers": repaired_header_size,
        "metadata_candidates": candidates,
        "sections": sections,
        "limitations": [
            "CLR entry point tokenと補助data directoryは復元せず、metadata/CIL解析専用にゼロ化しました。",
            "元の実行可能ファイルを再現する処理ではありません。",
        ],
        "executed": False,
        "emulated": False,
        "network_contacted": False,
    }
    return repaired, report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help=".NETメモリ領域")
    parser.add_argument("--output", required=True, type=Path, help="修復PEの出力先")
    parser.add_argument("--report", type=Path, help="JSONレポートの出力先")
    parser.add_argument("--metadata-rva", type=lambda value: int(value, 0))
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    for output_path in (args.output, args.report):
        if output_path is not None:
            _reject_reparse_components(output_path)
    data = _read_bounded(args.input, args.max_input_bytes)
    repaired, report = repair_dotnet_memory_image(
        data,
        metadata_rva=args.metadata_rva,
        max_output_bytes=args.max_output_bytes,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(repaired)
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
