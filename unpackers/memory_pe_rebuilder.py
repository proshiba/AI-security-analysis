#!/usr/bin/env python3
"""メモリ配置されたPE imageを、実行せずfile layoutへ再構成する。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pefile


MAX_INPUT_SIZE = 512 * 1024 * 1024
MAX_SECTIONS = 96


class MemoryPEError(ValueError):
    """memory imageが安全に再構成できないことを示す。"""


def rebuild_memory_pe(
    data: bytes,
    *,
    max_input_size: int = MAX_INPUT_SIZE,
) -> tuple[dict[str, object], bytes]:
    """RVA配置のsectionを検証し、PointerToRawData配置へ戻す。"""

    if not data.startswith(b"MZ"):
        raise MemoryPEError("memory imageはMZ headerで始まっていません")
    if not 1 <= len(data) <= max_input_size:
        raise MemoryPEError("memory imageのサイズが許容範囲外です")
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise MemoryPEError("PE headerを解析できません") from exc
    section_count = int(pe.FILE_HEADER.NumberOfSections)
    if section_count != len(pe.sections) or not 1 <= section_count <= MAX_SECTIONS:
        raise MemoryPEError("PE section数が不正です")
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
    size_of_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    if size_of_headers <= 0 or size_of_headers > len(data):
        raise MemoryPEError("SizeOfHeadersがmemory image境界外です")
    if size_of_image <= 0 or size_of_image > len(data):
        raise MemoryPEError("memory imageがSizeOfImageを満たしていません")

    output_size = size_of_headers
    for section in pe.sections:
        raw_offset = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        virtual_address = int(section.VirtualAddress)
        if raw_offset < 0 or raw_size < 0 or virtual_address < 0:
            raise MemoryPEError("sectionに負の範囲があります")
        if virtual_address + raw_size > len(data):
            raise MemoryPEError("section RVA範囲がmemory image境界を超えています")
        if raw_offset + raw_size > max_input_size:
            raise MemoryPEError("再構成後のsection範囲が上限を超えます")
        output_size = max(output_size, raw_offset + raw_size)

    rebuilt = bytearray(output_size)
    rebuilt[:size_of_headers] = data[:size_of_headers]
    sections: list[dict[str, object]] = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\0").decode("ascii", errors="replace")
        raw_offset = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        virtual_address = int(section.VirtualAddress)
        rebuilt[raw_offset : raw_offset + raw_size] = data[
            virtual_address : virtual_address + raw_size
        ]
        sections.append(
            {
                "name": name,
                "virtual_address": virtual_address,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
            }
        )

    rebuilt_bytes = bytes(rebuilt)
    try:
        verified = pefile.PE(data=rebuilt_bytes, fast_load=True)
    except pefile.PEFormatError as exc:
        raise MemoryPEError("再構成したPEを再解析できません") from exc
    if len(verified.sections) != section_count:
        raise MemoryPEError("再構成後のsection数が一致しません")

    return {
        "schema_version": 1,
        "status": "rebuilt",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "input_size": len(data),
        "size_of_image": size_of_image,
        "output_sha256": hashlib.sha256(rebuilt_bytes).hexdigest(),
        "output_size": len(rebuilt_bytes),
        "machine": hex(int(pe.FILE_HEADER.Machine)),
        "entry_point_rva": hex(int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)),
        "sections": sections,
        "executed": False,
        "emulated": False,
        "network_contacted": False,
    }, rebuilt_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--max-input-size", type=int, default=MAX_INPUT_SIZE)
    return parser


def _reject_aliases(paths: list[Path]) -> None:
    resolved = [path.resolve() for path in paths]
    if len(set(resolved)) != len(resolved):
        raise ValueError("input、output、reportは異なるパスである必要があります")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _reject_aliases([args.input, args.output, args.report])
    if args.input.stat().st_size > args.max_input_size:
        raise MemoryPEError("memory imageのサイズが許容範囲外です")
    report, rebuilt = rebuild_memory_pe(
        args.input.read_bytes(), max_input_size=args.max_input_size
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(rebuilt)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": report["output_sha256"],
                "size": report["output_size"],
                "executed": False,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
