#!/usr/bin/env python3
"""メモリ領域として保存されたPEを、実行せずファイル配置へ再構成する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
from pathlib import Path
from typing import Any

import pefile

DEFAULT_MAX_INPUT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class MappedPEError(ValueError):
    """再構成できない入力または安全上限違反を表す。"""


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_reparse_components(path: Path) -> None:
    """既存の親要素にsymlinkやjunctionが含まれる出力先を拒否する。"""

    absolute = path.absolute()
    current = Path(absolute.parts[0])
    if _is_reparse_point(current):
        raise MappedPEError(f"出力先にreparse pointが含まれます: {current}")
    for part in absolute.parts[1:]:
        current /= part
        try:
            current.lstat()
        except FileNotFoundError:
            break
        if _is_reparse_point(current):
            raise MappedPEError(f"出力先にreparse pointが含まれます: {current}")


def _bounded_positive(value: int, name: str) -> int:
    if value <= 0:
        raise MappedPEError(f"{name}は正の整数である必要があります")
    return value


def rebuild_mapped_pe(
    data: bytes,
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[bytes, dict[str, Any]]:
    """メモリ配置のsectionをPEヘッダー記載のraw offsetへコピーする。"""

    _bounded_positive(max_output_bytes, "max_output_bytes")
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise MappedPEError("入力はMZヘッダーを持つPEメモリ領域ではありません")
    try:
        image = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise MappedPEError(f"PEヘッダーを解析できません: {exc}") from exc

    header_size = int(image.OPTIONAL_HEADER.SizeOfHeaders)
    image_size = int(image.OPTIONAL_HEADER.SizeOfImage)
    if not 0 < header_size <= len(data):
        raise MappedPEError("SizeOfHeadersが入力境界外です")
    if not 0 < image_size <= len(data):
        raise MappedPEError("入力長がSizeOfImageを満たしていません")

    output_size = header_size
    sections: list[dict[str, Any]] = []
    for section in image.sections:
        virtual_address = int(section.VirtualAddress)
        virtual_size = int(section.Misc_VirtualSize)
        raw_offset = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        if min(virtual_address, virtual_size, raw_offset, raw_size) < 0:
            raise MappedPEError("sectionに負の値があります")
        if virtual_address + min(virtual_size, raw_size) > len(data):
            raise MappedPEError(f"sectionのメモリ範囲が入力境界外です: {section.Name!r}")
        output_size = max(output_size, raw_offset + raw_size)
        sections.append(
            {
                "name": bytes(section.Name).rstrip(b"\0").decode("latin-1"),
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
            }
        )

    if output_size > max_output_bytes:
        raise MappedPEError(f"再構成後サイズが上限を超えます: {output_size} > {max_output_bytes}")

    rebuilt = bytearray(output_size)
    rebuilt[:header_size] = data[:header_size]
    for section in sections:
        copy_size = min(section["virtual_size"], section["raw_size"])
        source_start = section["virtual_address"]
        target_start = section["raw_offset"]
        rebuilt[target_start : target_start + copy_size] = data[source_start : source_start + copy_size]

    try:
        parsed = pefile.PE(data=bytes(rebuilt), fast_load=True)
    except pefile.PEFormatError as exc:
        raise MappedPEError(f"再構成後PEを検証できません: {exc}") from exc

    report = {
        "schema_version": 1,
        "analysis": "mapped_pe_reconstruction",
        "status": "rebuilt",
        "input_size": len(data),
        "output_size": len(rebuilt),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "output_sha256": hashlib.sha256(rebuilt).hexdigest(),
        "machine": f"0x{int(parsed.FILE_HEADER.Machine):04x}",
        "image_base": f"0x{int(parsed.OPTIONAL_HEADER.ImageBase):x}",
        "size_of_image": image_size,
        "sections": sections,
        "executed": False,
        "emulated": False,
        "network_contacted": False,
    }
    return bytes(rebuilt), report


def _read_bounded(path: Path, limit: int) -> bytes:
    _bounded_positive(limit, "max_input_bytes")
    size = path.stat().st_size
    if size > limit:
        raise MappedPEError(f"入力サイズが上限を超えます: {size} > {limit}")
    data = path.read_bytes()
    if len(data) != size:
        raise MappedPEError("入力の読み取り中にサイズが変化しました")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="PEメモリ領域")
    parser.add_argument("--output", required=True, type=Path, help="再構成PEの出力先")
    parser.add_argument("--report", type=Path, help="JSONレポートの出力先")
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    for output_path in (args.output, args.report):
        if output_path is not None:
            _reject_reparse_components(output_path)
    data = _read_bounded(args.input, args.max_input_bytes)
    rebuilt, report = rebuild_mapped_pe(
        data,
        max_output_bytes=args.max_output_bytes,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(rebuilt)
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
