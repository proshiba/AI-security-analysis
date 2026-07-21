"""静的解析用の最小ELFレイアウト解析機能。"""

from __future__ import annotations

from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class LoadSegment:
    """ファイルオフセットと仮想アドレスを対応付けるPT_LOAD。"""

    offset: int
    virtual_address: int
    file_size: int
    memory_size: int


@dataclass(frozen=True)
class ElfLayout:
    """抽出器が必要とするELFヘッダー情報。"""

    bits: int
    byte_order: str
    machine: int
    entry_point: int
    segments: tuple[LoadSegment, ...]

    def virtual_to_offset(self, address: int, size: int = 1) -> int:
        """ファイルに存在する仮想アドレスをオフセットへ変換する。"""
        if size < 0:
            raise ValueError("sizeは0以上でなければなりません")
        for segment in self.segments:
            relative = address - segment.virtual_address
            if 0 <= relative and relative + size <= segment.file_size:
                return segment.offset + relative
        raise ValueError(f"仮想アドレス0x{address:x}はファイル内に存在しません")


def parse_elf_layout(data: bytes) -> ElfLayout:
    """ELF32/ELF64のヘッダーとPT_LOADだけを安全に解析する。"""
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("ELFファイルではありません")

    elf_class = data[4]
    encoding = data[5]
    if elf_class not in (1, 2):
        raise ValueError(f"未対応のELFクラスです: {elf_class}")
    if encoding not in (1, 2):
        raise ValueError(f"未対応のバイト順です: {encoding}")

    endian = "<" if encoding == 1 else ">"
    header_format = endian + ("HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH")
    header_size = struct.calcsize(header_format)
    if len(data) < 16 + header_size:
        raise ValueError("ELFヘッダーが途中で切れています")
    header = struct.unpack_from(header_format, data, 16)
    machine = header[1]
    entry_point = header[3]
    program_offset = header[4]
    program_entry_size = header[8]
    program_count = header[9]

    program_format = endian + ("IIIIIIII" if elf_class == 1 else "IIQQQQQQ")
    minimum_program_size = struct.calcsize(program_format)
    if program_entry_size < minimum_program_size and program_count:
        raise ValueError("プログラムヘッダーのエントリー長が不正です")

    segments: list[LoadSegment] = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        if offset + minimum_program_size > len(data):
            raise ValueError("プログラムヘッダーが途中で切れています")
        values = struct.unpack_from(program_format, data, offset)
        if values[0] != 1:
            continue
        if elf_class == 1:
            file_offset, virtual_address, file_size, memory_size = (
                values[1], values[2], values[4], values[5]
            )
        else:
            file_offset, virtual_address, file_size, memory_size = (
                values[2], values[3], values[5], values[6]
            )
        if file_offset + file_size > len(data):
            raise ValueError("PT_LOADがファイル終端を越えています")
        segments.append(LoadSegment(file_offset, virtual_address, file_size, memory_size))

    return ElfLayout(
        bits=32 if elf_class == 1 else 64,
        byte_order="little" if encoding == 1 else "big",
        machine=machine,
        entry_point=entry_point,
        segments=tuple(segments),
    )
