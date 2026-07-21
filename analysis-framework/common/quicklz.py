#!/usr/bin/env python3
"""QuickLZ 1.5 level 1/3 を境界検証付きで静的展開する。"""

from __future__ import annotations


def parse_header(data: bytes) -> dict[str, int | bool]:
    """QuickLZフレームヘッダーを検証して返す。"""
    if len(data) < 3:
        raise ValueError("QuickLZ入力が短すぎます")
    header_size = 9 if data[0] & 2 else 3
    if len(data) < header_size:
        raise ValueError("QuickLZヘッダーが途中で終わっています")
    width = 4 if header_size == 9 else 1
    compressed_size = int.from_bytes(data[1 : 1 + width], "little")
    decompressed_size = int.from_bytes(data[1 + width : 1 + width * 2], "little")
    if compressed_size < header_size or compressed_size > len(data):
        raise ValueError("QuickLZ圧縮サイズが不正です")
    if decompressed_size <= 0:
        raise ValueError("QuickLZ展開サイズが不正です")
    return {
        "header_size": header_size,
        "compressed_size": compressed_size,
        "decompressed_size": decompressed_size,
        "level": (data[0] >> 2) & 3,
        "is_compressed": bool(data[0] & 1),
    }


def _hash_level1(buffer: bytearray, position: int) -> int:
    value = buffer[position] | buffer[position + 1] << 8 | buffer[position + 2] << 16
    return ((value >> 12) ^ value) & 0x0FFF


def _decompress_level1(data: bytes, header: dict[str, int | bool]) -> bytes:
    source = int(header["header_size"])
    output_size = int(header["decompressed_size"])
    output = bytearray()
    hash_offsets = [0] * 4096
    last_hashed = -1
    control_word = 1

    def update_hash(position: int) -> None:
        if position + 2 < len(output):
            hash_offsets[_hash_level1(output, position)] = position

    while len(output) < output_size:
        if control_word == 1:
            if source + 4 > len(data):
                raise ValueError("QuickLZ制御語が途中で終わっています")
            control_word = int.from_bytes(data[source : source + 4], "little")
            source += 4
        if control_word & 1:
            if source + 3 > len(data):
                raise ValueError("QuickLZ一致トークンが途中で終わっています")
            fetch = int.from_bytes(data[source : source + 4].ljust(4, b"\0"), "little")
            match_offset = hash_offsets[(fetch >> 4) & 0x0FFF]
            if fetch & 0x0F:
                match_length = (fetch & 0x0F) + 2
                source += 2
            else:
                match_length = data[source + 2]
                source += 3
            if match_offset < 0 or match_offset >= len(output):
                raise ValueError("QuickLZ一致オフセットが不正です")
            match_start = len(output)
            for index in range(match_length):
                if len(output) >= output_size:
                    break
                output.append(output[match_offset + index])
            while last_hashed < match_start:
                last_hashed += 1
                update_hash(last_hashed)
            last_hashed = len(output) - 1
        else:
            if source >= len(data):
                raise ValueError("QuickLZリテラルが途中で終わっています")
            output.append(data[source])
            source += 1
            while last_hashed < len(output) - 3:
                last_hashed += 1
                update_hash(last_hashed)
        control_word >>= 1
    return bytes(output)


def _decompress_level3(data: bytes, header: dict[str, int | bool]) -> bytes:
    source = int(header["header_size"])
    output_size = int(header["decompressed_size"])
    output = bytearray()
    control_word = 1
    bit_lengths = (4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0)
    last_match_start = output_size - 11

    while len(output) < output_size:
        if control_word == 1:
            if source + 4 > len(data):
                raise ValueError("QuickLZ制御語が途中で終わっています")
            control_word = int.from_bytes(data[source : source + 4], "little")
            source += 4
        if source + 4 > len(data) and len(output) < last_match_start:
            raise ValueError("QuickLZ level 3トークンが途中で終わっています")
        fetch = int.from_bytes(data[source : source + 4].ljust(4, b"\0"), "little")
        if control_word & 1:
            control_word >>= 1
            if fetch & 3 == 0:
                offset, match_length, consumed = (fetch & 0xFF) >> 2, 3, 1
            elif fetch & 2 == 0:
                offset, match_length, consumed = (fetch & 0xFFFF) >> 2, 3, 2
            elif fetch & 1 == 0:
                offset = (fetch & 0xFFFF) >> 6
                match_length, consumed = ((fetch >> 2) & 0x0F) + 3, 2
            elif fetch & 0x7F != 3:
                offset = (fetch >> 7) & 0x1FFFF
                match_length, consumed = ((fetch >> 2) & 0x1F) + 2, 3
            else:
                offset = fetch >> 15
                match_length, consumed = ((fetch >> 7) & 0xFF) + 3, 4
            source += consumed
            if offset < 3 or offset > len(output):
                raise ValueError("QuickLZ level 3一致オフセットが不正です")
            if len(output) + match_length > output_size - 4:
                raise ValueError("QuickLZ level 3一致長が不正です")
            for _ in range(match_length):
                output.append(output[-offset])
            continue

        if len(output) < last_match_start:
            literal_count = bit_lengths[control_word & 0x0F]
            if literal_count <= 0 or source + literal_count > len(data):
                raise ValueError("QuickLZ level 3リテラルが途中で終わっています")
            output.extend(data[source : source + literal_count])
            source += literal_count
            control_word >>= literal_count
            continue

        while len(output) < output_size:
            if control_word == 1:
                if source + 4 > len(data):
                    raise ValueError("QuickLZ末尾制御語が途中で終わっています")
                source += 4
                control_word = 1 << 31
            if source >= len(data):
                raise ValueError("QuickLZ末尾リテラルが途中で終わっています")
            output.append(data[source])
            source += 1
            control_word >>= 1
    return bytes(output)


def decompress(data: bytes) -> bytes:
    """QuickLZ 1.5 level 1/3フレームを展開する。"""
    header = parse_header(data)
    source = int(header["header_size"])
    output_size = int(header["decompressed_size"])
    if not header["is_compressed"]:
        end = source + output_size
        if end > len(data):
            raise ValueError("QuickLZ非圧縮本体が途中で終わっています")
        return data[source:end]
    if header["level"] == 1:
        return _decompress_level1(data, header)
    if header["level"] == 3:
        return _decompress_level3(data, header)
    raise ValueError(f"未対応のQuickLZ levelです: {header['level']}")
