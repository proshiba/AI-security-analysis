#!/usr/bin/env python3
"""UPX/UCL系で使われるNRV2E/LE32ストリームを上限付きで静的展開する。"""

from __future__ import annotations


class NrvError(ValueError):
    """入力破損または設定上限超過を表す。"""


class Le32Bits:
    def __init__(self, source: bytes):
        self.source = source
        self.offset = 0
        self.buffer = 0
        self.remaining = 0

    def bit(self) -> int:
        if self.remaining:
            self.remaining -= 1
            return (self.buffer >> self.remaining) & 1
        if self.offset + 4 > len(self.source):
            raise NrvError("NRV2Eビット列が途中で終了しました")
        self.buffer = int.from_bytes(self.source[self.offset : self.offset + 4], "little")
        self.offset += 4
        self.remaining = 31
        return (self.buffer >> 31) & 1


def decompress_nrv2e_le32(source: bytes, max_output: int) -> tuple[bytes, int]:
    """UCLのNRV2E/LE32形式を実行せず、出力上限内で展開する。"""
    bits = Le32Bits(source)
    output = bytearray()
    last_offset = 1
    while True:
        while bits.bit():
            if bits.offset >= len(source):
                raise NrvError("NRV2Eリテラルが入力範囲を超えました")
            output.append(source[bits.offset])
            bits.offset += 1

        match_offset = 1
        while True:
            match_offset = match_offset * 2 + bits.bit()
            if match_offset > 0xFFFFFF + 3:
                raise NrvError("NRV2E参照オフセットが範囲外です")
            if bits.bit():
                break
            match_offset = (match_offset - 1) * 2 + bits.bit()

        if match_offset == 2:
            match_offset = last_offset
            match_length = bits.bit()
        else:
            if bits.offset >= len(source):
                raise NrvError("NRV2Eオフセットが入力範囲を超えました")
            match_offset = (match_offset - 3) * 256 + source[bits.offset]
            bits.offset += 1
            if match_offset == 0xFFFFFFFF:
                break
            match_length = (match_offset ^ 0xFFFFFFFF) & 1
            match_offset = (match_offset >> 1) + 1
            last_offset = match_offset

        if match_length:
            match_length = 1 + bits.bit()
        elif bits.bit():
            match_length = 3 + bits.bit()
        else:
            match_length = 1
            while True:
                match_length = match_length * 2 + bits.bit()
                if match_length >= max_output:
                    raise NrvError("NRV2E一致長が出力上限を超えました")
                if bits.bit():
                    break
            match_length += 3
        match_length += match_offset > 0x500

        if match_offset > len(output):
            raise NrvError("NRV2E後方参照が出力先頭より前を指しています")
        if len(output) + match_length + 1 > max_output:
            raise NrvError("NRV2E展開結果が設定上限を超えました")
        copy_from = len(output) - match_offset
        for _ in range(match_length + 1):
            output.append(output[copy_from])
            copy_from += 1
    return bytes(output), bits.offset
