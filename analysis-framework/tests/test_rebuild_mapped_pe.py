"""メモリ配置PE再構成の単体テスト。"""

from __future__ import annotations

import struct
from pathlib import Path
import sys

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRAMEWORK))

from common import rebuild_mapped_pe as mapped  # noqa: E402


def _mapped_pe_fixture() -> bytes:
    """raw offsetとRVAが異なる最小PE32メモリ領域を作る。"""

    data = bytearray(0x2000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 4, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x1000:0x1004] = b"\x90\x90\xc3\x00"
    return bytes(data)


def test_rebuild_mapped_pe_moves_virtual_section_to_raw_offset() -> None:
    rebuilt, report = mapped.rebuild_mapped_pe(_mapped_pe_fixture())

    assert rebuilt[0x200:0x204] == b"\x90\x90\xc3\x00"
    assert report["status"] == "rebuilt"
    assert report["sections"][0]["virtual_address"] == 0x1000
    assert report["sections"][0]["raw_offset"] == 0x200
    assert report["executed"] is False
    assert report["network_contacted"] is False


def test_rebuild_mapped_pe_rejects_truncated_and_oversized_output() -> None:
    with pytest.raises(mapped.MappedPEError, match="MZ"):
        mapped.rebuild_mapped_pe(b"not a PE")
    with pytest.raises(mapped.MappedPEError, match="SizeOfImage"):
        mapped.rebuild_mapped_pe(_mapped_pe_fixture()[:0x1000])
    with pytest.raises(mapped.MappedPEError, match="上限"):
        mapped.rebuild_mapped_pe(_mapped_pe_fixture(), max_output_bytes=0x100)
