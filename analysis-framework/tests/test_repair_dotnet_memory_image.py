"""アンチダンプ済み.NETメモリ領域修復の単体テスト。"""

from __future__ import annotations

from pathlib import Path
import struct
import sys

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRAMEWORK))

from common import repair_dotnet_memory_image as repair  # noqa: E402


def _damaged_dotnet_image(*, duplicate_metadata: bool = False) -> bytes:
    data = bytearray(0x3000)
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
    struct.pack_into("<I", data, optional + 56, 0x3000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 14 * 8, 0x1008, 72)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x250:0x254] = b"BSJB"
    struct.pack_into("<HHII", data, 0x254, 1, 1, 0, 12)
    data[0x260:0x26C] = b"v4.0.30319\0\0"
    struct.pack_into("<HH", data, 0x26C, 0, 1)
    struct.pack_into("<II", data, 0x270, 0x40, 4)
    data[0x278:0x27C] = b"#~\0\0"
    data[0x1008 : 0x1008 + 72] = b"X" * 72
    if duplicate_metadata:
        data[0x300:0x304] = b"BSJB"
    return bytes(data)


def test_repair_restores_clr_header_and_mapped_section_offsets() -> None:
    repaired, report = repair.repair_dotnet_memory_image(_damaged_dotnet_image())

    assert struct.unpack_from("<I", repaired, 0x1008)[0] == 72
    assert struct.unpack_from("<I", repaired, 0x1010)[0] == 0x250
    assert struct.unpack_from("<I", repaired, 0x1018)[0] == 1
    section = 0x98 + 0xE0
    assert struct.unpack_from("<I", repaired, section + 20)[0] == 0x1000
    assert report["metadata_rva"] == 0x250
    assert report["metadata_size"] == 0x44
    assert report["size_of_headers"] == 0x400
    assert report["executed"] is False


def test_repair_requires_unique_or_explicit_metadata_root() -> None:
    data = _damaged_dotnet_image(duplicate_metadata=True)
    with pytest.raises(repair.DotNetMemoryRepairError, match="一意"):
        repair.repair_dotnet_memory_image(data)
    _, report = repair.repair_dotnet_memory_image(data, metadata_rva=0x250)
    assert report["metadata_candidates"] == [0x250, 0x300]


def test_repair_rejects_invalid_metadata_and_size_budget() -> None:
    data = _damaged_dotnet_image()
    with pytest.raises(repair.DotNetMemoryRepairError, match="BSJB"):
        repair.repair_dotnet_memory_image(data, metadata_rva=0x260)
    with pytest.raises(repair.DotNetMemoryRepairError, match="上限"):
        repair.repair_dotnet_memory_image(data, max_output_bytes=1024)
