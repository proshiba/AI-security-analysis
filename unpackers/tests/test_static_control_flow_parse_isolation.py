"""malformed import directoryの制御フロー解析fail isolationを検証する。"""

from __future__ import annotations

import struct

import pytest

from unpackers import static_control_flow


def _minimal_pe() -> bytes:
    """entrypointがRETだけの小さなPE32 fixtureを返す。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
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
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200] = 0xC3
    return bytes(data)


def test_import_directory_struct_error_is_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """import parseだけのstruct.errorでCFG全体を失敗させない。"""

    image = static_control_flow.pefile.PE(data=_minimal_pe(), fast_load=True)

    def broken_directory_parse(**_kwargs) -> None:
        raise struct.error("malformed import directory")

    image.parse_data_directories = broken_directory_parse
    monkeypatch.setattr(
        static_control_flow.pefile,
        "PE",
        lambda **_kwargs: image,
    )
    result = static_control_flow.analyze_pe_control_flow(_minimal_pe())

    assert result["status"] == "analyzed"
    assert result["static_context"]["import_directory_parse"] == {
        "status": "parse_failed",
        "error_type": "error",
    }
    assert result["executed"] is False
    assert result["network_contacted"] is False
