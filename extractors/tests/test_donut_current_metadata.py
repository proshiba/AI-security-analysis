"""Tests for current Donut delivery metadata extraction."""

from __future__ import annotations

import struct

from extractors.donutloader.extractor import inspect_chain
from unpackers.donut_unpacker import chaskey_ctr


def current_donut_fixture() -> bytes:
    """Build an encrypted current-layout instance without a terminal PE."""
    instance = bytearray(0x400)
    instance[4:20] = bytes(range(16))
    instance[20:36] = bytes(range(16, 32))
    struct.pack_into("<I", instance, 0x240, 52)
    dlls = b"ole32;oleaut32;wininet;mscoree;shell32\0"
    instance[0x244 : 0x244 + len(dlls)] = dlls
    instance[0x240:] = chaskey_ctr(
        bytes(instance[4:20]),
        bytes(instance[20:36]),
        bytes(instance[0x240:]),
    )
    return (
        b"\xe8"
        + struct.pack("<I", len(instance))
        + instance
        + b"\x59\x48\x89\x5c\x24\x08"
    )


def test_current_layout_metadata_does_not_use_legacy_offsets() -> None:
    """Report current layout metadata without invoking legacy module parsing."""
    result = inspect_chain(current_donut_fixture(), deep=False)
    candidate = result["donut_candidates"][0]
    assert candidate["layout"] == "current-0x240-array"
    assert candidate["payloads"] == []
    assert "unpack_error" not in candidate
