"""Unit tests for strict contiguous and sparse Donut discovery."""

from __future__ import annotations

import struct

import pytest

from unpackers.donut_unpacker import find_donut_shellcodes


def donut_fixture() -> bytes:
    """Build a minimal structurally valid modern Donut shellcode fixture."""
    payload = b"MZterminal"
    module = bytearray(1320 + len(payload))
    struct.pack_into("<III", module, 0, 2, 0, 1)
    module[12:22] = b"v4.0.30319"
    struct.pack_into("<II", module, 1312, len(payload), len(payload))
    module[1320:] = payload
    instance = bytearray(0xDB0 + len(module))
    struct.pack_into("<I", instance, 0x234, 0)
    struct.pack_into("<I", instance, 0x290, 3)
    instance[0x294:0x2A0] = b"ole32;wininet"
    struct.pack_into("<I", instance, 0x974, 2)
    struct.pack_into("<Q", instance, 0xDA8, len(module))
    instance[0xDB0:] = module
    return b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"


def test_find_contiguous_and_sparse_donut() -> None:
    """Find strict Donut structures and retain original offsets and strides."""
    shellcode = donut_fixture()
    contiguous = find_donut_shellcodes(b"xx" + shellcode, (1,))
    sparse_bytes = b"".join(bytes([value, 0, 0, 0]) for value in shellcode)
    sparse = find_donut_shellcodes(b"abc" + sparse_bytes, (4,))
    assert contiguous[0].offset == 2 and contiguous[0].data == shellcode
    assert sparse[0].offset == 3 and sparse[0].stride == 4


def test_find_donut_rejects_invalid_stride() -> None:
    """Reject non-positive lane strides."""
    with pytest.raises(ValueError):
        find_donut_shellcodes(b"noise", (0,))



def test_false_candidates_do_not_copy_large_intervals() -> None:
    """Reject plausible-length call bytes before slicing candidate intervals."""
    block = b"\xe8" + struct.pack("<I", 1024) + b"A" * 1029
    noise = block * 2048
    assert find_donut_shellcodes(noise, (1, 4)) == []
