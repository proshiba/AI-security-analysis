"""Unit tests for family-neutral index-XOR PE recovery."""

from __future__ import annotations

import struct

import pytest

from unpackers.index_xor_pe_unpacker import candidate_report, find_first_byte_xor_pes, first_byte_index_xor, pe_extent


def minimal_pe() -> bytes:
    """Build a small structurally valid PE fixture."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xE0)
    section = 0x80 + 24 + 0xE0
    struct.pack_into("<II", data, section + 16, 0x200, 0x200)
    return bytes(data)


def test_contiguous_and_sparse_recovery_and_report() -> None:
    """Recover the same PE from contiguous and sparse index-XOR storage."""
    pe = minimal_pe()
    key = 0x51
    envelope = bytes([key]) + bytes(value ^ ((key + index) & 0xFF) for index, value in enumerate(pe))
    sparse = b"".join(bytes([value, 0xAA, 0xBB, 0xCC]) for value in envelope)
    contiguous = find_first_byte_xor_pes(b"prefix" + envelope, (1,))
    lanes = find_first_byte_xor_pes(b"prefix!" + sparse, (4,))
    assert contiguous[0].data == pe
    assert lanes[0].data == pe
    assert candidate_report(contiguous)[0]["size"] == len(pe)
    assert pe_extent(pe) == len(pe)
    assert first_byte_index_xor(envelope) == pe


def test_index_xor_validation() -> None:
    """Reject invalid envelopes, PE headers, and stride values."""
    with pytest.raises(ValueError):
        first_byte_index_xor(b"x")
    with pytest.raises(ValueError):
        find_first_byte_xor_pes(b"anything", (0,))
    assert pe_extent(b"not-pe") is None

