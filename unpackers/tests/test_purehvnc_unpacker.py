"""Unit tests for PureHVNC envelope recovery."""

from __future__ import annotations

import struct

import pytest

from unpackers.purehvnc_unpacker import find_first_byte_xor_pes, first_byte_index_xor, pe_extent


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


def test_first_byte_xor_and_extent() -> None:
    """Recover a valid PE from the first-byte/index transform."""
    pe = minimal_pe()
    key = 0x51
    envelope = bytes([key]) + bytes(value ^ ((key + index) & 0xFF) for index, value in enumerate(pe))
    assert first_byte_index_xor(envelope) == pe
    assert pe_extent(pe) == len(pe)
    candidates = find_first_byte_xor_pes(b"prefix" + envelope)
    assert candidates and candidates[0].data == pe


def test_envelope_validation() -> None:
    """Reject truncated envelopes, invalid PEs, and invalid strides."""
    with pytest.raises(ValueError):
        first_byte_index_xor(b"x")
    assert pe_extent(b"not-pe") is None
    with pytest.raises(ValueError):
        find_first_byte_xor_pes(b"anything", (0,))
