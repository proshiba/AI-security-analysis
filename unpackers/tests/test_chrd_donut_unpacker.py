"""Unit tests for bounded CHRD reconstruction primitives."""

from __future__ import annotations

import struct

import pytest

from unpackers.chrd_donut_unpacker import (
    decode_low_nibbles,
    decode_numeric_stream,
    decrypt_outer_blob,
    parse_chrd_config,
    pe_resources,
    recover_numeric_stream,
    rol32,
    rol8,
    ror8,
    sha256_bytes,
)


def test_rotations_hash_nibbles_and_outer_transform() -> None:
    """Exercise small deterministic CHRD transformations."""
    assert rol8(0x81, 1) == 0x03
    assert ror8(0x03, 1) == 0x81
    assert rol32(0x80000000, 1) == 1
    assert sha256_bytes(b"a").startswith("ca9781")
    assert decode_low_nibbles({15000: bytes([0x1A, 0x2B, 0x3C, 0x4D])}) == b"\xab\xcd"
    assert len(decrypt_outer_blob(bytes(8))) == 8


def test_numeric_affine_segment() -> None:
    """Decode a simple affine numeric segment without executing any payload."""
    values = [10.0, 20.0]
    arrays = values + [0.0, 0.0] + [1.0, 1.0] + [0.0, 0.0]
    stream = struct.pack("<I", 1) + bytes([1]) + bytes(8) + struct.pack("<I", 2) + struct.pack("<8d", *arrays)
    assert decode_numeric_stream(stream) == bytes([10, 20])


def test_chrd_validation_paths() -> None:
    """Reject missing resources and malformed configs/carriers."""
    with pytest.raises(ValueError):
        decode_low_nibbles({})
    with pytest.raises(ValueError):
        parse_chrd_config(b"CHRD")
    with pytest.raises(ValueError):
        recover_numeric_stream(b"short", {"version": 99})
    with pytest.raises(Exception):
        pe_resources(b"MZ" + bytes(1024))
