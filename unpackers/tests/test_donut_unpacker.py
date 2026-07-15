"""Unit tests for static Donut module recovery."""

from __future__ import annotations

import struct

import pytest

from unpackers.donut_unpacker import (
    chaskey_block,
    chaskey_ctr,
    decrypt_instance,
    is_donut_shellcode,
    parse_module,
    recover_module_payload,
    rotr32,
    sha256_bytes,
    unpack_donut,
)


def fixture_shellcode() -> tuple[bytes, bytes]:
    """Build a minimal unencrypted modern Donut fixture."""
    payload = b"MZtest-terminal"
    module = bytearray(1320 + len(payload))
    struct.pack_into("<III", module, 0, 2, 0, 1)
    module[12:22] = b"v4.0.30319"
    module[268:272] = b"LAB\0"
    struct.pack_into("<II", module, 1312, len(payload), len(payload))
    module[1320:] = payload
    instance = bytearray(0xDB0 + len(module))
    struct.pack_into("<I", instance, 0x234, 0)
    struct.pack_into("<I", instance, 0x290, 3)
    instance[0x294:0x2A0] = b"ole32;wininet"
    struct.pack_into("<I", instance, 0x974, 2)
    struct.pack_into("<Q", instance, 0xDA8, len(module))
    instance[0xDB0:] = module
    shellcode = b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"
    return shellcode, payload


def test_hash_rotate_and_chaskey_validation() -> None:
    """Exercise deterministic primitives and their bounds checks."""
    assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert rotr32(1, 1) == 0x80000000
    assert len(chaskey_block(bytes(16), bytes(16))) == 16
    with pytest.raises(ValueError):
        chaskey_block(b"x", bytes(16))


def test_ctr_round_trip_and_full_unpack() -> None:
    """Verify CTR reversibility and recover the synthetic terminal module."""
    clear = b"abc" * 20
    encrypted = chaskey_ctr(bytes(range(16)), bytes(16), clear)
    assert chaskey_ctr(bytes(range(16)), bytes(16), encrypted) == clear
    shellcode, payload = fixture_shellcode()
    assert is_donut_shellcode(shellcode)
    instance, layout = decrypt_instance(shellcode)
    assert layout.name == "modern-0x290"
    module = instance[0xDB0:]
    assert parse_module(module)["runtime"] == "v4.0.30319"
    assert recover_module_payload(module) == payload
    assert unpack_donut(shellcode).payload == payload


def test_reject_non_donut_and_unsupported_compression() -> None:
    """Reject malformed instances and unsupported module compression."""
    assert not is_donut_shellcode(b"MZ")
    with pytest.raises(ValueError):
        decrypt_instance(b"MZ")
    module = bytearray(1320)
    struct.pack_into("<I", module, 8, 9)
    with pytest.raises(ValueError):
        recover_module_payload(bytes(module))
