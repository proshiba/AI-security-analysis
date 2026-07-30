"""回転・XOR Donut sidecar復元の回帰テスト。"""

from __future__ import annotations

import struct

import pytest

from unpackers.rotated_xor_donut import (
    decode_rotated_xor,
    recover_rotated_xor_donut,
)


def _donut_fixture() -> bytes:
    """厳格なcall-over-instance検証を通る最小Donut fixtureを返す。"""

    instance = bytearray(0x300)
    struct.pack_into("<I", instance, 0x23C, 3)
    instance[0x240:0x24C] = b"ole32;wininet"
    return b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"


def _encode(clear: bytes, rotation: int, xor_key: int) -> bytes:
    xored = bytes(value ^ xor_key for value in clear)
    shift = rotation % len(clear)
    return xored[shift:] + xored[:shift] if shift else xored


def test_rotated_xor_sidecar_recovers_only_valid_donut() -> None:
    clear = _donut_fixture()
    encoded = _encode(clear, 0x3EF14, 0xC6)
    assert decode_rotated_xor(encoded) == clear
    report, artifacts = recover_rotated_xor_donut(encoded)
    assert report["status"] == "donut_shellcode_recovered"
    assert artifacts == [("rotated-xor-donut-shellcode", clear)]


def test_rotated_xor_sidecar_rejects_noise_and_invalid_parameters() -> None:
    report, artifacts = recover_rotated_xor_donut(b"ordinary sidecar data")
    assert report["status"] == "profile_not_matched"
    assert artifacts == []
    with pytest.raises(ValueError):
        decode_rotated_xor(b"")
    with pytest.raises(ValueError):
        decode_rotated_xor(b"x", xor_key=256)
