from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK = ROOT / "analysis-framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from malware.formbook_loader import xor2f_terminal_unpacker as unpacker


def _fixture() -> tuple[bytes, bytes]:
    raw_offset = 0x1000
    section_rva = 0x1000
    entry_rva = 0x1550
    marker_raw = 0x36C3
    section_size = 0x45E00
    data = bytearray(raw_offset + section_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, entry_rva)
    section = optional + 0xE0
    data[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, section + 8, section_size, section_rva, section_size, raw_offset)
    struct.pack_into("<I", data, section + 36, 0x60000020)

    cursor = raw_offset
    for value in unpacker.PACKER_DWORD_ANCHORS:
        struct.pack_into("<I", data, cursor, value)
        cursor += 4

    final = bytearray(unpacker.REGION_SIZE)
    final[unpacker.INNER_ENTRY_OFFSET : unpacker.INNER_ENTRY_OFFSET + 16] = bytes.fromhex(
        "558bec83ec64e835e6ffff8be55dc3aa"
    )
    key1 = unpacker._derive_key(unpacker.KEY1_SEED, unpacker.KEY1_XOR_MASKS)
    key2 = unpacker._derive_key(unpacker.KEY2_SEED, unpacker.KEY2_XOR_MASKS)

    zero = bytes(unpacker.REGION_SIZE)
    keystream1 = unpacker._rc4(zero, key1)
    combined_keystream = b"".join(
        unpacker._rc4(keystream1[offset : offset + unpacker.RC4_CHUNK_SIZE], key2)
        for offset in range(0, len(keystream1), unpacker.RC4_CHUNK_SIZE)
    )
    final[: len(unpacker.REGION_MARKER)] = bytes(
        left ^ right
        for left, right in zip(unpacker.REGION_MARKER, combined_keystream)
    )
    layer1 = b"".join(
        unpacker._rc4(
            final[offset : offset + unpacker.RC4_CHUNK_SIZE],
            key2,
        )
        for offset in range(0, len(final), unpacker.RC4_CHUNK_SIZE)
    )
    encrypted = unpacker._rc4(layer1, key1)
    assert encrypted.startswith(unpacker.REGION_MARKER)
    data[marker_raw : marker_raw + len(encrypted)] = encrypted
    return bytes(data), bytes(final)


def test_recovers_two_layer_rc4_memory_image_without_family_promotion() -> None:
    sample, expected = _fixture()

    report, artifacts = unpacker.recover_xor2f_native_memory_image(sample)

    assert report["status"] == "native_memory_image_recovered"
    assert report["supports_family_attribution"] is False
    assert report["terminal_payload_recovered"] is False
    assert report["static_config_recovered"] is False
    assert report["c2"] == []
    assert report["artifact"]["sha256"] == hashlib.sha256(expected).hexdigest()
    assert artifacts == [("decrypted_native_memory_image", expected)]
    assert report["static_unpack"]["raw_key_material_included"] is False


def test_missing_structural_anchor_is_rejected() -> None:
    sample, _expected = _fixture()
    changed = bytearray(sample)
    anchor = struct.pack("<I", unpacker.KEY1_XOR_MASKS[0])
    offset = changed.find(anchor, 0x1000, 0x36C3)
    assert offset >= 0
    changed[offset : offset + 4] = b"\x00" * 4

    with pytest.raises(unpacker.Xor2fTerminalUnpackerNoEvidence, match="定数"):
        unpacker.recover_xor2f_native_memory_image(bytes(changed))


def test_duplicate_marker_is_rejected() -> None:
    sample, _expected = _fixture()
    changed = bytearray(sample)
    changed[0x3000 : 0x3004] = unpacker.REGION_MARKER

    with pytest.raises(unpacker.Xor2fTerminalUnpackerNoEvidence, match="一意"):
        unpacker.recover_xor2f_native_memory_image(bytes(changed))


def test_invalid_inner_entry_is_rejected() -> None:
    sample, _expected = _fixture()
    changed = bytearray(sample)
    region_raw = changed.find(unpacker.REGION_MARKER, 0x1000)
    encrypted = bytes(changed[region_raw : region_raw + unpacker.REGION_SIZE])
    key1 = unpacker._derive_key(unpacker.KEY1_SEED, unpacker.KEY1_XOR_MASKS)
    key2 = unpacker._derive_key(unpacker.KEY2_SEED, unpacker.KEY2_XOR_MASKS)
    layer1 = unpacker._rc4(encrypted, key1)
    final = bytearray(
        b"".join(
            unpacker._rc4(layer1[offset : offset + unpacker.RC4_CHUNK_SIZE], key2)
            for offset in range(0, len(layer1), unpacker.RC4_CHUNK_SIZE)
        )
    )
    final[unpacker.INNER_ENTRY_OFFSET : unpacker.INNER_ENTRY_OFFSET + 16] = b"\x00" * 16
    inverse_layer = b"".join(
        unpacker._rc4(final[offset : offset + unpacker.RC4_CHUNK_SIZE], key2)
        for offset in range(0, len(final), unpacker.RC4_CHUNK_SIZE)
    )
    changed[region_raw : region_raw + unpacker.REGION_SIZE] = unpacker._rc4(
        inverse_layer, key1
    )

    with pytest.raises(unpacker.Xor2fTerminalUnpackerNoEvidence, match="prologue"):
        unpacker.recover_xor2f_native_memory_image(bytes(changed))
