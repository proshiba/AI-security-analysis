"""Tests for public Casper-era ShadowPad extractor primitives."""

from __future__ import annotations

import struct

from extractors.shadowpad import legacy
from extractors.shadowpad.legacy import (
    CASPER_FLAGS,
    LEGACY_CONFIG_LABELS,
    decrypt_casper_block,
    decrypt_legacy_string,
    decrypt_xor_block,
    decode_legacy_pe,
    find_legacy_configs,
    legacy_x64_stream,
    legacy_x86_stream,
    parse_legacy_config,
    quicklz_decompress,
    quicklz_header,
    unpack_casper_block,
)


def _encode_string(value: str, variant: str, seed: int = 0x1234) -> bytes:
    key = seed
    output = bytearray(struct.pack("<H", seed))
    for raw in value.encode() + b"\x00":
        output.append(raw ^ (key & 0xFF))
        if variant == "x86":
            key = (
                (key >> 16) * 0x1447208B + key * 0x208B0000 - 0x04875A15
            ) & 0xFFFFFFFF
        else:
            rotated = ((key << 16) & 0xFFFFFFFF) + (key >> 16)
            key = (rotated * 0x9C67DA34 + 0xF88A61D7) & 0xFFFFFFFF
    return bytes(output)


def _config(variant: str) -> bytes:
    size, pool = (0x858, 0x58) if variant == "x86" else (0x85C, 0x5C)
    config = bytearray(size)
    cursor = 0
    values = {
        0: "fixture-id",
        1: "FixtureService",
        12: "TCP://c2.example:443",
        28: "HTTP\n\n\n\n\n",
    }
    for index, value in values.items():
        encoded = _encode_string(value, variant, 0x1234 + index)
        struct.pack_into("<H", config, index * 2, cursor)
        config[pool + cursor : pool + cursor + len(encoded)] = encoded
        cursor += len(encoded)
    config[0x40:0x50] = bytes([8, 8, 8, 8]) * 4
    struct.pack_into("<II", config, 0x50, 10, 5)
    return bytes(config)


def _quicklz_uncompressed(data: bytes) -> bytes:
    size = 9 + len(data)
    return bytes([0x46]) + struct.pack("<II", size, len(data)) + data


def _xor_block(payload: bytes, code: int = 0) -> bytes:
    framed = _quicklz_uncompressed(payload)
    plain = (
        struct.pack(">IIIII", 0x11223300, CASPER_FLAGS, code, len(framed), len(payload))
        + framed
    )
    key = 0x5A
    return bytes(value ^ key for value in plain)


def test_legacy_outer_streams_round_trip() -> None:
    plain = b"legacy shadowpad stream"
    for transform in (legacy_x86_stream, legacy_x64_stream):
        encoded = transform(plain, 0x12345678)
        assert transform(encoded, 0x12345678) == plain


def test_quicklz_literal_and_match_tokens() -> None:
    literal = (
        bytes([0x47])
        + struct.pack("<II", 18, 5)
        + struct.pack("<I", 0x80000000)
        + b"hello"
    )
    assert quicklz_header(literal)["level"] == 1
    assert quicklz_decompress(literal) == b"hello"

    value = int.from_bytes(b"abc", "little")
    match_hash = ((value >> 12) ^ value) & 0x0FFF
    matched = (
        bytes([0x47])
        + struct.pack("<II", 20, 6)
        + struct.pack("<I", 0x80000008)
        + b"abc"
        + struct.pack("<H", (match_hash << 4) | 1)
        + b"00"
    )
    assert quicklz_decompress(matched) == b"abcabc"


def test_block_ciphers_and_unpacking() -> None:
    source = bytes(range(1, 33))
    assert (
        decrypt_casper_block(source).hex()
        == "9e50223d56ed9d7484876cb6e83fb62166d1e67deaa3f25dc2bfb57d9adf6d8d"
    )
    assert decrypt_xor_block(bytes([1, 2, 3, 4])) == bytes([5, 6, 7, 0])

    config = _config("x64")
    header, unpacked = unpack_casper_block(_xor_block(config), "xor-byte")
    assert header["flags"] == CASPER_FLAGS
    assert unpacked == config


def test_legacy_string_and_config_variants() -> None:
    for variant in ("x86", "x64"):
        assert (
            decrypt_legacy_string(_encode_string("sample", variant), variant)
            == "sample"
        )
        parsed = parse_legacy_config(_config(variant), variant)
        assert parsed["strings"]["campaign_id"] == "fixture-id"
        assert parsed["strings"]["c2_1"] == "TCP://c2.example:443"
        assert parsed["dns_servers"] == ["8.8.8.8"] * 4
        assert parsed["timeout_multiplier"] == 10


def test_find_legacy_configs() -> None:
    block = _xor_block(_config("x64"))
    found = find_legacy_configs(b"prefix" + block + b"suffix", "x64")
    assert len(found) == 1
    assert found[0]["offset"] == 6
    assert found[0]["strings"]["c2_1"] == "TCP://c2.example:443"


def test_decode_legacy_pe_structurally(monkeypatch) -> None:
    module_size = 0x1000
    decoded = bytearray(0x18 + module_size)
    decoded[: len(legacy.LEGACY_X86_PREFIX)] = legacy.LEGACY_X86_PREFIX
    decoded[0x0E] = 0x68
    struct.pack_into("<I", decoded, 0x0F, module_size)
    seed = 0x10203040
    encoded = struct.pack("<I", seed) + legacy_x86_stream(bytes(decoded), seed)

    class Section:
        PointerToRawData = 0
        SizeOfRawData = len(encoded)
        VirtualAddress = 0x6000

    class PE:
        sections = [Section()]

    monkeypatch.setattr(legacy.pefile, "PE", lambda **_: PE())
    recovered = decode_legacy_pe(encoded)
    assert len(recovered) == 1
    assert recovered[0].architecture == "x86"
    assert recovered[0].seed_rva == 0x6000
    assert recovered[0].data == bytes(decoded)


def test_labels_cover_the_complete_offset_table() -> None:
    assert len(LEGACY_CONFIG_LABELS) == 32
