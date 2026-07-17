"""Tests for every public ShadowPad extractor function."""

from __future__ import annotations

import hashlib
import struct

from extractors.shadowpad.extractor import (
    PayloadDecode,
    add_seed_bytes,
    decode_candidates,
    decode_payload,
    derive_aes_key,
    extract,
    find_32_config,
    find_64_chunks,
    network_values,
    parse_32_config,
    parse_64_config,
    scatter_aes,
    scatter_stream,
)


def _stream_encode(data: bytes, seed: int, sub_key: int) -> bytes:
    return scatter_stream(data, seed, sub_key)


def _payload_with_32_config(sub_key: int) -> bytes:
    config_offset = 0x100
    payload = bytearray(config_offset + 0x400)
    payload[:5] = b"\xe9\x00\x00\x00\x00"
    struct.pack_into("<III", payload, config_offset + 0x18, 0x80, 0x40, 0x40)
    struct.pack_into("<I", payload, config_offset + 0x28, 2)
    payload[config_offset + 0x7A : config_offset + 0x8A] = b"\x08" * 16
    cursor = 0
    values = ["2020/01/01 00:00:00"] + [""] * 14 + ["TCP://c2.example:443"] + [""] * 7
    for index, value in enumerate(values):
        table = 0x34 + 2 * index if index < 19 else 0x72 + 2 * (index - 19)
        struct.pack_into("<H", payload, config_offset + table, cursor)
        raw = value.encode()
        seed = 0x1200 + index
        encoded = _stream_encode(raw, seed, sub_key)
        struct.pack_into(
            "<HH", payload, config_offset + 0xBE + cursor, seed, len(encoded)
        )
        payload[
            config_offset + 0xBE + cursor + 4 : config_offset
            + 0xBE
            + cursor
            + 4
            + len(encoded)
        ] = encoded
        cursor += 4 + len(encoded)
    return bytes(payload)


def test_seed_stream_and_key_derivation() -> None:
    assert add_seed_bytes(0x01020304) == 10
    plain = b"hello"
    encoded = scatter_stream(plain, 0x12345678, 0x443246BA)
    assert scatter_stream(encoded, 0x12345678, 0x443246BA) == plain
    digest = hashlib.md5(b"x").digest()
    assert len(derive_aes_key(digest)) == 32


def test_decode_payload_stream() -> None:
    seed, key = 0x10203040, 0x443246BA
    plain = b"\xe9\x01\x02\x03\x00" + b"A" * 32
    encoded = struct.pack("<I", seed) + scatter_stream(plain, seed, key)
    decoded = decode_payload(encoded)
    assert decoded == PayloadDecode(plain, "stream", "0x443246ba")
    assert decode_payload(b"short") is None
    assert decode_candidates(encoded)[0][0] == "input"


def test_aes_validation() -> None:
    try:
        scatter_aes(b"short", bytes(16))
    except ValueError as error:
        assert "short" in str(error)
    else:
        raise AssertionError("short AES input must fail")


def test_32_config_parsing_and_extract() -> None:
    key = 0x443246BA
    decoded = _payload_with_32_config(key)
    assert find_32_config(decoded) == 0x100
    config = parse_32_config(decoded, key)
    assert config and config["strings"]["c2_1"] == "TCP://c2.example:443"
    assert network_values(config) == ["TCP://c2.example:443"]
    seed = 0x11223344
    encoded = struct.pack("<I", seed) + scatter_stream(decoded, seed, key)
    result = extract(encoded, "fixture.dat")
    assert result["findings"][0]["value"] == "TCP://c2.example:443"
    assert result["executed"] is False and result["network_contacted"] is False


def test_64_chunk_validation_and_no_config() -> None:
    chunks = b"".join(
        struct.pack("<I", (tag << 24) | 4) + b"abcd" for tag in (0x80, 0x02, 0x90)
    )
    payload = b"prefix" + chunks
    assert find_64_chunks(payload) == 6
    decode = PayloadDecode(payload, "stream", "0x443246ba")
    assert parse_64_config(payload, decode) is None
    assert find_64_chunks(b"none") is None
