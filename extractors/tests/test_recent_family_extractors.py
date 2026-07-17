"""Tests for Amadey, Latrodectus, and current Vidar config profiles."""

from __future__ import annotations

import base64
import itertools

from extractors.amadey.extractor import decode_amadey_string, extract as extract_amadey
from extractors.config_extractor import get_extractor, normalize_family
from extractors.latrodectus.extractor import (
    decrypt_legacy_strings,
    decrypt_string,
    extract as extract_latrodectus,
    fnv1a_32,
)
from extractors.vidar import extractor as vidar_extractor
from extractors.vidar.extractor import extract as extract_vidar, recover_xor_config

AMADEY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "


def _encode_amadey(key: str, plain: bytes) -> str:
    """Create a fixture value inverse to the reviewed custom alphabet decoder."""
    encoded = base64.b64encode(plain).decode()
    output = []
    for index, character in enumerate(encoded):
        if character == "=":
            output.append(character)
            continue
        desired = AMADEY_ALPHABET.index(character)
        key_index = AMADEY_ALPHABET.index(key[index % len(key)])
        output.append(AMADEY_ALPHABET[(desired + key_index) % 0x3F])
    return "".join(output)


def _encrypt_latro_legacy(seed: int, plain: bytes) -> bytes:
    """Create a mode-one legacy Latrodectus encrypted-string fixture."""
    header = seed.to_bytes(4, "little")
    encoded_length = (len(plain) ^ int.from_bytes(header[:2], "little")).to_bytes(2, "little")
    output = bytearray()
    for byte in plain:
        seed = (seed + 1) & 0xFFFFFFFF
        output.append((seed ^ byte) & 0xFF)
    return header + encoded_length + bytes(output)


def _vidar_blob() -> bytes:
    """Build one validated repeated-XOR Vidar config fixture."""
    key = b"0123456789abcdef"
    blob = bytearray(0x072 + 0x243 * 2)
    blob[:16] = key

    def store(base: int, value_offset: int, length_offset: int, value: bytes) -> None:
        """Store one repeated-XOR field in the fixture."""
        blob[base + length_offset] = len(value)
        encrypted = bytes(left ^ right for left, right in zip(value, itertools.cycle(key)))
        blob[base + value_offset : base + value_offset + len(value)] = encrypted

    store(0, 0x010, 0x030, b"1.8")
    store(0, 0x031, 0x071, b"fixture")
    store(0x072, 0, 0x100, b"http://198.51.100.4/gate")
    store(0x072, 0x101, 0x141, b"tag")
    store(0x072, 0x142, 0x242, b"FixtureAgent/1")
    return bytes(blob)


def test_amadey_alphabet_decoder_and_fallback() -> None:
    """Round-trip the alphabet decoder and retain conservative wrapper output."""
    key = "0123456789abcdef0123456789abcdef"
    encoded = _encode_amadey(key, b"http://example.test/index.php")
    assert decode_amadey_string(key, encoded) == b"http://example.test/index.php"
    result = extract_amadey(b"MZ Amadey", "wrapper.exe")
    assert result["family"] == "amadey" and not result["config"]["static_config_recovered"]


def test_latrodectus_legacy_primitives_and_dispatch() -> None:
    """Cover decryption, group hashing, feature fallback, alias, and dispatch."""
    record = _encrypt_latro_legacy(0x12345678, b"https://example.test/live/")
    assert decrypt_string(record, 1) == b"https://example.test/live/"
    assert decrypt_legacy_strings(record + record) == ["https://example.test/live/"]
    assert fnv1a_32(b"Facial") == 3828029093
    result = extract_latrodectus(b"MZ ipconfig /all rundll32.exe", "wrapper.dll")
    assert result["family"] == "latrodectus"
    assert normalize_family("latro") == "latrodectus"
    assert get_extractor("latrodectus") is not None


def test_vidar_xor_config_and_extractor() -> None:
    """Recover a current Vidar XOR profile and its confirmed C2 evidence."""
    blob = _vidar_blob()
    config = recover_xor_config(blob)
    assert config["version"] == "1.8" and config["build_id"] == "fixture"
    assert config["scan_source"] == "complete_input"
    assert config["c2_urls"] == ["http://198.51.100.4/gate"]
    result = extract_vidar(blob, "fixture.bin")
    assert result["findings"][0]["confidence"] == "confirmed"


def test_vidar_uses_compact_inflated_pe_for_large_input(monkeypatch) -> None:
    """Avoid scanning a huge certificate gap when a compact PE is available."""
    compact = _vidar_blob()
    large = b"MZ" + bytes(2048)
    monkeypatch.setattr(vidar_extractor, "MAX_CONFIG_SCAN", 1024)
    monkeypatch.setattr(
        vidar_extractor,
        "recover_inflated_pe",
        lambda data: ({"status": "recovered"}, compact),
    )
    config = vidar_extractor.recover_xor_config(large)
    assert config["c2_urls"] == ["http://198.51.100.4/gate"]
    assert config["scan_source"] == "inflated_pe_compacted"
    assert config["original_size"] == len(large)
