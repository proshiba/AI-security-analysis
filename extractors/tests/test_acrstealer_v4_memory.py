from __future__ import annotations

import struct
from types import SimpleNamespace

from extractors.acrstealer import v4_memory_core as core
from extractors.acrstealer.v4_memory import (
    PRNG_MARKERS,
    _keystream_word,
    decrypt_string,
    extract_v4_memory_profile,
)


def _rol8(value: int, count: int) -> int:
    count &= 7
    if not count:
        return value & 0xFF
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _encrypt(clear: bytes, seed: int) -> bytes:
    result = bytearray()
    for index, byte in enumerate(clear):
        word = _keystream_word(seed, index)
        value = byte ^ (word & 0xFF)
        value = _rol8(value, (word >> 8) & 0xFF)
        value = (value + ((word >> 16) & 0xFF)) & 0xFF
        value ^= (word >> 24) & 0xFF
        result.append(value)
    return bytes(result)


def _minimal_memory_pe(strings: list[str], *, include_signature: bool = True) -> bytes:
    image_base = 0x400000
    text_rva = 0x1000
    data_rva = 0x3000
    decryptor = image_base + 0x1800
    data = bytearray(0x5000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, text_rva)
    struct.pack_into("<I", data, optional + 20, text_rva)
    struct.pack_into("<I", data, optional + 24, data_rva)
    struct.pack_into("<I", data, optional + 28, image_base)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, len(data))
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<I", data, optional + 92, 16)
    section_table = optional + 0xE0
    data[section_table : section_table + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section_table + 8, 0x1800, text_rva, 0x1800, 0x400)
    struct.pack_into("<I", data, section_table + 36, 0x60000020)
    section_table += 40
    data[section_table : section_table + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section_table + 8, 0x1800, data_rva, 0x1800, 0x1C00)
    struct.pack_into("<I", data, section_table + 36, 0x40000040)

    cursor = text_rva
    if include_signature:
        for marker in PRNG_MARKERS:
            data[cursor : cursor + len(marker)] = marker
            cursor += len(marker) + 3
    cursor += 32
    source_cursor = data_rva
    for seed, text in enumerate(strings):
        clear = text.encode("utf-8")
        cipher = _encrypt(clear, seed)
        data[source_cursor : source_cursor + len(cipher)] = cipher
        source = image_base + source_cursor
        # push seed; push length; push source; push eax; call decryptor
        call = bytearray()
        call += b"\x68" + struct.pack("<I", seed)
        call += b"\x68" + struct.pack("<I", len(cipher))
        call += b"\x68" + struct.pack("<I", source)
        call += b"\x50"
        call_address = image_base + cursor + len(call)
        call += b"\xE8" + struct.pack("<i", decryptor - (call_address + 5))
        data[cursor : cursor + len(call)] = call
        cursor += len(call) + 2
        source_cursor += len(cipher) + 8
    return bytes(data)


def test_decrypt_string_round_trip() -> None:
    clear = b"wss.infrastructurecore.cc"
    assert decrypt_string(_encrypt(clear, 61), 61) == clear


def test_extract_v4_memory_profile_from_synthetic_memory_image() -> None:
    strings = [
        "\\Login Data",
        "\\Local State",
        "\\Cookies",
        "\\Web Data",
        "Mozilla/5.0 synthetic",
        "User-Agent",
        "websocket",
        "wss://wss.infrastructurecore.cc/gate-path",
        "cloudflare-dns.com",
        "dns.google",
        "keycdn.com",
        "4.3.2-alpha3",
        "a6cdcc0b-6b38-49d6-9672-20be114d9eba",
        "019fddb7-f955-741d-9654-974f603f741d",
    ]
    profile = extract_v4_memory_profile(_minimal_memory_pe(strings))
    assert profile is not None
    assert profile.version == "4.3.2-alpha3"
    assert profile.c2_urls == ("wss://wss.infrastructurecore.cc/gate-path",)
    assert "wss.infrastructurecore.cc" in profile.c2_hosts
    assert profile.decoy_hosts == ("keycdn.com",)
    assert profile.dns_resolvers == ("cloudflare-dns.com", "dns.google")
    assert profile.generic_domain_findings == ()
    assert profile.layout == "memory_mapped"
    # 先頭call-siteが意図的なsignature bytesとの境界に重なるfixtureでも、
    # 独立した証拠群と残りの設定を復元できることを確認する。
    assert profile.decoded_count >= len(strings) - 1


def test_missing_prng_signature_fails_closed() -> None:
    strings = ["\\Login Data", "\\Cookies", "Mozilla/5.0", "wss://bad.example"] * 4
    assert extract_v4_memory_profile(_minimal_memory_pe(strings, include_signature=False)) is None


def test_insufficient_independent_evidence_fails_closed() -> None:
    strings = [f"ordinary-string-{index}" for index in range(20)]
    assert extract_v4_memory_profile(_minimal_memory_pe(strings)) is None


def test_generic_domain_is_not_promoted_to_confirmed_c2() -> None:
    strings = [
        "\\Login Data",
        "\\Local State",
        "\\Cookies",
        "\\Web Data",
        "Mozilla/5.0 synthetic",
        "User-Agent",
        "websocket",
        "suspicious-update.top",
        "4.3.2-alpha3",
        "a6cdcc0b-6b38-49d6-9672-20be114d9eba",
        "ordinary-a",
        "ordinary-b",
        "ordinary-c",
        "ordinary-d",
    ]
    profile = extract_v4_memory_profile(_minimal_memory_pe(strings))
    assert profile is not None
    assert profile.c2_urls == ()
    assert profile.c2_hosts == ()
    assert profile.generic_domain_findings == ("suspicious-update.top",)


def test_capstone_disassembly_is_streamed_with_byte_and_instruction_caps(
    monkeypatch,
) -> None:
    consumed = 0
    observed_data = b""

    class FakeInstruction:
        def group(self, _group: int) -> bool:
            return False

    class FakeDecoder:
        detail = False

        def __init__(self, _arch: int, _mode: int) -> None:
            pass

        def disasm(self, data: bytes, _address: int):
            nonlocal consumed, observed_data
            observed_data = data
            for _ in range(10):
                consumed += 1
                yield FakeInstruction()

    monkeypatch.setattr(core, "Cs", FakeDecoder)
    monkeypatch.setattr(core, "MAX_DISASSEMBLY_BYTES", 4)
    monkeypatch.setattr(core, "MAX_DISASSEMBLY_INSTRUCTIONS", 3)
    view = SimpleNamespace(text=b"0123456789", text_address=0x401000)
    assert core._decode_calls(view) == []
    assert observed_data == b"0123"
    assert consumed == 3
