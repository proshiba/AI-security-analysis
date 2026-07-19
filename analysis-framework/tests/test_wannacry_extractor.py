"""上限付きWannaCry W/101復元の回帰試験。"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest


MODULE_PATH = Path(__file__).parents[1] / "malware" / "wannacry" / "extract_config.py"
SPEC = importlib.util.spec_from_file_location("wannacry_extract_config", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_embedded_worm_accepts_explicitly_truncated_resource() -> None:
    payload = b"MZ" + b"A" * 30
    recovered, declared_size, complete = MODULE._embedded_worm(
        struct.pack("<I", 128) + payload
    )
    assert recovered == payload
    assert declared_size == 128
    assert complete is False


def test_embedded_worm_rejects_non_pe_and_empty_resource() -> None:
    with pytest.raises(ValueError):
        MODULE._embedded_worm(b"\x00\x00\x00")
    with pytest.raises(ValueError):
        MODULE._embedded_worm(struct.pack("<I", 4) + b"NOPE")


def test_expected_pe_extent_uses_largest_section_end() -> None:
    image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(SizeOfHeaders=0x400),
        sections=[
            SimpleNamespace(PointerToRawData=0x400, SizeOfRawData=0x600),
            SimpleNamespace(PointerToRawData=0xA00, SizeOfRawData=0x200),
        ],
    )
    assert MODULE._pe_expected_extent(image) == 0xC00

def _zipcrypto_encrypt(data: bytes, password: bytes) -> bytes:
    table: list[int] = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    key0, key1, key2 = 0x12345678, 0x23456789, 0x34567890

    def update(value: int) -> None:
        nonlocal key0, key1, key2
        key0 = (key0 >> 8) ^ table[(key0 ^ value) & 0xFF]
        key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        key2 = (key2 >> 8) ^ table[(key2 ^ (key1 >> 24)) & 0xFF]

    for value in password:
        update(value)
    result = bytearray()
    for plain in data:
        temporary = key2 | 2
        result.append(plain ^ (((temporary * (temporary ^ 1)) >> 8) & 0xFF))
        update(plain)
    return bytes(result)


def _encrypted_local_member(name: str, content: bytes) -> bytes:
    import binascii
    import zlib

    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    compressed = compressor.compress(content) + compressor.flush()
    crc = binascii.crc32(content) & 0xFFFFFFFF
    encryption_header = b"\x00" * 11 + bytes([crc >> 24])
    encrypted = _zipcrypto_encrypt(encryption_header + compressed, MODULE.ZIP_PASSWORD)
    encoded_name = name.encode("utf-8")
    header = MODULE.ZIP_LOCAL_HEADER.pack(
        b"PK\x03\x04", 20, 1, 8, 0, 0, crc, len(encrypted), len(content), len(encoded_name), 0
    )
    return header + encoded_name + encrypted


def test_encrypted_package_recovers_c2_without_writing_members() -> None:
    content = b"gx7ekbenv2riucmf.onion;57g7spgrzlojinas.onion;"
    summary, members = MODULE.parse_encrypted_package(_encrypted_local_member("c.wnry", content))
    assert summary["complete"] is True
    assert summary["recovered_count"] == 1
    assert summary["entries"][0]["crc32_valid"] is True
    assert members == {"c.wnry": content}
