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


def test_embedded_worm_direct_requires_reviewed_resource_and_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = b"MZ" + b"T" * 30

    def find_resource(_image: object, resource_type: str, resource_name: str) -> bytes | None:
        return task if (resource_type, resource_name) == ("R", "1831") else None

    monkeypatch.setattr(MODULE, "find_resource", find_resource)
    data = b"MZ\0mssecsvc2.1\0tasksche.exe\0"
    payload, declared, complete, source_shape = MODULE._select_embedded_worm(data, object())
    assert payload == data
    assert declared == len(data)
    assert complete is True
    assert source_shape == "embedded_worm_direct"
    with pytest.raises(ValueError, match="review済みR/1831"):
        MODULE._select_embedded_worm(b"MZ\0tasksche.exe\0", object())


def test_outer_wrapper_has_stronger_recovered_artifact_lineage() -> None:
    payload = b"worm"
    task = b"task"
    outer = MODULE._recovered_artifact_evidence("outer_wrapper_w_101", payload, task)
    direct = MODULE._recovered_artifact_evidence("embedded_worm_direct", payload, task)
    assert [item["artifact_role"] for item in outer] == [
        "embedded_worm",
        "embedded_task_image",
    ]
    assert [item["artifact_role"] for item in direct] == ["embedded_task_image"]


def test_task_image_audit_fails_closed_on_high_entropy_importless_image() -> None:
    data = bytes(range(256)) * 32
    section = SimpleNamespace(
        Name=b".text\0\0\0",
        PointerToRawData=0,
        SizeOfRawData=len(data),
        VirtualAddress=0x1000,
        Misc_VirtualSize=len(data),
    )
    image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1100),
        sections=[section],
        DIRECTORY_ENTRY_IMPORT=[],
    )
    result = MODULE._task_image_audit(data, image, None)
    assert result["execution_viability"] == "not_statically_corroborated"
    assert result["entrypoint_section"] == ".text"
    assert result["entrypoint_section_entropy"] == 8.0
    assert result["all_sections_high_entropy"] is True


def test_task_image_audit_does_not_overstate_image_with_imports() -> None:
    data = bytes(range(256)) * 32
    section = SimpleNamespace(
        Name=b".text\0\0\0",
        PointerToRawData=0,
        SizeOfRawData=len(data),
        VirtualAddress=0x1000,
        Misc_VirtualSize=len(data),
    )
    image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1100),
        sections=[section],
        DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(imports=[object()])],
    )
    result = MODULE._task_image_audit(data, image, None)
    assert result["execution_viability"] == "structurally_parseable"


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
