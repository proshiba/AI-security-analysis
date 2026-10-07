"""RTF objdataの有界OLE1復元と標準pipeline統合を検証する。"""

from __future__ import annotations

import hashlib
import struct

import pytest

from unpackers import rtf_objdata
from unpackers.rtf_objdata import recover_rtf_objdata
from unpackers.static_unpacker import detect_format, unpack_bytes


def _ole1_string(value: bytes) -> bytes:
    raw = value + b"\x00" if value else b""
    return struct.pack("<I", len(raw)) + raw


def _package(payload: bytes, *, declared_name: bytes = b"invoice.pdf") -> bytes:
    native = (
        struct.pack("<H", 2)
        + declared_name
        + b"\x00"
        + b"C:\\fake\\invoice.pdf\x00"
        + b"\x00" * 4
        + struct.pack("<I", len(b"C:\\Temp\\invoice.pdf\x00"))
        + b"C:\\Temp\\invoice.pdf\x00"
        + struct.pack("<I", len(payload))
        + payload
        + b"trailing-metadata"
    )
    return (
        struct.pack("<II", 0x501, 2)
        + _ole1_string(b"Package")
        + _ole1_string(b"")
        + _ole1_string(b"")
        + struct.pack("<I", len(native))
        + native
    )


def _rtf(*objects: bytes, invalid_hex: bytes | None = None) -> bytes:
    groups = []
    for blob in objects:
        encoded = blob.hex().encode("ascii")
        midpoint = len(encoded) // 2
        groups.append(
            b"{\\object{\\*\\objdata\n"
            + encoded[:midpoint]
            + b"{\\*\\ignored nested-junk}"
            + encoded[midpoint:]
            + b"}}"
        )
    if invalid_hex is not None:
        groups.append(b"{\\object{\\*\\objdata " + invalid_hex + b"}}")
    return b"{\\rtf1\\ansi\n" + b"\n".join(groups) + b"}"


def test_recovers_valid_package_payload_and_ignores_nested_group() -> None:
    payload = b"MZ" + bytes(range(64))

    report, artifacts = recover_rtf_objdata(_rtf(_package(payload)))

    assert report["status"] == "artifacts_recovered"
    assert report["objdata_group_count"] == 1
    assert report["invalid_objdata_count"] == 0
    assert report["objects"][0]["class_name"] == "Package"
    assert report["objects"][0]["declared_extension"] == ".pdf"
    assert report["objects"][0]["package_payload_sha256"] == hashlib.sha256(
        payload
    ).hexdigest()
    assert artifacts == [("rtf-ole1-package-payload", payload)]


def test_partial_recovery_reports_invalid_sibling_without_guessing() -> None:
    payload = b"MZ" + b"A" * 96

    report, artifacts = recover_rtf_objdata(
        _rtf(_package(payload), invalid_hex=b"0" * 63)
    )

    assert report["status"] == "partial_artifacts_recovered"
    assert report["objdata_group_count"] == 2
    assert report["unique_native_count"] == 1
    assert report["invalid_objdata_count"] == 1
    assert report["objects"][1]["status"] == "validation_failed"
    assert artifacts == [("rtf-ole1-package-payload", payload)]


def test_duplicate_payload_is_retained_once() -> None:
    payload = b"MZ" + b"B" * 80
    packaged = _package(payload)

    report, artifacts = recover_rtf_objdata(_rtf(packaged, packaged))

    assert report["status"] == "artifacts_recovered"
    assert report["unique_native_count"] == 1
    assert report["objects"][1]["duplicate"] is True
    assert artifacts == [("rtf-ole1-package-payload", payload)]


def test_malformed_native_length_fails_closed() -> None:
    malformed = bytearray(_package(b"MZ" + b"C" * 32))
    native_size_offset = 8 + len(_ole1_string(b"Package")) + 8
    malformed[native_size_offset : native_size_offset + 4] = struct.pack(
        "<I", 0x7FFFFFFF
    )

    report, artifacts = recover_rtf_objdata(_rtf(bytes(malformed)))

    assert report["status"] == "validation_failed"
    assert report["invalid_objdata_count"] == 1
    assert artifacts == []


def test_size_limit_and_non_rtf_are_not_recovered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rtf_objdata, "MAX_RTF_BYTES", 16)
    report, artifacts = recover_rtf_objdata(b"{\\rtf1 " + b"A" * 32 + b"}")
    assert report["status"] == "input_size_blocked"
    assert artifacts == []

    report, artifacts = recover_rtf_objdata(b"not an rtf objdata record")
    assert report["status"] == "not_rtf"
    assert artifacts == []


def test_standard_pipeline_routes_rtf_to_objdata_recovery() -> None:
    payload = b"MZ" + b"D" * 128
    source = _rtf(_package(payload))

    report, artifacts = unpack_bytes(source, "document.rtf")

    assert detect_format(source, "document.rtf") == "rtf"
    assert report["format"] == "rtf"
    assert report["rtf_objdata"]["status"] == "artifacts_recovered"
    assert ("rtf-ole1-package-payload", payload) in artifacts
    assert detect_format(b"plain text", "misleading.rtf") == "data"
