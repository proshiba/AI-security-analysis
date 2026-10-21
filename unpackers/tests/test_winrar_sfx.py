from __future__ import annotations

import struct
import zlib

from unpackers.winrar_sfx import (
    MAX_INPUT_SIZE,
    MAX_SCAN_BYTES,
    RAR5_MAGIC,
    assess_winrar_sfx,
    build_rar_sfx_extraction_plan,
    parse_sevenzip_rar_listing,
    verify_rar_sfx_extraction,
)


def _vint(value: int) -> bytes:
    encoded = bytearray()
    while True:
        current = value & 0x7F
        value >>= 7
        encoded.append(current | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def _rar5_main_header() -> bytes:
    body = _vint(1) + _vint(0) + _vint(0)
    protected = _vint(len(body)) + body
    return RAR5_MAGIC + struct.pack("<I", zlib.crc32(protected)) + protected


def _minimal_pe(overlay: bytes) -> tuple[bytes, int]:
    payload = bytearray(0x400)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    payload[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", payload, 0x86, 1)
    struct.pack_into("<H", payload, 0x94, 0xF0)
    struct.pack_into("<H", payload, 0x98, 0x20B)
    section = 0x98 + 0xF0
    payload[section : section + 5] = b".text"
    struct.pack_into("<I", payload, section + 16, 0x200)
    struct.pack_into("<I", payload, section + 20, 0x200)
    return bytes(payload) + overlay, len(payload)


def _listing(*member_blocks: str, setup: str = "Setup=host.exe") -> str:
    return (
        "Path = input.exe\nType = Rar5\nPhysical Size = 100\n"
        f"Comment =\n{{\n{setup}\n}}\n\n----------\n" + "\n\n".join(member_blocks)
    )


def _member(
    name: str,
    size: int,
    *,
    crc: str = "",
    checksum: str = "",
    copy_link: str = "",
) -> str:
    return (
        f"Path = {name}\nFolder = -\nSize = {size}\nAttributes = A\n"
        f"Alternate Stream = -\nCRC = {crc}\nChecksum = {checksum}\n"
        f"Symbolic Link = \nHard Link = \nCopy Link = {copy_link}"
    )


def test_sfx_detector_finds_valid_rar_after_large_overlay_prefix() -> None:
    data, overlay_start = _minimal_pe(b"P" * 10_556 + _rar5_main_header())

    report = assess_winrar_sfx(data)

    assert report["status"] == "validated_sfx_container"
    assert report["candidate"] is True
    assert report["archive_format"] == "rar5"
    assert report["archive_offset"] == overlay_start + 10_556
    assert report["overlay_prefix_size"] == 10_556
    assert report["header_crc_verified"] is True
    assert report["family_attribution_allowed"] is False


def test_sfx_detector_rejects_corrupt_header_crc() -> None:
    header = bytearray(_rar5_main_header())
    header[-1] ^= 1
    data, _ = _minimal_pe(b"P" * 5000 + bytes(header))

    report = assess_winrar_sfx(data)

    assert report["status"] == "not_candidate"
    assert report["candidate"] is False
    assert report["malformed_signature_count"] == 1


def test_sfx_detector_fails_closed_when_scan_is_incomplete() -> None:
    data, overlay_start = _minimal_pe(b"P" * 20_000 + _rar5_main_header())

    report = assess_winrar_sfx(
        data,
        overlay_start=overlay_start,
        max_scan_bytes=4096,
    )

    assert report["status"] == "scan_limit_reached"
    assert report["candidate"] is False
    assert report["scan_complete"] is False


def test_sfx_detector_default_scan_covers_entire_accepted_large_input() -> None:
    assert MAX_SCAN_BYTES == MAX_INPUT_SIZE
    data, overlay_start = _minimal_pe(
        b"P" * 1024
        + _rar5_main_header()
        + b"A" * (32 * 1024 * 1024 + 4096)
    )

    report = assess_winrar_sfx(data)

    assert report["status"] == "validated_sfx_container"
    assert report["candidate"] is True
    assert report["scan_complete"] is True
    assert report["archive_offset"] == overlay_start + 1024
    assert report["scanned_bytes"] == len(data) - overlay_start


def test_sfx_detector_rejects_multiple_valid_headers_across_full_scan() -> None:
    data, _ = _minimal_pe(
        b"P" * 1024
        + _rar5_main_header()
        + b"Q" * 4096
        + _rar5_main_header()
    )

    report = assess_winrar_sfx(data)

    assert report["status"] == "ambiguous_valid_headers"
    assert report["candidate"] is False
    assert report["valid_header_count"] == 2


def test_listing_plan_validates_count_size_setup_and_copy_link() -> None:
    host = b"MZhost"
    crc = f"{zlib.crc32(host) & 0xFFFFFFFF:08X}"
    listing = parse_sevenzip_rar_listing(
        _listing(
            _member("host.exe", len(host), crc=crc),
            _member("alias.exe", len(host), copy_link="host.exe"),
            _member("module.dll", 10, checksum="a" * 64),
            _member("config.bin", 8),
            _member("document.pdf", 100),
            setup="Setup=alias.exe",
        )
    )

    report, plan = build_rar_sfx_extraction_plan(listing)

    assert report["status"] == "planned"
    assert report["member_count"] == 5
    assert report["declared_total_size"] == 130
    assert report["safe_path_count"] == 5
    assert report["copy_link_alias_count"] == 1
    assert report["setup_target_count"] == 1
    assert [item["name"] for item in plan] == [
        "host.exe",
        "module.dll",
        "config.bin",
    ]
    assert plan[0]["priority"] == 0


def test_listing_plan_rejects_unsafe_path_and_size_mismatch_shape() -> None:
    unsafe = parse_sevenzip_rar_listing(
        _listing(_member("../payload.exe", 4), setup="Setup=../payload.exe")
    )
    report, plan = build_rar_sfx_extraction_plan(unsafe)
    assert report["status"] == "unsafe_member_path_blocked"
    assert plan == []

    missing_setup = parse_sevenzip_rar_listing(
        _listing(_member("payload.exe", 4), setup="Setup=missing.exe")
    )
    report, plan = build_rar_sfx_extraction_plan(missing_setup)
    assert report["status"] == "setup_target_missing"
    assert plan == []


def test_extraction_verifier_requires_exact_set_size_crc_and_tool_integrity() -> None:
    payload = b"MZhost"
    plan = [
        {
            "name": "host.exe",
            "size": len(payload),
            "crc32": f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}",
        }
    ]

    blocked = verify_rar_sfx_extraction(
        plan,
        {"host.exe": payload},
        external_archive_integrity_verified=False,
    )
    assert blocked["status"] == "external_archive_integrity_unverified"

    mismatch = verify_rar_sfx_extraction(
        plan,
        {"host.exe": payload, "extra.dll": b"MZextra"},
        external_archive_integrity_verified=True,
    )
    assert mismatch["status"] == "extracted_member_set_mismatch"

    verified = verify_rar_sfx_extraction(
        plan,
        {"host.exe": payload},
        external_archive_integrity_verified=True,
    )
    assert verified["status"] == "verified"
    assert verified["verified_member_count"] == 1
    assert verified["members"][0]["crc32_verified"] is True
    assert verified["sample_executed"] is False
