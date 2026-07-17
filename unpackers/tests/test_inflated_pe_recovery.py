"""Test certificate-gap PE compaction without using a real executable."""

from __future__ import annotations

import struct

import unpackers.container_recovery as recovery
from unpackers.container_recovery import recover_inflated_pe


def minimal_inflated_pe(gap: int = 128) -> bytes:
    """Build a parseable one-section PE with a distant security directory."""
    image = bytearray(0x400 + gap + 8)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 20, 0x1000)
    struct.pack_into("<I", image, optional + 24, 0x1000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HH", image, optional + 40, 4, 0)
    struct.pack_into("<I", image, optional + 56, 0x2000)
    struct.pack_into("<I", image, optional + 60, 0x200)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<IIII", image, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", image, optional + 92, 16)
    security_offset = 0x400 + gap
    struct.pack_into("<II", image, optional + 96 + 4 * 8, security_offset, 8)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x10, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x210] = b"\x90" * 16
    image[security_offset : security_offset + 8] = b"CERTTEST"
    return bytes(image)


def test_inflated_pe_gap_recovery(monkeypatch) -> None:
    """Compact a synthetic certificate-gap PE and clear its security entry."""
    monkeypatch.setattr(recovery, "MAX_SECURITY_GAP", 64)
    report, compact = recover_inflated_pe(minimal_inflated_pe())
    assert report["status"] == "recovered"
    assert compact is not None and len(compact) == 0x400
