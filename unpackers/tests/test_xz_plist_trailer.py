"""Tests for bounded XML plist metadata following concatenated XZ streams."""

from __future__ import annotations

import lzma

from unpackers.container_recovery import recover_xz


def test_recover_xz_with_xml_plist_trailer() -> None:
    """Recover payload streams while recording a bounded plist trailer."""
    payload = b"disk-image" * 128
    trailer = b'<?xml version="1.0"?><plist><dict/></plist>'
    report, recovered = recover_xz(
        lzma.compress(payload, format=lzma.FORMAT_XZ) + trailer
    )
    assert report["status"] == "recovered_with_trailing_metadata"
    assert report["trailing_metadata_format"] == "xml-plist"
    assert recovered == payload
