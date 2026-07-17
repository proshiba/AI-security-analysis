"""Regression tests for concatenated and bounded XZ recovery."""

from __future__ import annotations

import lzma

import unpackers.container_recovery as recovery


def test_recover_concatenated_xz_streams() -> None:
    """Return all concatenated streams rather than only the first stream."""
    first, second = b"A" * 512, b"B" * 2048
    data = lzma.compress(first, format=lzma.FORMAT_XZ)
    data += lzma.compress(second, format=lzma.FORMAT_XZ)
    report, recovered = recovery.recover_xz(data)
    assert report["status"] == "recovered"
    assert report["streams"] == 2
    assert recovered == first + second


def test_recover_xz_rejects_trailing_non_stream_data() -> None:
    """Reject unparsed trailing bytes after an otherwise valid XZ stream."""
    data = lzma.compress(b"payload", format=lzma.FORMAT_XZ) + b"trailing"
    report, recovered = recovery.recover_xz(data)
    assert report["status"] == "trailing_data_blocked"
    assert recovered is None
