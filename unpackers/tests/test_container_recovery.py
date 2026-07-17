"""Unit tests for bounded container and anti-analysis recovery helpers."""

from __future__ import annotations

import lzma
import struct

from unpackers.container_recovery import recover_macho_slices, recover_xz


def test_xz_recovery_and_invalid_input() -> None:
    """Recover a bounded XZ stream and reject malformed input."""
    value = b"payload" * 128
    report, recovered = recover_xz(lzma.compress(value, format=lzma.FORMAT_XZ))
    assert report["status"] == "recovered" and recovered == value
    report, recovered = recover_xz(b"not-xz")
    assert report["status"] == "invalid_xz" and recovered is None


def test_macho_fat_slice_recovery_and_bounds() -> None:
    """Recover one thin slice and report an out-of-bounds peer."""
    thin = b"\xcf\xfa\xed\xfe" + b"A" * 60
    header_size = 8 + 2 * 20
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2)
    header += struct.pack(">IIIII", 0x01000007, 3, header_size, len(thin), 2)
    header += struct.pack(">IIIII", 0x0100000C, 0, 999999, 64, 2)
    report, artifacts = recover_macho_slices(header + thin)
    assert report["status"] == "recovered"
    assert artifacts == [("macho-slice-0", thin)]
    assert report["architectures"][1]["status"] == "bounds_blocked"
