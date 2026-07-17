"""Regression coverage for a current Donut x64 loader prologue."""

from __future__ import annotations

import struct

from unpackers.donut_unpacker import is_donut_shellcode


def test_current_x64_loader_prologue() -> None:
    """Accept the x64 prologue observed after a current Donut instance."""
    shellcode = b"\xe8" + struct.pack("<I", 16) + b"A" * 16
    shellcode += b"\x59\x48\x89\x5c\x24\x08"
    assert is_donut_shellcode(shellcode)
