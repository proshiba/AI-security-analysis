"""Regression coverage for current encrypted Donut instance layouts."""

from __future__ import annotations

import struct

from unpackers.donut_unpacker import chaskey_ctr, decrypt_instance


def test_decrypt_current_0x240_instance_layout() -> None:
    """Decrypt and validate the 0x240 API-count layout seen in the VX set."""
    instance = bytearray(0x400)
    instance[4:20] = bytes(range(16))
    instance[20:36] = bytes(range(16, 32))
    struct.pack_into("<I", instance, 0x240, 52)
    dlls = b"ole32;oleaut32;wininet;mscoree;shell32\0"
    instance[0x244 : 0x244 + len(dlls)] = dlls
    encrypted = bytearray(instance)
    encrypted[0x240:] = chaskey_ctr(
        bytes(instance[4:20]),
        bytes(instance[20:36]),
        bytes(instance[0x240:]),
    )
    shellcode = b"\xe8" + struct.pack("<I", len(encrypted))
    shellcode += encrypted + b"\x59\x48\x89\x5c\x24\x08"
    recovered, layout = decrypt_instance(shellcode)
    assert layout.name == "current-0x240-array"
    assert recovered == bytes(instance)
