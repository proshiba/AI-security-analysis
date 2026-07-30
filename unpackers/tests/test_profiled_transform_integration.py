"""宣言型byte変換とstatic_unpackerの統合テスト。"""

from __future__ import annotations

import struct

from unpackers.static_unpacker import unpack_bytes


def _encoded_donut_fixture() -> tuple[bytes, bytes]:
    instance = bytearray(0x300)
    struct.pack_into("<I", instance, 0x23C, 3)
    instance[0x240:0x24C] = b"ole32;wininet"
    clear = b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"
    xored = bytes(value ^ 0xC6 for value in clear)
    shift = 0x3EF14 % len(clear)
    encoded = xored[shift:] + xored[:shift]
    return encoded, clear


def test_static_unpacker_uses_profile_registry_and_keeps_legacy_report() -> None:
    encoded, clear = _encoded_donut_fixture()
    report, artifacts = unpack_bytes(encoded, "riched32.dat")
    assert report["profiled_transforms"]["status"] == "validated_artifacts_recovered"
    assert report["rotated_xor_donut"]["status"] == "donut_shellcode_recovered"
    assert ("rotated-xor-donut-shellcode", clear) in artifacts
    assert report["executed"] is False
    assert report["network_contacted"] is False
