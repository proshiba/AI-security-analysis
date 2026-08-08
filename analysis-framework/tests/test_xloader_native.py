"""FormBook／XLoaderネイティブ静的解析補助器のテスト。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "formbook_loader"
    / "native_xloader.py"
)
SPEC = importlib.util.spec_from_file_location("native_xloader", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
NATIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = NATIVE
SPEC.loader.exec_module(NATIVE)


def test_rc4_sub_round_trip() -> None:
    key = b"synthetic-key"
    plaintext = b"\x55\x8b\xec\x83\xec\x10synthetic-body\xc3"

    encrypted = NATIVE.encrypt_rc4_sub(plaintext, key)

    assert NATIVE.decrypt_rc4_sub(encrypted, key) == plaintext


def test_protected_function_recovery_uses_external_descriptor() -> None:
    base = (0x10203040, 0x50607080, 0x90A0B0C0, 0xD0E0F000, 0x12345678)
    descriptor_plain = NATIVE.ProtectedFunctionDescriptor(
        name="synthetic",
        seed=0x11111111,
        mix=0x22222222,
        encrypted_start_marker=b"",
        encrypted_end_marker=b"",
    )
    key = NATIVE.derive_protected_function_key(
        descriptor_plain, base, 0x33333333
    )
    start = b"START!"
    end = b"!END!!"
    body = b"\x55\x8b\xec\x83\xec\x08\x33\xc0\xc3"
    descriptor = NATIVE.ProtectedFunctionDescriptor(
        name="synthetic",
        seed=descriptor_plain.seed,
        mix=descriptor_plain.mix,
        encrypted_start_marker=NATIVE.encrypt_rc4_sub(start, key),
        encrypted_end_marker=NATIVE.encrypt_rc4_sub(end, key),
    )
    image = b"prefix" + start + NATIVE.encrypt_rc4_sub(body, key) + end + b"tail"

    patched, report = NATIVE.recover_protected_function(
        image, descriptor, base, 0x33333333
    )

    assert body in patched
    assert report["function_size"] == len(body)
    assert report["x86_score"] > 0
    assert start not in patched
    assert end not in patched


def test_stack_builder_decode_and_sanitized_inventory() -> None:
    base_key = b"0123456789abcdefghij"
    bl_value = 0x5A
    plaintext = b"QUJDREVGR0hJSktMTU5PUA=="
    key = bytes(value ^ bl_value for value in base_key)
    encrypted = NATIVE.encrypt_rc4_sub(plaintext, key)
    assert len(encrypted) == 24
    prologue = b"\x55\x8b\xec"
    stack_writes = b"".join(
        b"\xc7\x45"
        + bytes([(0xE0 + index) & 0xFF])
        + encrypted[index : index + 4]
        for index in range(0, len(encrypted), 4)
    )
    prefix = prologue + stack_writes + b"\x6a" + bytes([len(encrypted)])
    bl_offset = len(prefix)
    call_offset = bl_offset + 2
    target = 0x200
    displacement = target - (call_offset + 5)
    image = (
        prefix
        + b"\xb3"
        + bytes([bl_value])
        + b"\xe8"
        + struct.pack("<i", displacement)
        + b"\xc3"
    )

    builders = NATIVE.decode_stack_string_builders(image, target, base_key)
    inventory = NATIVE.inventory_encoded_network_candidates(builders)

    assert builders[0].decoded == plaintext
    assert inventory["builder_count"] == 1
    assert inventory["base64_like_candidate_count"] == 1
    assert inventory["values_retained"] is False
    assert "QUJD" not in str(inventory)


def test_candidate_layout_uses_nearest_previous_offset() -> None:
    builders = [
        NATIVE.DecodedBuilder(offset, 0x5A, b"QUJDREVGR0hJ")
        for offset in (0x100, 0x160, 0x1C0, 0x220, 0x1000)
    ]

    inventory = NATIVE.inventory_encoded_network_candidates(builders)
    candidates = inventory["candidates"]

    assert inventory["layout_gap_method"] == "nearest_predecessor"
    assert inventory["layout_median_gap"] == 0x60
    assert inventory["layout_separation_threshold"] == 0x400
    assert inventory["separated_layout_candidate_count"] == 1
    assert [
        candidate["separated_layout_candidate"]
        for candidate in candidates
    ] == [False, False, False, False, True]


def test_candidate_layout_separates_large_cluster_from_base64_false_positives() -> None:
    builders = [
        NATIVE.DecodedBuilder(0x100 + index * 0x60, 0x5A, b"QUJDREVGR0hJ")
        for index in range(8)
    ]
    builders.extend(
        [
            NATIVE.DecodedBuilder(0x2000, 0x5A, b"USERNAME"),
            NATIVE.DecodedBuilder(0x2060, 0x5A, b"ProgramFiles"),
        ]
    )

    inventory = NATIVE.inventory_encoded_network_candidates(builders)

    assert inventory["base64_like_candidate_count"] == 10
    assert inventory["primary_layout_cluster_candidate_count"] == 8
    assert inventory["non_primary_base64_like_candidate_count"] == 2
    assert [
        candidate["primary_layout_cluster_candidate"]
        for candidate in inventory["candidates"]
    ] == [True] * 8 + [False, False]


def test_missing_protected_function_marker_is_an_error() -> None:
    descriptor = NATIVE.ProtectedFunctionDescriptor(
        name="missing",
        seed=1,
        mix=2,
        encrypted_start_marker=b"abcdef",
        encrypted_end_marker=b"ghijkl",
    )

    with pytest.raises(ValueError, match="開始マーカー"):
        NATIVE.recover_protected_function(
            b"no markers here", descriptor, (1, 2, 3, 4, 5), 3
        )
