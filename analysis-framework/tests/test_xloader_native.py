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


TEST_BASE_KEY = b"0123456789abcdefghij"
TEST_PLAINTEXT = b"QUJDREVGR0hJSktM"
TEST_DECRYPT_TARGET = 0x300


def _stack_writes(value: bytes, *, start: int | None = None) -> bytes:
    assert len(value) % 4 == 0
    displacement = -len(value) if start is None else start
    return b"".join(
        b"\xc7\x45"
        + bytes([(displacement + index) & 0xFF])
        + value[index : index + 4]
        for index in range(0, len(value), 4)
    )


def _direct_call(prefix: bytes, target: int = TEST_DECRYPT_TARGET) -> bytes:
    call_offset = len(prefix)
    displacement = target - (call_offset + 5)
    return b"\xe8" + struct.pack("<i", displacement)


def _finish_function(
    prefix: bytes, target: int = TEST_DECRYPT_TARGET
) -> bytes:
    image = prefix + _direct_call(prefix, target) + b"\xc3"
    assert len(image) <= target
    return image.ljust(target + 1, b"\x90")


def _encrypted(plaintext: bytes, tweak: int) -> bytes:
    key = bytes(value ^ tweak for value in TEST_BASE_KEY)
    return NATIVE.encrypt_rc4_sub(plaintext, key)


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
    ).ljust(target + 1, b"\x90")

    builders = NATIVE.decode_stack_string_builders(image, target, base_key)
    inventory = NATIVE.inventory_encoded_network_candidates(builders)

    assert builders[0].decoded == plaintext
    assert inventory["builder_count"] == 1
    assert inventory["base64_like_candidate_count"] == 1
    assert inventory["values_retained"] is False
    assert "QUJD" not in str(inventory)


def test_builder_accepts_bl_before_remaining_stack_writes() -> None:
    tweak = 0x5A
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    writes = _stack_writes(encrypted)
    prefix = (
        b"\x55\x8b\xec"
        + writes[:7]
        + b"\xb3"
        + bytes([tweak])
        + writes[7:]
        + b"\x6a"
        + bytes([len(encrypted)])
    )

    builders = NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    )

    assert builders == [NATIVE.DecodedBuilder(0, tweak, TEST_PLAINTEXT)]


def test_builder_accepts_pointer_push_and_immediate_store_padding() -> None:
    tweak = 0x5A
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted, start=-18)
        + b"\x66\xc7\x45\xfe\x00\x00"
        + b"\x6a\x0d"
    )
    prefix += _direct_call(prefix, 0x280)
    prefix += (
        b"\x6a"
        + bytes([len(encrypted)])
        + b"\x8d\x45\xee"
        + b"\x50"
        + b"\xb3"
        + bytes([tweak])
    )

    builders = NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    )

    assert builders == [NATIVE.DecodedBuilder(0, tweak, TEST_PLAINTEXT)]


def test_builder_rejects_non_null_immediate_store_padding() -> None:
    tweak = 0x5A
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted, start=-18)
        + b"\x66\xc7\x45\xfe\xaa\xbb"
        + b"\x6a"
        + bytes([len(encrypted)])
        + b"\xb3"
        + bytes([tweak])
    )

    assert NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    ) == []


def test_builder_propagates_ebx_length_and_tweak() -> None:
    tweak = 0x6C
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted)
        + b"\xbb"
        + struct.pack("<I", len(encrypted))
        + b"\x53"
        + b"\xbb"
        + struct.pack("<I", tweak)
    )

    builders = NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    )

    assert builders == [NATIVE.DecodedBuilder(0, tweak, TEST_PLAINTEXT)]


def test_builder_ignores_e8_bytes_inside_an_immediate() -> None:
    target = 0x180
    fake_call_offset = 6
    fake_displacement = struct.pack(
        "<i", target - (fake_call_offset + 5)
    )
    assert fake_displacement[-1] == 0
    image = (
        b"\x55\x8b\xec\xc7\x45\xc0"
        + b"\xe8"
        + fake_displacement[:3]
        + b"\x00\xc0\xc3"
    ).ljust(target + 1, b"\x90")

    assert NATIVE.decode_stack_string_builders(
        image, target, TEST_BASE_KEY
    ) == []


def test_builder_rejects_bl_clobber_before_call() -> None:
    tweak = 0x5A
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted)
        + b"\x6a"
        + bytes([len(encrypted)])
        + b"\xb3"
        + bytes([tweak])
        + b"\x31\xdb"
    )

    assert NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    ) == []


def test_builder_rejects_incomplete_stack_value() -> None:
    tweak = 0x5A
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted[:-4], start=-len(encrypted))
        + b"\x6a"
        + bytes([len(encrypted)])
        + b"\xb3"
        + bytes([tweak])
    )

    assert NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    ) == []


def test_builder_with_repeated_tweak_assignment_is_not_duplicated() -> None:
    tweak = 0x5A
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted)
        + b"\x6a"
        + bytes([len(encrypted)])
        + b"\xbb\x11\x00\x00\x00"
        + b"\xb3"
        + bytes([tweak])
    )

    builders = NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    )

    assert builders == [NATIVE.DecodedBuilder(0, tweak, TEST_PLAINTEXT)]


def test_builder_rejects_out_of_range_decrypt_target() -> None:
    with pytest.raises(ValueError, match="入力範囲外"):
        NATIVE.decode_stack_string_builders(
            b"\x55\x8b\xec\xc3", 0x100, TEST_BASE_KEY
        )


def test_builder_rejects_unknown_length_register() -> None:
    tweak = 0x5A
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted)
        + b"\x50"
        + b"\xb3"
        + bytes([tweak])
    )

    assert NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    ) == []


def test_builder_rejects_ambiguous_nested_function_boundary() -> None:
    tweak = 0x5A
    encrypted = _encrypted(TEST_PLAINTEXT, tweak)
    prefix = (
        b"\x55\x8b\xec\x90"
        + b"\x55\x8b\xec"
        + _stack_writes(encrypted)
        + b"\x6a"
        + bytes([len(encrypted)])
        + b"\xb3"
        + bytes([tweak])
    )

    assert NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    ) == []


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


def test_output_path_rejects_input_and_key_aliases(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    key_path = tmp_path / "key.bin"
    input_path.write_bytes(b"input")
    key_path.write_bytes(b"key")

    with pytest.raises(ValueError, match="output"):
        NATIVE._validated_output_path(input_path, (input_path, key_path))
    with pytest.raises(ValueError, match="output"):
        NATIVE._validated_output_path(key_path, (input_path, key_path))


def test_output_path_rejects_existing_hardlink_alias(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    alias_path = tmp_path / "output.bin"
    input_path.write_bytes(b"input")
    try:
        alias_path.hardlink_to(input_path)
    except OSError:
        pytest.skip("hardlink creation is unavailable")

    with pytest.raises(ValueError, match="output"):
        NATIVE._validated_output_path(alias_path, (input_path,))
    assert input_path.read_bytes() == b"input"
