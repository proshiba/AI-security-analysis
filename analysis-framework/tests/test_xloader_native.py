"""FormBook／XLoaderネイティブ静的解析補助器のテスト。"""

from __future__ import annotations

import importlib.util
import json
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


def _builder_function_at(
    function_offset: int,
    target: int,
    *,
    plaintext: bytes = TEST_PLAINTEXT,
    tweak: int = 0x5A,
) -> bytes:
    encrypted = _encrypted(plaintext, tweak)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted)
        + b"\x6a"
        + bytes([len(encrypted)])
        + b"\xb3"
        + bytes([tweak])
    )
    call_offset = function_offset + len(prefix)
    displacement = target - (call_offset + 5)
    return prefix + b"\xe8" + struct.pack("<i", displacement) + b"\xc3"


def _place_function(image: bytearray, offset: int, function: bytes) -> None:
    image[offset : offset + len(function)] = function


def _direct_call_function(function_offset: int, targets: tuple[int, ...]) -> bytes:
    function = bytearray(b"\x55\x8b\xec")
    for target in targets:
        call_offset = function_offset + len(function)
        function.extend(b"\xe8")
        function.extend(struct.pack("<i", target - (call_offset + 5)))
    function.extend(b"\xc3")
    return bytes(function)


def _base_key_helper(
    helper_offset: int,
    base_key: bytes,
    *,
    mask: int,
    byte_xor: int,
    mask_register: str = "eax",
    byte_xor_register: str | None = None,
) -> bytes:
    assert len(base_key) == NATIVE.BASE_KEY_LENGTH
    assert mask_register in {"eax", "ecx"}
    assert byte_xor_register in {None, "cl"}
    before_byte_xor = bytes(value ^ byte_xor for value in base_key)
    function = bytearray(b"\x55\x8b\xec\x83\xec\x24")
    function.extend(
        (b"\xb8" if mask_register == "eax" else b"\xb9")
        + struct.pack("<I", mask)
    )
    for index in range(0, len(before_byte_xor), 4):
        displacement = -0x24 + index
        word = int.from_bytes(before_byte_xor[index : index + 4], "little")
        function.extend(
            b"\xc7\x45"
            + bytes([displacement & 0xFF])
            + struct.pack("<I", word ^ mask)
        )
        function.extend(
            (b"\x31\x45" if mask_register == "eax" else b"\x31\x4d")
            + bytes([displacement & 0xFF])
        )
    function.extend(b"\x33\xc0")
    if byte_xor_register == "cl":
        function.extend(
            b"\xb1"
            + bytes([byte_xor])
            + b"\x30\x4c\x05\xdc"
        )
    else:
        function.extend(b"\x80\x74\x05\xdc" + bytes([byte_xor]))
    function.extend(
        b"\x40\x83\xf8\x14\x72\xf5"
        + b"\x6a\x14\x8d\x45\xdc\x50"
    )
    copy_target = helper_offset + 0x180
    call_offset = helper_offset + len(function)
    function.extend(
        b"\xe8" + struct.pack("<i", copy_target - (call_offset + 5)) + b"\xc3"
    )
    return bytes(function)


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


def test_auto_discovery_decodes_unique_call_target() -> None:
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(_encrypted(TEST_PLAINTEXT, 0x5A))
        + b"\x6a"
        + bytes([len(TEST_PLAINTEXT)])
        + b"\xb3\x5a"
    )
    image = _finish_function(prefix)

    result = NATIVE.auto_decode_stack_string_builders(image, TEST_BASE_KEY)

    discovery = result.call_target_discovery
    assert result.status == "decoded"
    assert result.key_status == "provided"
    assert discovery.status == "resolved"
    assert discovery.selected_call_target == TEST_DECRYPT_TARGET
    assert discovery.scan_truncated is False
    assert discovery.candidates[0].builder_count == 1
    assert discovery.candidates[0].function_offsets == (0,)
    assert result.builders == (
        NATIVE.DecodedBuilder(0, 0x5A, TEST_PLAINTEXT),
    )


def test_auto_discovery_recovers_stack_byte_written_from_constant_cl() -> None:
    encrypted = _encrypted(TEST_PLAINTEXT, 0x5A)
    prefix = bytearray(b"\x55\x8b\xec")
    prefix.extend(_stack_writes(encrypted[:12], start=-16))
    prefix.extend(b"\xb1" + encrypted[12:13])
    prefix.extend(b"\x88\x4d\xfc")
    for displacement, value in zip(range(-3, 0), encrypted[13:], strict=True):
        prefix.extend(b"\xc6\x45" + bytes([displacement & 0xFF, value]))
    prefix.extend(b"\x6a" + bytes([len(encrypted)]) + b"\xb3\x5a")
    image = _finish_function(bytes(prefix))

    result = NATIVE.auto_decode_stack_string_builders(image, TEST_BASE_KEY)

    assert result.status == "decoded"
    assert result.builders == (
        NATIVE.DecodedBuilder(0, 0x5A, TEST_PLAINTEXT),
    )


def test_auto_discovery_reports_unrecovered_base_key() -> None:
    image = bytearray(b"\x90" * (TEST_DECRYPT_TARGET + 1))
    function = _builder_function_at(0, TEST_DECRYPT_TARGET)
    image[: len(function)] = function

    result = NATIVE.auto_decode_stack_string_builders(bytes(image))

    assert result.status == "base_key_not_recovered"
    assert result.key_status == "not_recovered"
    assert result.call_target_discovery.status == "resolved"
    assert (
        result.call_target_discovery.selected_call_target
        == TEST_DECRYPT_TARGET
    )
    assert result.builders == ()


def test_auto_discovery_preserves_call_target_ambiguity() -> None:
    second_function_offset = 0x80
    second_target = 0x320
    image = bytearray(b"\x90" * (second_target + 1))
    first = _builder_function_at(0, TEST_DECRYPT_TARGET)
    second = _builder_function_at(second_function_offset, second_target)
    image[: len(first)] = first
    image[
        second_function_offset : second_function_offset + len(second)
    ] = second

    result = NATIVE.auto_decode_stack_string_builders(
        bytes(image), TEST_BASE_KEY
    )

    assert result.status == "call_target_ambiguous"
    assert result.call_target_discovery.status == "ambiguous"
    assert result.call_target_discovery.selected_call_target is None
    assert tuple(
        candidate.decrypt_call_target
        for candidate in result.call_target_discovery.candidates
    ) == (TEST_DECRYPT_TARGET, second_target)
    assert result.builders == ()


def test_auto_discovery_resolves_only_clearly_dominant_target() -> None:
    primary_target = 0x1000
    secondary_target = 0x1100
    image = bytearray(b"\x90" * 0x1200)
    for index in range(12):
        offset = index * 0x60
        _place_function(
            image,
            offset,
            _builder_function_at(offset, primary_target),
        )
    for index in range(2):
        offset = 0x600 + index * 0x60
        _place_function(
            image,
            offset,
            _builder_function_at(offset, secondary_target),
        )

    discovery = NATIVE.discover_stack_string_builder_call_targets(
        bytes(image)
    )

    assert discovery.status == "resolved"
    assert discovery.selection_method == "dominant"
    assert discovery.selected_call_target == primary_target
    assert sorted(candidate.builder_count for candidate in discovery.candidates) == [
        2,
        12,
    ]


def test_auto_discovery_keeps_small_count_margin_ambiguous() -> None:
    primary_target = 0x1000
    secondary_target = 0x1100
    image = bytearray(b"\x90" * 0x1200)
    for index in range(9):
        offset = index * 0x50
        _place_function(
            image,
            offset,
            _builder_function_at(offset, primary_target),
        )
    for index in range(8):
        offset = 0x500 + index * 0x50
        _place_function(
            image,
            offset,
            _builder_function_at(offset, secondary_target),
        )

    discovery = NATIVE.discover_stack_string_builder_call_targets(
        bytes(image)
    )

    assert discovery.status == "ambiguous"
    assert discovery.selection_method == "none"
    assert discovery.selected_call_target is None


def test_auto_decode_recovers_base_key_from_direct_helper() -> None:
    helper_offset = 0x500
    image = bytearray(b"\x90" * 0x800)
    _place_function(
        image,
        0,
        _builder_function_at(0, TEST_DECRYPT_TARGET),
    )
    _place_function(
        image,
        TEST_DECRYPT_TARGET,
        _direct_call_function(TEST_DECRYPT_TARGET, (helper_offset,)),
    )
    _place_function(
        image,
        helper_offset,
        _base_key_helper(
            helper_offset,
            TEST_BASE_KEY,
            mask=0x9AB20000,
            byte_xor=0x66,
        ),
    )

    result = NATIVE.auto_decode_stack_string_builders(bytes(image))

    assert result.status == "decoded"
    assert result.key_status == "statically_recovered"
    assert result.base_key_recovery == NATIVE.BaseKeyRecoveryEvidence(
        status="recovered",
        helper_offsets=(helper_offset,),
        scanned_callee_count=1,
    )
    assert result.builders == (
        NATIVE.DecodedBuilder(0, 0x5A, TEST_PLAINTEXT),
    )
    public_inventory = NATIVE.inventory_encoded_network_candidates(
        result.builders
    )
    assert TEST_BASE_KEY.decode("ascii") not in str(public_inventory)
    assert TEST_PLAINTEXT.decode("ascii") not in str(public_inventory)


def test_auto_decode_recovers_base_key_masked_with_ecx() -> None:
    helper_offset = 0x500
    image = bytearray(b"\x90" * 0x800)
    _place_function(
        image,
        0,
        _builder_function_at(0, TEST_DECRYPT_TARGET),
    )
    _place_function(
        image,
        TEST_DECRYPT_TARGET,
        _direct_call_function(TEST_DECRYPT_TARGET, (helper_offset,)),
    )
    _place_function(
        image,
        helper_offset,
        _base_key_helper(
            helper_offset,
            TEST_BASE_KEY,
            mask=0xDECBD40F,
            byte_xor=0xEC,
            mask_register="ecx",
        ),
    )

    result = NATIVE.auto_decode_stack_string_builders(bytes(image))

    assert result.status == "decoded"
    assert result.key_status == "statically_recovered"
    assert result.base_key_recovery == NATIVE.BaseKeyRecoveryEvidence(
        status="recovered",
        helper_offsets=(helper_offset,),
        scanned_callee_count=1,
    )
    assert result.builders == (
        NATIVE.DecodedBuilder(0, 0x5A, TEST_PLAINTEXT),
    )


def test_auto_decode_recovers_base_key_with_constant_cl_byte_xor() -> None:
    helper_offset = 0x500
    image = bytearray(b"\x90" * 0x800)
    _place_function(
        image,
        0,
        _builder_function_at(0, TEST_DECRYPT_TARGET),
    )
    _place_function(
        image,
        TEST_DECRYPT_TARGET,
        _direct_call_function(TEST_DECRYPT_TARGET, (helper_offset,)),
    )
    _place_function(
        image,
        helper_offset,
        _base_key_helper(
            helper_offset,
            TEST_BASE_KEY,
            mask=0xDECBD40F,
            byte_xor=0xEC,
            mask_register="ecx",
            byte_xor_register="cl",
        ),
    )

    result = NATIVE.auto_decode_stack_string_builders(bytes(image))

    assert result.status == "decoded"
    assert result.key_status == "statically_recovered"
    assert result.base_key_recovery == NATIVE.BaseKeyRecoveryEvidence(
        status="recovered",
        helper_offsets=(helper_offset,),
        scanned_callee_count=1,
    )
    assert result.builders == (
        NATIVE.DecodedBuilder(0, 0x5A, TEST_PLAINTEXT),
    )


def test_auto_decode_rejects_multiple_base_key_helpers() -> None:
    helper_offsets = (0x500, 0x680)
    image = bytearray(b"\x90" * 0x900)
    _place_function(
        image,
        0,
        _builder_function_at(0, TEST_DECRYPT_TARGET),
    )
    _place_function(
        image,
        TEST_DECRYPT_TARGET,
        _direct_call_function(TEST_DECRYPT_TARGET, helper_offsets),
    )
    for index, helper_offset in enumerate(helper_offsets):
        key = bytes(value ^ index for value in TEST_BASE_KEY)
        _place_function(
            image,
            helper_offset,
            _base_key_helper(
                helper_offset,
                key,
                mask=0x11111111 + index,
                byte_xor=0x66,
            ),
        )

    result = NATIVE.auto_decode_stack_string_builders(bytes(image))

    assert result.status == "base_key_not_recovered"
    assert result.key_status == "not_recovered"
    assert result.base_key_recovery == NATIVE.BaseKeyRecoveryEvidence(
        status="ambiguous",
        helper_offsets=helper_offsets,
        scanned_callee_count=2,
    )
    assert result.builders == ()


def test_auto_cli_report_omits_key_and_plaintext(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper_offset = 0x500
    image = bytearray(b"\x90" * 0x800)
    _place_function(
        image,
        0,
        _builder_function_at(0, TEST_DECRYPT_TARGET),
    )
    _place_function(
        image,
        TEST_DECRYPT_TARGET,
        _direct_call_function(TEST_DECRYPT_TARGET, (helper_offset,)),
    )
    _place_function(
        image,
        helper_offset,
        _base_key_helper(
            helper_offset,
            TEST_BASE_KEY,
            mask=0x9AB20000,
            byte_xor=0x66,
        ),
    )
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "report.json"
    input_path.write_bytes(image)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "native_xloader.py",
            str(input_path),
            "--output",
            str(output_path),
        ],
    )

    assert NATIVE.main() == 0

    report_text = output_path.read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["automation_status"] == "decoded"
    assert report["key_status"] == "statically_recovered"
    assert report["base_key_recovery"]["raw_key_retained"] is False
    assert TEST_BASE_KEY.decode("ascii") not in report_text
    assert TEST_PLAINTEXT.decode("ascii") not in report_text


def test_auto_discovery_reports_no_candidate() -> None:
    result = NATIVE.auto_decode_stack_string_builders(
        b"\x90" * 64, TEST_BASE_KEY
    )

    assert result.status == "call_target_not_found"
    assert result.call_target_discovery.status == "not_found"
    assert result.call_target_discovery.candidates == ()
    assert result.builders == ()


def test_auto_discovery_fails_closed_at_prologue_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(NATIVE, "MAX_AUTO_DISCOVERY_PROLOGUES", 1)
    image = b"\x55\x8b\xec\xc3" * 2

    result = NATIVE.auto_decode_stack_string_builders(image, TEST_BASE_KEY)

    assert result.status == "scan_limit_exceeded"
    assert result.call_target_discovery.status == "scan_limit_exceeded"
    assert result.call_target_discovery.scan_truncated is True
    assert result.call_target_discovery.selected_call_target is None
    assert result.call_target_discovery.candidates == ()
    assert result.builders == ()


def test_auto_discovery_fails_closed_at_candidate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(NATIVE, "MAX_AUTO_DISCOVERY_CANDIDATES", 1)
    second_function_offset = 0x80
    image = bytearray(b"\x90" * (TEST_DECRYPT_TARGET + 1))
    first = _builder_function_at(0, TEST_DECRYPT_TARGET)
    second = _builder_function_at(
        second_function_offset, TEST_DECRYPT_TARGET
    )
    image[: len(first)] = first
    image[
        second_function_offset : second_function_offset + len(second)
    ] = second

    result = NATIVE.auto_decode_stack_string_builders(
        bytes(image), TEST_BASE_KEY
    )

    assert result.status == "scan_limit_exceeded"
    assert result.call_target_discovery.status == "scan_limit_exceeded"
    assert result.call_target_discovery.scan_truncated is True
    assert result.call_target_discovery.selected_call_target is None
    assert result.call_target_discovery.candidates == ()
    assert result.builders == ()


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


def test_builder_accepts_forced_or_bl_and_known_al_stack_writes() -> None:
    tweak = 0xFF
    plaintext = b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldY"
    encrypted = _encrypted(plaintext, tweak)
    assert len(encrypted) == 32
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted[:8], start=-36)
        + b"\x66\xc7\x45\xe4"
        + encrypted[8:10]
        + b"\xb0"
        + encrypted[10:11]
        + b"\x88\x45\xe6"
        + b"\xb0\xf7"
        + b"\x30\xc0"
        + _stack_writes(encrypted[11:31], start=-25)
        + b"\x66\xc7\x45\xfb"
        + encrypted[31:32]
        + b"\x00"
        + b"\x88\x45\xfd"
        + b"\x6a"
        + bytes([len(encrypted)])
        + b"\x80\xcb\xff"
    )

    builders = NATIVE.decode_stack_string_builders(
        _finish_function(prefix),
        TEST_DECRYPT_TARGET,
        TEST_BASE_KEY,
    )

    assert builders == [NATIVE.DecodedBuilder(0, tweak, plaintext)]


def test_builder_rejects_non_forcing_or_bl_without_known_value() -> None:
    encrypted = _encrypted(TEST_PLAINTEXT, 0x5A)
    prefix = (
        b"\x55\x8b\xec"
        + _stack_writes(encrypted)
        + b"\x6a"
        + bytes([len(encrypted)])
        + b"\x80\xcb\x5a"
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
