from __future__ import annotations

from unpackers.remcos_native_constant_writer import (
    RemcosNativeConstantLimits,
    recover_remcos_native_constants,
)
from unpackers.static_unpacker import unpack_bytes

KEY = b"static-key"
HELPER_PREFIX = bytes.fromhex(
    "8b5424048b4c240801caf7d98b5c240c8b44241001d889c6f7db89df"
)
HELPER_MIDDLE = bytes.fromhex("8a040a01f33203")
HELPER_LOOP = bytes.fromhex("29f343750289fb88040a4175")


def _call(source: int, target: int) -> bytes:
    return b"\xe8" + (target - source - 5).to_bytes(4, "little", signed=True)


def _writer(plaintext: bytes, *, gap: bool = False) -> bytes:
    ciphertext = bytes(
        value ^ KEY[index % len(KEY)] for index, value in enumerate(plaintext)
    )
    framed = len(ciphertext).to_bytes(4, "little") + ciphertext
    framed += b"\x00" * ((-len(framed)) % 4)
    code = bytearray(b"\x8b\x54\x24\x04")
    for index in range(0, len(framed), 4):
        code.extend(b"\xc7\x02" + framed[index : index + 4])
        if index + 4 < len(framed):
            step = 8 if gap and index == 0 else 4
            code.extend(b"\x83\xc2" + bytes([step]))
    code.extend(b"\xc2\x04\x00")
    return bytes(code)


def _fixture(
    plaintext: bytes = b"one.invalid/payload.bin\x00two.example/path.bin\x00\x00",
    *,
    duplicate_helper: bool = False,
    gap: bool = False,
    reference_writer: bool = True,
) -> bytes:
    data = bytearray(b"\x90" * 0x900)
    wrapper = 0x300
    expression = 0x306
    helper_call = 0x330
    helper = 0x400
    writer = 0x600

    data[0x20:0x25] = _call(0x20, wrapper)
    data[0x25 : 0x25 + len(KEY)] = KEY
    if reference_writer:
        data[0x80:0x85] = _call(0x80, writer)

    data[wrapper:expression] = b"\x90" * (expression - wrapper)
    first = 0x10203040
    second = 0x55667788
    third = (len(KEY) - (first ^ second)) & 0xFFFFFFFF
    expression_bytes = (
        b"\xb8"
        + first.to_bytes(4, "little")
        + b"\x35"
        + second.to_bytes(4, "little")
        + b"\x05"
        + third.to_bytes(4, "little")
        + b"\x50"
    )
    data[expression : expression + len(expression_bytes)] = expression_bytes
    data[expression + len(expression_bytes) : helper_call] = b"\x90" * (
        helper_call - expression - len(expression_bytes)
    )
    data[helper_call : helper_call + 5] = _call(helper_call, helper)

    helper_bytes = (
        HELPER_PREFIX
        + b"\x90" * 8
        + HELPER_MIDDLE
        + b"\x90" * 8
        + HELPER_LOOP
        + b"\x90" * 8
        + b"\xc2\x10\x00"
    )
    data[helper : helper + len(helper_bytes)] = helper_bytes
    if duplicate_helper:
        data[0x500 : 0x500 + len(helper_bytes)] = helper_bytes
    writer_bytes = _writer(plaintext, gap=gap)
    data[writer : writer + len(writer_bytes)] = writer_bytes
    return bytes(data)


def _semantic_variant_fixture() -> bytes:
    data = bytearray(b"\x90" * 0xA00)
    wrapper = 0x300
    wrapper_body = 0x340
    helper_call = 0x380
    helper = 0x500
    writer = 0x700

    data[0x20:0x25] = _call(0x20, wrapper)
    data[0x25 : 0x25 + len(KEY)] = KEY
    data[0x80:0x85] = _call(0x80, writer)
    data[wrapper : wrapper + 5] = b"\xe9" + (wrapper_body - wrapper - 5).to_bytes(
        4, "little", signed=True
    )
    initial = 0x100
    xor_value = 0x55
    add_value = (len(KEY) - (initial ^ xor_value)) & 0xFFFFFFFF
    expression = (
        b"\x68"
        + initial.to_bytes(4, "little")
        + b"\x81\x34\x24"
        + xor_value.to_bytes(4, "little")
        + b"\x81\x04\x24"
        + add_value.to_bytes(4, "little")
        + b"\x50"
    )
    data[wrapper_body : wrapper_body + len(expression)] = expression
    data[helper_call : helper_call + 5] = _call(helper_call, helper)

    helper_bytes = bytearray()
    helper_bytes.extend(b"\x8b\x54\x24\x04\xfc")
    helper_bytes.extend(b"\x8b\x4c\x24\x08\x85\xd2")
    helper_bytes.extend(b"\x01\xca\xf7\xd9\x8b\x5c\x24\x0c")
    helper_bytes.extend(b"\x8b\x44\x24\x10\x01\xd8\x89\xc6\xf7\xdb\x89\xdf")
    load_relative = len(helper_bytes)
    helper_bytes.extend(b"\x8a\x04\x0a\x01\xf3\x32\x03")
    helper_bytes.extend(b"\x90" * 32)
    helper_bytes.extend(b"\x29\xf3\x43\x75\x02\x89\xfb\x88\x04\x0a\x41")
    branch_relative = len(helper_bytes)
    branch_source = helper + branch_relative
    branch_target = helper + load_relative
    helper_bytes.extend(
        b"\x0f\x85"
        + (branch_target - branch_source - 6).to_bytes(4, "little", signed=True)
        + b"\xc2\x10\x00"
    )
    data[helper : helper + len(helper_bytes)] = helper_bytes
    writer_bytes = _writer(b"semantic.invalid/path.bin")
    data[writer : writer + len(writer_bytes)] = writer_bytes
    return bytes(data)


def test_recovers_framed_constants_and_preserves_network_evidence_boundary() -> None:
    report, artifacts = recover_remcos_native_constants(_fixture())

    assert report["status"] == "constants_recovered"
    assert report["candidate_count"] == 1
    assert report["decrypt_context"]["key_size"] == len(KEY)
    assert report["candidates"][0]["direct_call_reference_present"] is True
    assert artifacts == [
        (
            "remcos-native-constant-001.txt",
            b"one.invalid/payload.bin\x00two.example/path.bin\x00\x00",
        )
    ]
    assert report["network_candidates"] == [
        {
            "source_sequence": 1,
            "order": 1,
            "role": "payload_retrieval_candidate",
            "host": "one.invalid",
            "path": "/payload.bin",
            "scheme": "unresolved",
            "c2_confirmed": False,
        },
        {
            "source_sequence": 1,
            "order": 2,
            "role": "payload_retrieval_candidate",
            "host": "two.example",
            "path": "/path.bin",
            "scheme": "unresolved",
            "c2_confirmed": False,
        },
    ]
    assert report["evidence_boundary"]["family_attribution_allowed"] is False
    assert report["evidence_boundary"]["c2_confirmation_allowed"] is False
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False
    assert KEY.hex() not in repr(report)


def test_accepts_strict_writer_without_direct_call_as_lower_strength_evidence() -> None:
    report, _artifacts = recover_remcos_native_constants(
        _fixture(b"Publisher", reference_writer=False)
    )

    assert report["status"] == "constants_recovered"
    assert report["candidates"][0]["direct_call_reference_present"] is False
    assert report["candidates"][0]["call_reference_offsets"] == []


def test_recovers_semantic_helper_and_jump_stack_wrapper_variant() -> None:
    report, artifacts = recover_remcos_native_constants(_semantic_variant_fixture())

    assert report["status"] == "constants_recovered"
    assert report["decrypt_context"]["key_size"] == len(KEY)
    assert artifacts == [
        ("remcos-native-constant-001.txt", b"semantic.invalid/path.bin")
    ]


def test_rejects_ambiguous_decrypt_helper_profile() -> None:
    report, artifacts = recover_remcos_native_constants(_fixture(duplicate_helper=True))

    assert report["status"] == "decrypt_helper_not_unique"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_unrelated_data_is_complete_not_applicable() -> None:
    """無関係なdata層を候補集合未完了として親caseへ伝播しない。"""

    report, artifacts = recover_remcos_native_constants(b"opaque benign data")

    assert report["status"] == "not_applicable_profile"
    assert report["candidate_set_complete"] is True
    assert report["candidate_set_truncated"] is False
    assert report["candidate_count"] == 0
    assert artifacts == []


def test_rejects_noncontiguous_dword_writer() -> None:
    report, artifacts = recover_remcos_native_constants(_fixture(gap=True))

    assert report["status"] == "writer_candidates_rejected"
    assert report["candidate_count"] == 0
    assert artifacts == []


def test_rejects_input_and_candidate_limits_without_partial_output() -> None:
    data = _fixture()
    report, artifacts = recover_remcos_native_constants(
        data,
        limits=RemcosNativeConstantLimits(max_input_bytes=len(data) - 1),
    )

    assert report["status"] == "input_size_rejected"
    assert artifacts == []

    report, artifacts = recover_remcos_native_constants(
        data,
        limits=RemcosNativeConstantLimits(max_candidates=0),
    )
    assert report["status"] == "candidate_limit_exceeded"
    assert report["candidate_set_truncated"] is True
    assert artifacts == []


def test_static_unpacker_routes_raw_data_through_strict_decoder() -> None:
    report, artifacts = unpack_bytes(_fixture(), name="native-stage.bin")

    assert report["format"] == "data"
    assert report["remcos_native_constant_writer"]["status"] == ("constants_recovered")
    assert any(kind == "remcos-native-constant-001.txt" for kind, _ in artifacts)
