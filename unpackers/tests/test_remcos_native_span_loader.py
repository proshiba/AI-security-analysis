from __future__ import annotations

import hashlib

import unpackers.remcos_native_span_loader as span_loader
from unpackers.remcos_native_span_loader import (
    RemcosNativeSpanLimits,
    recover_remcos_native_span_stage,
)

KEY = bytes.fromhex("11223344")
STAGE_SIZE = 256


def _jne(source: int, target: int) -> bytes:
    return b"\x0f\x85" + (target - source - 6).to_bytes(4, "little", signed=True)


def _loader(*, stage_size: int = STAGE_SIZE, key: bytes = KEY) -> bytes:
    data = bytearray(b"\x90" * 0x240)

    data[0x20:0x24] = b"\x8b\x44\x24\x04"
    data[0x30:0x32] = b"\x89\xc3"
    data[0x40:0x46] = b"\x81\xc3" + (0x1000).to_bytes(4, "little")
    data[0x60:0x63] = b"\x8b\x0c\x10"
    data[0x70:0x73] = b"\x89\x0c\x13"
    data[0x80] = 0x42
    data[0x90:0x96] = b"\x81\xfa" + stage_size.to_bytes(4, "little")
    data[0xA0:0xA6] = _jne(0xA0, 0x60)

    data[0x120:0x125] = b"\xba" + stage_size.to_bytes(4, "little")
    data[0x130:0x132] = b"\x31\xc0"
    data[0x140:0x144] = b"\x8b\x7c\x24\x0c"
    data[0x160:0x167] = b"\x81\x34\x07" + key
    data[0x170:0x173] = b"\x83\xc0\x04"
    data[0x180:0x182] = b"\x39\xd0"
    data[0x190:0x196] = _jne(0x190, 0x160)
    data[0x1A0:0x1A2] = b"\xff\xd7"
    return bytes(data)


def _encrypt(value: bytes, key: bytes = KEY) -> bytes:
    return bytes(byte ^ key[index & 3] for index, byte in enumerate(value))


def test_recovers_stage_from_instruction_derived_size_and_key() -> None:
    plaintext = b"A" * STAGE_SIZE
    report, artifacts = recover_remcos_native_span_stage(
        _loader(),
        _encrypt(plaintext),
        limits=RemcosNativeSpanLimits(require_constant_writer_validation=False),
    )

    assert report["status"] == "stage_recovered"
    assert report["copy_profile"]["stage_size"] == STAGE_SIZE
    assert report["xor_profile"]["stage_size"] == STAGE_SIZE
    assert report["zero_padding_size"] == 0
    assert artifacts == [("remcos-native-stage-03.bin", plaintext)]
    assert KEY.hex() not in repr(report)


def test_zero_pads_ciphertext_before_dword_xor() -> None:
    plaintext = b"B" * (STAGE_SIZE - 4)
    report, artifacts = recover_remcos_native_span_stage(
        _loader(),
        _encrypt(plaintext),
        limits=RemcosNativeSpanLimits(require_constant_writer_validation=False),
    )

    assert report["status"] == "stage_recovered"
    assert report["zero_padding_size"] == 4
    assert artifacts[0][1] == plaintext + KEY


def test_default_profile_requires_constant_writer_validation(monkeypatch) -> None:
    plaintext = b"C" * STAGE_SIZE

    report, artifacts = recover_remcos_native_span_stage(_loader(), _encrypt(plaintext))
    assert report["status"] == "recovered_stage_validation_failed"
    assert artifacts == []

    monkeypatch.setattr(
        span_loader,
        "recover_remcos_native_constants",
        lambda _data: (
            {
                "status": "constants_recovered",
                "profile": "test-profile",
                "candidate_count": 1,
                "network_candidates": [],
            },
            [],
        ),
    )
    report, artifacts = recover_remcos_native_span_stage(_loader(), _encrypt(plaintext))
    assert report["status"] == "stage_recovered"
    assert artifacts == [("remcos-native-stage-03.bin", plaintext)]


def test_accepts_independently_corroborated_bounded_cfg(monkeypatch) -> None:
    plaintext = b"E" * STAGE_SIZE
    ciphertext = _encrypt(plaintext)
    monkeypatch.setattr(
        span_loader,
        "recover_remcos_polymorphic_xor_loader",
        lambda _loader, payload: (
            {
                "status": "shellcode_recovered",
                "profile": "test-cfg-profile",
                "candidate_count": 1,
                "loop_size": STAGE_SIZE,
                "xor_key_sha256": hashlib.sha256(KEY).hexdigest(),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
            },
            [],
        ),
    )

    report, artifacts = recover_remcos_native_span_stage(_loader(), ciphertext)

    assert report["status"] == "stage_recovered"
    assert report["stage_validation"]["accepted_by"] == ["bounded_cfg"]
    assert artifacts == [("remcos-native-stage-03.bin", plaintext)]


def test_rejects_size_mismatch_and_candidate_limits_without_partial_output() -> None:
    report, artifacts = recover_remcos_native_span_stage(
        _loader(), b"X" * (STAGE_SIZE + 1)
    )
    assert report["status"] == "payload_exceeds_stage_size"
    assert artifacts == []

    report, artifacts = recover_remcos_native_span_stage(
        _loader(),
        b"X" * STAGE_SIZE,
        limits=RemcosNativeSpanLimits(max_anchor_candidates=0),
    )
    assert report["status"] == "copy_profile_not_unique"
    assert artifacts == []


def test_rejects_non_back_edge_xor_loop() -> None:
    loader = bytearray(_loader())
    loader[0x190:0x196] = _jne(0x190, 0x1A0)
    report, artifacts = recover_remcos_native_span_stage(
        bytes(loader), _encrypt(b"D" * STAGE_SIZE)
    )

    assert report["status"] == "xor_profile_not_unique"
    assert artifacts == []
