"""PE trailer RC4 decoderの厳格境界と昇格禁止を検証する。"""

from __future__ import annotations

import hashlib
import struct

import pytest

from unpackers import pe_trailer_rc4 as target
from unpackers import static_unpacker


def _minimal_pe() -> bytes:
    """section末尾が0x400になる無害なPE32 fixtureを返す。"""

    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 20, 0x1000)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(optional), 0x210E)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        1,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    headers = b"PE\0\0" + coff + optional + section
    image[0x80 : 0x80 + len(headers)] = headers
    image[0x200] = 0xC3
    return bytes(image)


def _shellcode(*, valid_entry: bool = True) -> bytes:
    """実行しない合成x86命令列を、profileの固定jump marker付きで作る。"""

    entry_offset = 0x497
    prefix = b"\xe9\x92\x04\x00\x00"
    padding = b"synthetic-fixture" * 80
    prefix = (prefix + padding)[:entry_offset].ljust(entry_offset, b"F")
    if not valid_entry:
        return prefix + b"\0" * target.MAX_ENTRY_PROBE_SIZE
    block = bytes.fromhex("558bec83ec0431c075029090e80000000083c00175029090c9c3")
    return prefix + (block * 32)[: target.MAX_ENTRY_PROBE_SIZE]


def _fixture(
    payload: bytes | None = None,
    *,
    key: bytes = bytes(range(1, target.KEY_SIZE + 1)),
    declared_length: int | None = None,
    footer_offset_delta: int = 0,
    extra_before_footer: bytes = b"",
    apply_xor: bool = True,
) -> bytes:
    payload = _shellcode() if payload is None else payload
    if len(key) != target.KEY_SIZE:
        raise ValueError("fixture keyは32 byteが必要です")
    rc4_plaintext = (
        bytes(value ^ target.XOR_VALUE for value in payload) if apply_xor else payload
    )
    encrypted = target._rc4(rc4_plaintext, key)
    header = bytearray(target.HEADER_SIZE)
    header[: target.KEY_SIZE] = key
    struct.pack_into(
        "<I",
        header,
        target.DECLARED_LENGTH_OFFSET,
        len(payload) if declared_length is None else declared_length,
    )
    image = _minimal_pe()
    footer = struct.pack("<I", len(image) + footer_offset_delta)
    return image + bytes(header) + encrypted + extra_before_footer + footer


def test_valid_fixture_recovers_only_unattributed_x86_shellcode() -> None:
    payload = _shellcode()
    report, artifacts = target.recover_pe_trailer_rc4(_fixture(payload))

    assert artifacts == [("pe-trailer-rc4-xor7b-x86-shellcode", payload)]
    assert report["status"] == "recovered_x86_shellcode"
    assert report["artifact"] == {
        "kind": "pe-trailer-rc4-xor7b-x86-shellcode",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "format": "raw-x86-shellcode",
        "structure_validated": True,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_payload_confirmed": False,
        "raw_payload_included": False,
    }
    assert report["trailer"]["exact_eof_boundary"] is True
    assert report["trailer"]["raw_key_included"] is False
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False
    assert report["terminal_payload_confirmed"] is False
    assert report["safety"]["family_or_c2_promoted"] is False
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False


@pytest.mark.parametrize("delta", [-1, 1])
def test_footer_must_equal_validated_pe_extent(delta: int) -> None:
    report, artifacts = target.recover_pe_trailer_rc4(
        _fixture(footer_offset_delta=delta)
    )

    assert artifacts == []
    assert report["status"] == "no_candidates"
    assert report["candidate_count"] == 0


@pytest.mark.parametrize("declared_delta", [-1, 1])
def test_declared_length_must_end_exactly_before_footer(declared_delta: int) -> None:
    payload = _shellcode()
    report, artifacts = target.recover_pe_trailer_rc4(
        _fixture(payload, declared_length=len(payload) + declared_delta)
    )

    assert artifacts == []
    assert report["status"] == "candidate_rejected"
    assert report["rejection_reasons"] == {"declared_output_boundary_mismatch": 1}


def test_unaccounted_trailing_byte_is_rejected() -> None:
    report, artifacts = target.recover_pe_trailer_rc4(
        _fixture(extra_before_footer=b"X")
    )

    assert artifacts == []
    assert report["rejection_reasons"] == {"declared_output_boundary_mismatch": 1}


def test_zero_key_is_rejected_without_rc4_attempt() -> None:
    report, artifacts = target.recover_pe_trailer_rc4(
        _fixture(key=b"\0" * target.KEY_SIZE)
    )

    assert artifacts == []
    assert report["evaluated_candidate_count"] == 0
    assert report["rejection_reasons"] == {"key_invalid": 1}


def test_unrecognized_post_rc4_data_is_rejected() -> None:
    payload = bytearray(_shellcode())
    payload[0] = 0x90
    report, artifacts = target.recover_pe_trailer_rc4(_fixture(bytes(payload)))

    assert artifacts == []
    assert report["rejection_reasons"] == {"decoded_structure_invalid": 1}


def test_valid_rc4_only_variant_is_recovered_without_xor() -> None:
    """コード上の条件分岐どおり、markerなしRC4出力も構造検証後だけ保持する。"""

    payload = _shellcode()
    report, artifacts = target.recover_pe_trailer_rc4(
        _fixture(payload, apply_xor=False)
    )

    assert artifacts == [("pe-trailer-rc4-x86-shellcode", payload)]
    assert report["status"] == "recovered_x86_shellcode"
    assert report["trailer"]["post_rc4_marker_matched"] is False
    assert report["transforms"] == ["rc4"]
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False


def test_marker_alone_cannot_bypass_entry_structure_validation() -> None:
    report, artifacts = target.recover_pe_trailer_rc4(
        _fixture(_shellcode(valid_entry=False))
    )

    assert artifacts == []
    assert report["rejection_reasons"] == {"decoded_structure_invalid": 1}


def test_declared_output_budget_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _shellcode()
    monkeypatch.setattr(target, "MAX_OUTPUT_SIZE", len(payload) - 1)
    report, artifacts = target.recover_pe_trailer_rc4(_fixture(payload))

    assert artifacts == []
    assert report["status"] == "budget_exhausted"
    assert report["recovery_attempts_complete"] is False
    assert report["recovered_artifact_set_complete"] is False
    assert report["limit_reason"] == "declared_output_size_limit"


def test_malformed_pe_never_becomes_trailer_candidate() -> None:
    malformed = bytearray(_fixture())
    malformed[:2] = b"ZZ"
    report, artifacts = target.recover_pe_trailer_rc4(bytes(malformed))

    assert artifacts == []
    assert report["status"] == "no_candidates"
    assert report["candidate_count"] == 0


def test_static_unpacker_routes_verified_child_without_family_promotion() -> None:
    payload = _shellcode()
    report, artifacts = static_unpacker.unpack_bytes(_fixture(payload), "fixture.exe")

    trailer = report["pe_trailer_rc4"]
    assert trailer["status"] == "recovered_x86_shellcode"
    assert trailer["family_attribution_allowed"] is False
    assert trailer["c2_confirmation_allowed"] is False
    assert trailer["terminal_payload_confirmed"] is False
    assert ("pe-trailer-rc4-xor7b-x86-shellcode", payload) in artifacts
