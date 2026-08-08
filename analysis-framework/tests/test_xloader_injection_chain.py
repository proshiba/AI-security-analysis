from __future__ import annotations

import struct

import pytest

from malware.formbook_loader.injection_chain import (
    DEFAULT_API_ENTRIES,
    FunctionRange,
    InjectionChainError,
    build_report,
    context_field_accesses,
    immediate_values,
    immediate_references,
    verify_candidate_filter,
    verify_protected_apis,
)


def _mov_eax_from_ecx(displacement: int) -> bytes:
    return b"\x8b\x81" + struct.pack("<I", displacement)


def _mov_ecx_to_eax(displacement: int) -> bytes:
    return b"\x89\x81" + struct.pack("<I", displacement)


def _push(value: int) -> bytes:
    return b"\x68" + struct.pack("<I", value)


def _synthetic_image() -> bytes:
    image = bytearray(b"\x90" * 0x2D000)
    image[0x12530 : 0x1253A] = _push(0x13) + _push(0x19996921)
    image[0x11DF0 : 0x11DFA] = _push(0x438) + _push(0x1A)
    image[0x19160 : 0x19165] = _push(0x1A)
    image[0x22A40 : 0x22A4F] = _push(0x42000) + _push(0x43000) + _push(0x1000)
    image[0x2C330 : 0x2C335] = _push(0x42000)

    cursor = 0x261E0
    for placeholder in (
        0x77777777,
        0x11111111,
        0x11111112,
        0x11111113,
        0x11111114,
        0x11111115,
        0x11111116,
        0x11111117,
        0x11111118,
        0x11111119,
        0x1111111A,
    ):
        encoded = _push(placeholder)
        image[cursor : cursor + len(encoded)] = encoded
        cursor += len(encoded)

    for entry in DEFAULT_API_ENTRIES:
        image[entry.wrapper : entry.wrapper + 10] = (
            _push(entry.seed) + _push(entry.constant)
        )

    image[0x100:0x106] = _mov_eax_from_ecx(0xA90)
    image[0x106:0x10C] = _mov_eax_from_ecx(0x2ED4)
    image[0x10C:0x112] = _mov_ecx_to_eax(0x2ED4)
    return bytes(image)


def test_immediate_values_extracts_unsigned_values() -> None:
    image = _push(0xFFFFFFFF) + _push(0x1A)
    values = immediate_values(image, FunctionRange(0, len(image)))
    assert values == {0xFFFFFFFF, 0x1A}


def test_immediate_references_records_address_and_instruction() -> None:
    image = _push(0x6E1) + _push(0x10)
    references = immediate_references(image, 0x6E1)
    assert references == [
        {"address": "0x0", "mnemonic": "push", "operands": "0x6e1"}
    ]

def test_context_field_accesses_distinguishes_read_and_write() -> None:
    image = (
        _mov_eax_from_ecx(0x2ED4)
        + _mov_ecx_to_eax(0x2ED4)
        + _mov_eax_from_ecx(0xA90)
    )
    report = context_field_accesses(image, (0xA90, 0x2ED4))
    assert report["0x2ed4"]["reads"] == 1
    assert report["0x2ed4"]["writes"] == 1
    assert report["0xa90"]["reads"] == 1


def test_candidate_filter_requires_length_and_explorer_hash() -> None:
    image = _push(0x13) + _push(0x19996921)
    result = verify_candidate_filter(image, FunctionRange(0, len(image)))
    assert result["status"] == "confirmed"
    assert result["maximum_accepted_name_length"] == 18
    assert result["reject_if_contains_current_executable_stem"] is True


def test_protected_api_vectors_and_wrapper_constants() -> None:
    image = _synthetic_image()
    entries = verify_protected_apis(image)
    assert len(entries) == 8
    assert all(item["hash_matches"] for item in entries)
    assert all(item["constant_present_in_wrapper"] for item in entries)
    assert {item["name"] for item in entries} == {
        "NtOpenProcess",
        "NtQueryInformationProcess",
        "NtOpenThread",
        "NtSuspendThread",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtResumeThread",
        "ExitProcess",
    }


def test_build_report_recovers_injection_chain_without_execution() -> None:
    report = build_report(
        _synthetic_image(),
        sample_sha256="a" * 64,
        candidate_filter=FunctionRange(0x12530, 0x12670),
        injection=FunctionRange(0x11DF0, 0x12530),
        thread_open=FunctionRange(0x19160, 0x191E0),
        clone=FunctionRange(0x22A40, 0x22B10),
        module_extent=FunctionRange(0x2C330, 0x2C350),
        stub=FunctionRange(0x261E0, 0x26730),
    )
    assert report["status"] == "confirmed"
    assert report["safety"]["sample_executed_locally"] is False
    assert report["injection_operations"]["process_open_access_mask"]["found"] is True
    assert report["injection_operations"]["injected_stub"]["placeholder_count"] >= 10
    assert report["context_field_accesses"]["0x2ed4"]["writes"] == 1
    assert report["injection_state_handshake"]["classification"] == (
        "injection_synchronization_not_c2"
    )
    assert report["c2_recovery_implication"]["injection_stub_key_offset"] == "0x6e1"


def test_build_report_rejects_invalid_sample_hash() -> None:
    with pytest.raises(InjectionChainError, match="64桁"):
        build_report(
            _synthetic_image(),
            sample_sha256="bad",
            candidate_filter=FunctionRange(0x12530, 0x12670),
            injection=FunctionRange(0x11DF0, 0x12530),
            thread_open=FunctionRange(0x19160, 0x191E0),
            clone=FunctionRange(0x22A40, 0x22B10),
            module_extent=FunctionRange(0x2C330, 0x2C350),
            stub=FunctionRange(0x261E0, 0x26730),
        )
