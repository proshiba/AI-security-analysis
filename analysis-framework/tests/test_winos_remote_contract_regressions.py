"""remote desktopのfault・alignment・dynamic length境界を検証する。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE_PATH = FRAMEWORK / "malware" / "valleyrat" / "winos_remote_desktop_contracts.py"
SPEC = importlib.util.spec_from_file_location("winos_remote_contract_regressions_target", MODULE_PATH)
assert SPEC and SPEC.loader
WINOS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WINOS
SPEC.loader.exec_module(WINOS)


def _bitmap_descriptor(mode: int, *, total: int | None = None) -> bytes:
    expected = 0x29 + (4 * (1 << mode) if mode <= 8 else 0)
    payload = bytearray(expected if total is None else total)
    payload[0] = 0x17
    if len(payload) >= 0x11:
        struct.pack_into("<H", payload, 0x0F, mode)
    return bytes(payload)


def test_zero_fps_is_code_accepted_but_refused_as_division_fault() -> None:
    zero = WINOS.classify_remote_desktop_payload(b"\x07\x00", direction="server_to_client")
    assert zero.length_valid is True
    assert zero.structure_valid is False
    assert zero.contract_valid is False
    assert zero.structure_status == "unsafe_zero_fps_division"
    assert "fps_zero_would_divide_1000_by_zero" in zero.validation_errors
    assert zero.operation_executed is False
    assert zero.wire_bytes is None

    pixel_zero = WINOS.classify_remote_desktop_payload(b"\x06\x00", direction="server_to_client")
    assert pixel_zero.length_valid is True
    assert pixel_zero.structure_valid is False
    assert "pixel_mode_zero_reaches_division_by_zero" in pixel_zero.validation_errors
    assert ("division_fault_risk", True) in pixel_zero.metadata
    for raw, effective in ((1, 1), (3, 4), (7, 8)):
        pixel = WINOS.classify_remote_desktop_payload(bytes([0x06, raw]), direction="server_to_client")
        assert pixel.contract_valid is True
        assert ("pixel_mode_effective", effective) in pixel.metadata

    nonzero = WINOS.classify_remote_desktop_payload(b"\x07\x01", direction="server_to_client")
    assert nonzero.contract_valid is True
    assert ("derived_interval_ms", 1000) in nonzero.metadata


def test_input_records_require_explicit_runtime_size_and_exact_divisibility() -> None:
    unbound = WINOS.classify_remote_desktop_payload(
        b"\x0c" + bytes(80),
        direction="server_to_client",
    )
    assert unbound.length_valid is True
    assert unbound.structure_valid is False
    assert "input_record_size_not_bound" in unbound.validation_errors

    aligned = WINOS.classify_remote_desktop_payload(
        b"\x0c" + bytes(80),
        direction="server_to_client",
        input_record_size=40,
    )
    assert aligned.contract_valid is True
    assert ("record_count", 2) in aligned.metadata
    assert ("record_alignment_valid", True) in aligned.metadata

    misaligned = WINOS.classify_remote_desktop_payload(
        b"\x0c" + bytes(81),
        direction="server_to_client",
        input_record_size=40,
    )
    assert misaligned.structure_valid is False
    assert "input_record_body_not_divisible_by_record_size" in misaligned.validation_errors

    for invalid in (0, 65537):
        with pytest.raises(ValueError):
            WINOS.classify_remote_desktop_payload(
                b"\x0cX",
                direction="server_to_client",
                input_record_size=invalid,
            )


@pytest.mark.parametrize("mode", [0, 1, 8, 9, 16, 32])
def test_bitmap_descriptor_length_is_exact_function_of_mode(mode: int) -> None:
    exact = WINOS.classify_remote_desktop_payload(
        _bitmap_descriptor(mode),
        direction="client_to_server",
    )
    expected = 0x29 + (4 * (1 << mode) if mode <= 8 else 0)
    assert exact.contract_valid is True
    assert ("bitmap_mode", mode) in exact.metadata
    assert ("expected_total_length", expected) in exact.metadata

    short = WINOS.classify_remote_desktop_payload(
        _bitmap_descriptor(mode, total=expected - 1),
        direction="client_to_server",
    )
    assert short.contract_valid is False
    if expected == 0x29:
        assert "bitmap_info_header_requires_0x28_bytes" in short.validation_errors
    else:
        assert "bitmap_format_descriptor_length_not_exact_for_mode" in short.validation_errors

    long = WINOS.classify_remote_desktop_payload(
        _bitmap_descriptor(mode, total=expected + 1),
        direction="client_to_server",
    )
    assert long.contract_valid is False
    assert "bitmap_format_descriptor_length_not_exact_for_mode" in long.validation_errors


def test_advertised_raw_size_is_positive_u32_not_wire_frame_cap() -> None:
    payload = b"\x00" + struct.pack("<I", 0x02000001) + b"x"

    uncapped = WINOS.classify_remote_desktop_payload(
        payload,
        direction="client_to_server",
    )
    assert uncapped.structure_valid is False
    assert uncapped.contract_valid is False
    assert "compressed_payload_processing_not_validated" in uncapped.validation_errors
    assert ("advertised_uncompressed_size", 0x02000001) in uncapped.metadata
    assert ("malware_size_validation", "positive_u32_only") in uncapped.metadata
    assert ("analysis_decompression_cap_bytes", "not_configured") in uncapped.metadata
    assert ("within_analysis_decompression_cap", "not_evaluated") in uncapped.metadata
    assert uncapped.decompressed is False

    capped = WINOS.classify_remote_desktop_payload(
        payload,
        direction="client_to_server",
        analysis_decompression_cap_bytes=0x02000000,
    )
    assert capped.contract_valid is False
    assert ("within_analysis_decompression_cap", False) in capped.metadata
    assert capped.expected_safe_outcome == "refused_no_wire"
    assert capped.wire_bytes is None

    zero = WINOS.classify_remote_desktop_payload(
        b"\x00" + struct.pack("<I", 0) + b"x",
        direction="client_to_server",
    )
    assert zero.length_valid is True
    assert zero.structure_valid is False
    assert "advertised_uncompressed_size_must_be_positive_u32" in zero.validation_errors

    for invalid in (0, 0x100000000, True, 1.5):
        with pytest.raises((TypeError, ValueError)):
            WINOS.classify_remote_desktop_payload(
                payload,
                direction="client_to_server",
                analysis_decompression_cap_bytes=invalid,
            )
