"""NVML Winos主制御dispatcherの純粋offline契約を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE_PATH = FRAMEWORK / "malware" / "valleyrat" / "winos_nvml_main_contracts.py"
SPEC = importlib.util.spec_from_file_location("winos_nvml_main_contracts_test_target", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
WINOS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WINOS
SPEC.loader.exec_module(WINOS)


def _payload(command: int, total_length: int, fill: int = 0x41) -> bytes:
    return bytes([command]) + bytes([fill]) * (total_length - 1)


def test_identity_and_complete_confirmed_command_ranges_are_pinned() -> None:
    assert WINOS.SAMPLE_SHA256 == "024ab2a62c91090e576557302c8aadd35ab77303bab4e4c7ba7964d3fccbbf2c"
    assert WINOS.DISPATCHER == "FUN_180021ca0"
    assert WINOS.CIPHER_MODE == "rolling_header_plus_0x36"
    expected = {
        *range(0x00, 0x14),
        0x59,
        0x5A,
        0x64,
        0x65,
        *range(0x66, 0x82),
        0xC9,
        0xCA,
    }
    assert {command for command, _spec in WINOS.known_command_specs()} == expected


@pytest.mark.parametrize(
    ("command", "minimum"),
    [(0x00, 0xA43), (0x05, 0x2D8)],
)
def test_dispatcher_minimum_boundaries(command: int, minimum: int) -> None:
    assert WINOS.classify_main_payload(_payload(command, minimum - 1)).contract_valid is False
    assert WINOS.classify_main_payload(_payload(command, minimum)).contract_valid is True
    assert WINOS.classify_main_payload(_payload(command, minimum + 1)).contract_valid is True


def test_tunnel_exact_length_and_config_range_are_distinct() -> None:
    for length, valid in ((0x7D1, False), (0x7D2, True), (0x7D3, False)):
        assert WINOS.classify_main_payload(_payload(0x13, length)).contract_valid is valid
    for length, valid in ((1, True), (2, True), (0x7D2, True), (0x7D3, False)):
        assert WINOS.classify_main_payload(_payload(0x12, length)).contract_valid is valid


def test_command_line_and_module_name_return_hash_only() -> None:
    for command in (0x06, 0x74):
        body = "cmd.exe".encode("utf-16-le") + b"\x00\x00"
        result = WINOS.classify_main_payload(bytes([command]) + body)
        assert result.contract_valid is True
        assert result.utf16_summary is not None
        assert result.utf16_summary.sha256 == hashlib.sha256(body).hexdigest()
        assert "cmd.exe" not in repr(result)
        assert result.raw_payload_retained is False

    for body in (b"", b"A", b"\x00\xd8", b"\x00\x00"):
        assert WINOS.classify_main_payload(b"\x06" + body).contract_valid is False


def test_group_update_requires_subcommand_and_valid_utf16_body() -> None:
    valid = WINOS.classify_main_payload(b"\x07\x00A\x00")
    assert valid.contract_valid is True
    assert ("subcommand", 0) in valid.metadata
    assert WINOS.classify_main_payload(b"\x07\x02A\x00").contract_valid is False
    assert WINOS.classify_main_payload(b"\x07\x00A").contract_valid is False
    assert WINOS.classify_main_payload(b"\x07\x00").contract_valid is False


def test_sized_capture_uses_defaults_for_short_body_and_clamps_two_int32_values() -> None:
    default = WINOS.classify_main_payload(b"\x0a")
    ignored = WINOS.classify_main_payload(b"\x0aABC")
    sized = WINOS.classify_main_payload(b"\x0a" + struct.pack("<ii", -1, 5000))
    assert default.length_rule is WINOS.LengthRule.OPTIONAL_DIMENSIONS
    assert default.contract_valid is True
    assert ("effective_width", 300) in default.metadata
    assert ("effective_height", 200) in default.metadata
    assert ("ignored_body_bytes", 3) in ignored.metadata
    assert ("requested_width", -1) in sized.metadata
    assert ("requested_height", 5000) in sized.metadata
    assert ("effective_width", 80) in sized.metadata
    assert ("effective_height", 1080) in sized.metadata
    assert sized.expected_reply_command == 0x15


def test_commands_59_and_5a_are_explicit_desktop_stream_controls() -> None:
    assert WINOS.classify_main_payload(b"\x59").contract_valid is False
    for raw, normalized in ((0, 0), (1, 1), (255, 1)):
        result = WINOS.classify_main_payload(bytes([0x59, raw]))
        assert result.role == "desktop_streaming_mode_toggle"
        assert result.contract_valid is True
        assert ("selector_raw", raw) in result.metadata
        assert ("selector_normalized", normalized) in result.metadata
    reset = WINOS.classify_main_payload(b"\x5a")
    assert reset.role == "desktop_streaming_reset"
    assert reset.contract_valid is True


def test_66_through_81_delegated_families_are_complete_and_never_called() -> None:
    results = {command: WINOS.classify_main_payload(bytes([command])) for command in range(0x66, 0x82)}
    assert all(result.known_command for result in results.values())
    assert results[0x74].contract_valid is False
    assert all(result.contract_valid for command, result in results.items() if command not in (0x74, 0x81))
    assert all(result.operation_executed is False for result in results.values())
    assert all(result.delegated_handler_called is False for result in results.values())

    for command in range(0x66, 0x6A):
        assert results[command].delegated_family == "FUN_180030360_family_0x66_0x69"
    for command in (*range(0x6B, 0x74), *range(0x76, 0x7A)):
        assert results[command].delegated_family == "FUN_18001edd0_family_0x6b_0x73_0x76_0x79"
    assert results[0x74].role == "module_unload_by_utf16_name"
    assert results[0x75].role == "module_inventory_reset"
    assert results[0x7A].delegated_family == "FUN_180045f20_family_0x7a_0x7b"
    assert results[0x7C].delegated_family == "FUN_18004d360_family_0x7c_0x7d"
    assert results[0x7E].delegated_family == "FUN_18004c480"
    assert results[0x7F].delegated_family == "FUN_18003a440"
    assert results[0x80].delegated_family == "FUN_180042f10"
    assert results[0x81].delegated_family == "FUN_180042cf0"


def test_ca00_role_differences_are_metadata_on_main_variant() -> None:
    roles = {
        0x0B: "clear_application_security_system_event_logs",
        0x0C: "self_restart",
        0x0D: "disconnect_then_self_terminate",
        0x0E: "forced_logoff",
        0x0F: "forced_reboot",
        0x10: "forced_shutdown",
        0x11: "loader_mode_toggle",
        0x12: "c2_config_replace_and_reconnect",
        0x13: "network_tunnel_or_proxy_job",
    }
    specs = dict(WINOS.known_command_specs())
    for command, role in roles.items():
        spec = specs[command]
        length = spec.exact_length or spec.minimum_length
        result = WINOS.classify_main_payload(_payload(command, length))
        assert result.role == role
        assert any(key == "ca00_role_at_same_id" for key, _value in result.metadata)


def test_registration_complete_and_known_replies_are_metadata_only() -> None:
    for command, reply, payload in (
        (0x00, 0x05, _payload(0x00, 0xA43)),
        (0x04, 0x03, b"\x04"),
        (0x09, 0x15, b"\x09"),
        (0x0A, 0x15, b"\x0a"),
        (0xCA, 0xCB, b"\xca"),
    ):
        result = WINOS.classify_main_payload(payload)
        assert result.expected_reply_command == reply
        assert result.should_respond is False
        assert result.send_allowed is False
        assert result.wire_bytes is None
    complete = WINOS.classify_main_payload(b"\xca")
    assert ("initialization_commands", "0x7A/0x7C") in complete.metadata


def test_unknown_truncation_types_and_limits_fail_closed() -> None:
    unknown = WINOS.classify_main_payload(b"\xfeunreviewed")
    assert unknown.command == 0xFE
    assert unknown.known_command is False
    assert unknown.contract_valid is False
    assert unknown.processing_state == "decoded_classified_refused"
    assert unknown.payload_sha256 == hashlib.sha256(b"\xfeunreviewed").hexdigest()
    assert unknown.wire_bytes is None

    with pytest.raises(WINOS.EmptyDecodedPayloadError):
        WINOS.classify_main_payload(b"")
    with pytest.raises(TypeError):
        WINOS.classify_main_payload(bytearray(b"\x02"))
    with pytest.raises(WINOS.PayloadLimitExceededError):
        WINOS.classify_main_payload(b"\x02A", maximum_decoded_payload_bytes=1)
    for invalid in (0, WINOS.ABSOLUTE_MAXIMUM_DECODED_PAYLOAD_BYTES + 1):
        with pytest.raises(ValueError):
            WINOS.classify_main_payload(b"\x02", maximum_decoded_payload_bytes=invalid)


def test_offline_contract_has_no_live_probe_network_os_or_serializer_dependency() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "import requests",
        "import urllib",
        "import os",
        "live_probe",
        "c2_detector",
        "reviewed_c2",
        "serialize_reply",
        "to_wire",
    ):
        assert forbidden not in source
