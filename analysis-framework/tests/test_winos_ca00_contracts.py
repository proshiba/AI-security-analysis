"""Winos CA00 x86 dispatcherの副作用なしcommand契約分類器を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE_PATH = FRAMEWORK / "malware" / "valleyrat" / "winos_ca00_contracts.py"
SPEC = importlib.util.spec_from_file_location("winos_ca00_contracts_test_target", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
WINOS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WINOS
SPEC.loader.exec_module(WINOS)


EXPECTED_ROLES = {
    0x00: "module_descriptor_request",
    0x01: "module_transfer",
    0x02: "disconnect",
    0x03: "registration_or_screen_snapshot_request",
    0x04: "screen_capture_request",
    0x05: "file_drop_and_execute",
    0x06: "utf16_process_command_line",
    0x07: "group_or_remark_update",
    0x08: "process_name_lookup",
    0x09: "display_or_snapshot_metadata_request",
    0x0A: "sized_screen_capture",
    0x0B: "restart_security_tray_targets",
    0x0C: "clear_application_security_system_event_logs",
    0x0D: "self_restart",
    0x0E: "self_delete_cleanup",
    0x0F: "forced_logoff",
    0x10: "forced_reboot",
    0x11: "forced_shutdown",
    0x12: "loader_mode_toggle",
    0x13: "c2_config_replace_and_reconnect",
    0x14: "network_tunnel_or_proxy_job",
    0x64: "registry_special_flag",
    0x65: "registry_special_flag",
    0xC9: "heartbeat_or_registration_challenge",
    0xCA: "registration_complete",
}


def _payload(command: int, total_length: int, *, fill: int = 0x41) -> bytes:
    assert total_length >= 1
    return bytes([command]) + bytes([fill]) * (total_length - 1)


def test_contract_table_names_only_dispatcher_confirmed_commands() -> None:
    specs = dict(WINOS.known_command_specs())
    assert set(specs) == set(EXPECTED_ROLES)
    assert {command: spec.role for command, spec in specs.items()} == EXPECTED_ROLES


@pytest.mark.parametrize(
    ("command", "expected_length"),
    [(0x00, 0xA45), (0x14, 0x7D2)],
)
def test_exact_length_contract_rejects_both_boundaries(command: int, expected_length: int) -> None:
    short = WINOS.classify_ca00_payload(_payload(command, expected_length - 1))
    exact = WINOS.classify_ca00_payload(_payload(command, expected_length))
    long = WINOS.classify_ca00_payload(_payload(command, expected_length + 1))

    assert short.length_rule is WINOS.LengthRule.EXACT
    assert short.expected_length == expected_length
    assert short.length_valid is False
    assert short.contract_valid is False
    assert exact.length_valid is True
    assert exact.contract_valid is True
    assert long.length_valid is False
    assert long.contract_valid is False


@pytest.mark.parametrize(
    ("command", "minimum_length"),
    [(0x05, 0x2D8)],
)
def test_minimum_length_contract_accepts_boundary_and_larger(command: int, minimum_length: int) -> None:
    short = WINOS.classify_ca00_payload(_payload(command, minimum_length - 1))
    exact = WINOS.classify_ca00_payload(_payload(command, minimum_length))
    long = WINOS.classify_ca00_payload(_payload(command, minimum_length + 1))

    assert short.length_rule is WINOS.LengthRule.MINIMUM
    assert short.minimum_length == minimum_length
    assert short.length_valid is False
    assert short.contract_valid is False
    assert exact.length_valid is True
    assert exact.contract_valid is True
    assert long.length_valid is True
    assert long.contract_valid is True


def test_utf16_command_line_returns_only_hash_length_and_validity() -> None:
    command_line = "cmd.exe /c whoami".encode("utf-16-le") + b"\x00\x00"
    result = WINOS.classify_ca00_payload(b"\x06" + command_line)
    summary = result.utf16_summary

    assert result.role == "utf16_process_command_line"
    assert result.malicious_capability == "arbitrary_process_execution"
    assert result.contract_valid is True
    assert summary is not None
    assert summary.byte_length == len(command_line)
    assert summary.code_unit_count == len(command_line) // 2
    assert summary.sha256 == hashlib.sha256(command_line).hexdigest()
    assert summary.even_length is True
    assert summary.valid_encoding is True
    assert summary.null_terminated is True
    assert summary.has_non_null_code_unit is True
    assert summary.valid is True
    assert not hasattr(summary, "text")
    assert "cmd.exe" not in repr(result)
    assert result.body_sha256 == summary.sha256
    assert result.raw_payload_retained is False


@pytest.mark.parametrize(
    ("body", "error"),
    [
        (b"", "decoded_payload_shorter_than_minimum"),
        (b"A", "utf16_odd_byte_length"),
        (b"\x00\xd8", "utf16_invalid_encoding"),
        (b"\x00\x00", "utf16_no_non_null_code_unit"),
    ],
)
def test_utf16_command_line_truncation_and_invalid_encoding_fail_closed(body: bytes, error: str) -> None:
    result = WINOS.classify_ca00_payload(b"\x06" + body)
    assert result.contract_valid is False
    assert result.structure_valid is False
    assert error in result.validation_errors
    assert result.wire_bytes is None


@pytest.mark.parametrize("subcommand", [0, 1])
def test_group_or_remark_accepts_only_confirmed_subcommands(subcommand: int) -> None:
    result = WINOS.classify_ca00_payload(bytes([0x07, subcommand]))
    assert result.length_valid is True
    assert result.structure_valid is True
    assert result.contract_valid is True
    assert ("subcommand", subcommand) in result.metadata


def test_group_or_remark_rejects_missing_unknown_and_malformed_utf16_value() -> None:
    missing = WINOS.classify_ca00_payload(b"\x07")
    unknown = WINOS.classify_ca00_payload(b"\x07\x02")
    malformed_value = WINOS.classify_ca00_payload(b"\x07\x00A")

    assert missing.length_valid is False
    assert missing.structure_valid is False
    assert "group_or_remark_subcommand_missing" in missing.validation_errors
    assert unknown.length_valid is True
    assert unknown.structure_valid is False
    assert ("subcommand", 2) in unknown.metadata
    assert malformed_value.structure_valid is False
    assert malformed_value.utf16_summary is not None
    assert "utf16_odd_byte_length" in malformed_value.validation_errors


def test_group_or_remark_utf16_value_is_summarized_without_content() -> None:
    value = "分析端末".encode("utf-16-le")
    result = WINOS.classify_ca00_payload(b"\x07\x01" + value)
    assert result.contract_valid is True
    assert result.utf16_summary is not None
    assert result.utf16_summary.sha256 == hashlib.sha256(value).hexdigest()
    assert "分析端末" not in repr(result)


def test_sized_screen_capture_requires_two_little_endian_int32_values() -> None:
    truncated = WINOS.classify_ca00_payload(b"\x0a" + b"\x00" * 7)
    exact = WINOS.classify_ca00_payload(b"\x0a" + struct.pack("<ii", 1920, 1080))
    signed = WINOS.classify_ca00_payload(b"\x0a" + struct.pack("<ii", -1, 0) + b"extra")

    assert truncated.length_valid is False
    assert truncated.structure_valid is False
    assert "screen_dimensions_require_two_int32_le_values" in truncated.validation_errors
    assert exact.contract_valid is True
    assert exact.metadata == (("width", 1920), ("height", 1080))
    assert signed.contract_valid is True
    assert signed.metadata == (("width", -1), ("height", 0))


@pytest.mark.parametrize("challenge", [0, 1])
def test_c9_accepts_only_confirmed_challenge_values(challenge: int) -> None:
    result = WINOS.classify_ca00_payload(bytes([0xC9, challenge]))
    assert result.contract_valid is True
    assert ("challenge_value", challenge) in result.metadata


def test_c9_truncation_and_unknown_challenge_fail_closed() -> None:
    truncated = WINOS.classify_ca00_payload(b"\xc9")
    unknown = WINOS.classify_ca00_payload(b"\xc9\x02")
    assert truncated.length_valid is False
    assert truncated.structure_valid is False
    assert "challenge_second_byte_missing" in truncated.validation_errors
    assert unknown.length_valid is True
    assert unknown.structure_valid is False
    assert "challenge_second_byte_not_0_or_1" in unknown.validation_errors


@pytest.mark.parametrize(
    ("command", "reply"),
    [(0x04, 0x03), (0x09, 0x14), (0x0A, 0x14), (0xCA, 0xCB)],
)
def test_confirmed_reply_commands_are_metadata_only(command: int, reply: int) -> None:
    if command == 0x0A:
        payload = bytes([command]) + struct.pack("<ii", 1, 1)
    else:
        payload = bytes([command])
    result = WINOS.classify_ca00_payload(payload)

    assert result.expected_reply_command == reply
    assert result.reply_metadata_only is True
    assert result.should_respond is False
    assert result.send_allowed is False
    assert result.wire_bytes is None
    assert result.expected_safe_outcome == "refused_no_wire"


@pytest.mark.parametrize(
    ("command", "flag"),
    [(0x0F, 4), (0x10, 6), (0x11, 5)],
)
def test_exit_windows_ex_flags_are_passive_metadata(command: int, flag: int) -> None:
    result = WINOS.classify_ca00_payload(bytes([command]))
    assert result.contract_valid is True
    assert ("exit_windows_ex_flag", flag) in result.metadata
    assert result.operation_executed is False
    assert result.wire_bytes is None


def test_unknown_command_preserves_numeric_value_and_never_claims_valid_contract() -> None:
    raw = b"\xfeunreviewed"
    result = WINOS.classify_ca00_payload(raw)
    assert result.command == 0xFE
    assert result.known_command is False
    assert result.role == "unknown"
    assert result.malicious_capability == "unknown"
    assert result.length_rule is WINOS.LengthRule.UNKNOWN
    assert result.length_valid is None
    assert result.structure_valid is None
    assert result.contract_valid is False
    assert result.validation_errors == ("unknown_command",)
    assert result.payload_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.wire_bytes is None


@pytest.mark.parametrize("command", sorted(EXPECTED_ROLES))
def test_every_known_command_is_server_to_client_and_refused_without_wire(command: int) -> None:
    specs = dict(WINOS.known_command_specs())
    spec = specs[command]
    if command == 0x01:
        descriptor = bytearray(WINOS.MODULE_DESCRIPTOR_BYTES)
        struct.pack_into("<I", descriptor, WINOS.MODULE_SIZE_OFFSET_IN_DESCRIPTOR, 1)
        payload = b"\x01" + bytes(descriptor) + b"M"
    elif command == 0x06:
        payload = b"\x06A\x00"
    elif command == 0x07:
        payload = b"\x07\x00"
    elif command == 0x0A:
        payload = b"\x0a" + struct.pack("<ii", 1, 1)
    elif command == 0xC9:
        payload = b"\xc9\x00"
    else:
        payload = _payload(command, spec.length_value)
    result = WINOS.classify_ca00_payload(payload)

    assert result.direction is WINOS.Direction.SERVER_TO_CLIENT
    assert result.expected_safe_outcome == "refused_no_wire"
    assert result.should_respond is False
    assert result.send_allowed is False
    assert result.operation_executed is False
    assert result.raw_payload_retained is False
    assert result.wire_bytes is None


def test_empty_non_bytes_and_invalid_limits_are_rejected() -> None:
    with pytest.raises(WINOS.EmptyDecodedPayloadError, match="command byte"):
        WINOS.classify_ca00_payload(b"")
    for value in (bytearray(b"\x02"), memoryview(b"\x02"), "\x02", None):
        with pytest.raises(TypeError, match="bytes"):
            WINOS.classify_ca00_payload(value)
    for maximum in (0, WINOS.ABSOLUTE_MAXIMUM_DECODED_PAYLOAD_BYTES + 1):
        with pytest.raises(ValueError, match="maximum_decoded_payload_bytes"):
            WINOS.classify_ca00_payload(b"\x02", maximum_decoded_payload_bytes=maximum)
    for maximum in (True, 1.0, "1"):
        with pytest.raises(TypeError, match="maximum_decoded_payload_bytes"):
            WINOS.classify_ca00_payload(b"\x02", maximum_decoded_payload_bytes=maximum)


def test_caller_limit_is_enforced_before_hashing_or_classification() -> None:
    with pytest.raises(WINOS.PayloadLimitExceededError, match="上限"):
        WINOS.classify_ca00_payload(b"\x02A", maximum_decoded_payload_bytes=1)


def test_module_has_no_network_os_or_reply_serializer_imports() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "import requests",
        "import urllib",
        "import os",
        "from socket",
        "from subprocess",
        "serialize_reply",
        "to_wire",
    ):
        assert forbidden not in source
