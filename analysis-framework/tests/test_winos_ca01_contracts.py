"""Winos CA01 x64 command契約の副作用なし分類を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE_PATH = FRAMEWORK / "malware" / "valleyrat" / "winos_ca01_contracts.py"
SPEC = importlib.util.spec_from_file_location("winos_ca01_contracts_test_target", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
WINOS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WINOS
SPEC.loader.exec_module(WINOS)


def _payload(command: int, total_length: int, fill: int = 0x41) -> bytes:
    return bytes([command]) + bytes([fill]) * (total_length - 1)


def test_variant_identity_and_known_command_ids_are_pinned() -> None:
    assert WINOS.SAMPLE_SHA256 == "807361fe1ff663ff3716a7e667e964f9d8fd15a20766bd2796bd46b1f67e168e"
    assert WINOS.DISPATCHER == "FUN_18000f6a0"
    assert WINOS.CIPHER_MODE == "fixed_xor_cc"
    assert {item[0] for item in WINOS.known_command_specs()} == {
        *range(0x00, 0x14),
        0x64,
        0x65,
        0xC9,
        0xCA,
    }


@pytest.mark.parametrize(("command", "length"), [(0x00, 0xA45), (0x13, 0x7D2)])
def test_exact_boundaries_reject_short_and_long(command: int, length: int) -> None:
    assert WINOS.classify_ca01_payload(_payload(command, length - 1)).contract_valid is False
    exact = WINOS.classify_ca01_payload(_payload(command, length))
    assert exact.length_rule is WINOS.LengthRule.EXACT
    assert exact.exact_length == length
    assert exact.contract_valid is True
    assert WINOS.classify_ca01_payload(_payload(command, length + 1)).contract_valid is False


@pytest.mark.parametrize(("command", "length"), [(0x05, 0x2D8)])
def test_minimum_boundaries_reject_truncation(command: int, length: int) -> None:
    assert WINOS.classify_ca01_payload(_payload(command, length - 1)).contract_valid is False
    assert WINOS.classify_ca01_payload(_payload(command, length)).contract_valid is True
    assert WINOS.classify_ca01_payload(_payload(command, length + 1)).contract_valid is True


def test_c2_replacement_is_bounded_to_fixed_dispatcher_copy_capacity() -> None:
    minimum = WINOS.classify_ca01_payload(b"\x12")
    with_body = WINOS.classify_ca01_payload(b"\x12A")
    maximum = WINOS.classify_ca01_payload(_payload(0x12, 0x7D2))
    over = WINOS.classify_ca01_payload(_payload(0x12, 0x7D3))
    assert minimum.contract_valid is True
    assert with_body.contract_valid is True
    assert maximum.contract_valid is True
    assert maximum.length_rule is WINOS.LengthRule.RANGE
    assert maximum.maximum_length == 0x7D2
    assert over.length_valid is False


def test_utf16_command_is_hash_only_and_malformed_values_fail_closed() -> None:
    body = "cmd.exe /c whoami".encode("utf-16-le") + b"\x00\x00"
    result = WINOS.classify_ca01_payload(b"\x06" + body)
    assert result.contract_valid is True
    assert result.utf16_summary is not None
    assert result.utf16_summary.sha256 == hashlib.sha256(body).hexdigest()
    assert "cmd.exe" not in repr(result)
    assert not hasattr(result.utf16_summary, "text")
    for malformed in (b"", b"A", b"\x00\xd8", b"\x00\x00"):
        assert WINOS.classify_ca01_payload(b"\x06" + malformed).contract_valid is False


def test_group_update_and_dimensions_validate_minimum_structure() -> None:
    assert WINOS.classify_ca01_payload(b"\x07").contract_valid is False
    assert WINOS.classify_ca01_payload(b"\x07\x02").contract_valid is False
    group = WINOS.classify_ca01_payload(b"\x07\x01")
    assert group.contract_valid is True
    assert ("subcommand", 1) in group.metadata

    truncated = WINOS.classify_ca01_payload(b"\x0a" + b"\x00" * 7)
    dimensions = WINOS.classify_ca01_payload(b"\x0a" + struct.pack("<ii", 1920, 1080))
    assert truncated.contract_valid is False
    assert dimensions.contract_valid is True
    assert ("width", 1920) in dimensions.metadata
    assert ("height", 1080) in dimensions.metadata


def test_ca00_ca01_differences_from_0b_are_explicit() -> None:
    differences = {item.command: item for item in WINOS.ca00_ca01_differences()}
    assert differences[0x0B].ca00_role == "restart_security_tray_targets"
    assert differences[0x0B].ca01_role == "clear_application_security_system_event_logs"
    assert differences[0x0C].ca00_role == "clear_application_security_system_event_logs"
    assert differences[0x0C].ca01_role == "self_restart"
    assert differences[0x13].ca00_role == "c2_config_replace_and_reconnect"
    assert differences[0x13].ca01_role == "network_tunnel_or_proxy_job"
    assert differences[0x14].ca00_role == "network_tunnel_or_proxy_job"
    assert differences[0x14].ca01_role == "unknown"
    assert differences[0x64].ca00_role == "registry_special_flag"
    assert differences[0x64].ca01_role == "ignored_reserved"

    clear_logs = WINOS.classify_ca01_payload(b"\x0b")
    assert ("ca00_role_at_same_id", "restart_security_tray_targets") in clear_logs.metadata
    assert clear_logs.operation_executed is False


def test_ca01_has_no_command_14_and_reserved_64_65_are_not_registry_actions() -> None:
    unknown = WINOS.classify_ca01_payload(b"\x14")
    assert unknown.known_command is False
    assert unknown.command == 0x14
    assert ("ca00_role_at_same_id", "network_tunnel_or_proxy_job") in unknown.metadata
    for command in (0x64, 0x65):
        result = WINOS.classify_ca01_payload(bytes([command]))
        assert result.role == "ignored_reserved"
        assert result.malicious_capability == "none_observed"


def test_ca01_c9_treats_zero_and_any_nonzero_as_two_dispatcher_branches() -> None:
    for raw, normalized in ((0, 0), (1, 1), (2, 1), (255, 1)):
        result = WINOS.classify_ca01_payload(bytes([0xC9, raw]))
        assert result.contract_valid is True
        assert ("challenge_value_raw", raw) in result.metadata
        assert ("challenge_value_normalized", normalized) in result.metadata
    assert WINOS.classify_ca01_payload(b"\xc9").contract_valid is False


@pytest.mark.parametrize(
    ("command", "reply"),
    [(0x00, 0x05), (0x04, 0x03), (0x09, 0x14), (0x0A, 0x14), (0xCA, 0xCB)],
)
def test_reply_ids_are_metadata_only(command: int, reply: int) -> None:
    specs = dict(WINOS.known_command_specs())
    spec = specs[command]
    if command == 0x0A:
        payload = b"\x0a" + struct.pack("<ii", 1, 1)
    else:
        payload = _payload(command, spec.exact_length or spec.minimum_length)
    result = WINOS.classify_ca01_payload(payload)
    assert result.expected_reply_command == reply
    assert result.should_respond is False
    assert result.send_allowed is False
    assert result.wire_bytes is None


def test_unknown_limit_and_type_fail_closed() -> None:
    unknown = WINOS.classify_ca01_payload(b"\xfeunreviewed")
    assert unknown.command == 0xFE
    assert unknown.known_command is False
    assert unknown.contract_valid is False
    assert unknown.validation_errors == ("unknown_command",)
    assert unknown.processing_state == "decoded_classified_refused"
    assert unknown.wire_bytes is None

    with pytest.raises(WINOS.EmptyDecodedPayloadError):
        WINOS.classify_ca01_payload(b"")
    with pytest.raises(TypeError):
        WINOS.classify_ca01_payload(bytearray(b"\x02"))
    with pytest.raises(WINOS.PayloadLimitExceededError):
        WINOS.classify_ca01_payload(b"\x02A", maximum_decoded_payload_bytes=1)
    for invalid in (0, WINOS.ABSOLUTE_MAXIMUM_DECODED_PAYLOAD_BYTES + 1):
        with pytest.raises(ValueError):
            WINOS.classify_ca01_payload(b"\x02", maximum_decoded_payload_bytes=invalid)


def test_every_known_command_is_refused_without_wire_or_os_action() -> None:
    for command, spec in WINOS.known_command_specs():
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
            payload = _payload(command, spec.exact_length or spec.minimum_length)
        result = WINOS.classify_ca01_payload(payload)
        assert result.direction is WINOS.Direction.SERVER_TO_CLIENT
        assert result.expected_safe_outcome == "refused_no_wire"
        assert result.operation_executed is False
        assert result.raw_payload_retained is False
        assert result.wire_bytes is None


def test_module_has_no_network_os_or_serializer_imports() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "import requests",
        "import urllib",
        "import os",
        "serialize_reply",
        "to_wire",
    ):
        assert forbidden not in source
