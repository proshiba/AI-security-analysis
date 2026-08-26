"""NVML Winos bootstrap dispatcherのoffline契約を検証する。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE_PATH = FRAMEWORK / "malware" / "valleyrat" / "winos_nvml_bootstrap_contracts.py"
SPEC = importlib.util.spec_from_file_location("winos_nvml_bootstrap_contracts_test_target", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
WINOS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WINOS
SPEC.loader.exec_module(WINOS)


def _transfer(command: int, module: bytes, *, advertised_size: int | None = None) -> bytes:
    descriptor = bytearray(WINOS.MODULE_DESCRIPTOR_BYTES)
    struct.pack_into(
        "<I",
        descriptor,
        WINOS.MODULE_SIZE_OFFSET_IN_DESCRIPTOR,
        len(module) if advertised_size is None else advertised_size,
    )
    return bytes([command]) + bytes(descriptor) + module


def test_identity_and_exact_dispatcher_command_set_are_pinned() -> None:
    assert WINOS.SAMPLE_SHA256 == "39b206588c743913ce1235c398e7bcea37393afe16b1f5dc26428a659d2add60"
    assert WINOS.DISPATCHER == "FUN_180008c40"
    assert WINOS.CIPHER_MODE == "rolling_header_plus_0x36"
    assert {command for command, _spec in WINOS.known_command_specs()} == {0x01, 0x04, 0x05, 0xC9}


def test_command_04_requires_exact_0x65_and_summarizes_utf16_name() -> None:
    body = "登录模块.dll".encode("utf-16-le") + b"\x00\x00"
    body += b"\x00" * (100 - len(body))
    exact = WINOS.classify_bootstrap_payload(b"\x04" + body)
    assert exact.decoded_payload_length == 0x65
    assert exact.length_rule is WINOS.LengthRule.EXACT
    assert exact.contract_valid is True
    assert exact.utf16_summary is not None
    assert exact.utf16_summary.byte_length == 100
    assert "登录模块" not in repr(exact)
    assert exact.expected_reply_command == 0x05
    assert exact.reply_condition == "requested_module_not_current"
    assert exact.should_respond is False
    assert exact.wire_bytes is None

    assert WINOS.classify_bootstrap_payload(b"\x04" + body[:-1]).contract_valid is False
    assert WINOS.classify_bootstrap_payload(b"\x04" + body + b"\x00").contract_valid is False


def test_command_04_invalid_utf16_fails_closed_even_at_exact_length() -> None:
    malformed = b"\x00\xd8" + b"\x00" * 98
    result = WINOS.classify_bootstrap_payload(b"\x04" + malformed)
    assert result.length_valid is True
    assert result.structure_valid is False
    assert "utf16_invalid_encoding" in result.validation_errors


@pytest.mark.parametrize("command", [0x01, 0x05])
def test_transfer_validates_descriptor_size_and_available_body(command: int) -> None:
    valid = WINOS.classify_bootstrap_payload(_transfer(command, b"MZ"))
    summary = valid.module_transfer_summary
    assert valid.contract_valid is True
    assert summary is not None
    assert summary.descriptor_length == WINOS.MODULE_DESCRIPTOR_BYTES
    assert summary.module_body_offset == 0xA43
    assert summary.advertised_module_size == 2
    assert summary.available_module_bytes == 2
    assert summary.advertised_size_positive is True
    assert summary.advertised_size_available is True
    assert valid.module_loaded is False
    assert valid.module_executed is False

    truncated = WINOS.classify_bootstrap_payload(_transfer(command, b"M", advertised_size=2))
    assert truncated.length_valid is True
    assert truncated.structure_valid is False
    assert "advertised_module_size_exceeds_available_bytes" in truncated.validation_errors


@pytest.mark.parametrize("command", [0x01, 0x05])
def test_transfer_minimum_and_embedded_size_boundaries(command: int) -> None:
    too_short = bytes([command]) + b"\x00" * (0xA44 - 2)
    assert len(too_short) == 0xA43
    result = WINOS.classify_bootstrap_payload(too_short)
    assert result.length_valid is False
    assert result.contract_valid is False

    zero = WINOS.classify_bootstrap_payload(_transfer(command, b"", advertised_size=0))
    assert zero.length_valid is False
    assert "advertised_module_size_not_positive" in zero.validation_errors

    over_limit = WINOS.classify_bootstrap_payload(
        _transfer(command, b"X", advertised_size=WINOS.MAX_EMBEDDED_MODULE_BYTES + 1)
    )
    assert over_limit.structure_valid is False
    assert "advertised_module_size_exceeds_32mib" in over_limit.validation_errors


def test_command_01_records_stricter_descriptor_branch_without_parsing_module() -> None:
    command_01 = WINOS.classify_bootstrap_payload(_transfer(0x01, b"A"))
    command_05 = WINOS.classify_bootstrap_payload(_transfer(0x05, b"A"))
    assert ("descriptor_validation_branch", True) in command_01.metadata
    assert ("descriptor_validation_branch", False) in command_05.metadata
    assert ("blocked_when_stage_active", True) in command_01.metadata
    assert command_01.operation_executed is False
    assert command_05.operation_executed is False


def test_c9_is_known_log_and_return_heartbeat() -> None:
    result = WINOS.classify_bootstrap_payload(b"\xc9")
    assert result.contract_valid is True
    assert result.role == "heartbeat_ignored_by_bootstrap_dispatcher"
    assert ("dispatcher_action", "log_and_return") in result.metadata
    assert result.expected_safe_outcome == "refused_no_wire"


def test_unknown_truncated_type_and_limits_fail_closed() -> None:
    unknown = WINOS.classify_bootstrap_payload(b"\x02")
    assert unknown.command == 2
    assert unknown.known_command is False
    assert unknown.validation_errors == ("unknown_command",)
    assert unknown.processing_state == "decoded_classified_refused"

    with pytest.raises(WINOS.EmptyDecodedPayloadError):
        WINOS.classify_bootstrap_payload(b"")
    with pytest.raises(TypeError):
        WINOS.classify_bootstrap_payload(bytearray(b"\xc9"))
    with pytest.raises(WINOS.PayloadLimitExceededError):
        WINOS.classify_bootstrap_payload(b"\xc9A", maximum_decoded_payload_bytes=1)
    for invalid in (0, WINOS.ABSOLUTE_MAXIMUM_DECODED_PAYLOAD_BYTES + 1):
        with pytest.raises(ValueError):
            WINOS.classify_bootstrap_payload(b"\xc9", maximum_decoded_payload_bytes=invalid)


def test_no_network_os_loader_or_serializer_implementation() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "import requests",
        "import urllib",
        "import os",
        "VirtualAlloc",
        "CreateThread",
        "LoadLibrary",
        "serialize_reply",
        "to_wire",
    ):
        assert forbidden not in source
