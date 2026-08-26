"""Winos remote desktop pluginの双方向pure classifierを検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import struct
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE_PATH = FRAMEWORK / "malware" / "valleyrat" / "winos_remote_desktop_contracts.py"
SPEC = importlib.util.spec_from_file_location("winos_remote_desktop_contracts_test_target", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
WINOS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WINOS
SPEC.loader.exec_module(WINOS)


def test_identity_codec_and_exact_wire_limits_are_pinned() -> None:
    assert WINOS.SAMPLE_SHA256 == "9ad36bf24222cc8591c72ea42beaf1b45db27699a67e359f05396b3108946353"
    assert WINOS.DISPATCHER == "FUN_1800178f0"
    assert WINOS.FRAME_BUILDER == "FUN_1800158c0"
    assert WINOS.FRAME_PARSER == "FUN_180015e50"
    assert WINOS.CIPHER_MODE == "rolling_header_plus_0x36"
    assert WINOS.WIRE_MINIMUM_TOTAL_LENGTH == 15
    assert WINOS.WIRE_MAXIMUM_TOTAL_LENGTH == 0x02000000
    assert WINOS.ABSOLUTE_MAXIMUM_DECODED_PAYLOAD_BYTES == 0x02000000 - 14


def test_direction_specific_command_sets_do_not_cross_classify() -> None:
    server = {command for command, _spec in WINOS.known_command_specs("server_to_client")}
    client = {command for command, _spec in WINOS.known_command_specs("client_to_server")}
    assert server == {*range(0x04, 0x15), 0xC9}
    assert client == {0x00, 0x01, 0x02, 0x03, 0x17, 0xC9}
    assert WINOS.classify_remote_desktop_payload(b"\x17", direction="server_to_client").known_command is False
    assert WINOS.classify_remote_desktop_payload(b"\x04", direction="client_to_server").known_command is False


def test_server_selector_flags_fps_and_quality_presets_are_metadata_only() -> None:
    assert WINOS.classify_remote_desktop_payload(b"\x07", direction="server_to_client").contract_valid is False
    zero = WINOS.classify_remote_desktop_payload(b"\x07\x00", direction="server_to_client")
    assert zero.length_valid is True
    assert zero.structure_valid is False
    assert ("division_fault_risk", True) in zero.metadata
    fps = WINOS.classify_remote_desktop_payload(b"\x07\x1e", direction="server_to_client")
    assert fps.role == "frames_per_second"
    assert fps.contract_valid is True
    assert ("fps", 30) in fps.metadata
    flag = WINOS.classify_remote_desktop_payload(b"\x08\xff", direction="server_to_client")
    assert ("flag_normalized", 1) in flag.metadata
    for command, quality in ((0x12, 60), (0x13, 85), (0x14, 100)):
        result = WINOS.classify_remote_desktop_payload(bytes([command]), direction="server_to_client")
        assert result.role == "compression_quality"
        assert ("quality", quality) in result.metadata
        assert result.operation_executed is False


def test_input_records_are_not_interpreted_or_injected() -> None:
    body = b"sensitive-input-records"
    result = WINOS.classify_remote_desktop_payload(
        b"\x0c" + body,
        direction="server_to_client",
        input_record_size=len(body),
    )
    assert result.contract_valid is True
    assert result.sensitive_content is True
    assert result.content_disclosure_allowed is False
    assert result.input_injected is False
    assert result.body_sha256 == hashlib.sha256(body).hexdigest()
    assert ("record_size_source", "explicit_runtime_context") in result.metadata
    assert ("record_alignment_validated", True) in result.metadata
    assert ("record_alignment_valid", True) in result.metadata
    assert body.hex() not in repr(result)
    command_only = WINOS.classify_remote_desktop_payload(b"\x0c", direction="server_to_client")
    assert command_only.length_valid is True
    assert command_only.structure_valid is False
    assert command_only.contract_valid is False
    assert ("malware_length_validation", "command_only_logs_and_returns") in command_only.metadata


def test_client_geometry_requires_exact_four_dwords() -> None:
    body = struct.pack("<IIII", 0, 0, 1920, 1080)
    exact = WINOS.classify_remote_desktop_payload(b"\x03" + body, direction="client_to_server")
    assert exact.contract_valid is True
    assert exact.exact_length == 17
    assert ("geometry_dword_2", 1920) in exact.metadata
    assert ("geometry_dword_3", 1080) in exact.metadata
    assert (
        WINOS.classify_remote_desktop_payload(b"\x03" + body[:-1], direction="client_to_server").contract_valid is False
    )
    assert (
        WINOS.classify_remote_desktop_payload(b"\x03" + body + b"X", direction="client_to_server").contract_valid
        is False
    )


@pytest.mark.parametrize(
    ("command", "role"), [(0x00, "initial_full_screen_frame"), (0x01, "subsequent_or_delta_screen_frame")]
)
def test_screen_frames_parse_only_u32_and_deflate_hash_without_decompression(command: int, role: str) -> None:
    compressed = b"not-expanded-zlib-bytes"
    payload = bytes([command]) + struct.pack("<I", 4096) + compressed
    result = WINOS.classify_remote_desktop_payload(payload, direction="client_to_server")
    assert result.role == role
    assert result.structure_valid is False
    assert result.contract_valid is False
    assert result.structure_status == "positive_advertised_size_and_nonempty_compressed_bytes_not_validated"
    assert "compressed_payload_processing_not_validated" in result.validation_errors
    assert result.sensitive_content is True
    assert result.decompressed is False
    assert result.image_rendered is False
    assert ("advertised_uncompressed_size", 4096) in result.metadata
    assert ("compressed_body_sha256", hashlib.sha256(compressed).hexdigest()) in result.metadata
    assert ("decompression_attempted", False) in result.metadata
    assert ("payload_processing_validated", False) in result.metadata
    assert compressed.hex() not in repr(result)

    truncated = WINOS.classify_remote_desktop_payload(bytes([command]) + b"\x00" * 4, direction="client_to_server")
    assert truncated.contract_valid is False
    zero = WINOS.classify_remote_desktop_payload(
        bytes([command]) + struct.pack("<I", 0) + b"X",
        direction="client_to_server",
    )
    assert zero.contract_valid is False


def test_clipboard_messages_are_never_disclosed_or_accessed() -> None:
    for direction, payload in (
        ("server_to_client", b"\x0dsecret"),
        ("client_to_server", b"\x02secret"),
    ):
        result = WINOS.classify_remote_desktop_payload(payload, direction=direction)
        assert result.known_command is True
        assert result.sensitive_content is True
        assert result.content_disclosure_allowed is False
        assert result.clipboard_accessed is False
        assert "secret" not in repr(result)


def test_observed_profile_sequences_are_shape_compatible() -> None:
    bitmap = bytearray(0x28)
    struct.pack_into("<H", bitmap, 0x0E, 16)
    client_payloads = [
        b"\x17" + bytes(bitmap),
        b"\x03" + b"\x00" * 16,
        b"\x00" + struct.pack("<I", 1) + b"X",
    ]
    server_payloads = [b"\x04", b"\x07\x1e"]
    client_results = [
        WINOS.classify_remote_desktop_payload(payload, direction="client_to_server") for payload in client_payloads
    ]
    assert all(result.contract_valid for result in client_results[:2])
    assert client_results[2].contract_valid is False
    assert client_results[2].structure_status == "positive_advertised_size_and_nonempty_compressed_bytes_not_validated"
    assert dict(client_results[2].metadata)["payload_processing_validated"] is False
    assert all(
        WINOS.classify_remote_desktop_payload(payload, direction="server_to_client").contract_valid
        for payload in server_payloads
    )


def test_unknown_type_direction_and_limits_fail_closed() -> None:
    unknown = WINOS.classify_remote_desktop_payload(b"\xfe", direction="server_to_client")
    assert unknown.known_command is False
    assert unknown.validation_errors == ("unknown_command_for_direction",)
    assert unknown.sensitive_content is True
    assert unknown.wire_bytes is None
    with pytest.raises(WINOS.EmptyDecodedPayloadError):
        WINOS.classify_remote_desktop_payload(b"", direction="server_to_client")
    with pytest.raises(TypeError):
        WINOS.classify_remote_desktop_payload(bytearray(b"\x04"), direction="server_to_client")
    with pytest.raises(ValueError):
        WINOS.classify_remote_desktop_payload(b"\x04", direction="unknown")
    with pytest.raises(WINOS.PayloadLimitExceededError):
        WINOS.classify_remote_desktop_payload(
            b"\x04A",
            direction="server_to_client",
            maximum_decoded_payload_bytes=1,
        )


def test_no_network_live_probe_os_zlib_or_serializer_dependency() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "import requests",
        "import urllib",
        "import os",
        "import zlib",
        "decompress(",
        "SendInput",
        "OpenClipboard",
        "live_probe",
        "c2_detector",
        "reviewed_c2",
        "serialize_reply",
        "to_wire",
    ):
        assert forbidden not in source
