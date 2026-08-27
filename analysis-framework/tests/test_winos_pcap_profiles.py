"""Winos PCAPの明示capture profileと安全上限を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "malware" / "valleyrat" / "campaigns" / "signed_proxy_sideload"
sys.path.insert(0, str(MODULE_ROOT))
SPEC = importlib.util.spec_from_file_location("winos_pcap_profiles", MODULE_ROOT / "winos_pcap.py")
assert SPEC and SPEC.loader
PCAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PCAP)
import winos_protocol as PROTOCOL  # noqa: E402


HEADER_CA01_NVML = bytes.fromhex("3800000000000000ca01")
SERVER = ("121.127.253.206", 8856)
CLIENT = ("10.0.0.8", 52000)


def _row(
    *,
    stream: int,
    sequence: int,
    source: tuple[str, int],
    destination: tuple[str, int],
    payload: bytes,
) -> str:
    return "|".join(
        (
            "1724500000.125",
            str(stream),
            str(sequence),
            source[0],
            str(source[1]),
            destination[0],
            str(destination[1]),
            payload.hex(),
        )
    )


def _frame(payload: bytes) -> bytes:
    return PROTOCOL.build_frame(
        payload,
        HEADER_CA01_NVML,
        cipher_mode=PROTOCOL.CipherMode.ROLLING_HEADER_PLUS_0X36,
    )


def test_wire_frame_limit_and_stream_analysis_cap_are_distinct() -> None:
    assert PROTOCOL.MAX_FRAME_SIZE == 0x02000000
    assert PCAP.MAX_STREAM_BYTES == 2 * PROTOCOL.MAX_FRAME_SIZE
    assert PCAP.MIN_STREAM_BYTES == PCAP.MAX_STREAM_BYTES

    incomplete = PROTOCOL.parse_frame(PROTOCOL.MAX_FRAME_SIZE.to_bytes(4, "little") + HEADER_CA01_NVML)
    assert incomplete.declared_length == 0x02000000
    assert incomplete.complete is False

    with pytest.raises(ValueError, match="declared frame length"):
        PROTOCOL.parse_frame((PROTOCOL.MAX_FRAME_SIZE + 1).to_bytes(4, "little") + HEADER_CA01_NVML)
    with pytest.raises(ValueError, match="maximum_stream_bytes"):
        PCAP.analyze_rows([], [], maximum_stream_bytes=PCAP.MIN_STREAM_BYTES - 1)


def test_raw_stage_body_requires_explicit_server_first_frame_profile() -> None:
    body = b"R" * (PCAP.NVML_RAW_STAGE_TOTAL_LENGTH - PCAP.FRAME_OVERHEAD)
    raw_stage = PCAP.NVML_RAW_STAGE_TOTAL_LENGTH.to_bytes(4, "little") + HEADER_CA01_NVML + body
    following = _frame(b"\xc9")
    server_row = _row(
        stream=9,
        sequence=1,
        source=SERVER,
        destination=CLIENT,
        payload=raw_stage + following,
    )

    default_result = PCAP.analyze_rows([server_row], [SERVER])
    assert default_result["capture_profile"] is None
    assert default_result["events"][0]["command"] is not None
    assert default_result["events"][0]["payload_kind"] == "decrypted_command_payload"

    result = PCAP.analyze_rows(
        [server_row],
        [SERVER],
        capture_profile=PCAP.CaptureProfile.NVML_RAW_STAGE_307214,
    )
    assert result["capture_profile"] == "nvml_raw_stage_307214"
    assert result["profile_selected_explicitly"] is True
    assert result["offline_defensive_max_frame_size"] == 0x02000000
    assert result["analysis_stream_safety_cap"] == 0x04000000
    assert result["streams"][0]["raw_stage_body_frame_count"] == 1
    assert [event["command"] for event in result["events"]] == [None, 0xC9]

    stage_event = result["events"][0]
    assert stage_event["direction"] == "server_to_client"
    assert stage_event["payload_kind"] == "raw_stage_body"
    assert stage_event["lengths"]["raw_stage_body"] == len(body)
    assert stage_event["lengths"]["decrypted_payload"] is None
    assert stage_event["shape"]["command_present"] is False
    assert stage_event["shape"]["cipher_applied"] is False
    assert stage_event["hashes"]["payload_sha256"] == hashlib.sha256(body).hexdigest()
    assert stage_event["profile_classification"] == {
        "known": True,
        "role": "raw_stage_body_without_command_byte",
        "direction": "server_to_client",
        "length_valid": True,
        "decoded": False,
        "classified": True,
        "refused": True,
        "expected_safe_outcome": "refused_no_wire",
    }

    serialized = json.dumps(result)
    assert body[:64].hex() not in serialized
    assert all("peer" not in stream for stream in result["streams"])
    assert CLIENT[0] not in serialized
    assert result["safety"]["profile_auto_detected"] is False
    assert result["safety"]["raw_stage_body_published"] is False

    client_row = _row(
        stream=10,
        sequence=1,
        source=CLIENT,
        destination=SERVER,
        payload=raw_stage,
    )
    client_result = PCAP.analyze_rows(
        [client_row],
        [SERVER],
        capture_profile="nvml_raw_stage_307214",
    )
    assert client_result["events"][0]["command"] is not None
    assert client_result["events"][0]["payload_kind"] == "decrypted_command_payload"


def test_explicit_profiles_refuse_private_payload_content() -> None:
    bitmap = bytearray(0x28)
    bitmap[0x0E:0x10] = (16).to_bytes(2, "little")
    remote = _frame(b"\x17" + bytes(bitmap))
    row = _row(
        stream=12,
        sequence=1,
        source=CLIENT,
        destination=SERVER,
        payload=remote,
    )
    private = PCAP.analyze_rows_private(
        [row],
        [SERVER],
        maximum_payload_bytes=64,
        capture_profile=PCAP.CaptureProfile.REMOTE_DESKTOP,
    )
    assert private["output_scope"] == "private_profile_content_refused"
    assert private["capture_profile"] == "remote_desktop"
    assert private["safety"]["profile_payload_content_refused"] is True
    event = private["events"][0]
    assert event["payload_content_refused"] is True
    assert event["expected_safe_outcome"] == "refused_no_wire"
    assert "payload_hex_prefix" not in event


def test_remote_desktop_profile_classifies_observed_bidirectional_sequence() -> None:
    client_stream = b"".join(
        (
            _frame(b"\x17" + bytes(0x0E) + b"\x10\x00" + bytes(0x18)),
            _frame(b"\x03" + bytes(16)),
            _frame(b"\x00" + (1920 * 1080).to_bytes(4, "little") + b"z"),
            _frame(b"\x01" + (1024).to_bytes(4, "little") + b"z"),
        )
    )
    server_stream = _frame(b"\x04") + _frame(b"\x07\x1e")
    rows = [
        _row(
            stream=21,
            sequence=1,
            source=CLIENT,
            destination=SERVER,
            payload=client_stream,
        ),
        _row(
            stream=21,
            sequence=1,
            source=SERVER,
            destination=CLIENT,
            payload=server_stream,
        ),
    ]

    result = PCAP.analyze_rows(rows, [SERVER], capture_profile="remote_desktop")
    by_direction = {
        direction: [event for event in result["events"] if event["direction"] == direction]
        for direction in ("client_to_server", "server_to_client")
    }
    assert [event["command"] for event in by_direction["client_to_server"]] == [
        0x17,
        0x03,
        0x00,
        0x01,
    ]
    assert [event["command"] for event in by_direction["server_to_client"]] == [
        0x04,
        0x07,
    ]
    assert [event["profile_classification"]["role"] for event in by_direction["client_to_server"]] == [
        "bitmap_format_descriptor",
        "screen_geometry",
        "initial_full_screen_frame",
        "subsequent_or_delta_screen_frame",
    ]
    assert [event["profile_classification"]["role"] for event in by_direction["server_to_client"]] == [
        "capture_start_or_event",
        "frames_per_second",
    ]
    assert all(event["profile_classification"]["length_valid"] is True for event in result["events"])
    assert result["safety"]["remote_desktop_content_published"] is False
    serialized = json.dumps(result)
    assert "payload_hex" not in serialized
    assert "clipboard_bytes" not in serialized


def test_capture_profile_and_stream_cap_cli_are_explicit() -> None:
    parser = PCAP.build_parser()
    args = parser.parse_args(
        [
            "fixture.pcap",
            "--endpoint",
            "121.127.253.206:8856",
            "--capture-profile",
            "remote_desktop",
            "--max-stream-bytes",
            str(PCAP.MAX_STREAM_BYTES),
        ]
    )
    assert args.capture_profile == "remote_desktop"
    assert args.max_stream_bytes == PCAP.MAX_STREAM_BYTES

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "fixture.pcap",
                "--endpoint",
                "121.127.253.206:8856",
                "--capture-profile",
                "auto",
            ]
        )


def test_unknown_capture_profile_fails_closed() -> None:
    with pytest.raises(ValueError, match="unsupported capture profile"):
        PCAP.analyze_rows([], [], capture_profile="automatic")
