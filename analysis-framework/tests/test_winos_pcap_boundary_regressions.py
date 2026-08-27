"""Winos PCAPのraw requestとprofile/cipher provenance境界を検証する。"""

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
SPEC = importlib.util.spec_from_file_location("winos_pcap_boundary_regressions_target", MODULE_ROOT / "winos_pcap.py")
assert SPEC and SPEC.loader
PCAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PCAP)
import winos_protocol as PROTOCOL  # noqa: E402


SERVER = ("121.127.253.206", 8856)
CLIENT = ("10.0.0.8", 52000)
HEADER = bytes.fromhex("3800000000000000ca01")


def _row(payload: bytes, *, server_to_client: bool = False) -> str:
    source, destination = (SERVER, CLIENT) if server_to_client else (CLIENT, SERVER)
    return "|".join(
        (
            "1724500000.125",
            "9",
            "1",
            source[0],
            str(source[1]),
            destination[0],
            str(destination[1]),
            payload.hex(),
        )
    )


def test_raw_initial_request_is_event_only_under_explicit_profile_and_exact_length() -> None:
    raw = bytes.fromhex("363400")
    assert raw == PCAP.NVML_RAW_INITIAL_REQUEST
    assert raw.hex() == "363400"
    default = PCAP.analyze_rows([_row(raw)], [SERVER])
    assert default["events"] == []
    assert default["streams"][0]["unparsed_tail_length"] == 3

    result = PCAP.analyze_rows(
        [_row(raw)],
        [SERVER],
        capture_profile="nvml_raw_stage_307214",
    )
    assert result["profile_selected_explicitly"] is True
    assert result["profile_cipher_binding_enforced"] is True
    assert result["streams"][0]["raw_initial_stage_request_count"] == 1
    assert result["streams"][0]["unparsed_tail_length"] == 0
    event = result["events"][0]
    assert event["command"] is None
    assert event["payload_kind"] == "raw_initial_stage_request"
    assert event["direction"] == "client_to_server"
    assert event["lengths"] == {
        "frame": 3,
        "framing_overhead": 0,
        "raw_initial_stage_request": 3,
        "decrypted_payload": None,
        "command_body": None,
    }
    assert event["hashes"]["payload_sha256"] == hashlib.sha256(raw).hexdigest()
    assert event["profile_classification"]["role"] == ("raw_initial_stage_request_without_frame_header")
    assert event["profile_classification"]["length_valid"] is True
    assert result["safety"]["raw_initial_stage_request_published"] is False
    assert raw.hex() not in json.dumps(result)

    for invalid in (raw[:-1], b"\x05\x00\x00"):
        wrong = PCAP.analyze_rows(
            [_row(invalid)],
            [SERVER],
            capture_profile="nvml_raw_stage_307214",
        )
        assert wrong["events"] == []
        assert wrong["streams"][0]["unparsed_tail_length"] == len(invalid)


@pytest.mark.parametrize("profile", ["nvml_raw_stage_307214", "remote_desktop"])
def test_explicit_capture_profile_rejects_wrong_cipher_provenance(profile: str) -> None:
    with pytest.raises(ValueError, match="requires cipher mode rolling_header_plus_0x36"):
        PCAP.analyze_rows(
            [],
            [SERVER],
            capture_profile=profile,
            cipher_mode=PROTOCOL.CipherMode.FIXED_XOR_CC,
        )


def test_remote_bitmap_profile_uses_dynamic_exact_length_without_content() -> None:
    bitmap = bytearray(0x28)
    bitmap[0x0E:0x10] = (16).to_bytes(2, "little")
    frame = PROTOCOL.build_frame(b"\x17" + bytes(bitmap), HEADER)
    result = PCAP.analyze_rows(
        [_row(frame)],
        [SERVER],
        capture_profile="remote_desktop",
    )
    classification = result["events"][0]["profile_classification"]
    assert classification["role"] == "bitmap_format_descriptor"
    assert classification["bitmap_mode"] == 16
    assert classification["expected_total_length"] == 0x29
    assert classification["length_valid"] is True
    assert result["safety"]["remote_desktop_content_published"] is False
