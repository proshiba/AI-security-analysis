from __future__ import annotations

import base64

from n520_protocol import (
    build_packet, decode_stream, derive_session_key, extract_plugin, parse_handshake,
)


HANDSHAKE = base64.b64decode(
    "VedMRkxG6ePmvrff01cXjuWZG+aqQh24G//XqST3EZ6HtDJGPpyDZkEDR1c="
)


def test_packet_round_trip() -> None:
    parsed = parse_handshake(HANDSHAKE)
    key = derive_session_key(HANDSHAKE)
    packet = build_packet(parsed["session_id"], 7, 16, b"demo\0MZpayload", key, iv=b"I" * 16)
    frames, remaining = decode_stream(packet, parsed["session_id"], key)
    assert remaining == b""
    assert len(frames) == 1
    assert frames[0]["authenticated"] is True
    assert frames[0]["command"] == 16
    assert frames[0]["payload"] == b"demo\0MZpayload"


def test_extracts_both_plugin_formats() -> None:
    simple = extract_plugin(16, b"sample.dll\0MZone")
    assert simple and simple["operator_name"] == "sample.dll"
    assert simple["artifact"] == b"MZone"
    with_data = extract_plugin(18, b"plugin\0" + (3).to_bytes(4, "little") + b"arg" + b"MZtwo")
    assert with_data and with_data["input_size"] == 3
    assert with_data["artifact"] == b"MZtwo"


def test_rejects_tampered_frame() -> None:
    parsed = parse_handshake(HANDSHAKE)
    key = derive_session_key(HANDSHAKE)
    packet = bytearray(build_packet(parsed["session_id"], 1, 1, b"", key, iv=b"V" * 16))
    packet[20] ^= 1
    frames, _ = decode_stream(bytes(packet), parsed["session_id"], key)
    assert frames[0]["crc_matches"] is False
    assert frames[0].get("authenticated") is None
