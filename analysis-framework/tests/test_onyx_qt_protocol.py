"""Onyx終端HTTP fingerprintをoffline fixtureだけで検証する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys

from unpackers.onyx_qt_loader import xor_swap_stream_transform


FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE = (
    FRAMEWORK
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "onyx_qt_loader"
    / "protocol.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("onyx_qt_protocol", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROTOCOL = _load()


def _request_fixture() -> bytes:
    header = bytearray(0x32)
    for offset, value in PROTOCOL._HEADER_KNOWN_BYTES.items():
        header[offset] = value
    masked = bytes(value ^ 0x3A for value in header)
    slot = (
        b"utuhv.cn".ljust(0x100, b"\0")
        + struct.pack("<H", 8080)
        + "HTTP".encode("utf-16le")
        + b"\0\0"
    )
    config = (slot * 4).ljust(0xA94, b"\0")
    encrypted = xor_swap_stream_transform(bytes((1, 2, 3, 4, 5)), config)
    return masked + struct.pack("<I", 0x40) + encrypted


def test_confirms_request_and_recovers_endpoint() -> None:
    result = PROTOCOL.classify_request_body(_request_fixture())
    assert result["matched"] is True
    assert result["confidence"] == 0.99
    assert result["endpoint"] == {
        "host": "utuhv.cn",
        "port": 8080,
        "transport": "http",
        "role": "control",
    }
    assert result["raw_config_included"] is False


def test_request_fails_closed_on_length_header_and_slot_changes() -> None:
    body = _request_fixture()
    assert PROTOCOL.classify_request_body(body[:-1])["matched"] is False
    mutated = bytearray(body)
    mutated[0] ^= 1
    assert PROTOCOL.classify_request_body(bytes(mutated))["matched"] is False
    mutated = bytearray(body)
    mutated[0x36 + 0x10C] ^= 1
    assert PROTOCOL.classify_request_body(bytes(mutated))["matched"] is False


def test_confirms_response_envelope_without_retaining_payload() -> None:
    payload = b"offline-fixture"
    body = bytearray(0x36 + len(payload))
    struct.pack_into("<I", body, 0x1E, 0x00013009)
    struct.pack_into("<I", body, 0x22, len(payload) + 4)
    struct.pack_into("<I", body, 0x2E, 0x02072024)
    struct.pack_into("<I", body, 0x32, len(payload))
    body[0x36:] = payload
    result = PROTOCOL.classify_response_body(bytes(body))
    assert result["matched"] is True
    assert result["payload_size"] == len(payload)
    assert result["payload_retained"] is False
    assert result["payload_executed"] is False
    assert result["trailing_size"] == 0
    assert result["trailing_contract"] == "exact"

    padded = PROTOCOL.classify_response_body(bytes(body) + b"\0" * 8)
    assert padded["matched"] is True
    assert padded["trailing_size"] == 8
    assert padded["trailing_contract"] == "zero_padding"

    nonzero = PROTOCOL.classify_response_body(bytes(body) + b"\0\x01")
    assert nonzero["matched"] is False
    assert nonzero["reason"] == "response_nonzero_trailing_bytes"
    excessive = PROTOCOL.classify_response_body(
        bytes(body) + b"\0" * (PROTOCOL.MAX_RESPONSE_PADDING_SIZE + 1)
    )
    assert excessive["matched"] is False
    assert excessive["reason"] == "response_padding_limit_exceeded"


def test_response_and_emulation_plan_fail_safe(monkeypatch) -> None:
    assert PROTOCOL.classify_response_body(b"short")["matched"] is False
    monkeypatch.setattr(PROTOCOL, "MAX_RESPONSE_BODY_SIZE", 4)
    oversized = PROTOCOL.classify_response_body(b"12345")
    assert oversized["matched"] is False
    assert oversized["reason"] == "response_size_limit_exceeded"
    plan = PROTOCOL.safe_emulation_plan()
    assert plan["max_inbound_requests"] == 1
    assert plan["send_valid_response"] is False
    assert plan["active_live_probe_supported"] is False
