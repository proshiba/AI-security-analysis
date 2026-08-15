"""ValleyRAT／PureRAT synthetic-result境界の横断回帰テスト。"""

from __future__ import annotations

import importlib
import json
import struct
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
FRAMEWORK = REPOSITORY / "analysis-framework"
PURE = FRAMEWORK / "malware" / "purehvnc"
WINOS = (
    FRAMEWORK
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "signed_proxy_sideload"
)
for root in (REPOSITORY, FRAMEWORK, PURE, WINOS):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

WINOS_PROTOCOL = importlib.import_module("winos_protocol")
WINOS_EMULATOR = importlib.import_module("winos_emulator")
PURE_HOST = importlib.import_module("purerat_host_emulator")
PURE_SYNTHETIC = importlib.import_module("purerat_synthetic_result")
N520 = importlib.import_module("malware.valleyrat.n520_host_emulator")
VVAS = importlib.import_module("emulators.valleyrat.vvas_loopback_emulator")
ONYX = importlib.import_module(
    "malware.valleyrat.campaigns.onyx_qt_loader.emulator"
)
ONYX_PROTOCOL = importlib.import_module(
    "malware.valleyrat.campaigns.onyx_qt_loader.protocol"
)


def _winos_frame(command: int, body: bytes = b"") -> bytes:
    header = struct.pack("<II", 0x12345678, 0) + b"\xCA\x00"
    return WINOS_PROTOCOL.build_frame(bytes([command]) + body, header)


def _pure_frame(discriminator: int, body: bytes = b"") -> bytes:
    key = (discriminator << 3) | 2
    varint = bytearray()
    while key >= 0x80:
        varint.append((key & 0x7F) | 0x80)
        key >>= 7
    varint.extend((key, len(body)))
    varint.extend(body)
    return PURE_HOST.encode_inner_frame(bytes(varint))


def test_only_reviewed_winos_ack_bytes_are_generated() -> None:
    heartbeat = WINOS_EMULATOR.synthetic_response_decision(_winos_frame(0xC9))
    registration = WINOS_EMULATOR.synthetic_response_decision(_winos_frame(0x06))
    operation = WINOS_EMULATOR.synthetic_response_decision(
        _winos_frame(0x10, b"sensitive-command")
    )

    assert heartbeat.send_allowed is True
    assert registration.send_allowed is True
    assert operation.send_allowed is False
    assert WINOS_EMULATOR.response_for_frame(_winos_frame(0x10)) == b""


def test_purerat_and_n520_fake_results_are_metadata_only() -> None:
    pure = PURE_SYNTHETIC.synthetic_result_decision(
        _pure_frame(86, b"sensitive-command")
    ).to_dict()
    n520 = N520.synthetic_result_decision(16, outcome="failure").to_dict()

    assert pure["send_allowed"] is False
    assert pure["wire_bytes"] is None
    assert pure["operation_executed"] is False
    assert n520["result_command"] == 2
    assert n520["send_allowed"] is False
    assert n520["wire_bytes"] is None
    assert n520["operation_executed"] is False
    assert "sensitive-command" not in json.dumps(pure, ensure_ascii=False)


def test_vvas_header_only_and_onyx_empty_ack_are_not_task_results() -> None:
    header = VVAS.build_synthetic_response(b"32\x00", allow_header_only=True)
    task = VVAS.synthetic_task_result_decision().to_dict()

    assert len(header) == 14
    assert len(header[14:]) == 0
    assert task["send_allowed"] is False
    assert task["wire_bytes"] is None
    assert ONYX.SAFE_NO_CONTENT_RESPONSE.endswith(b"\r\n\r\n")
    assert b"Content-Length: 0" in ONYX.SAFE_NO_CONTENT_RESPONSE
    assert ONYX_PROTOCOL.classify_response_body(b"")["matched"] is False


def test_no_family_enables_live_fake_result_transmission() -> None:
    assert N520.LIVE_FAKE_RESULT_TRANSMISSION_ALLOWED is False
    assert PURE_HOST.LIVE_FAKE_RESULT_TRANSMISSION_ALLOWED is False
    assert VVAS.TASK_RESULT_TRANSMISSION_ALLOWED is False
    assert VVAS.STAGE_BODY_TRANSMISSION_ALLOWED is False
