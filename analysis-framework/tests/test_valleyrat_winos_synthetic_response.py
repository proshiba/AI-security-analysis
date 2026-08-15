"""Winosのloopback限定synthetic response契約を検証する。"""

from __future__ import annotations

import importlib
import socket
import struct
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WINOS_DIR = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "signed_proxy_sideload"
)
if str(WINOS_DIR) not in sys.path:
    sys.path.insert(0, str(WINOS_DIR))

PROTOCOL = importlib.import_module("winos_protocol")
EMULATOR = importlib.import_module("winos_emulator")
HEADER = struct.pack("<II", 0x12345678, 0) + b"\xCA\x00"


def _frame(command: int, payload: bytes = b"") -> bytes:
    return PROTOCOL.build_frame(bytes([command]) + payload, HEADER)


def test_heartbeat_response_is_fixed_and_reviewed() -> None:
    request = _frame(0xC9)
    decision = EMULATOR.synthetic_response_decision(request)

    assert decision.send_allowed is True
    assert decision.response_command == 0xC9
    assert decision.response_kind == "reviewed_heartbeat_status"
    assert decision.wire_schema_status == "reviewed_fixed_payload_c900"
    assert decision.operation_executed is False
    response = PROTOCOL.parse_frame(EMULATOR.response_for_frame(request))
    assert response.payload_hex == "c900"


def test_registration_response_is_fixed_and_reviewed() -> None:
    request = _frame(0x06)
    decision = EMULATOR.synthetic_response_decision(request)

    assert decision.send_allowed is True
    assert decision.response_command == 0xCA
    assert decision.response_kind == "reviewed_registration_completed"
    assert decision.wire_schema_status == "reviewed_fixed_payload_ca"
    response = PROTOCOL.parse_frame(EMULATOR.response_for_frame(request))
    assert response.payload_hex == "ca"


def test_operation_result_serializer_is_fail_closed() -> None:
    request = _frame(0x10, b"synthetic-operation")
    decision = EMULATOR.synthetic_response_decision(request)

    assert decision.send_allowed is False
    assert decision.response_command is None
    assert decision.response_kind == "operation_result_refused"
    assert decision.wire_schema_status == "operation_result_serializer_unresolved"
    assert decision.fixture_only is True
    assert decision.operation_executed is False
    assert EMULATOR.response_for_frame(request) == b""
    assert "synthetic-operation" not in repr(asdict(decision))


def test_known_nonreply_control_command_is_also_fail_closed() -> None:
    request = _frame(0x04, b"stage-channel")
    decision = EMULATOR.synthetic_response_decision(request)

    assert decision.received_role == "stage_channel_control"
    assert decision.send_allowed is False
    assert EMULATOR.response_for_frame(request) == b""


def test_loopback_ack_is_not_reported_as_operation_result() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    results: list[dict[str, object]] = []
    worker = threading.Thread(
        target=lambda: results.append(EMULATOR.serve_once(port=port, timeout=2.0)),
        daemon=True,
    )
    worker.start()
    request = _frame(0xC9)
    deadline = time.monotonic() + 2.0
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2) as client:
                client.sendall(request)
                response = client.recv(64)
            break
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)
    worker.join(timeout=2.0)

    assert PROTOCOL.parse_frame(response).payload_hex == "c900"
    assert len(results) == 1
    assert results[0]["synthetic_response_sent"] is True
    assert results[0]["fake_result_sent"] is False
    assert results[0]["operation_executed"] is False
