"""Onyx passive sinkをloopback fixtureだけで検証する。"""

from __future__ import annotations

import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_ROOT = REPOSITORY_ROOT / "analysis-framework"
for import_root in (REPOSITORY_ROOT, FRAMEWORK_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from unpackers.onyx_qt_loader import xor_swap_stream_transform  # noqa: E402

from malware.valleyrat.campaigns.onyx_qt_loader import protocol  # noqa: E402
from malware.valleyrat.campaigns.onyx_qt_loader.emulator import (  # noqa: E402
    PassiveOnyxLoopbackSink,
)


def _request_body() -> bytes:
    header = bytearray(protocol.REQUEST_HEADER_SIZE)
    for offset, value in protocol._HEADER_KNOWN_BYTES.items():
        header[offset] = value
    masked = bytes(value ^ 0x3A for value in header)
    slot = (
        b"loopback.fixture".ljust(0x100, b"\0")
        + struct.pack("<H", 8080)
        + "HTTP".encode("utf-16le")
        + b"\0\0"
    )
    config = (slot * 4).ljust(protocol.REQUEST_CONFIG_SIZE, b"\0")
    encrypted = xor_swap_stream_transform(protocol.REQUEST_CONFIG_KEY, config)
    return masked + struct.pack("<I", 0x40) + encrypted


def _exchange(body: bytes, *, declared_size: int | None = None) -> tuple[bytes, dict[str, Any]]:
    result: dict[str, Any] = {}
    sink = PassiveOnyxLoopbackSink(timeout_seconds=2.0)
    host, port = sink.open()

    def serve() -> None:
        result.update(sink.serve_once())

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    content_length = len(body) if declared_size is None else declared_size
    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        + f"Content-Length: {content_length}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )
    with socket.create_connection((host, port), timeout=2.0) as client:
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        response = client.recv(4096)
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    return response, result


def test_loopback_sink_classifies_one_request_and_never_sends_valid_response() -> None:
    response, result = _exchange(_request_body())

    assert response.startswith(b"HTTP/1.1 204 No Content\r\n")
    assert response.endswith(b"\r\n\r\n")
    assert result["requests_handled"] == 1
    assert result["classification"]["matched"] is True
    assert result["classification"]["endpoint"]["host"] == "loopback.fixture"
    assert result["request_body_retained"] is False
    assert result["response_body_size"] == 0
    assert result["valid_onyx_response_sent"] is False
    assert result["sample_executed"] is False
    assert result["external_network_contacted"] is False


def test_loopback_sink_fails_closed_on_http_shape_and_bind_target() -> None:
    response, result = _exchange(_request_body(), declared_size=1)

    assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    assert result["classification"] == {
        "matched": False,
        "reason": "content_length_mismatch",
    }
    assert result["valid_onyx_response_sent"] is False
    with pytest.raises(ValueError, match="host_must_be_numeric_loopback"):
        PassiveOnyxLoopbackSink("0.0.0.0")
    with pytest.raises(ValueError, match="host_must_be_numeric_loopback"):
        PassiveOnyxLoopbackSink("localhost")
