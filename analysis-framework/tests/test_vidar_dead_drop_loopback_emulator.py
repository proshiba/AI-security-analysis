"""Vidar dead-drop loopback facadeを検証する。"""

from __future__ import annotations

import importlib
import socket
import sys
import threading
from pathlib import Path

import pytest

VIDAR = Path(__file__).parents[1] / "malware" / "vidar"
if str(VIDAR) not in sys.path:
    sys.path.insert(0, str(VIDAR))

MODULE = importlib.import_module("dead_drop_loopback_emulator")


def test_facade_serves_one_synthetic_snapshot_on_loopback() -> None:
    ready = threading.Event()
    selected: list[int] = []
    result: dict = {}

    def callback(port: int) -> None:
        selected.append(port)
        ready.set()

    def server() -> None:
        result.update(
            MODULE.serve_once(
                "telegram",
                "198.51.100.42:443",
                ready_callback=callback,
            )
        )

    thread = threading.Thread(target=server)
    thread.start()
    assert ready.wait(2.0)
    with socket.create_connection(("127.0.0.1", selected[0]), timeout=2.0) as client:
        client.sendall(b"GET /profile HTTP/1.1\r\nHost: loopback.test\r\n\r\n")
        response = client.recv(4096)
    thread.join(2.0)

    assert b"198.51.100.42:443" in response
    assert result["status"] == "synthetic_snapshot_sent"
    assert result["safety"]["loopback_only"] is True
    assert result["safety"]["raw_response_retained"] is False
    assert result["safety"]["payload_sent"] is False


@pytest.mark.parametrize("bind", ("0.0.0.0", "192.0.2.1", "localhost"))
def test_non_numeric_or_non_loopback_bind_is_rejected(bind: str) -> None:
    with pytest.raises(MODULE.VidarDeadDropLoopbackError):
        MODULE.serve_once("telegram", "198.51.100.42:443", bind=bind)


@pytest.mark.parametrize("endpoint", ("8.8.8.8:443", "127.0.0.1:80", "198.51.100.42:0"))
def test_non_documentation_or_invalid_endpoint_is_rejected(endpoint: str) -> None:
    with pytest.raises(MODULE.VidarDeadDropLoopbackError):
        MODULE.build_synthetic_body("telegram", endpoint)


def test_wrong_path_gets_no_response_body() -> None:
    ready = threading.Event()
    selected: list[int] = []
    result: dict = {}

    def callback(port: int) -> None:
        selected.append(port)
        ready.set()

    def server() -> None:
        result.update(
            MODULE.serve_once("steam", "203.0.113.7:8443", ready_callback=callback)
        )

    thread = threading.Thread(target=server)
    thread.start()
    assert ready.wait(2.0)
    with socket.create_connection(("127.0.0.1", selected[0]), timeout=2.0) as client:
        client.sendall(b"GET /wrong HTTP/1.1\r\nHost: loopback.test\r\n\r\n")
        assert client.recv(4096) == b""
    thread.join(2.0)
    assert result["status"] == "request_mismatch_no_response"
    assert result["response"]["size"] == 0
