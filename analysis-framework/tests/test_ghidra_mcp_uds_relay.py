from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import ghidra_mcp_uds_relay as target


def configuration(**overrides):
    values = {
        "uds_path": r"\tmp\ghidra-mcp-Administrator\ghidra-9924.sock",
        "listen_host": "127.0.0.1",
        "listen_port": 18089,
        "connect_timeout": 5.0,
        "idle_timeout": 185.0,
        "max_connections": 4,
        "max_request_bytes": 1024,
        "max_response_bytes": 2048,
    }
    values.update(overrides)
    return target.validate_configuration(target.build_parser().parse_args(sum(
        ([f"--{name.replace('_', '-')}", str(value)] for name, value in values.items()),
        [],
    )))


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1", "localhost", "::1"])
def test_relay_rejects_every_non_fixed_ipv4_loopback_listener(host: str) -> None:
    with pytest.raises(target.RelayConfigurationError):
        configuration(listen_host=host)


def test_relay_configuration_is_bounded_and_reports_local_url() -> None:
    value = configuration()
    assert value.listen_url == "http://127.0.0.1:18089"
    assert value.max_connections == 4
    with pytest.raises(target.RelayConfigurationError):
        configuration(max_connections=target.MAX_CONNECTIONS + 1)
    with pytest.raises(target.RelayConfigurationError):
        configuration(max_response_bytes=target.MAX_DIRECTION_BYTES + 1)


def test_copy_bounded_preserves_http_bytes_without_rewriting() -> None:
    source_reader, source_writer = socket.socketpair()
    destination_reader, destination_writer = socket.socketpair()
    payload = (
        b"POST /decompile HTTP/1.1\r\nContent-Length: 39\r\n\r\n"
        b'{"program":"/daily/sample/program.exe"}'
    )
    stop = threading.Event()
    worker = threading.Thread(
        target=target._copy_bounded,
        args=(source_reader, destination_writer),
        kwargs={"maximum_bytes": len(payload), "stop": stop},
    )
    try:
        worker.start()
        source_writer.sendall(payload)
        source_writer.shutdown(socket.SHUT_WR)
        observed = bytearray()
        while True:
            chunk = destination_reader.recv(4096)
            if not chunk:
                break
            observed.extend(chunk)
        worker.join(2.0)
        assert not worker.is_alive()
        assert bytes(observed) == payload
        assert stop.is_set() is False
    finally:
        for item in (source_reader, source_writer, destination_reader, destination_writer):
            item.close()


def test_copy_bounded_closes_connection_after_limit() -> None:
    source_reader, source_writer = socket.socketpair()
    destination_reader, destination_writer = socket.socketpair()
    stop = threading.Event()
    worker = threading.Thread(
        target=target._copy_bounded,
        args=(source_reader, destination_writer),
        kwargs={"maximum_bytes": 3, "stop": stop},
    )
    try:
        worker.start()
        source_writer.sendall(b"four")
        worker.join(2.0)
        assert not worker.is_alive()
        assert stop.is_set() is True
    finally:
        for item in (source_reader, source_writer, destination_reader, destination_writer):
            item.close()
