from __future__ import annotations

import socket
import sys
import threading
import time
from concurrent.futures import Future
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


def test_relay_connection_preserves_fast_response_after_request_half_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_relay, client_peer = socket.socketpair()
    upstream_relay, upstream_peer = socket.socketpair()
    monkeypatch.setattr(target, "connect_uds", lambda _path, _timeout: upstream_relay)
    worker = threading.Thread(
        target=target.relay_connection,
        args=(client_relay, configuration(connect_timeout=0.1, idle_timeout=2.0)),
    )
    response = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}"

    def upstream_server() -> None:
        observed = bytearray()
        while True:
            chunk = upstream_peer.recv(4096)
            if not chunk:
                break
            observed.extend(chunk)
        assert bytes(observed) == b"GET / HTTP/1.1\r\n\r\n"
        upstream_peer.sendall(response)
        upstream_peer.shutdown(socket.SHUT_WR)

    server = threading.Thread(target=upstream_server)
    try:
        worker.start()
        server.start()
        client_peer.sendall(b"GET / HTTP/1.1\r\n\r\n")
        client_peer.shutdown(socket.SHUT_WR)
        observed_response = bytearray()
        while True:
            chunk = client_peer.recv(4096)
            if not chunk:
                break
            observed_response.extend(chunk)
        worker.join(2.0)
        server.join(2.0)
        assert not worker.is_alive()
        assert not server.is_alive()
        assert bytes(observed_response) == response
    finally:
        for item in (client_relay, client_peer, upstream_relay, upstream_peer):
            item.close()


def test_relay_connection_releases_after_client_leaves_without_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_relay, client_peer = socket.socketpair()
    upstream_relay, upstream_peer = socket.socketpair()
    monkeypatch.setattr(target, "connect_uds", lambda _path, _timeout: upstream_relay)
    worker = threading.Thread(
        target=target.relay_connection,
        args=(client_relay, configuration(connect_timeout=0.1, idle_timeout=10.0)),
    )
    started = time.monotonic()
    try:
        worker.start()
        client_peer.sendall(b"GET /stalled HTTP/1.1\r\n\r\n")
        client_peer.close()
        worker.join(target.PEER_EOF_DRAIN_TIMEOUT + 2.0)
        assert not worker.is_alive()
        assert time.monotonic() - started < target.PEER_EOF_DRAIN_TIMEOUT + 1.5
    finally:
        for item in (client_relay, upstream_relay, upstream_peer):
            item.close()


def test_relay_connection_uses_one_common_idle_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_relay, client_peer = socket.socketpair()
    upstream_relay, upstream_peer = socket.socketpair()
    monkeypatch.setattr(target, "connect_uds", lambda _path, _timeout: upstream_relay)
    worker = threading.Thread(
        target=target.relay_connection,
        args=(client_relay, configuration(connect_timeout=0.1, idle_timeout=0.1)),
    )
    started = time.monotonic()
    try:
        worker.start()
        worker.join(2.0)
        elapsed = time.monotonic() - started
        assert not worker.is_alive()
        assert elapsed < 1.6
    finally:
        for item in (client_relay, client_peer, upstream_relay, upstream_peer):
            item.close()


def test_submit_failure_releases_acquired_permit_and_closes_client() -> None:
    client_relay, client_peer = socket.socketpair()
    permits = threading.BoundedSemaphore(1)
    assert permits.acquire(blocking=False)

    class FailedExecutor:
        def submit(self, *_args: object, **_kwargs: object) -> Future[None]:
            raise RuntimeError("synthetic submit failure")

    try:
        with pytest.raises(RuntimeError, match="synthetic submit failure"):
            target._submit_relay_connection(
                FailedExecutor(),
                client_relay,
                configuration(),
                permits,
                set(),
            )
        assert permits.acquire(blocking=False)
        assert client_peer.recv(1) == b""
    finally:
        client_relay.close()
        client_peer.close()


def test_completed_future_releases_acquired_permit_exactly_once() -> None:
    client_relay, client_peer = socket.socketpair()
    permits = threading.BoundedSemaphore(1)
    assert permits.acquire(blocking=False)
    future: Future[None] = Future()
    futures: set[Future[None]] = set()

    class SuccessfulExecutor:
        def submit(self, *_args: object, **_kwargs: object) -> Future[None]:
            return future

    try:
        returned = target._submit_relay_connection(
            SuccessfulExecutor(),
            client_relay,
            configuration(),
            permits,
            futures,
        )
        assert returned is future
        assert future in futures
        future.set_result(None)
        assert future not in futures
        assert permits.acquire(blocking=False)
        assert permits.acquire(blocking=False) is False
    finally:
        client_relay.close()
        client_peer.close()
