"""ValleyRAT/N520 host adapterのoffline loopback契約を検証する。"""

from __future__ import annotations

import base64
import importlib.util
import socket
import sys
import threading
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE = FRAMEWORK / "malware" / "valleyrat" / "n520_host_emulator.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "valleyrat_n520_offline_loopback_contract",
        MODULE,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


N520 = _load()
HANDSHAKE = base64.b64decode(
    "VedMRkxG6ePmvrff01cXjuWZG+aqQh24G//XqST3EZ6HtDJGPpyDZkEDR1c="
)


def _server_frame(command: int, payload: bytes, *, sequence: int = 7) -> bytes:
    parsed = N520.parse_handshake(HANDSHAKE)
    return N520.build_packet(
        parsed["session_id"],
        sequence,
        command,
        payload,
        N520.derive_session_key(HANDSHAKE),
        iv=b"S" * 16,
    )


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = stream.recv(size - len(value))
        if not chunk:
            raise ConnectionError(f"loopback受信が途中で終了しました: {len(value)}/{size}")
        value.extend(chunk)
    return bytes(value)


def test_real_loopback_fragments_are_bounded_redacted_and_never_retried() -> None:
    """実loopback TCPで、1送信・無応答終了・data最小化をまとめて確認する。"""

    private_payload = b"operator-secret.dll\0MZ-private-plugin-body"
    response = _server_frame(16, private_payload)
    received: list[bytes] = []
    peer_was_loopback: list[bool] = []
    unexpected_after_registration: list[bytes] = []
    server_errors: list[BaseException] = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2.0)
        port = int(listener.getsockname()[1])

        def serve() -> None:
            try:
                connection, peer = listener.accept()
                peer_was_loopback.append(
                    socket.gethostbyname(peer[0]).startswith("127.")
                )
                with connection:
                    connection.settimeout(2.0)
                    for fragment in (HANDSHAKE[:1], HANDSHAKE[1:19], HANDSHAKE[19:]):
                        connection.sendall(fragment)
                    registration = _recv_exact(connection, 80)
                    received.append(registration)
                    for fragment in (response[:3], response[3:51], response[51:]):
                        connection.sendall(fragment)
                    unexpected_after_registration.append(connection.recv(1))
            except BaseException as exc:  # noqa: BLE001 - thread失敗をmainへ転送する
                server_errors.append(exc)

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        events: list[dict] = []
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as client:
            result = N520.run_bounded_host_session(
                client,
                policy=N520.HostPolicy(
                    timeout_seconds=1.0,
                    maximum_response_bytes=4096,
                    maximum_frames=1,
                    maximum_read_calls=8,
                    read_chunk_bytes=32,
                ),
                allow_empty_registration=True,
                registration_iv=b"R" * 16,
                transcript_callback=events.append,
            ).to_dict()
        server.join(timeout=3.0)

    assert not server.is_alive()
    assert server_errors == []
    assert peer_was_loopback == [True]
    assert len(received) == 1
    assert unexpected_after_registration == [b""]

    parsed = N520.parse_handshake(HANDSHAKE)
    frames, remainder = N520.decode_stream(
        received[0],
        parsed["session_id"],
        N520.derive_session_key(HANDSHAKE),
    )
    assert remainder == b""
    assert len(frames) == 1
    assert frames[0]["command"] == 1
    assert frames[0]["payload"] == b""

    assert result["status"] == "file_or_plugin_transfer_refused"
    assert result["safety"]["application_send_count"] == 1
    assert result["safety"]["fake_result_sent"] is False
    assert result["decisions"][0]["should_respond"] is False
    assert result["decisions"][0]["transfer_refused"] is True
    assert result["collection"]["response_size"] == len(response)
    assert private_payload.decode("ascii") not in repr(result)
    assert private_payload.decode("ascii") not in repr(events)
    assert "operator-secret.dll" not in repr(result)
    assert "MZ-private-plugin-body" not in repr(events)


class _OneByteStream:
    """read-call上限を決定的に消費する非network fixture。"""

    def __init__(self) -> None:
        self.incoming = bytearray(HANDSHAKE + b"unframed")
        self.sent: list[bytes] = []
        self.timeout_seconds: float | None = None

    def settimeout(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, _maximum_bytes: int) -> bytes:
        if not self.incoming:
            return b""
        value = bytes(self.incoming[:1])
        del self.incoming[:1]
        return value


def test_post_registration_read_call_limit_stops_without_retry() -> None:
    stream = _OneByteStream()
    result = N520.run_bounded_host_session(
        stream,
        policy=N520.HostPolicy(
            timeout_seconds=0.5,
            maximum_response_bytes=64,
            maximum_frames=1,
            maximum_read_calls=2,
            read_chunk_bytes=64,
        ),
        allow_empty_registration=True,
        registration_iv=b"R" * 16,
    ).to_dict()

    assert stream.timeout_seconds == 0.5
    assert len(stream.sent) == 1
    assert result["status"] == "incomplete_or_unframed_response"
    assert result["collection"]["response_size"] == 2
    assert result["collection"]["read_call_limit_reached"] is True
    assert result["safety"]["session_continues"] is False


@pytest.mark.parametrize(
    ("command", "classification"),
    [
        (1, "client_registration_or_heartbeat"),
        (2, "client_result_upload"),
        (3, "client_station_identity"),
        (17, "client_plugin_request_or_execution"),
    ],
)
def test_client_origin_commands_from_server_are_direction_mismatches(
    command: int,
    classification: str,
) -> None:
    decision = N520.classify_command(command, payload=b"private").to_dict()
    assert decision["classification"] == classification
    assert decision["direction"] == "unexpected_server_to_client"
    assert decision["action"] == "no_response_and_terminate"
    assert decision["should_respond"] is False
    assert decision["terminate_session"] is True
    assert "private" not in repr(decision)
