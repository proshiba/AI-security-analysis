#!/usr/bin/env python3
"""AsyncRAT／VenomRATのC2側をapplication層だけloopback再現する。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import socket
import struct
from collections.abc import Callable
from typing import Any

from tls_messagepack_rat_host_emulator import (
    SessionLimits,
    TlsMessagePackHostError,
    build_synthetic_client_info,
    decode_frame,
    encode_frame,
    resolve_profile,
)

MAXIMUM_REQUEST_FRAMES = 2
MAXIMUM_RESPONSE_FRAMES = 1
TASK_TRANSMISSION_ALLOWED = False
ARBITRARY_RESULT_TRANSMISSION_ALLOWED = False


class LoopbackC2EmulatorError(ValueError):
    """loopback、frame数、またはreview済みschemaの境界違反を示す。"""


def _loopback_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise LoopbackC2EmulatorError("bindにはnumeric loopback IPだけを指定できます") from exc
    if not address.is_loopback:
        raise LoopbackC2EmulatorError("loopback外へのbindは拒否しました")
    return address


def _recv_exact(stream: socket.socket, size: int, *, maximum_calls: int = 64) -> bytes:
    output = bytearray()
    calls = 0
    while len(output) < size:
        if calls >= maximum_calls:
            raise LoopbackC2EmulatorError("review済みread-call上限を超えました")
        calls += 1
        chunk = stream.recv(size - len(output))
        if not chunk:
            raise LoopbackC2EmulatorError("frame受信途中で接続が終了しました")
        output.extend(chunk)
    return bytes(output)


def _recv_frame(stream: socket.socket, limits: SessionLimits) -> bytes:
    header = _recv_exact(stream, 4)
    declared = struct.unpack("<I", header)[0]
    if not 1 <= declared <= limits.maximum_frame_bytes:
        raise LoopbackC2EmulatorError("request frame長がreview済み上限外です")
    return header + _recv_exact(stream, declared)


def _frame_metadata(frame: bytes, limits: SessionLimits) -> dict[str, Any]:
    decoded = decode_frame(frame, limits)
    return {
        "frame_size": decoded.frame_size,
        "frame_sha256": decoded.frame_sha256,
        "decoded_size": decoded.decoded_size,
        "decoded_sha256": decoded.decoded_sha256,
        "field_count": len(decoded.values),
    }


def serve_once(
    profile_id: str,
    *,
    bind: str = "127.0.0.1",
    port: int = 0,
    timeout_seconds: float = 2.0,
    ready_callback: Callable[[int], None] | None = None,
) -> dict[str, Any]:
    """1接続、ClientInfo＋Ping、固定heartbeat responseだけを処理する。"""

    selected = resolve_profile(profile_id)
    address = _loopback_address(bind)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise LoopbackC2EmulatorError("portが範囲外です")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0.1 <= float(timeout_seconds) <= 10.0
    ):
        raise LoopbackC2EmulatorError("timeout_secondsが範囲外です")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    bind_target: tuple[Any, ...] = (
        (str(address), port, 0, 0) if family == socket.AF_INET6 else (str(address), port)
    )
    limits = SessionLimits(
        timeout_seconds=float(timeout_seconds),
        maximum_frame_bytes=64 * 1024,
        maximum_decoded_bytes=64 * 1024,
        maximum_map_entries=64,
        maximum_string_bytes=8192,
        maximum_binary_bytes=64 * 1024,
        maximum_opcode_bytes=64,
        maximum_read_calls=64,
        maximum_send_bytes=1024,
    )
    registration_exact = False
    ping_exact = False
    response = b""
    received: list[dict[str, Any]] = []
    status = "malformed_or_incomplete_request"
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(bind_target)
        server.listen(1)
        server.settimeout(float(timeout_seconds))
        selected_port = int(server.getsockname()[1])
        if ready_callback is not None:
            ready_callback(selected_port)
        client, peer = server.accept()
        with client:
            peer_address = ipaddress.ip_address(str(peer[0]))
            if not peer_address.is_loopback:
                raise LoopbackC2EmulatorError("loopback外peerを拒否しました")
            client.settimeout(float(timeout_seconds))
            try:
                registration_frame = _recv_frame(client, limits)
                registration = decode_frame(registration_frame, limits)
                received.append(_frame_metadata(registration_frame, limits))
                registration_exact = registration.values == build_synthetic_client_info(profile_id)
                if registration_exact:
                    ping_frame = _recv_frame(client, limits)
                    ping = decode_frame(ping_frame, limits)
                    received.append(_frame_metadata(ping_frame, limits))
                    ping_exact = ping.values == {
                        selected.packet_key: selected.heartbeat_request_opcode,
                        "Message": "",
                    }
                if registration_exact and ping_exact:
                    response = encode_frame(
                        {selected.packet_key: selected.heartbeat_response_opcode},
                        limits,
                    )
                    client.sendall(response)
                    status = "reviewed_heartbeat_response_sent"
                elif not registration_exact:
                    status = "client_info_mismatch_no_response"
                else:
                    status = "ping_mismatch_no_response"
            except (OSError, TlsMessagePackHostError, LoopbackC2EmulatorError):
                status = "malformed_or_incomplete_request"
    response_metadata = (
        {
            "frame_size": len(response),
            "frame_sha256": hashlib.sha256(response).hexdigest(),
            "packet": selected.heartbeat_response_opcode,
        }
        if response
        else None
    )
    return {
        "schema_version": 1,
        "profile_id": selected.profile_id,
        "family": selected.family,
        "protocol": "tls_messagepack_application_loopback",
        "bind": str(address),
        "port": selected_port,
        "status": status,
        "registration_exact": registration_exact,
        "ping_exact": ping_exact,
        "received_frame_count": len(received),
        "received_frames": received,
        "response": response_metadata,
        "safety": {
            "loopback_only": True,
            "tls_terminated": False,
            "application_layer_fixture": True,
            "raw_frame_retained": False,
            "victim_metadata_retained": False,
            "task_sent": False,
            "arbitrary_result_sent": False,
            "operation_executed": False,
            "maximum_request_frames": MAXIMUM_REQUEST_FRAMES,
            "maximum_response_frames": MAXIMUM_RESPONSE_FRAMES,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    args = parser.parse_args()
    result = serve_once(
        args.profile_id,
        bind=args.bind,
        port=args.port,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
