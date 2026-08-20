#!/usr/bin/env python3
"""review済み複数検体profileをloopbackだけで模擬する検出器検証facade。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import socket
import ssl
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reviewed_c2_collection import (
    BW_FAMILY,
    VVAS_FAMILY,
    ReviewedC2CollectionError,
    ReviewedSampleProfile,
    load_collection,
)
from tls_messagepack_rat_host_emulator import (
    SessionLimits,
    TlsMessagePackHostError,
    decode_frame,
    encode_frame,
)

MAXIMUM_CONNECTIONS = 1
MAXIMUM_REQUEST_FRAMES = 1
MAXIMUM_RESPONSE_FRAMES = 1
TASK_TRANSMISSION_ALLOWED = False
STAGE_TRANSMISSION_ALLOWED = False
ARBITRARY_RESULT_TRANSMISSION_ALLOWED = False


class ReviewedC2LoopbackError(ValueError):
    """loopback、TLS、frame、またはprofile境界違反を示す。"""


def _loopback_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ReviewedC2LoopbackError("bindにはnumeric loopback IPだけを指定できます") from exc
    if not address.is_loopback:
        raise ReviewedC2LoopbackError("loopback外へのbindは拒否しました")
    return address


def _limits() -> SessionLimits:
    return SessionLimits(
        timeout_seconds=3.0,
        maximum_frame_bytes=96,
        maximum_decoded_bytes=1024,
        maximum_map_entries=4,
        maximum_string_bytes=256,
        maximum_binary_bytes=1,
        maximum_opcode_bytes=64,
        maximum_read_calls=16,
        maximum_send_bytes=64,
    )


def _recv_exact(stream: socket.socket, size: int, *, maximum_calls: int = 16) -> bytes:
    output = bytearray()
    calls = 0
    while len(output) < size:
        if calls >= maximum_calls:
            raise ReviewedC2LoopbackError("read call上限を超えました")
        calls += 1
        chunk = stream.recv(size - len(output))
        if not chunk:
            raise ReviewedC2LoopbackError("request受信途中で接続が終了しました")
        output.extend(chunk)
    return bytes(output)


def _recv_messagepack_frame(stream: socket.socket) -> bytes:
    header = _recv_exact(stream, 4)
    declared = struct.unpack("<I", header)[0]
    if not 1 <= declared <= 92:
        raise ReviewedC2LoopbackError("request frame長が上限外です")
    return header + _recv_exact(stream, declared)


def _tls_context(cert: Path | None, key: Path | None) -> ssl.SSLContext:
    if cert is None or key is None:
        raise ReviewedC2LoopbackError(
            "BwRAT TLS facadeにはrepo外の--tls-certと--tls-keyが必要です"
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(certfile=cert, keyfile=key)
    except (OSError, ssl.SSLError) as exc:
        raise ReviewedC2LoopbackError("TLS certificate／private keyを読み込めません") from exc
    return context


def _handle_bwrat(stream: socket.socket, profile: ReviewedSampleProfile) -> tuple[str, int, bytes]:
    frame = _recv_messagepack_frame(stream)
    try:
        decoded = decode_frame(frame, _limits())
    except TlsMessagePackHostError:
        return "malformed_request_no_response", len(frame), b""
    request_exact = decoded.values == {"Pac_ket": "Ping", "Message": ""}
    if not request_exact:
        return "heartbeat_request_mismatch_no_response", len(frame), b""
    response = encode_frame({"Pac_ket": "Po_ng"}, _limits())
    stream.sendall(response)
    return "reviewed_heartbeat_response_sent", len(frame), response


def _handle_vvas(stream: socket.socket, profile: ReviewedSampleProfile) -> tuple[str, int, bytes]:
    request = stream.recv(4)
    if request != b"32\x00":
        return "vvas_checkin_mismatch_no_response", len(request), b""
    response = struct.pack("<I", 307214) + b"\x00" * 10
    stream.sendall(response)
    return "reviewed_vvas_header_only_sent", len(request), response


def serve_once(
    profile_pack: Path,
    profile_id: str,
    *,
    bind: str = "127.0.0.1",
    port: int = 0,
    timeout_seconds: float = 2.0,
    tls_cert: Path | None = None,
    tls_key: Path | None = None,
    application_layer_only: bool = False,
    ready_callback: Callable[[int], None] | None = None,
) -> dict[str, Any]:
    """1接続・1request・1固定responseだけを処理する。"""

    collection = load_collection(profile_pack)
    profile = collection.profiles.get(profile_id)
    if profile is None:
        raise ReviewedC2LoopbackError("未知profile_idです")
    address = _loopback_address(bind)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ReviewedC2LoopbackError("portが範囲外です")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0.1 <= float(timeout_seconds) <= 10.0
    ):
        raise ReviewedC2LoopbackError("timeout_secondsが範囲外です")
    context = None
    if profile.family == BW_FAMILY and not application_layer_only:
        context = _tls_context(tls_cert, tls_key)
    if profile.family == VVAS_FAMILY and (tls_cert is not None or tls_key is not None):
        raise ReviewedC2LoopbackError("vvaS profileへTLS keyを指定できません")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    bind_target: tuple[Any, ...] = (
        (str(address), port, 0, 0) if family == socket.AF_INET6 else (str(address), port)
    )
    status = "request_not_processed"
    request_size = 0
    response = b""
    tls_active = False
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
                raise ReviewedC2LoopbackError("loopback外peerを拒否しました")
            client.settimeout(float(timeout_seconds))
            stream: socket.socket = client
            wrapped: ssl.SSLSocket | None = None
            try:
                if context is not None:
                    wrapped = context.wrap_socket(client, server_side=True)
                    stream = wrapped
                    tls_active = True
                if profile.family == BW_FAMILY:
                    status, request_size, response = _handle_bwrat(stream, profile)
                else:
                    status, request_size, response = _handle_vvas(stream, profile)
            except (OSError, ssl.SSLError, ReviewedC2LoopbackError):
                status = "malformed_or_incomplete_request"
            finally:
                if wrapped is not None:
                    try:
                        wrapped.close()
                    except OSError:
                        pass
    return {
        "schema_version": 1,
        "collection_id": collection.collection_id,
        "profile_id": profile.profile_id,
        "profile_sha256": profile.profile_sha256,
        "sample_sha256": profile.sample_sha256,
        "terminal_sha256": profile.terminal_sha256,
        "family": profile.family,
        "bind": str(address),
        "port": selected_port,
        "status": status,
        "request_size": request_size,
        "response": (
            {
                "size": len(response),
                "sha256": hashlib.sha256(response).hexdigest(),
            }
            if response
            else None
        ),
        "safety": {
            "loopback_only": True,
            "tls_active": tls_active,
            "application_layer_only": profile.family == BW_FAMILY and application_layer_only,
            "raw_request_retained": False,
            "raw_response_retained": False,
            "victim_metadata_retained": False,
            "task_sent": False,
            "stage_sent": False,
            "arbitrary_result_sent": False,
            "operation_executed": False,
            "maximum_connections": MAXIMUM_CONNECTIONS,
            "maximum_request_frames": MAXIMUM_REQUEST_FRAMES,
            "maximum_response_frames": MAXIMUM_RESPONSE_FRAMES,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    parser.add_argument("--application-layer-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = serve_once(
            args.profiles,
            args.profile_id,
            bind=args.bind,
            port=args.port,
            timeout_seconds=args.timeout_seconds,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
            application_layer_only=args.application_layer_only,
        )
    except (OSError, ReviewedC2CollectionError, ReviewedC2LoopbackError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
