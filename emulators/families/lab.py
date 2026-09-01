#!/usr/bin/env python3
"""profile定義family向けのloopback限定合成registration lab。

Internet上のC2とwire互換ではありません。合成identityと空command応答だけで
field関係とframingを再現し、検体を実行せずparserを検証します。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import socketserver
import struct

from emulators.common import (
    load_strict_json_object,
    read_exact_bounded,
    require_port,
    require_timeout,
)
from emulators.common import (
    require_loopback as validate_loopback,
)
from extractors.profiled_family import load_profiles, normalize_family, profile_for

MAX_FRAME = 65_536


def require_loopback(host: str) -> str:
    """loopbackを返し、外部のbind先または接続先を拒否する。"""
    return validate_loopback(host, "family emulator")


def emulation_profile(family: str) -> dict:
    """1 familyの無害化済みfieldとtransport metadataを返す。"""
    profile = profile_for(family)
    fields = {
        "rat": ["lab_emulator", "family", "client_id", "capabilities"],
        "stealer": ["lab_emulator", "family", "client_id", "items"],
        "loader": ["lab_emulator", "family", "request", "stage_sha256"],
    }[profile["category"]]
    return {
        "family": profile["family"],
        "display_name": profile["display_name"],
        "category": profile["category"],
        "observed_transport": profile["transport"],
        "lab_framing": "uint32-be length plus JSON",
        "synthetic_fields": fields,
        "wire_compatible_with_malware": False,
    }


def synthetic_message(family: str) -> dict:
    """実hostや被害者identityを含まない合成lab messageを構築する。"""
    profile = emulation_profile(family)
    value = {
        "lab_emulator": True,
        "family": profile["family"],
        "client_id": "LAB-FIXTURE",
    }
    if profile["category"] == "rat":
        value["capabilities"] = []
    elif profile["category"] == "stealer":
        value["items"] = []
    else:
        value.update({"request": "metadata_only", "stage_sha256": None})
    return value


def encode_frame(value: dict) -> bytes:
    """有界の合成JSON frameを1件encodeする。"""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_FRAME:
        raise ValueError("emulator frameがsize上限を超えています")
    return struct.pack(">I", len(raw)) + raw


def decode_frame(frame: bytes) -> dict:
    """完全なlab marker付きframeをstrict decodeする。"""
    if len(frame) < 4:
        raise ValueError("emulator frame headerが途中で切れています")
    length = struct.unpack(">I", frame[:4])[0]
    if length > MAX_FRAME or len(frame) != length + 4:
        raise ValueError("emulator frameの宣言長または実長が不正です")
    value = load_strict_json_object(
        frame[4:], label="family emulator frame", maximum_bytes=MAX_FRAME
    )
    if value.get("lab_emulator") is not True:
        raise ValueError("lab markerが必要です")
    return value


def _read_frame(sock: socket.socket) -> bytes:
    """uint32-be宣言長を先に検証して1 frameだけ読む。"""
    header = read_exact_bounded(sock, 4, maximum_bytes=4, label="family frame header")
    length = struct.unpack(">I", header)[0]
    payload = read_exact_bounded(
        sock, length, maximum_bytes=MAX_FRAME, label="family frame payload"
    )
    return header + payload


def _response_for(family: str) -> dict[str, object]:
    """profile完全一致時だけ返す空command応答を構築する。"""
    return {
        "lab_emulator": True,
        "family": family,
        "accepted": True,
        "profile_matched": True,
        "commands": [],
    }


class Handler(socketserver.BaseRequestHandler):
    """完全一致するlab registrationだけへ空command listを返す。"""

    def handle(self) -> None:
        """本文を保持せず、有界の合成frameを1件だけ処理する。"""
        self.request.settimeout(5.0)
        try:
            value = decode_frame(_read_frame(self.request))
            family = normalize_family(str(value.get("family") or ""), load_profiles())
            if value != synthetic_message(family):
                return
            self.request.sendall(encode_frame(_response_for(family)))
        except (TimeoutError, OSError, ValueError):
            return


class Server(socketserver.ThreadingTCPServer):
    """再利用可能なIPv4 loopback限定threaded emulator server。"""

    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False
    request_queue_size = 8


class ServerV6(Server):
    """IPv6 loopback用のthreaded emulator server。"""

    address_family = socket.AF_INET6


def build_server(host: str, port: int) -> Server:
    """IPv4／IPv6 loopbackだけへfamily lab serverをbindする。"""
    host = require_loopback(host)
    require_port(port, allow_zero=True, label="family emulator port")
    server_type = ServerV6 if ":" in host else Server
    return server_type((host, port), Handler)


def send(family: str, host: str, port: int, timeout: float = 5.0) -> dict:
    """loopback labへ完全一致の合成messageを1件だけ送る。"""
    host = require_loopback(host)
    require_port(port, allow_zero=False, label="family emulator port")
    timeout = require_timeout(timeout, label="family emulator timeout")
    request = encode_frame(synthetic_message(family))
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        response_frame = _read_frame(sock)
        response = decode_frame(response_frame)
    normalized_family = normalize_family(family, load_profiles())
    expected_response = _response_for(normalized_family)
    if response != expected_response:
        raise ValueError("family emulator response profileが一致しません")
    return {
        "family": normalized_family,
        "response_is_lab_emulator": response.get("lab_emulator") is True,
        "accepted": response.get("accepted") is True,
        "profile_matched": response.get("profile_matched") is True,
        "response_family_matched": response.get("family") == normalized_family,
        "commands_returned": bool(response.get("commands")),
        "request_bytes": len(request),
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "response_bytes": len(response_frame),
        "response_sha256": hashlib.sha256(response_frame).hexdigest(),
        "network_scope": "loopback_only",
        "wire_compatible_with_malware": False,
    }


def build_parser() -> argparse.ArgumentParser:
    """preview、server、loopback client subcommandを定義する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preview = commands.add_parser("preview")
    preview.add_argument("--family", required=True, choices=sorted(load_profiles()))
    server = commands.add_parser("server")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=19090)
    client = commands.add_parser("client")
    client.add_argument("--family", required=True, choices=sorted(load_profiles()))
    client.add_argument("--host", default="127.0.0.1")
    client.add_argument("--port", type=int, default=19090)
    client.add_argument("--timeout", type=float, default=5.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    """合成frameのpreviewまたはloopback server／clientを実行する。"""
    args = build_parser().parse_args(argv)
    if args.command == "preview":
        print(
            json.dumps(
                {
                    "profile": emulation_profile(args.family),
                    "message": synthetic_message(args.family),
                    "network_contacted": False,
                },
                indent=2,
            )
        )
        return 0
    if args.command == "server":
        server = build_server(args.host, args.port)
        try:
            server.serve_forever()
        finally:
            server.server_close()
        return 0
    print(
        json.dumps(
            send(args.family, args.host, args.port, timeout=args.timeout), indent=2
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
