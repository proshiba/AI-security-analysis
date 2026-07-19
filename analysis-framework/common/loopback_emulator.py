#!/usr/bin/env python3
"""検出器試験専用の、非互換・ループバック限定合成C2サーバー。"""

from __future__ import annotations

import argparse
import ipaddress
import socket


SYNTHETIC_PREFIX = b"AISEC-SYNTHETIC-C2/"


def validate_loopback(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        if host.lower() != "localhost":
            raise ValueError("エミュレーターはlocalhostにだけバインドできます") from exc
    else:
        if not address.is_loopback:
            raise ValueError("エミュレーターはループバックにだけバインドできます")


def serve_once(host: str, port: int, profile: str, timeout: float = 5.0) -> dict[str, object]:
    """1接続だけ受け、明示的な合成バナーを最大64バイト送る。"""
    validate_loopback(host)
    banner = (SYNTHETIC_PREFIX + profile.encode("ascii", errors="replace"))[:64]
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(timeout)
        bound_port = server.getsockname()[1]
        connection, peer = server.accept()
        with connection:
            connection.settimeout(timeout)
            connection.sendall(banner)
        return {
            "host": host,
            "port": bound_port,
            "peer_is_loopback": ipaddress.ip_address(peer[0]).is_loopback,
            "bytes_sent": len(banner),
            "malware_protocol_compatible": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="ループバック限定合成C2エミュレーター")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19081)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    print(serve_once(args.host, args.port, args.profile, args.timeout))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
