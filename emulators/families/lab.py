#!/usr/bin/env python3
"""Loopback-only synthetic registration lab for profile-defined families.

This is deliberately not a wire-compatible client for Internet C2 services.
It models field relationships and framing with synthetic identities and empty
responses so analysts can test parsers without running malware.
"""

from __future__ import annotations

import argparse
import json
import socket
import socketserver
import struct

from emulators.common import require_loopback as validate_loopback
from extractors.profiled_family import load_profiles, normalize_family, profile_for

MAX_FRAME = 65_536


def require_loopback(host: str) -> str:
    """Return a loopback host or reject every external emulator target."""
    return validate_loopback(host, "family emulator")


def emulation_profile(family: str) -> dict:
    """Return sanitized field and transport metadata for one family."""
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
    """Build a non-sensitive lab message with no real host or victim identity."""
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
    """Encode one bounded synthetic JSON frame."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_FRAME:
        raise ValueError("emulator frame exceeds limit")
    return struct.pack(">I", len(raw)) + raw


def decode_frame(frame: bytes) -> dict:
    """Decode and validate one complete lab-marked frame."""
    if len(frame) < 4:
        raise ValueError("truncated emulator frame")
    length = struct.unpack(">I", frame[:4])[0]
    if length > MAX_FRAME or len(frame) != length + 4:
        raise ValueError("invalid emulator frame length")
    value = json.loads(frame[4:])
    if not isinstance(value, dict) or value.get("lab_emulator") is not True:
        raise ValueError("lab marker required")
    return value


def _read_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ValueError("truncated emulator stream")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class Handler(socketserver.BaseRequestHandler):
    """Accept a lab-marked registration and return an empty command list."""

    def handle(self) -> None:
        """Process one bounded synthetic frame without retaining its contents."""
        header = _read_exact(self.request, 4)
        length = struct.unpack(">I", header)[0]
        if length > MAX_FRAME:
            return
        value = decode_frame(header + _read_exact(self.request, length))
        family = normalize_family(str(value.get("family") or ""), load_profiles())
        response = {"lab_emulator": True, "family": family, "accepted": True, "commands": []}
        self.request.sendall(encode_frame(response))


class Server(socketserver.ThreadingTCPServer):
    """Reusable loopback-only threaded emulator server."""

    allow_reuse_address = True


def build_server(host: str, port: int) -> Server:
    """Create a loopback-only family lab server."""
    return Server((require_loopback(host), port), Handler)


def send(family: str, host: str, port: int, timeout: float = 5.0) -> dict:
    """Send one synthetic message to a loopback-only lab server."""
    require_loopback(host)
    request = encode_frame(synthetic_message(family))
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(request)
        header = _read_exact(sock, 4)
        length = struct.unpack(">I", header)[0]
        response = decode_frame(header + _read_exact(sock, length))
    return {
        "family": normalize_family(family, load_profiles()),
        "response_is_lab_emulator": response.get("lab_emulator") is True,
        "commands_returned": bool(response.get("commands")),
        "network_scope": "loopback_only",
        "wire_compatible_with_malware": False,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build preview, server, and loopback client subcommands."""
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
    return parser


def main(argv: list[str] | None = None) -> int:
    """Preview a synthetic frame or run the loopback server/client."""
    args = build_parser().parse_args(argv)
    if args.command == "preview":
        print(json.dumps({"profile": emulation_profile(args.family), "message": synthetic_message(args.family), "network_contacted": False}, indent=2))
        return 0
    if args.command == "server":
        server = build_server(args.host, args.port)
        try:
            server.serve_forever()
        finally:
            server.server_close()
        return 0
    print(json.dumps(send(args.family, args.host, args.port), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
