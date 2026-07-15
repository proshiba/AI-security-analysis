#!/usr/bin/env python3
"""Loopback-only synthetic HTTP lab for reviewed stealer request shapes."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import re
from urllib import request
from urllib.parse import urlsplit

PROFILES = {
    "formbook": {"method": "POST", "path": "/lab/formbook/submit"},
    "vidar": {"method": "GET", "path": "/lab/vidar/bootstrap"},
    "lummastealer": {"method": "POST", "path": "/lab/lumma/api"},
    "remusstealer": {"method": "POST", "path": "/lab/remus/submit"},
    "amosstealer": {"method": "POST", "path": "/ledger/lab-fixture"},
}


def require_loopback(host: str) -> str:
    """Reject every non-loopback emulator bind or target host."""
    if host.lower() == "localhost":
        return host
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise ValueError("stealer emulator is loopback-only")


def profile_for(family: str) -> dict:
    """Return a reviewed synthetic lab profile."""
    normalized = family.lower().replace("-", "")
    if normalized not in PROFILES:
        raise ValueError(f"unsupported family: {family}")
    return {"family": normalized, **PROFILES[normalized]}


def synthetic_body(family: str) -> bytes:
    """Build a non-sensitive lab check-in containing no host or victim identity."""
    return json.dumps(
        {
            "lab_emulator": True,
            "family": profile_for(family)["family"],
            "client_id": "LAB-FIXTURE",
            "items": [],
        },
        separators=(",", ":"),
    ).encode()


class Handler(BaseHTTPRequestHandler):
    """Accept only synthetic lab requests and return no commands."""

    server_version = "ASA-Stealer-Lab/1"

    def _reply(self, status: int, value: dict) -> None:
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        """Return an empty synthetic bootstrap response."""
        if not re.fullmatch(r"/lab/vidar/bootstrap", self.path):
            self._reply(404, {"lab_emulator": True, "error": "not_found"})
            return
        self._reply(200, {"lab_emulator": True, "bootstrap": [], "commands": []})

    def do_POST(self) -> None:  # noqa: N802
        """Accept a bounded lab-marked JSON payload and never return commands."""
        length = min(int(self.headers.get("Content-Length", "0")), 65536)
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._reply(400, {"lab_emulator": True, "error": "invalid_json"})
            return
        if not isinstance(value, dict) or value.get("lab_emulator") is not True:
            self._reply(403, {"lab_emulator": True, "error": "lab_marker_required"})
            return
        self._reply(200, {"lab_emulator": True, "accepted": True, "commands": []})

    def log_message(self, format: str, *args) -> None:
        """Suppress default request logging to avoid retaining fixture content."""


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    """Build a loopback-only threaded lab server."""
    return ThreadingHTTPServer((require_loopback(host), port), Handler)


def send(family: str, base_url: str, timeout: float = 5.0) -> dict:
    """Send one synthetic request to a loopback-only lab server."""
    parsed = urlsplit(base_url)
    require_loopback(parsed.hostname or "")
    profile = profile_for(family)
    target = base_url.rstrip("/") + profile["path"]
    body = None if profile["method"] == "GET" else synthetic_body(family)
    req = request.Request(
        target,
        data=body,
        method=profile["method"],
        headers={"Content-Type": "application/json"},
    )
    with request.urlopen(req, timeout=timeout) as response:
        value = json.loads(response.read(65536))
    return {
        "family": profile["family"],
        "status": response.status,
        "response_is_lab_emulator": value.get("lab_emulator") is True,
        "commands_returned": bool(value.get("commands")),
        "network_scope": "loopback_only",
    }


def build_parser() -> argparse.ArgumentParser:
    """Build server/client subcommand parsers."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=18080)
    client = commands.add_parser("client")
    client.add_argument("--family", required=True, choices=sorted(PROFILES))
    client.add_argument("--base-url", default="http://127.0.0.1:18080")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the loopback lab server or one synthetic client request."""
    args = build_parser().parse_args(argv)
    if args.command == "server":
        server = build_server(args.host, args.port)
        try:
            server.serve_forever()
        finally:
            server.server_close()
        return 0
    print(json.dumps(send(args.family, args.base_url), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
