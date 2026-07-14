#!/usr/bin/env python3
"""Local-only MX-Go control/content server emulator with synthetic data."""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

SYNTHETIC_RECIPIENTS = ("taro@example.invalid", "hanako@example.invalid")
CONTENT = {
    "/jp01.txt": "\n".join(SYNTHETIC_RECIPIENTS) + "\n",
    "/html-a.txt": "<html><body>MX-Go lab fixture</body></html>\n",
    "/fscs-a.txt": "threads=1\ninterval=60\n",
    "/yuming.txt": "sender.example.invalid\n",
    "/dimk.txt": "selector._domainkey.sender.example.invalid\n",
}


class MXGoState:
    def __init__(self) -> None:
        self.active = False
        self.shutdown_requested = False
        self.heartbeat_count = 0
        self.last_client_id: str | None = None


class MXGoHandler(BaseHTTPRequestHandler):
    server_version = "MXGoLab/1"

    @property
    def state(self) -> MXGoState:
        return self.server.mxgo_state  # type: ignore[attr-defined]

    def _json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 65_536)
            value = json.loads(self.rfile.read(length))
            return value if isinstance(value, dict) else None
        except (ValueError, json.JSONDecodeError):
            return None

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in CONTENT:
            body = CONTENT[path].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-MXGo-Lab", "synthetic")
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/api/client_command/"):
            self._json(200, {"lab_emulator": True, "commands": {}, "pending": False})
            return
        self._json(404, {"lab_emulator": True, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        payload = self._read_json()
        if payload is None:
            self._json(400, {"lab_emulator": True, "error": "invalid_json"})
            return
        if path == "/api/v1/heartbeat_direct":
            self.state.heartbeat_count += 1
            self.state.last_client_id = str(payload.get("client_id", ""))[:128]
            host, port = self.server.server_address[:2]
            self._json(200, {
                "lab_emulator": True,
                "ok": True,
                "active": self.state.active,
                "commands": {"do_restart": False, "do_exit_mx": False, "do_show_ui": False},
                "recipients_url": f"http://{host}:{port}/jp01.txt",
            })
            return
        if path == "/api/v1/activate":
            self.state.active = True
            self._json(200, {"lab_emulator": True, "ok": True, "active": True})
            return
        if path == "/api/v1/shutdown":
            self.state.shutdown_requested = True
            self._json(200, {"lab_emulator": True, "ok": True, "shutdown_requested": True})
            return
        if path == "/api/v1/selftest_result":
            self._json(200, {"lab_emulator": True, "ok": True, "accepted": True})
            return
        self._json(404, {"lab_emulator": True, "error": "not_found"})

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def build_server(host: str = "127.0.0.1", port: int = 5000) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("MX-Go emulator may bind only to loopback")
    server = ThreadingHTTPServer((host, port), MXGoHandler)
    server.mxgo_state = MXGoState()  # type: ignore[attr-defined]
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    server = build_server(args.host, args.port)
    print(json.dumps({"listen": f"http://{args.host}:{server.server_port}", "synthetic_recipients": len(SYNTHETIC_RECIPIENTS)}))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())