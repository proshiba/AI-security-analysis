#!/usr/bin/env python3
"""合成dataだけを返すloopback限定MX-Go control／content server。"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from emulators.common import build_loopback_http_server, load_strict_json_object
from emulators.unclassified.mx_go.protocol import (
    MAX_REQUEST_BYTES,
    require_synthetic_action,
    require_synthetic_heartbeat,
)

SYNTHETIC_RECIPIENTS = ("taro@example.invalid", "hanako@example.invalid")
CONTENT = {
    "/jp01.txt": "\n".join(SYNTHETIC_RECIPIENTS) + "\n",
    "/html-a.txt": "<html><body>MX-Go lab fixture</body></html>\n",
    "/fscs-a.txt": "threads=1\ninterval=60\n",
    "/yuming.txt": "sender.example.invalid\n",
    "/dimk.txt": "selector._domainkey.sender.example.invalid\n",
}
IO_TIMEOUT_SECONDS = 5.0


class MXGoState:
    """thread-safeな合成server状態。"""

    def __init__(self) -> None:
        self.active = False
        self.shutdown_requested = False
        self.heartbeat_count = 0
        self.last_client_id: str | None = None
        self.lock = threading.Lock()


class MXGoHandler(BaseHTTPRequestHandler):
    """固定の合成requestだけを処理するHTTP handler。"""

    server_version = "MXGoLab/1"
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        """headerとbodyのslow送信を有界時間で打ち切る。"""
        super().setup()
        self.connection.settimeout(IO_TIMEOUT_SECONDS)

    @property
    def state(self) -> MXGoState:
        return self.server.mxgo_state  # type: ignore[attr-defined]

    def _json(self, status: int, value: dict[str, Any]) -> None:
        """Connectionを閉じる有界JSON応答を返す。"""
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any] | None:
        """宣言長と実長を検証してstrict JSON objectを読む。"""
        if (
            self.headers.get("Content-Type", "").split(";", 1)[0].lower()
            != "application/json"
        ):
            self._json(
                415, {"lab_emulator": True, "error": "application_json_required"}
            )
            return None
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._json(411, {"lab_emulator": True, "error": "content_length_required"})
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self._json(400, {"lab_emulator": True, "error": "invalid_content_length"})
            return None
        if length < 0:
            self._json(400, {"lab_emulator": True, "error": "invalid_content_length"})
            return None
        if length > MAX_REQUEST_BYTES:
            self._json(413, {"lab_emulator": True, "error": "request_too_large"})
            return None
        try:
            body = self.rfile.read(length)
        except OSError:
            return None
        if len(body) != length:
            self._json(400, {"lab_emulator": True, "error": "truncated_request"})
            return None
        try:
            return load_strict_json_object(
                body, label="MX-Go request", maximum_bytes=MAX_REQUEST_BYTES
            )
        except ValueError:
            self._json(400, {"lab_emulator": True, "error": "invalid_json"})
            return None

    def do_GET(self) -> None:  # noqa: N802
        """固定contentまたは空command fixtureだけを返す。"""
        path = self.path
        if path in CONTENT:
            body = CONTENT[path].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-MXGo-Lab", "synthetic")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        command_id = path.removeprefix("/api/client_command/")
        if (
            path.startswith("/api/client_command/")
            and 1 <= len(command_id) <= 128
            and all(
                character.isalnum() or character in "-_" for character in command_id
            )
        ):
            self._json(200, {"lab_emulator": True, "commands": {}, "pending": False})
            return
        self._json(404, {"lab_emulator": True, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        """完全一致の合成heartbeatまたは状態fixtureだけを処理する。"""
        path = self.path
        payload = self._read_json()
        if payload is None:
            return
        if path == "/api/v1/heartbeat_direct":
            try:
                require_synthetic_heartbeat(payload)
            except ValueError:
                self._json(
                    403, {"lab_emulator": True, "error": "heartbeat_profile_mismatch"}
                )
                return
            with self.state.lock:
                self.state.heartbeat_count += 1
                self.state.last_client_id = str(payload["client_id"])
                active = self.state.active
            host, port = self.server.server_address[:2]
            rendered_host = f"[{host}]" if ":" in host else host
            self._json(
                200,
                {
                    "lab_emulator": True,
                    "ok": True,
                    "active": active,
                    "commands": {
                        "do_restart": False,
                        "do_exit_mx": False,
                        "do_show_ui": False,
                    },
                    "recipients_url": f"http://{rendered_host}:{port}/jp01.txt",
                },
            )
            return
        if path == "/api/v1/activate":
            try:
                require_synthetic_action(payload, "activate")
            except ValueError:
                self._json(
                    403, {"lab_emulator": True, "error": "action_profile_mismatch"}
                )
                return
            with self.state.lock:
                self.state.active = True
            self._json(200, {"lab_emulator": True, "ok": True, "active": True})
            return
        if path == "/api/v1/shutdown":
            try:
                require_synthetic_action(payload, "shutdown")
            except ValueError:
                self._json(
                    403, {"lab_emulator": True, "error": "action_profile_mismatch"}
                )
                return
            with self.state.lock:
                self.state.shutdown_requested = True
            self._json(
                200, {"lab_emulator": True, "ok": True, "shutdown_requested": True}
            )
            return
        if path == "/api/v1/selftest_result":
            try:
                require_synthetic_action(payload, "selftest_result")
            except ValueError:
                self._json(
                    403, {"lab_emulator": True, "error": "action_profile_mismatch"}
                )
                return
            self._json(200, {"lab_emulator": True, "ok": True, "accepted": True})
            return
        self._json(404, {"lab_emulator": True, "error": "not_found"})

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def build_server(host: str = "127.0.0.1", port: int = 5000) -> ThreadingHTTPServer:
    """IPv4／IPv6のliteral loopbackだけへserverをbindする。"""
    server = build_loopback_http_server(host, port, MXGoHandler, label="MX-Go emulator")
    server.mxgo_state = MXGoState()  # type: ignore[attr-defined]
    return server


def main() -> int:
    """CLIからloopback限定serverを起動する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    server = build_server(args.host, args.port)
    listen_host = server.server_address[0]
    rendered_host = f"[{listen_host}]" if ":" in listen_host else listen_host
    print(
        json.dumps(
            {
                "listen": f"http://{rendered_host}:{server.server_port}",
                "synthetic_recipients": len(SYNTHETIC_RECIPIENTS),
            }
        )
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
