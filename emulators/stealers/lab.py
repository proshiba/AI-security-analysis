#!/usr/bin/env python3
"""6系統のstealer C2を安全に検証するloopback限定HTTP lab。"""

from __future__ import annotations

import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error, parse, request

from emulators.common import (
    build_loopback_http_server,
    load_strict_json_object,
    require_loopback_http_base_url,
    require_timeout,
)
from emulators.common import (
    require_loopback as validate_loopback,
)

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
IO_TIMEOUT_SECONDS = 5.0
LAB_STEALC_KEY = b"loopback-stealc-key"
LAB_UUID = "00000000-0000-4000-8000-000000000000"
LAB_HEX_ID = "0" * 32
AMOS_CAMPAIGN_ID = "a" * 64

PROFILES = {
    "stealc": {
        "method": "POST",
        "path": "/lab/stealc/v2",
        "emulation_scope": "reviewed_registration_subset",
        "wire_compatibility": "registration_request_and_token_response",
    },
    "lummastealer": {
        "method": "POST",
        "path": "/lab/lumma/v6",
        "emulation_scope": "reviewed_registration_subset",
        "wire_compatibility": "registration_request_shape_only",
    },
    "remusstealer": {
        "method": "POST",
        "path": "/lab/remus/register",
        "emulation_scope": "reviewed_registration_subset",
        "wire_compatibility": "registration_request_and_opaque_envelope_shape",
    },
    "formbook": {
        "method": "POST",
        "path": "/lab/formbook/passive-sink",
        "emulation_scope": "passive_sink",
        "wire_compatibility": "none",
    },
    "vidar": {
        "method": "GET",
        "path": "/lab/vidar/profile-sink",
        "emulation_scope": "profile_matched_passive_sink",
        "wire_compatibility": "none",
    },
    "amosstealer": {
        "method": "POST",
        "path": f"/ledger/{AMOS_CAMPAIGN_ID}",
        "emulation_scope": "paired_passive_sink",
        "wire_compatibility": "route_shape_only",
    },
}


def require_loopback(host: str) -> str:
    """loopback以外のbind先または接続先を拒否する。"""

    return validate_loopback(host, "stealer emulator")


def profile_for(family: str) -> dict[str, object]:
    """family名を正規化し、安全なlab profileを返す。"""

    normalized = family.lower().replace("-", "")
    aliases = {"lumma": "lummastealer", "remus": "remusstealer", "amos": "amosstealer"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in PROFILES:
        raise ValueError(f"未対応familyです: {family}")
    return {"family": normalized, **PROFILES[normalized]}


def _rc4(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 keyが空です")
    state = list(range(256))
    right = 0
    for left in range(256):
        right = (right + state[left] + key[left % len(key)]) & 0xFF
        state[left], state[right] = state[right], state[left]
    left = right = 0
    output = bytearray()
    for value in data:
        left = (left + 1) & 0xFF
        right = (right + state[left]) & 0xFF
        state[left], state[right] = state[right], state[left]
        output.append(value ^ state[(state[left] + state[right]) & 0xFF])
    return bytes(output)


def synthetic_body(family: str) -> tuple[str, bytes | None]:
    """被害端末情報を含まないfamily別の合成request bodyを作る。"""

    profile = profile_for(family)
    family = str(profile["family"])
    if family == "stealc":
        plain = json.dumps(
            {"build": "LAB-FIXTURE", "hwid": LAB_UUID, "type": "create"},
            separators=(",", ":"),
        ).encode()
        return "application/json", base64.b64encode(_rc4(plain, LAB_STEALC_KEY))
    if family == "lummastealer":
        return "application/x-www-form-urlencoded", parse.urlencode(
            {"uid": LAB_HEX_ID, "cid": "LAB"}
        ).encode()
    if family == "remusstealer":
        return "application/x-www-form-urlencoded", parse.urlencode(
            {"tag": LAB_HEX_ID, "exp": "2000000000", "hwid": LAB_HEX_ID}
        ).encode()
    if family in {"formbook", "amosstealer"}:
        return "application/json", json.dumps(
            {"lab_emulator": True, "family": family, "items": []}, separators=(",", ":")
        ).encode()
    return "application/json", None


class Handler(BaseHTTPRequestHandler):
    """厳格な合成requestだけを受理し、taskを返さない。"""

    server_version = "ASA-Stealer-Lab/2"
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        """headerとbodyのslow送信を有界時間で打ち切る。"""
        super().setup()
        self.connection.settimeout(IO_TIMEOUT_SECONDS)

    def _send(self, status: int, content_type: str, body: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json_error(self, status: int, reason: str) -> None:
        body = json.dumps(
            {"lab_emulator": True, "error": reason}, separators=(",", ":")
        ).encode()
        self._send(status, "application/json", body)

    def _body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._json_error(411, "content_length_required")
            return None
        if length < 0:
            self._json_error(400, "invalid_content_length")
            return None
        if length > MAX_REQUEST_BYTES:
            self._json_error(413, "request_too_large")
            return None
        try:
            body = self.rfile.read(length)
        except OSError:
            return None
        if len(body) != length:
            self._json_error(400, "truncated_request")
            return None
        return body

    def _peer_is_loopback(self) -> bool:
        try:
            require_loopback(self.client_address[0])
        except ValueError:
            self._json_error(403, "loopback_peer_required")
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        """Vidarのprofile一致後に使うpassive sinkだけを提供する。"""

        if not self._peer_is_loopback():
            return
        if self.path != PROFILES["vidar"]["path"]:
            self._json_error(404, "not_found")
            return
        self._send(204, "application/octet-stream")

    def do_POST(self) -> None:  # noqa: N802
        """family別の合成登録またはpassive sink requestを処理する。"""

        if not self._peer_is_loopback():
            return
        body = self._body()
        if body is None:
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if self.path == PROFILES["stealc"]["path"]:
            self._stealc(content_type, body)
        elif self.path == PROFILES["lummastealer"]["path"]:
            self._lumma(content_type, body)
        elif self.path == PROFILES["remusstealer"]["path"]:
            self._remus(content_type, body)
        elif self.path == PROFILES["formbook"]["path"]:
            self._passive_json("formbook", content_type, body)
        elif self.path in {
            PROFILES["amosstealer"]["path"],
            f"/ledger/live/{AMOS_CAMPAIGN_ID}",
        }:
            self._passive_json("amosstealer", content_type, body)
        else:
            self._json_error(404, "not_found")

    def _stealc(self, content_type: str, body: bytes) -> None:
        try:
            plain = _rc4(base64.b64decode(body, validate=True), LAB_STEALC_KEY)
            value = load_strict_json_object(
                plain, label="StealC lab registration", maximum_bytes=MAX_REQUEST_BYTES
            )
        except (ValueError, UnicodeDecodeError):
            self._json_error(400, "invalid_stealc_registration")
            return
        if content_type != "application/json" or value != {
            "build": "LAB-FIXTURE",
            "hwid": LAB_UUID,
            "type": "create",
        }:
            self._json_error(403, "stealc_lab_profile_mismatch")
            return
        response = json.dumps(
            {"access_token": "0" * 64}, separators=(",", ":")
        ).encode()
        self._send(
            200, "application/json", base64.b64encode(_rc4(response, LAB_STEALC_KEY))
        )

    def _lumma(self, content_type: str, body: bytes) -> None:
        try:
            rendered = body.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            self._json_error(400, "invalid_lumma_registration_encoding")
            return
        try:
            values = parse.parse_qs(
                rendered, keep_blank_values=True, strict_parsing=True, max_num_fields=8
            )
        except ValueError:
            self._json_error(400, "invalid_lumma_registration_form")
            return
        expected = {"uid": [LAB_HEX_ID], "cid": ["LAB"]}
        if content_type != "application/x-www-form-urlencoded" or values != expected:
            self._json_error(403, "lumma_lab_profile_mismatch")
            return
        self._send(200, "application/json", b"[]")

    def _remus(self, content_type: str, body: bytes) -> None:
        try:
            rendered = body.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            self._json_error(400, "invalid_remus_registration_encoding")
            return
        try:
            values = parse.parse_qs(
                rendered, keep_blank_values=True, strict_parsing=True, max_num_fields=8
            )
        except ValueError:
            self._json_error(400, "invalid_remus_registration_form")
            return
        expected = {"tag": [LAB_HEX_ID], "exp": ["2000000000"], "hwid": [LAB_HEX_ID]}
        if content_type != "application/x-www-form-urlencoded" or values != expected:
            self._json_error(403, "remus_lab_profile_mismatch")
            return
        self._send(
            201,
            "application/octet-stream",
            b"LAB-OPAQUE-NON-TASK-ENVELOPE".ljust(41, b"."),
        )

    def _passive_json(self, family: str, content_type: str, body: bytes) -> None:
        try:
            value = load_strict_json_object(
                body, label=f"{family} passive sink", maximum_bytes=MAX_REQUEST_BYTES
            )
        except ValueError:
            self._json_error(400, "invalid_json")
            return
        if content_type != "application/json" or value != {
            "lab_emulator": True,
            "family": family,
            "items": [],
        }:
            self._json_error(403, "lab_marker_required")
            return
        self._send(204, "application/octet-stream")

    def log_message(self, format: str, *args: object) -> None:
        """fixture内容を保持しないよう標準request logを無効化する。"""


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    """loopbackだけへbindするthreaded lab serverを作る。"""
    return build_loopback_http_server(host, port, Handler, label="stealer emulator")


def _exchange(
    method: str, target: str, content_type: str, body: bytes | None, timeout: float
) -> tuple[int, str, bytes]:
    """redirectせず、応答をsize上限付きで1件取得する。"""
    req = request.Request(
        target,
        data=body,
        method=method,
        headers={"Content-Type": content_type, "Connection": "close"},
    )
    opener = request.build_opener(request.ProxyHandler({}), _NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as response:
            status = response.status
            response_type = (
                response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            )
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
    except error.HTTPError as exc:
        status = exc.code
        response_type = exc.headers.get("Content-Type", "").split(";", 1)[0].lower()
        response_body = exc.read(MAX_RESPONSE_BYTES + 1)
    if len(response_body) > MAX_RESPONSE_BYTES:
        raise ValueError("stealer lab responseがsize上限を超えています")
    return status, response_type, response_body


def send(family: str, base_url: str, timeout: float = 5.0) -> dict[str, object]:
    """loopback labへfamily別の合成requestだけを送る。"""
    base_url = require_loopback_http_base_url(base_url, "stealer emulator")
    timeout = require_timeout(timeout, label="stealer emulator timeout")
    profile = profile_for(family)
    content_type, body = synthetic_body(family)
    targets = [str(profile["path"])]
    if profile["family"] == "amosstealer":
        targets.append(f"/ledger/live/{AMOS_CAMPAIGN_ID}")
    statuses: list[int] = []
    content_types: list[str] = []
    responses: list[bytes] = []
    for path in targets:
        status, response_type, response_body = _exchange(
            str(profile["method"]), base_url + path, content_type, body, timeout
        )
        statuses.append(status)
        content_types.append(response_type)
        responses.append(response_body)
    token_shape = False
    if profile["family"] == "stealc" and responses:
        decoded = load_strict_json_object(
            _rc4(base64.b64decode(responses[0], validate=True), LAB_STEALC_KEY),
            label="StealC lab response",
            maximum_bytes=MAX_RESPONSE_BYTES,
        )
        token = decoded.get("access_token")
        token_shape = (
            set(decoded) == {"access_token"}
            and isinstance(token, str)
            and token == "0" * 64
        )
        response_validated = (
            statuses == [200] and content_types == ["application/json"] and token_shape
        )
    elif profile["family"] == "lummastealer":
        response_validated = (
            statuses == [200]
            and content_types == ["application/json"]
            and responses == [b"[]"]
        )
    elif profile["family"] == "remusstealer":
        expected = b"LAB-OPAQUE-NON-TASK-ENVELOPE".ljust(41, b".")
        response_validated = (
            statuses == [201]
            and content_types == ["application/octet-stream"]
            and responses == [expected]
        )
    else:
        response_validated = (
            statuses == [204] * len(targets)
            and content_types == ["application/octet-stream"] * len(targets)
            and all(not value for value in responses)
        )
    if not response_validated:
        raise ValueError("stealer lab response contractが一致しません")
    return {
        "family": profile["family"],
        "statuses": statuses,
        "request_count": len(targets),
        "accepted": True,
        "responses_validated": True,
        "response_bytes": [len(value) for value in responses],
        "registration_token_shape_matched": token_shape,
        "commands_returned": False,
        "c2_confirmed": False,
        "emulation_scope": profile["emulation_scope"],
        "wire_compatibility": profile["wire_compatibility"],
        "network_scope": "loopback_only",
        "redirect_followed": False,
        "proxy_used": False,
        "victim_metadata_sent": False,
    }


def build_parser() -> argparse.ArgumentParser:
    """server/client subcommandを定義する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server", help="loopback lab serverを起動します")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=18080)
    client = commands.add_parser("client", help="合成requestを1 sequence送信します")
    client.add_argument("--family", required=True, choices=sorted(PROFILES))
    client.add_argument("--base-url", default="http://127.0.0.1:18080")
    client.add_argument("--timeout", type=float, default=5.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    """loopback lab serverまたは合成clientを実行する。"""

    args = build_parser().parse_args(argv)
    if args.command == "server":
        server = build_server(args.host, args.port)
        try:
            server.serve_forever()
        finally:
            server.server_close()
        return 0
    print(
        json.dumps(
            send(args.family, args.base_url, timeout=args.timeout),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
