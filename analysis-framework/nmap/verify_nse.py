#!/usr/bin/env python3
"""loopback模擬C2へNmap NSEを接続し、protocol送受信を統合検証する。"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from typing import Callable
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
Handler = Callable[[socket.socket], None]


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    value = bytearray()
    while len(value) < size:
        chunk = stream.recv(size - len(value))
        if not chunk:
            raise ConnectionError(f"受信途中で接続が閉じました: {len(value)}/{size}")
        value.extend(chunk)
    return bytes(value)


def _recv_until(stream: socket.socket, marker: bytes, maximum: int = 16384) -> bytes:
    value = bytearray()
    while marker not in value:
        chunk = stream.recv(1024)
        if not chunk:
            raise ConnectionError("header受信途中で接続が閉じました")
        value.extend(chunk)
        if len(value) > maximum:
            raise ValueError("受信headerが上限を超えました")
    return bytes(value)


class OneShotServer:
    """localhostで1 connectionだけ処理する試験server。"""

    def __init__(self, handler: Handler) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(15)
        self.port = int(self._listener.getsockname()[1])
        self._handler = handler
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        last_scan_error: BaseException | None = None
        try:
            # Nmapの-sT port scan接続はapplication dataなしで先に切断される。
            # これを最大3回無視し、その後のNSE接続を同じlistenerで処理する。
            for _ in range(4):
                try:
                    connection, _ = self._listener.accept()
                    connection.settimeout(8)
                    with connection:
                        self._handler(connection)
                    return
                except TimeoutError as exc:
                    self.error = last_scan_error or exc
                    return
                except (
                    ConnectionResetError,
                    ConnectionAbortedError,
                    BrokenPipeError,
                    ConnectionError,
                    ssl.SSLError,
                ) as exc:
                    last_scan_error = exc
                    continue
            self.error = last_scan_error or TimeoutError("NSE接続を受信できませんでした")
        except BaseException as exc:  # 試験threadの失敗をmain threadへ転送する
            self.error = exc
        finally:
            self._listener.close()

    def finish(self) -> None:
        self.thread.join(timeout=15)
        if self.thread.is_alive():
            raise TimeoutError("模擬C2 serverが終了しませんでした")
        if self.error:
            raise RuntimeError(f"模擬C2 server失敗: {self.error}") from self.error


def _xor_winos(payload: bytes, header: bytes) -> bytes:
    return bytes(
        value ^ ((header[0 if index == 0 else (index - 1) % 10] + 0x36) & 0xFF)
        for index, value in enumerate(payload)
    )


def _winos_handler(connection: socket.socket) -> None:
    declared = struct.unpack("<I", _recv_exact(connection, 4))[0]
    request = _recv_exact(connection, declared - 4)
    if declared != 15 or len(request) != 11:
        raise ValueError("Winos request形状が不正です")
    header = struct.pack("<IIH", 0xA1B2C3D4, 0, 0xCA)
    connection.sendall(struct.pack("<I", 15) + header + _xor_winos(b"\xCA", header))


def _vvas_handler(connection: socket.socket) -> None:
    if _recv_exact(connection, 3) != bytes.fromhex("333200"):
        raise ValueError("vvaS check-inが一致しません")
    connection.sendall(struct.pack("<I", 307214) + b"\0" * 10)


def _n520_handler(context: ssl.SSLContext) -> Handler:
    def handler(connection: socket.socket) -> None:
        with context.wrap_socket(connection, server_side=True) as tls:
            session_id = 0x11223344
            mixed = (((session_id >> 16) ^ (session_id & 0xFFFF)) | 0xA5A50000) & 0xFFFFFFFF
            magic = (session_id ^ mixed) & 0xFFFFFFFF
            first = struct.pack("<II", session_id, magic) + bytes(range(32))
            tls.sendall(first + struct.pack("<I", zlib.crc32(first) & 0xFFFFFFFF))
            time.sleep(0.2)

    return handler


def _pack_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 31:
        raise ValueError("試験用MessagePack文字列が長すぎます")
    return bytes([0xA0 | len(raw)]) + raw


def _messagepack_frame(key: str, value: str) -> bytes:
    raw = b"\x82" + _pack_string(key) + _pack_string(value) + _pack_string("Message") + _pack_string("")
    compressed = struct.pack("<I", len(raw)) + gzip.compress(raw, compresslevel=9, mtime=0)
    return struct.pack("<I", len(compressed)) + compressed


def _dotnet_handler(context: ssl.SSLContext, packet_key: str, response: str) -> Handler:
    def handler(connection: socket.socket) -> None:
        with context.wrap_socket(connection, server_side=True) as tls:
            declared = struct.unpack("<I", _recv_exact(tls, 4))[0]
            request = _recv_exact(tls, declared)
            if declared > 96 or len(request) < 5:
                raise ValueError("TLS MessagePack requestが上限外です")
            raw_size = struct.unpack("<I", request[:4])[0]
            raw = gzip.decompress(request[4:])
            if len(raw) != raw_size or _pack_string(packet_key) not in raw or _pack_string("Ping") not in raw:
                raise ValueError("TLS MessagePack Pingが一致しません")
            tls.sendall(_messagepack_frame(packet_key, response))
            time.sleep(0.2)

    return handler


def _purerat_handler(context: ssl.SSLContext) -> Handler:
    def handler(connection: socket.socket) -> None:
        if _recv_exact(connection, 4) != bytes.fromhex("04000000"):
            raise ValueError("PureRAT preludeが一致しません")
        with context.wrap_socket(connection, server_side=True):
            time.sleep(0.2)

    return handler


def _read_line(connection: socket.socket) -> bytes:
    return _recv_until(connection, b"\n", maximum=1024)


def _ftp_handler(connection: socket.socket) -> None:
    connection.sendall(b"220 loopback FTP ready\r\n")
    if _read_line(connection) != b"USER sample-user\r\n":
        raise ValueError("FTP USERが一致しません")
    connection.sendall(b"331 password required\r\n")
    if _read_line(connection) != b"PASS sample-pass\r\n":
        raise ValueError("FTP PASSが一致しません")
    connection.sendall(b"230 logged in\r\n")
    if _read_line(connection) == b"QUIT\r\n":
        connection.sendall(b"221 goodbye\r\n")


def _rc4(data: bytes, key: bytes) -> bytes:
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


def _http_request(connection: socket.socket) -> tuple[dict[str, str], bytes]:
    data = _recv_until(connection, b"\r\n\r\n")
    header, initial = data.split(b"\r\n\r\n", 1)
    lines = header.decode("iso-8859-1").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name.casefold()] = value.strip()
    length = int(headers.get("content-length", "0"))
    body = initial + _recv_exact(connection, length - len(initial)) if len(initial) < length else initial[:length]
    return headers, body


def _http_response(connection: socket.socket, status: int, content_type: str, body: bytes) -> None:
    reason = {200: "OK", 201: "Created"}[status]
    header = (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    connection.sendall(header + body)


def _stealc_handler(key: bytes) -> Handler:
    def handler(connection: socket.socket) -> None:
        _, body = _http_request(connection)
        plain = _rc4(base64.b64decode(body, validate=True), key)
        request = json.loads(plain.decode("utf-8"))
        if request.get("build") != "loopback" or request.get("type") != "create":
            raise ValueError("StealC登録requestが一致しません")
        response = json.dumps({"access_token": "a" * 64}, separators=(",", ":")).encode("ascii")
        _http_response(connection, 200, "application/json", base64.b64encode(_rc4(response, key)))

    return handler


def _lumma_handler(connection: socket.socket) -> None:
    _, body = _http_request(connection)
    if b"uid=" not in body:
        raise ValueError("Lumma uid登録がありません")
    _http_response(connection, 200, "application/json", b"[]")


def _remus_handler(connection: socket.socket) -> None:
    _, body = _http_request(connection)
    if b"tag=" not in body or b"exp=" not in body:
        raise ValueError("Remus tag/exp登録がありません")
    _http_response(connection, 201, "application/octet-stream", b"R" * 41)


def _make_tls_context(directory: Path) -> tuple[ssl.SSLContext, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    der = certificate.public_bytes(serialization.Encoding.DER)
    return context, hashlib.sha256(der).hexdigest()


def _resolve_nmap(value: str | None) -> Path:
    candidates = [
        Path(value) if value else None,
        Path(r"C:\Users\Administrator\Tools\Nmap\nmap.exe"),
        Path(shutil.which("nmap") or ""),
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("Nmap executableが見つかりません。--nmapで指定してください")


def _run_nmap(nmap_exe: Path, script: str, port: int, script_args: str, expected: str) -> dict[str, object]:
    command = [
        str(nmap_exe), "-n", "-sT", "-Pn", "--host-timeout", "10s", "--script-timeout", "7s",
        "-p", str(port), "--script", str((SCRIPTS / script).resolve()),
        "--script-args", script_args, "127.0.0.1",
    ]
    completed = subprocess.run(command, capture_output=True, timeout=20, check=False)
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    if completed.returncode != 0 or expected not in output:
        raise AssertionError(
            f"Nmap検証失敗: script={script}, expected={expected}, returncode={completed.returncode}\n{output}"
        )
    return {"script": script, "port": port, "expected_status": expected, "passed": True}


def _exercise(
    nmap_exe: Path,
    handler: Handler,
    script: str,
    script_args: str,
    expected: str,
) -> dict[str, object]:
    server = OneShotServer(handler)
    try:
        result = _run_nmap(nmap_exe, script, server.port, script_args, expected)
    except BaseException as primary:
        try:
            server.finish()
        except BaseException as fixture_error:
            primary.add_note(f"fixture={script}: {fixture_error}")
        raise
    server.finish()
    return result


def verify_all(nmap_value: str | None = None) -> dict[str, object]:
    """全10 modeを外部networkなしで検証する。"""

    nmap_exe = _resolve_nmap(nmap_value)
    key = b"loopback-rc4-key"
    encoded_key = base64.b64encode(key).decode("ascii")
    records: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="nmap-c2-validation-") as temporary:
        context, certificate_sha256 = _make_tls_context(Path(temporary))
        cases = [
            (_winos_handler, "valleyrat-c2.nse", "valleyrat.mode=winos", "winos_control_response"),
            (_vvas_handler, "valleyrat-c2.nse", "valleyrat.mode=vvas", "vvas_stage_header_match"),
            (_n520_handler(context), "valleyrat-c2.nse", "valleyrat.mode=n520", "n520_server_first_handshake_match"),
            (_dotnet_handler(context, "Packet", "pong"), "dotnet-rat-c2.nse", f"dotnet-rat.family=asyncrat,dotnet-rat.expected-cert={certificate_sha256}", "messagepack_ping_response_match"),
            (_dotnet_handler(context, "Pac_ket", "Po_ng"), "dotnet-rat-c2.nse", f"dotnet-rat.family=venomrat,dotnet-rat.expected-cert={certificate_sha256}", "messagepack_ping_response_match"),
            (_purerat_handler(context), "purerat-c2.nse", f"purerat.expected-cert={certificate_sha256}", "purerat_prelude_tls_certificate_match"),
            (_ftp_handler, "agenttesla-ftp-c2.nse", "agenttesla.user=sample-user,agenttesla.pass=sample-pass", "sample_credential_ftp_login_succeeded"),
            (_stealc_handler(key), "stealer-http-c2.nse", f"stealer.family=stealc,stealer.build=loopback,stealer.key-base64='{encoded_key}'", "stealc_registration_token_match"),
            (_lumma_handler, "stealer-http-c2.nse", "stealer.family=lumma,stealer.uid=0123456789abcdef0123456789abcdef", "lumma_registration_shape_match"),
            (_remus_handler, "stealer-http-c2.nse", "stealer.family=remus,stealer.tag=0123456789abcdef0123456789abcdef,stealer.exp=1785860014", "remus_registration_envelope_match"),
        ]
        for handler, script, script_args, expected in cases:
            records.append(_exercise(nmap_exe, handler, script, script_args, expected))
    return {
        "schema_version": 1,
        "nmap_executable": str(nmap_exe),
        "external_network_used": False,
        "case_count": len(records),
        "passed_count": sum(bool(record["passed"]) for record in records),
        "cases": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Nmap C2 NSEをlocalhost模擬C2で統合検証します")
    parser.add_argument("--nmap", help="nmap executable path")
    parser.add_argument("--output", type=Path, help="結果JSONの保存先")
    args = parser.parse_args()
    report = verify_all(args.nmap)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
