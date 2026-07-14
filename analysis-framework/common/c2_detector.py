#!/usr/bin/env python3
"""Bounded C2 liveness and Internet-scanner fingerprint collection.

The probe never downloads a declared stage, follows redirects, or executes data.
Protocol confirmation is separate from TCP/HTTP/TLS reachability.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html.parser
import ipaddress
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from n520_protocol import build_packet as build_n520_packet
from n520_protocol import decode_stream as decode_n520_stream
from n520_protocol import derive_session_key as derive_n520_session_key
from n520_protocol import extract_plugin as extract_n520_plugin
from n520_protocol import parse_handshake as parse_n520_handshake


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """Implement the murmur3 32 operation for the analysis framework."""
    c1, c2, h1 = 0xCC9E2D51, 0x1B873593, seed & 0xFFFFFFFF
    rounded = len(data) & ~3
    for offset in range(0, rounded, 4):
        k1 = int.from_bytes(data[offset:offset + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k1 = 0
    for index, value in enumerate(tail):
        k1 |= value << (8 * index)
    if tail:
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= len(data)
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 if h1 < 0x80000000 else h1 - 0x100000000


class TitleParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        """Implement the   init   operation for the analysis framework."""
        super().__init__()
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, _attrs) -> None:
        """Implement the handle starttag operation for the analysis framework."""
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        """Implement the handle endtag operation for the analysis framework."""
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        """Implement the handle data operation for the analysis framework."""
        if self.in_title:
            self.parts.append(data)

    @property
    def title(self) -> str | None:
        """Implement the title operation for the analysis framework."""
        value = " ".join(" ".join(self.parts).split())
        return value[:512] or None


def parse_headers(raw: bytes) -> tuple[int | None, dict[str, str], bytes]:
    """Implement the parse headers operation for the analysis framework."""
    head, separator, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = None
    if lines:
        match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
        status = int(match.group(1)) if match else None
    headers = {}
    for line in lines[1:]:
        key, found, value = line.partition(b":")
        if found:
            headers[key.decode("latin1").strip().lower()] = value.decode("latin1").strip()
    return status, headers, body if separator else b""


def mxgo_loopback_target(host: str) -> bool:
    """Restrict active MX-Go protocol emulation to the local lab."""
    return host.lower() in {"localhost", "127.0.0.1", "::1"}


def build_mxgo_heartbeat(client_id: str = "LAB-MXGO-000000000000") -> dict:
    """Build a synthetic heartbeat without collecting host identifiers."""
    return {
        "client_id": client_id[:128],
        "mxc_id": "LAB-MXC-000000000000",
        "app_version": "2.0.0-go-portable",
        "license_key": "LAB_ONLY",
        "go_version": "lab",
        "is_running": False,
        "is_sending": False,
        "sent_total": 0,
        "sent_today": 0,
        "fail_today": 0,
        "lab_emulator": True,
    }


def read_bounded(sock: socket.socket, maximum: int) -> bytes:
    """Implement the read bounded operation for the analysis framework."""
    chunks, total = [], 0
    while total < maximum:
        try:
            chunk = sock.recv(min(4096, maximum - total))
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def read_for_duration(sock: socket.socket, maximum: int, duration: float) -> bytes:
    """Read a bounded N520 response window and stop cleanly on idle timeout."""
    chunks, total = [], 0
    deadline = time.monotonic() + duration
    while total < maximum and time.monotonic() < deadline:
        sock.settimeout(max(0.1, min(1.0, deadline - time.monotonic())))
        try:
            chunk = sock.recv(min(65536, maximum - total))
        except socket.timeout:
            continue
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def write_n520_archive(path: Path, password: str, frames: list[dict], plugins: list[dict]) -> None:
    """Store encrypted frames and recovered plugin bytes only in an AES ZIP."""
    import pyzipper

    path.parent.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(password.encode())
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        for index, frame in enumerate(frames, 1):
            archive.writestr(f"frames/{index:03d}-{frame['raw_sha256']}.bin", frame["raw"])
        for plugin in plugins:
            suffix = ".dll" if plugin["pe_magic"] else ".bin"
            archive.writestr(f"payloads/{plugin['artifact_sha256']}{suffix}", plugin["artifact"])


def tls_metadata(sock: ssl.SSLSocket) -> dict:
    """Implement the tls metadata operation for the analysis framework."""
    der = sock.getpeercert(binary_form=True)
    result = {
        "version": sock.version(),
        "cipher": list(sock.cipher() or ()),
        "certificate_sha256": hashlib.sha256(der).hexdigest() if der else None,
        "certificate_length": len(der) if der else 0,
    }
    if der:
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(der)
            result.update({
                "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                "serial_number_hex": hex(cert.serial_number),
                "not_valid_before": cert.not_valid_before_utc.isoformat(),
                "not_valid_after": cert.not_valid_after_utc.isoformat(),
            })
        except Exception as exc:
            result["certificate_parse_error"] = f"{type(exc).__name__}: {exc}"
    return result


def collect_jarm(host: str, port: int, script: Path | None, timeout: float) -> dict:
    """Implement the collect jarm operation for the analysis framework."""
    if not script or not script.is_file():
        return {"status": "not_collected", "reason": "official Salesforce JARM script not found"}
    try:
        completed = subprocess.run(
            [sys.executable, str(script), "-p", str(port), host], capture_output=True,
            text=True, timeout=max(20.0, timeout * 12), check=False,
        )
        match = re.search(r"\b[0-9a-f]{62}\b", completed.stdout, re.I)
        fingerprint = match.group(0).lower() if match else None
        if fingerprint == "0" * 62:
            fingerprint = None
        return {
            "status": "collected" if fingerprint else "no_fingerprint",
            "fingerprint": fingerprint,
            "tool": "Salesforce JARM", "exit_code": completed.returncode,
            "output_tail": completed.stdout[-1000:],
        }
    except Exception as exc:
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}


def probe(args) -> dict:
    """Implement the probe operation for the analysis framework."""
    started = time.perf_counter()
    result = {
        "schema_version": 2, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host": args.host, "port": args.port, "protocol": args.protocol,
        "timeout_seconds": args.timeout,
        "maximum_response_bytes": 64 if args.protocol == "vvas" else (44 if args.protocol == "n520" else args.max_bytes),
        "alive": False, "c2_confirmed": False, "network_contacted": True,
    }
    if args.protocol == "mxgo" and args.mxgo_mode == "preview":
        body = json.dumps(build_mxgo_heartbeat(args.mxgo_client_id), separators=(",", ":")).encode()
        result.update({
            "status": "dry_run",
            "network_contacted": False,
            "application_data_sent": False,
            "mxgo_request_preview": {
                "method": "POST",
                "path": "/api/v1/heartbeat_direct",
                "content_type": "application/json",
                "body_length": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "fields": sorted(build_mxgo_heartbeat(args.mxgo_client_id)),
                "uses_real_machine_identity": False,
            },
        })
        return result
    try:
        result["resolved_ips"] = sorted({item[4][0] for item in socket.getaddrinfo(args.host, args.port, type=socket.SOCK_STREAM)})
    except OSError as exc:
        result["resolution_error"] = f"{type(exc).__name__}: {exc}"
    raw = b""
    tls = None
    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as base:
            base.settimeout(args.timeout)
            result["tcp_status"] = "open"
            result["alive"] = True
            connection: socket.socket = base
            if args.protocol in {"https", "tls", "n520"}:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sni = args.sni or ("update.microsoft.com" if args.protocol == "n520" else args.host)
                connection = context.wrap_socket(base, server_hostname=sni)
                tls = tls_metadata(connection)
                result["tls"] = tls
            if args.protocol == "n520":
                raw = read_bounded(connection, 44)
                handshake = parse_n520_handshake(raw)
                result.update({
                    "n520_handshake": handshake,
                    "status": "confirmed_n520_c2" if handshake["header_matches"] else (
                        "protocol_mismatch" if raw else "connected_no_response"
                    ),
                    "c2_confirmed": handshake["header_matches"],
                    "application_data_sent": False,
                })
                if handshake["header_matches"] and args.n520_checkin:
                    session_id = handshake["session_id"]
                    session_key = derive_n520_session_key(raw)
                    checkin = build_n520_packet(session_id, 1, 1, b"", session_key)
                    connection.sendall(checkin)
                    result["application_data_sent"] = True
                    response = read_for_duration(connection, args.n520_max_bytes, args.n520_wait)
                    frames, remainder = decode_n520_stream(response, session_id, session_key, args.n520_max_frames)
                    plugins = []
                    for frame in frames:
                        if frame.get("authenticated"):
                            plugin = extract_n520_plugin(frame.get("command", -1), frame.get("payload", b""))
                            if plugin:
                                plugins.append(plugin)
                    if args.artifact_zip:
                        write_n520_archive(args.artifact_zip, args.archive_password, frames, plugins)
                    frame_metadata = []
                    for frame in frames:
                        frame_metadata.append({
                            key: value for key, value in frame.items()
                            if key not in {"raw", "payload"}
                        })
                    plugin_metadata = []
                    for plugin in plugins:
                        plugin_metadata.append({
                            key: value for key, value in plugin.items() if key != "artifact"
                        })
                    result["n520_collection"] = {
                        "checkin_command": 1,
                        "checkin_payload_size": 0,
                        "checkin_packet_sha256": hashlib.sha256(checkin).hexdigest(),
                        "application_data_sent": True,
                        "station_id_sent": False,
                        "response_bytes": len(response),
                        "maximum_response_bytes": args.n520_max_bytes,
                        "collection_window_seconds": args.n520_wait,
                        "response_sha256": hashlib.sha256(response).hexdigest(),
                        "frame_count": len(frames),
                        "frames": frame_metadata,
                        "trailing_unparsed_bytes": len(remainder),
                        "plugins": plugin_metadata,
                        "artifact_archive": str(args.artifact_zip) if args.artifact_zip else None,
                        "payload_executed": False,
                    }
            elif args.protocol == "vvas":
                payload = bytes.fromhex(args.send_hex or "333200")
                connection.sendall(payload)
                raw = read_bounded(connection, min(args.max_bytes, 64))
                expected = args.expected_stage_size
                declared = struct.unpack("<I", raw[:4])[0] if len(raw) >= 4 else None
                header_matches = len(raw) >= args.expected_header_size and declared == expected and raw[4:args.expected_header_size] == b"\0" * (args.expected_header_size - 4)
                result.update({
                    "sent_hex": payload.hex(), "declared_stage2_size": declared,
                    "expected_stage2_size": expected, "header_matches": header_matches,
                    "status": "confirmed_vvas_c2" if header_matches else ("protocol_mismatch" if raw else "connected_no_response"),
                    "c2_confirmed": header_matches,
                })
            elif args.protocol == "mxgo":
                host_header = f"{args.host}:{args.port}"
                if args.mxgo_mode == "checkin":
                    request_body = json.dumps(
                        build_mxgo_heartbeat(args.mxgo_client_id), separators=(",", ":"),
                    ).encode()
                    request = (
                        f"POST /api/v1/heartbeat_direct HTTP/1.1\r\nHost: {host_header}\r\n"
                        f"User-Agent: MX-Go-Lab-Detector/1\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(request_body)}\r\nConnection: close\r\n\r\n"
                    ).encode() + request_body
                else:
                    request_body = b""
                    request = (
                        f"GET {args.mxgo_recipient_path} HTTP/1.1\r\nHost: {host_header}\r\n"
                        "User-Agent: MX-Go-Lab-Detector/1\r\nConnection: close\r\n\r\n"
                    ).encode()
                connection.sendall(request)
                raw = read_bounded(connection, args.max_bytes)
                status, headers, response_body = parse_headers(raw)
                result.update({
                    "status": "mxgo_lab_response" if status else ("protocol_mismatch" if raw else "connected_no_response"),
                    "application_data_sent": True,
                    "mxgo_mode": args.mxgo_mode,
                    "http": {"status": status, "headers": headers, "path": (
                        "/api/v1/heartbeat_direct" if args.mxgo_mode == "checkin" else args.mxgo_recipient_path
                    )},
                })
                if args.mxgo_mode == "checkin":
                    try:
                        decoded = json.loads(response_body)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        decoded = {}
                    lab_marker = isinstance(decoded, dict) and decoded.get("lab_emulator") is True
                    result["c2_confirmed"] = lab_marker
                    result["mxgo_checkin"] = {
                        "synthetic_identity_sent": True,
                        "real_machine_identity_sent": False,
                        "response_is_lab_emulator": lab_marker,
                        "response_keys": sorted(decoded) if isinstance(decoded, dict) else [],
                        "command_values_returned": False,
                    }
                else:
                    lines = [line.strip() for line in response_body.decode("utf-8", errors="replace").splitlines() if line.strip()]
                    address_like = [line for line in lines if re.fullmatch(r"[^@\s]+@[^@\s]+", line)]
                    result["mxgo_recipients"] = {
                        "count": len(address_like),
                        "response_sha256": hashlib.sha256(response_body).hexdigest(),
                        "values_redacted": True,
                        "all_addresses_use_invalid_tld": bool(address_like) and all(
                            value.rsplit("@", 1)[-1].endswith(".invalid") for value in address_like
                        ),
                    }
            elif args.protocol in {"http", "https"}:
                host_header = args.http_host or args.sni or args.host
                request = f"GET {args.http_path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: c2-detector/2\r\nAccept: text/html,*/*;q=0.1\r\nConnection: close\r\n\r\n".encode()
                connection.sendall(request)
                raw = read_bounded(connection, args.max_bytes)
                status, headers, body = parse_headers(raw)
                parser = TitleParser()
                parser.feed(body.decode("utf-8", errors="replace"))
                result["http"] = {"status": status, "title": parser.title, "headers": headers, "path": args.http_path, "redirect_followed": False}
                result["status"] = "http_response" if status else ("protocol_mismatch" if raw else "connected_no_response")
            else:
                if args.send_hex:
                    connection.sendall(bytes.fromhex(args.send_hex))
                raw = read_bounded(connection, args.max_bytes)
                result["status"] = "banner_received" if raw else "tcp_open_no_banner"
    except ConnectionRefusedError as exc:
        result.update({"status": "closed", "tcp_status": "closed", "error": str(exc)})
    except (socket.timeout, TimeoutError) as exc:
        result.update({"status": "timeout", "error": str(exc) or "timed out"})
    except Exception as exc:
        result.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"})

    if raw:
        result["banner"] = {
            "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "shodan_mmh3": murmur3_32(raw),
            "prefix_base64": base64.b64encode(raw[:512]).decode(),
        }
    if args.collect_jarm and args.protocol in {"https", "tls", "n520"}:
        result["jarm"] = collect_jarm(args.sni or args.host, args.port, args.jarm_script, args.timeout)

    try:
        ipaddress.ip_address(args.host)
        target_filter = f"ip:{args.host}"
    except ValueError:
        target_filter = f"hostname:{args.host}"
    queries = [f"{target_filter} port:{args.port}"]
    for resolved_ip in result.get("resolved_ips", []):
        query = f"ip:{resolved_ip} port:{args.port}"
        if query not in queries:
            queries.append(query)
    if result.get("banner"):
        queries.append(f"hash:{result['banner']['shodan_mmh3']}")
    if result.get("http", {}).get("title"):
        title = result["http"]["title"].replace('"', '\\"')
        queries.append(f'http.title:"{title}"')
    cert_hash = (tls or {}).get("certificate_sha256")
    if cert_hash:
        queries.append(f"ssl.cert.fingerprint:{cert_hash}")
    jarm = result.get("jarm", {}).get("fingerprint")
    if jarm:
        queries.append(f"ssl.jarm:{jarm}")
    result["shodan"] = {
        "banner_hash_algorithm": "signed MurmurHash3 x86_32 of captured raw banner bytes",
        "queries": queries,
        "recommended_combination": " ".join(queries[1:]) if len(queries) > 1 else queries[0],
        "warning": "Revalidate fields in Shodan before operational use; banner, IP, certificate and JARM can change or be shared.",
    }
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def main() -> int:
    """Implement the main operation for the analysis framework."""
    parser = argparse.ArgumentParser(description="Bounded C2 liveness and Shodan fingerprint collector.")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--protocol", choices=["tcp", "vvas", "n520", "http", "https", "tls", "mxgo"], default="tcp")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-bytes", type=int, default=65536)
    parser.add_argument("--send-hex")
    parser.add_argument("--expected-stage-size", type=int, default=307214)
    parser.add_argument("--expected-header-size", type=int, default=14)
    parser.add_argument("--http-path", default="/")
    parser.add_argument("--http-host")
    parser.add_argument("--sni")
    parser.add_argument("--mxgo-mode", choices=["preview", "checkin", "recipients"], default="preview")
    parser.add_argument("--mxgo-client-id", default="LAB-MXGO-000000000000")
    parser.add_argument("--mxgo-recipient-path", default="/jp01.txt")
    parser.add_argument("--mxgo-allow-loopback-network", action="store_true")
    parser.add_argument("--n520-checkin", action="store_true", help="send one empty command-1 registration after a confirmed N520 handshake")
    parser.add_argument("--n520-wait", type=float, default=15.0)
    parser.add_argument("--n520-max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--n520-max-frames", type=int, default=16)
    parser.add_argument("--artifact-zip", type=Path)
    parser.add_argument("--archive-password", default="infected")
    parser.add_argument("--collect-jarm", action="store_true")
    parser.add_argument("--jarm-script", type=Path, default=Path(r"C:\Users\Administrator\Tools\Salesforce-JARM\jarm.py"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0.1 <= args.timeout <= 30 or not 1 <= args.max_bytes <= 1048576:
        parser.error("port, timeout, or max-bytes is outside the allowed range")
    if not 1 <= args.n520_wait <= 30 or not 1 <= args.n520_max_bytes <= 16 * 1024 * 1024 or not 1 <= args.n520_max_frames <= 64:
        parser.error("N520 collection bounds are outside the allowed range")
    if args.protocol == "mxgo" and args.mxgo_mode != "preview":
        if not mxgo_loopback_target(args.host):
            parser.error("active MX-Go emulation is loopback-only")
        if not args.mxgo_allow_loopback_network:
            parser.error("active MX-Go emulation requires --mxgo-allow-loopback-network")
        if not re.fullmatch(r"/[A-Za-z0-9._/-]{1,200}", args.mxgo_recipient_path):
            parser.error("invalid MX-Go recipient fixture path")
    if args.n520_checkin and args.protocol != "n520":
        parser.error("--n520-checkin requires --protocol n520")
    if args.n520_checkin and not args.artifact_zip:
        parser.error("--n520-checkin requires --artifact-zip for contained evidence storage")
    try:
        ipaddress.ip_address(args.host)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9.-]+", args.host):
            parser.error("invalid host")
    result = probe(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("alive") or result.get("status") == "dry_run" else 1


if __name__ == "__main__":
    raise SystemExit(main())




