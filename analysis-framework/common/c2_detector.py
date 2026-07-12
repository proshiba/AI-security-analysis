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


def murmur3_32(data: bytes, seed: int = 0) -> int:
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
        super().__init__()
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, _attrs) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data)

    @property
    def title(self) -> str | None:
        value = " ".join(" ".join(self.parts).split())
        return value[:512] or None


def parse_headers(raw: bytes) -> tuple[int | None, dict[str, str], bytes]:
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


def read_bounded(sock: socket.socket, maximum: int) -> bytes:
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


def tls_metadata(sock: ssl.SSLSocket) -> dict:
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
    started = time.perf_counter()
    result = {
        "schema_version": 2, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host": args.host, "port": args.port, "protocol": args.protocol,
        "timeout_seconds": args.timeout, "maximum_response_bytes": 64 if args.protocol == "vvas" else args.max_bytes,
        "alive": False, "c2_confirmed": False, "network_contacted": True,
    }
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
            if args.protocol in {"https", "tls"}:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = context.wrap_socket(base, server_hostname=args.sni or args.host)
                tls = tls_metadata(connection)
                result["tls"] = tls
            if args.protocol == "vvas":
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
    if args.collect_jarm and args.protocol in {"https", "tls"}:
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
    parser = argparse.ArgumentParser(description="Bounded C2 liveness and Shodan fingerprint collector.")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--protocol", choices=["tcp", "vvas", "http", "https", "tls"], default="tcp")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-bytes", type=int, default=65536)
    parser.add_argument("--send-hex")
    parser.add_argument("--expected-stage-size", type=int, default=307214)
    parser.add_argument("--expected-header-size", type=int, default=14)
    parser.add_argument("--http-path", default="/")
    parser.add_argument("--http-host")
    parser.add_argument("--sni")
    parser.add_argument("--collect-jarm", action="store_true")
    parser.add_argument("--jarm-script", type=Path, default=Path(r"C:\Users\Administrator\Tools\Salesforce-JARM\jarm.py"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0.1 <= args.timeout <= 30 or not 1 <= args.max_bytes <= 1048576:
        parser.error("port, timeout, or max-bytes is outside the allowed range")
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
    return 0 if result.get("alive") else 1


if __name__ == "__main__":
    raise SystemExit(main())




