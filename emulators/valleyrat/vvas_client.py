#!/usr/bin/env python3
"""Bounded ValleyRAT vvaS protocol emulator.

This tool emulates the observed ValleyRAT vvaS check-in without executing any
sample code. By default it emits a preflight result without network contact.
An explicitly enabled live probe reads only the small response header/prefix
needed for protocol confirmation and never downloads the declared stage payload.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_SEND_HEX = "333200"
DEFAULT_EXPECTED_STAGE_SIZE = 307214
DEFAULT_EXPECTED_HEADER_SIZE = 14
DEFAULT_MAX_READ = 64
DEFAULT_TIMEOUT = 8.0


def parse_vvas_header(raw: bytes, expected_stage_size: int, expected_header_size: int) -> dict[str, Any]:
    """Parse a vvaS response prefix and decide whether it matches the known header."""
    declared = struct.unpack("<I", raw[:4])[0] if len(raw) >= 4 else None
    padding = raw[4:expected_header_size] if len(raw) >= 4 else b""
    header_matches = (
        len(raw) >= expected_header_size
        and declared == expected_stage_size
        and padding == b"\0" * (expected_header_size - 4)
    )
    status = "confirmed_vvas_c2" if header_matches else ("protocol_mismatch" if raw else "connected_no_response")
    return {
        "declared_stage2_size": declared,
        "expected_stage2_size": expected_stage_size,
        "expected_header_size": expected_header_size,
        "header_matches": header_matches,
        "status": status,
    }


def read_bounded(sock: socket.socket, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
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


def banner_metadata(raw: bytes) -> dict[str, Any] | None:
    if not raw:
        return None
    return {
        "length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "prefix_base64": base64.b64encode(raw[:512]).decode("ascii"),
    }


def preflight_vvas_target(
    host: str,
    port: int,
    send_hex: str,
    expected_stage_size: int,
    expected_header_size: int,
    max_read: int,
    timeout: float,
    allow_stage_download: bool = False,
    risk_accepted: bool = False,
) -> dict[str, Any]:
    """Describe a bounded vvaS probe without resolving or contacting its target."""
    if allow_stage_download and not risk_accepted:
        raise ValueError("--allow-stage-download requires --i-understand-stage-download-risk")
    bytes.fromhex(send_hex)
    effective_max_read = max_read if allow_stage_download else min(max_read, DEFAULT_MAX_READ)
    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "port": port,
        "protocol": "vvas",
        "send_hex": send_hex.lower(),
        "expected_stage2_size": expected_stage_size,
        "expected_header_size": expected_header_size,
        "timeout_seconds": timeout,
        "maximum_response_bytes": effective_max_read,
        "stage_download_requested": allow_stage_download,
        "stage_download_permitted": allow_stage_download and risk_accepted,
        "network_contacted": False,
        "application_data_sent": False,
        "alive": False,
        "c2_confirmed": False,
        "status": "dry_run",
        "required_network_opt_in": "--allow-network",
    }


def probe_vvas_target(
    host: str,
    port: int,
    send_hex: str,
    expected_stage_size: int,
    expected_header_size: int,
    max_read: int,
    timeout: float,
    allow_stage_download: bool = False,
    risk_accepted: bool = False,
    allow_network: bool = False,
) -> dict[str, Any]:
    """Preflight by default; explicitly connect and collect bounded metadata when allowed."""
    if allow_stage_download and not risk_accepted:
        raise ValueError("--allow-stage-download requires --i-understand-stage-download-risk")
    if not allow_network:
        return preflight_vvas_target(
            host,
            port,
            send_hex,
            expected_stage_size,
            expected_header_size,
            max_read,
            timeout,
            allow_stage_download,
            risk_accepted,
        )
    # Safe default: collect only the response header/prefix. Reading more than
    # 64 bytes requires the explicit stage-download risk flags below.
    effective_max_read = max_read if allow_stage_download else min(max_read, DEFAULT_MAX_READ)
    started = time.perf_counter()
    payload = bytes.fromhex(send_hex)
    result: dict[str, Any] = {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "port": port,
        "protocol": "vvas",
        "send_hex": send_hex.lower(),
        "timeout_seconds": timeout,
        "maximum_response_bytes": effective_max_read,
        "stage_download_requested": allow_stage_download,
        "stage_download_permitted": allow_stage_download and risk_accepted,
        "network_contacted": True,
        "alive": False,
        "c2_confirmed": False,
    }
    raw = b""
    try:
        try:
            result["resolved_ips"] = sorted({item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        except OSError as exc:
            result["resolution_error"] = f"{type(exc).__name__}: {exc}"
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            result["tcp_status"] = "open"
            result["alive"] = True
            connection.sendall(payload)
            raw = read_bounded(connection, effective_max_read)
            header = parse_vvas_header(raw, expected_stage_size, expected_header_size)
            result.update(header)
            result["c2_confirmed"] = bool(header["header_matches"])
    except ConnectionRefusedError as exc:
        result.update({"status": "closed", "tcp_status": "closed", "error": str(exc)})
    except (socket.timeout, TimeoutError) as exc:
        result.update({"status": "timeout", "error": str(exc) or "timed out"})
    except Exception as exc:  # Network errors should be serialized for repeatable evidence.
        result.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"})
    metadata = banner_metadata(raw)
    if metadata:
        result["banner"] = metadata
    result["bytes_read"] = len(raw)
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def load_profile_targets(profile_path: Path, target_index: int | None = None) -> list[dict[str, Any]]:
    profile = json.loads(profile_path.read_text(encoding="utf-8-sig"))
    vvas = profile.get("vvas", {})
    targets = profile.get("live_c2_targets", [])
    if target_index is not None:
        try:
            targets = [targets[target_index]]
        except IndexError as exc:
            raise ValueError(f"target index out of range: {target_index}") from exc
    normalized = []
    for target in targets:
        if target.get("protocol") != "vvas":
            raise ValueError(f"unsupported profile target protocol for vvas_client: {target.get('protocol')}")
        normalized.append({
            "host": target["host"],
            "port": int(target["port"]),
            "send_hex": target.get("send_hex") or vvas.get("checkin_hex") or DEFAULT_SEND_HEX,
            "expected_stage_size": int(target.get("expected_stage_size") or vvas.get("stage2_size") or DEFAULT_EXPECTED_STAGE_SIZE),
            "expected_header_size": int(target.get("expected_header_size") or vvas.get("stage2_header_size") or DEFAULT_EXPECTED_HEADER_SIZE),
        })
    return normalized


def dry_run_result(
    targets: list[dict[str, Any]],
    max_read: int = DEFAULT_MAX_READ,
    timeout: float = DEFAULT_TIMEOUT,
    allow_stage_download: bool = False,
    risk_accepted: bool = False,
) -> dict[str, Any]:
    results = [
        preflight_vvas_target(
            target["host"],
            target["port"],
            target["send_hex"],
            target["expected_stage_size"],
            target["expected_header_size"],
            max_read,
            timeout,
            allow_stage_download,
            risk_accepted,
        )
        for target in targets
    ]
    return {"schema_version": 1, "results": results} if len(results) != 1 else results[0]


def write_json_result(result: dict[str, Any], output: Path | None) -> None:
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    print(text, end="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safely emulate a bounded ValleyRAT vvaS check-in.")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--target-index", type=int)
    parser.add_argument("--send-hex", default=DEFAULT_SEND_HEX)
    parser.add_argument("--expected-stage-size", type=int, default=DEFAULT_EXPECTED_STAGE_SIZE)
    parser.add_argument("--expected-header-size", type=int, default=DEFAULT_EXPECTED_HEADER_SIZE)
    parser.add_argument("--max-read", type=int, default=DEFAULT_MAX_READ)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-network", action="store_true", help="Explicitly allow the bounded live vvaS probe.")
    parser.add_argument("--dry-run", action="store_true", help="Force preflight even when --allow-network is present.")
    parser.add_argument("--allow-stage-download", action="store_true", help="Dangerous: allow reading more than the safe header/prefix.")
    parser.add_argument("--i-understand-stage-download-risk", action="store_true", help="Required with --allow-stage-download.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.allow_stage_download and not args.i_understand_stage_download_risk:
        parser.error("--allow-stage-download requires --i-understand-stage-download-risk")
    if args.profile:
        targets = load_profile_targets(args.profile, args.target_index)
    else:
        if not args.host or args.port is None:
            raise SystemExit("--host and --port are required unless --profile is supplied")
        targets = [{
            "host": args.host,
            "port": args.port,
            "send_hex": args.send_hex,
            "expected_stage_size": args.expected_stage_size,
            "expected_header_size": args.expected_header_size,
        }]
    if args.dry_run or not args.allow_network:
        write_json_result(
            dry_run_result(
                targets,
                args.max_read,
                args.timeout,
                args.allow_stage_download,
                args.i_understand_stage_download_risk,
            ),
            args.output,
        )
        return 0
    results = [
        probe_vvas_target(
            target["host"],
            target["port"],
            target["send_hex"],
            target["expected_stage_size"],
            target["expected_header_size"],
            args.max_read,
            args.timeout,
            args.allow_stage_download,
            args.i_understand_stage_download_risk,
            args.allow_network,
        )
        for target in targets
    ]
    output: dict[str, Any] = {"schema_version": 1, "results": results} if len(results) != 1 else results[0]
    write_json_result(output, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
