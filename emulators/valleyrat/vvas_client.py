#!/usr/bin/env python3
"""有界なValleyRAT vvaS protocol emulator。

既定ではnetworkへ接続せずpreflight結果だけを返す。live probeは中央profileへ
完全一致するtargetだけを許可し、protocol確認に必要な最大64 byteだけを読む。
宣言されたstage payloadは取得しない。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_SEND_HEX = "333200"
DEFAULT_EXPECTED_STAGE_SIZE = 307214
DEFAULT_EXPECTED_HEADER_SIZE = 14
DEFAULT_MAX_READ = 64
DEFAULT_TIMEOUT = 8.0
LIVE_STAGE_DOWNLOAD_ALLOWED = False

COMMON_ROOT = Path(__file__).resolve().parents[2] / "analysis-framework" / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

from c2_protocol_probe_profiles import (  # noqa: E402
    ProtocolProfileError,
    load_profiles,
    profile_registry_metadata,
)


def parse_vvas_header(raw: bytes, expected_stage_size: int, expected_header_size: int) -> dict[str, Any]:
    """vvaS応答prefixを解析し、既知headerとの一致を判定する。"""
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
    """名前解決も接続も行わず、有界なvvaS probe計画を返す。"""
    if allow_stage_download and not risk_accepted:
        raise ValueError("--allow-stage-downloadには--i-understand-stage-download-riskが必要です")
    bytes.fromhex(send_hex)
    effective_max_read = min(max_read, DEFAULT_MAX_READ)
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
        "stage_download_permitted": False,
        "stage_download_live_allowed": LIVE_STAGE_DOWNLOAD_ALLOWED,
        "network_contacted": False,
        "application_data_sent": False,
        "alive": False,
        "c2_confirmed": False,
        "status": "dry_run",
        "required_network_opt_in": "--allow-network",
    }


def reviewed_live_target(protocol_profile_id: str) -> dict[str, Any]:
    """中央registryからlive利用可能なvvaS targetを完全一致で解決する。"""

    metadata = profile_registry_metadata()
    profiles = load_profiles(expected_sha256=metadata["sha256"])
    profile = profiles.get(protocol_profile_id)
    if profile is None:
        raise ProtocolProfileError(
            f"未レビューのprotocol_profile_idです: {protocol_profile_id}"
        )
    if (
        profile.get("family") != "valleyrat"
        or profile.get("protocol") != "vvas"
        or profile.get("method") != "vvas_checkin"
        or profile.get("handler") != "c2_detector_vvas"
        or profile.get("send_hex") != DEFAULT_SEND_HEX
        or profile.get("expected_stage_size") != DEFAULT_EXPECTED_STAGE_SIZE
        or profile.get("expected_header_size") != DEFAULT_EXPECTED_HEADER_SIZE
        or profile.get("maximum_response_bytes") != DEFAULT_MAX_READ
        or profile.get("timeout_seconds") != 3.0
    ):
        raise ProtocolProfileError("中央vvaS profileがレビュー済み安全境界と一致しません")
    return {
        "protocol_profile_id": protocol_profile_id,
        "profile_registry_source": metadata["source"],
        "profile_registry_sha256": metadata["sha256"],
        "host": profile["host"],
        "port": int(profile["port"]),
        "send_hex": profile["send_hex"],
        "expected_stage_size": int(profile["expected_stage_size"]),
        "expected_header_size": int(profile["expected_header_size"]),
        "maximum_response_bytes": int(profile["maximum_response_bytes"]),
        "timeout_seconds": float(profile["timeout_seconds"]),
    }


def _require_exact_live_target(
    protocol_profile_id: str | None,
    *,
    host: str,
    port: int,
    send_hex: str,
    expected_stage_size: int,
    expected_header_size: int,
    max_read: int,
    timeout: float,
) -> dict[str, Any]:
    if not protocol_profile_id:
        raise PermissionError("live vvaS probeには--protocol-profile-idが必要です")
    target = reviewed_live_target(protocol_profile_id)
    observed = {
        "host": host.casefold().rstrip("."),
        "port": port,
        "send_hex": send_hex.casefold(),
        "expected_stage_size": expected_stage_size,
        "expected_header_size": expected_header_size,
        "maximum_response_bytes": max_read,
        "timeout_seconds": float(timeout),
    }
    expected = {key: target[key] for key in observed}
    if observed != expected:
        raise PermissionError(
            f"live引数が中央profileと一致しません: {protocol_profile_id}"
        )
    return target


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
    *,
    protocol_profile_id: str | None = None,
) -> dict[str, Any]:
    """既定はpreflightとし、liveは中央profile完全一致時だけ実行する。"""
    if allow_stage_download and not risk_accepted:
        raise ValueError("--allow-stage-downloadには--i-understand-stage-download-riskが必要です")
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
    if allow_stage_download:
        raise PermissionError("live vvaS probeではstage downloadを許可しません")
    target = _require_exact_live_target(
        protocol_profile_id,
        host=host,
        port=port,
        send_hex=send_hex,
        expected_stage_size=expected_stage_size,
        expected_header_size=expected_header_size,
        max_read=max_read,
        timeout=timeout,
    )
    effective_max_read = int(target["maximum_response_bytes"])
    started = time.perf_counter()
    payload = bytes.fromhex(str(target["send_hex"]))
    result: dict[str, Any] = {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "protocol_profile_id": target["protocol_profile_id"],
        "profile_registry_source": target["profile_registry_source"],
        "profile_registry_sha256": target["profile_registry_sha256"],
        "host": target["host"],
        "port": target["port"],
        "protocol": "vvas",
        "send_hex": target["send_hex"],
        "timeout_seconds": target["timeout_seconds"],
        "maximum_response_bytes": effective_max_read,
        "stage_download_requested": False,
        "stage_download_permitted": False,
        "stage_download_live_allowed": LIVE_STAGE_DOWNLOAD_ALLOWED,
        "network_contacted": True,
        "application_data_sent": False,
        "alive": False,
        "c2_confirmed": False,
    }
    raw = b""
    try:
        try:
            result["resolved_ips"] = sorted({
                item[4][0]
                for item in socket.getaddrinfo(
                    target["host"], target["port"], type=socket.SOCK_STREAM
                )
            })
        except OSError as exc:
            result["resolution_error"] = f"{type(exc).__name__}: {exc}"
        with socket.create_connection(
            (target["host"], target["port"]),
            timeout=target["timeout_seconds"],
        ) as connection:
            connection.settimeout(target["timeout_seconds"])
            result["tcp_status"] = "open"
            result["alive"] = True
            connection.sendall(payload)
            result["application_data_sent"] = True
            raw = read_bounded(connection, effective_max_read)
            header = parse_vvas_header(
                raw,
                target["expected_stage_size"],
                target["expected_header_size"],
            )
            result.update(header)
            result["c2_confirmed"] = bool(header["header_matches"])
    except ConnectionRefusedError as exc:
        result.update({"status": "closed", "tcp_status": "closed", "error": str(exc)})
    except (socket.timeout, TimeoutError) as exc:
        result.update({"status": "timeout", "error": str(exc) or "timed out"})
    except Exception as exc:  # network errorを再検証可能な証拠として正規化する。
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
            raise ValueError(f"target indexが範囲外です: {target_index}") from exc
    normalized = []
    for target in targets:
        if target.get("protocol") != "vvas":
            raise ValueError(f"vvas_client未対応のprofile protocolです: {target.get('protocol')}")
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
    parser = argparse.ArgumentParser(description="ValleyRAT vvaS check-inを安全かつ有界に模擬します。")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--protocol-profile-id")
    parser.add_argument("--target-index", type=int)
    parser.add_argument("--send-hex")
    parser.add_argument("--expected-stage-size", type=int)
    parser.add_argument("--expected-header-size", type=int)
    parser.add_argument("--max-read", type=int)
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-network", action="store_true", help="中央profile完全一致の有界live probeを明示許可します。")
    parser.add_argument("--dry-run", action="store_true", help="--allow-network指定時もpreflightだけを実行します。")
    parser.add_argument("--allow-stage-download", action="store_true", help="互換parse専用です。liveでは常に拒否します。")
    parser.add_argument("--i-understand-stage-download-risk", action="store_true", help="--allow-stage-downloadと併用する互換引数です。")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.allow_stage_download and not args.i_understand_stage_download_risk:
        parser.error("--allow-stage-downloadには--i-understand-stage-download-riskが必要です")
    if args.allow_network and not args.dry_run:
        if args.allow_stage_download:
            parser.error("live vvaS probeではstage downloadを許可しません")
        if not args.protocol_profile_id:
            parser.error("live vvaS probeには--protocol-profile-idが必要です")
        if args.profile is not None or args.target_index is not None:
            parser.error("--profile/--target-indexはoffline preflight専用です")
        try:
            target = reviewed_live_target(args.protocol_profile_id)
        except (OSError, ValueError, ProtocolProfileError) as exc:
            parser.error(str(exc))
        overrides = {
            "host": args.host.casefold().rstrip(".") if args.host else None,
            "port": args.port,
            "send_hex": args.send_hex.casefold() if args.send_hex else None,
            "expected_stage_size": args.expected_stage_size,
            "expected_header_size": args.expected_header_size,
            "maximum_response_bytes": args.max_read,
            "timeout_seconds": args.timeout,
        }
        for key, value in overrides.items():
            if value is not None and value != target[key]:
                parser.error(f"--{key.replace('_', '-')}が中央profileと一致しません")
        result = probe_vvas_target(
            target["host"],
            target["port"],
            target["send_hex"],
            target["expected_stage_size"],
            target["expected_header_size"],
            target["maximum_response_bytes"],
            target["timeout_seconds"],
            False,
            False,
            True,
            protocol_profile_id=args.protocol_profile_id,
        )
        write_json_result(result, args.output)
        return 0

    send_hex = args.send_hex or DEFAULT_SEND_HEX
    expected_stage_size = (
        DEFAULT_EXPECTED_STAGE_SIZE
        if args.expected_stage_size is None
        else args.expected_stage_size
    )
    expected_header_size = (
        DEFAULT_EXPECTED_HEADER_SIZE
        if args.expected_header_size is None
        else args.expected_header_size
    )
    max_read = DEFAULT_MAX_READ if args.max_read is None else args.max_read
    timeout = DEFAULT_TIMEOUT if args.timeout is None else args.timeout
    if args.profile:
        targets = load_profile_targets(args.profile, args.target_index)
    elif args.protocol_profile_id:
        target = reviewed_live_target(args.protocol_profile_id)
        targets = [{
            "host": args.host or target["host"],
            "port": args.port if args.port is not None else target["port"],
            "send_hex": send_hex,
            "expected_stage_size": expected_stage_size,
            "expected_header_size": expected_header_size,
        }]
    else:
        if not args.host or args.port is None:
            raise SystemExit("--profileを指定しない場合は--hostと--portが必要です")
        targets = [{
            "host": args.host,
            "port": args.port,
            "send_hex": send_hex,
            "expected_stage_size": expected_stage_size,
            "expected_header_size": expected_header_size,
        }]
    write_json_result(
        dry_run_result(
            targets,
            max_read,
            timeout,
            args.allow_stage_download,
            args.i_understand_stage_download_risk,
        ),
        args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
