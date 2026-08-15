#!/usr/bin/env python3
"""vvaS check-inへheaderだけを返すloopback限定の防御用facade。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
from dataclasses import asdict, dataclass
from typing import Any

from emulators.valleyrat.vvas_client import (
    DEFAULT_EXPECTED_HEADER_SIZE,
    DEFAULT_EXPECTED_STAGE_SIZE,
    DEFAULT_SEND_HEX,
)

CHECKIN = bytes.fromhex(DEFAULT_SEND_HEX)
MAXIMUM_REQUEST_BYTES = len(CHECKIN)
SYNTHETIC_HEADER_ONLY_ALLOWED = True
STAGE_BODY_TRANSMISSION_ALLOWED = False
TASK_RESULT_TRANSMISSION_ALLOWED = False


@dataclass(frozen=True)
class SyntheticVvasResponseDecision:
    """vvaS bootstrapに対するheader-only応答判断。"""

    checkin_valid: bool
    response_kind: str
    send_allowed: bool
    declared_stage_size: int | None
    header_size: int
    stage_body_bytes: int = 0
    terminal_protocol_available: bool = False
    operation_executed: bool = False
    fixture_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SyntheticVvasTaskResultDecision:
    """terminal stage未回収時にwire byteを生成しないfake task result判断。"""

    outcome: str
    send_allowed: bool = False
    wire_schema_status: str = "terminal_stage_and_operator_protocol_unrecovered"
    wire_bytes: None = None
    operation_executed: bool = False
    fixture_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def synthetic_response_decision(
    request: bytes,
    *,
    allow_header_only: bool = False,
) -> SyntheticVvasResponseDecision:
    """exact check-inだけをheader-only fixtureへ変換する。"""

    if not isinstance(request, bytes):
        raise TypeError("requestはbytesで指定してください")
    valid = request == CHECKIN
    allowed = valid and allow_header_only is True
    return SyntheticVvasResponseDecision(
        checkin_valid=valid,
        response_kind=(
            "synthetic_stage_header_only"
            if allowed
            else "invalid_checkin_or_header_not_allowed"
        ),
        send_allowed=allowed,
        declared_stage_size=DEFAULT_EXPECTED_STAGE_SIZE if allowed else None,
        header_size=DEFAULT_EXPECTED_HEADER_SIZE if allowed else 0,
    )


def build_synthetic_response(
    request: bytes,
    *,
    allow_header_only: bool = False,
) -> bytes:
    """stage bodyを含まない14-byte parser fixtureだけを構築する。"""

    decision = synthetic_response_decision(
        request,
        allow_header_only=allow_header_only,
    )
    if not decision.send_allowed:
        return b""
    return struct.pack("<I", DEFAULT_EXPECTED_STAGE_SIZE) + b"\x00" * (
        DEFAULT_EXPECTED_HEADER_SIZE - 4
    )


def synthetic_task_result_decision(
    *,
    outcome: str = "success",
) -> SyntheticVvasTaskResultDecision:
    """terminal protocolを推測せず、送信禁止の抽象結果だけを返す。"""

    if not isinstance(outcome, str) or outcome not in {"success", "failure", "no_output"}:
        raise ValueError("outcomeはsuccess、failure、no_outputのいずれかです")
    return SyntheticVvasTaskResultDecision(outcome=outcome)


def serve_once(
    bind: str = "127.0.0.1",
    port: int = 0,
    *,
    timeout: float = 3.0,
    allow_header_only: bool = False,
) -> dict[str, Any]:
    """numeric loopbackで1接続・exact 3-byte check-inだけを処理する。"""

    if not _is_loopback(bind):
        raise ValueError("bindはnumeric loopback addressに限定します")
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.settimeout(timeout)
        server.bind((bind, port))
        server.listen(1)
        selected_port = int(server.getsockname()[1])
        client, peer = server.accept()
        with client:
            peer_ip = str(peer[0])
            if not _is_loopback(peer_ip):
                raise PermissionError("loopback以外のpeerを拒否しました")
            client.settimeout(timeout)
            request = client.recv(MAXIMUM_REQUEST_BYTES + 1)
            decision = synthetic_response_decision(
                request,
                allow_header_only=allow_header_only,
            )
            response = build_synthetic_response(
                request,
                allow_header_only=allow_header_only,
            )
            if response:
                client.sendall(response)
    return {
        "schema_version": 1,
        "protocol": "vvas_bootstrap",
        "bind": bind,
        "port": selected_port,
        "peer_loopback": True,
        "received_bytes": len(request),
        "sent_bytes": len(response),
        "decision": decision.to_dict(),
        "safety": {
            "sample_executed": False,
            "operation_executed": False,
            "stage_body_sent": False,
            "stage_body_bytes": 0,
            "fake_task_result_sent": False,
            "task_result_transmission_allowed": TASK_RESULT_TRANSMISSION_ALLOWED,
            "loopback_only": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--allow-synthetic-header-only", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            serve_once(
                args.bind,
                args.port,
                allow_header_only=args.allow_synthetic_header_only,
            ),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
