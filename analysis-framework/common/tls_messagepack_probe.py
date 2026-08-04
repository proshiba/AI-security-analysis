#!/usr/bin/env python3
"""AsyncRAT／VenomRATのレビュー済みTLS MessagePack応答を限定検証する。"""

from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import ipaddress
import socket
import ssl
import struct
from typing import Any, Callable


class MessagePackProbeError(ValueError):
    """frame、圧縮payload、またはMessagePackが安全上限に違反したことを示す。"""


def _pack_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    size = len(raw)
    if size <= 31:
        return bytes([0xA0 | size]) + raw
    if size <= 0xFF:
        return b"\xD9" + bytes([size]) + raw
    if size <= 0xFFFF:
        return b"\xDA" + struct.pack(">H", size) + raw
    raise MessagePackProbeError("MessagePack文字列が長すぎます")


def encode_string_map(values: dict[str, str]) -> bytes:
    """安全なprobeで必要な文字列mapだけをMessagePack化する。"""

    if not 1 <= len(values) <= 15:
        raise MessagePackProbeError("MessagePack mapは1〜15要素に限定します")
    return bytes([0x80 | len(values)]) + b"".join(
        _pack_string(str(key)) + _pack_string(str(value)) for key, value in values.items()
    )


def _read_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(data):
        raise MessagePackProbeError("MessagePack文字列headerが不足しています")
    prefix = data[offset]
    offset += 1
    if 0xA0 <= prefix <= 0xBF:
        size = prefix & 0x1F
    elif prefix == 0xD9:
        if offset + 1 > len(data):
            raise MessagePackProbeError("str8長が不足しています")
        size = data[offset]
        offset += 1
    elif prefix == 0xDA:
        if offset + 2 > len(data):
            raise MessagePackProbeError("str16長が不足しています")
        size = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
    else:
        raise MessagePackProbeError(f"文字列以外のMessagePack型です: 0x{prefix:02x}")
    end = offset + size
    if end > len(data):
        raise MessagePackProbeError("MessagePack文字列本文が不足しています")
    return data[offset:end].decode("utf-8"), end


def decode_string_map(data: bytes) -> dict[str, str]:
    """応答確認に必要な小さい文字列mapだけをfail-closedで読む。"""

    if not data or not 0x81 <= data[0] <= 0x8F:
        raise MessagePackProbeError("fixmap以外のMessagePack応答は受け付けません")
    count = data[0] & 0x0F
    offset = 1
    result: dict[str, str] = {}
    for _ in range(count):
        key, offset = _read_string(data, offset)
        value, offset = _read_string(data, offset)
        result[key] = value
    if offset != len(data):
        raise MessagePackProbeError("MessagePack応答末尾に未解析byteがあります")
    return result


def encode_compressed_frame(values: dict[str, str]) -> bytes:
    """4-byte原文長＋gzip payloadを、4-byte wire長でframe化する。"""

    raw = encode_string_map(values)
    compressed = struct.pack("<I", len(raw)) + gzip.compress(raw, compresslevel=9, mtime=0)
    return struct.pack("<I", len(compressed)) + compressed


def decode_compressed_payload(data: bytes, *, maximum_decoded_bytes: int = 1024) -> dict[str, str]:
    """VenomRAT／AsyncRATの圧縮MessagePackを上限付きで復号する。"""

    if len(data) < 5:
        raise MessagePackProbeError("圧縮payloadが短すぎます")
    declared = struct.unpack("<I", data[:4])[0]
    if declared > maximum_decoded_bytes:
        raise MessagePackProbeError("展開後sizeが上限を超えています")
    raw = gzip.decompress(data[4:])
    if len(raw) != declared or len(raw) > maximum_decoded_bytes:
        raise MessagePackProbeError("展開後sizeが宣言値と一致しません")
    return decode_string_map(raw)


def certificate_assessment(observed_der: bytes, expected_sha256: str | None) -> dict[str, Any]:
    """証明書一致を加点材料とし、不一致をC2除外条件にはしない。"""

    observed = hashlib.sha256(observed_der).hexdigest()
    expected = expected_sha256.casefold() if expected_sha256 else None
    matched = expected == observed if expected else None
    if matched is True:
        state = "exact_match"
        reason = "検体内蔵証明書SHA-256と観測証明書が一致"
    elif matched is False:
        state = "mismatch_inconclusive"
        reason = "証明書は不一致だが、改変build・fork・rotationの可能性があるためC2を除外しない"
    else:
        state = "observed_without_static_pin"
        reason = "観測証明書SHA-256は取得したが検体側期待値は未復元"
    return {
        "observed_sha256": observed,
        "expected_sha256": expected,
        "exact_match": matched,
        "state": state,
        "certificate_mismatch_excludes_c2": False,
        "reason": reason,
    }


def _recv_exact(stream: Any, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("TLS streamが応答途中で終了しました")
        chunks.extend(chunk)
    return bytes(chunks)


def exchange_reviewed_packet(stream: Any, profile: dict[str, Any]) -> dict[str, Any]:
    """匿名・空Messageのheartbeatを1 frameだけ送信し、期待packet名を検証する。"""

    request = {
        str(profile["packet_key"]): str(profile["request_packet"]),
        str(profile.get("message_key", "Message")): "",
    }
    frame = encode_compressed_frame(request)
    if len(frame) > int(profile.get("maximum_request_bytes", 96)):
        raise MessagePackProbeError("review済みrequest上限を超えています")
    stream.sendall(frame)
    header = _recv_exact(stream, 4)
    declared = struct.unpack("<I", header)[0]
    maximum = int(profile["maximum_response_bytes"])
    if not 1 <= declared <= maximum:
        raise MessagePackProbeError("response frame長がreview済み上限外です")
    payload = _recv_exact(stream, declared)
    decoded = decode_compressed_payload(payload)
    packet_value = decoded.get(str(profile["packet_key"]))
    expected = {str(value) for value in profile["expected_response_packets"]}
    confirmed = packet_value in expected
    return {
        "sent_bytes": len(frame),
        "received_bytes": 4 + len(payload),
        "application_data_sent": True,
        "protocol_response_received": True,
        "response_packet": packet_value,
        "response_fields": sorted(decoded),
        "c2_confirmed": confirmed,
        "victim_metadata_sent": False,
        "stage_requested": False,
        "operation_command_sent": False,
        "command_polling_performed": False,
    }


def _public_addresses(host: str, port: int, resolver: Callable[..., Any]) -> list[str]:
    values = sorted({item[4][0] for item in resolver(host, port, type=socket.SOCK_STREAM) if item[4]})
    if not values:
        raise ValueError("DNS解決結果がありません")
    if any(not ipaddress.ip_address(value).is_global for value in values):
        raise ValueError("非global IPへの外部C2 probeは拒否しました")
    return values


def probe_reviewed_tls_messagepack(
    profile: dict[str, Any],
    *,
    allow_network: bool = False,
    allow_application_probe: bool = False,
    resolver: Callable[..., Any] = socket.getaddrinfo,
    connector: Callable[..., Any] = socket.create_connection,
    context_factory: Callable[[], ssl.SSLContext] | None = None,
) -> dict[str, Any]:
    """完全一致profileへTLS接続し、明示許可時だけ匿名heartbeatを送る。"""

    timestamp = datetime.now(timezone.utc).isoformat()
    if not allow_network:
        return {
            "timestamp_utc": timestamp,
            "status": "network_disabled",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": False,
            "application_data_sent": False,
            "certificate_mismatch_excludes_c2": False,
        }
    host = str(profile["host"])
    port = int(profile["port"])
    addresses = _public_addresses(host, port, resolver)
    raw = connector((addresses[0], port), timeout=float(profile["timeout_seconds"]))
    try:
        raw.settimeout(float(profile["timeout_seconds"]))
        context = context_factory() if context_factory else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls = context.wrap_socket(raw, server_hostname=str(profile.get("sni") or host))
        try:
            cert = certificate_assessment(
                tls.getpeercert(binary_form=True), profile.get("expected_certificate_sha256")
            )
            result = {
                "timestamp_utc": timestamp,
                "status": "tls_handshake_only_application_probe_disabled",
                "alive": True,
                "c2_confirmed": False,
                "target_contact_attempted": True,
                "target_connection_established": True,
                "application_data_sent": False,
                "protocol_response_received": False,
                "resolved_ips": addresses,
                "tls": {"handshake": True, "certificate": cert},
                "certificate_mismatch_excludes_c2": False,
                "victim_metadata_sent": False,
                "stage_requested": False,
                "operation_command_sent": False,
            }
            if allow_application_probe:
                result.update(exchange_reviewed_packet(tls, profile))
                result["status"] = (
                    "confirmed_tls_messagepack_c2"
                    if result["c2_confirmed"]
                    else "tls_messagepack_response_mismatch"
                )
            return result
        finally:
            tls.close()
    finally:
        raw.close()