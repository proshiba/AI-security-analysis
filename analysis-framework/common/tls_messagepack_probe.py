#!/usr/bin/env python3
"""AsyncRAT／VenomRATのレビュー済みTLS MessagePack応答を限定検証する。"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import socket
import ssl
import struct
from typing import Any, Callable

from tls_messagepack_c2_detector import (
    TlsMessagePackDetectorError,
    certificate_assessment as _certificate_assessment,
    classify_reviewed_response,
)
from tls_messagepack_rat_host_emulator import (
    SessionLimits,
    TlsMessagePackHostError,
    decode_frame,
    encode_frame,
)


class MessagePackProbeError(ValueError):
    """frame、圧縮payload、またはMessagePackが安全上限に違反したことを示す。"""


def encode_compressed_frame(values: dict[str, str]) -> bytes:
    """string mapをreview済みの4-byte長＋gzip frameへ変換する。"""

    if not isinstance(values, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in values.items()
    ):
        raise MessagePackProbeError("probe frameは文字列mapだけを許可します")
    try:
        return encode_frame(values)
    except TlsMessagePackHostError as exc:
        raise MessagePackProbeError("TLS MessagePack frameを構築できません") from exc


def decode_compressed_payload(
    data: bytes,
    *,
    maximum_decoded_bytes: int = 1024,
) -> dict[str, str]:
    """4-byte原文長＋gzip payloadを、有界decoderで厳格に復号する。"""

    if not isinstance(data, bytes) or not 5 <= len(data) <= 1024:
        raise MessagePackProbeError("圧縮payloadがreview済み上限外です")
    if (
        isinstance(maximum_decoded_bytes, bool)
        or not isinstance(maximum_decoded_bytes, int)
        or not 64 <= maximum_decoded_bytes <= 16 * 1024 * 1024
    ):
        raise MessagePackProbeError("maximum_decoded_bytesがreview済み上限外です")
    limits = SessionLimits(
        timeout_seconds=3.0,
        maximum_frame_bytes=1024,
        maximum_decoded_bytes=maximum_decoded_bytes,
        maximum_map_entries=15,
        maximum_string_bytes=256,
        maximum_binary_bytes=1,
        maximum_opcode_bytes=64,
        maximum_read_calls=8,
        maximum_send_bytes=96,
    )
    try:
        decoded = decode_frame(struct.pack("<I", len(data)) + data, limits)
    except (TypeError, TlsMessagePackHostError) as exc:
        raise MessagePackProbeError("圧縮payloadを厳格に復号できません") from exc
    if any(not isinstance(value, str) for value in decoded.values.values()):
        raise MessagePackProbeError("文字列以外の応答値を拒否しました")
    return {
        key: value
        for key, value in decoded.values.items()
        if isinstance(value, str)
    }


def certificate_assessment(
    observed_der: bytes,
    expected_sha256: str | None,
) -> dict[str, Any]:
    """証明書一致を加点材料とし、不一致をC2除外条件にはしない。"""

    return _certificate_assessment(observed_der, expected_sha256)


def _recv_exact(
    stream: Any,
    size: int,
    *,
    maximum_calls: int = 16,
) -> bytes:
    chunks = bytearray()
    calls = 0
    while len(chunks) < size:
        if calls >= maximum_calls:
            raise MessagePackProbeError("responseのread-call上限を超えました")
        calls += 1
        chunk = stream.recv(size - len(chunks))
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise MessagePackProbeError("TLS streamがbytes以外を返しました")
        raw = bytes(chunk)
        if len(raw) > size - len(chunks):
            raise MessagePackProbeError("TLS streamが要求量を超えて返しました")
        if not raw:
            raise ConnectionError("TLS streamが応答途中で終了しました")
        chunks.extend(raw)
    return bytes(chunks)


def exchange_reviewed_packet(
    stream: Any,
    profile: dict[str, Any],
    *,
    negotiated_tls_version: str | None = "TLSv1.2",
) -> dict[str, Any]:
    """匿名Pingを1 frameだけ送り、review済みheartbeat応答を完全一致検証する。"""

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
    try:
        assessment = classify_reviewed_response(
            profile,
            header + payload,
            negotiated_tls_version=negotiated_tls_version,
        )
    except TlsMessagePackDetectorError as exc:
        raise MessagePackProbeError(
            "review済みTLS MessagePack応答として解析できません"
        ) from exc
    application = assessment["application"]
    return {
        "sent_bytes": len(frame),
        "received_bytes": 4 + len(payload),
        "request_count": 1,
        "request_budget_used": 1,
        "application_data_sent": True,
        "protocol_response_received": True,
        "response_packet": application["response_packet"],
        "response_field_count": application["response_field_count"],
        "response_frame_size": application["frame_size"],
        "response_frame_sha256": application["frame_sha256"],
        "response_decoded_size": application["decoded_size"],
        "response_decoded_sha256": application["decoded_sha256"],
        "detector_status": assessment["status"],
        "tls_version_exact": assessment["tls"]["version_exact"],
        "c2_confirmed": assessment["c2_confirmed"],
        "victim_metadata_sent": False,
        "stage_requested": False,
        "operation_command_sent": False,
        "command_polling_performed": False,
        "raw_request_published": False,
        "raw_response_published": False,
        "raw_response_retained": False,
        "synthetic_result_sent": False,
    }


def _public_addresses(
    host: str,
    port: int,
    resolver: Callable[..., Any],
) -> list[str]:
    values = sorted(
        {
            item[4][0]
            for item in resolver(host, port, type=socket.SOCK_STREAM)
            if item[4]
        }
    )
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
    raw = connector(
        (addresses[0], port),
        timeout=float(profile["timeout_seconds"]),
    )
    try:
        raw.settimeout(float(profile["timeout_seconds"]))
        context = (
            context_factory()
            if context_factory
            else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        )
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls = context.wrap_socket(
            raw,
            server_hostname=str(profile.get("sni") or host),
        )
        try:
            version_reader = getattr(tls, "version", None)
            observed_version = version_reader() if callable(version_reader) else None
            cert = certificate_assessment(
                tls.getpeercert(binary_form=True),
                profile.get("expected_certificate_sha256"),
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
                "tls": {
                    "handshake": True,
                    "observed_version": observed_version,
                    "expected_version": "TLSv1.2",
                    "version_exact": observed_version == "TLSv1.2",
                    "certificate": cert,
                },
                "certificate_mismatch_excludes_c2": False,
                "victim_metadata_sent": False,
                "stage_requested": False,
                "operation_command_sent": False,
                "raw_response_retained": False,
            }
            if allow_application_probe:
                result.update(
                    exchange_reviewed_packet(
                        tls,
                        profile,
                        negotiated_tls_version=observed_version,
                    )
                )
                result["status"] = result["detector_status"]
            return result
        finally:
            tls.close()
    finally:
        raw.close()
