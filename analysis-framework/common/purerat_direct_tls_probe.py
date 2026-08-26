#!/usr/bin/env python3
"""レビュー済みPureRAT endpointをTLS-first・送信なしで証明書pin判定する。"""

from __future__ import annotations

import gzip
import hashlib
import io
import ipaddress
import socket
import ssl
import struct
import zlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

MAX_FRAME_SIZE = 4 * 1024 * 1024
REVIEWED_PROFILE_ID = "purerat-441-d025a296-45-192-211-77-56001-direct-tls10"
EXPECTED_NEGOTIATED_TLS_VERSION = "TLSv1"
PROTOBUF_NET_TYPES = {
    1: "client_registration",
    2: "heartbeat",
    3: "status_or_error",
    4: "plugin_context_direction_unconfirmed",
    5: "plugin_descriptor_or_cache_miss_request",
    35: "auxiliary_message",
    38: "configuration_update",
    86: "command",
}


class PureRatDirectTlsError(ValueError):
    """direct-TLS profile、frame、または安全境界が不正な場合のエラー。"""


Resolver = Callable[..., list[tuple[Any, ...]]]
Connector = Callable[[tuple[str, int], float], Any]
TlsHandshaker = Callable[[Any, dict[str, Any]], dict[str, Any]]


def reviewed_profile() -> dict[str, Any]:
    """d025 carrierから独立検証した単一endpointの変更可能なcopyを返す。"""
    return {
        "profile_id": REVIEWED_PROFILE_ID,
        "family": "purehvnc",
        "variant": "managed_purerat_4_4_1_direct_tls",
        "root_sample_sha256": "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677",
        "terminal_sample_sha256": "df0359edefe34a970af39227978dbe7f1caa09caf98a2c6db53f49187ec25dd7",
        "host": "45.192.211.77",
        "pinned_ips": ["45.192.211.77"],
        "port": 56001,
        "handler": "purerat_direct_tls",
        "method": "purerat_direct_tls_certificate_pin",
        "wire_mode": "direct_tls",
        "send_hex": "",
        "sni": None,
        "tls_version": "TLSv1.0",
        "expected_certificate_sha256": "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57",
        "timeout_seconds": 3.0,
        "request_budget_bytes": 0,
        "maximum_request_bytes": 0,
        "maximum_response_bytes": 0,
        "allow_openssl_legacy_security_level": True,
        "source": "analysis-framework/docs/PURERAT-DIRECT-TLS-STATIC-RECOVERY.md",
    }


def validate_reviewed_profile(profile: dict[str, Any]) -> dict[str, Any]:
    """完全固定profile以外を、DNS解決やsocket作成より前に拒否する。"""
    if type(profile) is not dict or profile != reviewed_profile():
        raise PureRatDirectTlsError("review済みd025 PureRAT direct-TLS profileと完全一致しません")
    return reviewed_profile()


def encode_inner_frame(protobuf_payload: bytes, *, maximum_size: int = MAX_FRAME_SIZE) -> bytes:
    """protobuf-net payloadをGZip化し、little-endian 32-bit長を付ける。"""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressor:
        compressor.write(protobuf_payload)
    compressed = buffer.getvalue()
    if not compressed or len(compressed) > maximum_size:
        raise PureRatDirectTlsError("圧縮済みframeが上限を超えています")
    return struct.pack("<I", len(compressed)) + compressed


def decode_inner_frame(frame: bytes, *, maximum_size: int = MAX_FRAME_SIZE) -> bytes:
    """完全な1 frameだけを受理し、GZip bombを上限付きで展開する。"""
    if len(frame) < 4:
        raise PureRatDirectTlsError("frame headerが不足しています")
    declared = struct.unpack_from("<I", frame)[0]
    if not 1 <= declared <= maximum_size or len(frame) != declared + 4:
        raise PureRatDirectTlsError("frame長が不正です")
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        clear = decoder.decompress(frame[4:], maximum_size + 1)
        if len(clear) > maximum_size or decoder.unconsumed_tail:
            raise PureRatDirectTlsError("展開後payloadが上限を超えています")
        clear += decoder.flush()
    except zlib.error as exc:
        raise PureRatDirectTlsError("GZip payloadが不正です") from exc
    if len(clear) > maximum_size or not decoder.eof or decoder.unused_data:
        raise PureRatDirectTlsError("GZip payloadが不正です")
    return clear


def _read_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    for index in range(10):
        position = offset + index
        if position >= len(data):
            raise PureRatDirectTlsError("protobuf varintが途中で終了しました")
        byte = data[position]
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, position + 1
    raise PureRatDirectTlsError("protobuf varintが長すぎます")


def inspect_protobuf_net_payload(payload: bytes) -> dict[str, Any]:
    """先頭field keyを読み、既知ProtoInclude discriminatorを安全に分類する。"""
    key, cursor = _read_varint(payload)
    field_number = key >> 3
    wire_type = key & 7
    if field_number < 1:
        raise PureRatDirectTlsError("protobuf field numberが不正です")
    embedded_size: int | None = None
    if wire_type == 2:
        embedded_size, cursor = _read_varint(payload, cursor)
        if cursor + embedded_size > len(payload):
            raise PureRatDirectTlsError("protobuf length-delimited fieldが途中で終了しました")
    return {
        "first_field_number": field_number,
        "first_wire_type": wire_type,
        "protoinclude_type": PROTOBUF_NET_TYPES.get(field_number, "unknown"),
        "embedded_size": embedded_size,
    }


def classify_inner_frame(frame: bytes, *, maximum_size: int = MAX_FRAME_SIZE) -> dict[str, Any]:
    """offline frameを展開し、実行せずにProtoInclude種別を返す。"""
    payload = decode_inner_frame(frame, maximum_size=maximum_size)
    return {
        "framing": "tls/le32/gzip/protobuf-net",
        "protobuf_size": len(payload),
        **inspect_protobuf_net_payload(payload),
    }


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _resolve_and_select(profile: dict[str, Any], resolver: Resolver) -> tuple[tuple[str, ...], str]:
    host = str(profile["host"])
    port = int(profile["port"])
    if _public_ip(host):
        answers = (host,)
    else:
        answers = tuple(
            sorted(
                {
                    str(item[4][0])
                    for item in resolver(host, port, type=socket.SOCK_STREAM)
                    if _public_ip(str(item[4][0]))
                }
            )
        )
    if not answers:
        raise PureRatDirectTlsError("global DNS応答を取得できません")
    pinned = tuple(str(value) for value in profile.get("pinned_ips") or [])
    if len(pinned) > 1 or any(not _public_ip(value) for value in pinned):
        raise PureRatDirectTlsError("pinned_ipsは0件または単一global IPに限定します")
    if pinned and pinned[0] not in answers:
        raise PureRatDirectTlsError("現在のDNS応答とreview済みpinned IPが一致しません")
    return answers, pinned[0] if pinned else answers[0]


def _perform_direct_tls_handshake(raw_socket: Any, profile: dict[str, Any]) -> dict[str, Any]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.maximum_version = ssl.TLSVersion.TLSv1
    if profile.get("allow_openssl_legacy_security_level") is True:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    sni = profile.get("sni")
    server_hostname = str(sni) if isinstance(sni, str) and sni else None
    with context.wrap_socket(raw_socket, server_hostname=server_hostname, do_handshake_on_connect=False) as tls_socket:
        tls_socket.settimeout(float(profile["timeout_seconds"]))
        tls_socket.do_handshake()
        certificate = tls_socket.getpeercert(binary_form=True)
        if not certificate:
            raise ssl.SSLError("peer certificateを取得できません")
        cipher = tls_socket.cipher()
        return {
            "version": tls_socket.version(),
            "cipher": cipher[0] if cipher else None,
            "certificate_sha256": hashlib.sha256(certificate).hexdigest(),
        }


def _disabled(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "alive": False,
        "c2_confirmed": False,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "tls_before_application_data": True,
        "plaintext_prelude_sent": False,
        "application_data_sent": False,
        "protocol_response_received": False,
        "registration_attempted": False,
        "task_poll_attempted": False,
        "task_executed": False,
        "operation_command_sent": False,
        "certificate_mismatch_excludes_c2": False,
        "certificate_mismatch_excludes_exact_build_endpoint": True,
        "certificate_mismatch_excludes_family_c2": False,
        "tls_version_mismatch_excludes_c2": False,
        "tls_version_mismatch_excludes_exact_build_endpoint": True,
        "tls_version_mismatch_excludes_family_c2": False,
        "resolved_ips": [],
    }


def probe_reviewed_purerat_direct_tls(
    profile: dict[str, Any],
    *,
    allow_network: bool = False,
    allow_legacy_tls: bool = False,
    resolver: Resolver | None = None,
    connector: Connector | None = None,
    tls_handshaker: TlsHandshaker | None = None,
) -> dict[str, Any]:
    """TLS 1.0を最初のwire byteとして確立し、証明書pinだけを照合する。

    protobuf登録、task取得、plugin要求、command処理は行わない。ネットワークと
    legacy TLSの2 gateが明示されない限りfail-closedする。
    """
    profile = validate_reviewed_profile(profile)
    if not allow_network:
        return _disabled("network_disabled")
    if not allow_legacy_tls:
        return _disabled("legacy_tls_disabled")
    if profile.get("handler") != "purerat_direct_tls":
        raise PureRatDirectTlsError("PureRAT direct-TLS handlerではありません")
    if profile.get("wire_mode") != "direct_tls" or profile.get("tls_version") != "TLSv1.0":
        raise PureRatDirectTlsError("wire modeはdirect TLS 1.0に限定します")
    if profile.get("send_hex") not in (None, "") or int(profile.get("maximum_request_bytes", -1)) != 0:
        raise PureRatDirectTlsError("direct-TLS certificate probeはapplication data送信を許可しません")
    expected = str(profile.get("expected_certificate_sha256") or "").casefold()
    if len(expected) != 64 or any(value not in "0123456789abcdef" for value in expected):
        raise PureRatDirectTlsError("期待証明書SHA-256が不正です")

    resolve = resolver or socket.getaddrinfo
    connect = connector or socket.create_connection
    handshake = tls_handshaker or _perform_direct_tls_handshake
    answers, connect_ip = _resolve_and_select(profile, resolve)
    raw_socket = connect((connect_ip, int(profile["port"])), float(profile["timeout_seconds"]))
    try:
        raw_socket.settimeout(float(profile["timeout_seconds"]))
        tls = handshake(raw_socket, profile)
    finally:
        try:
            raw_socket.close()
        except OSError:
            pass

    observed_version = str(tls.get("version") or "")
    version_exact = observed_version == EXPECTED_NEGOTIATED_TLS_VERSION
    observed = str(tls.get("certificate_sha256") or "").casefold()
    certificate_exact = observed == expected
    confirmed = version_exact and certificate_exact
    if not version_exact:
        status = "purerat_direct_tls_version_mismatch_inconclusive"
    elif certificate_exact:
        status = "confirmed_purerat_direct_tls_certificate"
    else:
        status = "purerat_direct_tls_certificate_mismatch"
    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "status": status,
        "profile_id": profile["profile_id"],
        "root_sample_sha256": profile["root_sample_sha256"],
        "terminal_sample_sha256": profile["terminal_sample_sha256"],
        "alive": True,
        "c2_confirmed": confirmed,
        "target_contact_attempted": True,
        "target_connection_established": True,
        "wire_mode": "direct_tls",
        "application_framing": "le32/gzip/protobuf-net",
        "tls_before_application_data": True,
        "plaintext_prelude_sent": False,
        "application_data_sent": False,
        "protocol_response_received": False,
        "tls": {
            "handshake": True,
            "version": observed_version or None,
            "expected_version": EXPECTED_NEGOTIATED_TLS_VERSION,
            "version_exact_match": version_exact,
            "cipher": tls.get("cipher"),
            "certificate": {
                "state": "exact_match" if certificate_exact else "mismatch_inconclusive",
                "exact_match": certificate_exact,
                "observed_sha256": observed or None,
                "expected_sha256": expected,
                "certificate_mismatch_excludes_c2": False,
            },
        },
        "certificate_mismatch_excludes_c2": False,
        "certificate_mismatch_excludes_exact_build_endpoint": True,
        "certificate_mismatch_excludes_family_c2": False,
        "tls_version_mismatch_excludes_c2": False,
        "tls_version_mismatch_excludes_exact_build_endpoint": True,
        "tls_version_mismatch_excludes_family_c2": False,
        "resolved_ips": list(answers),
        "connected_ip": connect_ip,
        "registration_attempted": False,
        "task_poll_attempted": False,
        "task_executed": False,
        "operation_command_sent": False,
    }
