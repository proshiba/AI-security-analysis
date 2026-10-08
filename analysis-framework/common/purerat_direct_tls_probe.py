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
MAXIMUM_EXPANSION_RATIO = 128
MAXIMUM_LOOPBACK_RESOLVER_RESULTS = 16
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


def _require_bytes(value: object, label: str) -> bytes:
    """mutableなbytes-like値を暗黙変換せず、正確なbytesだけを受理する。"""
    if type(value) is not bytes:
        raise PureRatDirectTlsError(f"{label}はbytesで指定してください")
    return value


def _require_bound(value: object, label: str, absolute_maximum: int) -> int:
    """boolを除く正の整数だけをhard limitとして受理する。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise PureRatDirectTlsError(f"{label}は整数で指定してください")
    if not 1 <= value <= absolute_maximum:
        raise PureRatDirectTlsError(f"{label}が安全上限外です")
    return value


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


def encode_inner_frame(
    protobuf_payload: bytes,
    *,
    maximum_size: int = MAX_FRAME_SIZE,
    maximum_expansion_ratio: int = MAXIMUM_EXPANSION_RATIO,
) -> bytes:
    """protobuf-net payloadをGZip化し、little-endian 32-bit長を付ける。"""
    payload = _require_bytes(protobuf_payload, "protobuf payload")
    selected_maximum = _require_bound(maximum_size, "maximum_size", MAX_FRAME_SIZE)
    selected_ratio = _require_bound(
        maximum_expansion_ratio,
        "maximum_expansion_ratio",
        MAXIMUM_EXPANSION_RATIO,
    )
    if not payload or len(payload) > selected_maximum:
        raise PureRatDirectTlsError("protobuf payloadが空、または上限を超えています")
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressor:
        compressor.write(payload)
    compressed = buffer.getvalue()
    if not compressed or len(compressed) > selected_maximum:
        raise PureRatDirectTlsError("圧縮済みframeが上限を超えています")
    if len(payload) > len(compressed) * selected_ratio:
        raise PureRatDirectTlsError("protobuf payloadが展開率上限を超えています")
    return struct.pack("<I", len(compressed)) + compressed


def decode_inner_frame(
    frame: bytes,
    *,
    maximum_size: int = MAX_FRAME_SIZE,
    maximum_expansion_ratio: int = MAXIMUM_EXPANSION_RATIO,
) -> bytes:
    """完全な1 frameだけを受理し、GZip bombを上限付きで展開する。"""
    value = _require_bytes(frame, "inner frame")
    selected_maximum = _require_bound(maximum_size, "maximum_size", MAX_FRAME_SIZE)
    selected_ratio = _require_bound(
        maximum_expansion_ratio,
        "maximum_expansion_ratio",
        MAXIMUM_EXPANSION_RATIO,
    )
    if len(value) < 4:
        raise PureRatDirectTlsError("frame headerが不足しています")
    declared = struct.unpack_from("<I", value)[0]
    if not 1 <= declared <= selected_maximum or len(value) != declared + 4:
        raise PureRatDirectTlsError("frame長が不正です")
    output_bound = min(selected_maximum, declared * selected_ratio)
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        clear = decoder.decompress(value[4:], output_bound + 1)
        if len(clear) > output_bound or decoder.unconsumed_tail:
            raise PureRatDirectTlsError("展開後payloadがsizeまたは展開率上限を超えています")
        remaining = output_bound + 1 - len(clear)
        clear += decoder.flush(remaining)
    except zlib.error as exc:
        raise PureRatDirectTlsError("GZip payloadが不正です") from exc
    if len(clear) > output_bound:
        raise PureRatDirectTlsError("展開後payloadがsizeまたは展開率上限を超えています")
    if not decoder.eof or decoder.unused_data:
        raise PureRatDirectTlsError("GZip payloadが不正です")
    if not clear:
        raise PureRatDirectTlsError("展開後protobuf payloadが空です")
    return clear


def _read_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    for index in range(10):
        position = offset + index
        if position >= len(data):
            raise PureRatDirectTlsError("protobuf varintが途中で終了しました")
        byte = data[position]
        if index == 9 and byte > 1:
            raise PureRatDirectTlsError("protobuf varintが64-bit範囲を超えています")
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, position + 1
    raise PureRatDirectTlsError("protobuf varintが長すぎます")


def inspect_protobuf_net_payload(payload: bytes) -> dict[str, Any]:
    """先頭field keyを読み、既知ProtoInclude discriminatorを安全に分類する。"""
    value = _require_bytes(payload, "protobuf payload")
    if not value:
        raise PureRatDirectTlsError("protobuf payloadが空です")
    key, cursor = _read_varint(value)
    field_number = key >> 3
    wire_type = key & 7
    if not 1 <= field_number <= 0x1FFFFFFF:
        raise PureRatDirectTlsError("protobuf field numberが不正です")
    if wire_type != 2:
        raise PureRatDirectTlsError("protobuf-net継承envelopeはwire type 2である必要があります")
    embedded_size, cursor = _read_varint(value, cursor)
    if cursor + embedded_size != len(value):
        raise PureRatDirectTlsError("protobuf length-delimited fieldが途中で終了したかtrailing fieldがあります")
    return {
        "first_field_number": field_number,
        "first_wire_type": wire_type,
        "protoinclude_type": PROTOBUF_NET_TYPES.get(field_number, "unknown"),
        "embedded_size": embedded_size,
        "single_root_envelope_exact": True,
        "family_attribution_confirmed": False,
    }


def classify_inner_frame(
    frame: bytes,
    *,
    maximum_size: int = MAX_FRAME_SIZE,
    maximum_expansion_ratio: int = MAXIMUM_EXPANSION_RATIO,
) -> dict[str, Any]:
    """offline frameを展開し、実行せずにProtoInclude種別を返す。"""
    wire = _require_bytes(frame, "inner frame")
    payload = decode_inner_frame(
        wire,
        maximum_size=maximum_size,
        maximum_expansion_ratio=maximum_expansion_ratio,
    )
    return {
        "framing": "tls/le32/gzip/protobuf-net",
        "frame_size": len(wire),
        "frame_sha256": hashlib.sha256(wire).hexdigest(),
        "protobuf_size": len(payload),
        "protobuf_sha256": hashlib.sha256(payload).hexdigest(),
        "offline_only": True,
        **inspect_protobuf_net_payload(payload),
    }


def _loopback_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return str(address) == value.casefold() and (
        (address.version == 4 and address.is_loopback) or (address.version == 6 and value.casefold() == "::1")
    )


def _resolve_loopback(profile: dict[str, Any], resolver: Resolver) -> tuple[tuple[str, ...], str]:
    """注入resolverが返す単一numeric loopbackだけをtest接続先にする。"""

    host = str(profile["host"])
    port = int(profile["port"])
    try:
        raw_answers = resolver(host, port, type=socket.SOCK_STREAM)
        observed: set[str] = set()
        for index, item in enumerate(raw_answers):
            if index >= MAXIMUM_LOOPBACK_RESOLVER_RESULTS:
                raise PureRatDirectTlsError("注入resolverの応答件数が上限を超えています")
            observed.add(str(item[4][0]))
        answers = tuple(sorted(observed))
    except PureRatDirectTlsError:
        raise
    except Exception as exc:
        raise PureRatDirectTlsError("注入resolverのloopback応答を検証できません") from exc
    if len(answers) != 1 or not _loopback_ip(answers[0]):
        raise PureRatDirectTlsError("互換probeの接続先は単一のnumeric loopbackに限定します")
    return answers, answers[0]


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
        "probable_c2": False,
        "confidence": 0.0,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "loopback_contact_attempted": False,
        "loopback_connection_established": False,
        "external_target_contact_allowed": False,
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
    """loopback TLS 1.0 harnessで証明書profileをprobable分類する。

    protobuf登録、task取得、plugin要求、command処理は行わない。ネットワークと
    legacy TLSの2 gateに加え、明示注入したresolverとconnectorを要求する。
    接続先は単一numeric loopbackだけで、外部C2確認には使用できない。
    """
    profile = validate_reviewed_profile(profile)
    if not allow_network:
        return _disabled("network_disabled")
    if not allow_legacy_tls:
        return _disabled("legacy_tls_disabled")
    if resolver is None or connector is None:
        return _disabled("external_backend_disabled")
    if not callable(resolver) or not callable(connector):
        raise PureRatDirectTlsError("resolverとconnectorは明示的なcallableが必要です")
    if profile.get("handler") != "purerat_direct_tls":
        raise PureRatDirectTlsError("PureRAT direct-TLS handlerではありません")
    if profile.get("wire_mode") != "direct_tls" or profile.get("tls_version") != "TLSv1.0":
        raise PureRatDirectTlsError("wire modeはdirect TLS 1.0に限定します")
    if profile.get("send_hex") not in (None, "") or int(profile.get("maximum_request_bytes", -1)) != 0:
        raise PureRatDirectTlsError("direct-TLS certificate probeはapplication data送信を許可しません")
    expected = str(profile.get("expected_certificate_sha256") or "").casefold()
    if len(expected) != 64 or any(value not in "0123456789abcdef" for value in expected):
        raise PureRatDirectTlsError("期待証明書SHA-256が不正です")

    resolve = resolver
    connect = connector
    handshake = tls_handshaker or _perform_direct_tls_handshake
    answers, connect_ip = _resolve_loopback(profile, resolve)
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
    probable = version_exact and certificate_exact
    if not version_exact:
        status = "purerat_direct_tls_version_mismatch_inconclusive"
    elif certificate_exact:
        status = "purerat_direct_tls_certificate_match_probable_loopback"
    else:
        status = "purerat_direct_tls_certificate_mismatch"
    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "status": status,
        "profile_id": profile["profile_id"],
        "root_sample_sha256": profile["root_sample_sha256"],
        "terminal_sample_sha256": profile["terminal_sample_sha256"],
        "alive": False,
        "c2_confirmed": False,
        "probable_c2": probable,
        "confidence": 0.75 if probable else 0.0,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "loopback_contact_attempted": True,
        "loopback_connection_established": True,
        "external_target_contact_allowed": False,
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
        "family_attribution_confirmed": False,
        "evidence_scope": "offline_or_numeric_loopback_compatibility_harness",
    }
