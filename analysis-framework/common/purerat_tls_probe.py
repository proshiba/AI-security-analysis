#!/usr/bin/env python3
"""レビュー済みPureRAT endpointへ4-byte prelude後のTLS pin確認だけを行う。"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Callable


PURE_PROTOCOL_PRELUDE = bytes.fromhex("04000000")


class PureRatProbeError(ValueError):
    """PureRAT probeのprofileまたは安全境界が不正な場合のエラー。"""


Resolver = Callable[..., list[tuple[Any, ...]]]
Connector = Callable[[tuple[str, int], float], Any]
TlsHandshaker = Callable[[Any, dict[str, Any]], dict[str, Any]]


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _resolve_and_select(
    profile: dict[str, Any],
    resolver: Resolver,
) -> tuple[tuple[str, ...], str]:
    """対象を一度だけ解決し、任意のIP pinを検証して接続先を固定する。"""
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
        raise PureRatProbeError("global DNS応答を取得できません")
    pinned = tuple(str(value) for value in profile.get("pinned_ips") or [])
    if len(pinned) > 1 or any(not _public_ip(value) for value in pinned):
        raise PureRatProbeError("pinned_ipsは0件または単一global IPに限定します")
    if pinned and pinned[0] not in answers:
        raise PureRatProbeError("現在のDNS応答とreview済みpinned IPが一致しません")
    return answers, pinned[0] if pinned else answers[0]


def _tls_version(value: str) -> ssl.TLSVersion:
    versions = {
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    try:
        return versions[value]
    except KeyError as exc:
        raise PureRatProbeError(f"未レビューのTLS versionです: {value}") from exc


def _perform_tls_handshake(raw_socket: Any, profile: dict[str, Any]) -> dict[str, Any]:
    """prelude送信済みsocket上でTLSを確立し、公開可能なfingerprintだけを返す。"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    version = _tls_version(str(profile["tls_version"]))
    context.minimum_version = version
    context.maximum_version = version
    sni = profile.get("sni")
    server_hostname = str(sni) if isinstance(sni, str) and sni else None
    with context.wrap_socket(
        raw_socket,
        server_hostname=server_hostname,
        do_handshake_on_connect=False,
    ) as tls_socket:
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
        "application_data_sent": False,
        "protocol_prelude_sent": False,
        "protocol_prelude_accepted": False,
        "protocol_response_received": False,
        "victim_metadata_sent": False,
        "registration_attempted": False,
        "task_poll_attempted": False,
        "task_executed": False,
        "payload_download_attempted": False,
        "stage_requested": False,
        "operation_command_sent": False,
        "certificate_mismatch_excludes_c2": False,
        "resolved_ips": [],
    }


def probe_reviewed_purerat_tls(
    profile: dict[str, Any],
    *,
    allow_network: bool = False,
    allow_protocol_prelude: bool = False,
    resolver: Resolver | None = None,
    connector: Connector | None = None,
    tls_handshaker: TlsHandshaker | None = None,
) -> dict[str, Any]:
    """固有prelude受理、TLS成立、設定証明書pin一致を1接続で検証する。"""
    if not allow_network:
        return _disabled("network_disabled")
    if not allow_protocol_prelude:
        return _disabled("purerat_protocol_prelude_disabled")
    if profile.get("handler") != "purerat_tls_prelude":
        raise PureRatProbeError("PureRAT handlerではありません")
    if profile.get("send_hex") != PURE_PROTOCOL_PRELUDE.hex():
        raise PureRatProbeError("PureRAT preludeは04000000だけを許可します")
    if int(profile.get("maximum_request_bytes", 0)) != len(PURE_PROTOCOL_PRELUDE):
        raise PureRatProbeError("PureRAT request上限は4 byteである必要があります")
    expected = str(profile.get("expected_certificate_sha256") or "").casefold()
    if len(expected) != 64 or any(value not in "0123456789abcdef" for value in expected):
        raise PureRatProbeError("期待証明書SHA-256が不正です")

    resolve = resolver or socket.getaddrinfo
    connect = connector or socket.create_connection
    handshake = tls_handshaker or _perform_tls_handshake
    answers, connect_ip = _resolve_and_select(profile, resolve)
    raw_socket = connect(
        (connect_ip, int(profile["port"])),
        float(profile["timeout_seconds"]),
    )
    try:
        raw_socket.settimeout(float(profile["timeout_seconds"]))
        raw_socket.sendall(PURE_PROTOCOL_PRELUDE)
        tls = handshake(raw_socket, profile)
    finally:
        try:
            raw_socket.close()
        except OSError:
            pass

    observed = str(tls.get("certificate_sha256") or "").casefold()
    exact = observed == expected
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": (
            "confirmed_purerat_prelude_tls_certificate"
            if exact
            else "purerat_prelude_tls_certificate_mismatch"
        ),
        "alive": True,
        "c2_confirmed": exact,
        "target_contact_attempted": True,
        "target_connection_established": True,
        "application_data_sent": True,
        "protocol_prelude_sent": True,
        "protocol_prelude_length": len(PURE_PROTOCOL_PRELUDE),
        "protocol_prelude_accepted": True,
        "protocol_response_received": False,
        "tls": {
            "handshake": True,
            "version": tls.get("version"),
            "cipher": tls.get("cipher"),
            "certificate": {
                "state": "exact_match" if exact else "mismatch_inconclusive",
                "exact_match": exact,
                "observed_sha256": observed or None,
                "expected_sha256": expected,
                "certificate_mismatch_excludes_c2": False,
            },
        },
        "certificate_mismatch_excludes_c2": False,
        "resolved_ips": list(answers),
        "connected_ip": connect_ip,
        "victim_metadata_sent": False,
        "registration_attempted": False,
        "task_poll_attempted": False,
        "task_executed": False,
        "payload_download_attempted": False,
        "stage_requested": False,
        "operation_command_sent": False,
    }
