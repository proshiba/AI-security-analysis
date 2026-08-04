#!/usr/bin/env python3
"""レビュー済みC2候補を限定観測し、JSONと日本語Markdownを生成する。"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import ipaddress
import json
import re
import socket
import ssl
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from c2_detector import probe
from c2_protocol_probe_profiles import (
    ProtocolProfileError,
    resolve_profile,
)
from tls_messagepack_probe import probe_reviewed_tls_messagepack
from stealer_registration_probe import probe_reviewed_stealer_registration


HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9.-]+")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ALLOWED_PROTOCOLS = {"dns", "tcp", "http", "https", "tls", "winos", "vvas", "n520", "ftp", "asyncrat", "venomrat", "stealc", "lummastealer", "remusstealer"}
ALLOWED_METHODS = {
    "dns_resolve",
    "tcp_connect",
    "passive_banner",
    "tls_handshake",
    "http_get",
    "winos_heartbeat",
    "vvas_checkin",
    "n520_server_first",
    "ftp_authenticated",
    "asyncrat_tls_messagepack",
    "venomrat_tls_messagepack",
    "stealc_v2_registration_task",
    "lumma_v6_registration_task",
    "remus_registration_task",
}
ACTIVE_PROFILE_METHODS = {
    "winos_heartbeat", "vvas_checkin", "n520_server_first", "ftp_authenticated",
    "asyncrat_tls_messagepack", "venomrat_tls_messagepack",
    "stealc_v2_registration_task", "lumma_v6_registration_task", "remus_registration_task",
}
ALLOWED_TRANSPORTS = {"direct", "tor-socks5"}
METHOD_CEILINGS = {
    "dns_resolve": 0.05,
    "tcp_connect": 0.25,
    "passive_banner": 0.55,
    "tls_handshake": 0.45,
    "http_get": 0.60,
    "winos_heartbeat": 0.95,
    "vvas_checkin": 0.95,
    "n520_server_first": 0.95,
    "ftp_authenticated": 0.95,
    "asyncrat_tls_messagepack": 0.95,
    "venomrat_tls_messagepack": 0.95,
    "stealc_v2_registration_task": 0.95,
    "lumma_v6_registration_task": 0.95,
    "remus_registration_task": 0.95,
}
METHOD_LABELS = {
    "dns_resolve": "DNS解決のみ（接続先port不明、C2 serviceへの接続なし）",
    "tcp_connect": "DNS解決＋単一TCP接続（送受信なし）",
    "passive_banner": "DNS解決＋単一TCP接続＋server-first banner限定受信",
    "tls_handshake": "DNS解決＋単一TLS handshake（application dataなし）",
    "http_get": "DNS解決＋TLS/HTTP GET 1回（redirectなし）",
    "winos_heartbeat": "完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信",
    "vvas_checkin": "完全一致・レビュー済みvvaS check-in 3 byte＋64 byte限定header検証",
    "n520_server_first": "完全一致・N520 TLS server-first 44 byte handshake検証（check-in送信なし）",
    "ftp_authenticated": "完全一致・private資格情報によるFTP USER/PASS/QUIT限定認証（file操作なし）",
    "asyncrat_tls_messagepack": "完全一致・AsyncRAT TLS圧縮MessagePack Ping 1 frame＋64 byte限定応答",
    "venomrat_tls_messagepack": "完全一致・VenomRAT TLS圧縮MessagePack Ping 1 frame＋64 byte限定応答",
    "stealc_v2_registration_task": "完全一致・StealC v2合成端末登録＋loader task取得（最大2要求）",
    "lumma_v6_registration_task": "完全一致・Lumma v6設定登録＋合成hwid task取得（最大2要求）",
    "remus_registration_task": "完全一致・Remus合成端末登録＋step=1 task取得（最大2要求）",
}
SAFE_HTTP_HEADERS = {"server", "content-type", "content-length", "date", "connection"}


class PlanError(ValueError):
    """監視計画が安全制約を満たさない場合のエラー。"""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_plan(plan: dict) -> dict:
    """完全一致ターゲット、上限、根拠、probe種別を検証する。"""
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise PlanError("schema_version=1 のobjectが必要です")
    window = plan.get("analysis_window")
    if not isinstance(window, dict) or not window.get("start") or not window.get("end"):
        raise PlanError("analysis_window.start/end が必要です")
    targets = plan.get("targets")
    if not isinstance(targets, list) or not targets:
        raise PlanError("targets は1件以上のlistである必要があります")
    if len(targets) > 256:
        raise PlanError("1回の監視対象は256 endpoint以下です")

    seen: set[tuple] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise PlanError("targetはobjectである必要があります")
        host = str(target.get("host", "")).lower()
        if not HOST_RE.fullmatch(host) or "*" in host or "/" in host:
            raise PlanError(f"完全一致hostではありません: {host}")
        if not _is_ip(host) and "." not in host:
            raise PlanError(f"FQDNまたはIPではありません: {host}")
        port = target.get("port")
        if not isinstance(port, int) or not 0 <= port <= 65535:
            raise PlanError(f"portが不正です: {port}")
        protocol = target.get("protocol", "tcp")
        method = target.get("method", "tcp_connect")
        transport = target.get("transport", "direct")
        if protocol not in ALLOWED_PROTOCOLS:
            raise PlanError(f"protocolが許可されていません: {protocol}")
        if method not in ALLOWED_METHODS:
            raise PlanError(f"methodが許可されていません: {method}")
        if transport not in ALLOWED_TRANSPORTS:
            raise PlanError(f"transportが許可されていません: {transport}")
        profile_id = target.get("protocol_profile_id")
        profile = None
        if method in ACTIVE_PROFILE_METHODS:
            if not isinstance(profile_id, str) or not profile_id:
                raise PlanError(f"{method}にはprotocol_profile_idが必要です")
            try:
                profile = resolve_profile(profile_id, host, port)
            except ProtocolProfileError as exc:
                raise PlanError(str(exc)) from exc
            if (profile["protocol"], profile["method"]) != (protocol, method):
                raise PlanError("protocol profileとtargetのprotocol/methodが一致しません")
        elif profile_id is not None:
            raise PlanError("protocol_profile_idはレビュー済みactive methodだけに使用できます")
        if host.endswith(".onion") and transport != "tor-socks5":
            raise PlanError(".onionはloopback SOCKS5経由に限定します")
        if not host.endswith(".onion") and transport != "direct":
            raise PlanError("Tor経由は.onion完全一致ターゲットに限定します")
        expected_protocol = {
            "tcp_connect": "tcp",
            "passive_banner": "tcp",
            "tls_handshake": "tls",
            "winos_heartbeat": "winos",
            "vvas_checkin": "vvas",
            "n520_server_first": "n520",
            "ftp_authenticated": "ftp",
            "asyncrat_tls_messagepack": "asyncrat",
            "venomrat_tls_messagepack": "venomrat",
            "stealc_v2_registration_task": "stealc",
            "lumma_v6_registration_task": "lummastealer",
            "remus_registration_task": "remusstealer",
        }.get(method)
        if expected_protocol and protocol != expected_protocol:
            raise PlanError(f"{method}にはprotocol={expected_protocol}が必要です")
        if method == "http_get" and protocol not in {"http", "https"}:
            raise PlanError("http_getにはhttpまたはhttpsが必要です")
        if method == "dns_resolve" and (protocol != "dns" or port != 0):
            raise PlanError("dns_resolveにはprotocol=dns、port=0が必要です")
        if method != "dns_resolve" and port == 0:
            raise PlanError("port=0はdns_resolveだけに使用できます")
        if profile is not None:
            target.setdefault("timeout_seconds", float(profile["timeout_seconds"]))
            target.setdefault("maximum_response_bytes", int(profile["maximum_response_bytes"]))
        timeout = float(target.get("timeout_seconds", 3.0))
        maximum = int(target.get("maximum_response_bytes", 256))
        response_limit = (
            int(profile["maximum_response_bytes"])
            if profile is not None
            else (1024 if method == "ftp_authenticated" else 256)
        )
        if not 0.1 <= timeout <= 5.0 or not 1 <= maximum <= response_limit:
            raise PlanError(f"timeout<=5秒、response<={response_limit} byteを超えています")
        if profile and (
            timeout != float(profile["timeout_seconds"])
            or maximum != int(profile["maximum_response_bytes"])
        ):
            raise PlanError("active protocol probeはレビュー済みtimeout/response上限との完全一致が必要です")
        path = str(target.get("http_path", "/"))
        if "\r" in path or "\n" in path or not path.startswith("/") or len(path) > 512:
            raise PlanError("HTTP pathが不正です")
        if any(key in target for key in ("send_hex", "payload", "cidr", "ports", "checkin")):
            raise PlanError("payload、check-in、range scanは監視計画へ指定できません")
        samples = target.get("sample_sha256s", [])
        if not isinstance(samples, list) or any(not SHA256_RE.fullmatch(str(x)) for x in samples):
            raise PlanError("sample_sha256sが不正です")
        sources = target.get("sources")
        if not isinstance(sources, list) or not sources or any(not str(x).strip() for x in sources):
            raise PlanError("各targetに1件以上の根拠sourcesが必要です")
        key = (host, port, protocol, path, transport)
        if key in seen:
            raise PlanError(f"重複targetです: {key}")
        seen.add(key)
        target["host"] = host
    return plan


def _probe_args(target: dict, allow_network: bool) -> SimpleNamespace:
    method = target.get("method", "tcp_connect")
    profile = (
        resolve_profile(target["protocol_profile_id"], target["host"], target["port"])
        if target.get("protocol_profile_id")
        else {}
    )
    return SimpleNamespace(
        host=target["host"],
        port=target["port"],
        protocol=target.get("protocol", "tcp"),
        timeout=float(target.get("timeout_seconds", 3.0)),
        max_bytes=int(target.get("maximum_response_bytes", 256)),
        send_hex=profile.get("send_hex"),
        expected_stage_size=int(profile.get("expected_stage_size", 0)),
        expected_header_size=int(profile.get("expected_header_size", 0)),
        http_path=target.get("http_path", "/"),
        http_host=target.get("http_host"),
        sni=profile.get("sni") or target.get("sni"),
        mxgo_mode="preview",
        mxgo_client_id="LAB-MXGO-000000000000",
        mxgo_recipient_path="/fixture.txt",
        n520_checkin=False,
        n520_wait=1.0,
        n520_max_bytes=256,
        n520_max_frames=1,
        artifact_zip=None,
        archive_password="infected",
        proxy_host="127.0.0.1" if target.get("transport") == "tor-socks5" else None,
        proxy_port=int(target.get("proxy_port", 9050)),
        collect_jarm=False,
        jarm_script=None,
        allow_network=allow_network,
        target_role="c2",
        sample_sha256=target.get("sample_sha256s", []),
        connect_only=method == "tcp_connect",
    )


def _probe_winos_reviewed(profile: dict, allow_network: bool) -> dict:
    """既存のreview済みWinos実装を明示pathから読み、完全一致profileだけを渡す。"""
    if not allow_network:
        return {
            "status": "network_disabled",
            "connected": False,
            "sent_bytes": 0,
            "received_bytes": 0,
            "dns_answers": [],
            "response": None,
            "stage_requested": False,
            "victim_metadata_sent": False,
            "operation_command_sent": False,
        }
    module_path = (
        Path(__file__).parents[1]
        / "malware"
        / "valleyrat"
        / "campaigns"
        / "signed_proxy_sideload"
        / "winos_protocol.py"
    )
    spec = importlib.util.spec_from_file_location("reviewed_winos_protocol", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("review済みWinos protocol moduleを読み込めません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.probe_reviewed_endpoint(
        profile["host"],
        profile["port"],
        profile["pinned_ips"][0],
        allow_live=True,
        timeout=float(profile["timeout_seconds"]),
    )


def _winos_observation(target: dict, allow_network: bool) -> dict:
    """Winos heartbeatを共通observatonへ正規化し、operation commandは保持しない。"""
    timestamp = datetime.now(timezone.utc).isoformat()
    profile = resolve_profile(target["protocol_profile_id"], target["host"], target["port"])
    try:
        raw = _probe_winos_reviewed(profile, allow_network)
    except ConnectionRefusedError:
        return {
            "timestamp_utc": timestamp,
            "status": "closed",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": True,
            "target_connection_established": False,
            "application_data_sent": False,
            "resolved_ips": [],
            "stage_requested": False,
            "victim_metadata_sent": False,
            "operation_command_sent": False,
        }
    except (socket.timeout, TimeoutError):
        return {
            "timestamp_utc": timestamp,
            "status": "timeout",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": True,
            "target_connection_established": False,
            "application_data_sent": False,
            "resolved_ips": [],
            "stage_requested": False,
            "victim_metadata_sent": False,
            "operation_command_sent": False,
        }
    except (OSError, ValueError, RuntimeError) as exc:
        dns_pin_failed = "DNS answer" in str(exc)
        return {
            "timestamp_utc": timestamp,
            "status": "dns_pin_mismatch" if dns_pin_failed else "probe_error",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": not dns_pin_failed,
            "target_connection_established": False,
            "application_data_sent": False,
            "error_type": type(exc).__name__,
            "resolved_ips": [],
            "stage_requested": False,
            "victim_metadata_sent": False,
            "operation_command_sent": False,
        }
    response = raw.get("response") if isinstance(raw.get("response"), dict) else None
    command = response.get("command") if response else None
    response_complete = bool(response and response.get("complete"))
    confirmed = response_complete and command in {0xC9, 0xCA, 0xCB}
    sent = int(raw.get("sent_bytes") or 0)
    received = int(raw.get("received_bytes") or 0)
    return {
        "timestamp_utc": timestamp,
        "status": (
            "confirmed_winos_c2" if confirmed else ("winos_protocol_mismatch" if received else "connected_no_response")
        ),
        "alive": bool(raw.get("connected")),
        "c2_confirmed": confirmed,
        "target_contact_attempted": allow_network,
        "target_connection_established": bool(raw.get("connected")),
        "application_data_sent": sent > 0,
        "heartbeat_sent": sent > 0,
        "protocol_response_received": received > 0,
        "resolved_ips": list(raw.get("dns_answers") or []),
        "pinned_ip": raw.get("pinned_ip"),
        "sent_bytes": sent,
        "received_bytes": received,
        "winos_response": (
            {
                "declared_length": response.get("declared_length"),
                "command": command,
                "role": response.get("role"),
                "complete": response_complete,
            }
            if response
            else None
        ),
        "stage_requested": False,
        "victim_metadata_sent": False,
        "operation_command_sent": False,
    }


def _load_agenttesla_c2_module():
    """共通c2_detectorとの名前衝突を避け、AgentTesla固有moduleを読み込む。"""

    module_path = Path(__file__).parents[1] / "malware" / "agenttesla" / "c2_detector.py"
    spec = importlib.util.spec_from_file_location("agenttesla_c2_detector_private", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("AgentTesla C2 detectorを読み込めません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _agenttesla_ftp_observation(
    target: dict,
    allow_network: bool,
    allow_authentication: bool,
    private_credential_vault: Path | None,
) -> dict:
    """完全一致private資格情報でFTP認証だけを確認し、秘密値とraw replyを破棄する。"""

    timestamp = datetime.now(timezone.utc).isoformat()
    disabled = {
        "timestamp_utc": timestamp,
        "alive": False,
        "c2_confirmed": False,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "application_data_sent": False,
        "authentication_attempted": False,
        "authentication_accepted": False,
        "credential_material_published": False,
        "file_transfer_attempted": False,
        "directory_operation_attempted": False,
        "stage_requested": False,
        "victim_metadata_sent": False,
        "operation_command_sent": False,
        "resolved_ips": [],
    }
    if not allow_network:
        return {**disabled, "status": "network_disabled"}
    if not allow_authentication:
        return {**disabled, "status": "authentication_disabled"}
    if private_credential_vault is None:
        return {**disabled, "status": "private_credential_vault_missing"}
    profile = resolve_profile(target["protocol_profile_id"], target["host"], target["port"])
    try:
        module = _load_agenttesla_c2_module()
        credential = module.load_private_ftp_credential(
            private_credential_vault,
            profile["credential_reference"],
            profile["host"],
            profile["port"],
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return {
            **disabled,
            "status": "private_credential_vault_error",
            "error_type": type(exc).__name__,
        }
    try:
        raw = module.probe_ftp_authenticated(
            profile["host"],
            profile["port"],
            credential,
            timeout=float(profile["timeout_seconds"]),
        )
    except ConnectionRefusedError:
        return {**disabled, "status": "closed", "target_contact_attempted": True}
    except (socket.timeout, TimeoutError):
        return {**disabled, "status": "timeout", "target_contact_attempted": True}
    except (OSError, ValueError, RuntimeError) as exc:
        return {
            **disabled,
            "status": "ftp_authentication_probe_error",
            "target_contact_attempted": True,
            "error_type": type(exc).__name__,
        }
    accepted = bool(raw.get("authentication_accepted"))
    return {
        "timestamp_utc": timestamp,
        "status": "confirmed_ftp_credential_endpoint" if accepted else "ftp_authentication_rejected",
        "alive": True,
        "c2_confirmed": accepted,
        "target_contact_attempted": True,
        "target_connection_established": True,
        "application_data_sent": True,
        "protocol_response_received": True,
        "authentication_attempted": True,
        "authentication_accepted": accepted,
        "credential_material_published": False,
        "file_transfer_attempted": False,
        "directory_operation_attempted": False,
        "commands_sent": raw.get("commands_sent", []),
        "banner": raw.get("banner"),
        "user_reply_code": raw.get("user_reply_code"),
        "pass_reply_code": raw.get("pass_reply_code"),
        "quit_reply_code": raw.get("quit_reply_code"),
        "resolved_ips": raw.get("resolved_addresses", []),
        "stage_requested": False,
        "victim_metadata_sent": False,
        "operation_command_sent": False,
    }


def _tls_messagepack_observation(
    target: dict,
    allow_network: bool,
    allow_application_probe: bool,
) -> dict:
    """AsyncRAT／VenomRATの完全一致TLS MessagePack profileを限定観測する。"""

    profile = resolve_profile(target["protocol_profile_id"], target["host"], target["port"])
    try:
        return probe_reviewed_tls_messagepack(
            profile,
            allow_network=allow_network,
            allow_application_probe=allow_application_probe,
        )
    except ConnectionRefusedError:
        status = "closed"
    except (socket.timeout, TimeoutError):
        status = "timeout"
    except ssl.SSLError:
        status = "tls_handshake_failed"
    except (OSError, ValueError, RuntimeError) as exc:
        return {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "tls_messagepack_probe_error",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": allow_network,
            "target_connection_established": False,
            "application_data_sent": False,
            "error_type": type(exc).__name__,
            "certificate_mismatch_excludes_c2": False,
            "resolved_ips": [],
            "stage_requested": False,
            "victim_metadata_sent": False,
            "operation_command_sent": False,
        }
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "alive": False,
        "c2_confirmed": False,
        "target_contact_attempted": allow_network,
        "target_connection_established": False,
        "application_data_sent": False,
        "certificate_mismatch_excludes_c2": False,
        "resolved_ips": [],
        "stage_requested": False,
        "victim_metadata_sent": False,
        "operation_command_sent": False,
    }

def _stealer_registration_observation(
    target: dict,
    allow_network: bool,
    allow_registration_tasking: bool,
) -> dict:
    """StealC／Lumma／Remusの合成端末登録とtask取得を正規化する。"""

    profile = resolve_profile(target["protocol_profile_id"], target["host"], target["port"])
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        result = probe_reviewed_stealer_registration(
            profile,
            allow_network=allow_network,
            allow_registration_tasking=allow_registration_tasking,
        )
    except ConnectionRefusedError:
        status = "closed"
    except (socket.timeout, TimeoutError):
        status = "timeout"
    except (OSError, ValueError, RuntimeError) as exc:
        return {
            "timestamp_utc": timestamp,
            "status": "stealer_registration_probe_error",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": allow_network and allow_registration_tasking,
            "target_connection_established": False,
            "application_data_sent": False,
            "error_type": type(exc).__name__,
            "registration_attempted": False,
            "task_poll_attempted": False,
            "task_content_published": False,
            "task_executed": False,
            "payload_download_attempted": False,
            "victim_metadata_sent": False,
            "resolved_ips": [],
        }
    else:
        return {"timestamp_utc": timestamp, **result}
    return {
        "timestamp_utc": timestamp,
        "status": status,
        "alive": False,
        "c2_confirmed": False,
        "target_contact_attempted": True,
        "target_connection_established": False,
        "application_data_sent": False,
        "registration_attempted": True,
        "task_poll_attempted": False,
        "task_content_published": False,
        "task_executed": False,
        "payload_download_attempted": False,
        "victim_metadata_sent": False,
        "resolved_ips": [],
    }


def _dns_observation(target: dict, allow_network: bool) -> dict:
    """port不明FQDNをDNS解決だけで観測し、C2到達とは扱わない。"""
    timestamp = datetime.now(timezone.utc).isoformat()
    if not allow_network:
        return {
            "timestamp_utc": timestamp,
            "status": "network_disabled",
            "alive": False,
            "dns_resolution_attempted": False,
            "target_contact_attempted": False,
            "target_connection_established": False,
            "resolved_ips": [],
        }
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(target["host"], None, type=socket.SOCK_STREAM)}
    except OSError as exc:
        return {
            "timestamp_utc": timestamp,
            "status": "dns_resolution_failed",
            "alive": False,
            "dns_resolution_attempted": True,
            "target_contact_attempted": False,
            "target_connection_established": False,
            "resolution_error": type(exc).__name__,
            "resolved_ips": [],
        }
    return {
        "timestamp_utc": timestamp,
        "status": "dns_resolved",
        "alive": False,
        "dns_resolution_attempted": True,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "resolved_ips": sorted(addresses),
    }


def _sanitize_observation(observation: dict) -> dict:
    """banner本文やcookie等を公開結果へ残さずfingerprintだけ保持する。"""
    value = dict(observation)
    banner = value.get("banner")
    if isinstance(banner, dict):
        banner = dict(banner)
        prefix = banner.pop("prefix_base64", None)
        if prefix:
            try:
                decoded = base64.b64decode(prefix, validate=True)
            except (ValueError, TypeError):
                decoded = b""
            banner["ftp_220_marker"] = decoded.startswith(b"220")
        value["banner"] = banner
    http = value.get("http")
    if isinstance(http, dict):
        http = dict(http)
        headers = http.get("headers")
        if isinstance(headers, dict):
            http["headers"] = {
                str(key).lower(): val for key, val in headers.items() if str(key).lower() in SAFE_HTTP_HEADERS
            }
        value["http"] = http
    value.pop("sent_hex", None)
    return value


def assess_observation(target: dict, observation: dict) -> dict:
    """到達性とC2稼働確度を分離して評価する。"""
    method = target.get("method", "tcp_connect")
    ceiling = METHOD_CEILINGS[method]
    status = observation.get("status", "unknown")
    tcp_open = observation.get("tcp_status") == "open" or bool(observation.get("target_connection_established"))
    http_status = (observation.get("http") or {}).get("status")
    banner = observation.get("banner") or {}
    tls = observation.get("tls") or {}

    if status in {
        "network_disabled",
        "authentication_disabled",
        "private_credential_vault_missing",
        "private_credential_vault_error",
        "tls_handshake_only_application_probe_disabled",
        "malware_registration_tasking_disabled",
    } and not observation.get("target_contact_attempted"):
        return {
            "state": "not_observed_safety_gate",
            "reachability_confidence": 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "安全gateが未充足のためprotocol-level観測を実施していない",
        }

    if method == "dns_resolve":
        resolved = bool(observation.get("resolved_ips"))
        return {
            "state": "dns_resolved_c2_service_not_confirmed" if resolved else "dns_not_resolved",
            "reachability_confidence": 0.15 if resolved else 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0 if resolved else 0.50,
            "reason": (
                "FQDN/IPは解決できたがport不明のためC2 serviceへ未接続"
                if resolved
                else "DNS解決結果なし。port不明のためC2 serviceへ未接続"
            ),
        }

    if observation.get("c2_confirmed"):
        return {
            "state": "c2_protocol_confirmed",
            "reachability_confidence": 1.0,
            "c2_operational_confidence": 0.95,
            "method_confidence_ceiling": max(0.95, ceiling),
            "negative_observation_confidence": 0.0,
            "reason": "review済みmalware固有protocol応答が一致",
        }
    if observation.get("protocol_response_received"):
        return {
            "state": "application_endpoint_reachable_c2_not_confirmed",
            "reachability_confidence": 0.98,
            "c2_operational_confidence": min(0.60, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "application protocol応答を受信したがreview済み期待応答との一致は未確認",
        }
    if http_status is not None:
        return {
            "state": "application_endpoint_reachable_c2_not_confirmed",
            "reachability_confidence": 0.95,
            "c2_operational_confidence": min(0.60, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "限定HTTP応答を確認したが所有者・C2 protocolは未確認",
        }
    if banner.get("length"):
        app_score = 0.50 if banner.get("ftp_220_marker") else 0.45
        return {
            "state": "server_first_response_reachable_c2_not_confirmed",
            "reachability_confidence": 0.95,
            "c2_operational_confidence": min(app_score, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "server-first応答を確認したがmalware固有fingerprintではない",
        }
    if tls:
        return {
            "state": "tls_endpoint_reachable_c2_not_confirmed",
            "reachability_confidence": 0.95,
            "c2_operational_confidence": min(0.40, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": (
                "TLS handshakeは成立した。証明書不一致は非C2の除外根拠にせず、application protocolは未確認"
                if ((tls.get("certificate") or {}).get("state") == "mismatch_inconclusive")
                else "TLS handshake成立のみでC2は未確認"
            ),
        }
    if tcp_open or observation.get("alive"):
        return {
            "state": "transport_reachable_c2_not_confirmed",
            "reachability_confidence": 0.90,
            "c2_operational_confidence": min(0.25, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "TCP到達性のみでC2 applicationは未確認",
        }
    proxy_unavailable = target.get("transport") == "tor-socks5" and not observation.get("target_contact_attempted")
    if proxy_unavailable:
        return {
            "state": "not_observed_proxy_unavailable",
            "reachability_confidence": 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "loopback Tor SOCKS5へ接続できず対象へ到達していない",
        }
    negative = 0.85 if status == "closed" else (0.70 if observation.get("resolution_error") else 0.40)
    return {
        "state": "not_reachable_at_observation",
        "reachability_confidence": 0.0,
        "c2_operational_confidence": 0.0,
        "method_confidence_ceiling": ceiling,
        "negative_observation_confidence": negative,
        "reason": "この観測時点では到達応答なし。停止の恒久判定ではない",
    }


def monitor(
    plan: dict,
    *,
    allow_network: bool = False,
    allow_application_probes: bool = False,
    allow_authentication: bool = False,
    allow_malware_registration: bool = False,
    private_credential_vault: Path | None = None,
) -> dict:
    """レビュー済み対象を各1回だけ観測する。"""
    plan = validate_plan(plan)
    results = []
    for target in plan["targets"]:
        method = target.get("method", "tcp_connect")
        if method == "dns_resolve":
            raw = _dns_observation(target, allow_network)
        elif method == "winos_heartbeat":
            raw = _winos_observation(target, allow_network)
        elif method == "ftp_authenticated":
            raw = _agenttesla_ftp_observation(
                target,
                allow_network,
                allow_authentication,
                private_credential_vault,
            )
        elif method in {"asyncrat_tls_messagepack", "venomrat_tls_messagepack"}:
            raw = _tls_messagepack_observation(
                target,
                allow_network,
                allow_application_probes,
            )
        elif method in {
            "stealc_v2_registration_task", "lumma_v6_registration_task", "remus_registration_task",
        }:
            raw = _stealer_registration_observation(
                target, allow_network, allow_malware_registration
            )
        else:
            raw = probe(_probe_args(target, allow_network))
        observation = _sanitize_observation(raw)
        results.append(
            {
                "target_id": target.get("target_id"),
                "family": target.get("family", "unknown"),
                "host": target["host"],
                "port": target["port"],
                "protocol": target.get("protocol", "tcp"),
                "transport": target.get("transport", "direct"),
                "method": target.get("method", "tcp_connect"),
                "protocol_profile_id": target.get("protocol_profile_id"),
                "method_description": METHOD_LABELS[target.get("method", "tcp_connect")],
                "http_path": target.get("http_path") if target.get("method") == "http_get" else None,
                "sample_sha256s": target.get("sample_sha256s", []),
                "associated_case_count": int(
                    target.get("associated_case_count", len(target.get("sample_sha256s", [])))
                ),
                "analyzed_dates": target.get("analyzed_dates", []),
                "sources": target["sources"],
                "observation": observation,
                "assessment": assess_observation(target, observation),
            }
        )
    counts = Counter(item["assessment"]["state"] for item in results)
    reviewed_message_results = [
        item
        for item in results
        if item["method"] in {
            "winos_heartbeat", "vvas_checkin", "asyncrat_tls_messagepack", "venomrat_tls_messagepack",
            "stealc_v2_registration_task", "lumma_v6_registration_task", "remus_registration_task",
        } and item["observation"].get("application_data_sent")
    ]
    reviewed_protocol_probe_count = sum(bool(item.get("protocol_profile_id")) for item in results)
    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_window": plan["analysis_window"],
        "collection_scope": plan.get("collection_scope", "provided_targets"),
        "onion_excluded_by_policy": bool(plan.get("onion_excluded_by_policy", False)),
        "inventory_summary": plan.get("inventory_summary", {}),
        "policy": {
            "exact_targets_only": True,
            "one_bounded_probe_per_target": True,
            "maximum_application_requests_per_target": 2,
            "maximum_timeout_seconds": 5,
            "maximum_response_bytes": max(
                (int(target.get("maximum_response_bytes", 256)) for target in plan["targets"]),
                default=256,
            ),
            "redirect_followed": False,
            "malware_checkin_sent": bool(reviewed_message_results),
            "reviewed_heartbeat_or_checkin_sent_count": len(reviewed_message_results),
            "reviewed_protocol_probe_count": reviewed_protocol_probe_count,
            "protocol_profile_registry_enforced": True,
            "stage_requested": any(bool(item["observation"].get("stage_requested")) for item in results),
            "victim_metadata_sent": any(
                bool(item["observation"].get("victim_metadata_sent")) for item in results
            ),
            "command_polling_performed": any(
                bool(item["observation"].get("task_poll_attempted")) for item in results
            ),
            "malware_registration_tasking_enabled": allow_malware_registration,
            "registration_attempted_count": sum(
                bool(item["observation"].get("registration_attempted")) for item in results
            ),
            "task_poll_attempted_count": sum(
                bool(item["observation"].get("task_poll_attempted")) for item in results
            ),
            "task_available_count": sum(
                item["observation"].get("task_available") is True for item in results
            ),
            "task_content_published": False,
            "task_executed": False,
            "payload_download_attempted": False,
            "range_scan_performed": False,
            "tcp_open_confirms_c2": False,
            "network_enabled": allow_network,
            "reviewed_application_probes_enabled": allow_application_probes,
            "private_authentication_enabled": allow_authentication,
            "reviewed_malware_registration_enabled": allow_malware_registration,
            "private_credential_vault_used": private_credential_vault is not None,
            "authentication_attempted_count": sum(
                bool(item["observation"].get("authentication_attempted")) for item in results
            ),
            "file_transfer_attempted": any(
                bool(item["observation"].get("file_transfer_attempted")) for item in results
            ),
            "certificate_mismatch_excludes_c2": False,
        },
        "target_count": len(results),
        "state_counts": dict(sorted(counts.items())),
        "results": results,
    }


def _defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def _endpoint_label(item: dict) -> str:
    host = _defang_host(str(item.get("host") or "-"))
    port = int(item.get("port") or 0)
    return f"`{host}:{port}`" if port else f"`{host}`（DNSのみ）"


def _score(value: float) -> str:
    label = "高" if value >= 0.80 else ("中" if value >= 0.40 else "低")
    return f"{value:.2f}（{label}）"


def _markdown_cell(value: object) -> str:
    return str(value or "-").replace("|", "\\|").replace("\n", "<br>")


def _ip_detail_cell(detail: dict) -> str:
    address = _defang_host(str(detail.get("ip") or "-"))
    as_record = detail.get("as") if isinstance(detail.get("as"), dict) else {}
    geo = detail.get("geo") if isinstance(detail.get("geo"), dict) else {}
    infrastructure = detail.get("infrastructure") if isinstance(detail.get("infrastructure"), dict) else {}
    asn = as_record.get("asn")
    organization = as_record.get("organization") or "組織不明"
    as_label = f"AS{asn} / {organization}" if asn else organization
    geo_label = (
        " / ".join(
            str(value)
            for value in (
                geo.get("country_name"),
                geo.get("subdivision_name"),
                geo.get("city_name"),
            )
            if value
        )
        or "Geo未取得"
    )
    tags = (
        "、".join(
            str(tag.get("label"))
            for tag in infrastructure.get("tags", [])
            if isinstance(tag, dict) and tag.get("label")
        )
        or "タグなし"
    )
    bulletproof = (
        infrastructure.get("bulletproof_hosting") if isinstance(infrastructure.get("bulletproof_hosting"), dict) else {}
    )
    bulletproof_label = bulletproof.get("label") or "防弾ホスティング判定不能"
    return _markdown_cell(f"`{address}`<br>{as_label}<br>{geo_label}<br>{tags}<br>{bulletproof_label}")


def _transition_side(details: list[dict]) -> str:
    if not details:
        return "解決なし"
    return "<br><br>".join(_ip_detail_cell(detail) for detail in details)


def render_markdown(result: dict) -> str:
    """監視結果を人がレビューしやすい日本語一覧表へ変換する。"""
    lifecycle_labels = {
        "active_on": "継続監視（ON）",
        "active_grace": "継続監視（OFF猶予）",
        "active_unobserved": "継続監視（未観測）",
        "retired_stopped": "停止（監視対象外）",
    }
    rows = []
    for item in result["results"]:
        assessment = item["assessment"]
        observation = item["observation"]
        endpoint = _endpoint_label(item)
        if item.get("http_path"):
            endpoint += f" `{item['http_path']}`"
        checked = observation.get("timestamp_utc", "-")
        methods = item["method_description"]
        if item["transport"] == "tor-socks5":
            methods += "（localhost Tor SOCKS5経由）"
        result_text = f"{assessment['state']} / {assessment['reason']}"
        lifecycle = item.get("monitoring_lifecycle") or {}
        if lifecycle.get("status"):
            lifecycle_status = lifecycle["status"]
            result_text += f"<br>監視状態: {lifecycle_labels.get(lifecycle_status, lifecycle_status)}"
        confidence = (
            f"到達 {_score(assessment['reachability_confidence'])}<br>"
            f"C2稼働 {_score(assessment['c2_operational_confidence'])}<br>"
            f"手法上限 {_score(assessment['method_confidence_ceiling'])}"
        )
        source = "<br>".join(item["sources"][:3])
        rows.append(
            f"| {item['family']} | {endpoint} | {item['associated_case_count']} | {checked} | "
            f"{methods} | {result_text} | {confidence} | {source} |"
        )
    counts = result.get("state_counts", {})
    summary = "、".join(f"{key}: {value}" for key, value in sorted(counts.items())) or "なし"
    inventory = result.get("inventory_summary") or {}
    coverage_summary = (
        f"全{inventory.get('scanned_ioc_file_count', 0)} IOCファイルを走査し、"
        f"通常IP/FQDN {inventory.get('ordinary_candidate_host_count', 0)} hostのうち"
        f"{inventory.get('planned_ordinary_host_count', 0)} hostを計画へ反映"
        f"（カバレッジ {inventory.get('ordinary_host_coverage_percent', 0):.2f}%）。"
        f"既知port {inventory.get('network_service_endpoint_count', 0)} endpoint、"
        f"port不明 {inventory.get('dns_only_target_count', 0)} hostはDNS-onlyです。"
        f"レビュー済みmalware固有protocolは {inventory.get('reviewed_protocol_target_count', 0)} endpointへ適用しました。"
        if inventory
        else ""
    )
    history_summary = result.get("monitoring_history_summary") or {}
    raw_ip_changes = sum(
        (item.get("dns_tracking") or {}).get("raw_ip_change_count", 0) for item in result.get("results", [])
    )
    infrastructure_ip_changes = sum(
        (item.get("dns_tracking") or {}).get("infrastructure_ip_change_count", 0) for item in result.get("results", [])
    )
    ignored_cdn_rotations = sum(
        (item.get("dns_tracking") or {}).get("shared_cdn_rotation_ignored_count", 0)
        for item in result.get("results", [])
    )
    ip_detail_rows = []
    transition_rows = []
    transition_labels = {
        "infrastructure_ip_change": "C2インフラIP変化",
        "shared_cdn_rotation_ignored": "共有CDNローテーション（除外）",
        "resolution_state_changed": "DNS解決状態変化",
        "raw_ip_change_unclassified": "未分類IP変化",
    }
    for item in result.get("results", []):
        endpoint = _endpoint_label(item)
        dns_tracking = item.get("dns_tracking") or {}
        dns_history = dns_tracking.get("history") or []
        latest_point = dns_history[-1] if dns_history else {}
        for detail in latest_point.get("ip_details", []):
            infrastructure = detail.get("infrastructure") or {}
            bulletproof = infrastructure.get("bulletproof_hosting") or {}
            as_record = detail.get("as") or {}
            geo = detail.get("geo") or {}
            tags = (
                "、".join(
                    str(tag.get("label"))
                    for tag in infrastructure.get("tags", [])
                    if isinstance(tag, dict) and tag.get("label")
                )
                or "タグなし"
            )
            geo_label = (
                " / ".join(
                    str(value)
                    for value in (
                        geo.get("country_name"),
                        geo.get("subdivision_name"),
                        geo.get("city_name"),
                    )
                    if value
                )
                or "未取得"
            )
            asn = as_record.get("asn")
            as_label = (
                f"AS{asn} / {as_record.get('organization') or '組織不明'}"
                if asn
                else as_record.get("organization") or "未取得"
            )
            ip_detail_rows.append(
                f"| {endpoint} | `{_defang_host(str(detail.get('ip') or '-'))}` | "
                f"{_markdown_cell(as_label)} | {_markdown_cell(geo_label)} | "
                f"{_markdown_cell(tags)} | {_markdown_cell(bulletproof.get('label') or '判定不能')} |"
            )
        for transition in dns_tracking.get("transitions", []):
            classification = transition.get("classification")
            transition_rows.append(
                f"| {endpoint} | {transition.get('observed_at_utc') or '-'} | "
                f"{_transition_side(transition.get('from') or [])} | "
                f"{_transition_side(transition.get('to') or [])} | "
                f"{transition_labels.get(classification, classification or '未分類')} |"
            )
    ip_detail_section = [
        "## 最新IPのAS・Geo・インフラタグ",
        "",
        "| endpoint | IP | AS / 組織 | Geo | タグ | 防弾ホスティング評価 |",
        "|---|---|---|---|---|---|",
        *(ip_detail_rows or ["| - | - | - | - | - | 解決IPなし |"]),
        "",
        "`防弾ホスティング`は明示的なprovider評価、`防弾ホスティング - 疑い`は高密度C2悪用等の状況証拠に基づきます。単一の悪性IP観測だけでは付与しません。完全な理由とOSINT sourceはJSONの`infrastructure.bulletproof_hosting`を参照してください。",
        "",
    ]
    transition_section = [
        "## 旧IPから新IPへの遷移",
        "",
        "| endpoint | 観測時刻（UTC） | 旧IP（AS・Geo・タグ） | 新IP（AS・Geo・タグ） | 分類 |",
        "|---|---|---|---|---|",
        *(transition_rows or ["| - | - | - | - | 現時点ではIP遷移なし |"]),
        "",
    ]
    policy = result.get("policy") or {}
    if policy.get("malware_checkin_sent"):
        active_probe_policy = (
            f"レビュー済み完全一致profileに限り、malware固有protocol要求を"
            f"合計{policy.get('reviewed_heartbeat_or_checkin_sent_count', 0)}対象へ送信しました。"
            "送信内容はprofile固定または合成IDだけで、実ホストのvictim metadataを含みません。"
        )
    else:
        active_probe_policy = "今回、レビュー済みmalware固有protocol要求は対象へ送信されませんでした。"
    if policy.get("task_poll_attempted_count", 0):
        active_probe_policy += (
            f"StealC／Lumma／Remusでは登録後のtask取得を"
            f"{policy.get('task_poll_attempted_count', 0)}対象へ各1回試行しました。"
            "task本文・token・合成IDは公開せず、task実行、URL追跡、payload取得は行っていません。"
        )
    else:
        active_probe_policy += "task取得、task実行、payload取得は行っていません。"
    if policy.get("authentication_attempted_count", 0):
        authentication_policy = (
            f"AgentTesla FTPはprivate vaultの完全一致資格情報で"
            f"{policy.get('authentication_attempted_count', 0)}回認証を試行しました。"
            "USER／必要時のPASS／QUITだけを送信し、資格情報値とraw replyは保存していません。"
        )
    else:
        authentication_policy = "認証情報は使用していません。"
    scope = str(result.get("collection_scope") or "provided_targets")
    if scope == "all_historical_c2":
        report_title = "# 全解析履歴のC2稼働状況"
        scope_description = (
            "`.onion`はユーザー指定により対象外です。通常のIP/FQDNは、"
            "C2/control/exfil等の役割根拠を持つ全履歴IOCから自動抽出しています。"
        )
    else:
        report_title = "# 対象限定のC2稼働状況"
        scope_description = (
            f"監視scopeは `{scope}` です。`.onion`は対象外で、"
            "入力planへ明示した根拠付きendpointだけを確認しています。"
        )
    return "\n".join(
        [
            report_title,
            "",
            f"対象期間は `{result['analysis_window']['start']}` から `{result['analysis_window']['end']}`、監視対象は {result['target_count']} endpointです。状態内訳は {summary} です。",
            "",
            coverage_summary,
            "",
            scope_description,
            "",
            "この結果は観測時点のスナップショットです。TCP open、TLS証明書、一般HTTP/FTP応答だけではC2を確定しません。到達性とC2稼働確度を分離します。OFFが7日以上継続し、2回以上の実観測がある対象だけを停止扱いにして次回active対象から外します。",
            "",
            "## 一覧",
            "",
            "| ファミリー | endpoint | 関連case数 | 確認時刻（UTC） | 確認方法 | 観測結果 | confidence | 根拠 |",
            "|---|---|---:|---|---|---|---|---|",
            *rows,
            "",
            "## confidenceの読み方",
            "",
            "- `到達`: 今回のtransport／application到達観測の確からしさです。",
            "- `C2稼働`: 観測結果が、解析済みmalwareのC2 application稼働を示す確度です。TCP接続だけなら最大0.25です。",
            "- `手法上限`: その確認方法が、成功時でも単独で到達できるC2確度の上限です。malware check-inやmalware固有protocolとの一致がない限り0.60以下です。",
            "- `negative_observation_confidence` はJSONに保持し、拒否は比較的強い停止側観測、timeoutは弱い停止側観測として区別します。",
            "",
            "## DNS/IP遷移履歴",
            "",
            f"raw IP変化は {raw_ip_changes} 回、CDN除外後のインフラIP変化は {infrastructure_ip_changes} 回、同一共有CDN内ローテーションとして除外した変化は {ignored_cdn_rotations} 回です。",
            "",
            "Cloudflare、Akamai、Fastly等の共有CDNでは、同一provider内のedge IP入替を履歴へ残しますが、C2インフラ自体のIP変化件数には加えません。providerまたは非CDN ASNが変わった場合はインフラ変化として扱います。詳細は `monitoring-history.json` の `dns_tracking.history` を参照してください。",
            "",
            *transition_section,
            *ip_detail_section,
            "## 継続監視と停止履歴",
            "",
            f"次回active対象は {history_summary.get('active_target_count', result.get('target_count', 0))} 件、停止履歴へ移した対象は {history_summary.get('retired_target_count', 0)} 件です。ONの対象、7日未満のOFF、proxy利用不可等の未観測対象は継続監視します。",
            "",
            "停止条件は、最後のON以後または初回OFFから7日以上が経過し、その期間に2回以上のOFF実観測があり、最新観測もOFFであることです。単発timeoutや未観測だけでは停止しません。次回対象は `active-targets.json`、停止を含む全履歴は `monitoring-history.json` を参照してください。",
            "",
            "## 安全境界",
            "",
            f"既知portは完全一致host・単一portへ各1回、port不明hostはDNS解決だけを行い、timeout最大5秒、応答最大{policy.get('maximum_response_bytes', 256)} byteで確認しました。"
            + active_probe_policy
            + authentication_policy
            + "port range、redirect追跡は使用していません。`.onion`は本監視の対象外です。",
            "",
            "機械可読の完全な根拠、DNS解決先、証明書／banner hash、個別timeoutは [monitoring-results.json](monitoring-results.json)、今回の実効対象は [effective-targets.json](effective-targets.json)、次回active対象は [active-targets.json](active-targets.json) を参照してください。",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="レビュー済みC2の限定監視と日本語結果生成")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument(
        "--allow-reviewed-application-probes",
        action="store_true",
        help="完全一致profileの匿名Ping 1 frameを許可します。",
    )
    parser.add_argument(
        "--allow-authentication",
        action="store_true",
        help="完全一致AgentTesla FTP profileのUSER/PASS/QUIT限定認証を許可します。",
    )
    parser.add_argument(
        "--allow-malware-registration-tasking",
        action="store_true",
        help="完全一致StealC／Lumma／Remus profileの合成登録とtask取得を許可します。",
    )
    parser.add_argument(
        "--private-credential-vault",
        type=Path,
        help="リポジトリ外のAgentTesla sensitive_local_only JSON。",
    )
    args = parser.parse_args()
    try:
        plan = json.loads(args.targets.read_text(encoding="utf-8"))
        result = monitor(
            plan,
            allow_network=args.allow_network,
            allow_application_probes=args.allow_reviewed_application_probes,
            allow_authentication=args.allow_authentication,
            allow_malware_registration=args.allow_malware_registration_tasking,
            private_credential_vault=args.private_credential_vault,
        )
    except (OSError, json.JSONDecodeError, PlanError, ValueError) as exc:
        parser.error(str(exc))
    args.output_directory.mkdir(parents=True, exist_ok=True)
    (args.output_directory / "monitoring-results.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_directory / "README.md").write_text(render_markdown(result), encoding="utf-8")
    print(
        json.dumps(
            {
                "target_count": result["target_count"],
                "state_counts": result["state_counts"],
                "output_directory": str(args.output_directory),
                "network_enabled": args.allow_network,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
