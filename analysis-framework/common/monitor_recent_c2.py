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
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace

from c2_detector import probe
from c2_protocol_probe_profiles import (
    PROFILE_METHODS,
    ProtocolProfileError,
    canonical_profile_object_sha256,
    profile_registry_metadata,
    remus_review_registry_metadata,
    resolve_profile,
    validate_redline_profile_binding,
    validate_xloader_profile_evidence,
)
from darkcomet_profile_evidence import (
    DarkCometEvidenceError,
    validate_darkcomet_profile_evidence,
)
from darkcomet_server_first_probe import probe_reviewed_darkcomet_server_first
from purerat_direct_tls_probe import (
    PureRatDirectTlsError,
    probe_reviewed_purerat_direct_tls,
)
from purerat_direct_tls_probe import (
    reviewed_profile as reviewed_purerat_profile,
)
from remus_profile_evidence import (
    RemusEvidenceError,
    validate_remus_profile_evidence,
)
from stealer_registration_probe import probe_reviewed_stealer_registration
from tls_messagepack_c2_detector import resolve_detector_binding
from tls_messagepack_probe import probe_reviewed_tls_messagepack

HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9.-]+")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ALLOWED_PROTOCOLS = {
    "dns",
    "tcp",
    "http",
    "https",
    "tls",
    "winos",
    "vvas",
    "n520",
    "purerat_direct_tls",
    "ftp",
    "asyncrat",
    "venomrat",
    "stealc",
    "lummastealer",
    "remusstealer",
    "darkcomet",
    "redlinestealer",
    "xloader_http_get_pkt2",
}
ALLOWED_METHODS = {
    "dns_resolve",
    "tcp_connect",
    "protocol_profile_required",
    "passive_banner",
    "tls_handshake",
    "http_get",
    "winos_heartbeat",
    "vvas_checkin",
    "n520_server_first",
    "purerat_direct_tls_certificate_pin",
    "ftp_authenticated",
    "asyncrat_tls_messagepack",
    "venomrat_tls_messagepack",
    "stealc_v2_registration_task",
    "lumma_v6_registration_task",
    "remus_registration_task",
    "darkcomet_server_first_idtype",
    "redline_checkconnect_soap11",
    "xloader_v8_get_registration",
}
ACTIVE_PROFILE_METHODS = {
    "winos_heartbeat",
    "vvas_checkin",
    "n520_server_first",
    "purerat_direct_tls_certificate_pin",
    "ftp_authenticated",
    "asyncrat_tls_messagepack",
    "venomrat_tls_messagepack",
    "stealc_v2_registration_task",
    "lumma_v6_registration_task",
    "remus_registration_task",
    "darkcomet_server_first_idtype",
    "redline_checkconnect_soap11",
    "xloader_v8_get_registration",
}
PROFILE_REQUIRED_PROTOCOLS = frozenset(protocol for protocol, _method in PROFILE_METHODS.values())
ALLOWED_TRANSPORTS = {"direct", "tor-socks5"}
METHOD_CEILINGS = {
    "dns_resolve": 0.05,
    "tcp_connect": 0.25,
    "protocol_profile_required": 0.05,
    "passive_banner": 0.55,
    "tls_handshake": 0.45,
    "http_get": 0.60,
    "winos_heartbeat": 0.95,
    "vvas_checkin": 0.95,
    "n520_server_first": 0.95,
    "purerat_direct_tls_certificate_pin": 0.92,
    "ftp_authenticated": 0.95,
    "asyncrat_tls_messagepack": 0.95,
    "venomrat_tls_messagepack": 0.95,
    "stealc_v2_registration_task": 0.95,
    "lumma_v6_registration_task": 0.95,
    "remus_registration_task": 0.95,
    "darkcomet_server_first_idtype": 0.98,
    "redline_checkconnect_soap11": 0.98,
    "xloader_v8_get_registration": 0.98,
}
METHOD_LABELS = {
    "dns_resolve": "DNS解決のみ（接続先port不明、C2 serviceへの接続なし）",
    "tcp_connect": "DNS解決＋単一TCP接続（送受信なし）",
    "protocol_profile_required": "malware固有protocol hintあり・review済み完全一致profile未登録（DNS観測のみ）",
    "passive_banner": "DNS解決＋単一TCP接続＋server-first banner限定受信",
    "tls_handshake": "DNS解決＋単一TLS handshake（application dataなし）",
    "http_get": "DNS解決＋TLS/HTTP GET 1回（redirectなし）",
    "winos_heartbeat": "完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信",
    "vvas_checkin": "完全一致・レビュー済みvvaS check-in 3 byte＋64 byte限定header検証",
    "n520_server_first": "完全一致・N520 TLS server-first 44 byte handshake検証（check-in送信なし）",
    "purerat_direct_tls_certificate_pin": "完全一致・PureRAT direct TLS 1.0 handshake＋leaf証明書pin（application data送信なし）",
    "ftp_authenticated": "完全一致・private資格情報によるFTP USER/PASS/QUIT限定認証（file操作なし）",
    "asyncrat_tls_messagepack": "完全一致・AsyncRAT TLS圧縮MessagePack Ping 1 frame＋64 byte限定応答",
    "venomrat_tls_messagepack": "完全一致・VenomRAT TLS圧縮MessagePack Ping 1 frame＋64 byte限定応答",
    "stealc_v2_registration_task": "完全一致・StealC v2合成端末登録＋loader task取得（最大2要求）",
    "lumma_v6_registration_task": "完全一致・Lumma v6設定登録＋合成hwid task取得（最大2要求）",
    "remus_registration_task": "完全一致・Remus合成端末登録＋step=1 task取得（最大2要求）",
    "darkcomet_server_first_idtype": "完全一致・DarkComet RC4 server-first IDTYPE復号（application data送信なし）",
    "redline_checkconnect_soap11": "完全一致・RedLine SOAP 1.1 CheckConnect 1要求＋4 KiB限定応答",
    "xloader_v8_get_registration": "完全一致・XLoader v8合成PKT2登録GET 1要求＋暗号応答検証（command非公開・非実行）",
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


def validate_plan(plan: dict, *, repository_root: Path | None = None) -> dict:
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
    active_targets = [
        target for target in targets if isinstance(target, dict) and target.get("method") in ACTIVE_PROFILE_METHODS
    ]
    protocol_registry_pin: dict[str, str] | None = None
    remus_registry_pin: dict[str, str] | None = None
    if active_targets:
        protocol_registry_pin = plan.get("protocol_profile_registry")
        try:
            current_profile_registry = profile_registry_metadata()
        except ProtocolProfileError as exc:
            raise PlanError(f"C2 protocol profile registryを検証できません: {exc}") from exc
        if protocol_registry_pin != current_profile_registry:
            raise PlanError("計画のC2 protocol profile registry source/SHA-256 pinが一致しません")
    if any(target.get("method") == "remus_registration_task" for target in active_targets):
        remus_registry_pin = plan.get("remus_review_registry")
        try:
            current_remus_registry = remus_review_registry_metadata(repository_root=repository_root)
        except ProtocolProfileError as exc:
            raise PlanError(f"Remus review registryを検証できません: {exc}") from exc
        if remus_registry_pin != current_remus_registry:
            raise PlanError("計画のRemus review registry source/SHA-256 pinが一致しません")

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
                profile = resolve_profile(
                    profile_id,
                    host,
                    port,
                    expected_registry_sha256=protocol_registry_pin["sha256"],
                )
            except ProtocolProfileError as exc:
                raise PlanError(str(exc)) from exc
            if (profile["protocol"], profile["method"]) != (protocol, method):
                raise PlanError("protocol profileとtargetのprotocol/methodが一致しません")
            if (
                target.get("protocol_profile_registry_source") != protocol_registry_pin["source"]
                or target.get("protocol_profile_registry_sha256") != protocol_registry_pin["sha256"]
            ):
                raise PlanError("targetのC2 protocol profile registry pinが計画と一致しません")
            profile_samples = profile.get("sample_sha256s")
            if not isinstance(profile_samples, list) or target.get("sample_sha256s") != profile_samples:
                raise PlanError("active targetのsample集合がprofileと完全一致しません")
            if method == "purerat_direct_tls_certificate_pin" and (
                profile.get("source")
                != "analysis-framework/malware/purehvnc/purerat_441_emulator_evidence.json"
                or profile.get("handler") != "purerat_direct_tls"
                or profile.get("wire_mode") != "direct_tls"
                or profile.get("tls_version") != "TLSv1.0"
                or profile.get("sni") is not None
                or profile.get("send_hex") not in (None, "")
                or type(target.get("maximum_request_bytes")) is not int
                or target.get("maximum_request_bytes") != 0
                or type(target.get("maximum_response_bytes")) is not int
                or target.get("maximum_response_bytes") != 0
                or type(target.get("timeout_seconds")) is not float
                or target.get("timeout_seconds") != 3.0
            ):
                raise PlanError(
                    "PureRAT targetはTLS1.0/SNIなし/application送受信0のexact profileに限定します"
                )
            if method == "darkcomet_server_first_idtype":
                evidence_sha256 = target.get("protocol_profile_evidence_sha256")
                evidence_source = target.get("protocol_profile_evidence_source")
                if evidence_source != profile.get("source") or not isinstance(evidence_sha256, str):
                    raise PlanError("DarkComet profileには計画生成時の証拠source/SHA-256固定が必要です")
                try:
                    validate_darkcomet_profile_evidence(
                        profile,
                        repository_root=repository_root,
                        expected_sha256=evidence_sha256,
                    )
                except DarkCometEvidenceError as exc:
                    raise PlanError(f"DarkComet profile証拠を再検証できません: {exc}") from exc
            if method == "remus_registration_task":
                evidence_sha256 = target.get("protocol_profile_evidence_sha256")
                evidence_source = target.get("protocol_profile_evidence_source")
                if evidence_source != profile.get("evidence_source") or not isinstance(evidence_sha256, str):
                    raise PlanError("Remus profileには計画生成時の証拠source/SHA-256固定が必要です")
                if (
                    remus_registry_pin is None
                    or target.get("protocol_profile_review_id") != profile.get("review_id")
                    or target.get("protocol_profile_review_registry_source") != remus_registry_pin["source"]
                    or target.get("protocol_profile_review_registry_sha256") != remus_registry_pin["sha256"]
                    or profile.get("review_registry_source") != remus_registry_pin["source"]
                    or profile.get("review_registry_sha256") != remus_registry_pin["sha256"]
                    or target.get("protocol_profile_flow_artifact_source") != profile.get("flow_artifact_source")
                    or target.get("protocol_profile_flow_artifact_sha256") != profile.get("flow_artifact_sha256")
                ):
                    raise PlanError("Remus review registry/flow artifact pinが完全一致しません")
                if (
                    type(target.get("timeout_seconds")) is not float
                    or target.get("timeout_seconds") != 3.0
                    or type(target.get("maximum_request_bytes")) is not int
                    or target.get("maximum_request_bytes") != 4096
                    or type(target.get("maximum_response_bytes")) is not int
                    or target.get("maximum_response_bytes") != 8192
                ):
                    raise PlanError("Remus targetのtimeout/request/response上限が固定値と一致しません")
                try:
                    validate_remus_profile_evidence(
                        profile,
                        repository_root=repository_root,
                        expected_sha256=evidence_sha256,
                        expected_registry_sha256=remus_registry_pin["sha256"],
                        expected_flow_artifact_sha256=target["protocol_profile_flow_artifact_sha256"],
                    )
                except RemusEvidenceError as exc:
                    raise PlanError(f"Remus profile証拠を再検証できません: {exc}") from exc
            if method == "redline_checkconnect_soap11":
                try:
                    redline = validate_redline_profile_binding(
                        profile,
                        repository_root=repository_root,
                    )
                except ProtocolProfileError as exc:
                    raise PlanError(
                        f"RedLine profile証拠を再検証できません: {exc}"
                    ) from exc
                binding = redline["binding"]
                registry = redline["registry"]
                if (
                    target.get("protocol_profile_evidence_source")
                    != profile.get("config_source")
                    or target.get("protocol_profile_evidence_sha256")
                    != profile.get("config_artifact_review_sha256")
                    or target.get("protocol_profile_review_id")
                    != profile.get("config_review_id")
                    or target.get("protocol_profile_endpoint_json_pointer")
                    != profile.get("endpoint_json_pointer")
                    or target.get("protocol_profile_terminal_mvid")
                    != profile.get("terminal_mvid")
                    or target.get(
                        "protocol_profile_terminal_cil_semantic_sha256"
                    )
                    != profile.get("terminal_cil_semantic_sha256")
                    or target.get("protocol_profile_request_sha256")
                    != profile.get("request_sha256")
                    or target.get("protocol_profile_family_registry_source")
                    != registry["source"]
                    or target.get("protocol_profile_family_registry_sha256")
                    != registry["sha256"]
                    or binding.get("endpoint") != profile.get("endpoint")
                ):
                    raise PlanError(
                        "RedLine config/MVID/CIL/request/family registry pinが完全一致しません"
                    )
                if (
                    type(target.get("timeout_seconds")) is not float
                    or target.get("timeout_seconds") != 3.0
                    or type(target.get("maximum_request_bytes")) is not int
                    or target.get("maximum_request_bytes") != 357
                    or type(target.get("maximum_response_bytes")) is not int
                    or target.get("maximum_response_bytes") != 4096
                ):
                    raise PlanError(
                        "RedLine targetのtimeout/request/response上限が固定値と一致しません"
                    )
            if method == "xloader_v8_get_registration":
                evidence_sha256 = target.get("protocol_profile_evidence_sha256")
                if (
                    target.get("protocol_profile_evidence_source")
                    != profile.get("review_evidence_source")
                    or evidence_sha256 != profile.get("review_evidence_sha256")
                    or target.get("protocol_profile_review_id")
                    != profile.get("review_id")
                    or target.get("protocol_profile_payload_sha256")
                    != canonical_profile_object_sha256(profile)
                    or target.get(
                        "protocol_profile_private_material_reference"
                    )
                    != profile.get("private_material_reference")
                    or target.get("protocol_profile_private_material_sha256")
                    != profile.get("private_material_sha256")
                    or target.get(
                        "protocol_profile_selector_path_table_sha256"
                    )
                    != profile.get("selector_path_table_sha256")
                    or target.get(
                        "protocol_profile_synthetic_template_id"
                    )
                    != profile.get("synthetic_template_id")
                    or target.get(
                        "protocol_profile_pkt2_inner_plaintext_sha256"
                    )
                    != profile.get("pkt2_inner_plaintext_sha256")
                    or target.get("protocol_profile_request_sha256")
                    != profile.get("request_sha256")
                ):
                    raise PlanError(
                        "XLoader profile/private material/selector/synthetic/request/review pinが完全一致しません"
                    )
                try:
                    validate_xloader_profile_evidence(
                        profile,
                        repository_root=repository_root,
                        expected_sha256=evidence_sha256,
                    )
                except ProtocolProfileError as exc:
                    raise PlanError(
                        f"XLoader review証拠を再検証できません: {exc}"
                    ) from exc
                if (
                    type(target.get("timeout_seconds")) is not float
                    or target.get("timeout_seconds") != 3.0
                    or type(target.get("maximum_request_bytes")) is not int
                    or target.get("maximum_request_bytes") != 4096
                    or type(target.get("maximum_response_bytes")) is not int
                    or target.get("maximum_response_bytes") != 8192
                ):
                    raise PlanError(
                        "XLoader targetのtimeout/request/response上限が固定値と一致しません"
                    )
        elif profile_id is not None:
            raise PlanError("protocol_profile_idはレビュー済みactive methodだけに使用できます")
        if method == "protocol_profile_required":
            hints = target.get("protocol_hints")
            if not isinstance(hints, list) or not hints or len(hints) != len(set(hints)):
                raise PlanError("protocol_profile_requiredには重複のない明示protocol_hintsが必要です")
            if any(hint not in PROFILE_REQUIRED_PROTOCOLS for hint in hints):
                raise PlanError("protocol_hintsはレビュー対象のmalware protocolに限定します")
            expected_status = (
                "reviewed_exact_profile_missing" if len(hints) == 1 else "conflicting_explicit_protocol_hints"
            )
            if (
                target.get("protocol_profile_required") is not True
                or target.get("protocol_profile_status") != expected_status
            ):
                raise PlanError("protocol_profile_requiredにはIOC由来の明示protocol_hintsとfail-closed印が必要です")
            if protocol != "tcp":
                raise PlanError("protocol_profile_requiredは非接続transport表現のprotocol=tcpに限定します")
        if host.endswith(".onion") and transport != "tor-socks5":
            raise PlanError(".onionはloopback SOCKS5経由に限定します")
        if not host.endswith(".onion") and transport != "direct":
            raise PlanError("Tor経由は.onion完全一致ターゲットに限定します")
        expected_protocol = {
            "tcp_connect": "tcp",
            "passive_banner": "tcp",
            "tls_handshake": "tls",
            "purerat_direct_tls_certificate_pin": "purerat_direct_tls",
            "winos_heartbeat": "winos",
            "vvas_checkin": "vvas",
            "n520_server_first": "n520",
            "ftp_authenticated": "ftp",
            "asyncrat_tls_messagepack": "asyncrat",
            "venomrat_tls_messagepack": "venomrat",
            "stealc_v2_registration_task": "stealc",
            "lumma_v6_registration_task": "lummastealer",
            "remus_registration_task": "remusstealer",
            "darkcomet_server_first_idtype": "darkcomet",
            "redline_checkconnect_soap11": "redlinestealer",
            "xloader_v8_get_registration": "xloader_http_get_pkt2",
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
        minimum_response = (
            0 if method == "purerat_direct_tls_certificate_pin" else 1
        )
        response_limit = (
            int(profile["maximum_response_bytes"])
            if profile is not None
            else (1024 if method == "ftp_authenticated" else 256)
        )
        if not 0.1 <= timeout <= 5.0 or not minimum_response <= maximum <= response_limit:
            raise PlanError(f"timeout<=5秒、response<={response_limit} byteを超えています")
        if profile and (
            timeout != float(profile["timeout_seconds"]) or maximum != int(profile["maximum_response_bytes"])
        ):
            raise PlanError("active protocol probeはレビュー済みtimeout/response上限との完全一致が必要です")
        path = str(target.get("http_path", "/"))
        if "\r" in path or "\n" in path or not path.startswith("/") or len(path) > 512:
            raise PlanError("HTTP pathが不正です")
        if any(key in target for key in ("send_hex", "payload", "cidr", "ports", "checkin")):
            raise PlanError("payload、check-in、range scanは監視計画へ指定できません")
        samples = target.get("sample_sha256s", [])
        if (
            not isinstance(samples, list)
            or any(type(value) is not str or not SHA256_RE.fullmatch(value) for value in samples)
            or len(samples) != len(set(samples))
            or samples != sorted(samples)
        ):
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


def _probe_winos_reviewed(
    profile: dict,
    allow_network: bool,
    expected_registry_sha256: str,
) -> dict:
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
        profile["profile_id"],
        profile["host"],
        profile["port"],
        allow_live=True,
        expected_registry_sha256=expected_registry_sha256,
    )


def _winos_observation(target: dict, allow_network: bool) -> dict:
    """Winos heartbeatを共通observationへ正規化し、operation commandは保持しない。"""
    timestamp = datetime.now(UTC).isoformat()
    registry_sha256 = target["protocol_profile_registry_sha256"]
    profile = resolve_profile(
        target["protocol_profile_id"],
        target["host"],
        target["port"],
        expected_registry_sha256=registry_sha256,
    )
    try:
        raw = _probe_winos_reviewed(
            profile,
            allow_network,
            registry_sha256,
        )
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
    except TimeoutError:
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
        "channel_role": raw.get("channel_role"),
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

    timestamp = datetime.now(UTC).isoformat()
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
    except TimeoutError:
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
    except TimeoutError:
        status = "timeout"
    except ssl.SSLError:
        status = "tls_handshake_failed"
    except (OSError, ValueError, RuntimeError) as exc:
        return {
            "timestamp_utc": datetime.now(UTC).isoformat(),
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
        "timestamp_utc": datetime.now(UTC).isoformat(),
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



def _sanitize_tls_messagepack_observation(target: dict, observation: dict) -> dict:
    """AsyncRAT／VenomRAT観測を既知scalarとfingerprintだけへ制限する。"""

    expected_packet = resolve_detector_binding(
        target["protocol_profile_id"]
    ).response_packet
    allowed_statuses = {
        "network_disabled",
        "closed",
        "timeout",
        "tls_handshake_failed",
        "tls_messagepack_probe_error",
        "tls_handshake_only_application_probe_disabled",
        "confirmed_tls_messagepack_c2",
        "tls_messagepack_response_mismatch",
        "tls_version_mismatch",
    }
    status = observation.get("status")
    if status not in allowed_statuses:
        status = "tls_messagepack_probe_error"
    value: dict[str, object] = {
        "timestamp_utc": (
            observation.get("timestamp_utc")
            if isinstance(observation.get("timestamp_utc"), str)
            else datetime.now(UTC).isoformat()
        ),
        "status": status,
        "profile_id": target.get("protocol_profile_id"),
    }
    boolean_fields = (
        "alive",
        "c2_confirmed",
        "target_contact_attempted",
        "target_connection_established",
        "application_data_sent",
        "protocol_response_received",
        "certificate_mismatch_excludes_c2",
        "victim_metadata_sent",
        "stage_requested",
        "operation_command_sent",
        "command_polling_performed",
        "raw_request_published",
        "raw_response_published",
        "raw_response_retained",
        "synthetic_result_sent",
        "tls_version_exact",
    )
    for field in boolean_fields:
        observed = observation.get(field, False)
        value[field] = observed if type(observed) is bool else False
    integer_fields = (
        "sent_bytes",
        "received_bytes",
        "request_count",
        "request_budget_used",
        "response_field_count",
        "response_frame_size",
        "response_decoded_size",
    )
    for field in integer_fields:
        observed = observation.get(field, 0)
        value[field] = observed if type(observed) is int and observed >= 0 else -1
    response_packet = observation.get("response_packet")
    value["response_packet"] = response_packet if response_packet == expected_packet else None
    detector_status = observation.get("detector_status")
    value["detector_status"] = (
        detector_status
        if detector_status
        in {
            "confirmed_tls_messagepack_c2",
            "tls_messagepack_response_mismatch",
            "tls_version_mismatch",
        }
        else None
    )
    for field in ("response_frame_sha256", "response_decoded_sha256"):
        observed = observation.get(field)
        value[field] = (
            observed
            if isinstance(observed, str) and SHA256_RE.fullmatch(observed)
            else None
        )
    resolved_ips = observation.get("resolved_ips")
    value["resolved_ips"] = (
        [item for item in resolved_ips if isinstance(item, str) and _is_ip(item)]
        if isinstance(resolved_ips, list)
        else []
    )
    tls = observation.get("tls")
    if isinstance(tls, dict):
        certificate = tls.get("certificate")
        certificate = certificate if isinstance(certificate, dict) else {}
        observed_sha256 = certificate.get("observed_sha256")
        expected_sha256 = certificate.get("expected_sha256")
        value["tls"] = {
            "handshake": tls.get("handshake") is True,
            "observed_version": (
                tls.get("observed_version")
                if tls.get("observed_version")
                in {None, "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
                else "invalid"
            ),
            "expected_version": (
                tls.get("expected_version")
                if tls.get("expected_version") in {None, "TLSv1.2"}
                else "invalid"
            ),
            "version_exact": tls.get("version_exact") is True,
            "certificate": {
                "state": (
                    certificate.get("state")
                    if certificate.get("state")
                    in {
                        "exact_match",
                        "mismatch_inconclusive",
                        "observed_without_static_pin",
                    }
                    else "invalid"
                ),
                "exact_match": certificate.get("exact_match") is True,
                "observed_sha256": (
                    observed_sha256
                    if isinstance(observed_sha256, str)
                    and SHA256_RE.fullmatch(observed_sha256)
                    else None
                ),
                "expected_sha256": (
                    expected_sha256
                    if isinstance(expected_sha256, str)
                    and SHA256_RE.fullmatch(expected_sha256)
                    else None
                ),
                "certificate_mismatch_excludes_c2": (
                    certificate.get("certificate_mismatch_excludes_c2") is True
                ),
            },
        }
    return value


def _sanitize_purerat_observation(observation: dict) -> dict:
    """PureRAT観測を既知scalar/TLS fingerprintだけへfail-closedで制限する。"""

    reviewed = reviewed_purerat_profile()
    allowed_statuses = {
        "network_disabled",
        "legacy_tls_disabled",
        "closed",
        "timeout",
        "purerat_direct_tls_probe_error",
        "confirmed_purerat_direct_tls_certificate",
        "purerat_direct_tls_certificate_mismatch",
        "purerat_direct_tls_version_mismatch_inconclusive",
    }
    status = observation.get("status")
    if status not in allowed_statuses:
        status = "purerat_direct_tls_probe_error"
    value = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "status": status,
        "profile_id": reviewed["profile_id"],
        "root_sample_sha256": reviewed["root_sample_sha256"],
        "terminal_sample_sha256": reviewed["terminal_sample_sha256"],
        "wire_mode": "direct_tls",
        "application_framing": "le32/gzip/protobuf-net",
    }
    boolean_fields = (
        "alive",
        "c2_confirmed",
        "target_contact_attempted",
        "target_connection_established",
        "tls_before_application_data",
        "plaintext_prelude_sent",
        "application_data_sent",
        "protocol_response_received",
        "victim_metadata_sent",
        "registration_attempted",
        "task_poll_attempted",
        "task_executed",
        "operation_command_sent",
        "pfx_loaded",
        "private_key_loaded",
        "client_certificate_sent",
        "raw_request_published",
        "raw_response_published",
        "certificate_mismatch_excludes_c2",
        "certificate_mismatch_excludes_exact_build_endpoint",
        "certificate_mismatch_excludes_family_c2",
        "tls_version_mismatch_excludes_c2",
        "tls_version_mismatch_excludes_exact_build_endpoint",
        "tls_version_mismatch_excludes_family_c2",
    )
    for field in boolean_fields:
        observed = observation.get(field, False)
        value[field] = observed if type(observed) is bool else False
    for field in ("sent_bytes", "received_bytes", "request_count"):
        observed = observation.get(field, 0)
        value[field] = observed if type(observed) is int else -1
    resolved_ips = observation.get("resolved_ips")
    value["resolved_ips"] = (
        [item for item in resolved_ips if isinstance(item, str) and _is_ip(item)]
        if isinstance(resolved_ips, list)
        else []
    )
    connected_ip = observation.get("connected_ip")
    value["connected_ip"] = (
        connected_ip
        if isinstance(connected_ip, str) and _is_ip(connected_ip)
        else None
    )
    tls = observation.get("tls")
    if isinstance(tls, dict):
        certificate = tls.get("certificate")
        certificate = certificate if isinstance(certificate, dict) else {}
        version = tls.get("version")
        expected_version = tls.get("expected_version")
        observed_sha256 = certificate.get("observed_sha256")
        expected_sha256 = certificate.get("expected_sha256")
        value["tls"] = {
            "handshake": tls.get("handshake") is True,
            "version": version
            if version in {None, "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
            else "invalid",
            "expected_version": expected_version
            if expected_version in {None, "TLSv1"}
            else "invalid",
            "version_exact_match": tls.get("version_exact_match") is True,
            "certificate": {
                "state": certificate.get("state")
                if certificate.get("state")
                in {"exact_match", "mismatch_inconclusive"}
                else "invalid",
                "exact_match": certificate.get("exact_match") is True,
                "observed_sha256": observed_sha256
                if isinstance(observed_sha256, str)
                and SHA256_RE.fullmatch(observed_sha256)
                else None,
                "expected_sha256": expected_sha256
                if isinstance(expected_sha256, str)
                and SHA256_RE.fullmatch(expected_sha256)
                else None,
                "certificate_mismatch_excludes_c2": (
                    certificate.get("certificate_mismatch_excludes_c2") is True
                ),
            },
        }
    return value


def _purerat_direct_tls_observation(
    target: dict,
    allow_network: bool,
    allow_legacy_tls: bool,
    *,
    resolver=None,
    connector=None,
    tls_handshaker=None,
) -> dict:
    """PureRAT TLS 1.0 leaf pinを送信0 byteの独立gateで観測する。"""

    timestamp = datetime.now(UTC).isoformat()

    def failed(status: str, *, attempted: bool, error_type: str | None = None) -> dict:
        value = {
            "timestamp_utc": timestamp,
            "status": status,
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": attempted,
            "target_connection_established": False,
            "tls_before_application_data": True,
            "plaintext_prelude_sent": False,
            "application_data_sent": False,
            "protocol_response_received": False,
            "sent_bytes": 0,
            "received_bytes": 0,
            "request_count": 0,
            "victim_metadata_sent": False,
            "registration_attempted": False,
            "task_poll_attempted": False,
            "task_executed": False,
            "operation_command_sent": False,
            "pfx_loaded": False,
            "private_key_loaded": False,
            "client_certificate_sent": False,
            "raw_request_published": False,
            "raw_response_published": False,
            "certificate_mismatch_excludes_c2": False,
            "certificate_mismatch_excludes_family_c2": False,
            "tls_version_mismatch_excludes_c2": False,
            "tls_version_mismatch_excludes_family_c2": False,
            "resolved_ips": [],
        }
        if error_type is not None:
            value["error_type"] = error_type
        return value

    contact_attempted = False
    try:
        registry = profile_registry_metadata()
        if (
            target.get("protocol_profile_registry_source") != registry["source"]
            or target.get("protocol_profile_registry_sha256") != registry["sha256"]
        ):
            raise PlanError("PureRAT common registry pinがdispatch直前に一致しません")
        profile = resolve_profile(
            target["protocol_profile_id"],
            target["host"],
            target["port"],
            expected_registry_sha256=registry["sha256"],
        )
        reviewed = reviewed_purerat_profile()
        for key, expected in reviewed.items():
            if key != "source" and profile.get(key) != expected:
                raise PlanError(
                    f"PureRAT common/direct profile fieldが不一致です: {key}"
                )
        if (
            profile.get("source")
            != "analysis-framework/malware/purehvnc/purerat_441_emulator_evidence.json"
            or profile.get("protocol") != "purerat_direct_tls"
            or profile.get("sample_sha256s")
            != [profile.get("root_sample_sha256"), profile.get("terminal_sample_sha256")]
        ):
            raise PlanError("PureRAT common profile evidence/protocol pinが不一致です")
        exact_target = (
            target.get("family") == profile.get("family"),
            target.get("protocol") == profile.get("protocol"),
            target.get("method") == profile.get("method"),
            target.get("sample_sha256s") == profile.get("sample_sha256s"),
            target.get("timeout_seconds") == profile.get("timeout_seconds"),
            target.get("maximum_request_bytes")
            == profile.get("maximum_request_bytes"),
            target.get("maximum_response_bytes")
            == profile.get("maximum_response_bytes"),
        )
        if not all(exact_target):
            raise PlanError("PureRAT target/profileのdispatch直前pinが一致しません")
        selected_connector = connector or socket.create_connection

        def tracked_connector(*args, **kwargs):
            nonlocal contact_attempted
            contact_attempted = True
            return selected_connector(*args, **kwargs)

        result = probe_reviewed_purerat_direct_tls(
            reviewed,
            allow_network=allow_network,
            allow_legacy_tls=allow_legacy_tls,
            resolver=resolver,
            connector=tracked_connector,
            tls_handshaker=tls_handshaker,
        )
    except ConnectionRefusedError:
        return failed("closed", attempted=contact_attempted)
    except TimeoutError:
        return failed("timeout", attempted=contact_attempted)
    except (PlanError, PureRatDirectTlsError, ValueError, RuntimeError) as exc:
        return failed(
            "purerat_direct_tls_probe_error",
            attempted=False,
            error_type=type(exc).__name__,
        )
    except OSError as exc:
        return failed(
            "purerat_direct_tls_probe_error",
            attempted=contact_attempted,
            error_type=type(exc).__name__,
        )
    allowed_statuses = {
        "network_disabled",
        "legacy_tls_disabled",
        "confirmed_purerat_direct_tls_certificate",
        "purerat_direct_tls_certificate_mismatch",
        "purerat_direct_tls_version_mismatch_inconclusive",
    }
    status = result.get("status")
    if status not in allowed_statuses:
        return failed(
            "purerat_direct_tls_probe_error",
            attempted=contact_attempted,
            error_type="UnexpectedProbeStatus",
        )
    boolean_fields = (
        "alive",
        "c2_confirmed",
        "target_contact_attempted",
        "target_connection_established",
        "tls_before_application_data",
        "plaintext_prelude_sent",
        "application_data_sent",
        "protocol_response_received",
        "victim_metadata_sent",
        "registration_attempted",
        "task_poll_attempted",
        "task_executed",
        "operation_command_sent",
        "pfx_loaded",
        "private_key_loaded",
        "client_certificate_sent",
        "raw_request_published",
        "raw_response_published",
        "certificate_mismatch_excludes_c2",
        "certificate_mismatch_excludes_exact_build_endpoint",
        "certificate_mismatch_excludes_family_c2",
        "tls_version_mismatch_excludes_c2",
        "tls_version_mismatch_excludes_exact_build_endpoint",
        "tls_version_mismatch_excludes_family_c2",
    )
    value = {
        "timestamp_utc": timestamp,
        "status": status,
        "profile_id": reviewed["profile_id"],
        "root_sample_sha256": reviewed["root_sample_sha256"],
        "terminal_sample_sha256": reviewed["terminal_sample_sha256"],
        "wire_mode": "direct_tls",
        "application_framing": "le32/gzip/protobuf-net",
        "sent_bytes": result.get("sent_bytes", 0)
        if type(result.get("sent_bytes", 0)) is int
        else -1,
        "received_bytes": result.get("received_bytes", 0)
        if type(result.get("received_bytes", 0)) is int
        else -1,
        "request_count": result.get("request_count", 0)
        if type(result.get("request_count", 0)) is int
        else -1,
        "resolved_ips": [
            item
            for item in result.get("resolved_ips", [])
            if isinstance(item, str) and _is_ip(item)
        ],
    }
    for field in boolean_fields:
        observed = result.get(field, False)
        value[field] = observed if type(observed) is bool else False
    connected_ip = result.get("connected_ip")
    value["connected_ip"] = (
        connected_ip
        if isinstance(connected_ip, str) and _is_ip(connected_ip)
        else None
    )
    observed_tls = result.get("tls")
    if isinstance(observed_tls, dict):
        observed_certificate = observed_tls.get("certificate")
        observed_certificate = (
            observed_certificate if isinstance(observed_certificate, dict) else {}
        )
        version = observed_tls.get("version")
        expected_version = observed_tls.get("expected_version")
        value["tls"] = {
            "handshake": observed_tls.get("handshake") is True,
            "version": version
            if version in {None, "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
            else "invalid",
            "expected_version": expected_version
            if expected_version in {None, "TLSv1"}
            else "invalid",
            "version_exact_match": observed_tls.get("version_exact_match") is True,
            "certificate": {
                "state": observed_certificate.get("state")
                if observed_certificate.get("state")
                in {"exact_match", "mismatch_inconclusive"}
                else "invalid",
                "exact_match": observed_certificate.get("exact_match") is True,
                "observed_sha256": observed_certificate.get("observed_sha256")
                if isinstance(observed_certificate.get("observed_sha256"), str)
                and SHA256_RE.fullmatch(observed_certificate["observed_sha256"])
                else None,
                "expected_sha256": observed_certificate.get("expected_sha256")
                if isinstance(observed_certificate.get("expected_sha256"), str)
                and SHA256_RE.fullmatch(observed_certificate["expected_sha256"])
                else None,
                "certificate_mismatch_excludes_c2": (
                    observed_certificate.get("certificate_mismatch_excludes_c2")
                    is True
                ),
            },
        }
    return value


def _darkcomet_server_first_observation(
    target: dict,
    allow_network: bool,
    repository_root: Path | None,
) -> dict:
    """DarkCometの受信専用RC4 challenge probeを共通観測へ正規化する。"""

    profile = resolve_profile(target["protocol_profile_id"], target["host"], target["port"])
    profile["evidence_sha256"] = target["protocol_profile_evidence_sha256"]
    profile["evidence_source"] = target["protocol_profile_evidence_source"]
    try:
        return probe_reviewed_darkcomet_server_first(
            profile,
            allow_network=allow_network,
            repository_root=repository_root,
        )
    except ConnectionRefusedError:
        status = "closed"
    except TimeoutError:
        status = "timeout"
    except (OSError, ValueError, RuntimeError) as exc:
        return {
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "status": "darkcomet_server_first_probe_error",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": allow_network,
            "target_connection_established": False,
            "application_data_sent": False,
            "sent_bytes": 0,
            "protocol_response_received": False,
            "server_first_response_received": False,
            "server_first_bytes_received": 0,
            "error_type": type(exc).__name__,
            "decrypted_plaintext_published": False,
            "rc4_key_published": False,
            "resolved_ips": [],
            "stage_requested": False,
            "victim_metadata_sent": False,
            "operation_command_sent": False,
        }
    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "status": status,
        "alive": False,
        "c2_confirmed": False,
        "target_contact_attempted": allow_network,
        "target_connection_established": False,
        "application_data_sent": False,
        "sent_bytes": 0,
        "protocol_response_received": False,
        "server_first_response_received": False,
        "server_first_bytes_received": 0,
        "decrypted_plaintext_published": False,
        "rc4_key_published": False,
        "resolved_ips": [],
        "stage_requested": False,
        "victim_metadata_sent": False,
        "operation_command_sent": False,
    }


def _stealer_registration_observation(
    target: dict,
    allow_network: bool,
    allow_registration_tasking: bool,
    repository_root: Path | None,
) -> dict:
    """StealC／Lumma／Remusの合成端末登録とtask取得を正規化する。"""

    profile = resolve_profile(
        target["protocol_profile_id"],
        target["host"],
        target["port"],
        expected_registry_sha256=target.get("protocol_profile_registry_sha256"),
    )
    timestamp = datetime.now(UTC).isoformat()
    try:
        result = probe_reviewed_stealer_registration(
            profile,
            allow_network=allow_network,
            allow_registration_tasking=allow_registration_tasking,
            repository_root=repository_root,
            expected_evidence_sha256=target.get("protocol_profile_evidence_sha256"),
            expected_evidence_source=target.get("protocol_profile_evidence_source"),
            expected_profile_registry_source=target.get("protocol_profile_registry_source"),
            expected_profile_registry_sha256=target.get("protocol_profile_registry_sha256"),
            expected_registry_source=target.get("protocol_profile_review_registry_source"),
            expected_registry_sha256=target.get("protocol_profile_review_registry_sha256"),
            expected_flow_artifact_source=target.get("protocol_profile_flow_artifact_source"),
            expected_flow_artifact_sha256=target.get("protocol_profile_flow_artifact_sha256"),
            expected_review_id=target.get("protocol_profile_review_id"),
        )
    except ConnectionRefusedError:
        status = "closed"
    except TimeoutError:
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


def _load_redline_active_probe_module():
    """RedLine固有active probeを明示pathから読み込む。"""

    module_path = (
        Path(__file__).parents[1]
        / "malware"
        / "redlinestealer"
        / "active_probe.py"
    )
    module_name = "_monitor_redline_active_probe"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("RedLine active probe moduleを読み込めません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _load_xloader_active_probe_module():
    """XLoader固有active probeをpackage相対import付きで読み込む。"""

    family_root = (
        Path(__file__).parents[1]
        / "malware"
        / "formbook_loader"
    )
    package_name = "_monitor_formbook_loader"
    module_name = f"{package_name}.xloader_active_probe"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    package = sys.modules.get(package_name)
    if package is None:
        package = ModuleType(package_name)
        package.__path__ = [str(family_root)]  # type: ignore[attr-defined]
        package.__package__ = package_name
        sys.modules[package_name] = package
    spec = importlib.util.spec_from_file_location(
        module_name,
        family_root / "xloader_active_probe.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("XLoader active probe moduleを読み込めません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _normalize_bounded_active_result(result: dict) -> dict:
    """family結果へ共通のrequest budget・送受信量・非公開flagを補う。"""

    value = dict(result)
    request_count = int(value.get("request_count") or 0)
    request_size = int(
        value.get("request_size")
        or (value.get("request_evidence") or {}).get("request_bytes")
        or 0
    )
    response_size = int(
        value.get("response_size")
        or (value.get("http") or {}).get("response_body_length")
        or 0
    )
    value.setdefault("request_budget_used", request_count)
    value.setdefault(
        "sent_bytes",
        request_size if value.get("application_data_sent") else 0,
    )
    value.setdefault("received_bytes", response_size)
    value.setdefault(
        "protocol_response_received",
        bool(
            value.get("c2_confirmed")
            or value.get("task_response_received")
            or (
                isinstance(value.get("http"), dict)
                and value["http"].get("status") is not None
            )
        ),
    )
    value.setdefault("synthetic_identity_sent", False)
    value.setdefault("victim_metadata_sent", False)
    value.setdefault("task_poll_attempted", False)
    value.setdefault("task_content_published", False)
    value.setdefault("task_executed", False)
    value.setdefault("payload_download_attempted", False)
    value.setdefault("raw_request_published", False)
    value.setdefault("raw_response_published", False)
    return value


def _redline_checkconnect_observation(
    target: dict,
    allow_network: bool,
    allow_reviewed_checkconnect: bool,
    acknowledged_profiles: frozenset[str],
) -> dict:
    """RedLine CheckConnectを専用gateとprofile ID確認付きで1回だけ呼ぶ。"""

    profile_id = str(target["protocol_profile_id"])
    acknowledgement = profile_id if profile_id in acknowledged_profiles else None
    try:
        current_common_registry = profile_registry_metadata()
        if (
            target.get("protocol_profile_registry_source")
            != current_common_registry["source"]
            or target.get("protocol_profile_registry_sha256")
            != current_common_registry["sha256"]
        ):
            raise PlanError(
                "RedLine common registryのdispatch直前pinが一致しません"
            )
        profile = resolve_profile(
            profile_id,
            target["host"],
            target["port"],
            expected_registry_sha256=target[
                "protocol_profile_registry_sha256"
            ],
        )
        exact_target_fields = (
            target.get("family") == profile.get("family"),
            target.get("protocol") == profile.get("protocol"),
            target.get("method") == profile.get("method"),
            target.get("sample_sha256s") == profile.get("sample_sha256s"),
            target.get("timeout_seconds") == profile.get("timeout_seconds"),
            target.get("maximum_request_bytes")
            == profile.get("maximum_request_bytes"),
            target.get("maximum_response_bytes")
            == profile.get("maximum_response_bytes"),
            target.get("protocol_profile_evidence_source")
            == profile.get("config_source"),
            target.get("protocol_profile_evidence_sha256")
            == profile.get("config_artifact_review_sha256"),
            target.get("protocol_profile_review_id")
            == profile.get("config_review_id"),
            target.get("protocol_profile_endpoint_json_pointer")
            == profile.get("endpoint_json_pointer"),
            target.get("protocol_profile_terminal_mvid")
            == profile.get("terminal_mvid"),
            target.get("protocol_profile_terminal_cil_semantic_sha256")
            == profile.get("terminal_cil_semantic_sha256"),
            target.get("protocol_profile_request_sha256")
            == profile.get("request_sha256"),
            target.get("protocol_profile_family_registry_source")
            == profile.get("family_profile_registry_source"),
            target.get("protocol_profile_family_registry_sha256")
            == profile.get("family_profile_registry_sha256"),
        )
        if not all(exact_target_fields):
            raise PlanError(
                "RedLine target/profileのdispatch直前pinが一致しません"
            )
        module = _load_redline_active_probe_module()
        result = module.probe_reviewed_redline_checkconnect(
            profile_id,
            allow_network=allow_network,
            allow_reviewed_checkconnect=allow_reviewed_checkconnect,
            acknowledge_profile=acknowledgement,
            expected_profile_registry_sha256=target[
                "protocol_profile_family_registry_sha256"
            ],
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return _normalize_bounded_active_result(
            {
                "timestamp_utc": datetime.now(UTC).isoformat(),
                "status": "redline_checkconnect_probe_error",
                "alive": False,
                "c2_confirmed": False,
                "target_contact_attempted": False,
                "target_connection_established": False,
                "application_data_sent": False,
                "protocol_response_received": False,
                "error_type": type(exc).__name__,
                "request_count": 0,
            }
        )
    return _normalize_bounded_active_result(result)


def _xloader_registration_observation(
    target: dict,
    allow_network: bool,
    allow_xloader_registration: bool,
    private_material_path: Path | None,
    repository_root: Path | None,
) -> dict:
    """XLoader v8のreview済みreal C2へ合成PKT2を1 GETだけ送る。"""

    disabled = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "alive": False,
        "c2_confirmed": False,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "application_data_sent": False,
        "protocol_response_received": False,
        "registration_attempted": False,
        "task_poll_attempted": False,
        "request_count": 0,
    }
    if not allow_network:
        return _normalize_bounded_active_result(
            {**disabled, "status": "network_disabled"}
        )
    if not allow_xloader_registration:
        return _normalize_bounded_active_result(
            {**disabled, "status": "xloader_registration_disabled"}
        )
    if private_material_path is None:
        return _normalize_bounded_active_result(
            {**disabled, "status": "xloader_private_material_missing"}
        )
    profile = resolve_profile(
        target["protocol_profile_id"],
        target["host"],
        target["port"],
        expected_registry_sha256=target.get(
            "protocol_profile_registry_sha256"
        ),
    )
    try:
        module = _load_xloader_active_probe_module()
        private_material = module.load_private_material(
            private_material_path,
            repository_root=repository_root,
        )
        result = module.probe_reviewed_xloader_registration(
            profile,
            private_material=private_material,
            allow_network=True,
            allow_xloader_registration=True,
            allow_xloader_candidate_check=False,
            expected_profile_sha256=target[
                "protocol_profile_payload_sha256"
            ],
            expected_profile_registry_sha256=target[
                "protocol_profile_registry_sha256"
            ],
            expected_private_material_sha256=target[
                "protocol_profile_private_material_sha256"
            ],
            expected_selector_path_table_sha256=target[
                "protocol_profile_selector_path_table_sha256"
            ],
            expected_synthetic_template_id=target[
                "protocol_profile_synthetic_template_id"
            ],
            expected_pkt2_inner_plaintext_sha256=target[
                "protocol_profile_pkt2_inner_plaintext_sha256"
            ],
            expected_request_sha256=target[
                "protocol_profile_request_sha256"
            ],
            expected_review_id=target["protocol_profile_review_id"],
            expected_profile_id=target["protocol_profile_id"],
        )
    except ConnectionRefusedError:
        return _normalize_bounded_active_result(
            {
                **disabled,
                "status": "closed",
                "target_contact_attempted": True,
                "registration_attempted": True,
            }
        )
    except TimeoutError:
        return _normalize_bounded_active_result(
            {
                **disabled,
                "status": "timeout",
                "target_contact_attempted": True,
                "registration_attempted": True,
            }
        )
    except OSError as exc:
        return _normalize_bounded_active_result(
            {
                **disabled,
                "status": "xloader_network_error",
                "target_contact_attempted": True,
                "registration_attempted": True,
                "error_type": type(exc).__name__,
            }
        )
    except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
        return _normalize_bounded_active_result(
            {
                **disabled,
                "status": "xloader_profile_or_material_error",
                "error_type": type(exc).__name__,
            }
        )
    return _normalize_bounded_active_result(result)


def _dns_observation(target: dict, allow_network: bool) -> dict:
    """port不明FQDNをDNS解決だけで観測し、C2到達とは扱わない。"""
    timestamp = datetime.now(UTC).isoformat()
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
    for key in (
        "request",
        "raw_request",
        "request_body",
        "response",
        "raw_response",
        "response_body",
        "command_content",
        "task_content",
        "credential",
        "cookie",
        "token",
        "private_material",
        "network_rc4_key",
        "url_seed",
    ):
        value.pop(key, None)
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
        for key in (
            "body",
            "raw",
            "raw_request",
            "raw_response",
            "request_headers",
            "set_cookie",
            "location",
        ):
            http.pop(key, None)
        headers = http.get("headers")
        if isinstance(headers, dict):
            http["headers"] = {
                str(key).lower(): val for key, val in headers.items() if str(key).lower() in SAFE_HTTP_HEADERS
            }
        value["http"] = http
    for field in ("request_evidence", "protocol_evidence", "exact_binding"):
        nested = value.get(field)
        if not isinstance(nested, dict):
            continue
        nested = dict(nested)
        for key in (
            "raw",
            "body",
            "plaintext",
            "ciphertext",
            "command_content",
            "task_content",
            "token",
            "cookie",
            "key",
            "url_seed",
            "private_material",
        ):
            nested.pop(key, None)
        value[field] = nested
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
        "legacy_tls_disabled",
        "authentication_disabled",
        "private_credential_vault_missing",
        "private_credential_vault_error",
        "tls_handshake_only_application_probe_disabled",
        "malware_registration_tasking_disabled",
        "reviewed_checkconnect_not_authorized",
        "profile_acknowledgement_missing_or_mismatch",
        "redline_checkconnect_probe_error",
        "xloader_registration_disabled",
        "xloader_private_material_missing",
        "xloader_profile_or_material_error",
    } and not observation.get("target_contact_attempted"):
        return {
            "state": "not_observed_safety_gate",
            "reachability_confidence": 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "安全gateが未充足のためprotocol-level観測を実施していない",
        }

    if method == "purerat_direct_tls_certificate_pin":
        certificate = tls.get("certificate") if isinstance(tls, dict) else {}
        certificate = certificate if isinstance(certificate, dict) else {}
        expected_certificate = reviewed_purerat_profile()[
            "expected_certificate_sha256"
        ]
        no_send = (
            observation.get("application_data_sent") is False
            and observation.get("plaintext_prelude_sent") is False
            and observation.get("victim_metadata_sent") is False
            and observation.get("raw_request_published") is False
            and observation.get("raw_response_published") is False
            and int(observation.get("sent_bytes") or 0) == 0
            and int(observation.get("request_count") or 0) == 0
            and observation.get("registration_attempted") is False
            and observation.get("task_poll_attempted") is False
            and observation.get("task_executed") is False
            and observation.get("operation_command_sent") is False
            and observation.get("pfx_loaded") is False
            and observation.get("private_key_loaded") is False
            and observation.get("client_certificate_sent") is False
        )
        exact_confirmation = (
            status == "confirmed_purerat_direct_tls_certificate"
            and observation.get("c2_confirmed") is True
            and observation.get("target_contact_attempted") is True
            and observation.get("target_connection_established") is True
            and observation.get("tls_before_application_data") is True
            and observation.get("protocol_response_received") is False
            and isinstance(tls, dict)
            and tls.get("handshake") is True
            and tls.get("version") == "TLSv1"
            and tls.get("expected_version") == "TLSv1"
            and tls.get("version_exact_match") is True
            and certificate.get("state") == "exact_match"
            and certificate.get("exact_match") is True
            and certificate.get("observed_sha256") == expected_certificate
            and certificate.get("expected_sha256") == expected_certificate
            and certificate.get("certificate_mismatch_excludes_c2") is False
            and observation.get("certificate_mismatch_excludes_c2") is False
            and observation.get("certificate_mismatch_excludes_family_c2")
            is False
            and observation.get("tls_version_mismatch_excludes_c2") is False
            and observation.get("tls_version_mismatch_excludes_family_c2")
            is False
            and no_send
        )
        if exact_confirmation:
            return {
                "state": "c2_protocol_confirmed",
                "reachability_confidence": 1.0,
                "c2_operational_confidence": 0.92,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "送信0 byteのdirect TLS 1.0とreview済みleaf証明書pinが完全一致",
            }
        mismatch_status = status in {
            "purerat_direct_tls_certificate_mismatch",
            "purerat_direct_tls_version_mismatch_inconclusive",
        }
        if mismatch_status and observation.get("c2_confirmed") is False and no_send:
            return {
                "state": "purerat_tls_endpoint_reachable_exact_build_not_confirmed",
                "reachability_confidence": (
                    0.98
                    if observation.get("target_connection_established")
                    else 0.0
                ),
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": (
                    "TLS endpointへ到達したがreview済みexact buildのTLS versionまたはleaf pinと不一致。PureRAT family C2の否定根拠にはしない"
                ),
            }
        if (
            status == "confirmed_purerat_direct_tls_certificate"
            or observation.get("c2_confirmed") is True
        ):
            return {
                "state": "purerat_confirmation_inconsistent_c2_not_confirmed",
                "reachability_confidence": (
                    0.98
                    if observation.get("target_connection_established")
                    else 0.0
                ),
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "PureRAT確認status、TLS version、証明書pinまたはno-send flagが矛盾するためC2確定を禁止",
            }
        reachable = bool(observation.get("target_connection_established"))
        return {
            "state": "purerat_endpoint_not_confirmed",
            "reachability_confidence": 0.98 if reachable else 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": (
                0.85
                if status == "closed"
                else (0.40 if status in {"timeout", "purerat_direct_tls_probe_error"} else 0.0)
            ),
            "reason": (
                "PureRAT専用TLS version／証明書pin契約が完全一致しないためC2確定を禁止"
            ),
        }

    if method in {"asyncrat_tls_messagepack", "venomrat_tls_messagepack"}:
        detector_binding = resolve_detector_binding(
            target["protocol_profile_id"]
        )
        expected_packet = detector_binding.response_packet
        certificate = tls.get("certificate") if isinstance(tls, dict) else {}
        certificate = certificate if isinstance(certificate, dict) else {}
        certificate_shape_exact = (
            isinstance(certificate.get("observed_sha256"), str)
            and SHA256_RE.fullmatch(certificate["observed_sha256"]) is not None
            and certificate.get("expected_sha256")
            == detector_binding.certificate_sha256
            and certificate.get("certificate_mismatch_excludes_c2") is False
            and (
                (
                    certificate.get("state") == "exact_match"
                    and certificate.get("exact_match") is True
                )
                or (
                    certificate.get("state") == "mismatch_inconclusive"
                    and certificate.get("exact_match") is False
                )
            )
        )
        no_side_effect = (
            observation.get("victim_metadata_sent") is False
            and observation.get("stage_requested") is False
            and observation.get("operation_command_sent") is False
            and observation.get("command_polling_performed") is False
            and observation.get("raw_request_published") is False
            and observation.get("raw_response_published") is False
            and observation.get("raw_response_retained") is False
            and observation.get("synthetic_result_sent") is False
        )
        exact_confirmation = (
            status == "confirmed_tls_messagepack_c2"
            and observation.get("detector_status") == "confirmed_tls_messagepack_c2"
            and observation.get("c2_confirmed") is True
            and observation.get("target_contact_attempted") is True
            and observation.get("target_connection_established") is True
            and observation.get("application_data_sent") is True
            and observation.get("protocol_response_received") is True
            and observation.get("request_count") == 1
            and observation.get("request_budget_used") == 1
            and 0 < int(observation.get("sent_bytes") or 0) <= 96
            and 4 < int(observation.get("received_bytes") or 0) <= 68
            and observation.get("response_packet") == expected_packet
            and observation.get("response_field_count") == 1
            and 4 < int(observation.get("response_frame_size") or 0) <= 68
            and 0 < int(observation.get("response_decoded_size") or 0) <= 1024
            and isinstance(observation.get("response_frame_sha256"), str)
            and SHA256_RE.fullmatch(observation["response_frame_sha256"]) is not None
            and isinstance(observation.get("response_decoded_sha256"), str)
            and SHA256_RE.fullmatch(observation["response_decoded_sha256"]) is not None
            and observation.get("tls_version_exact") is True
            and isinstance(tls, dict)
            and tls.get("handshake") is True
            and tls.get("observed_version") == "TLSv1.2"
            and tls.get("expected_version") == "TLSv1.2"
            and tls.get("version_exact") is True
            and observation.get("certificate_mismatch_excludes_c2") is False
            and certificate_shape_exact
            and no_side_effect
        )
        if exact_confirmation:
            return {
                "state": "c2_protocol_confirmed",
                "reachability_confidence": 1.0,
                "c2_operational_confidence": 0.95,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": (
                    "TLS 1.2上のreview済みfamily固有Ping応答1 fieldが完全一致し、"
                    "task・operation・任意result送信は行っていない"
                ),
            }
        mismatch_status = status in {
            "tls_messagepack_response_mismatch",
            "tls_version_mismatch",
        }
        if mismatch_status and observation.get("c2_confirmed") is False:
            return {
                "state": "tls_messagepack_endpoint_reachable_protocol_not_confirmed",
                "reachability_confidence": (
                    0.98 if observation.get("target_connection_established") else 0.0
                ),
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": (
                    "TLS endpointへ到達したが、TLS 1.2またはfamily固有heartbeat応答が"
                    "完全一致せずC2確定を禁止"
                ),
            }
        if status == "confirmed_tls_messagepack_c2" or observation.get("c2_confirmed"):
            return {
                "state": "tls_messagepack_confirmation_inconsistent_c2_not_confirmed",
                "reachability_confidence": (
                    0.98 if observation.get("target_connection_established") else 0.0
                ),
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": (
                    "TLS MessagePack確認status、TLS version、応答fingerprint、request budget"
                    "または副作用flagが矛盾するためC2確定を禁止"
                ),
            }
        reachable = bool(observation.get("target_connection_established"))
        return {
            "state": (
                "tls_endpoint_reachable_c2_not_confirmed"
                if reachable
                else "tls_messagepack_not_observed"
            ),
            "reachability_confidence": 0.98 if reachable else 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": (
                0.85
                if status == "closed"
                else (0.40 if status in {"timeout", "tls_handshake_failed"} else 0.0)
            ),
            "reason": (
                "TLS handshakeには到達したがapplication probe未許可のためC2未確認"
                if reachable
                else "review済みTLS MessagePack応答を観測していない"
            ),
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

    if method == "protocol_profile_required":
        resolved = bool(observation.get("resolved_ips"))
        return {
            "state": "protocol_profile_required_c2_unverified",
            "reachability_confidence": 0.15 if resolved else 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": (
                "DNSは解決したが、review済み完全一致profile未登録のためTCP接続・malware application data送信を行わずC2稼働は未検証"
                if resolved
                else "review済み完全一致profile未登録のためTCP接続せず、DNS解決結果も得られずC2稼働は未検証"
            ),
        }

    if method == "redline_checkconnect_soap11":
        forbidden_side_effect = any(
            bool(observation.get(field))
            for field in (
                "synthetic_identity_sent",
                "victim_metadata_sent",
                "registration_attempted",
                "task_poll_attempted",
                "task_content_published",
                "task_executed",
                "payload_download_attempted",
                "redirect_followed",
                "raw_request_published",
                "raw_response_published",
            )
        )
        exact_status = status in {
            "confirmed_redline_checkconnect",
            "redline_checkconnect_protocol_match_result_false",
        }
        exact_flags = (
            observation.get("c2_confirmed") is True
            and observation.get("protocol_response_received") is True
            and observation.get("target_connection_established") is True
            and observation.get("application_data_sent") is True
            and observation.get("request_count") == 1
            and observation.get("request_budget_used") == 1
            and int(observation.get("sent_bytes") or 0) > 0
            and int(observation.get("received_bytes") or 0) > 0
            and not forbidden_side_effect
        )
        if exact_status and exact_flags:
            accepted = status == "confirmed_redline_checkconnect"
            return {
                "state": "c2_protocol_confirmed",
                "reachability_confidence": 1.0,
                "c2_operational_confidence": 0.98 if accepted else 0.95,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": (
                    "完全一致profileのSOAP 1.1 CheckConnectへ厳密なboolean true応答が一致"
                    if accepted
                    else "完全一致profileのSOAP 1.1 CheckConnectへ厳密なboolean false応答が一致。protocolは確認したが後続受入状態は未確認"
                ),
            }
        if exact_status or observation.get("c2_confirmed"):
            return {
                "state": "redline_confirmation_inconsistent_c2_not_confirmed",
                "reachability_confidence": 0.98 if tcp_open else 0.0,
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "RedLine確認status、応答flag、request budgetまたは副作用flagが矛盾するためC2確定を禁止",
            }
        if tcp_open:
            return {
                "state": "redline_endpoint_reachable_protocol_not_confirmed",
                "reachability_confidence": 0.98,
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "endpointへ到達したが厳密なCheckConnectResponse構造が一致しない",
            }

    if method == "xloader_v8_get_registration":
        protocol_evidence = (
            observation.get("protocol_evidence")
            if isinstance(observation.get("protocol_evidence"), dict)
            else {}
        )
        forbidden_side_effect = any(
            bool(observation.get(field))
            for field in (
                "victim_metadata_sent",
                "real_victim_metadata_sent",
                "task_content_published",
                "task_executed",
                "payload_download_attempted",
                "stage_requested",
                "operation_command_sent",
                "redirect_followed",
                "raw_request_published",
                "raw_response_published",
            )
        )
        exact_status = status == "confirmed_xloader_v8_get_registration_command"
        exact_flags = (
            observation.get("c2_confirmed") is True
            and observation.get("target_connection_established") is True
            and observation.get("application_data_sent") is True
            and observation.get("protocol_response_received") is True
            and observation.get("registration_attempted") is True
            and observation.get("registration_accepted") is True
            and observation.get("synthetic_identity_sent") is True
            and observation.get("task_poll_attempted") is True
            and observation.get("task_response_received") is True
            and observation.get("request_count") == 1
            and observation.get("request_budget_used") == 1
            and int(observation.get("sent_bytes") or 0) > 0
            and int(observation.get("received_bytes") or 0) > 0
            and protocol_evidence.get("magic") == "XLNG"
            and protocol_evidence.get("command_id_valid") is True
            and not forbidden_side_effect
        )
        if exact_status and exact_flags:
            return {
                "state": "c2_protocol_confirmed",
                "reachability_confidence": 1.0,
                "c2_operational_confidence": 0.98,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "完全一致real-C2 profileの合成PKT2を1 GETだけ送り、review済み鍵でXLNG command envelopeを復号・検証",
            }
        if exact_status or observation.get("c2_confirmed"):
            return {
                "state": "xloader_confirmation_inconsistent_c2_not_confirmed",
                "reachability_confidence": 0.98 if tcp_open else 0.0,
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "XLoader確認status、暗号応答、合成ID、request budgetまたは副作用flagが矛盾するためC2確定を禁止",
            }
        if status == "xloader_v8_response_mismatch" or tcp_open:
            return {
                "state": "xloader_endpoint_reachable_protocol_not_confirmed",
                "reachability_confidence": 0.98,
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "HTTP到達または応答は得たが、404やdecoyを含み得てXLNG暗号応答が一致しないためC2未確認",
            }

    if method == "darkcomet_server_first_idtype":
        if (
            status == "confirmed_darkcomet_idtype"
            and observation.get("idtype_exact_match") is True
            and observation.get("c2_confirmed") is True
        ):
            return {
                "state": "c2_protocol_confirmed",
                "reachability_confidence": 1.0,
                "c2_operational_confidence": 0.98,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "静的解析鍵でserver-first IDTYPEが完全一致し、送信なしでDarkComet protocolを確認",
            }
        states = {
            "darkcomet_idtype_mismatch": (
                "darkcomet_challenge_mismatch_c2_not_confirmed",
                "受信challengeを復号したがIDTYPEへ一致しないためDarkComet C2とは判定しない",
            ),
            "darkcomet_ciphertext_partial": (
                "darkcomet_partial_challenge_c2_not_confirmed",
                "server-first応答が途中で終了し、DarkComet challengeを判定できない",
            ),
            "darkcomet_ciphertext_malformed": (
                "darkcomet_malformed_challenge_c2_not_confirmed",
                "server-first応答が許可したraw/ASCII-hex形状ではない",
            ),
            "darkcomet_ciphertext_overlong": (
                "darkcomet_overlong_challenge_c2_not_confirmed",
                "server-first応答が12 byte判定上限を超えたためDarkComet C2とは判定しない",
            ),
            "connected_no_response": (
                "darkcomet_server_first_no_response_c2_not_confirmed",
                "TCP接続は成立したがserver-first応答を受信していない",
            ),
            "receive_skipped_deadline_exhausted": (
                "darkcomet_receive_skipped_deadline_exhausted_c2_not_confirmed",
                "TCP接続後に全体期限を消費したためserver-first受信を開始せず、C2とは判定しない",
            ),
        }
        if status in states:
            state, reason = states[status]
            received = int(observation.get("server_first_bytes_received") or 0)
            return {
                "state": state,
                "reachability_confidence": 0.98 if received else 0.90,
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": reason,
            }
        if observation.get("c2_confirmed") or status == "confirmed_darkcomet_idtype":
            return {
                "state": "darkcomet_confirmation_inconsistent_c2_not_confirmed",
                "reachability_confidence": 0.98 if observation.get("target_connection_established") else 0.0,
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": ceiling,
                "negative_observation_confidence": 0.0,
                "reason": "IDTYPE完全一致status・flagの組が整合しないためDarkComet C2とは判定しない",
            }

    if method == "remus_registration_task" and status == "remus_task_schema_unverified":
        return {
            "state": "remus_task_schema_unverified_c2_not_confirmed",
            "reachability_confidence": 0.98 if tcp_open else 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "typeは静的範囲内だがname/dataの実protocol型が未復元のためC2 confirmedを禁止",
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
    allow_purerat_legacy_tls: bool = False,
    allow_authentication: bool = False,
    allow_malware_registration: bool = False,
    allow_reviewed_checkconnect: bool = False,
    acknowledged_redline_profiles: set[str] | frozenset[str] | None = None,
    allow_xloader_registration: bool = False,
    private_credential_vault: Path | None = None,
    xloader_private_material: Path | None = None,
    repository_root: Path | None = None,
) -> dict:
    """レビュー済み対象を各1回だけ観測する。"""
    plan = validate_plan(plan, repository_root=repository_root)
    redline_acknowledgements = frozenset(acknowledged_redline_profiles or ())
    results = []
    for target in plan["targets"]:
        method = target.get("method", "tcp_connect")
        if method == "dns_resolve" or method == "protocol_profile_required":
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
        elif method == "purerat_direct_tls_certificate_pin":
            raw = _purerat_direct_tls_observation(
                target,
                allow_network,
                allow_purerat_legacy_tls,
            )
        elif method == "darkcomet_server_first_idtype":
            raw = _darkcomet_server_first_observation(target, allow_network, repository_root)
        elif method == "redline_checkconnect_soap11":
            raw = _redline_checkconnect_observation(
                target,
                allow_network,
                allow_reviewed_checkconnect,
                redline_acknowledgements,
            )
        elif method == "xloader_v8_get_registration":
            raw = _xloader_registration_observation(
                target,
                allow_network,
                allow_xloader_registration,
                xloader_private_material,
                repository_root,
            )
        elif method in {
            "stealc_v2_registration_task",
            "lumma_v6_registration_task",
            "remus_registration_task",
        }:
            raw = _stealer_registration_observation(target, allow_network, allow_malware_registration, repository_root)
        else:
            raw = probe(_probe_args(target, allow_network))
        if method == "purerat_direct_tls_certificate_pin":
            raw = _sanitize_purerat_observation(raw)
        elif method in {"asyncrat_tls_messagepack", "venomrat_tls_messagepack"}:
            raw = _sanitize_tls_messagepack_observation(target, raw)
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
                "protocol_profile_evidence_sha256": target.get("protocol_profile_evidence_sha256"),
                "protocol_profile_evidence_source": target.get("protocol_profile_evidence_source"),
                "method_description": METHOD_LABELS[target.get("method", "tcp_connect")],
                "http_path": target.get("http_path") if target.get("method") == "http_get" else None,
                "sample_sha256s": target.get("sample_sha256s", []),
                "associated_case_count": int(
                    target.get("associated_case_count", len(target.get("sample_sha256s", [])))
                ),
                "analyzed_dates": target.get("analyzed_dates", []),
                "protocol_hints": target.get("protocol_hints", []),
                "sources": target["sources"],
                "observation": observation,
                "assessment": assess_observation(target, observation),
            }
        )
    counts = Counter(item["assessment"]["state"] for item in results)
    reviewed_message_results = [
        item
        for item in results
        if item["method"]
        in {
            "winos_heartbeat",
            "vvas_checkin",
            "asyncrat_tls_messagepack",
            "venomrat_tls_messagepack",
            "stealc_v2_registration_task",
            "lumma_v6_registration_task",
            "remus_registration_task",
            "redline_checkconnect_soap11",
            "xloader_v8_get_registration",
        }
        and item["observation"].get("application_data_sent")
    ]
    reviewed_protocol_probe_count = sum(bool(item.get("protocol_profile_id")) for item in results)
    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(UTC).isoformat(),
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
            "victim_metadata_sent": any(bool(item["observation"].get("victim_metadata_sent")) for item in results),
            "command_polling_performed": any(bool(item["observation"].get("task_poll_attempted")) for item in results),
            "malware_registration_tasking_enabled": allow_malware_registration,
            "registration_attempted_count": sum(
                bool(item["observation"].get("registration_attempted")) for item in results
            ),
            "task_poll_attempted_count": sum(bool(item["observation"].get("task_poll_attempted")) for item in results),
            "task_available_count": sum(item["observation"].get("task_available") is True for item in results),
            "task_content_published": any(
                bool(item["observation"].get("task_content_published"))
                for item in results
            ),
            "task_executed": any(
                bool(item["observation"].get("task_executed"))
                for item in results
            ),
            "payload_download_attempted": any(
                bool(item["observation"].get("payload_download_attempted"))
                for item in results
            ),
            "range_scan_performed": False,
            "tcp_open_confirms_c2": False,
            "network_enabled": allow_network,
            "reviewed_application_probes_enabled": allow_application_probes,
            "purerat_legacy_tls_certificate_probe_enabled": (
                allow_purerat_legacy_tls
            ),
            "reviewed_redline_checkconnect_enabled": allow_reviewed_checkconnect,
            "acknowledged_redline_profile_count": len(
                redline_acknowledgements
            ),
            "private_authentication_enabled": allow_authentication,
            "reviewed_malware_registration_enabled": allow_malware_registration,
            "reviewed_xloader_registration_enabled": allow_xloader_registration,
            "private_credential_vault_used": private_credential_vault is not None,
            "xloader_private_material_used": xloader_private_material is not None,
            "authentication_attempted_count": sum(
                bool(item["observation"].get("authentication_attempted")) for item in results
            ),
            "file_transfer_attempted": any(
                bool(item["observation"].get("file_transfer_attempted")) for item in results
            ),
            "redline_checkconnect_attempted_count": sum(
                item["method"] == "redline_checkconnect_soap11"
                and bool(item["observation"].get("application_data_sent"))
                for item in results
            ),
            "redline_checkconnect_confirmed_count": sum(
                item["method"] == "redline_checkconnect_soap11"
                and item["assessment"]["state"] == "c2_protocol_confirmed"
                for item in results
            ),
            "xloader_registration_attempted_count": sum(
                item["method"] == "xloader_v8_get_registration"
                and bool(item["observation"].get("registration_attempted"))
                for item in results
            ),
            "xloader_protocol_confirmed_count": sum(
                item["method"] == "xloader_v8_get_registration"
                and item["assessment"]["state"] == "c2_protocol_confirmed"
                for item in results
            ),
            "application_request_count": sum(
                int(item["observation"].get("request_count") or 0)
                for item in results
            ),
            "certificate_mismatch_excludes_c2": False,
            "darkcomet_dns_timeout_bounded": False,
            "darkcomet_deadline_scope": "post_dns_connect_receive",
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
    if policy.get("redline_checkconnect_attempted_count", 0):
        active_probe_policy += (
            f"RedLine CheckConnectは"
            f"{policy.get('redline_checkconnect_attempted_count', 0)}対象へ引数なしSOAP要求を各1回送り、"
            f"{policy.get('redline_checkconnect_confirmed_count', 0)}対象で厳密なboolean応答を確認しました。"
        )
    if policy.get("xloader_registration_attempted_count", 0):
        active_probe_policy += (
            f"XLoaderはreview済みreal-C2 profile "
            f"{policy.get('xloader_registration_attempted_count', 0)}対象へ合成PKT2を各1 GETだけ送り、"
            f"{policy.get('xloader_protocol_confirmed_count', 0)}対象で暗号応答を確認しました。"
        )
    if policy.get("task_poll_attempted_count", 0):
        active_probe_policy += (
            f"StealC／Lumma／Remusの登録後task取得またはXLoader単一登録応答のcommand有無確認を"
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
            f"監視scopeは `{scope}` です。`.onion`は対象外で、入力planへ明示した根拠付きendpointだけを確認しています。"
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
        "--allow-purerat-legacy-tls-certificate-probe",
        action="store_true",
        help="完全一致PureRAT profileのTLS 1.0 leaf証明書pin観測を許可します（application data送信なし）。",
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
        "--allow-reviewed-checkconnect",
        action="store_true",
        help="完全一致RedLine profileの引数なしSOAP CheckConnect 1要求を許可します。",
    )
    parser.add_argument(
        "--acknowledge-redline-profile",
        action="append",
        default=[],
        metavar="PROFILE_ID",
        help="送信を承認するRedLine profile ID。完全一致で、profileごとに指定します。",
    )
    parser.add_argument(
        "--allow-xloader-registration",
        action="store_true",
        help="review済みreal-C2 XLoader profileの合成PKT2登録GET 1要求を許可します。",
    )
    parser.add_argument(
        "--private-credential-vault",
        type=Path,
        help="リポジトリ外のAgentTesla sensitive_local_only JSON。",
    )
    parser.add_argument(
        "--xloader-private-material",
        type=Path,
        help="リポジトリ外のXLoader検体固有鍵・合成PKT2 JSON。",
    )
    args = parser.parse_args()
    try:
        plan = json.loads(args.targets.read_text(encoding="utf-8"))
        result = monitor(
            plan,
            allow_network=args.allow_network,
            allow_application_probes=args.allow_reviewed_application_probes,
            allow_purerat_legacy_tls=(
                args.allow_purerat_legacy_tls_certificate_probe
            ),
            allow_authentication=args.allow_authentication,
            allow_malware_registration=args.allow_malware_registration_tasking,
            allow_reviewed_checkconnect=args.allow_reviewed_checkconnect,
            acknowledged_redline_profiles=set(
                args.acknowledge_redline_profile
            ),
            allow_xloader_registration=args.allow_xloader_registration,
            private_credential_vault=args.private_credential_vault,
            xloader_private_material=args.xloader_private_material,
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
