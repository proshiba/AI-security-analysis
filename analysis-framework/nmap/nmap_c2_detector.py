#!/usr/bin/env python3
"""C2監視計画をallowlist済みNmap NSEへ変換し、公開可能な観測へ正規化する。"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

NMAP_ROOT = Path(__file__).resolve().parent
FRAMEWORK_ROOT = NMAP_ROOT.parent
COMMON_ROOT = FRAMEWORK_ROOT / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

from c2_protocol_probe_profiles import (  # noqa: E402
    load_profiles,
    profile_registry_metadata,
    resolve_profile,
)
SCRIPT_ROOT = NMAP_ROOT / "scripts"
SAFE_ARGUMENT_KEY = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
SAFE_SHA256 = re.compile(r"[0-9a-f]{64}")
MAXIMUM_ARGUMENT_BYTES = 4096
GENERIC_PROTOCOL_METHODS = {
    "http": "http_get",
    "https": "http_get",
    "tcp": "tcp_connect",
    "tls": "tls_handshake",
}


class NmapC2Error(ValueError):
    """Nmap C2実行計画または結果が安全契約を満たさない場合のエラー。"""


@dataclass(frozen=True)
class NmapBinding:
    """monitor methodと単一NSE script／modeの固定対応。"""

    script: str
    mode_key: str | None = None
    mode_value: str | None = None
    sends_application_data: bool = False
    confirmation_allowed: bool = True


METHOD_BINDINGS: dict[str, NmapBinding] = {
    "dns_resolve": NmapBinding("c2-dns-observe.nse", confirmation_allowed=False),
    "protocol_profile_required": NmapBinding("c2-dns-observe.nse", confirmation_allowed=False),
    "tcp_connect": NmapBinding(
        "c2-transport-observe.nse", "c2-transport.mode", "tcp-open", confirmation_allowed=False
    ),
    "passive_banner": NmapBinding(
        "c2-transport-observe.nse", "c2-transport.mode", "server-first", confirmation_allowed=False
    ),
    "tls_handshake": NmapBinding(
        "c2-transport-observe.nse", "c2-transport.mode", "tls", confirmation_allowed=False
    ),
    "http_get": NmapBinding(
        "c2-transport-observe.nse", "c2-transport.mode", "http-get", True, False
    ),
    "winos_heartbeat": NmapBinding("valleyrat-c2.nse", "valleyrat.mode", "winos", True),
    "vvas_checkin": NmapBinding("valleyrat-c2.nse", "valleyrat.mode", "vvas", True),
    "n520_server_first": NmapBinding("valleyrat-c2.nse", "valleyrat.mode", "n520"),
    "purerat_direct_tls_certificate_pin": NmapBinding(
        "purerat-direct-tls.nse", confirmation_allowed=False
    ),
    # prelude variant: TCP接続直後に 04 00 00 00 を送ってからTLS 1.2へ昇格する。
    # 4 byteを送るので sends_application_data=True。
    "purerat_tls_prelude": NmapBinding(
        "purerat-c2.nse", sends_application_data=True
    ),
    "ftp_authenticated": NmapBinding("agenttesla-ftp-c2.nse", sends_application_data=True),
    "asyncrat_tls_messagepack": NmapBinding(
        "dotnet-rat-c2.nse", "dotnet-rat.family", "asyncrat", True
    ),
    "venomrat_tls_messagepack": NmapBinding(
        "dotnet-rat-c2.nse", "dotnet-rat.family", "venomrat", True
    ),
    "stealc_v2_registration_task": NmapBinding(
        "stealer-http-c2.nse", "stealer.family", "stealc", True
    ),
    "lumma_v6_registration_task": NmapBinding(
        "stealer-http-c2.nse", "stealer.family", "lumma", True, False
    ),
    "remus_registration_task": NmapBinding(
        "stealer-http-c2.nse", "stealer.family", "remus", True, False
    ),
    "darkcomet_server_first_idtype": NmapBinding("darkcomet-c2.nse"),
    "redline_checkconnect_soap11": NmapBinding("redline-c2.nse", sends_application_data=True),
    "xloader_v8_get_registration": NmapBinding("xloader-c2.nse", confirmation_allowed=False),
    "formbook_reviewed_route_head": NmapBinding(
        "stealer-route-c2.nse",
        "stealer-route.mode",
        "formbook",
        sends_application_data=True,
        confirmation_allowed=False,
    ),
}

BOOLEAN_FIELDS = {
    "application_data_sent",
    "authentication_accepted",
    "authentication_attempted",
    "c2_confirmed",
    "certificate_exact_match",
    "certificate_mismatch_excludes_c2",
    "command_polling_performed",
    "crc_matches",
    "dns_resolution_attempted",
    "file_operation_attempted",
    "ftp_220_marker",
    "magic_matches",
    "network_contacted_by_nmap_scan",
    "operation_command_sent",
    "payload_download_attempted",
    "plaintext_prelude_sent",
    "probable_c2",
    "redirect_followed",
    "registration_attempted",
    "stage_downloaded",
    "stage_requested",
    "synthetic_identity_sent",
    "target_connection_established",
    "target_contact_attempted",
    "task_executed",
    "task_poll_attempted",
    "tls_version_enforced_by_nse",
    "victim_metadata_sent",
}
INTEGER_FIELDS = {
    "banner_code",
    "banner_length",
    "declared_length",
    "declared_stage_size",
    "expected_stage_size",
    "http_status",
    "pass_reply_code",
    "received_bytes",
    "request_count",
    "response_size",
    "sent_bytes",
    "user_reply_code",
}
FLOAT_FIELDS = {"confidence"}
ALLOWED_SCRIPT_FIELDS = BOOLEAN_FIELDS | INTEGER_FIELDS | FLOAT_FIELDS | {
    "certificate_sha256",
    "family",
    "note",
    "protocol",
    "resolved_ip",
    "response_command",
    "response_packet",
    "session_id",
    "status",
    "variant",
}
FORBIDDEN_FIELD_MARKERS = (
    "body",
    "ciphertext",
    "command_content",
    "cookie",
    "credential",
    "key",
    "password",
    "plaintext",
    "private",
    "raw",
    "request_data",
    "response_data",
    "secret",
    "task_content",
    "token",
)


def _nmap_executable(value: str | Path | None) -> Path:
    """Nmap実体を固定候補から解決し、通常file以外を拒否する。"""

    candidates = [
        Path(value) if value else None,
        Path(os.environ["NMAP_EXE"]) if os.environ.get("NMAP_EXE") else None,
        Path(r"C:\Users\Administrator\Tools\Nmap\nmap.exe"),
        Path(shutil.which("nmap") or ""),
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("Nmap executableが見つかりません")


def _strict_scalar(value: str) -> bool | int | float | str:
    lowered = value.casefold()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return value


def _table_value(element: ET.Element) -> object:
    if element.tag == "elem":
        return _strict_scalar(element.text or "")
    result: dict[str, object] = {}
    anonymous: list[object] = []
    for child in element:
        value = _table_value(child)
        key = child.get("key")
        if key:
            result[key] = value
        else:
            anonymous.append(value)
    if anonymous:
        result["items"] = anonymous
    return result


def parse_nmap_xml(xml_bytes: bytes, expected_script: str) -> dict[str, object]:
    """Nmap XMLから単一allowlist scriptのscalar結果だけを抽出する。"""

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise NmapC2Error("Nmap XMLを解析できません") from exc
    script_id = Path(expected_script).stem
    matching = [node for node in root.findall(".//script") if node.get("id") == script_id]
    if len(matching) > 1:
        raise NmapC2Error("同じNSE結果が複数あります")
    addresses = sorted(
        {
            node.get("addr", "")
            for node in root.findall(".//host/address")
            if node.get("addrtype") in {"ipv4", "ipv6"} and node.get("addr")
        }
    )
    port_nodes = root.findall(".//host/ports/port")
    port_state = None
    if port_nodes:
        states = {node.find("state").get("state") for node in port_nodes if node.find("state") is not None}
        if len(states) == 1:
            port_state = states.pop()
    if not matching:
        return {
            "status": "closed" if port_state == "closed" else "nmap_script_no_result",
            "resolved_ips": addresses,
            "nmap_port_state": port_state,
        }
    node = matching[0]
    flattened: dict[str, object] = {}
    for child in node:
        if child.tag == "elem" and child.get("key"):
            flattened[child.get("key", "")] = _table_value(child)
        elif child.tag == "table":
            value = _table_value(child)
            if isinstance(value, dict):
                flattened.update(value)
    if not flattened:
        return {
            "status": "nmap_script_error",
            "resolved_ips": addresses,
            "nmap_port_state": port_state,
        }
    flattened["resolved_ips"] = addresses
    flattened["nmap_port_state"] = port_state
    flattened["nmap_version"] = root.get("version")
    return flattened


def _converted_script_fields(raw: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in raw.items():
        normalized = str(key).casefold()
        if any(marker in normalized for marker in FORBIDDEN_FIELD_MARKERS):
            continue
        if key not in ALLOWED_SCRIPT_FIELDS:
            continue
        if key in BOOLEAN_FIELDS:
            if isinstance(value, bool):
                result[key] = value
            elif isinstance(value, str) and value.casefold() in {"true", "false"}:
                result[key] = value.casefold() == "true"
        elif key in INTEGER_FIELDS:
            if isinstance(value, bool):
                continue
            try:
                converted = int(value)
            except (TypeError, ValueError):
                continue
            if 0 <= converted <= 16 * 1024 * 1024:
                result[key] = converted
        elif key in FLOAT_FIELDS:
            try:
                converted_float = float(value)
            except (TypeError, ValueError):
                continue
            if 0.0 <= converted_float <= 1.0:
                result[key] = converted_float
        elif isinstance(value, str) and len(value.encode("utf-8")) <= 512:
            result[key] = value
    return result


def _quote_argument(value: object) -> str:
    text = str(value)
    if not text or len(text.encode("utf-8")) > MAXIMUM_ARGUMENT_BYTES:
        raise NmapC2Error("NSE引数が空、または上限を超えています")
    if any(character in text for character in ("\r", "\n", "\x00")):
        raise NmapC2Error("NSE引数に制御文字を含めることはできません")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_script_args(arguments: Mapping[str, object]) -> str:
    """NSE引数をshellへ露出しないargs-file用の1行へ変換する。"""

    entries: list[str] = []
    for key in sorted(arguments):
        if SAFE_ARGUMENT_KEY.fullmatch(key) is None:
            raise NmapC2Error("NSE引数keyが不正です")
        entries.append(f"{key}={_quote_argument(arguments[key])}")
    rendered = ",".join(entries)
    if len(rendered.encode("utf-8")) > 32 * 1024:
        raise NmapC2Error("NSE引数fileが上限を超えています")
    return rendered + "\n"


def _load_ftp_credential(vault_path: Path, reference: str, host: str, port: int) -> dict[str, str]:
    payload = json.loads(vault_path.read_text(encoding="utf-8"))
    if payload.get("classification") != "sensitive_local_only":
        raise NmapC2Error("private vaultのclassificationが不正です")
    matches = [
        item
        for item in payload.get("records", [])
        if isinstance(item, dict) and item.get("credential_id") == reference
    ]
    if len(matches) != 1:
        raise NmapC2Error("private資格情報参照は正確に1件一致する必要があります")
    record = matches[0]
    if str(record.get("protocol", "")).casefold() != "ftp":
        raise NmapC2Error("private資格情報はFTP recordではありません")
    if str(record.get("endpoint", "")).casefold() != f"{host.casefold().rstrip('.')}:{port}":
        raise NmapC2Error("private資格情報とendpointが一致しません")
    values: dict[str, str] = {}
    for source, destination in (("username", "agenttesla.user"), ("password", "agenttesla.pass")):
        value = record.get(source)
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
            raise NmapC2Error(f"FTP {source}が安全境界外です")
        if any(character in value for character in ("\r", "\n", "\x00")):
            raise NmapC2Error(f"FTP {source}に制御文字があります")
        values[destination] = value
    return values


def _profile_arguments(
    target: Mapping[str, object],
    binding: NmapBinding,
    *,
    private_credential_vault: Path | None,
    acknowledged_redline_profiles: frozenset[str],
) -> tuple[dict[str, object], dict[str, object]]:
    arguments: dict[str, object] = {}
    if binding.mode_key and binding.mode_value:
        arguments[binding.mode_key] = binding.mode_value
    method = str(target.get("method", "tcp_connect"))
    profile: dict[str, object] = {}
    profile_id = target.get("protocol_profile_id")
    if profile_id:
        profile = resolve_profile(
            str(profile_id),
            str(target["host"]),
            int(target["port"]),
            expected_registry_sha256=(
                str(target["protocol_profile_registry_sha256"])
                if target.get("protocol_profile_registry_sha256")
                else None
            ),
        )
        arguments["c2.profile-id"] = profile["profile_id"]
    timeout = float(target.get("timeout_seconds", profile.get("timeout_seconds", 3.0)))
    arguments_key = {
        "winos_heartbeat": "valleyrat.timeout",
        "vvas_checkin": "valleyrat.timeout",
        "n520_server_first": "valleyrat.timeout",
        "ftp_authenticated": "agenttesla.timeout",
        "asyncrat_tls_messagepack": "dotnet-rat.timeout",
        "venomrat_tls_messagepack": "dotnet-rat.timeout",
        "stealc_v2_registration_task": "stealer.timeout",
        "lumma_v6_registration_task": "stealer.timeout",
        "remus_registration_task": "stealer.timeout",
        "darkcomet_server_first_idtype": "darkcomet.timeout",
    }.get(method, "c2-transport.timeout")
    arguments[arguments_key] = int(timeout * 1000)
    if method in {"passive_banner", "http_get"}:
        arguments["c2-transport.max-response"] = int(target.get("maximum_response_bytes", 256))
    if method == "http_get":
        arguments["c2-transport.path"] = target.get("http_path", "/")
        arguments["c2-transport.host"] = target.get("http_host") or target["host"]
        arguments["c2-transport.http-tls"] = str(target.get("protocol")) == "https"
    elif method == "ftp_authenticated":
        if private_credential_vault is None:
            raise NmapC2Error("private credential vaultがありません")
        arguments.update(
            _load_ftp_credential(
                private_credential_vault,
                str(profile["credential_reference"]),
                str(profile["host"]),
                int(profile["port"]),
            )
        )
    elif method in {"asyncrat_tls_messagepack", "venomrat_tls_messagepack"}:
        arguments["dotnet-rat.expected-cert"] = profile["expected_certificate_sha256"]
    elif method == "purerat_tls_prelude":
        # 対象portをprofileの1件へ固定し、走査した他の開放portへ4 byteを
        # 送らないようにする。
        arguments["purerat.expected-cert"] = profile["expected_certificate_sha256"]
        arguments["purerat.ports"] = str(profile["port"])
    elif method == "stealc_v2_registration_task":
        arguments.update(
            {
                "stealer.build": profile["build"],
                "stealer.host": profile["http_host"],
                "stealer.key-base64": profile["network_rc4_key_base64"],
            }
        )
    elif method == "lumma_v6_registration_task":
        arguments.update(
            {
                "stealer.cid": profile["cid"] or "empty",
                "stealer.host": profile["http_host"],
                "stealer.uid": profile["uid"],
            }
        )
    elif method == "remus_registration_task":
        arguments.update(
            {
                "stealer.exp": profile["exp"],
                "stealer.host": profile["http_host"],
                "stealer.tag": profile["tag"],
            }
        )
    elif method == "darkcomet_server_first_idtype":
        arguments["darkcomet.key-base64"] = profile["network_rc4_key_base64"]
    elif method == "redline_checkconnect_soap11":
        profile_id_text = str(profile["profile_id"])
        if profile_id_text not in acknowledged_redline_profiles:
            raise NmapC2Error("RedLine profile acknowledgementがありません")
        arguments["redline.profile-id"] = profile_id_text
        arguments["redline.acknowledge-profile"] = profile_id_text
    elif method == "xloader_v8_get_registration":
        arguments["xloader.mode"] = "transport-only"
        arguments["xloader.acknowledge-no-protocol-check"] = "true"
    return arguments, profile


def _target_for_nmap(target: Mapping[str, object], profile: Mapping[str, object]) -> str:
    pinned = profile.get("pinned_ips")
    if isinstance(pinned, list) and len(pinned) == 1 and isinstance(pinned[0], str):
        return pinned[0]
    return str(target["host"])


def _disabled(status: str) -> dict[str, object]:
    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "execution_engine": "nmap_nse",
        "status": status,
        "alive": False,
        "c2_confirmed": False,
        "probable_c2": False,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "application_data_sent": False,
        "request_count": 0,
        "request_budget_used": 0,
        "sent_bytes": 0,
        "received_bytes": 0,
        "resolved_ips": [],
        "registration_attempted": False,
        "authentication_attempted": False,
        "file_transfer_attempted": False,
        "credential_material_published": False,
        "task_poll_attempted": False,
        "task_content_published": False,
        "task_executed": False,
        "payload_download_attempted": False,
        "victim_metadata_sent": False,
        "raw_request_published": False,
        "raw_response_published": False,
    }


def _gate_status(
    method: str,
    *,
    allow_network: bool,
    allow_application_probes: bool,
    allow_purerat_legacy_tls: bool,
    allow_authentication: bool,
    allow_malware_registration: bool,
    allow_reviewed_checkconnect: bool,
    allow_xloader_registration: bool,
) -> str | None:
    if not allow_network:
        return "network_disabled"
    if method in {
        "asyncrat_tls_messagepack",
        "formbook_reviewed_route_head",
        "venomrat_tls_messagepack",
    } and not allow_application_probes:
        return "tls_handshake_only_application_probe_disabled"
    if method == "purerat_direct_tls_certificate_pin" and not allow_purerat_legacy_tls:
        return "legacy_tls_disabled"
    if method == "ftp_authenticated" and not allow_authentication:
        return "authentication_disabled"
    if method in {
        "stealc_v2_registration_task",
        "lumma_v6_registration_task",
        "remus_registration_task",
    } and not allow_malware_registration:
        return "malware_registration_tasking_disabled"
    if method == "redline_checkconnect_soap11" and not allow_reviewed_checkconnect:
        return "reviewed_checkconnect_not_authorized"
    if method == "xloader_v8_get_registration" and not allow_xloader_registration:
        return "xloader_registration_disabled"
    return None


def _normalize_result(
    target: Mapping[str, object],
    binding: NmapBinding,
    profile: Mapping[str, object],
    parsed: Mapping[str, object],
) -> dict[str, object]:
    result = _disabled(str(parsed.get("status", "nmap_script_no_result")))
    result.update(_converted_script_fields(parsed))
    result.update(
        {
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "execution_engine": "nmap_nse",
            "nmap_script": binding.script,
            "nmap_port_state": parsed.get("nmap_port_state"),
            "nmap_version": parsed.get("nmap_version"),
            "protocol_profile_id": target.get("protocol_profile_id"),
            "resolved_ips": list(parsed.get("resolved_ips", [])),
            "target_contact_attempted": True,
            "network_contacted_by_nmap_scan": True,
        }
    )
    method = str(target.get("method", "tcp_connect"))
    if method in {"dns_resolve", "protocol_profile_required"}:
        result["alive"] = False
        result["target_contact_attempted"] = False
        result["target_connection_established"] = False
        result["application_data_sent"] = False
        result["request_count"] = 0
        return result
    expected_family = str(target.get("family", profile.get("family", "unknown")))
    observed_family = result.get("family")
    if observed_family not in {None, "unclassified", expected_family}:
        result.update(
            {
                "status": "nmap_script_family_mismatch",
                "c2_confirmed": False,
                "probable_c2": False,
            }
        )
    result["family"] = expected_family
    port_open = parsed.get("nmap_port_state") == "open"
    result["alive"] = bool(port_open or result.get("target_connection_established"))
    result["target_connection_established"] = bool(
        port_open or result.get("target_connection_established")
    )
    sent_bytes = int(result.get("sent_bytes") or 0)
    received_bytes = int(result.get("received_bytes") or result.get("response_size") or 0)
    result["sent_bytes"] = sent_bytes
    result["received_bytes"] = received_bytes
    result["application_data_sent"] = bool(
        binding.sends_application_data
        and (
            sent_bytes > 0
            or result.get("application_data_sent")
            or result.get("authentication_attempted")
            or result.get("synthetic_identity_sent")
        )
    )
    result["request_count"] = int(
        result.get("request_count") or (1 if result["application_data_sent"] else 0)
    )
    result["request_budget_used"] = result["request_count"]
    result["protocol_response_received"] = bool(
        result.get("c2_confirmed")
        or result.get("probable_c2")
        or received_bytes > 0
        or result.get("http_status") is not None
    )
    if result.get("banner_length"):
        result["banner"] = {
            "length": int(result["banner_length"]),
            "ftp_220_marker": bool(result.get("ftp_220_marker")),
        }
    if result.get("http_status") is not None:
        result["http"] = {"status": int(result["http_status"])}
    certificate = result.get("certificate_sha256")
    if isinstance(certificate, str) and SAFE_SHA256.fullmatch(certificate.casefold()):
        result["tls"] = {
            "handshake": True,
            "certificate": {
                "observed_sha256": certificate.casefold(),
                "expected_sha256": profile.get("expected_certificate_sha256"),
                "exact_match": result.get("certificate_exact_match"),
                "state": (
                    "exact_match"
                    if result.get("certificate_exact_match") is True
                    else "mismatch_inconclusive"
                ),
                "certificate_mismatch_excludes_c2": False,
            },
        }
    if not binding.confirmation_allowed and result.get("c2_confirmed"):
        result["nse_reported_match"] = True
        result["c2_confirmed"] = False
    if str(target.get("method")) == "purerat_direct_tls_certificate_pin":
        exact = result.get("certificate_exact_match") is True
        result.update(
            {
                "status": (
                    "purerat_nse_certificate_match_tls_version_unverified"
                    if exact
                    else "purerat_direct_tls_certificate_mismatch_inconclusive"
                ),
                "c2_confirmed": False,
                "tls_version_enforced_by_nse": False,
                "certificate_mismatch_excludes_c2": False,
                "certificate_mismatch_excludes_family_c2": False,
                "tls_version_mismatch_excludes_c2": False,
                "tls_version_mismatch_excludes_family_c2": False,
                "application_data_sent": False,
                "plaintext_prelude_sent": False,
                "sent_bytes": 0,
                "request_count": 0,
                "request_budget_used": 0,
                "registration_attempted": False,
                "task_poll_attempted": False,
                "task_executed": False,
            }
        )
    for field in (
        "operation_command_sent",
        "payload_download_attempted",
        "raw_request_published",
        "raw_response_published",
        "registration_attempted",
        "stage_requested",
        "task_content_published",
        "task_executed",
        "task_poll_attempted",
        "victim_metadata_sent",
    ):
        result.setdefault(field, False)
    return result


def probe_target_with_nmap(
    target: Mapping[str, object],
    *,
    allow_network: bool = False,
    allow_application_probes: bool = False,
    allow_purerat_legacy_tls: bool = False,
    allow_authentication: bool = False,
    allow_malware_registration: bool = False,
    allow_reviewed_checkconnect: bool = False,
    acknowledged_redline_profiles: frozenset[str] = frozenset(),
    allow_xloader_registration: bool = False,
    private_credential_vault: Path | None = None,
    nmap_executable: str | Path | None = None,
    executor: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, object]:
    """単一targetをallowlist済みNSEだけで観測する。"""

    method = str(target.get("method", "tcp_connect"))
    binding = METHOD_BINDINGS.get(method)
    if binding is None:
        raise NmapC2Error(f"Nmap NSEへ未登録のmethodです: {method}")
    if target.get("transport", "direct") != "direct":
        return _disabled("nmap_transport_unsupported")
    gate = _gate_status(
        method,
        allow_network=allow_network,
        allow_application_probes=allow_application_probes,
        allow_purerat_legacy_tls=allow_purerat_legacy_tls,
        allow_authentication=allow_authentication,
        allow_malware_registration=allow_malware_registration,
        allow_reviewed_checkconnect=allow_reviewed_checkconnect,
        allow_xloader_registration=allow_xloader_registration,
    )
    if gate:
        return _disabled(gate)
    if method == "ftp_authenticated" and private_credential_vault is None:
        return _disabled("private_credential_vault_missing")
    if method == "xloader_v8_get_registration":
        result = _disabled("xloader_nse_private_protocol_not_implemented")
        result["transport_only_nse_available"] = True
        return result
    try:
        arguments, profile = _profile_arguments(
            target,
            binding,
            private_credential_vault=private_credential_vault,
            acknowledged_redline_profiles=acknowledged_redline_profiles,
        )
        executable = _nmap_executable(nmap_executable)
        script_path = (SCRIPT_ROOT / binding.script).resolve()
        if script_path.parent != SCRIPT_ROOT.resolve() or not script_path.is_file():
            raise NmapC2Error("allowlist済みNSE scriptが見つかりません")
        target_value = _target_for_nmap(target, profile)
        timeout_seconds = max(1, min(int(float(target.get("timeout_seconds", 3.0)) + 7), 15))
        with tempfile.TemporaryDirectory(prefix="nmap-c2-args-") as directory:
            args_path = Path(directory) / "script-args.txt"
            args_path.write_text(render_script_args(arguments), encoding="utf-8", newline="\n")
            try:
                args_path.chmod(0o600)
            except OSError:
                pass
            command = [str(executable), "-n", "-Pn"]
            if method in {"dns_resolve", "protocol_profile_required"}:
                command.extend(["-sn"])
            else:
                command.extend(["-sT", "-p", str(int(target["port"]))])
            command.extend(
                [
                    "--host-timeout",
                    f"{timeout_seconds}s",
                    "--script-timeout",
                    f"{timeout_seconds - 1}s",
                    "--script",
                    str(script_path),
                    "--script-args-file",
                    str(args_path),
                    "-oX",
                    "-",
                    target_value,
                ]
            )
            completed = executor(
                command,
                capture_output=True,
                timeout=timeout_seconds + 10,
                check=False,
            )
        if completed.returncode != 0:
            result = _disabled("nmap_execution_failed")
            result["target_contact_attempted"] = True
            result["error_type"] = "NmapNonZeroExit"
            return result
        parsed = parse_nmap_xml(completed.stdout, binding.script)
        return _normalize_result(target, binding, profile, parsed)
    except FileNotFoundError:
        return _disabled("nmap_unavailable")
    except (NmapC2Error, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        result = _disabled("nmap_probe_error")
        if method == "ftp_authenticated":
            result["status"] = "private_credential_vault_error"
        result["error_type"] = type(exc).__name__
        return result


def normalize_legacy_target(
    target: Mapping[str, object],
    *,
    sample_sha256: str | None = None,
) -> dict[str, object]:
    """旧live targetを中央profileまたは汎用transport NSEへ正規化する。"""

    host_value = target.get("host")
    port_value = target.get("port")
    protocol_value = target.get("protocol", "tcp")
    if (
        not isinstance(host_value, str)
        or not 1 <= len(host_value) <= 253
        or host_value.startswith("-")
        or any(ord(character) < 33 or ord(character) == 127 for character in host_value)
    ):
        raise NmapC2Error("target hostが不正です")
    if isinstance(port_value, bool) or not isinstance(port_value, int) or not 1 <= port_value <= 65535:
        raise NmapC2Error("target portが不正です")
    if not isinstance(protocol_value, str):
        raise NmapC2Error("target protocolが不正です")
    protocol = protocol_value.casefold()
    host = host_value.casefold().rstrip(".")
    if sample_sha256 is not None:
        sample_sha256 = sample_sha256.casefold()
        if SAFE_SHA256.fullmatch(sample_sha256) is None:
            raise NmapC2Error("sample SHA-256が不正です")

    profiles = load_profiles()
    matches = [
        profile
        for profile in profiles.values()
        if profile["host"] == host
        and profile["port"] == port_value
        and profile["protocol"] == protocol
        and (
            sample_sha256 is None
            or sample_sha256 in profile.get("sample_sha256s", [])
        )
    ]
    if len(matches) > 1:
        raise NmapC2Error("endpointとsampleに一致するprofileが複数あります")
    registry = profile_registry_metadata()
    if matches:
        profile = matches[0]
        samples = list(profile.get("sample_sha256s", []))
        return {
            "target_id": f"legacy-reviewed-{profile['profile_id']}",
            "family": profile["family"],
            "host": host,
            "port": port_value,
            "transport": "direct",
            "protocol": protocol,
            "method": profile["method"],
            "sample_sha256s": samples,
            "associated_case_count": len(samples),
            "sources": [profile["source"]],
            "roles": [profile["role"]],
            "selection_basis": "中央registryのreview済みNmap NSE profile完全一致",
            "protocol_profile_id": profile["profile_id"],
            "protocol_profile_registry_source": registry["source"],
            "protocol_profile_registry_sha256": registry["sha256"],
            "timeout_seconds": profile["timeout_seconds"],
            "maximum_request_bytes": profile.get("maximum_request_bytes"),
            "maximum_response_bytes": profile["maximum_response_bytes"],
        }

    if target.get("send_hex") is not None or target.get("expected_stage_size") is not None:
        raise NmapC2Error("未レビューの送信値またはstage取得はNmap NSEへ移行できません")
    method = GENERIC_PROTOCOL_METHODS.get(protocol)
    if method is None:
        raise NmapC2Error(f"Nmap NSEへ未対応のlegacy protocolです: {protocol}")
    timeout_value = target.get("timeout_seconds", 3.0)
    if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)):
        raise NmapC2Error("timeoutが不正です")
    timeout = float(timeout_value)
    if not 0.1 <= timeout <= 30.0:
        raise NmapC2Error("timeoutが許容範囲外です")
    result: dict[str, object] = {
        "target_id": "legacy-generic-nmap-target",
        "family": str(target.get("family") or "unknown"),
        "host": host,
        "port": port_value,
        "transport": "direct",
        "protocol": protocol,
        "method": method,
        "sample_sha256s": [sample_sha256] if sample_sha256 else [],
        "associated_case_count": 1 if sample_sha256 else 0,
        "sources": ["legacy reviewed target without an exact protocol profile"],
        "roles": ["c2_candidate"],
        "selection_basis": "汎用Nmap NSEによる到達性観測のみ",
        "timeout_seconds": timeout,
        "maximum_request_bytes": 0 if method != "http_get" else 4096,
        "maximum_response_bytes": 4096,
    }
    if method == "http_get":
        result["http_host"] = target.get("http_host") or host
        result["http_path"] = target.get("http_path") or "/"
    return result


def _write_cli_result(result: Mapping[str, object], output: Path | None) -> None:
    rendered = json.dumps(dict(result), ensure_ascii=False, indent=2) + "\n"
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")


def main() -> int:
    """旧CLI互換targetをNmap NSEだけで観測する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--protocol", default="tcp")
    parser.add_argument("--family")
    parser.add_argument("--sample-sha256")
    parser.add_argument("--http-host")
    parser.add_argument("--http-path", default="/")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--nmap")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--allow-reviewed-application-probes", action="store_true")
    parser.add_argument("--allow-purerat-legacy-tls", action="store_true")
    parser.add_argument("--allow-authentication", action="store_true")
    parser.add_argument("--allow-malware-registration-tasking", action="store_true")
    parser.add_argument("--allow-reviewed-checkconnect", action="store_true")
    parser.add_argument("--acknowledge-redline-profile", action="append", default=[])
    parser.add_argument("--allow-xloader-registration", action="store_true")
    parser.add_argument("--private-credential-vault", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    legacy = {
        "host": args.host,
        "port": args.port,
        "protocol": args.protocol,
        "family": args.family,
        "http_host": args.http_host,
        "http_path": args.http_path,
        "timeout_seconds": args.timeout,
    }
    try:
        target = normalize_legacy_target(legacy, sample_sha256=args.sample_sha256)
        result = probe_target_with_nmap(
            target,
            allow_network=args.allow_network,
            allow_application_probes=args.allow_reviewed_application_probes,
            allow_purerat_legacy_tls=args.allow_purerat_legacy_tls,
            allow_authentication=args.allow_authentication,
            allow_malware_registration=args.allow_malware_registration_tasking,
            allow_reviewed_checkconnect=args.allow_reviewed_checkconnect,
            acknowledged_redline_profiles=frozenset(args.acknowledge_redline_profile),
            allow_xloader_registration=args.allow_xloader_registration,
            private_credential_vault=args.private_credential_vault,
            nmap_executable=args.nmap,
        )
    except NmapC2Error as exc:
        result = _disabled("nmap_target_validation_failed")
        result["error_type"] = type(exc).__name__
    _write_cli_result(result, args.output)
    return 0 if result.get("alive") else 1


def nmap_method_coverage() -> dict[str, object]:
    """monitor methodとNSE fileの完全対応を公開する。"""

    return {
        "schema_version": 1,
        "execution_backend": "nmap_nse_only",
        "method_count": len(METHOD_BINDINGS),
        "methods": {
            method: {
                "script": binding.script,
                "mode_key": binding.mode_key,
                "mode_value": binding.mode_value,
                "confirmation_allowed": binding.confirmation_allowed,
            }
            for method, binding in sorted(METHOD_BINDINGS.items())
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
