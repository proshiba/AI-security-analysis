#!/usr/bin/env python3
"""防御的RATホストエミュレーターの完全一致profileを検証する。"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from c2_protocol_probe_profiles import (
    ProtocolProfileError,
    canonical_lf_json_sha256,
    canonical_profile_object_sha256,
    profile_registry_metadata,
)
from c2_protocol_probe_profiles import (
    load_profiles as load_protocol_profiles,
)
from immutable_snapshot import decode_strict_json, read_bounded_snapshot

DEFAULT_REGISTRY_PATH = Path(__file__).with_name("rat_emulator_profiles.json")
REGISTRY_SOURCE = "analysis-framework/common/rat_emulator_profiles.json"
MAXIMUM_REGISTRY_BYTES = 256 * 1024
MAXIMUM_EVIDENCE_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
ALLOWED_ADAPTERS = frozenset(
    {
        "purerat_direct_tls_v1",
        "tls_messagepack_rat_host",
        "valleyrat_n520_v1",
        "valleyrat_winos_v1",
    }
)
ALLOWED_LIVE_SCOPES = frozenset(
    {"leased_external", "offline_or_loopback_only"}
)
OFFLINE_ONLY_ADAPTERS = frozenset(
    {"purerat_direct_tls_v1", "valleyrat_winos_v1"}
)

PROFILE_KEYS = {
    "profile_id",
    "protocol_profile_id",
    "protocol_profile_object_sha256",
    "family",
    "adapter_id",
    "host",
    "port",
    "pinned_ips",
    "transport",
    "tls_version",
    "sni",
    "expected_certificate_sha256",
    "certificate_mismatch_is_negative_evidence",
    "sample_sha256s",
    "evidence_source",
    "evidence_sha256",
    "registration_mode",
    "station_id_sent",
    "unknown_task_action",
    "file_transfer_action",
    "fake_result_scope",
    "allow_live_fake_results",
    "live_scope",
    "limits",
}
LIMIT_KEYS = {
    "duration_seconds",
    "maximum_connections",
    "maximum_outbound_frames",
    "maximum_outbound_bytes",
    "maximum_inbound_frames",
    "maximum_inbound_read_calls",
    "maximum_inbound_bytes",
    "maximum_frame_bytes",
    "maximum_commands",
    "minimum_send_interval_seconds",
}


class RatEmulatorProfileError(ValueError):
    """profile registry、証拠、endpointのいずれかが安全境界外である。"""


@dataclass(frozen=True)
class RegistrySnapshot:
    """検証済みregistryと、その不変byte列の識別情報。"""

    source: str
    sha256: str
    protocol_profile_registry: dict[str, str]
    profiles: dict[str, dict[str, Any]]


def repository_root() -> Path:
    """既定repository rootを返す。"""

    return Path(__file__).resolve().parents[2]


def _canonical_global_ip(value: object) -> str:
    if type(value) is not str:
        raise RatEmulatorProfileError("pinned IPは文字列である必要があります")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise RatEmulatorProfileError("pinned IPが不正です") from exc
    if not address.is_global or address.compressed != value:
        raise RatEmulatorProfileError("pinned IPはcanonical global IPである必要があります")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise RatEmulatorProfileError(
            f"{label}のkeyが不正です: missing={missing}, extra={extra}"
        )


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _evidence_snapshot(root: Path, source: object, expected_sha256: object) -> bytes:
    if type(source) is not str or not source or "\\" in source or ":" in source:
        raise RatEmulatorProfileError("evidence_sourceはrepository相対pathで指定してください")
    if type(expected_sha256) is not str or SHA256_RE.fullmatch(expected_sha256) is None:
        raise RatEmulatorProfileError("evidence_sha256が不正です")
    relative = Path(source)
    if relative.is_absolute() or ".." in relative.parts:
        raise RatEmulatorProfileError("evidence_sourceがrepository外を指しています")
    absolute_root = Path(os.path.abspath(root))
    absolute = Path(os.path.abspath(absolute_root / relative))
    if not _within(absolute_root, absolute):
        raise RatEmulatorProfileError("evidence_sourceがrepository外を指しています")
    try:
        snapshot = read_bounded_snapshot(absolute, MAXIMUM_EVIDENCE_BYTES)
    except (OSError, ValueError) as exc:
        raise RatEmulatorProfileError(f"evidenceを安全に読み取れません: {exc}") from exc
    try:
        evidence_sha256 = canonical_lf_json_sha256(
            snapshot.data,
            label=f"RAT emulator evidence: {source}",
        )
    except ValueError as exc:
        raise RatEmulatorProfileError(
            f"evidenceはstrict UTF-8 JSON textである必要があります: {exc}"
        ) from exc
    if evidence_sha256 != expected_sha256:
        raise RatEmulatorProfileError("evidence SHA-256 pinが一致しません")
    return snapshot.data


def _validate_limits(value: object) -> dict[str, int | float]:
    if not isinstance(value, dict):
        raise RatEmulatorProfileError("limitsはobjectである必要があります")
    _exact_keys(value, LIMIT_KEYS, "limits")
    integer_bounds = {
        "maximum_connections": (1, 1),
        "maximum_outbound_frames": (1, 16),
        "maximum_outbound_bytes": (1, 64 * 1024),
        "maximum_inbound_frames": (1, 64),
        "maximum_inbound_read_calls": (2, 4096),
        "maximum_inbound_bytes": (1, 1024 * 1024),
        "maximum_frame_bytes": (1, 64 * 1024),
        "maximum_commands": (1, 16),
    }
    normalized: dict[str, int | float] = {}
    for name, (minimum, maximum) in integer_bounds.items():
        item = value.get(name)
        if type(item) is not int or not minimum <= item <= maximum:
            raise RatEmulatorProfileError(f"{name}が安全上限外です")
        normalized[name] = item
    duration = value.get("duration_seconds")
    interval = value.get("minimum_send_interval_seconds")
    if type(duration) is not float or not 1.0 <= duration <= 300.0:
        raise RatEmulatorProfileError("duration_secondsは1.0～300.0秒に限定します")
    if type(interval) is not float or not 0.0 <= interval <= 60.0:
        raise RatEmulatorProfileError("minimum_send_interval_secondsは1.0秒以上に限定します")
    if normalized["maximum_frame_bytes"] > normalized["maximum_inbound_bytes"]:
        raise RatEmulatorProfileError("1 frame上限がinbound合計上限を超えています")
    normalized["duration_seconds"] = duration
    normalized["minimum_send_interval_seconds"] = interval
    return normalized


def _validate_n520_evidence(profile: Mapping[str, Any], raw: bytes) -> None:
    try:
        document = decode_strict_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulatorProfileError(f"N520 evidence JSONが不正です: {exc}") from exc
    if not isinstance(document, dict):
        raise RatEmulatorProfileError("N520 evidenceはobjectである必要があります")
    c2 = document.get("c2")
    collection = document.get("collection")
    if not isinstance(c2, dict) or not isinstance(collection, dict):
        raise RatEmulatorProfileError("N520 evidenceのc2／collectionがありません")
    if (
        document.get("sample_sha256") not in profile["sample_sha256s"]
        or c2.get("host") != profile["host"]
        or c2.get("port") != profile["port"]
        or c2.get("confirmed") is not True
        or c2.get("certificate_sha256") != profile["expected_certificate_sha256"]
        or collection.get("checkin_command") != 1
        or collection.get("checkin_payload_size") != 0
        or collection.get("station_id_sent") is not False
    ):
        raise RatEmulatorProfileError("N520 evidenceとemulator profileが一致しません")


def _validate_tls_messagepack_evidence(
    profile: Mapping[str, Any],
    protocol_profile: Mapping[str, Any],
    raw: bytes,
) -> None:
    try:
        document = decode_strict_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulatorProfileError(f"TLS MessagePack evidence JSON is invalid: {exc}") from exc
    if not isinstance(document, dict):
        raise RatEmulatorProfileError("TLS MessagePack evidence must be an object")
    registration = document.get("registration")
    dispatcher = document.get("dispatcher")
    readiness = document.get("emulator_readiness")
    safety = document.get("safety")
    if not all(
        isinstance(value, dict) for value in (registration, dispatcher, readiness, safety)
    ):
        raise RatEmulatorProfileError("TLS MessagePack evidence sections are missing")
    heartbeat = list(protocol_profile.get("expected_response_packets") or [])
    expected_transfer = {
        "asyncrat": ["winUpdate", "plugin", "savePlugin"],
        "venomrat": ["plu_gin", "save_Plugin", "loadofflinelog"],
    }.get(str(profile["family"]))
    expected_keepalive = {
        "asyncrat": {
            "token": "0x06000024",
            "semantic": "88475d38f43dae09d0afa8eeb3fa2fb713fbccf38417ff9dcb568add90893fe0",
        },
        "venomrat": {
            "token": "0x06000056",
            "semantic": "8f598b167f1729f89266b9cb53bc218c0a24df4c2d037cf6179eeab985fdc2de",
        },
    }.get(str(profile["family"]))
    heartbeat_request = dispatcher.get("heartbeat_request")
    if (
        expected_transfer is None
        or expected_keepalive is None
        or not isinstance(heartbeat_request, dict)
    ):
        raise RatEmulatorProfileError("TLS MessagePack evidence family is unsupported")
    if (
        document.get("schema_version") != 1
        or document.get("family") != profile["family"]
        or document.get("sample_sha256") not in profile["sample_sha256s"]
        or document.get("analysis_status") != "complete"
        or registration.get("packet_key") != protocol_profile.get("packet_key")
        or registration.get("packet_value") != "ClientInfo"
        or registration.get("missing_required_fields") != []
        or registration.get("synthetic_values_required") is not True
        or registration.get("real_host_metadata_allowed") is not False
        or set(heartbeat_request)
        != {
            "method",
            "method_token",
            "cil_semantic_sha256",
            "packet_key",
            "packet_value",
            "message_key",
            "message_source",
            "emulator_message_value",
            "sanitized_for_privacy",
            "schema_confirmed",
        }
        or heartbeat_request.get("method")
        != "Client.Connection.ClientSocket.KeepAlivePacket"
        or heartbeat_request.get("method_token") != expected_keepalive["token"]
        or heartbeat_request.get("cil_semantic_sha256")
        != expected_keepalive["semantic"]
        or heartbeat_request.get("packet_key") != protocol_profile.get("packet_key")
        or heartbeat_request.get("packet_value") != protocol_profile.get("request_packet")
        or heartbeat_request.get("message_key") != protocol_profile.get("message_key")
        or heartbeat_request.get("message_source") != "active_window_title"
        or heartbeat_request.get("emulator_message_value") != ""
        or heartbeat_request.get("sanitized_for_privacy") is not True
        or heartbeat_request.get("schema_confirmed") is not True
        or dispatcher.get("heartbeat_response_markers") != heartbeat
        or dispatcher.get("file_or_plugin_transfer_markers") != expected_transfer
        or dispatcher.get("missing_command_markers") != []
        or readiness.get("registration_schema_confirmed") is not True
        or readiness.get("command_dispatcher_confirmed") is not True
        or readiness.get("heartbeat_request_response_confirmed") is not True
        or readiness.get("operation_result_serializer_confirmed") is not False
        or readiness.get("live_operation_fake_result_allowed") is not False
        or readiness.get("unknown_command_reply_allowed") is not False
        or any(
            safety.get(key) is not False
            for key in (
                "sample_executed",
                "network_contacted",
                "raw_cil_published",
                "unreviewed_literals_published",
            )
        )
    ):
        raise RatEmulatorProfileError(
            "TLS MessagePack evidence and emulator profile do not match"
        )


def _validate_winos_evidence(
    profile: Mapping[str, Any],
    protocol_profile: Mapping[str, Any],
    raw: bytes,
) -> None:
    """control-only C9 heartbeatの公開証拠を完全一致で検証する。"""

    try:
        document = decode_strict_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulatorProfileError(f"Winos evidence JSONが不正です: {exc}") from exc
    if not isinstance(document, dict):
        raise RatEmulatorProfileError("Winos evidenceはobjectである必要があります")
    stage = document.get("stage_flow")
    control = document.get("control_flow")
    live = document.get("live")
    safety = document.get("safety")
    if not all(isinstance(value, dict) for value in (stage, control, live, safety)):
        raise RatEmulatorProfileError("Winos evidenceの必須sectionがありません")
    endpoint = f"{profile['host']}:{profile['port']}"
    if (
        document.get("schema_version") != 1
        or document.get("protocol") != "winos_custom_tcp"
        or protocol_profile.get("protocol") != "winos"
        or protocol_profile.get("method") != "winos_heartbeat"
        or protocol_profile.get("handler") != "valleyrat_winos_reviewed"
        or protocol_profile.get("channel_role") != "control"
        or protocol_profile.get("pinned_ips") != profile["pinned_ips"]
        or protocol_profile.get("maximum_response_bytes") != 64
        or control.get("endpoint") != endpoint
        or 0xC9 not in list(control.get("observed_commands") or [])
        or stage.get("endpoint") != f"{profile['host']}:8856"
        or stage.get("endpoint") == endpoint
        or live.get("dns") != profile["pinned_ips"][0]
        or live.get("control_8868") != "valid_0xc9_heartbeat_response"
        or live.get("stage_8856") != "tcp_connected_no_bytes_sent"
        or any(
            safety.get(key) is not False
            for key in (
                "stage_requested",
                "victim_metadata_sent",
                "operation_command_sent",
            )
        )
    ):
        raise RatEmulatorProfileError("Winos evidenceとemulator profileが一致しません")


def _validate_purerat_evidence(
    profile: Mapping[str, Any],
    protocol_profile: Mapping[str, Any],
    raw: bytes,
) -> None:
    """PureRAT 4.4.1 registration schemaとwire pinを完全一致で検証する。"""

    try:
        document = decode_strict_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulatorProfileError(
            f"PureRAT evidence JSONが不正です: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise RatEmulatorProfileError("PureRAT evidenceはobjectである必要があります")
    source = document.get("source")
    schema = document.get("registration_schema")
    synthetic = document.get("synthetic_registration")
    safety = document.get("safety")
    call_chain = document.get("wire_call_chain")
    if (
        not all(
            isinstance(value, dict)
            for value in (source, schema, synthetic, safety)
        )
        or not isinstance(call_chain, list)
    ):
        raise RatEmulatorProfileError("PureRAT evidenceの必須sectionがありません")
    members = schema.get("proto_members")
    if not isinstance(members, list):
        raise RatEmulatorProfileError("PureRAT GClass4 member inventoryがありません")
    member_tags = [item.get("tag") for item in members if isinstance(item, dict)]
    semantic = {
        item.get("token"): item.get("semantic_sha256")
        for item in call_chain
        if isinstance(item, dict)
    }
    if (
        document.get("schema_version") != 1
        or document.get("status") != "confirmed"
        or document.get("family") != "purehvnc"
        or document.get("variant") != "purerat_4_4_1_direct_tls"
        or source.get("root_sample_sha256")
        != protocol_profile.get("root_sample_sha256")
        or source.get("terminal_sample_sha256")
        != protocol_profile.get("terminal_sample_sha256")
        or profile.get("sample_sha256s")
        != [source.get("root_sample_sha256"), source.get("terminal_sample_sha256")]
        or schema.get("base_contract") != "GClass2"
        or schema.get("registration_contract") != "GClass4"
        or schema.get("registration_protoinclude_tag") != 1
        or schema.get("base_proto_contract_confirmed") is not True
        or schema.get("registration_proto_contract_confirmed") is not True
        or schema.get("inventory_canonical_sha256")
        != "6f3989a771f7571bf06bafe4e2604280864431907e5af1d8a16ec3f4cb7be53f"
        or member_tags != list(range(1, 21))
        or semantic
        != {
            "0x06000080": "7e4389ecd11c8a416cf092a741162f897ed2a03375fa5b82cf47b3e5f89eb92f",
            "0x06000086": "bc7d416daddff80ba800ddfd7df609208bf74bb0ccd359b4da301eea950814d4",
            "0x06000090": "69e69fa120d5e6f2c0d20bcd5268f1346d0ce818c83c012d5a9e300359181e5d",
            "0x060000b3": "0248e2025ac399ebb40d7205a414a9394c4fd9d998c5ceb6b2a1abf38e4cc743",
        }
        or synthetic.get("scope") != "offline_or_loopback_only"
        or synthetic.get("real_identity_fields_populated") != 0
        or synthetic.get("protobuf_hex") != "0a00"
        or synthetic.get("protobuf_size") != 2
        or synthetic.get("protobuf_sha256")
        != "102b51b9765a56a3e899f7cf0ee38e5251f9c503b357b330a49183eb7b155604"
        or synthetic.get("deterministic_frame_size") != 26
        or synthetic.get("deterministic_frame_sha256")
        != "fae7f27b56eed121c893860cd4764d64541fe1a0b67bc22da050e70161f44001"
        or safety.get("loopback_registration_supported") is not True
        or any(
            safety.get(key) is not False
            for key in (
                "sample_executed",
                "network_used_for_schema_recovery",
                "external_c2_contacted",
                "raw_il_published",
                "pfx_published",
                "private_key_published",
                "client_certificate_used",
                "live_registration_allowed",
            )
        )
    ):
        raise RatEmulatorProfileError("PureRAT evidenceとemulator profileが一致しません")


def _validate_profile(
    raw: object,
    *,
    protocol_profiles: Mapping[str, dict[str, Any]],
    root: Path,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise RatEmulatorProfileError("profileはobjectである必要があります")
    _exact_keys(raw, PROFILE_KEYS, "profile")
    profile = deepcopy(raw)
    profile_id = profile.get("profile_id")
    if type(profile_id) is not str or PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise RatEmulatorProfileError("profile_idが不正です")
    protocol_profile_id = profile.get("protocol_profile_id")
    if type(protocol_profile_id) is not str or protocol_profile_id not in protocol_profiles:
        raise RatEmulatorProfileError("未レビューのprotocol_profile_idです")
    protocol_profile = protocol_profiles[protocol_profile_id]
    expected_object_sha256 = profile.get("protocol_profile_object_sha256")
    if (
        type(expected_object_sha256) is not str
        or canonical_profile_object_sha256(protocol_profile) != expected_object_sha256
    ):
        raise RatEmulatorProfileError("protocol profile object SHA-256 pinが一致しません")
    if (
        profile.get("family") != protocol_profile.get("family")
        or profile.get("host") != protocol_profile.get("host")
        or profile.get("port") != protocol_profile.get("port")
        or profile.get("sample_sha256s") != protocol_profile.get("sample_sha256s")
    ):
        raise RatEmulatorProfileError("protocol profileとのendpoint／sample bindingが一致しません")

    pinned = profile.get("pinned_ips")
    if not isinstance(pinned, list) or len(pinned) != 1:
        raise RatEmulatorProfileError("emulator profileには単一pinned IPが必要です")
    pinned_ip = _canonical_global_ip(pinned[0])
    try:
        endpoint_ip = ipaddress.ip_address(str(profile["host"]))
    except ValueError:
        endpoint_ip = None
    if endpoint_ip is not None and endpoint_ip != ipaddress.ip_address(pinned_ip):
        raise RatEmulatorProfileError("IP endpointはpinned IPと完全一致する必要があります")

    adapter_id = profile.get("adapter_id")
    if adapter_id not in ALLOWED_ADAPTERS:
        raise RatEmulatorProfileError("未レビューのadapter_idです")
    live_scope = profile.get("live_scope")
    if type(live_scope) is not str or live_scope not in ALLOWED_LIVE_SCOPES:
        raise RatEmulatorProfileError("live_scopeが欠落または未レビューです")
    expected_live_scope = (
        "offline_or_loopback_only"
        if adapter_id in OFFLINE_ONLY_ADAPTERS
        else "leased_external"
    )
    if live_scope != expected_live_scope:
        raise RatEmulatorProfileError("adapterとlive_scopeの安全境界が一致しません")

    certificate = profile.get("expected_certificate_sha256")
    if adapter_id == "valleyrat_winos_v1":
        transport_valid = (
            profile.get("transport") == "raw_tcp"
            and profile.get("tls_version") is None
            and profile.get("sni") is None
            and certificate is None
            and profile.get("certificate_mismatch_is_negative_evidence") is False
        )
    elif adapter_id == "purerat_direct_tls_v1":
        transport_valid = (
            profile.get("transport") == "tls"
            and profile.get("tls_version") == "TLSv1.0"
            and profile.get("sni") is None
            and type(certificate) is str
            and SHA256_RE.fullmatch(certificate) is not None
            and certificate == protocol_profile.get("expected_certificate_sha256")
            and profile.get("certificate_mismatch_is_negative_evidence") is False
        )
    else:
        transport_valid = (
            profile.get("transport") == "tls"
            and profile.get("tls_version") == "TLSv1.2"
            and profile.get("sni") == protocol_profile.get("sni")
            and type(certificate) is str
            and SHA256_RE.fullmatch(certificate) is not None
            and type(profile.get("certificate_mismatch_is_negative_evidence")) is bool
        )

    registration_modes = {
        "purerat_direct_tls_v1": "fixed_empty_gclass4",
        "valleyrat_n520_v1": "empty_command_1",
        "valleyrat_winos_v1": "fixed_c9_heartbeat",
        "tls_messagepack_rat_host": "synthetic_client_info",
    }
    fake_result_scopes = {
        "purerat_direct_tls_v1": "loopback_or_offline_only",
        "valleyrat_n520_v1": "loopback_or_offline_only",
        "valleyrat_winos_v1": "loopback_or_offline_only",
        "tls_messagepack_rat_host": "reviewed_heartbeat_request_only",
    }
    if (
        not transport_valid
        or profile.get("registration_mode") != registration_modes[adapter_id]
        or profile.get("station_id_sent") is not False
        or profile.get("unknown_task_action") != "no_response"
        or profile.get("file_transfer_action") != "reject_and_close"
        or profile.get("fake_result_scope") != fake_result_scopes[adapter_id]
        or profile.get("allow_live_fake_results") is not False
    ):
        raise RatEmulatorProfileError("emulator profileの安全policyが固定値と一致しません")

    limits = _validate_limits(profile.get("limits"))
    if limits["maximum_connections"] != 1 or (
        adapter_id in {
            "purerat_direct_tls_v1",
            "valleyrat_n520_v1",
            "valleyrat_winos_v1",
        }
        and limits["maximum_outbound_frames"] != 1
    ):
        raise RatEmulatorProfileError("初期profileは1接続・固定送信1 frameだけを許可します")

    evidence = _evidence_snapshot(
        root,
        profile["evidence_source"],
        profile["evidence_sha256"],
    )
    if adapter_id == "valleyrat_n520_v1":
        if protocol_profile.get("method") != "n520_server_first":
            raise RatEmulatorProfileError("N520 adapterとprotocol methodが一致しません")
        _validate_n520_evidence(profile, evidence)
    elif adapter_id == "tls_messagepack_rat_host":
        if (
            profile["profile_id"] != profile["protocol_profile_id"]
            or protocol_profile.get("method")
            not in {"asyncrat_tls_messagepack", "venomrat_tls_messagepack"}
            or protocol_profile.get("handler") != protocol_profile.get("method")
            or protocol_profile.get("expected_certificate_sha256")
            != profile["expected_certificate_sha256"]
            or profile["certificate_mismatch_is_negative_evidence"] is not False
        ):
            raise RatEmulatorProfileError("TLS MessagePack profile binding is invalid")
        if (
            not 1.0 <= float(limits["duration_seconds"]) <= 30.0
            or limits["maximum_outbound_frames"] != 2
            or limits["maximum_outbound_bytes"] > 64 * 1024
            or limits["maximum_inbound_frames"] != 1
            or limits["maximum_inbound_bytes"] > 64 * 1024
            or limits["maximum_frame_bytes"] > 64 * 1024
            or limits["maximum_commands"] != 1
            or limits["minimum_send_interval_seconds"] != 0.0
        ):
            raise RatEmulatorProfileError("TLS MessagePack limits exceed the reviewed session")
        _validate_tls_messagepack_evidence(profile, protocol_profile, evidence)
    elif adapter_id == "purerat_direct_tls_v1":
        if (
            profile["profile_id"]
            != "purerat-441-d025a296-direct-tls10-empty-gclass4"
            or profile["protocol_profile_id"]
            != "purerat-441-d025a296-45-192-211-77-56001-direct-tls10"
            or protocol_profile.get("method")
            != "purerat_direct_tls_certificate_pin"
            or protocol_profile.get("handler") != "purerat_direct_tls"
            or protocol_profile.get("tls_version") != "TLSv1.0"
            or protocol_profile.get("sni") is not None
            or protocol_profile.get("maximum_request_bytes") != 0
            or protocol_profile.get("maximum_response_bytes") != 0
        ):
            raise RatEmulatorProfileError("PureRAT direct-TLS profile bindingが不正です")
        if (
            float(limits["duration_seconds"]) != 3.0
            or limits["maximum_outbound_frames"] != 1
            or limits["maximum_outbound_bytes"] != 26
            or limits["maximum_inbound_frames"] != 1
            or limits["maximum_inbound_read_calls"] != 64
            or limits["maximum_inbound_bytes"] != 65_536
            or limits["maximum_frame_bytes"] != 65_536
            or limits["maximum_commands"] != 1
            or limits["minimum_send_interval_seconds"] != 0.0
        ):
            raise RatEmulatorProfileError(
                "PureRAT limitsがreview済みloopback sessionと一致しません"
            )
        _validate_purerat_evidence(profile, protocol_profile, evidence)
    elif adapter_id == "valleyrat_winos_v1":
        if (
            profile["profile_id"] != profile["protocol_profile_id"]
            or protocol_profile.get("method") != "winos_heartbeat"
            or protocol_profile.get("handler") != "valleyrat_winos_reviewed"
            or protocol_profile.get("channel_role") != "control"
        ):
            raise RatEmulatorProfileError("Winos control-only profile bindingが不正です")
        if (
            float(limits["duration_seconds"]) != 3.0
            or limits["maximum_outbound_frames"] != 1
            or limits["maximum_outbound_bytes"] != 15
            or limits["maximum_inbound_frames"] != 1
            or limits["maximum_inbound_read_calls"] != 16
            or limits["maximum_inbound_bytes"] != 64
            or limits["maximum_frame_bytes"] != 64
            or limits["maximum_commands"] != 1
            or limits["minimum_send_interval_seconds"] != 0.0
        ):
            raise RatEmulatorProfileError("Winos limitsがreview済みsessionと一致しません")
        _validate_winos_evidence(profile, protocol_profile, evidence)
    else:
        raise RatEmulatorProfileError("adapter validatorがありません")

    profile["limits"] = limits
    return profile

def _read_registry(path: Path) -> tuple[dict[str, Any], str]:
    try:
        snapshot = read_bounded_snapshot(path, MAXIMUM_REGISTRY_BYTES)
        document = decode_strict_json(snapshot.data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulatorProfileError(f"RAT emulator registryを安全に読み取れません: {exc}") from exc
    if not isinstance(document, dict):
        raise RatEmulatorProfileError("RAT emulator registryはobjectである必要があります")
    return document, canonical_lf_json_sha256(
        snapshot.data,
        label="RAT emulator registry",
    )


def load_registry(
    path: Path = DEFAULT_REGISTRY_PATH,
    *,
    expected_sha256: str | None = None,
    root: Path | None = None,
) -> RegistrySnapshot:
    """registry、元protocol profile、証拠を再検証して返す。"""

    document, digest = _read_registry(path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise RatEmulatorProfileError("RAT emulator registry SHA-256 pin mismatch")
    _exact_keys(document, {"schema_version", "protocol_profile_registry", "profiles"}, "registry")
    if document.get("schema_version") != 1:
        raise RatEmulatorProfileError("registryにはschema_version=1が必要です")
    protocol_pin = document.get("protocol_profile_registry")
    if not isinstance(protocol_pin, dict):
        raise RatEmulatorProfileError("protocol_profile_registry pinがありません")
    _exact_keys(protocol_pin, {"source", "sha256"}, "protocol_profile_registry")
    try:
        current_protocol_registry = profile_registry_metadata()
    except ProtocolProfileError as exc:
        raise RatEmulatorProfileError(str(exc)) from exc
    if protocol_pin != current_protocol_registry:
        raise RatEmulatorProfileError("protocol profile registry source/SHA-256 pinが一致しません")
    try:
        protocol_profiles = load_protocol_profiles(expected_sha256=protocol_pin["sha256"])
    except ProtocolProfileError as exc:
        raise RatEmulatorProfileError(str(exc)) from exc
    values = document.get("profiles")
    if not isinstance(values, list) or not values:
        raise RatEmulatorProfileError("profilesは1件以上必要です")
    effective_root = Path(os.path.abspath(root or repository_root()))
    profiles: dict[str, dict[str, Any]] = {}
    endpoints: set[tuple[str, int]] = set()
    for value in values:
        profile = _validate_profile(value, protocol_profiles=protocol_profiles, root=effective_root)
        profile_id = profile["profile_id"]
        endpoint = (profile["host"], profile["port"])
        if profile_id in profiles or endpoint in endpoints:
            raise RatEmulatorProfileError("profile IDまたはendpointが重複しています")
        profiles[profile_id] = profile
        endpoints.add(endpoint)
    return RegistrySnapshot(
        source=REGISTRY_SOURCE if path.resolve() == DEFAULT_REGISTRY_PATH.resolve() else str(path),
        sha256=digest,
        protocol_profile_registry=dict(protocol_pin),
        profiles=profiles,
    )


def load_profiles(
    path: Path = DEFAULT_REGISTRY_PATH,
    *,
    expected_sha256: str | None = None,
    root: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """検証済みprofileをIDで引けるdictとして返す。"""

    return load_registry(path, expected_sha256=expected_sha256, root=root).profiles


def registry_metadata(path: Path = DEFAULT_REGISTRY_PATH) -> dict[str, str]:
    """registryの公開可能なsourceと改行正規化SHA-256を返す。"""

    snapshot = read_bounded_snapshot(path, MAXIMUM_REGISTRY_BYTES)
    return {
        "source": REGISTRY_SOURCE if path.resolve() == DEFAULT_REGISTRY_PATH.resolve() else str(path),
        "sha256": canonical_lf_json_sha256(
            snapshot.data,
            label="RAT emulator registry",
        ),
    }


def resolve_profile(
    profile_id: str,
    *,
    path: Path = DEFAULT_REGISTRY_PATH,
    expected_registry_sha256: str | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    """完全一致IDのprofileだけを返す。host／portのCLI上書きは受け付けない。"""

    registry = load_registry(path, expected_sha256=expected_registry_sha256, root=root)
    try:
        return deepcopy(registry.profiles[profile_id])
    except KeyError as exc:
        raise RatEmulatorProfileError(f"未レビューのemulator profile IDです: {profile_id}") from exc


__all__ = [
    "ALLOWED_ADAPTERS",
    "DEFAULT_REGISTRY_PATH",
    "RatEmulatorProfileError",
    "RegistrySnapshot",
    "load_profiles",
    "load_registry",
    "registry_metadata",
    "resolve_profile",
]
