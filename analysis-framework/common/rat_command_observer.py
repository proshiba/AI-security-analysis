#!/usr/bin/env python3
"""6 familyの復号済みC2 messageを実行せずに正規化・分類する。"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from tls_messagepack_rat_host_emulator import (
    VENOM_CURRENT_PROFILE_ID,
    VENOM_PROFILE_ID,
    SessionLimits,
    TlsMessagePackHostError,
    classify_frame,
    decode_frame,
)

SCHEMA_VERSION = 1
MAXIMUM_MESSAGE_BYTES = 1024 * 1024
MAXIMUM_TEXT_BYTES = 8192
MAXIMUM_REMCOS_STREAM_BYTES = 64 * 1024 * 1024
MAXIMUM_REMCOS_STREAM_FRAMES = 4096
MAXIMUM_COLLECTION_ITEMS = 256
MAXIMUM_NESTING_DEPTH = 6
REMCOS_MAGIC = bytes.fromhex("24 04 ff 00")
REMCOS_DELIMITER = bytes.fromhex("7c 1e 1e 1f 7c")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CAPTURED_AT_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_COMMAND_OBSERVATION_TOKEN = object()
_PUBLIC_DETAIL_KEYS = frozenset(
    {
        "binary_payload_count",
        "binary_payload_size",
        "candidate_present",
        "candidate_sha256",
        "configuration_field_types_valid",
        "configuration_fields",
        "corroborating_service_count",
        "decoded_size",
        "declared_size",
        "dynamic_hex_field_count",
        "exact_sample_binding",
        "exact_sample_wire_match",
        "field_count",
        "interactive_command",
        "loader_entry_count",
        "loader_entry_schema_confirmed",
        "loader_url_scheme_counts",
        "message_type_id_recovered",
        "observer_action",
        "packet_kind",
        "payload_fetched",
        "payload_followed",
        "payload_sha256",
        "payload_size",
        "published_taxonomy_applied",
        "serializer_reimplemented",
        "task_data_protocol_type",
        "task_name_protocol_type",
        "task_schema_confirmed",
        "taxonomy_evidence_artifact_pinned",
        "taxonomy_source",
        "transport_decryption_performed",
    }
)


class RatCommandObserverError(ValueError):
    """入力、profile、または復号済みmessageが安全境界を満たさない。"""


def _freeze_public_detail(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_public_detail(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_public_detail(item) for item in value)
    return value


@dataclass(frozen=True)
class ObserverProfile:
    """1つの解析済みprotocol／taxonomy境界。"""

    profile_id: str
    family: str
    source_encoding: str
    evidence_scope: str
    protocol_status: str
    allowed_directions: frozenset[str]
    sample_sha256s: frozenset[str] = field(default_factory=frozenset)
    exact_wire_profile_id: str | None = None


@dataclass(frozen=True)
class CommandObservation:
    """公開可能な分類と、repository外だけへ保存する非公開内容。"""

    profile: ObserverProfile
    direction: str
    event_kind: str
    category: str
    normalized_command: str
    protocol_identifier: str | None
    identifier_confidence: str
    message_size: int
    message_sha256: str
    public_details: Mapping[str, Any] = field(default_factory=dict)
    private_fields: Mapping[str, Any] = field(default_factory=dict)
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _COMMAND_OBSERVATION_TOKEN:
            raise RatCommandObserverError("CommandObservationはinternal factoryからのみ生成できます")
        if not isinstance(self.public_details, Mapping):
            raise RatCommandObserverError("public detailsはobjectである必要があります")
        object.__setattr__(
            self,
            "public_details",
            _freeze_public_detail(dict(self.public_details)),
        )

    def public_event(self) -> dict[str, Any]:
        """command本文、URL、path、tokenを含まない公開用eventを返す。"""

        if self._construction_token is not _COMMAND_OBSERVATION_TOKEN:
            raise RatCommandObserverError("CommandObservationの生成provenanceが不正です")
        details = _bounded_projection(self.public_details)
        if not isinstance(details, dict) or set(details).difference(_PUBLIC_DETAIL_KEYS):
            raise RatCommandObserverError("public detailsに未許可keyが含まれます")
        identifier = self.protocol_identifier
        public_identifier = identifier if self.identifier_confidence != "unknown" else None
        identifier_digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest() if identifier is not None else None
        return {
            "schema_version": SCHEMA_VERSION,
            "artifact_type": "defensive_rat_command_observation",
            "profile_id": self.profile.profile_id,
            "family": self.profile.family,
            "source_encoding": self.profile.source_encoding,
            "evidence_scope": self.profile.evidence_scope,
            "protocol_status": self.profile.protocol_status,
            "direction": self.direction,
            "event_kind": self.event_kind,
            "category": self.category,
            "normalized_command": self.normalized_command,
            "protocol_identifier": public_identifier,
            "protocol_identifier_sha256": identifier_digest,
            "identifier_confidence": self.identifier_confidence,
            "message_size": self.message_size,
            "message_sha256": self.message_sha256,
            "safety_decision": "observe_only_no_response",
            "operation_executed": False,
            "payload_download_attempted": False,
            "plugin_retained_by_observer": False,
            "raw_content_published": False,
            **details,
        }


def _new_observation(**values: Any) -> CommandObservation:
    return CommandObservation(
        **values,
        _construction_token=_COMMAND_OBSERVATION_TOKEN,
    )


PROFILES = {
    "vidar-dead-drop-snapshot-v1": ObserverProfile(
        profile_id="vidar-dead-drop-snapshot-v1",
        family="vidar",
        source_encoding="vidar_dead_drop_snapshot_result",
        evidence_scope="exact_sample_offline_resolver_result",
        protocol_status="bootstrap_resolver_only_not_interactive_command_c2",
        allowed_directions=frozenset({"internal"}),
        sample_sha256s=frozenset(
            {
                "0c307efa752ca4d412aee733c3d4c3453942b44a22ec2b0d405156003beddc36",
                "0cad181b2a0c10c287173b15efa7bf92d387987a41a49ad9be3c486e43e3ddc2",
                "0030c014ec4fae311492a87011f565f9ff3b1881137dda152953c6fe718e33e0",
                "3d2cea3eaa43053ae0efa20de8544387d7cabeb70c89980f4241f3b6efa0e323",
            }
        ),
    ),
    "stealc-v2-1backs-decoded-json-v1": ObserverProfile(
        profile_id="stealc-v2-1backs-decoded-json-v1",
        family="stealc",
        source_encoding="stealc_v2_rc4_base64_decoded_json",
        evidence_scope="exact_sample_reviewed_registration_flow",
        protocol_status="create_then_loader_two_request_finite_state_machine",
        allowed_directions=frozenset({"client_to_server", "server_to_client"}),
        sample_sha256s=frozenset({"47854afb3cfeb64a85dda148e00e5ca83168f431a28e5c5fb28733e37f484b13"}),
    ),
    "remus-ba0044e8-decoded-task-v1": ObserverProfile(
        profile_id="remus-ba0044e8-decoded-task-v1",
        family="remusstealer",
        source_encoding="remus_chacha20_decoded_json",
        evidence_scope="exact_sample_reviewed_registration_flow",
        protocol_status="task_envelope_known_name_and_data_semantics_unresolved",
        allowed_directions=frozenset({"server_to_client"}),
        sample_sha256s=frozenset({"2b3a23db5ca7464a5c7f0975790af54097ed127a66ab0b551123831e8f40dfc6"}),
    ),
    "venomrat-603-6a24ba25-messagepack-v1": ObserverProfile(
        profile_id="venomrat-603-6a24ba25-messagepack-v1",
        family="venomrat",
        source_encoding="tls_le32_gzip_messagepack_frame",
        evidence_scope="exact_sample_reviewed_wire_profile",
        protocol_status="one_bounded_inbound_frame_per_live_session",
        allowed_directions=frozenset({"server_to_client"}),
        sample_sha256s=frozenset({"6a24ba25482c73d193fcc208d8ae267236b870b9ab30c44cabe2dc8bfb7a1073"}),
        exact_wire_profile_id=VENOM_PROFILE_ID,
    ),
    "venomrat-603-2b0af18b-messagepack-v1": ObserverProfile(
        profile_id="venomrat-603-2b0af18b-messagepack-v1",
        family="venomrat",
        source_encoding="tls_le32_gzip_messagepack_frame",
        evidence_scope="exact_current_sample_decode_profile_code_lineage_candidate",
        protocol_status="one_bounded_inbound_frame_heartbeat_request_unreviewed",
        allowed_directions=frozenset({"server_to_client"}),
        sample_sha256s=frozenset({"2b0af18bdd10782cf72a985b2f49564aa9058c34645205afb4fcc27724794f6a"}),
        exact_wire_profile_id=VENOM_CURRENT_PROFILE_ID,
    ),
    "remcos-published-340-taxonomy-v1": ObserverProfile(
        profile_id="remcos-published-340-taxonomy-v1",
        family="remcosrat",
        source_encoding="remcos_published_340_plaintext_candidate_frame",
        evidence_scope="published_family_taxonomy_unpinned_no_exact_sample_binding",
        protocol_status="explicit_opt_in_taxonomy_post_transport_decryption_only",
        allowed_directions=frozenset({"server_to_client"}),
    ),
    "remcos-decrypted-plaintext-framing-v1": ObserverProfile(
        profile_id="remcos-decrypted-plaintext-framing-v1",
        family="remcosrat",
        source_encoding="remcos_decrypted_plaintext_frame",
        evidence_scope="family_plaintext_framing_from_saved_pcap_not_version_bound",
        protocol_status="command_identifier_observed_semantics_and_transport_decryption_unresolved",
        allowed_directions=frozenset({"client_to_server", "server_to_client"}),
    ),
    "quasar-upstream-decoded-message-v1": ObserverProfile(
        profile_id="quasar-upstream-decoded-message-v1",
        family="quasarrat",
        source_encoding="quasar_upstream_decoded_message_object",
        evidence_scope="upstream_message_taxonomy_not_exact_sample_wire_profile",
        protocol_status="current_sample_type_ids_keys_and_endpoint_unresolved",
        allowed_directions=frozenset({"client_to_server", "server_to_client"}),
    ),
}


VENOM_TAXONOMY = {
    "Po_ng": ("heartbeat", "heartbeat_response"),
    "plu_gin": ("payload_transfer", "plugin_delivery"),
    "save_Plugin": ("payload_transfer", "plugin_cache_write"),
    "loadofflinelog": ("data_collection", "offline_log_collection"),
    "init_reg": ("registry", "registry_initialization"),
    "HVNCStop": ("remote_desktop", "hidden_desktop_stop"),
    "keylogsetting": ("input_capture", "keylogger_configuration"),
    "runningapp": ("process_discovery", "running_application_query"),
    "filterinfo": ("collection_filter", "collection_filter_configuration"),
}


STEALC_CONFIG_FIELD_TYPES = {
    "self_delete": bool,
    "take_screenshot": bool,
    "loader": bool,
    "steal_steam": bool,
    "steal_outlook": bool,
    "browsers": list,
    "plugins": list,
    "files": list,
}
STEALC_CONFIG_FIELDS = frozenset(STEALC_CONFIG_FIELD_TYPES)
STEALC_STATUS_FIELDS = frozenset(
    {"success", "blocked", "block", "error", "unknown", "error1", "error2", "error3", "error4", "error5"}
)
STEALC_DYNAMIC_HEX_RE = re.compile(r"^[0-9a-f]{10,15}$")
STEALC_TOKEN_RE = re.compile(r"^[0-9a-f]{64,128}$", re.IGNORECASE)
STEALC_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


REMCOS_PUBLISHED_TAXONOMY_SOURCE = "https://www.fortinet.com/blog/threat-research/latest-remcos-rat-phishing"


REMCOS_COMMANDS = {
    0x01: ("heartbeat", "heartbeat"),
    0x03: ("software_discovery", "installed_programs"),
    0x06: ("process_control", "process_manager"),
    0x08: ("window_discovery", "window_manager"),
    0x0D: ("command_execution", "execute_command"),
    0x0E: ("command_execution", "interactive_shell"),
    0x0F: ("browser_action", "open_webpage"),
    0x10: ("screen_capture", "screen_capture_or_screenlogger"),
    0x13: ("input_capture", "keylogger"),
    0x18: ("browser_data", "browser_history_or_logins_cleaner"),
    0x1B: ("camera_capture", "webcam"),
    0x1D: ("audio_capture", "microphone"),
    0x21: ("agent_lifecycle", "close_agent"),
    0x22: ("agent_lifecycle", "uninstall_agent"),
    0x23: ("agent_lifecycle", "restart_agent"),
    0x24: ("agent_lifecycle", "update_agent"),
    0x26: ("user_interaction", "message_box"),
    0x27: ("power_or_privilege", "power_manager_or_elevate"),
    0x28: ("clipboard", "clipboard_manager"),
    0x2C: ("payload_execution", "dll_loader"),
    0x2E: ("script_execution", "remote_scripting"),
    0x2F: ("registry", "registry_editor"),
    0x30: ("user_interaction", "chat"),
    0x32: ("network_proxy", "proxy"),
    0x34: ("service_control", "service_manager"),
    0x4B: ("registration", "client_registration"),
    0x4C: ("heartbeat", "heartbeat_response"),
    0x8F: ("file_discovery", "file_search"),
    0x92: ("desktop_modification", "set_wallpaper"),
    0x98: ("file_control", "file_manager"),
    0xA3: ("audio_output", "audio_player"),
    0xB2: ("payload_execution", "download_and_execute"),
}


QUASAR_TAXONOMY = {
    "ClientIdentification": ("registration", "client_identification"),
    "ClientIdentificationResult": ("registration", "client_identification_result"),
    "DoShellExecute": ("command_execution", "shell_execute"),
    "DoProcessStart": ("process_control", "process_start"),
    "DoProcessEnd": ("process_control", "process_end"),
    "DoVisitWebsite": ("browser_action", "visit_website"),
    "DoShutdownAction": ("power_control", "shutdown_action"),
    "DoCreateRegistryKey": ("registry", "registry_key_create"),
    "DoChangeRegistryValue": ("registry", "registry_value_change"),
    "DoDeleteRegistryKey": ("registry", "registry_key_delete"),
    "DoDeleteRegistryValue": ("registry", "registry_value_delete"),
    "DoRenameRegistryKey": ("registry", "registry_key_rename"),
    "DoRenameRegistryValue": ("registry", "registry_value_rename"),
    "GetRegistryKeys": ("registry", "registry_key_query"),
    "DoKeyboardEvent": ("remote_input", "keyboard_event"),
    "DoMouseEvent": ("remote_input", "mouse_event"),
    "GetDesktop": ("screen_capture", "desktop_capture"),
    "GetDirectory": ("file_discovery", "directory_listing"),
    "GetDrives": ("file_discovery", "drive_listing"),
    "GetKeyloggerLogsDirectory": ("input_capture", "keylogger_log_query"),
    "GetPasswords": ("credential_access", "password_collection"),
    "GetProcesses": ("process_discovery", "process_listing"),
    "GetSystemInfo": ("system_discovery", "system_information"),
    "FileTransferRequest": ("file_transfer", "file_transfer_request"),
    "FileTransferChunk": ("file_transfer", "file_transfer_chunk"),
    "FileTransferComplete": ("file_transfer", "file_transfer_complete"),
    "FileTransferCancel": ("file_transfer", "file_transfer_cancel"),
}


def resolve_profile(profile_id: str) -> ObserverProfile:
    """曖昧なfamily名を受けず、完全一致profileだけを返す。"""

    if not isinstance(profile_id, str):
        raise TypeError("profile_idは文字列で指定してください")
    try:
        return PROFILES[profile_id]
    except KeyError as exc:
        raise RatCommandObserverError("未レビューのcommand observer profileです") from exc


def _validate_direction(direction: str) -> str:
    if direction not in {"server_to_client", "client_to_server", "internal"}:
        raise RatCommandObserverError("directionが不正です")
    return direction


def _validate_sample(profile: ObserverProfile, sample_sha256: str | None) -> None:
    if profile.sample_sha256s:
        if sample_sha256 is None or sample_sha256.casefold() not in profile.sample_sha256s:
            raise RatCommandObserverError("sample SHA-256がexact observer profileと一致しません")
    elif sample_sha256 is not None and SHA256_RE.fullmatch(sample_sha256.casefold()) is None:
        raise RatCommandObserverError("sample SHA-256の形式が不正です")


def _bounded_projection(value: Any, *, depth: int = 0) -> Any:
    """messageを有界な非実行JSONへ写像し、bytesは内容でなくhashだけにする。"""

    if depth > MAXIMUM_NESTING_DEPTH:
        raise RatCommandObserverError("messageのnestingが上限を超えています")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RatCommandObserverError("非有限の浮動小数点値は許可しません")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAXIMUM_TEXT_BYTES:
            raise RatCommandObserverError("message textが上限を超えています")
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) > MAXIMUM_MESSAGE_BYTES:
            raise RatCommandObserverError("binary fieldが上限を超えています")
        return {"binary_size": len(raw), "binary_sha256": hashlib.sha256(raw).hexdigest()}
    if isinstance(value, Mapping):
        if len(value) > MAXIMUM_COLLECTION_ITEMS:
            raise RatCommandObserverError("message field数が上限を超えています")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 256:
                raise RatCommandObserverError("message keyが不正です")
            if key in result:
                raise RatCommandObserverError("message keyが重複しています")
            result[key] = _bounded_projection(item, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > MAXIMUM_COLLECTION_ITEMS:
            raise RatCommandObserverError("message配列が上限を超えています")
        return [_bounded_projection(item, depth=depth + 1) for item in value]
    raise RatCommandObserverError("messageに未対応の値型があります")


def _mapping_fingerprint(value: Mapping[str, Any]) -> tuple[int, str, dict[str, Any]]:
    projected = _bounded_projection(value)
    raw = json.dumps(
        projected,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(raw) > MAXIMUM_MESSAGE_BYTES:
        raise RatCommandObserverError("messageが上限を超えています")
    return len(raw), hashlib.sha256(raw).hexdigest(), projected


def _known_or_unknown(
    identifier: str,
    taxonomy: Mapping[str, tuple[str, str]],
) -> tuple[str, str, str]:
    selected = taxonomy.get(identifier)
    if selected is None:
        return "unknown", "unknown", "unknown"
    category, normalized = selected
    return category, normalized, "reviewed_taxonomy"


def _observe_vidar(
    profile: ObserverProfile,
    message: Mapping[str, Any],
    direction: str,
) -> CommandObservation:
    size, digest, projected = _mapping_fingerprint(message)
    legacy_safety = {
        "network_contacted": False,
        "sample_executed": False,
        "raw_snapshot_published": False,
        "shared_service_is_c2": False,
        "active_probe_required": False,
    }
    current_safety = {
        "network_contacted": False,
        "sample_executed": False,
        "tool_published_raw_response": False,
        "tool_managed_output_repository_publication": False,
        "shared_service_is_c2": False,
        "active_probe_required": False,
    }
    if (
        message.get("schema_version") != 1
        or message.get("profile") != "vidar_dead_drop_snapshot_correlation_v1"
        or message.get("safety") not in (legacy_safety, current_safety)
        or message.get("c2_confirmed") is not False
    ):
        raise RatCommandObserverError("Vidar snapshot resultの安全契約が不一致です")
    candidate = message.get("final_c2_candidate")
    if candidate is not None and (
        not isinstance(candidate, str)
        or not 1 <= len(candidate) <= 2048
        or any(character.isspace() or ord(character) < 0x20 for character in candidate)
    ):
        raise RatCommandObserverError("Vidar final candidateが不正です")
    correlated = candidate is not None
    count = message.get("corroborating_service_count")
    confidence = message.get("confidence")
    observations = message.get("observations")
    status = message.get("status")
    current_decoded = status == "decoded_correlated_final_c2_candidate"
    expected_statuses = (
        {"correlated_final_c2_candidate", "decoded_correlated_final_c2_candidate"}
        if correlated
        else {"inconclusive_snapshot_set"}
    )
    resolution = message.get("endpoint_resolution")
    if (
        status not in expected_statuses
        or message.get("final_c2_candidate_recovered") is not correlated
        or message.get("probable_c2") is not correlated
        or type(count) is not int
        or not 0 <= count <= MAXIMUM_COLLECTION_ITEMS
        or (correlated and count < (2 if current_decoded else 1))
        or isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not math.isfinite(float(confidence))
        or not 0.0 <= float(confidence) <= 1.0
        or not isinstance(observations, list)
        or len(observations) > MAXIMUM_COLLECTION_ITEMS
    ):
        raise RatCommandObserverError("Vidar snapshot resultのstatus/count整合が不一致です")
    if current_decoded and (
        not isinstance(resolution, Mapping)
        or resolution.get("method") != "tag_bound_enc_decoder_two_service_correlation"
        or resolution.get("shared_service_response_decoded") is not True
        or resolution.get("protocol_recovered") is not False
        or resolution.get("protocol_status") != "unresolved_static_protocol"
    ):
        raise RatCommandObserverError("Vidar decoded相関のprotocol安全契約が不一致です")
    return _new_observation(
        profile=profile,
        direction=direction,
        event_kind="configuration_instruction",
        category="bootstrap_resolution",
        normalized_command=("correlated_endpoint_candidate" if correlated else "no_unique_endpoint_candidate"),
        protocol_identifier=None,
        identifier_confidence="not_applicable",
        message_size=size,
        message_sha256=digest,
        public_details={
            "interactive_command": False,
            "candidate_present": correlated,
            "candidate_sha256": (
                hashlib.sha256(candidate.encode("utf-8")).hexdigest() if candidate is not None else None
            ),
            "corroborating_service_count": count,
        },
        private_fields={"snapshot_result": projected},
    )


def _stealc_dynamic_fields(message: Mapping[str, Any]) -> set[str]:
    return {
        key
        for key, value in message.items()
        if isinstance(key, str)
        and STEALC_DYNAMIC_HEX_RE.fullmatch(key)
        and isinstance(value, str)
        and STEALC_DYNAMIC_HEX_RE.fullmatch(value)
    }


def _stealc_url_scheme(value: str) -> str:
    if not 1 <= len(value) <= 2048 or any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise RatCommandObserverError("StealC loader URLが安全な構造ではありません")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise RatCommandObserverError("StealC loader URLを解析できません") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise RatCommandObserverError("StealC loader URLがreview済み構造と一致しません")
    return parsed.scheme


def _validate_stealc_message(
    message: Mapping[str, Any],
    direction: str,
) -> tuple[str, list[str], set[str], int | None, dict[str, int]]:
    dynamic_fields = _stealc_dynamic_fields(message)
    dynamic_candidates = {key for key in message if isinstance(key, str) and STEALC_DYNAMIC_HEX_RE.fullmatch(key)}
    if dynamic_candidates != dynamic_fields:
        raise RatCommandObserverError("StealC dynamic fieldの値形状が不一致です")
    has_type = "type" in message
    has_opcode = "opcode" in message
    if has_type == has_opcode:
        raise RatCommandObserverError("StealC messageはtype/opcodeのどちらか一方だけが必要です")

    if direction == "client_to_server":
        request_type = message.get("type")
        if request_type == "create":
            if set(message) != {"type", "build", "hwid"}:
                raise RatCommandObserverError("StealC create requestのkey集合が不一致です")
            if message.get("build") != "1backs" or not isinstance(message.get("hwid"), str):
                raise RatCommandObserverError("StealC create requestのbuild/HWIDが不一致です")
            if STEALC_UUID_RE.fullmatch(str(message["hwid"])) is None:
                raise RatCommandObserverError("StealC create requestのHWID形状が不一致です")
        elif request_type == "loader":
            if set(message) != {"type", "access_token"}:
                raise RatCommandObserverError("StealC loader requestのkey集合が不一致です")
            token = message.get("access_token")
            if not isinstance(token, str) or STEALC_TOKEN_RE.fullmatch(token) is None:
                raise RatCommandObserverError("StealC loader requestのtoken形状が不一致です")
        else:
            raise RatCommandObserverError("StealC request typeが有限2段階profile外です")
        return str(request_type), [], dynamic_fields, None, {}

    opcode = message.get("opcode")
    if not isinstance(opcode, str) or opcode not in STEALC_STATUS_FIELDS:
        raise RatCommandObserverError("StealC response opcodeがreview済み分類外です")
    if opcode != "success":
        if set(message) != {"opcode"}:
            raise RatCommandObserverError("StealC error responseのkey集合が不一致です")
        return opcode, [], dynamic_fields, None, {}

    loader = message.get("loader")
    if type(loader) is list:
        if set(message) != {"opcode", "loader", *dynamic_fields}:
            raise RatCommandObserverError("StealC loader responseのkey集合が不一致です")
        scheme_counts: dict[str, int] = {}
        for entry in loader:
            if type(entry) is not dict or set(entry) != {"url"} or not isinstance(entry.get("url"), str):
                raise RatCommandObserverError("StealC loader entry schemaが不一致です")
            scheme = _stealc_url_scheme(entry["url"])
            scheme_counts[scheme] = scheme_counts.get(scheme, 0) + 1
        return opcode, [], dynamic_fields, len(loader), scheme_counts

    config_fields = sorted(STEALC_CONFIG_FIELDS.intersection(message))
    allowed = {"opcode", "access_token", *STEALC_CONFIG_FIELDS, *dynamic_fields}
    token = message.get("access_token")
    if (
        not config_fields
        or set(message).difference(allowed)
        or not isinstance(token, str)
        or STEALC_TOKEN_RE.fullmatch(token) is None
        or any(type(message[field]) is not STEALC_CONFIG_FIELD_TYPES[field] for field in config_fields)
    ):
        raise RatCommandObserverError("StealC configuration response schemaが不一致です")
    return opcode, config_fields, dynamic_fields, None, {}


def _observe_stealc(
    profile: ObserverProfile,
    message: Mapping[str, Any],
    direction: str,
) -> CommandObservation:
    identifier, config_fields, dynamic_fields, loader_count, scheme_counts = _validate_stealc_message(
        message,
        direction,
    )
    projected = _bounded_projection(message)
    canonical_message = dict(message)
    canonical_message.pop("access_token", None)
    for key in dynamic_fields:
        canonical_message.pop(key)
    size, digest, _ = _mapping_fingerprint(canonical_message)

    if direction == "client_to_server" and identifier == "create":
        category, normalized, event_kind = "registration", "create_registration", "finite_state_transition"
    elif direction == "client_to_server":
        category, normalized, event_kind = "payload_delivery", "loader_configuration", "finite_state_transition"
    elif loader_count is not None:
        category, normalized, event_kind = "payload_delivery", "loader_configuration", "loader_task_response"
    elif config_fields:
        category, normalized, event_kind = "collection_configuration", "initial_configuration", "configuration_response"
    elif identifier in {"blocked", "block"}:
        category, normalized, event_kind = "access_control", "registration_blocked", "protocol_status"
    else:
        category = "protocol_error"
        normalized = f"status_{identifier}"
        event_kind = "protocol_status"

    return _new_observation(
        profile=profile,
        direction=direction,
        event_kind=event_kind,
        category=category,
        normalized_command=normalized,
        protocol_identifier=identifier,
        identifier_confidence="configured_classifier_schema_not_version_confirmation",
        message_size=size,
        message_sha256=digest,
        public_details={
            "interactive_command": False,
            "configuration_fields": config_fields,
            "configuration_field_types_valid": bool(config_fields),
            "dynamic_hex_field_count": len(dynamic_fields),
            "loader_entry_count": loader_count or 0,
            "loader_entry_schema_confirmed": loader_count is not None,
            "loader_url_scheme_counts": scheme_counts,
            "payload_followed": False,
            "payload_fetched": False,
        },
        private_fields={"decoded_message": projected},
    )


def _observe_remus(
    profile: ObserverProfile,
    message: Mapping[str, Any],
    direction: str,
) -> CommandObservation:
    size, digest, projected = _mapping_fingerprint(message)
    task_type = message.get("type")
    if set(message) != {"type", "name", "data"}:
        raise RatCommandObserverError("Remus task envelopeのkey集合が不一致です")
    if type(task_type) is not int or not 0 <= task_type <= 5:
        raise RatCommandObserverError("Remus task typeがreview済み範囲外です")
    return _new_observation(
        profile=profile,
        direction=direction,
        event_kind="task_envelope",
        category="unresolved_task_semantics",
        normalized_command=f"task_type_{task_type}",
        protocol_identifier=str(task_type),
        identifier_confidence="envelope_only_semantics_unresolved",
        message_size=size,
        message_sha256=digest,
        public_details={
            "task_schema_confirmed": False,
            "task_name_protocol_type": type(message.get("name")).__name__,
            "task_data_protocol_type": type(message.get("data")).__name__,
        },
        private_fields={"decoded_task_envelope": projected},
    )


def _observe_venom(
    profile: ObserverProfile,
    frame: bytes,
    direction: str,
) -> CommandObservation:
    if direction != "server_to_client":
        raise RatCommandObserverError("Venom command frameはserver_to_clientだけを受理します")
    if len(frame) > MAXIMUM_MESSAGE_BYTES:
        raise RatCommandObserverError("Venom frameが上限を超えています")
    try:
        decoded = decode_frame(frame, SessionLimits())
        decision = classify_frame(decoded, profile.exact_wire_profile_id or "", SessionLimits())
    except TlsMessagePackHostError as exc:
        raise RatCommandObserverError(f"Venom frameをexact profileで復号できません: {exc}") from exc
    if decision.packet_kind == "unknown":
        category, normalized, confidence = "unknown", "unknown", "unknown"
    else:
        category, normalized, confidence = _known_or_unknown(decision.opcode, VENOM_TAXONOMY)
    projected = _bounded_projection(decoded.values)
    return _new_observation(
        profile=profile,
        direction=direction,
        event_kind="command_frame",
        category=category,
        normalized_command=normalized,
        protocol_identifier=decision.opcode,
        identifier_confidence=confidence,
        message_size=decoded.frame_size,
        message_sha256=decoded.frame_sha256,
        public_details={
            "packet_kind": decision.packet_kind,
            "observer_action": decision.action,
            "binary_payload_count": decision.fingerprint.get("binary_payload_count", 0),
            "binary_payload_size": decision.fingerprint.get("binary_payload_size", 0),
            "decoded_size": decoded.decoded_size,
        },
        private_fields={"decoded_message": projected},
    )


def parse_remcos_plaintext_frame(frame: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Remcos family候補の復号後plaintext frameを長さ込みで厳格に分解する。"""

    if not isinstance(frame, (bytes, bytearray, memoryview)):
        raise TypeError("Remcos frameはbytes-likeで指定してください")
    raw = bytes(frame)
    if not 12 <= len(raw) <= MAXIMUM_MESSAGE_BYTES:
        raise RatCommandObserverError("Remcos plaintext frame長が範囲外です")
    if raw[:4] != REMCOS_MAGIC:
        raise RatCommandObserverError("Remcos packet magicが一致しません")
    declared_size = struct.unpack_from("<I", raw, 4)[0]
    if declared_size != len(raw) - 8 or declared_size < 4:
        raise RatCommandObserverError("Remcos packet sizeが実長と一致しません")
    command_id = struct.unpack_from("<I", raw, 8)[0]
    payload = raw[12:]
    if payload.count(REMCOS_DELIMITER) >= MAXIMUM_COLLECTION_ITEMS:
        raise RatCommandObserverError("Remcos payload field数が上限を超えています")
    fields = payload.split(REMCOS_DELIMITER) if payload else []
    if len(fields) > MAXIMUM_COLLECTION_ITEMS:
        raise RatCommandObserverError("Remcos payload field数が上限を超えています")
    decoded_fields: list[str | None] = []
    for item in fields:
        try:
            text = item.decode("utf-8")
        except UnicodeDecodeError:
            decoded_fields.append(None)
            continue
        decoded_fields.append(text if len(text.encode("utf-8")) <= MAXIMUM_TEXT_BYTES else None)
    return {
        "command_id": command_id,
        "declared_size": declared_size,
        "payload_size": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "field_count": len(fields),
        "decoded_fields": decoded_fields,
        "frame_size": len(raw),
        "frame_sha256": hashlib.sha256(raw).hexdigest(),
    }


class RemcosPlaintextStreamDecoder:
    """復号後Remcos TCP streamを分割・連結の両方に対応して有界復元する。"""

    def __init__(
        self,
        *,
        maximum_frame_bytes: int = MAXIMUM_MESSAGE_BYTES,
        maximum_stream_bytes: int = MAXIMUM_REMCOS_STREAM_BYTES,
        maximum_frames: int = MAXIMUM_REMCOS_STREAM_FRAMES,
    ) -> None:
        if (
            isinstance(maximum_frame_bytes, bool)
            or not isinstance(maximum_frame_bytes, int)
            or not 12 <= maximum_frame_bytes <= MAXIMUM_MESSAGE_BYTES
        ):
            raise RatCommandObserverError("Remcos frame上限が安全範囲外です")
        if (
            isinstance(maximum_stream_bytes, bool)
            or not isinstance(maximum_stream_bytes, int)
            or not maximum_frame_bytes <= maximum_stream_bytes <= MAXIMUM_REMCOS_STREAM_BYTES
        ):
            raise RatCommandObserverError("Remcos stream上限が安全範囲外です")
        if (
            isinstance(maximum_frames, bool)
            or not isinstance(maximum_frames, int)
            or not 1 <= maximum_frames <= MAXIMUM_REMCOS_STREAM_FRAMES
        ):
            raise RatCommandObserverError("Remcos frame数上限が安全範囲外です")
        self.maximum_frame_bytes = maximum_frame_bytes
        self.maximum_stream_bytes = maximum_stream_bytes
        self.maximum_frames = maximum_frames
        self._buffer = bytearray()
        self.total_input_bytes = 0
        self.decoded_frames = 0

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def _validate_partial_magic(self) -> None:
        prefix_size = min(len(self._buffer), len(REMCOS_MAGIC))
        if self._buffer[:prefix_size] != REMCOS_MAGIC[:prefix_size]:
            raise RatCommandObserverError("Remcos streamのpacket magicが一致しません")

    def feed(self, chunk: bytes | bytearray | memoryview) -> list[bytes]:
        """任意境界の1 chunkを受け、完全に検証できたframeだけを返す。"""

        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("Remcos stream chunkはbytes-likeで指定してください")
        raw = bytes(chunk)
        if self.total_input_bytes + len(raw) > self.maximum_stream_bytes:
            raise RatCommandObserverError("Remcos stream累積量が上限を超えました")
        self.total_input_bytes += len(raw)
        self._buffer.extend(raw)
        frames: list[bytes] = []
        while self._buffer:
            self._validate_partial_magic()
            if len(self._buffer) < 8:
                break
            declared_size = struct.unpack_from("<I", self._buffer, 4)[0]
            if declared_size < 4:
                raise RatCommandObserverError("Remcos streamのpacket sizeが最小値未満です")
            frame_size = 8 + declared_size
            if frame_size > self.maximum_frame_bytes:
                raise RatCommandObserverError("Remcos stream frameが上限を超えました")
            if len(self._buffer) < frame_size:
                break
            if self.decoded_frames >= self.maximum_frames:
                raise RatCommandObserverError("Remcos stream frame数が上限を超えました")
            frame = bytes(self._buffer[:frame_size])
            del self._buffer[:frame_size]
            parse_remcos_plaintext_frame(frame)
            frames.append(frame)
            self.decoded_frames += 1
        return frames

    def finish(self) -> None:
        """stream終端でtruncated frameが残っていないことを確認する。"""

        if self._buffer:
            raise RatCommandObserverError("Remcos stream終端に不完全なframeが残っています")


def _observe_remcos(
    profile: ObserverProfile,
    frame: bytes,
    direction: str,
) -> CommandObservation:
    parsed = parse_remcos_plaintext_frame(frame)
    command_id = int(parsed["command_id"])
    taxonomy_selected = profile.profile_id == "remcos-published-340-taxonomy-v1"
    selected = REMCOS_COMMANDS.get(command_id) if taxonomy_selected else None
    if selected is None:
        category, normalized = "unknown", "unknown"
        confidence = "unknown" if taxonomy_selected else "observed_identifier_semantics_unresolved"
    else:
        category, normalized = selected
        confidence = "published_unpinned_3_4_0_taxonomy"
    return _new_observation(
        profile=profile,
        direction=direction,
        event_kind="plaintext_command_frame",
        category=category,
        normalized_command=normalized,
        protocol_identifier=f"0x{command_id:02x}",
        identifier_confidence=confidence,
        message_size=int(parsed["frame_size"]),
        message_sha256=str(parsed["frame_sha256"]),
        public_details={
            "declared_size": parsed["declared_size"],
            "payload_size": parsed["payload_size"],
            "payload_sha256": parsed["payload_sha256"],
            "field_count": parsed["field_count"],
            "taxonomy_source": REMCOS_PUBLISHED_TAXONOMY_SOURCE if taxonomy_selected else None,
            "taxonomy_evidence_artifact_pinned": False,
            "published_taxonomy_applied": taxonomy_selected,
            "exact_sample_binding": False,
            "transport_decryption_performed": False,
        },
        private_fields={"decoded_payload_fields": parsed["decoded_fields"]},
    )


def _quasar_short_name(value: str) -> str:
    name = value.split(",", 1)[0].rsplit(".", 1)[-1]
    if not name or len(name.encode("utf-8")) > 256:
        raise RatCommandObserverError("Quasar message typeが不正です")
    return name


def _observe_quasar(
    profile: ObserverProfile,
    message: Mapping[str, Any],
    direction: str,
) -> CommandObservation:
    size, digest, projected = _mapping_fingerprint(message)
    identifier = message.get("message_type", message.get("$type"))
    if not isinstance(identifier, str):
        raise RatCommandObserverError("Quasar decoded messageにmessage typeがありません")
    short_name = _quasar_short_name(identifier)
    if short_name == "ClientIdentification" and direction != "client_to_server":
        raise RatCommandObserverError("Quasar registration messageの方向が不一致です")
    if (
        short_name != "ClientIdentification"
        and (short_name.endswith("Result") or short_name.startswith(("Do", "Get")))
        and direction != "server_to_client"
    ):
        raise RatCommandObserverError("Quasar command messageの方向が不一致です")
    category, normalized, confidence = _known_or_unknown(short_name, QUASAR_TAXONOMY)
    return _new_observation(
        profile=profile,
        direction=direction,
        event_kind="decoded_upstream_message",
        category=category,
        normalized_command=normalized,
        protocol_identifier=short_name,
        identifier_confidence=confidence,
        message_size=size,
        message_sha256=digest,
        public_details={
            "exact_sample_wire_match": False,
            "message_type_id_recovered": False,
            "serializer_reimplemented": False,
        },
        private_fields={"decoded_message": projected},
    )


def observe_command(
    profile_id: str,
    message: Mapping[str, Any] | bytes | bytearray | memoryview,
    *,
    direction: str,
    sample_sha256: str | None = None,
) -> CommandObservation:
    """完全一致profileへ束縛し、1 messageを副作用なしで分類する。"""

    profile = resolve_profile(profile_id)
    active_direction = _validate_direction(direction)
    if active_direction not in profile.allowed_directions:
        raise RatCommandObserverError("directionがobserver profileの許可方向と一致しません")
    normalized_sample = sample_sha256.casefold() if sample_sha256 is not None else None
    _validate_sample(profile, normalized_sample)
    if profile.family == "venomrat":
        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise RatCommandObserverError("Venom observerにはwire frame bytesが必要です")
        return _observe_venom(profile, bytes(message), active_direction)
    if profile.family == "remcosrat":
        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise RatCommandObserverError("Remcos observerには復号後frame bytesが必要です")
        return _observe_remcos(profile, bytes(message), active_direction)
    if not isinstance(message, Mapping):
        raise RatCommandObserverError("decoded observerにはJSON objectが必要です")
    if profile.family == "vidar":
        if message.get("sample_sha256") != normalized_sample:
            raise RatCommandObserverError("Vidar result内sample SHA-256がprofile bindingと不一致です")
        return _observe_vidar(profile, message, active_direction)
    if profile.family == "stealc":
        return _observe_stealc(profile, message, active_direction)
    if profile.family == "remusstealer":
        return _observe_remus(profile, message, active_direction)
    if profile.family == "quasarrat":
        return _observe_quasar(profile, message, active_direction)
    raise AssertionError(f"observer dispatch未実装です: {profile.family}")


def _validate_spool_provenance(
    profile: ObserverProfile,
    profile_id: str,
    envelope: Mapping[str, Any],
) -> None:
    schema_version = envelope.get("schema_version")
    envelope_profile = envelope.get("profile_id")
    source_scope = envelope.get("source_scope")
    direction = envelope.get("direction")
    captured_at = envelope.get("captured_at")
    sample_sha256 = envelope.get("sample_sha256")
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise RatCommandObserverError("spool schema_versionが未対応です")
    if envelope_profile != profile_id or envelope_profile != profile.profile_id:
        raise RatCommandObserverError("spool profile bindingが不一致です")
    if source_scope not in {"offline_capture", "loopback"}:
        raise RatCommandObserverError("spool source_scopeがoffline/loopbackではありません")
    if not isinstance(direction, str) or direction not in profile.allowed_directions:
        raise RatCommandObserverError("spool directionがprofileの許可方向と不一致です")
    if not isinstance(captured_at, str) or CAPTURED_AT_RE.fullmatch(captured_at) is None:
        raise RatCommandObserverError("spool captured_atがUTC秒精度ではありません")
    if sample_sha256 is not None and (not isinstance(sample_sha256, str) or sample_sha256 != sample_sha256.casefold()):
        raise RatCommandObserverError("spool sample SHA-256がcanonicalではありません")
    _validate_sample(profile, sample_sha256)


def decode_spool_message(profile_id: str, envelope: Mapping[str, Any]) -> Mapping[str, Any] | bytes:
    """非公開spool envelopeをprofile/provenanceへ束縛して厳格に取り出す。"""

    if not isinstance(envelope, Mapping):
        raise RatCommandObserverError("spool envelopeはobjectである必要があります")
    profile = resolve_profile(profile_id)
    binary_fields = {
        "schema_version",
        "profile_id",
        "sample_sha256",
        "source_scope",
        "direction",
        "captured_at",
        "encoding",
        "frame_base64",
    }
    decoded_fields = {
        "schema_version",
        "profile_id",
        "sample_sha256",
        "source_scope",
        "direction",
        "captured_at",
        "encoding",
        "message",
    }
    expected_fields = binary_fields if profile.family in {"venomrat", "remcosrat"} else decoded_fields
    if set(envelope) != expected_fields:
        raise RatCommandObserverError("spool envelopeのkey集合が不正です")
    _validate_spool_provenance(profile, profile_id, envelope)
    encoding = envelope.get("encoding")
    if profile.family in {"venomrat", "remcosrat"}:
        if encoding != "frame_base64":
            raise RatCommandObserverError("binary spool encodingが不正です")
        encoded = envelope.get("frame_base64")
        if not isinstance(encoded, str) or len(encoded) > (MAXIMUM_MESSAGE_BYTES * 4 // 3 + 8):
            raise RatCommandObserverError("frame_base64が不正です")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise RatCommandObserverError("frame_base64を厳格に復号できません") from exc
        if len(decoded) > MAXIMUM_MESSAGE_BYTES:
            raise RatCommandObserverError("binary spool frameが上限を超えています")
        return decoded
    if encoding != "decoded_json":
        raise RatCommandObserverError("decoded spool encodingが不正です")
    message = envelope.get("message")
    if not isinstance(message, Mapping):
        raise RatCommandObserverError("decoded spool messageはobjectである必要があります")
    _, _, projected = _mapping_fingerprint(message)
    return projected


__all__ = [
    "PROFILES",
    "REMCOS_PUBLISHED_TAXONOMY_SOURCE",
    "CommandObservation",
    "ObserverProfile",
    "RatCommandObserverError",
    "RemcosPlaintextStreamDecoder",
    "decode_spool_message",
    "observe_command",
    "parse_remcos_plaintext_frame",
    "resolve_profile",
]
