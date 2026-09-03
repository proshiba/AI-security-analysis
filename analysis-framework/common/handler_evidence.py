#!/usr/bin/env python3
"""信頼済みhandler成果物から設定と通信パターンを保守的に正規化する。"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from typing import Any

from handler_catalog import sanitize_public_value
from ioc_markdown import (
    CONFIRMED_STATIC_CONFIGURATION,
    PUBLIC_C2_FIELDS,
    normalize_confirmed_network_iocs,
)
from screenconnect_evidence import (
    legacy_screenconnect_config,
    screenconnect_management_role,
    validated_screenconnect_config,
)


MAX_CANDIDATE_PATTERNS = 256
DUAL_USE_MANAGEMENT_ROLES = frozenset(
    {"remote_management_relay", "screenconnect_clickonce_bootstrap"}
)
NETWORK_CONTAINER_FIELDS = (
    "c2",
    "config_endpoints",
)
CONFIG_NETWORK_FIELDS = (
    "endpoints",
    "config_endpoints",
    "network_candidates",
    "c2_urls",
    "config_record_urls",
)


def _validated_ghostdesk_endpoints(result: object) -> list[dict[str, Any]]:
    """旧GhostDesk wrapperの厳格XOR設定契約だけを標準IOCへ昇格する。"""

    if not isinstance(result, Mapping) or result.get("family") != "ghostdesk":
        return []
    config = result.get("config")
    configuration = result.get("configuration")
    candidates = result.get("c2")
    records = configuration.get("records") if isinstance(configuration, Mapping) else None
    token_record = records.get("token_record") if isinstance(records, Mapping) else None
    if (
        result.get("decoded_config_recovered") is not True
        or not isinstance(config, Mapping)
        or config.get("decoded_config_recovered") is not True
        or config.get("static_config_recovered") is not True
        or config.get("status") != "confirmed_static_xor_config"
        or config.get("endpoints") != candidates
        or not isinstance(configuration, Mapping)
        or configuration.get("decoded_config_recovered") is not True
        or configuration.get("algorithm") != "single-byte XOR"
        or configuration.get("unique_pair_required") is not True
        or not isinstance(token_record, Mapping)
        or token_record.get("raw_value_exported") is not False
        or not isinstance(candidates, list)
        or len(candidates) != 1
    ):
        return []
    endpoint = candidates[0]
    if (
        not isinstance(endpoint, Mapping)
        or not isinstance(endpoint.get("host"), str)
        or not endpoint.get("host")
        or type(endpoint.get("port")) is not int
        or not 1 <= int(endpoint["port"]) <= 65535
        or endpoint.get("transport") != "websocket_over_raw_tcp"
        or endpoint.get("role") != "configured_external_c2"
        or endpoint.get("websocket_path_redacted") != "/bot?token=<redacted>"
        or endpoint.get("configured_tls") is not False
        or endpoint.get("confidence")
        not in {"confirmed_static_xor_config", CONFIRMED_STATIC_CONFIGURATION}
    ):
        return []
    return [
        {
            **dict(endpoint),
            "confidence": CONFIRMED_STATIC_CONFIGURATION,
            "contacted": False,
            "liveness_confirmed": False,
            "evidence": {
                "kind": "decoded_xor_config",
                "all_expected_fields_validated": True,
                "raw_token_exported": False,
            },
        }
    ]


def _validated_ghostdesk_protocol(result: object) -> dict[str, Any] | None:
    """review済みGhostDeskの既存詳細schemaをlive未確認protocol要約へ変換する。"""

    if not _validated_ghostdesk_endpoints(result) or not isinstance(result, Mapping):
        return None
    sample = result.get("sample")
    reviewed = result.get("reviewed_ghidra_evidence")
    protocol = result.get("protocol")
    dispatch = result.get("command_dispatch")
    safety = result.get("safety")
    digest = sample.get("sha256") if isinstance(sample, Mapping) else None
    websocket = protocol.get("websocket") if isinstance(protocol, Mapping) else None
    crypto = protocol.get("session_crypto") if isinstance(protocol, Mapping) else None
    registration = protocol.get("registration") if isinstance(protocol, Mapping) else None
    heartbeat = protocol.get("heartbeat") if isinstance(protocol, Mapping) else None
    if (
        result.get("projection_scope") != "confirmed_reviewed_sample"
        or not isinstance(digest, str)
        or len(digest) != 64
        or not isinstance(reviewed, Mapping)
        or reviewed.get("applies_to_sha256") != digest
        or not isinstance(websocket, Mapping)
        or websocket.get("request_path_redacted") != "/bot?token=<redacted>"
        or not isinstance(crypto, Mapping)
        or crypto.get("key_agreement") != "ECDH P-256"
        or crypto.get("cipher") != "AES-GCM"
        or not isinstance(registration, Mapping)
        or registration.get("type") != "register"
        or not isinstance(registration.get("fields"), list)
        or not registration.get("fields")
        or not isinstance(heartbeat, Mapping)
        or heartbeat.get("type") != "heartbeat"
        or not isinstance(dispatch, Mapping)
        or not isinstance(dispatch.get("operator_commands_present"), list)
        or not dispatch.get("operator_commands_present")
        or not isinstance(dispatch.get("acknowledgement_types"), list)
        or not isinstance(safety, Mapping)
        or safety.get("sample_executed") is not False
        or safety.get("network_contacted") is not False
        or safety.get("operator_content_executed") is not False
    ):
        return None
    return {
        "family": "ghostdesk",
        "sample_sha256": digest,
        "method": "websocket_ecdh_aes_gcm_json",
        "transport": "websocket_over_raw_tcp",
        "framing": "rfc6455_websocket_frames",
        "serialization": "json_control_and_binary_stream_frames",
        "confidence": "high",
        "registration_method": "json_register_message",
        "dispatcher_method": "json_type_dispatch",
        "heartbeat_required": True,
        "heartbeat_method": "json_heartbeat_message",
        "command_markers": sorted(set(dispatch["operator_commands_present"])),
        "transfer_markers": sorted(
            value
            for value in set(dispatch["acknowledgement_types"])
            if value in {"file_data", "file_chunk", "upload_ok", "plugin_ack"}
        ),
        "heartbeat_response_markers": ["heartbeat"],
        "live_operation_fake_result_allowed": False,
        "live_verified": False,
    }


def trusted_handler_result(
    execution: Mapping[str, Any],
    artifact: Mapping[str, Any],
) -> bool:
    """reportと一致する十分な静的handler成果物だけを受理する。"""

    if (
        execution.get("status") != "succeeded"
        or artifact.get("executed_sample") is not False
        or artifact.get("network_contacted") is not False
    ):
        return False
    execution_evidence = execution.get("selected_evidence")
    artifact_evidence = artifact.get("selected_evidence")
    if (
        not isinstance(execution_evidence, Mapping)
        or execution_evidence.get("sufficient") is not True
        or not isinstance(artifact_evidence, Mapping)
        or artifact_evidence.get("sufficient") is not True
        or any(
            artifact_evidence.get(key) != value
            for key, value in execution_evidence.items()
        )
    ):
        return False
    execution_id = str(execution.get("handler_id") or "")
    handler = artifact.get("handler")
    artifact_id = str(handler.get("id") or "") if isinstance(handler, Mapping) else ""
    if not (execution_id and artifact_id and execution_id == artifact_id):
        return False
    selected_layer = execution.get("selected_layer_sha256")
    result = artifact.get("result")
    artifact_sample = (
        result.get("sample_sha256") if isinstance(result, Mapping) else None
    )
    if (
        selected_layer is not None
        and artifact_sample is not None
        and selected_layer != artifact_sample
    ):
        return False
    return True


def _trusted_results(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    return [
        (execution, artifact) for execution, artifact in handler_results if trusted_handler_result(execution, artifact)
    ]


def confirmed_static_handler_iocs(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """確認済み静的設定のendpointだけを公開可能なnetwork IOCへ正規化する。"""

    candidates_for_normalization: list[dict[str, Any]] = []
    for _execution, artifact in _trusted_results(handler_results):
        result = artifact.get("result")
        candidates = result.get("c2") if isinstance(result, Mapping) else None
        ghostdesk_candidates = _validated_ghostdesk_endpoints(result)
        if ghostdesk_candidates:
            candidates = ghostdesk_candidates
        config_endpoint_mode = False
        static_evidence: Any = None
        if isinstance(result, Mapping) and not isinstance(candidates, list):
            candidates = result.get("config_endpoints")
            config_endpoint_mode = isinstance(candidates, list)
            static_evidence = result.get("static_evidence")
        if isinstance(result, Mapping) and not isinstance(candidates, list):
            config = result.get("config")
            if isinstance(config, Mapping):
                candidates = config.get("config_endpoints")
                config_endpoint_mode = isinstance(candidates, list)
                static_evidence = config.get("static_evidence")
        if isinstance(result, Mapping) and not isinstance(candidates, list):
            legacy_config = legacy_screenconnect_config(result)
            if legacy_config is not None:
                candidates = legacy_config["config_endpoints"]
                static_evidence = legacy_config["static_evidence"]
                config_endpoint_mode = True
        if not isinstance(candidates, list):
            continue
        if config_endpoint_mode and (
            not isinstance(static_evidence, Mapping) or static_evidence.get("all_expected_fields_validated") is not True
        ):
            continue
        handler = artifact.get("handler") or {}
        source = f"handler:{handler.get('id')}"
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            record = dict(candidate)
            if config_endpoint_mode and not isinstance(record.get("evidence"), Mapping):
                record["evidence"] = {
                    "kind": "position_independent_static_config",
                    "resolved_from": record.get("resolved_from"),
                    "all_expected_fields_validated": True,
                }
            record["source"] = source
            candidates_for_normalization.append(record)
    return normalize_confirmed_network_iocs(candidates_for_normalization)


def static_config_recovered(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    network_iocs: list[dict[str, Any]],
) -> bool:
    """信頼済みconfig flagまたは確認済み静的endpointがあれば回収済みとする。"""

    if network_iocs:
        return True
    for _execution, artifact in _trusted_results(handler_results):
        result = artifact.get("result")
        if not isinstance(result, Mapping):
            continue
        if result.get("static_config_recovered") is True or result.get("decoded_config_recovered") is True:
            return True
        config = result.get("config")
        if isinstance(config, Mapping) and config.get("static_config_recovered") is True:
            return True
    return False


def is_dual_use_management_endpoint(
    record: object,
    *,
    family: str,
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> bool:
    """strict ScreenConnect configと完全相関する管理endpointだけを識別する。"""

    if family != "screenconnect_rmm" or not isinstance(record, Mapping):
        return False
    role = record.get("role")
    evidence = record.get("evidence")
    expected_classification = {
        "remote_management_relay": "dual_use_not_c2_by_itself",
        "screenconnect_clickonce_bootstrap": (
            "dual_use_management_endpoint_not_c2_by_itself"
        ),
    }.get(role)
    if (
        expected_classification is None
        or not isinstance(evidence, Mapping)
        or evidence.get("kind") != "screenconnect_embedded_management_endpoint"
        or evidence.get("malicious_use_confirmed") is not False
        or evidence.get("c2_classification") != expected_classification
    ):
        return False
    source = record.get("source")
    for execution, artifact in _trusted_results(handler_results):
        handler = artifact.get("handler")
        if (
            not isinstance(handler, Mapping)
            or handler.get("family") != "screenconnect_rmm"
            or handler.get("id") != execution.get("handler_id")
            or source != f"handler:{handler.get('id')}"
        ):
            continue
        if screenconnect_management_role(artifact.get("result"), record) == role:
            return True
    return False


def confirmed_static_protocol_evidence(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """完全なfamily固有method証拠だけを静的protocol確証へ正規化する。"""

    summaries: dict[str, dict[str, Any]] = {}
    for _execution, artifact in _trusted_results(handler_results):
        result = artifact.get("result")
        if not isinstance(result, Mapping):
            continue
        ghostdesk = _validated_ghostdesk_protocol(result)
        if ghostdesk is not None:
            identity = json.dumps(
                ghostdesk,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            summaries[identity] = ghostdesk
            continue
        protocol = result.get("protocol_evidence")
        profile = result.get("static_protocol")
        if not isinstance(protocol, Mapping) or not isinstance(profile, Mapping):
            continue
        registration = protocol.get("registration")
        dispatcher = protocol.get("dispatcher")
        heartbeat = dispatcher.get("heartbeat_request") if isinstance(dispatcher, Mapping) else None
        readiness = protocol.get("emulator_readiness")
        safety = protocol.get("safety")
        family = protocol.get("family")
        sample_sha256 = protocol.get("sample_sha256")
        heartbeat_required = readiness.get("heartbeat_required", True) if isinstance(readiness, Mapping) else True
        if not isinstance(heartbeat_required, bool):
            continue
        heartbeat_valid = (
            isinstance(heartbeat, Mapping)
            and heartbeat.get("schema_confirmed") is True
            and isinstance(readiness, Mapping)
            and readiness.get("heartbeat_request_response_confirmed") is True
            if heartbeat_required
            else heartbeat is None
            and isinstance(readiness, Mapping)
            and readiness.get("heartbeat_request_response_confirmed") is False
            and dispatcher.get("heartbeat_response_markers") == []
        )
        if (
            protocol.get("analysis_status") != "complete"
            or not isinstance(family, str)
            or family != result.get("family")
            or not isinstance(sample_sha256, str)
            or sample_sha256 != result.get("sample_sha256")
            or not isinstance(registration, Mapping)
            or registration.get("missing_required_fields") != []
            or not isinstance(dispatcher, Mapping)
            or dispatcher.get("missing_command_markers") != []
            or not heartbeat_valid
            or not isinstance(readiness, Mapping)
            or readiness.get("registration_schema_confirmed") is not True
            or readiness.get("command_dispatcher_confirmed") is not True
            or readiness.get("live_operation_fake_result_allowed") is not False
            or not isinstance(safety, Mapping)
            or safety.get("sample_executed") is not False
            or safety.get("network_contacted") is not False
            or safety.get("raw_cil_published") is not False
            or safety.get("unreviewed_literals_published") is not False
            or profile.get("status") != "confirmed"
            or profile.get("confidence") not in {"medium", "high"}
            or profile.get("tcp_open_only") is not False
            or profile.get("live_verified") is not False
        ):
            continue
        scalar_fields = ("method", "transport", "framing", "serialization")
        if any(not isinstance(profile.get(key), str) or not str(profile[key]).strip() for key in scalar_fields):
            continue
        record = {
            "family": family,
            "sample_sha256": sample_sha256,
            **{key: str(profile[key]) for key in scalar_fields},
            "confidence": str(profile["confidence"]),
            "registration_method": str(registration.get("method") or ""),
            "dispatcher_method": str(dispatcher.get("method") or ""),
            "heartbeat_required": heartbeat_required,
            "heartbeat_method": str(heartbeat.get("method") or "") if isinstance(heartbeat, Mapping) else "",
            "command_markers": [
                str(item) for item in dispatcher.get("observed_command_markers", []) if isinstance(item, str)
            ],
            "transfer_markers": [
                str(item) for item in dispatcher.get("file_or_plugin_transfer_markers", []) if isinstance(item, str)
            ],
            "heartbeat_response_markers": [
                str(item) for item in dispatcher.get("heartbeat_response_markers", []) if isinstance(item, str)
            ],
            "live_operation_fake_result_allowed": False,
            "live_verified": False,
        }
        identity = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        summaries[identity] = record
    return [summaries[key] for key in sorted(summaries)]


def terminal_managed_client_confirmed(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    family: str,
) -> bool:
    """信頼済みhandlerがrootを終端managed clientと検証した場合だけtrueを返す。"""

    for execution, artifact in _trusted_results(handler_results):
        result = artifact.get("result")
        handler = artifact.get("handler")
        handler_family = handler.get("family") if isinstance(handler, Mapping) else None
        result_family = result.get("family") if isinstance(result, Mapping) else None
        screenconnect_context = (
            family == "screenconnect_rmm"
            or handler_family == "screenconnect_rmm"
            or result_family == "ScreenConnect RMM"
        )
        if screenconnect_context:
            if (
                family == "screenconnect_rmm"
                and handler_family == "screenconnect_rmm"
                and isinstance(result, Mapping)
                and result.get("artifact_role") == "access_agent_installer"
                and validated_screenconnect_config(result) is not None
                and handler.get("id") == execution.get("handler_id")
            ):
                return True
            # ScreenConnect形の不正・不一致成果物を汎用booleanへfail-openしない。
            continue
        config = result.get("config") if isinstance(result, Mapping) else None
        if isinstance(config, Mapping) and config.get("terminal_managed_client") is True:
            return True
    return False


def _candidate_record(value: object, *, source: str, field: str) -> dict[str, Any] | None:
    sanitized = sanitize_public_value(value)
    if isinstance(sanitized, str):
        if not sanitized.strip() or sanitized.startswith("[REDACTED_"):
            return None
        return {
            "value": sanitized,
            "source": source,
            "source_field": field,
            "status": "candidate_static_handler_output",
        }
    if not isinstance(sanitized, dict):
        return None
    if sanitized.get("confidence") == CONFIRMED_STATIC_CONFIGURATION:
        return None
    record = {key: sanitized[key] for key in (*PUBLIC_C2_FIELDS, "value") if key in sanitized}
    if not any(
        isinstance(record.get(key), str) and bool(str(record[key]).strip())
        for key in ("url", "host", "domain", "ip", "address", "endpoint", "value")
    ):
        return None
    record["source"] = source
    record["source_field"] = field
    record["status"] = "candidate_static_handler_output"
    return record


def candidate_communication_patterns(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """信頼済みhandler内の未確定通信候補を、C2へ昇格せず決定的に返す。"""

    unique: dict[str, dict[str, Any]] = {}
    for _execution, artifact in _trusted_results(handler_results):
        handler = artifact.get("handler") or {}
        source = f"handler:{handler.get('id')}"
        result = artifact.get("result")
        if not isinstance(result, Mapping):
            continue
        containers: list[tuple[str, object]] = [
            (f"result.{field}", result.get(field)) for field in NETWORK_CONTAINER_FIELDS
        ]
        config = result.get("config")
        if isinstance(config, Mapping):
            containers.extend((f"result.config.{field}", config.get(field)) for field in CONFIG_NETWORK_FIELDS)
        for field, values in containers:
            if not isinstance(values, list):
                continue
            for value in values:
                record = _candidate_record(value, source=source, field=field)
                if record is None:
                    continue
                identity = json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                unique[identity] = record
                if len(unique) >= MAX_CANDIDATE_PATTERNS:
                    return [unique[key] for key in sorted(unique)]
    return [unique[key] for key in sorted(unique)]


def build_communication_pattern_document(
    *,
    sha256: str,
    family: str,
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> dict[str, Any]:
    """config回収と静的通信パターンを1つの公開可能な機械可読文書へまとめる。"""

    materialized = list(handler_results)
    trusted = _trusted_results(materialized)
    confirmed = confirmed_static_handler_iocs(trusted)
    candidates = candidate_communication_patterns(trusted)
    recovered = static_config_recovered(trusted, confirmed)
    protocols = confirmed_static_protocol_evidence(trusted)
    terminal_managed_client = terminal_managed_client_confirmed(
        trusted,
        family=family,
    )
    handler_ids = sorted(
        {
            str(execution.get("handler_id"))
            for execution, _artifact in trusted
            if isinstance(execution.get("handler_id"), str)
        }
    )
    if confirmed:
        status = "confirmed_static_configuration_patterns"
    elif candidates:
        status = "candidate_patterns_only"
    else:
        status = "unresolved"
    protocol_hints = sorted(
        {
            str(record[key])
            for record in [*confirmed, *candidates, *protocols]
            for key in ("transport", "protocol", "method")
            if isinstance(record.get(key), str) and str(record[key]).strip()
        }
    )
    management_endpoints = [
        record
        for record in confirmed
        if is_dual_use_management_endpoint(
            record,
            family=family,
            handler_results=trusted,
        )
    ]
    management_identities = {
        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for record in management_endpoints
    }
    c2_endpoints = [
        record
        for record in confirmed
        if json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        not in management_identities
    ]
    return {
        "schema_version": 1,
        "sha256": sha256,
        "family": family or "unclassified",
        "status": status,
        "config": {
            "static_config_recovered": recovered,
            "trusted_handler_ids": handler_ids,
            "terminal_managed_client": terminal_managed_client,
        },
        "communication": {
            "confirmed_static_endpoints": confirmed,
            "confirmed_static_c2_endpoints": c2_endpoints,
            "confirmed_static_management_endpoints": management_endpoints,
            "candidate_patterns": candidates,
            "protocol_hints": protocol_hints,
            "protocol_confirmed": bool(protocols),
            "protocol_evidence": protocols,
            "liveness_confirmed": False,
        },
        "evidence_boundary": {
            "candidate_patterns_are_c2_confirmation": False,
            "static_endpoint_is_liveness_confirmation": False,
            "static_protocol_is_liveness_confirmation": False,
            "protocol_confirmation_requires_family_specific_evidence": True,
            "dual_use_management_endpoint_is_c2_confirmation": False,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "credentials_published": False,
            "raw_payload_published": False,
        },
    }
