#!/usr/bin/env python3
"""信頼済みhandler成果物から設定と通信パターンを保守的に正規化する。"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from ipaddress import ip_address
from typing import Any

from analysis_contract import handler_result_quality
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
MAX_ROUTE_CONFIG_CANDIDATES = 64
MAX_ROUTE_CONFIG_ENDPOINTS = 32
MAX_ROUTE_ASSESSMENT_FAMILIES = 256
MAX_ROUTE_ASSESSMENT_ATTEMPTS = 4096
ROUTE_ONLY_ATTEMPT_STATUS = "handler_evidence_without_detector"
ROUTE_CONFIG_VARIANT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}\Z")
ROUTE_CONFIG_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
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
    "stage_urls",
)
CONFIGURATION_IDENTITY_FIELDS = (
    "url",
    "host",
    "domain",
    "ip",
    "address",
    "endpoint",
    "port",
    "transport",
    "protocol",
    "method",
    "path",
    "proxy",
    "reachability",
    "role",
)


def _sha256_identity(value: object) -> str | None:
    """lineage比較に使えるlowercase SHA-256だけを返す。"""

    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        return None
    return value


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
    supplied_selected_layer = execution.get("selected_layer_sha256")
    selected_layer = (
        _sha256_identity(supplied_selected_layer)
        if supplied_selected_layer is not None
        else None
    )
    if supplied_selected_layer is not None and selected_layer is None:
        return False
    artifact_layer = artifact.get("selected_layer")
    result = artifact.get("result")
    if selected_layer is not None:
        if (
            not isinstance(artifact_layer, Mapping)
            or _sha256_identity(artifact_layer.get("sha256")) != selected_layer
            or not isinstance(result, Mapping)
            or _sha256_identity(result.get("sample_sha256")) != selected_layer
        ):
            return False

    catalog_family = _artifact_handler_family(artifact)
    if catalog_family is None:
        return False
    reported_family = result.get("family") if isinstance(result, Mapping) else None
    if reported_family is not None and _family_identity(reported_family) != catalog_family:
        return False
    return True


def _trusted_results(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    return [
        (execution, artifact)
        for execution, artifact in handler_results
        if trusted_handler_result(execution, artifact)
    ]


def _family_identity(value: object) -> str | None:
    """表記揺れを除いたfamily比較専用identityを返す。"""

    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        return None
    normalized = "".join(character for character in value.casefold() if character.isalnum())
    return normalized or None


def _artifact_handler_family(artifact: Mapping[str, Any]) -> str | None:
    """handler ID prefixと整合するcatalog familyだけを返す。"""

    handler = artifact.get("handler")
    if not isinstance(handler, Mapping):
        return None
    handler_id = handler.get("id")
    if not isinstance(handler_id, str) or ":" not in handler_id:
        return None
    id_family = _family_identity(handler_id.split(":", 1)[0])
    if id_family is None:
        return None
    supplied_family = handler.get("family")
    if supplied_family is None:
        return id_family
    catalog_family = _family_identity(supplied_family)
    if catalog_family != id_family:
        return None
    return catalog_family


def _family_scoped_trusted_results(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    family: str | None,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """勝者familyだけを残し、勝者不明の複数familyはfail-closedにする。"""

    trusted = _trusted_results(handler_results)
    target = _family_identity(family)
    if target is None:
        observed = {
            observed_family
            for _execution, artifact in trusted
            if (observed_family := _artifact_handler_family(artifact)) is not None
        }
        if len(observed) != 1:
            return []
        target = next(iter(observed))
    return [
        (execution, artifact)
        for execution, artifact in trusted
        if _artifact_handler_family(artifact) == target
    ]


def _confirmed_static_handler_iocs_unscoped(
    trusted_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """同一帰属へ絞込済みの成果物を標準network IOCへ正規化する。"""

    candidates_for_normalization: list[dict[str, Any]] = []
    for _execution, artifact in trusted_results:
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


def _configuration_identity(
    records: Iterable[Mapping[str, Any]],
) -> str | None:
    """公開可能なendpoint意味値だけから非公開の比較identityを作る。"""

    projected = [
        {
            key: record[key]
            for key in CONFIGURATION_IDENTITY_FIELDS
            if key in record
        }
        for record in records
    ]
    if not projected:
        return None
    try:
        identities = sorted(
            {
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                for record in projected
            }
        )
    except (TypeError, ValueError):
        return None
    return json.dumps(
        identities,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _declared_configuration_identities(
    artifact: Mapping[str, Any],
) -> set[str] | None:
    """既存handlerの非秘密SHA-256 identityを固定pathだけから回収する。"""

    result = artifact.get("result")
    if not isinstance(result, Mapping):
        return set()
    config = result.get("config")
    evidence = result.get("evidence")
    vvas_recovery = config.get("vvas_recovery") if isinstance(config, Mapping) else None
    xor_vvas = (
        evidence.get("single_byte_xor_vvas")
        if isinstance(evidence, Mapping)
        else None
    )
    containers = (result, config, vvas_recovery, xor_vvas)
    identities: set[str] = set()
    for container in containers:
        if not isinstance(container, Mapping):
            continue
        value = container.get("configuration_identity_sha256")
        if value is None:
            continue
        if _sha256_identity(value) is None:
            return None
        identities.add(value)
    return identities


def _configuration_identity_conflicts(
    trusted_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> bool:
    """完全endpoint集合または明示config identityが相反すればtrueを返す。"""

    endpoint_identities: set[str] = set()
    declared_identities: set[str] = set()
    for pair in trusted_results:
        records = _confirmed_static_handler_iocs_unscoped([pair])
        if records:
            identity = _configuration_identity(records)
            if identity is None:
                return True
            endpoint_identities.add(identity)
        supplied = _declared_configuration_identities(pair[1])
        if supplied is None or len(supplied) > 1:
            return True
        declared_identities.update(supplied)
        if len(endpoint_identities) > 1 or len(declared_identities) > 1:
            return True
    return False


def _projected_handler_results(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    family: str | None,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """勝者family・単一config identityへ相関した結果だけを投影する。"""

    scoped = _family_scoped_trusted_results(handler_results, family=family)
    if _configuration_identity_conflicts(scoped):
        return []
    return scoped


def confirmed_static_handler_iocs(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    *,
    family: str | None = None,
) -> list[dict[str, Any]]:
    """勝者帰属と一致する確認済み静的endpointだけを正規化する。"""

    projected = _projected_handler_results(handler_results, family=family)
    return _confirmed_static_handler_iocs_unscoped(projected)


def static_config_recovered(
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
    network_iocs: list[dict[str, Any]],
    *,
    family: str | None = None,
) -> bool:
    """勝者帰属のconfig flagまたは相関済み静的endpointだけを受理する。"""

    projected = _projected_handler_results(handler_results, family=family)
    expected_iocs = _confirmed_static_handler_iocs_unscoped(projected)
    if network_iocs and expected_iocs:
        supplied_iocs = normalize_confirmed_network_iocs(network_iocs)
        if _configuration_identity(supplied_iocs) == _configuration_identity(
            expected_iocs
        ):
            return True
    for _execution, artifact in projected:
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
    for execution, artifact in _projected_handler_results(
        handler_results,
        family=family,
    ):
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
    *,
    family: str | None = None,
) -> list[dict[str, Any]]:
    """完全なfamily固有method証拠だけを静的protocol確証へ正規化する。"""

    summaries: dict[str, dict[str, Any]] = {}
    for _execution, artifact in _projected_handler_results(
        handler_results,
        family=family,
    ):
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
        protocol_family = protocol.get("family")
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
            or not isinstance(protocol_family, str)
            or protocol_family != result.get("family")
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
            "family": protocol_family,
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

    for execution, artifact in _projected_handler_results(
        handler_results,
        family=family,
    ):
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
    *,
    family: str | None = None,
) -> list[dict[str, Any]]:
    """信頼済みhandler内の未確定通信候補を、C2へ昇格せず決定的に返す。"""

    unique: dict[str, dict[str, Any]] = {}
    for _execution, artifact in _projected_handler_results(
        handler_results,
        family=family,
    ):
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
            containers.extend(
                (f"result.config.{field}", config.get(field))
                for field in CONFIG_NETWORK_FIELDS
            )
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


def _canonical_route_config_endpoint(value: object) -> tuple[str, str, int] | None:
    """route-only設定から公開できるcanonicalなhost:portだけを返す。"""

    sanitized = sanitize_public_value(value)
    if not isinstance(sanitized, str):
        return None
    text = sanitized.strip()
    if (
        not text
        or text != sanitized
        or len(text) > 512
        or "://" in text
        or any(ord(character) < 0x20 for character in text)
    ):
        return None
    if text.startswith("["):
        closing = text.find("]")
        if closing <= 1 or text[closing + 1 : closing + 2] != ":":
            return None
        host_text = text[1:closing]
        port_text = text[closing + 2 :]
        try:
            address = ip_address(host_text)
        except ValueError:
            return None
        effective_address = getattr(address, "ipv4_mapped", None) or address
        if (
            effective_address.is_loopback
            or effective_address.is_unspecified
            or effective_address.is_link_local
            or effective_address.is_multicast
        ):
            return None
        host = str(address)
        if ":" not in host:
            return None
        rendered_host = f"[{host}]"
    else:
        if text.count(":") != 1:
            return None
        host_text, port_text = text.rsplit(":", 1)
        normalized_host = host_text.rstrip(".").casefold()
        if not normalized_host or len(normalized_host) > 253:
            return None
        try:
            address = ip_address(normalized_host)
        except ValueError:
            labels = normalized_host.split(".")
            if any(ROUTE_CONFIG_DOMAIN_LABEL_RE.fullmatch(label) is None for label in labels):
                return None
            host = normalized_host
        else:
            effective_address = getattr(address, "ipv4_mapped", None) or address
            if (
                effective_address.is_loopback
                or effective_address.is_unspecified
                or effective_address.is_link_local
                or effective_address.is_multicast
            ):
                return None
            host = str(address)
        rendered_host = host
    if not port_text.isascii() or not port_text.isdigit():
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None
    return f"{rendered_host}:{port}", host, port


def _route_assessment_complete(assessment: Mapping[str, Any]) -> bool:
    """候補handlerの全予定試行が省略・枯渇なしで完了したかを返す。"""

    budget = assessment.get("budget")
    counts = {
        key: assessment.get(key)
        for key in (
            "planned_attempt_count",
            "actual_attempt_count",
            "unattempted_attempt_count",
            "omitted_attempt_detail_count",
        )
    }
    return bool(
        assessment.get("status") == "no_confirmed_family"
        and assessment.get("blockers") == []
        and isinstance(budget, Mapping)
        and budget.get("exhausted") is False
        and all(type(value) is int and value >= 0 for value in counts.values())
        and counts["planned_attempt_count"] > 0
        and counts["actual_attempt_count"] == counts["planned_attempt_count"]
        and counts["unattempted_attempt_count"] == 0
        and counts["omitted_attempt_detail_count"] == 0
    )


def _validated_route_config_candidate(
    *,
    family: str,
    family_result: Mapping[str, Any],
    attempt: Mapping[str, Any],
) -> dict[str, Any] | None:
    """帰属未確定のValleyRAT handler結果を設定候補だけへ厳格に縮約する。"""

    if (
        _family_identity(family) != "valleyrat"
        or family_result.get("routing_mode") != "candidate_verification"
        or family_result.get("assessment_eligible") is not True
        or family_result.get("confirmed") is not False
        or family_result.get("status")
        not in {ROUTE_ONLY_ATTEMPT_STATUS, "partial_budget_exhausted"}
        or attempt.get("family") != family
        or attempt.get("status") != ROUTE_ONLY_ATTEMPT_STATUS
    ):
        return None
    evidence = attempt.get("handler_evidence")
    detector = attempt.get("detector_corroboration")
    wrapper = attempt.get("result")
    layer = attempt.get("layer")
    handler_id = attempt.get("handler_id")
    if (
        not isinstance(evidence, Mapping)
        or evidence.get("sufficient") is not True
        or not isinstance(detector, Mapping)
        or detector.get("corroborated") is not False
        or detector.get("basis")
        not in {
            "no_corroborated_detector_in_lineage",
            "detector_route_does_not_support_family_attribution",
        }
        or not isinstance(wrapper, Mapping)
        or not isinstance(layer, Mapping)
        or not isinstance(handler_id, str)
        or not handler_id
        or len(handler_id) > 512
        or any(ord(character) < 0x20 for character in handler_id)
    ):
        return None
    layer_sha256 = _sha256_identity(layer.get("sha256"))
    result = wrapper.get("result")
    quota = wrapper.get("result_quota")
    if (
        layer_sha256 is None
        or not isinstance(result, Mapping)
        or not isinstance(quota, Mapping)
        or quota.get("truncated") is not False
        or quota.get("reasons") not in (None, [])
        or result.get("executed") is not False
        or result.get("network_contacted") is not False
    ):
        return None
    minimum_score = evidence.get("minimum_score")
    if type(minimum_score) is not int or not 1 <= minimum_score <= 1_000_000:
        return None
    computed_quality = handler_result_quality(result, minimum_score=minimum_score)
    if dict(evidence) != computed_quality:
        return None
    execution = {
        "source": "candidate_verification",
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": dict(evidence),
        "selected_layer_sha256": layer_sha256,
        "candidate_assessment_status": ROUTE_ONLY_ATTEMPT_STATUS,
        "detector_corroboration": dict(detector),
    }
    artifact = {
        **dict(wrapper),
        "selected_evidence": dict(evidence),
        "selected_layer": dict(layer),
    }
    if not trusted_handler_result(execution, artifact):
        return None
    handler = wrapper.get("handler")
    if (
        not isinstance(handler, Mapping)
        or handler.get("id") != handler_id
        or _family_identity(handler.get("family")) != "valleyrat"
        or _family_identity(result.get("family")) != "valleyrat"
    ):
        return None
    config = result.get("config")
    findings = result.get("findings")
    if (
        not isinstance(config, Mapping)
        or config.get("static_config_recovered") is not True
        or type(config.get("decoded_config_recovered")) is not bool
        or config.get("c2_liveness_confirmed") is not False
        or config.get("terminal_family_confirmed") is not False
        or config.get("attribution_scope") != "component_handler_route"
        or not isinstance(config.get("family_attribution_basis"), str)
        or not config.get("family_attribution_basis")
        or not isinstance(findings, list)
        or len(findings) > 1024
    ):
        return None
    variant = config.get("variant")
    endpoints = config.get("endpoints")
    if (
        not isinstance(variant, str)
        or ROUTE_CONFIG_VARIANT_RE.fullmatch(variant) is None
        or not isinstance(endpoints, list)
        or not 1 <= len(endpoints) <= MAX_ROUTE_CONFIG_ENDPOINTS
    ):
        return None
    canonical_endpoints: list[tuple[str, str, int]] = []
    for value in endpoints:
        endpoint = _canonical_route_config_endpoint(value)
        if endpoint is None:
            return None
        canonical_endpoints.append(endpoint)
    endpoint_values = [item[0] for item in canonical_endpoints]
    if len(endpoint_values) != len(set(endpoint_values)):
        return None
    finding_sources: dict[str, str] = {}
    for finding in findings:
        if not isinstance(finding, Mapping) or finding.get("kind") != "network.endpoint":
            continue
        endpoint = _canonical_route_config_endpoint(finding.get("value"))
        source = finding.get("source")
        if (
            endpoint is None
            or finding.get("role") != "static_config_c2"
            or finding.get("confidence") != "confirmed_static_config"
            or not isinstance(source, str)
            or not source
            or len(source) > 256
            or any(ord(character) < 0x20 for character in source)
        ):
            return None
        finding_sources[endpoint[0]] = source
    if set(finding_sources) != set(endpoint_values):
        return None
    configured_network_candidates = [
        {
            "endpoint": endpoint,
            "host": host,
            "port": port,
            "role": "static_config_c2_candidate",
            "evidence": {
                "kind": "validated_static_config_route_candidate",
                "handler_source": finding_sources[endpoint],
            },
            "contacted": False,
            "liveness_confirmed": False,
        }
        for endpoint, host, port in canonical_endpoints
    ]
    return {
        "candidate_family": "valleyrat",
        "family_attribution_confirmed": False,
        "handler_id": handler_id,
        "selected_layer_sha256": layer_sha256,
        "variant": variant,
        "recovery_type": (
            "decoded_config_recovered"
            if config.get("decoded_config_recovered") is True
            else "static_config_recovered"
        ),
        "configured_network_candidates": configured_network_candidates,
        "used_for_family_resolution": False,
        "used_for_c2_confirmation": False,
    }


def build_route_config_candidate_document(
    *,
    sha256: str,
    assessment: Mapping[str, Any],
) -> dict[str, Any]:
    """帰属未確定handlerの検証済み設定値をC2確証と分離して記録する。"""

    if _sha256_identity(sha256) is None:
        raise ValueError("route config candidateのroot SHA-256が不正です")
    global_safety_valid = bool(
        assessment.get("schema_version") == 1
        and assessment.get("executed_sample") is False
        and assessment.get("network_contacted") is False
        and assessment.get("filesystem_written_by_handlers") is False
        and assessment.get("confirmed_families") == []
        and assessment.get("status") in {"no_confirmed_family", "partial"}
    )
    complete = global_safety_valid and _route_assessment_complete(assessment)
    unique: dict[str, dict[str, Any]] = {}
    evaluated_attempts = 0
    rejected_attempts = 0
    families = assessment.get("families")
    if (
        global_safety_valid
        and isinstance(families, list)
        and len(families) <= MAX_ROUTE_ASSESSMENT_FAMILIES
    ):
        for family_result in families:
            if not isinstance(family_result, Mapping):
                continue
            family = family_result.get("family")
            attempts = family_result.get("attempts")
            if not isinstance(family, str) or not isinstance(attempts, list):
                continue
            if len(attempts) > MAX_ROUTE_ASSESSMENT_ATTEMPTS:
                rejected_attempts += len(attempts)
                continue
            for attempt in attempts:
                if not isinstance(attempt, Mapping) or attempt.get("status") != ROUTE_ONLY_ATTEMPT_STATUS:
                    continue
                evaluated_attempts += 1
                candidate = _validated_route_config_candidate(
                    family=family,
                    family_result=family_result,
                    attempt=attempt,
                )
                if candidate is None:
                    rejected_attempts += 1
                    continue
                identity = json.dumps(
                    candidate,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                unique[identity] = candidate
    ordered = [unique[key] for key in sorted(unique)]
    truncated = len(ordered) > MAX_ROUTE_CONFIG_CANDIDATES
    candidates = ordered[:MAX_ROUTE_CONFIG_CANDIDATES]
    recovered = bool(candidates)
    configurations = {
        tuple(item["endpoint"] for item in candidate["configured_network_candidates"])
        for candidate in candidates
    }
    if recovered and complete and not truncated:
        status = "route_config_candidates_recovered"
    elif recovered:
        status = "partial_route_config_candidates_recovered"
    elif not global_safety_valid:
        status = "assessment_rejected"
    elif not complete:
        status = "assessment_incomplete_no_route_config_candidate"
    else:
        status = "no_route_config_candidate"
    return {
        "schema_version": 1,
        "sha256": sha256,
        "status": status,
        "route_config_candidate_recovered": recovered,
        "candidate_count": len(candidates),
        "observed_candidate_count": len(ordered),
        "evaluated_route_attempt_count": evaluated_attempts,
        "rejected_route_attempt_count": rejected_attempts,
        "distinct_configuration_count": len(configurations),
        "conflicting_configuration_candidates_present": len(configurations) > 1,
        "candidate_set_complete": bool(complete and not truncated),
        "candidate_set_truncated": truncated,
        "family_attribution_confirmed": False,
        "used_for_family_resolution": False,
        "used_for_c2_confirmation": False,
        "candidates": candidates,
        "evidence_boundary": {
            "handler_config_is_family_confirmation": False,
            "route_config_candidate_is_c2_confirmation": False,
            "route_config_candidate_is_liveness_confirmation": False,
            "independent_detector_corroboration_present": False,
            "configuration_candidates_are_implicitly_merged": False,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_included": False,
            "raw_payload_published": False,
            "credentials_published": False,
        },
    }


def build_communication_pattern_document(
    *,
    sha256: str,
    family: str,
    handler_results: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> dict[str, Any]:
    """config回収と静的通信パターンを1つの公開可能な機械可読文書へまとめる。"""

    materialized = list(handler_results)
    trusted = _projected_handler_results(materialized, family=family)
    confirmed = confirmed_static_handler_iocs(trusted, family=family)
    candidates = candidate_communication_patterns(trusted, family=family)
    recovered = static_config_recovered(trusted, confirmed, family=family)
    protocols = confirmed_static_protocol_evidence(trusted, family=family)
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
