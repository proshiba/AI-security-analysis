#!/usr/bin/env python3
"""RAT emulatorの公開session要約群をC2監視用sidecarへ安全に変換する。

使用例:
  py -3 analysis-framework/common/build_rat_emulation_evidence.py `
    --targets intelligence/c2-monitoring/targets.json `
    --targets-sha256 <targetsのSHA-256> `
    --public-summary C:/private/session-1-public.json `
    --public-summary-sha256 <公開要約のSHA-256> `
    --output C:/private/rat-emulation-evidence.json

複数sessionは ``--public-summary`` と ``--public-summary-sha256`` を同じ順序で
繰り返す。非公開transcriptをdatastoreへ保管済みの場合は、verified upload reportを
``--archive-report`` と ``--archive-report-sha256`` で公開要約と同数・同順序に指定する。
入力はexpected SHA-256付きの不変snapshotとして読み、出力は既存fileを上書きせず、
flushとfsyncを完了してから返す。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import math
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable

from immutable_snapshot import (
    SnapshotIdentity,
    decode_strict_json,
    ensure_new_output,
    read_bounded_snapshot,
    write_new_json,
)
from c2_protocol_probe_profiles import (
    ProtocolProfileError,
    load_profiles as load_protocol_profiles,
)
from rat_emulation_evidence import (
    MAXIMUM_EVIDENCE_BYTES,
    REQUIRED_FALSE_SAFETY_FIELDS,
)
from rat_emulator_profiles import (
    RatEmulatorProfileError,
    RegistrySnapshot,
    load_registry as load_emulator_registry,
)
from tls_messagepack_rat_host_emulator import (
    TlsMessagePackHostError,
    resolve_profile as resolve_tls_messagepack_profile,
)


DEFAULT_MAXIMUM_SUMMARY_AGE_HOURS = 24.0
MAXIMUM_PLAN_BYTES = 16 * 1024 * 1024
MAXIMUM_ARCHIVE_REPORT_BYTES = 1024 * 1024
MAXIMUM_EVENTS = 10_000
MAXIMUM_COMMANDS = 64
MAXIMUM_SESSIONS = 256
MAXIMUM_SESSION_SECONDS = 300.0
MAXIMUM_FUTURE_SKEW = timedelta(minutes=5)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")
SAFE_OPCODE_RE = re.compile(r"^(?:0x[0-9a-f]{1,8}|[A-Za-z0-9][A-Za-z0-9_.:-]{0,31})$")
DATASTORE_TARGET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
DATASTORE_BUCKET = "malware-analysis-datastore-720232834682"
DATASTORE_REPORT_SCHEMA = "analysis-datastore-upload-report/v1"
FORBIDDEN_TLS_PUBLIC_KEYS = frozenset(
    {
        "body",
        "bytes",
        "client_info",
        "command_line",
        "content",
        "credential",
        "data",
        "password",
        "payload",
        "private_fields",
        "raw",
        "raw_frame_file",
        "raw_hex",
        "secret",
        "token",
        "wire_bytes",
    }
)


class RatEmulationEvidenceBuildError(ValueError):
    """公開要約、監視plan、profile binding、期限のいずれかが不正である。"""


@dataclass(frozen=True)
class SummaryInput:
    """expected SHA-256と対にした公開session要約。"""

    path: Path
    expected_sha256: str


@dataclass(frozen=True)
class ArchiveReportInput:
    """公開要約と同じ順序でSHA-256 pinしたdatastore upload report。"""

    path: Path
    expected_sha256: str


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value.casefold()) is None:
        raise RatEmulationEvidenceBuildError(f"{label}がSHA-256ではありません")
    return value.casefold()


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or not value:
        raise RatEmulationEvidenceBuildError(f"{label}にtimezone付き日時が必要です")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RatEmulationEvidenceBuildError(f"{label}を解釈できません") from exc
    if result.tzinfo is None:
        raise RatEmulationEvidenceBuildError(f"{label}にtimezoneがありません")
    return result.astimezone(UTC)


def _safe_token(value: object, label: str) -> str:
    if type(value) is not str or SAFE_TOKEN_RE.fullmatch(value) is None:
        raise RatEmulationEvidenceBuildError(f"{label}が公開可能なtokenではありません")
    return value


def _safe_opcode(value: object, label: str) -> int | str:
    if type(value) is int:
        if not 0 <= value <= 0xFFFFFFFF:
            raise RatEmulationEvidenceBuildError(f"{label}が32 bit範囲外です")
        return value
    if type(value) is str and SAFE_OPCODE_RE.fullmatch(value) is not None:
        return value
    raise RatEmulationEvidenceBuildError(f"{label}が公開可能なopcodeではありません")


def _bounded_int(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RatEmulationEvidenceBuildError(
            f"{label}は{minimum}以上{maximum}以下の整数である必要があります"
        )
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise RatEmulationEvidenceBuildError(f"{label}に未知fieldまたは欠落があります")


def _reject_forbidden_public_keys(value: object, label: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise RatEmulationEvidenceBuildError(f"{label}のkeyが文字列ではありません")
            if key.casefold() in FORBIDDEN_TLS_PUBLIC_KEYS:
                raise RatEmulationEvidenceBuildError(
                    f"{label}へraw・資格情報・本文fieldを混入できません: {key}"
                )
            _reject_forbidden_public_keys(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden_public_keys(item, f"{label}[{index}]")


def _validate_object_uri(value: object, target: str, manifest_sha256: str) -> str:
    prefix = f"s3://{DATASTORE_BUCKET}/"
    if type(value) is not str or not value.startswith(prefix) or len(value) > 1024:
        raise RatEmulationEvidenceBuildError(
            "archive reportのobject_uriが許可されたbucketではありません"
        )
    key = value.removeprefix(prefix)
    raw_parts = key.split("/")
    pure = PurePosixPath(key)
    if (
        not key
        or key.startswith("/")
        or "\\" in key
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,895}", key) is None
        or any(part in {"", ".", ".."} for part in raw_parts)
        or pure.is_absolute()
        or any(ord(character) < 32 for character in key)
        or target not in pure.parts
        or not pure.name.startswith(f"{target}-")
        or not pure.name.endswith(f"-{manifest_sha256[:12]}.zip")
        or pure.suffix.casefold() != ".zip"
    ):
        raise RatEmulationEvidenceBuildError(
            "archive reportのobject_uriがtargetへ安全にbindingされていません"
        )
    return value


def _validate_archive_report(
    report: dict[str, Any],
    identity: SnapshotIdentity,
    session_id: str,
) -> dict[str, Any]:
    """検証済みupload reportから公開可能な参照だけを抽出する。"""

    _reject_forbidden_public_keys(report, "archive report")
    target = report.get("target")
    if (
        report.get("schema_version") != DATASTORE_REPORT_SCHEMA
        or report.get("status") != "verified"
        or type(target) is not str
        or DATASTORE_TARGET_RE.fullmatch(target) is None
        or target != session_id
    ):
        raise RatEmulationEvidenceBuildError(
            "archive reportがverified状態またはsession targetへbindingされていません"
        )
    verification = report.get("s3_verification")
    if (
        not isinstance(verification, dict)
        or verification.get("server_side_encryption") != "AES256"
    ):
        raise RatEmulationEvidenceBuildError(
            "archive reportでS3 AES256検証を確認できません"
        )
    _bounded_int(
        report.get("archive_size"),
        "archive report.archive_size",
        minimum=1,
        maximum=1 << 50,
    )
    archive_sha256 = _sha256(
        report.get("archive_sha256"),
        "archive report.archive_sha256",
    )
    manifest_sha256 = _sha256(
        report.get("manifest_sha256"),
        "archive report.manifest_sha256",
    )
    return {
        "archived": True,
        "datastore_target": target,
        "object_uri": _validate_object_uri(
            report.get("object_uri"),
            target,
            manifest_sha256,
        ),
        "archive_sha256": archive_sha256,
        "manifest_sha256": manifest_sha256,
        "archive_report_sha256": identity.sha256,
        "server_side_encryption": "AES256",
    }


def _read_json_snapshot(
    path: Path,
    expected_sha256: str,
    maximum_bytes: int,
    label: str,
) -> tuple[dict[str, Any], SnapshotIdentity]:
    expected = _sha256(expected_sha256, f"{label} expected SHA-256")
    try:
        snapshot = read_bounded_snapshot(path, maximum_bytes)
    except (OSError, ValueError) as exc:
        raise RatEmulationEvidenceBuildError(f"{label}を安全に読み取れません: {exc}") from exc
    if snapshot.identity.sha256 != expected:
        raise RatEmulationEvidenceBuildError(f"{label} SHA-256 pinが一致しません")
    try:
        value = decode_strict_json(snapshot.data)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulationEvidenceBuildError(f"{label} JSONが不正です: {exc}") from exc
    if not isinstance(value, dict):
        raise RatEmulationEvidenceBuildError(f"{label} rootはobjectである必要があります")
    return value, snapshot.identity


def load_monitoring_plan(path: Path, expected_sha256: str) -> dict[str, Any]:
    """監視planをexpected SHA-256付きで不変読取する。"""

    plan, _identity = _read_json_snapshot(
        path,
        expected_sha256,
        MAXIMUM_PLAN_BYTES,
        "監視plan",
    )
    if plan.get("schema_version") != 1 or not isinstance(plan.get("targets"), list):
        raise RatEmulationEvidenceBuildError("監視plan schemaが不正です")
    return plan


def _matching_target(
    plan: dict[str, Any],
    profile: dict[str, Any],
    registry: RegistrySnapshot,
    protocol_profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    protocol_profile = protocol_profiles.get(profile["protocol_profile_id"])
    if protocol_profile is None:
        raise RatEmulationEvidenceBuildError("review済みprotocol profileが見つかりません")
    if profile.get("transport") != "tls":
        raise RatEmulationEvidenceBuildError(
            "現在のRAT emulator接続方式はprofile側のTLSに限定します"
        )
    expected = {
        "family": profile["family"],
        "host": profile["host"],
        "port": profile["port"],
        "transport": "direct",
        "protocol": protocol_profile["protocol"],
        "protocol_profile_id": profile["protocol_profile_id"],
        "protocol_profile_registry_source": registry.protocol_profile_registry["source"],
        "protocol_profile_registry_sha256": registry.protocol_profile_registry["sha256"],
        "sample_sha256s": profile["sample_sha256s"],
    }
    matches = [
        target
        for target in plan["targets"]
        if isinstance(target, dict)
        and all(target.get(key) == value for key, value in expected.items())
    ]
    if len(matches) != 1:
        raise RatEmulationEvidenceBuildError(
            "公開要約に完全一致する監視targetが1件ではありません"
        )
    target = matches[0]
    if target.get("http_path") is not None:
        raise RatEmulationEvidenceBuildError(
            "RAT emulatorの監視targetはdirect endpointに限定します"
        )
    return target


def _event_list(summary: dict[str, Any]) -> list[dict[str, Any]]:
    events = summary.get("events")
    event_count = summary.get("event_count")
    if (
        not isinstance(events, list)
        or type(event_count) is not int
        or not 0 <= event_count <= MAXIMUM_EVENTS
        or len(events) != event_count
        or any(not isinstance(event, dict) for event in events)
    ):
        raise RatEmulationEvidenceBuildError("公開要約のevent列が不正です")
    return events


def _event_time(
    events: list[dict[str, Any]],
    event_type: str,
    fallback: datetime,
) -> datetime:
    for event in events:
        if event.get("event_type") == event_type:
            return _timestamp(event.get("captured_at"), f"event.{event_type}.captured_at")
    return fallback


def _has_event(events: list[dict[str, Any]], event_type: str, field: str) -> bool:
    return any(
        event.get("event_type") == event_type
        and isinstance(event.get("public_fields"), dict)
        and event["public_fields"].get(field) is True
        for event in events
    )


def _validate_n520_adapter(adapter: dict[str, Any], profile: dict[str, Any]) -> None:
    if adapter.get("protocol") != "n520":
        raise RatEmulationEvidenceBuildError("N520 adapter_resultのprotocolが一致しません")
    safety = adapter.get("safety")
    if not isinstance(safety, dict):
        raise RatEmulationEvidenceBuildError("adapter_result.safetyがありません")
    required_false = (
        "sample_executed",
        "host_operation_executed",
        "file_or_plugin_retained",
        "file_or_plugin_executed",
        "fake_result_sent",
        "live_fake_result_transmission_allowed",
        "session_continues",
    )
    if any(safety.get(field) is not False for field in required_false):
        raise RatEmulationEvidenceBuildError("adapter safety境界が固定値と一致しません")
    registration = adapter.get("registration")
    if (
        not isinstance(registration, dict)
        or registration.get("real_identity_sent") is not False
        or registration.get("payload_size") != 0
    ):
        raise RatEmulationEvidenceBuildError("registrationが匿名・空payloadではありません")


def _validate_tls_wire_metadata(
    value: dict[str, Any],
    label: str,
    *,
    maximum_wire_bytes: int,
    maximum_decoded_bytes: int,
) -> tuple[int, str]:
    frame_size = _bounded_int(
        value.get("frame_size"),
        f"{label}.frame_size",
        minimum=1,
        maximum=maximum_wire_bytes,
    )
    frame_sha256 = _sha256(value.get("frame_sha256"), f"{label}.frame_sha256")
    _bounded_int(
        value.get("decoded_size"),
        f"{label}.decoded_size",
        minimum=1,
        maximum=maximum_decoded_bytes,
    )
    _sha256(value.get("decoded_sha256"), f"{label}.decoded_sha256")
    return frame_size, frame_sha256


def _validate_tls_messagepack_adapter(
    adapter: dict[str, Any],
    profile: dict[str, Any],
) -> None:
    """TLS MessagePack host adapterの公開結果をprofile単位でfail-closed検証する。"""

    _reject_forbidden_public_keys(adapter, "TLS MessagePack adapter_result")
    _require_exact_keys(
        adapter,
        {
            "schema_version",
            "family",
            "protocol",
            "status",
            "certificate_mismatch_is_negative_evidence",
            "registration",
            "collection",
            "command",
            "decisions",
            "heartbeat_request",
            "safety",
        },
        "TLS MessagePack adapter_result",
    )
    if (
        adapter.get("protocol") != profile["family"]
        or adapter.get("certificate_mismatch_is_negative_evidence")
        is not profile["certificate_mismatch_is_negative_evidence"]
    ):
        raise RatEmulationEvidenceBuildError(
            "TLS MessagePack adapter_resultのprotocol/certificate policyが一致しません"
        )
    try:
        exact_profile = resolve_tls_messagepack_profile(profile)
    except (TlsMessagePackHostError, TypeError, ValueError) as exc:
        raise RatEmulationEvidenceBuildError(
            f"TLS MessagePack adapter profileを解決できません: {exc}"
        ) from exc

    registration = adapter.get("registration")
    heartbeat_request = adapter.get("heartbeat_request")
    command = adapter.get("command")
    decisions = adapter.get("decisions")
    collection = adapter.get("collection")
    safety = adapter.get("safety")
    if not all(
        isinstance(value, dict)
        for value in (registration, heartbeat_request, command, collection, safety)
    ) or not isinstance(decisions, list):
        raise RatEmulationEvidenceBuildError(
            "TLS MessagePack adapter_resultのobject/list構造が不正です"
        )
    _require_exact_keys(
        registration,
        {
            "packet_kind",
            "opcode",
            "frame_size",
            "frame_sha256",
            "decoded_size",
            "decoded_sha256",
            "synthetic",
        },
        "TLS MessagePack registration",
    )
    if (
        registration.get("packet_kind") != "registration"
        or registration.get("opcode") != "ClientInfo"
        or registration.get("synthetic") is not True
    ):
        raise RatEmulationEvidenceBuildError(
            "registrationがreview済み合成ClientInfoではありません"
        )
    registration_size, _registration_sha256 = _validate_tls_wire_metadata(
        registration,
        "TLS MessagePack registration",
        maximum_wire_bytes=int(profile["limits"]["maximum_frame_bytes"]),
        maximum_decoded_bytes=int(profile["limits"]["maximum_outbound_bytes"]),
    )

    _require_exact_keys(
        heartbeat_request,
        {
            "packet_kind",
            "opcode",
            "sent",
            "synthetic",
            "frame_size",
            "frame_sha256",
            "decoded_size",
            "decoded_sha256",
        },
        "TLS MessagePack heartbeat request",
    )
    if (
        heartbeat_request.get("packet_kind") != "heartbeat_request"
        or heartbeat_request.get("opcode") != exact_profile.heartbeat_request_opcode
        or heartbeat_request.get("sent") is not True
        or heartbeat_request.get("synthetic") is not True
    ):
        raise RatEmulationEvidenceBuildError(
            "review済み固定heartbeat requestを1件送信した結果ではありません"
        )
    heartbeat_size, _heartbeat_sha256 = _validate_tls_wire_metadata(
        heartbeat_request,
        "TLS MessagePack heartbeat request",
        maximum_wire_bytes=int(profile["limits"]["maximum_frame_bytes"]),
        maximum_decoded_bytes=int(profile["limits"]["maximum_outbound_bytes"]),
    )
    if registration_size + heartbeat_size > int(profile["limits"]["maximum_outbound_bytes"]):
        raise RatEmulationEvidenceBuildError("outbound byte上限を超える公開結果です")

    _require_exact_keys(
        command,
        {
            "command",
            "opcode",
            "classification",
            "packet_kind",
            "action",
            "should_respond",
            "terminate_session",
            "frame_size",
            "frame_sha256",
            "decoded_size",
            "decoded_sha256",
        },
        "TLS MessagePack command",
    )
    if len(decisions) != 1 or decisions[0] != command:
        raise RatEmulationEvidenceBuildError(
            "TLS MessagePack commandは互換decisionを含め1件だけである必要があります"
        )
    opcode = _safe_opcode(command.get("opcode"), "TLS MessagePack command.opcode")
    packet_kind = command.get("packet_kind")
    if (
        type(opcode) is not str
        or command.get("command") != opcode
        or command.get("classification") != packet_kind
    ):
        raise RatEmulationEvidenceBuildError("command opcode/classification bindingが不正です")
    if opcode == exact_profile.heartbeat_response_opcode:
        expected_kind = "heartbeat"
    elif opcode in exact_profile.file_opcodes:
        expected_kind = "file_or_plugin"
    elif opcode in exact_profile.operation_opcodes:
        expected_kind = "operation"
    else:
        expected_kind = "unknown"
    expected_action = {
        "heartbeat": "record_heartbeat_response_and_terminate",
        "file_or_plugin": "refuse_file_or_plugin_and_terminate",
        "operation": "refuse_operation_and_terminate",
        "unknown": "terminate_unknown_command",
    }[expected_kind]
    if (
        packet_kind != expected_kind
        or command.get("action") != expected_action
        or command.get("should_respond") is not False
        or command.get("terminate_session") is not True
    ):
        raise RatEmulationEvidenceBuildError(
            "file/plugin/operation/unknownを含むcommandの無応答終了policyが不正です"
        )
    command_size, _command_sha256 = _validate_tls_wire_metadata(
        command,
        "TLS MessagePack command",
        maximum_wire_bytes=int(profile["limits"]["maximum_frame_bytes"]),
        maximum_decoded_bytes=int(profile["limits"]["maximum_inbound_bytes"]),
    )

    _require_exact_keys(
        collection,
        {"received_bytes", "read_calls", "frame_count", "command_count"},
        "TLS MessagePack collection",
    )
    if (
        collection.get("frame_count") != 1
        or collection.get("command_count") != 1
        or collection.get("received_bytes") != command_size
    ):
        raise RatEmulationEvidenceBuildError(
            "TLS MessagePack collectionは1 frame・1 commandである必要があります"
        )
    _bounded_int(
        collection.get("read_calls"),
        "TLS MessagePack collection.read_calls",
        minimum=1,
        maximum=int(profile["limits"]["maximum_inbound_read_calls"]),
    )

    required_false = {
        "sample_executed",
        "real_host_information_read",
        "real_effect_performed",
        "file_or_plugin_retained",
        "file_or_plugin_executed",
        "operation_executed",
        "secondary_network_performed",
        "arbitrary_fake_result_sent",
        "live_arbitrary_result_allowed",
        "session_continues",
    }
    _require_exact_keys(
        safety,
        {*required_false, "application_send_count"},
        "TLS MessagePack safety",
    )
    if (
        any(safety.get(field) is not False for field in required_false)
        or safety.get("application_send_count") != 2
    ):
        raise RatEmulationEvidenceBuildError(
            "合成ClientInfo/Ping以外を送信・実行しないsafety境界が不正です"
        )
    expected_status = {
        "heartbeat": "heartbeat_response_observed",
        "file_or_plugin": "file_or_plugin_refused",
        "operation": "operation_refused",
        "unknown": "unknown_command_terminated",
    }[expected_kind]
    if adapter.get("status") != expected_status:
        raise RatEmulationEvidenceBuildError("command分類とadapter statusが一致しません")


def _validate_summary_binding(
    summary: dict[str, Any],
    registry: RegistrySnapshot,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if (
        summary.get("schema_version") != 1
        or summary.get("artifact_type") != "defensive_rat_emulator_public_summary"
        or summary.get("status") != "completed"
    ):
        raise RatEmulationEvidenceBuildError("完了済みlive public summaryではありません")
    metadata = summary.get("metadata")
    adapter = summary.get("adapter_result")
    if not isinstance(metadata, dict) or not isinstance(adapter, dict):
        raise RatEmulationEvidenceBuildError("metadataまたはadapter_resultがありません")
    profile_id = metadata.get("profile_id")
    if type(profile_id) is not str or profile_id not in registry.profiles:
        raise RatEmulationEvidenceBuildError("未レビューのemulator profile IDです")
    profile = registry.profiles[profile_id]
    expected_metadata = {
        "profile_id": profile_id,
        "family": profile["family"],
        "protocol_profile_id": profile["protocol_profile_id"],
        "registry_sha256": registry.sha256,
        "protocol_profile_object_sha256": profile["protocol_profile_object_sha256"],
        "evidence_sha256": profile["evidence_sha256"],
        "sample_executed": False,
    }
    if any(metadata.get(key) != value for key, value in expected_metadata.items()):
        raise RatEmulationEvidenceBuildError(
            "公開要約とemulator profile registryのbindingが一致しません"
        )
    if adapter.get("schema_version") != 1 or adapter.get("family") != profile["family"]:
        raise RatEmulationEvidenceBuildError("adapter_resultのfamily/schemaが一致しません")
    adapter_id = profile.get("adapter_id")
    if adapter_id == "valleyrat_n520_v1":
        _validate_n520_adapter(adapter, profile)
    elif adapter_id == "tls_messagepack_rat_host":
        _validate_tls_messagepack_adapter(adapter, profile)
    else:
        raise RatEmulationEvidenceBuildError(f"未対応のadapter IDです: {adapter_id}")
    return metadata, adapter, profile


def _public_n520_commands(
    adapter: dict[str, Any],
    events: list[dict[str, Any]],
    completed_at: datetime,
) -> list[dict[str, Any]]:
    decisions = adapter.get("decisions")
    collection = adapter.get("collection")
    if not isinstance(decisions, list) or not isinstance(collection, dict):
        raise RatEmulationEvidenceBuildError("adapterのdecision/collectionが不正です")
    observed = [
        decision
        for decision in decisions
        if isinstance(decision, dict)
        and type(decision.get("command")) is int
        and decision.get("direction")
        in {"server_to_client", "unexpected_server_to_client"}
    ]
    if len(observed) > 1:
        raise RatEmulationEvidenceBuildError(
            "command単位frame hashを公開できない複数decision要約は拒否します"
        )
    if len(observed) > MAXIMUM_COMMANDS:
        raise RatEmulationEvidenceBuildError("command件数が上限を超えています")
    if not observed:
        return []
    response_size = collection.get("response_size")
    response_sha256 = collection.get("response_sha256")
    if type(response_size) is not int or not 0 < response_size <= 1024 * 1024:
        raise RatEmulationEvidenceBuildError("command response sizeが不正です")
    digest = _sha256(response_sha256, "command response SHA-256")
    decision = observed[0]
    opcode = decision["command"]
    if not 0 <= opcode <= 0xFFFFFFFF:
        raise RatEmulationEvidenceBuildError("command opcodeが不正です")
    if decision.get("should_respond") is not False or decision.get("terminate_session") is not True:
        raise RatEmulationEvidenceBuildError("未知commandへの無応答終了policyが確認できません")
    observed_at = _event_time(events, "n520_command_decision", completed_at)
    return [
        {
            "sequence": 1,
            "direction": "server_to_client",
            "observed_at_utc": observed_at.isoformat(),
            "message_kind": _safe_token(
                decision.get("classification"),
                "command classification",
            ),
            "packet_kind": _safe_token(
                decision.get("classification"),
                "command classification",
            ),
            "opcode": opcode,
            "wire_size": response_size,
            "wire_sha256": digest,
            "arguments_published": False,
            "raw_published": False,
        }
    ]


def _one_event(
    events: list[dict[str, Any]],
    event_type: str,
) -> dict[str, Any]:
    matches = [event for event in events if event.get("event_type") == event_type]
    if len(matches) != 1:
        raise RatEmulationEvidenceBuildError(
            f"TLS MessagePack summaryには{event_type}が1件必要です"
        )
    event = matches[0]
    if not isinstance(event.get("public_fields"), dict):
        raise RatEmulationEvidenceBuildError(f"{event_type}.public_fieldsが不正です")
    return event


def _validate_event_fields(
    event: dict[str, Any],
    expected: dict[str, Any],
    label: str,
) -> None:
    fields = event["public_fields"]
    if any(fields.get(key) != value for key, value in expected.items()):
        raise RatEmulationEvidenceBuildError(f"{label}とadapter_resultが一致しません")


def _validate_tls_messagepack_events(
    summary: dict[str, Any],
    adapter: dict[str, Any],
    events: list[dict[str, Any]],
) -> datetime:
    """1登録・1 Ping・1受信commandの公開event bindingを検証する。"""

    registration = adapter["registration"]
    heartbeat = adapter["heartbeat_request"]
    command = adapter["command"]
    preconnect_event = _one_event(events, "preconnect_policy_validated")
    _one_event(events, "tls_certificate_pinned")
    registration_event = _one_event(events, "registration_sent")
    heartbeat_event = _one_event(events, "heartbeat_request_sent")
    command_event = _one_event(events, "command_classified")
    terminated_event = _one_event(events, "session_terminated")
    outbound_registration = _one_event(events, "reviewed_registration_frame")
    outbound_heartbeat = _one_event(events, "reviewed_fixed_heartbeat_request_frame")
    _validate_event_fields(
        preconnect_event,
        {"single_connection": True},
        "preconnect policy event",
    )
    if any(
        event.get("event_type")
        in {"heartbeat_reply_sent", "reviewed_fixed_heartbeat_reply_frame"}
        for event in events
    ):
        raise RatEmulationEvidenceBuildError("pong/Po_ngへの追加reply送信は許可しません")

    wire_keys = (
        "packet_kind",
        "opcode",
        "frame_size",
        "frame_sha256",
        "decoded_size",
        "decoded_sha256",
        "synthetic",
    )
    _validate_event_fields(
        registration_event,
        {key: registration[key] for key in wire_keys},
        "registration event",
    )
    _validate_event_fields(
        heartbeat_event,
        {key: heartbeat[key] for key in (*wire_keys, "sent")},
        "heartbeat request event",
    )
    _validate_event_fields(
        command_event,
        {
            key: command[key]
            for key in (
                "packet_kind",
                "opcode",
                "action",
                "should_respond",
                "terminate_session",
                "frame_size",
                "frame_sha256",
                "decoded_size",
                "decoded_sha256",
            )
        },
        "command event",
    )
    _validate_event_fields(
        terminated_event,
        {"packet_kind": command["packet_kind"], "opcode": command["opcode"]},
        "session termination event",
    )
    for event, expected, label in (
        (outbound_registration, registration, "registration transport event"),
        (outbound_heartbeat, heartbeat, "heartbeat transport event"),
    ):
        if event.get("frame") != {
            "size": expected["frame_size"],
            "sha256": expected["frame_sha256"],
        }:
            raise RatEmulationEvidenceBuildError(f"{label}のwire hash/sizeが一致しません")
        _validate_event_fields(
            event,
            {
                "size": expected["frame_size"],
                "sha256": expected["frame_sha256"],
                "real_identity_sent": False,
                "synthetic": True,
            },
            label,
        )
    if summary.get("stop_reason") != adapter.get("status"):
        raise RatEmulationEvidenceBuildError("summary stop_reasonとadapter statusが一致しません")
    return _timestamp(command_event.get("captured_at"), "command_classified.captured_at")


def _public_tls_messagepack_command(
    adapter: dict[str, Any],
    observed_at: datetime,
) -> list[dict[str, Any]]:
    command = adapter["command"]
    packet_kind = _safe_token(command.get("packet_kind"), "command packet_kind")
    return [
        {
            "sequence": 1,
            "direction": "server_to_client",
            "observed_at_utc": observed_at.isoformat(),
            "message_kind": packet_kind,
            "packet_kind": packet_kind,
            "opcode": _safe_opcode(command.get("opcode"), "command opcode"),
            "wire_size": command["frame_size"],
            "wire_sha256": command["frame_sha256"],
            "arguments_published": False,
            "raw_published": False,
        }
    ]


def _build_session(
    summary: dict[str, Any],
    identity: SnapshotIdentity,
    plan: dict[str, Any],
    registry: RegistrySnapshot,
    protocol_profiles: dict[str, dict[str, Any]],
    *,
    reference_time: datetime,
    maximum_age: timedelta,
    archive_report: tuple[dict[str, Any], SnapshotIdentity] | None = None,
) -> dict[str, Any]:
    metadata, adapter, profile = _validate_summary_binding(summary, registry)
    target = _matching_target(plan, profile, registry, protocol_profiles)
    started = _timestamp(summary.get("started_at"), "started_at")
    completed = _timestamp(summary.get("completed_at"), "completed_at")
    duration = completed - started
    if duration.total_seconds() < 0 or duration.total_seconds() > MAXIMUM_SESSION_SECONDS:
        raise RatEmulationEvidenceBuildError("session時間が安全上限外です")
    if completed > reference_time + MAXIMUM_FUTURE_SKEW:
        raise RatEmulationEvidenceBuildError("公開要約の完了時刻が未来です")
    if reference_time - completed > maximum_age:
        raise RatEmulationEvidenceBuildError("公開要約が期限切れです")
    events = _event_list(summary)
    connection_established = _has_event(
        events,
        "preconnect_policy_validated",
        "single_connection",
    ) and any(event.get("event_type") == "tls_certificate_pinned" for event in events)
    adapter_id = profile["adapter_id"]
    if adapter_id == "valleyrat_n520_v1":
        handshake_confirmed = _has_event(
            events,
            "n520_handshake_validated",
            "header_matches",
        )
        registration_accepted: bool | None = None
        commands = _public_n520_commands(adapter, events, completed)
        heartbeat_count = 0
    elif adapter_id == "tls_messagepack_rat_host":
        _reject_forbidden_public_keys(summary, "TLS MessagePack public summary")
        if not connection_established:
            raise RatEmulationEvidenceBuildError(
                "TLS接続とcertificate pinを確認できない公開要約です"
            )
        observed_at = _validate_tls_messagepack_events(summary, adapter, events)
        handshake_confirmed = True
        registration_accepted = True
        commands = _public_tls_messagepack_command(adapter, observed_at)
        heartbeat_count = int(adapter["command"]["packet_kind"] == "heartbeat")
    else:
        raise RatEmulationEvidenceBuildError(f"未対応のadapter IDです: {adapter_id}")
    transcript_root = _sha256(
        summary.get("transcript_root_sha256"),
        "transcript root SHA-256",
    )
    session_id = summary.get("session_id")
    if type(session_id) is not str or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
        session_id,
    ):
        raise RatEmulationEvidenceBuildError("session_idが不正です")
    private_evidence: dict[str, Any] = {
        "archived": False,
        "transcript_root_sha256": transcript_root,
    }
    if archive_report is not None:
        report, report_identity = archive_report
        private_evidence = {
            **_validate_archive_report(report, report_identity, session_id),
            "transcript_root_sha256": transcript_root,
        }
    return {
        "schema_version": 1,
        "session_id": session_id,
        "family": target["family"],
        "host": target["host"],
        "port": target["port"],
        "protocol": target.get("protocol", "tcp"),
        "transport": target.get("transport", "direct"),
        "http_path": target.get("http_path"),
        "protocol_profile_id": target["protocol_profile_id"],
        "protocol_profile_registry_source": target["protocol_profile_registry_source"],
        "protocol_profile_registry_sha256": target["protocol_profile_registry_sha256"],
        "emulator_profile_id": metadata["profile_id"],
        "emulator_profile_registry_source": registry.source,
        "emulator_profile_registry_sha256": registry.sha256,
        "sample_sha256s": list(profile["sample_sha256s"]),
        "source_summary_snapshot": identity.public_dict(),
        "started_at_utc": started.isoformat(),
        "ended_at_utc": completed.isoformat(),
        "status": _safe_token(adapter.get("status"), "adapter status"),
        "connection_established": connection_established,
        "handshake_confirmed": handshake_confirmed,
        "registration_accepted": registration_accepted,
        "c2_confirmed": connection_established and handshake_confirmed,
        "heartbeat_count": heartbeat_count,
        "commands": commands,
        "synthetic_replies": [],
        "safety": {field: False for field in REQUIRED_FALSE_SAFETY_FIELDS},
        "private_evidence": private_evidence,
    }


def build_evidence(
    inputs: Iterable[SummaryInput],
    plan: dict[str, Any],
    *,
    archive_reports: Iterable[ArchiveReportInput] | None = None,
    reference_time: datetime | None = None,
    maximum_summary_age_hours: float = DEFAULT_MAXIMUM_SUMMARY_AGE_HOURS,
) -> dict[str, Any]:
    """公開要約群を検証し、監視pipelineが直接読めるsidecarを返す。"""

    if (
        isinstance(maximum_summary_age_hours, bool)
        or not isinstance(maximum_summary_age_hours, (int, float))
        or not math.isfinite(maximum_summary_age_hours)
        or maximum_summary_age_hours <= 0
    ):
        raise RatEmulationEvidenceBuildError("maximum_summary_age_hoursは正数が必要です")
    now = reference_time or datetime.now(UTC)
    if now.tzinfo is None:
        raise RatEmulationEvidenceBuildError("reference_timeにはtimezoneが必要です")
    now = now.astimezone(UTC)
    try:
        registry = load_emulator_registry()
        protocol_profiles = load_protocol_profiles(
            expected_sha256=registry.protocol_profile_registry["sha256"]
        )
    except (
        OSError,
        ProtocolProfileError,
        RatEmulatorProfileError,
        ValueError,
    ) as exc:
        raise RatEmulationEvidenceBuildError(
            f"emulator profile registryを検証できません: {exc}"
        ) from exc
    if plan.get("schema_version") != 1 or not isinstance(plan.get("targets"), list):
        raise RatEmulationEvidenceBuildError("監視plan schemaが不正です")
    if plan.get("protocol_profile_registry") != registry.protocol_profile_registry:
        raise RatEmulationEvidenceBuildError(
            "監視planとemulator registryのprotocol registry pinが一致しません"
        )
    values = list(inputs)
    if not 1 <= len(values) <= MAXIMUM_SESSIONS:
        raise RatEmulationEvidenceBuildError("公開要約は1件以上256件以下にしてください")
    report_values = None if archive_reports is None else list(archive_reports)
    if report_values is not None and len(report_values) != len(values):
        raise RatEmulationEvidenceBuildError(
            "archive reportは省略するか公開要約と同じ件数・順序で指定してください"
        )
    maximum_age = timedelta(hours=maximum_summary_age_hours)
    sessions: list[dict[str, Any]] = []
    seen_input_hashes: set[str] = set()
    seen_session_ids: set[str] = set()
    seen_transcript_roots: set[str] = set()
    seen_archive_report_hashes: set[str] = set()
    seen_archive_hashes: set[str] = set()
    seen_object_uris: set[str] = set()
    for index, item in enumerate(values):
        summary, identity = _read_json_snapshot(
            item.path,
            item.expected_sha256,
            MAXIMUM_EVIDENCE_BYTES,
            "RAT emulator public summary",
        )
        if identity.sha256 in seen_input_hashes:
            raise RatEmulationEvidenceBuildError("同一public summaryが重複しています")
        archive_report: tuple[dict[str, Any], SnapshotIdentity] | None = None
        if report_values is not None:
            report_input = report_values[index]
            report, report_identity = _read_json_snapshot(
                report_input.path,
                report_input.expected_sha256,
                MAXIMUM_ARCHIVE_REPORT_BYTES,
                "analysis datastore archive report",
            )
            if report_identity.sha256 in seen_archive_report_hashes:
                raise RatEmulationEvidenceBuildError("archive reportが重複しています")
            seen_archive_report_hashes.add(report_identity.sha256)
            archive_report = (report, report_identity)
        session = _build_session(
            summary,
            identity,
            plan,
            registry,
            protocol_profiles,
            reference_time=now,
            maximum_age=maximum_age,
            archive_report=archive_report,
        )
        transcript_root = session["private_evidence"]["transcript_root_sha256"]
        if session["session_id"] in seen_session_ids:
            raise RatEmulationEvidenceBuildError("session_idが重複しています")
        if transcript_root in seen_transcript_roots:
            raise RatEmulationEvidenceBuildError("transcript root hashが重複しています")
        private_evidence = session["private_evidence"]
        if private_evidence["archived"]:
            archive_hash = private_evidence["archive_sha256"]
            object_uri = private_evidence["object_uri"]
            if archive_hash in seen_archive_hashes or object_uri in seen_object_uris:
                raise RatEmulationEvidenceBuildError(
                    "archive objectまたはarchive SHA-256が重複しています"
                )
            seen_archive_hashes.add(archive_hash)
            seen_object_uris.add(object_uri)
        seen_input_hashes.add(identity.sha256)
        seen_session_ids.add(session["session_id"])
        seen_transcript_roots.add(transcript_root)
        sessions.append(session)
    sessions.sort(key=lambda value: (value["ended_at_utc"], value["session_id"]))
    result = {
        "schema_version": 1,
        "generated_at_utc": now.isoformat(),
        "protocol_profile_registry": dict(registry.protocol_profile_registry),
        "emulator_profile_registry": {
            "source": registry.source,
            "sha256": registry.sha256,
        },
        "sessions": sessions,
    }
    serialized_size = len(
        (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    )
    if serialized_size > MAXIMUM_EVIDENCE_BYTES:
        raise RatEmulationEvidenceBuildError("sidecarが許可size上限を超えています")
    return result


def write_evidence(
    output: Path,
    evidence: dict[str, Any],
    *,
    input_paths: Iterable[Path],
) -> None:
    """入力との同一pathと既存出力を拒否し、sidecarをfsync付きで新規作成する。"""

    destination = ensure_new_output(output, input_paths)
    write_new_json(destination, evidence)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--targets", type=Path, required=True, help="C2監視plan JSON")
    parser.add_argument(
        "--targets-sha256",
        required=True,
        help="監視plan入力の期待SHA-256",
    )
    parser.add_argument(
        "--public-summary",
        type=Path,
        action="append",
        required=True,
        help="RAT emulator公開要約。複数回指定できます",
    )
    parser.add_argument(
        "--public-summary-sha256",
        action="append",
        required=True,
        help="同じ順序の公開要約expected SHA-256。複数回指定できます",
    )
    parser.add_argument(
        "--archive-report",
        type=Path,
        action="append",
        help=(
            "同じ順序のanalysis datastore verified upload report。"
            "全件省略するか公開要約と同数指定します"
        ),
    )
    parser.add_argument(
        "--archive-report-sha256",
        action="append",
        help=(
            "同じ順序のarchive report expected SHA-256。"
            "--archive-reportと同数指定します"
        ),
    )
    parser.add_argument("--output", type=Path, required=True, help="新規sidecar出力path")
    parser.add_argument(
        "--maximum-summary-age-hours",
        type=float,
        default=DEFAULT_MAXIMUM_SUMMARY_AGE_HOURS,
        help="完了時刻から許容する最大経過時間。既定は24時間",
    )
    args = parser.parse_args()
    if len(args.public_summary) != len(args.public_summary_sha256):
        parser.error("--public-summaryと--public-summary-sha256の件数を一致させてください")
    if (args.archive_report is None) != (args.archive_report_sha256 is None):
        parser.error("--archive-reportと--archive-report-sha256は同時に指定してください")
    if args.archive_report is not None and (
        len(args.archive_report) != len(args.archive_report_sha256)
        or len(args.archive_report) != len(args.public_summary)
    ):
        parser.error(
            "archive reportとSHA-256は公開要約と同じ件数・順序で指定してください"
        )
    try:
        plan = load_monitoring_plan(args.targets, args.targets_sha256)
        inputs = [
            SummaryInput(path=path, expected_sha256=digest)
            for path, digest in zip(
                args.public_summary,
                args.public_summary_sha256,
                strict=True,
            )
        ]
        archive_inputs = (
            None
            if args.archive_report is None
            else [
                ArchiveReportInput(path=path, expected_sha256=digest)
                for path, digest in zip(
                    args.archive_report,
                    args.archive_report_sha256,
                    strict=True,
                )
            ]
        )
        result = build_evidence(
            inputs,
            plan,
            archive_reports=archive_inputs,
            maximum_summary_age_hours=args.maximum_summary_age_hours,
        )
        write_evidence(
            args.output,
            result,
            input_paths=[
                args.targets,
                *args.public_summary,
                *(args.archive_report or []),
            ],
        )
        output_identity = read_bounded_snapshot(
            args.output,
            MAXIMUM_EVIDENCE_BYTES,
        ).identity.public_dict()
    except (OSError, RatEmulationEvidenceBuildError, ValueError) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "session_count": len(result["sessions"]),
                "output": str(args.output),
                "output_snapshot": output_identity,
                "raw_transcript_published": False,
                "task_executed": False,
                "real_effect_performed": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
