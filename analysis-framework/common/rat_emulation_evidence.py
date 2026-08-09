#!/usr/bin/env python3
"""RAT emulatorの外部session証拠を検証し、公開可能な要約だけを返す。"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from immutable_snapshot import decode_strict_json, read_bounded_snapshot
from c2_protocol_probe_profiles import (
    ProtocolProfileError,
    load_profiles as load_protocol_profiles,
)
from rat_emulator_profiles import (
    RatEmulatorProfileError,
    RegistrySnapshot,
    load_registry as load_emulator_registry,
)


MAXIMUM_EVIDENCE_BYTES = 4 * 1024 * 1024
MAXIMUM_SESSIONS = 256
MAXIMUM_SESSION_SECONDS = 300.0
MAXIMUM_COMMANDS_PER_SESSION = 64
MAXIMUM_REPLIES_PER_SESSION = 64
MAXIMUM_WIRE_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SAFE_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,63}")
SAFE_SESSION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
SAFE_OPCODE_RE = re.compile(r"(?:0x[0-9a-f]{1,8}|[A-Za-z0-9][A-Za-z0-9_.:-]{0,31})")
SAFE_DATASTORE_TARGET_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
DATASTORE_BUCKET = "malware-analysis-datastore-720232834682"
SAFE_OBJECT_URI_RE = re.compile(
    rf"s3://{re.escape(DATASTORE_BUCKET)}/[A-Za-z0-9][A-Za-z0-9._/-]{{0,895}}"
)

REQUIRED_FALSE_SAFETY_FIELDS = (
    "raw_transcript_published",
    "command_content_published",
    "token_published",
    "url_published",
    "payload_published",
    "task_executed",
    "real_effect_performed",
    "payload_download_attempted",
    "followup_network_attempted",
    "victim_metadata_sent",
)


class RatEmulationEvidenceError(ValueError):
    """sidecar、plan binding、または公開境界が不正であることを示す。"""


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or not SHA256_RE.fullmatch(value.casefold()):
        raise RatEmulationEvidenceError(f"{label}は小文字64桁SHA-256である必要があります")
    return value.casefold()


def _safe_token(value: object, label: str) -> str:
    if type(value) is not str or not SAFE_TOKEN_RE.fullmatch(value):
        raise RatEmulationEvidenceError(f"{label}は公開可能な正規化tokenではありません")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or not value:
        raise RatEmulationEvidenceError(f"{label}にはtimezone付き日時が必要です")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RatEmulationEvidenceError(f"{label}を解釈できません") from exc
    if parsed.tzinfo is None:
        raise RatEmulationEvidenceError(f"{label}にはtimezoneが必要です")
    return parsed.astimezone(UTC)


def _bounded_int(value: object, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RatEmulationEvidenceError(
            f"{label}は{minimum}以上{maximum}以下の整数である必要があります"
        )
    return value


def _safe_opcode(value: object, label: str) -> int | str:
    if type(value) is int:
        if not 0 <= value <= 0xFFFFFFFF:
            raise RatEmulationEvidenceError(f"{label}が32 bit範囲外です")
        return value
    if type(value) is str and SAFE_OPCODE_RE.fullmatch(value):
        return value
    raise RatEmulationEvidenceError(f"{label}が公開可能な形式ではありません")


def _safe_object_uri(value: object, target: str, manifest_sha256: str) -> str:
    if type(value) is not str or SAFE_OBJECT_URI_RE.fullmatch(value) is None:
        raise RatEmulationEvidenceError(
            "private_evidence.object_uriが許可されたS3 object URIではありません"
        )
    key = value.removeprefix(f"s3://{DATASTORE_BUCKET}/")
    parts = key.split("/")
    if (
        any(part in {"", ".", ".."} for part in parts)
        or target not in parts
        or not parts[-1].startswith(f"{target}-")
        or not parts[-1].endswith(f"-{manifest_sha256[:12]}.zip")
    ):
        raise RatEmulationEvidenceError(
            "private_evidence.object_uriがdatastore targetへbindingされていません"
        )
    return value


def _endpoint_key(value: dict[str, Any]) -> str:
    host = str(value.get("host") or "").casefold().rstrip(".")
    port = int(value.get("port") or 0)
    protocol = str(value.get("protocol") or "tcp").casefold()
    transport = str(value.get("transport") or "direct").casefold()
    path = str(value.get("http_path") or "")
    return "|".join((host, str(port), protocol, transport, path))


def _sanitize_command(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RatEmulationEvidenceError("commandはobjectである必要があります")
    sequence = _bounded_int(
        value.get("sequence"),
        "command.sequence",
        minimum=1,
        maximum=MAXIMUM_COMMANDS_PER_SESSION,
    )
    direction = value.get("direction")
    if direction != "server_to_client":
        raise RatEmulationEvidenceError("公開commandはserver_to_clientに限定します")
    public_opcode = _safe_opcode(value.get("opcode"), "command.opcode")
    observed_at = _timestamp(value.get("observed_at_utc"), "command.observed_at_utc")
    if value.get("arguments_published") is not False or value.get("raw_published") is not False:
        raise RatEmulationEvidenceError("command本文・引数・raw byteの公開は禁止します")
    message_kind = _safe_token(value.get("message_kind"), "command.message_kind")
    packet_kind = _safe_token(
        value.get("packet_kind", message_kind),
        "command.packet_kind",
    )
    return {
        "sequence": sequence,
        "direction": direction,
        "observed_at_utc": observed_at.isoformat(),
        "message_kind": message_kind,
        "packet_kind": packet_kind,
        "opcode": public_opcode,
        "wire_size": _bounded_int(
            value.get("wire_size"),
            "command.wire_size",
            minimum=0,
            maximum=MAXIMUM_WIRE_BYTES,
        ),
        "wire_sha256": _sha256(value.get("wire_sha256"), "command.wire_sha256"),
        "arguments_published": False,
        "raw_published": False,
    }


def _sanitize_reply(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RatEmulationEvidenceError("synthetic replyはobjectである必要があります")
    sequence = _bounded_int(
        value.get("sequence"),
        "synthetic_reply.sequence",
        minimum=1,
        maximum=MAXIMUM_REPLIES_PER_SESSION,
    )
    if value.get("real_effect_performed") is not False or value.get("raw_published") is not False:
        raise RatEmulationEvidenceError("合成応答は実作用なし・raw非公開である必要があります")
    sent_at = _timestamp(value.get("sent_at_utc"), "synthetic_reply.sent_at_utc")
    result = {
        "sequence": sequence,
        "sent_at_utc": sent_at.isoformat(),
        "reply_kind": _safe_token(value.get("reply_kind"), "synthetic_reply.reply_kind"),
        "template_id": _safe_token(value.get("template_id"), "synthetic_reply.template_id"),
        "wire_size": _bounded_int(
            value.get("wire_size"),
            "synthetic_reply.wire_size",
            minimum=0,
            maximum=MAXIMUM_WIRE_BYTES,
        ),
        "wire_sha256": _sha256(
            value.get("wire_sha256"),
            "synthetic_reply.wire_sha256",
        ),
        "synthetic_reply_sent": True,
        "task_executed": False,
        "real_effect_performed": False,
        "raw_published": False,
    }
    packet_kind = value.get("packet_kind")
    opcode = value.get("opcode")
    if packet_kind is not None or opcode is not None:
        result["packet_kind"] = _safe_token(
            packet_kind,
            "synthetic_reply.packet_kind",
        )
        result["opcode"] = _safe_opcode(opcode, "synthetic_reply.opcode")
    return result


def _sanitize_private_evidence(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RatEmulationEvidenceError("private_evidenceはobjectである必要があります")
    archived = value.get("archived")
    if type(archived) is not bool:
        raise RatEmulationEvidenceError("private_evidence.archivedはboolである必要があります")
    result: dict[str, Any] = {
        "archived": archived,
        "transcript_root_sha256": _sha256(
            value.get("transcript_root_sha256"),
            "private_evidence.transcript_root_sha256",
        ),
    }
    if not archived:
        return result
    target = value.get("datastore_target")
    if type(target) is not str or SAFE_DATASTORE_TARGET_RE.fullmatch(target) is None:
        raise RatEmulationEvidenceError(
            "private_evidence.datastore_targetが公開可能なtargetではありません"
        )
    result.update(
        {
            "datastore_target": target,
            "archive_sha256": _sha256(
                value.get("archive_sha256"),
                "private_evidence.archive_sha256",
            ),
            "manifest_sha256": _sha256(
                value.get("manifest_sha256"),
                "private_evidence.manifest_sha256",
            ),
        }
    )
    object_uri = value.get("object_uri")
    archive_report_sha256 = value.get("archive_report_sha256")
    server_side_encryption = value.get("server_side_encryption")
    extended_values = (object_uri, archive_report_sha256, server_side_encryption)
    if any(item is not None for item in extended_values):
        if any(item is None for item in extended_values):
            raise RatEmulationEvidenceError(
                "private_evidenceのS3参照fieldは3項目すべてが必要です"
            )
        if server_side_encryption != "AES256":
            raise RatEmulationEvidenceError(
                "private_evidence.server_side_encryptionはAES256である必要があります"
            )
        result.update(
            {
                "object_uri": _safe_object_uri(
                    object_uri,
                    target,
                    result["manifest_sha256"],
                ),
                "archive_report_sha256": _sha256(
                    archive_report_sha256,
                    "private_evidence.archive_report_sha256",
                ),
                "server_side_encryption": "AES256",
            }
        )
    return result


def _sanitize_source_snapshot(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RatEmulationEvidenceError("source_summary_snapshotが必要です")
    return {
        "size": _bounded_int(
            value.get("size"),
            "source_summary_snapshot.size",
            minimum=1,
            maximum=MAXIMUM_EVIDENCE_BYTES,
        ),
        "sha256": _sha256(
            value.get("sha256"),
            "source_summary_snapshot.sha256",
        ),
        "link_count": _bounded_int(
            value.get("link_count"),
            "source_summary_snapshot.link_count",
            minimum=1,
            maximum=1,
        ),
    }


def _sanitize_session(
    value: object,
    target: dict[str, Any],
    emulator_registry: RegistrySnapshot,
    protocol_profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise RatEmulationEvidenceError("各sessionにはschema_version=1が必要です")
    session_id = value.get("session_id")
    if type(session_id) is not str or not SAFE_SESSION_ID_RE.fullmatch(session_id):
        raise RatEmulationEvidenceError("session_idが不正です")
    started = _timestamp(value.get("started_at_utc"), "started_at_utc")
    ended = _timestamp(value.get("ended_at_utc"), "ended_at_utc")
    duration = (ended - started).total_seconds()
    if not 0 <= duration <= MAXIMUM_SESSION_SECONDS:
        raise RatEmulationEvidenceError("session時間が公開sidecarの上限を超えています")

    commands = value.get("commands")
    replies = value.get("synthetic_replies")
    if not isinstance(commands, list) or len(commands) > MAXIMUM_COMMANDS_PER_SESSION:
        raise RatEmulationEvidenceError("commands件数が不正です")
    if not isinstance(replies, list) or len(replies) > MAXIMUM_REPLIES_PER_SESSION:
        raise RatEmulationEvidenceError("synthetic_replies件数が不正です")
    public_commands = sorted((_sanitize_command(item) for item in commands), key=lambda item: item["sequence"])
    public_replies = sorted((_sanitize_reply(item) for item in replies), key=lambda item: item["sequence"])
    if len({item["sequence"] for item in public_commands}) != len(public_commands):
        raise RatEmulationEvidenceError("command.sequenceが重複しています")
    if len({item["sequence"] for item in public_replies}) != len(public_replies):
        raise RatEmulationEvidenceError("synthetic_reply.sequenceが重複しています")

    safety = value.get("safety")
    if not isinstance(safety, dict):
        raise RatEmulationEvidenceError("session.safetyが必要です")
    for field in REQUIRED_FALSE_SAFETY_FIELDS:
        if safety.get(field) is not False:
            raise RatEmulationEvidenceError(f"session.safety.{field}=falseが必要です")

    expected_samples = sorted(target.get("sample_sha256s") or [])
    observed_samples = value.get("sample_sha256s")
    if not isinstance(observed_samples, list) or sorted(observed_samples) != expected_samples:
        raise RatEmulationEvidenceError("sessionとtargetのsample_sha256sが一致しません")
    if any(type(item) is not str or not SHA256_RE.fullmatch(item) for item in observed_samples):
        raise RatEmulationEvidenceError("session.sample_sha256sが不正です")

    emulator_profile_id = value.get("emulator_profile_id")
    if type(emulator_profile_id) is not str:
        raise RatEmulationEvidenceError("session.emulator_profile_idが必要です")
    emulator_profile = emulator_registry.profiles.get(emulator_profile_id)
    if emulator_profile is None:
        raise RatEmulationEvidenceError("未レビューのemulator profileです")
    protocol_profile = protocol_profiles.get(emulator_profile["protocol_profile_id"])
    if protocol_profile is None:
        raise RatEmulationEvidenceError("review済みprotocol profileが見つかりません")
    if (
        emulator_profile.get("family") != target.get("family")
        or emulator_profile.get("host") != target.get("host")
        or emulator_profile.get("port") != target.get("port")
        or emulator_profile.get("transport") != "tls"
        or target.get("transport") != "direct"
        or target.get("protocol") != protocol_profile.get("protocol")
        or target.get("http_path") is not None
        or emulator_profile.get("protocol_profile_id")
        != target.get("protocol_profile_id")
        or emulator_profile.get("sample_sha256s") != expected_samples
    ):
        raise RatEmulationEvidenceError(
            "emulator profileと監視targetのendpoint/family/profile/sample bindingが一致しません"
        )

    expected_binding = {
        "family": target.get("family"),
        "host": target.get("host"),
        "port": target.get("port"),
        "protocol": target.get("protocol", "tcp"),
        "transport": target.get("transport", "direct"),
        "http_path": target.get("http_path"),
        "protocol_profile_id": target.get("protocol_profile_id"),
        "protocol_profile_registry_source": target.get(
            "protocol_profile_registry_source"
        ),
        "protocol_profile_registry_sha256": target.get(
            "protocol_profile_registry_sha256"
        ),
        "emulator_profile_id": emulator_profile_id,
        "emulator_profile_registry_source": emulator_registry.source,
        "emulator_profile_registry_sha256": emulator_registry.sha256,
    }
    observed_binding = {
        "family": value.get("family"),
        "host": value.get("host"),
        "port": value.get("port"),
        "protocol": value.get("protocol"),
        "transport": value.get("transport"),
        "http_path": value.get("http_path"),
        "protocol_profile_id": value.get("protocol_profile_id"),
        "protocol_profile_registry_source": value.get(
            "protocol_profile_registry_source"
        ),
        "protocol_profile_registry_sha256": value.get(
            "protocol_profile_registry_sha256"
        ),
        "emulator_profile_id": value.get("emulator_profile_id"),
        "emulator_profile_registry_source": value.get(
            "emulator_profile_registry_source"
        ),
        "emulator_profile_registry_sha256": value.get(
            "emulator_profile_registry_sha256"
        ),
    }
    if observed_binding != expected_binding:
        raise RatEmulationEvidenceError("sessionのendpoint/family/profile/registry pinがtargetと一致しません")
    if not expected_binding["protocol_profile_id"]:
        raise RatEmulationEvidenceError("RAT emulationはreview済みprotocol profile対象に限定します")
    _sha256(
        expected_binding["protocol_profile_registry_sha256"],
        "protocol_profile_registry_sha256",
    )

    boolean_fields = (
        "connection_established",
        "handshake_confirmed",
        "c2_confirmed",
    )
    if any(type(value.get(field)) is not bool for field in boolean_fields):
        raise RatEmulationEvidenceError("sessionの接続・handshake・C2確認flagはboolが必要です")
    registration = value.get("registration_accepted")
    if registration is not None and type(registration) is not bool:
        raise RatEmulationEvidenceError("registration_acceptedはboolまたはnullが必要です")

    private_evidence = _sanitize_private_evidence(value.get("private_evidence"))
    result = {
        "schema_version": 1,
        "session_id": session_id,
        **expected_binding,
        "sample_sha256s": expected_samples,
        "source_summary_snapshot": _sanitize_source_snapshot(
            value.get("source_summary_snapshot")
        ),
        "started_at_utc": started.isoformat(),
        "ended_at_utc": ended.isoformat(),
        "duration_ms": round(duration * 1000, 3),
        "status": _safe_token(value.get("status"), "session.status"),
        "connection_established": value["connection_established"],
        "handshake_confirmed": value["handshake_confirmed"],
        "registration_accepted": registration,
        "c2_confirmed": value["c2_confirmed"],
        "heartbeat_count": _bounded_int(
            value.get("heartbeat_count"),
            "heartbeat_count",
            minimum=0,
            maximum=1024,
        ),
        "commands": public_commands,
        "command_count": len(public_commands),
        "synthetic_replies": public_replies,
        "synthetic_reply_count": len(public_replies),
        "synthetic_reply_sent": bool(public_replies),
        "safety": {field: False for field in REQUIRED_FALSE_SAFETY_FIELDS},
    }
    if private_evidence is not None:
        result["private_evidence"] = private_evidence
    return result


def load_and_validate(
    path: Path,
    expected_sha256: str,
    plan: dict[str, Any],
    *,
    maximum_bytes: int = MAXIMUM_EVIDENCE_BYTES,
) -> dict[str, Any]:
    """sidecarを不変snapshotとして読み、planへ完全一致する公開表現を返す。"""

    expected_digest = _sha256(expected_sha256, "rat emulation evidence expected SHA-256")
    snapshot = read_bounded_snapshot(path, maximum_bytes)
    if snapshot.identity.sha256 != expected_digest:
        raise RatEmulationEvidenceError("RAT emulation evidence SHA-256 pinが一致しません")
    try:
        payload = decode_strict_json(snapshot.data)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulationEvidenceError(f"RAT emulation evidence JSONが不正です: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RatEmulationEvidenceError("RAT emulation evidenceにはschema_version=1が必要です")
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise RatEmulationEvidenceError("監視planにはschema_version=1が必要です")
    targets = plan.get("targets")
    if not isinstance(targets, list):
        raise RatEmulationEvidenceError("監視plan.targetsはlistである必要があります")
    by_endpoint = {
        _endpoint_key(target): target for target in targets if isinstance(target, dict)
    }
    sessions = payload.get("sessions")
    if not isinstance(sessions, list) or not 1 <= len(sessions) <= MAXIMUM_SESSIONS:
        raise RatEmulationEvidenceError("sessionsは1件以上256件以下である必要があります")

    plan_registry = plan.get("protocol_profile_registry")
    observed_registry = payload.get("protocol_profile_registry")
    if not isinstance(plan_registry, dict) or observed_registry != plan_registry:
        raise RatEmulationEvidenceError("sidecarとplanのprotocol profile registry pinが一致しません")
    registry = {
        "source": str(plan_registry.get("source") or ""),
        "sha256": _sha256(plan_registry.get("sha256"), "protocol profile registry SHA-256"),
    }
    if observed_registry != registry:
        raise RatEmulationEvidenceError("protocol profile registryに未知fieldまたは非正規値があります")

    observed_emulator_registry = payload.get("emulator_profile_registry")
    if not isinstance(observed_emulator_registry, dict) or set(
        observed_emulator_registry
    ) != {"source", "sha256"}:
        raise RatEmulationEvidenceError(
            "emulator_profile_registryにはsourceとsha256が必要です"
        )
    try:
        emulator_registry = load_emulator_registry(
            expected_sha256=_sha256(
                observed_emulator_registry.get("sha256"),
                "emulator profile registry SHA-256",
            )
        )
        protocol_profiles = load_protocol_profiles(
            expected_sha256=registry["sha256"]
        )
    except (
        OSError,
        ProtocolProfileError,
        RatEmulatorProfileError,
        ValueError,
    ) as exc:
        raise RatEmulationEvidenceError(
            f"emulator profile registryを検証できません: {exc}"
        ) from exc
    emulator_registry_pin = {
        "source": emulator_registry.source,
        "sha256": emulator_registry.sha256,
    }
    if observed_emulator_registry != emulator_registry_pin:
        raise RatEmulationEvidenceError(
            "emulator profile registry source/SHA-256 pinが一致しません"
        )
    if emulator_registry.protocol_profile_registry != registry:
        raise RatEmulationEvidenceError(
            "emulator registryと監視planのprotocol registry pinが一致しません"
        )

    generated_at = _timestamp(payload.get("generated_at_utc"), "generated_at_utc")
    public_sessions: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for raw_session in sessions:
        if not isinstance(raw_session, dict):
            raise RatEmulationEvidenceError("sessionはobjectである必要があります")
        target = by_endpoint.get(_endpoint_key(raw_session))
        if target is None:
            raise RatEmulationEvidenceError("sidecarに監視plan外のendpointがあります")
        session = _sanitize_session(
            raw_session,
            target,
            emulator_registry,
            protocol_profiles,
        )
        if session["session_id"] in seen_ids:
            raise RatEmulationEvidenceError("session_idが重複しています")
        seen_ids.add(session["session_id"])
        public_sessions.append(session)

    public_sessions.sort(key=lambda item: (item["ended_at_utc"], item["session_id"]))
    return {
        "schema_version": 1,
        "generated_at_utc": generated_at.isoformat(),
        "protocol_profile_registry": registry,
        "emulator_profile_registry": emulator_registry_pin,
        "source_snapshot": snapshot.identity.public_dict(),
        "sessions": public_sessions,
    }


def canonical_public_bytes(evidence: dict[str, Any]) -> bytes:
    """公開sidecarの決定的なUTF-8 JSON表現を返す。"""

    return (
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def public_sha256(evidence: dict[str, Any]) -> str:
    """公開sidecar自体のSHA-256を返す。"""

    return hashlib.sha256(canonical_public_bytes(evidence)).hexdigest()


def attach_sessions(
    monitoring: dict[str, Any],
    evidence: dict[str, Any],
    *,
    evidence_source: str,
    evidence_sha256: str,
) -> dict[str, Any]:
    """検証済みsessionのallowlist要約を対応endpointへ結合する。"""

    digest = _sha256(evidence_sha256, "公開RAT emulation evidence SHA-256")
    results = monitoring.get("results")
    if not isinstance(results, list):
        raise RatEmulationEvidenceError("monitoring.resultsはlistである必要があります")
    entries = {
        _endpoint_key(entry): entry for entry in results if isinstance(entry, dict)
    }
    grouped: dict[str, list[dict[str, Any]]] = {}
    for session in evidence.get("sessions", []):
        key = _endpoint_key(session)
        entry = entries.get(key)
        if entry is None:
            raise RatEmulationEvidenceError("monitoring resultに対応しないsessionがあります")
        if (
            entry.get("family") != session.get("family")
            or entry.get("protocol_profile_id") != session.get("protocol_profile_id")
        ):
            raise RatEmulationEvidenceError("monitoring resultとsession bindingが一致しません")
        grouped.setdefault(key, []).append(session)

    total_commands = 0
    total_replies = 0
    confirmed_sessions = 0
    for key, sessions in grouped.items():
        commands = [
            {"session_id": session["session_id"], **command}
            for session in sessions
            for command in session["commands"]
        ]
        replies = [
            {"session_id": session["session_id"], **reply}
            for session in sessions
            for reply in session["synthetic_replies"]
        ]
        status_counts = Counter(session["status"] for session in sessions)
        fingerprints = sorted({command["wire_sha256"] for command in commands})
        confirmed = sum(bool(session["c2_confirmed"]) for session in sessions)
        total_commands += len(commands)
        total_replies += len(replies)
        confirmed_sessions += confirmed
        entries[key]["rat_emulation"] = {
            "schema_version": 1,
            "session_count": len(sessions),
            "latest_session_at_utc": max(session["ended_at_utc"] for session in sessions),
            "connection_established_count": sum(
                bool(session["connection_established"]) for session in sessions
            ),
            "handshake_confirmed_count": sum(
                bool(session["handshake_confirmed"]) for session in sessions
            ),
            "c2_confirmed_session_count": confirmed,
            "command_count": len(commands),
            "unique_command_fingerprint_count": len(fingerprints),
            "command_fingerprints": commands,
            "synthetic_reply_count": len(replies),
            "synthetic_reply_sent": bool(replies),
            "synthetic_replies": replies,
            "status_counts": dict(sorted(status_counts.items())),
            "task_executed": False,
            "real_effect_performed": False,
            "payload_download_attempted": False,
            "followup_network_attempted": False,
            "raw_transcript_published": False,
            "evidence": {
                "source": evidence_source,
                "sha256": digest,
            },
        }

    summary = {
        "schema_version": 1,
        "evidence_source": evidence_source,
        "evidence_sha256": digest,
        "session_count": sum(len(values) for values in grouped.values()),
        "endpoint_count": len(grouped),
        "c2_confirmed_session_count": confirmed_sessions,
        "command_observation_count": total_commands,
        "synthetic_reply_count": total_replies,
        "synthetic_reply_sent": bool(total_replies),
        "task_executed": False,
        "real_effect_performed": False,
        "payload_download_attempted": False,
        "followup_network_attempted": False,
        "raw_transcript_published": False,
    }
    monitoring["rat_emulation_summary"] = summary
    policy = monitoring.setdefault("policy", {})
    policy.update(
        {
            "rat_emulation_evidence_imported": True,
            "rat_emulation_session_count": summary["session_count"],
            "rat_emulation_command_observation_count": total_commands,
            "rat_emulation_synthetic_reply_count": total_replies,
            "rat_emulation_synthetic_reply_sent": bool(total_replies),
            "rat_emulation_task_executed": False,
            "rat_emulation_real_effect_performed": False,
            "rat_emulation_raw_transcript_published": False,
        }
    )
    return monitoring


__all__ = [
    "MAXIMUM_EVIDENCE_BYTES",
    "RatEmulationEvidenceError",
    "attach_sessions",
    "canonical_public_bytes",
    "load_and_validate",
    "public_sha256",
]
