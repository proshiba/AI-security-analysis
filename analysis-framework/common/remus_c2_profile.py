#!/usr/bin/env python3
"""RemusStealerの静的設定からC2判定profileをfail-closedで生成する。

このmoduleは外部通信を行わない。受け取ったendpointと静的根拠を検証し、
受動判定用profileを常に生成する。能動登録用profileは、完全一致に必要な
設定と出典hash、安全境界がすべて揃った場合だけ生成する。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from remus_profile_evidence import (
    EVIDENCE_POINTERS,
    RemusEvidenceError,
    build_evidence_binding,
    default_repository_root,
    resolve_remus_review_trust,
    validate_remus_profile_evidence,
)
from safe_private_output import reject_existing_reparse_components, write_private_output

DEFAULT_MAX_INPUT_BYTES = 1024 * 1024
MIN_EXP = 946_684_800  # 2000-01-01T00:00:00Z
MAX_EXP = 4_102_444_800  # 2100-01-01T00:00:00Z
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
TAG_RE = re.compile(r"[0-9a-fA-F]{32}")
PROFILE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
SOURCE_FRAGMENT_RE = re.compile(r"[A-Za-z0-9_.\[\]/-]{1,256}")
SOURCE_PATH_PART_RE = re.compile(r"[A-Za-z0-9._-]{1,255}")
ACTIVE_TAG_STATUSES = frozenset({"recovered", "confirmed", "reviewed"})
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class RemusC2ProfileError(ValueError):
    """入力がschemaまたは安全条件を満たさないことを表す。"""


def _normalise_sha256(value: Any, field: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise RemusC2ProfileError(f"{field}は64桁hex SHA-256で指定してください")
    return value.casefold()


def _normalise_tag(value: Any) -> tuple[str | None, str]:
    status = "reviewed"
    if isinstance(value, Mapping):
        status = str(value.get("status") or "")
        if status not in {"candidate", "recovered", "confirmed", "reviewed"}:
            return None, status or "missing"
        value = value.get("value")
    if value is None or value == "":
        return None, status
    if not isinstance(value, str) or TAG_RE.fullmatch(value) is None:
        raise RemusC2ProfileError("tag_candidateは32桁hexで指定してください")
    return value.casefold(), status


def _normalise_exp(value: Any) -> int | None:
    if isinstance(value, Mapping):
        value = value.get("value")
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RemusC2ProfileError("expはintegerのUnix epochで指定してください")
    if not MIN_EXP <= value <= MAX_EXP:
        raise RemusC2ProfileError(f"expが妥当なUnix epoch範囲外です: {MIN_EXP}..{MAX_EXP}")
    return value


def _normalise_host(value: Any, field: str, *, allow_ip: bool = True) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RemusC2ProfileError(f"{field}が空または前後に空白を含んでいます")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise RemusC2ProfileError(f"{field}には印字可能ASCIIだけを指定してください")
    if any(character in value for character in "/\\:@?#[]"):
        raise RemusC2ProfileError(f"{field}にはhost名だけを指定してください")
    if value.endswith("."):
        raise RemusC2ProfileError(f"{field}の末尾dotは許可しません")
    try:
        parsed_ip = ipaddress.ip_address(value)
    except ValueError:
        parsed_ip = None
    if parsed_ip is not None:
        if not allow_ip:
            raise RemusC2ProfileError(f"{field}にはDNS host名を指定してください")
        return parsed_ip.compressed.casefold()
    if len(value) > 253 or "." not in value:
        raise RemusC2ProfileError(f"{field}が完全修飾DNS名ではありません")
    labels = value.split(".")
    if any(DNS_LABEL_RE.fullmatch(label) is None for label in labels):
        raise RemusC2ProfileError(f"{field}のDNS labelが不正です")
    host = value.casefold()
    if host.endswith((".local", ".localhost", ".onion")):
        raise RemusC2ProfileError(f"{field}にローカルまたはonion hostは指定できません")
    return host


def _normalise_port(value: Any, field: str = "port") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise RemusC2ProfileError(f"{field}は1..65535のintegerで指定してください")
    return value


def _global_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _canonical_uri(scheme: str, host: str, port: int) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{rendered_host}:{port}"


def _normalise_endpoint(raw: Any, position: int) -> dict[str, Any]:
    if isinstance(raw, str):
        raw_map: Mapping[str, Any] = {"uri": raw, "slot_index": position}
    elif isinstance(raw, Mapping):
        raw_map = raw
    else:
        raise RemusC2ProfileError(f"endpoints[{position}]はURL文字列またはobjectで指定してください")

    uri = raw_map.get("uri", raw_map.get("url"))
    if not isinstance(uri, str) or not uri or uri != uri.strip():
        raise RemusC2ProfileError(f"endpoints[{position}].uriが不正です")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in uri):
        raise RemusC2ProfileError(f"endpoints[{position}].uriには印字可能ASCIIだけを指定してください")
    try:
        parsed = urlsplit(uri)
        parsed_port = parsed.port
    except ValueError as exc:
        raise RemusC2ProfileError(f"endpoints[{position}].uriを解析できません") from exc
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RemusC2ProfileError(f"endpoints[{position}].uriはrootのhttp(s) URLで指定してください")
    scheme = parsed.scheme.casefold()
    host = _normalise_host(parsed.hostname, f"endpoints[{position}].host")
    port = parsed_port or (443 if scheme == "https" else 80)
    port = _normalise_port(port, f"endpoints[{position}].port")

    declared_host = raw_map.get("host")
    if declared_host not in {None, ""} and _normalise_host(declared_host, f"endpoints[{position}].host") != host:
        raise RemusC2ProfileError(f"endpoints[{position}]のURLとhostが一致しません")
    declared_port = raw_map.get("port")
    if declared_port is not None and _normalise_port(declared_port, f"endpoints[{position}].port") != port:
        raise RemusC2ProfileError(f"endpoints[{position}]のURLとportが一致しません")
    declared_scheme = raw_map.get("scheme")
    if declared_scheme not in {None, ""} and str(declared_scheme).casefold() != scheme:
        raise RemusC2ProfileError(f"endpoints[{position}]のURLとschemeが一致しません")

    slot_index = raw_map.get("slot_index", position)
    if isinstance(slot_index, bool) or not isinstance(slot_index, int) or not 0 <= slot_index <= 255:
        raise RemusC2ProfileError(f"endpoints[{position}].slot_indexが不正です")
    if host == "none":
        raise RemusC2ProfileError("http://none sentinelは実endpointへ含めないでください")

    pinned_raw = raw_map.get("pinned_ips") or []
    if not isinstance(pinned_raw, Sequence) or isinstance(pinned_raw, (str, bytes)):
        raise RemusC2ProfileError(f"endpoints[{position}].pinned_ipsはlistで指定してください")
    pinned_ips: list[str] = []
    for item in pinned_raw:
        try:
            address = ipaddress.ip_address(item)
        except (TypeError, ValueError) as exc:
            raise RemusC2ProfileError(f"endpoints[{position}].pinned_ipsに不正なIPがあります") from exc
        if not address.is_global:
            raise RemusC2ProfileError(f"endpoints[{position}].pinned_ipsにはglobal IPだけを指定してください")
        normalized = address.compressed.casefold()
        if normalized not in pinned_ips:
            pinned_ips.append(normalized)
    if len(pinned_ips) > 1:
        raise RemusC2ProfileError("能動profileは単一のreview済みpinned IPだけを許可します")

    return {
        "slot_index": slot_index,
        "uri": _canonical_uri(scheme, host, port),
        "scheme": scheme,
        "host": host,
        "port": port,
        "pinned_ips": pinned_ips,
    }


def _normalise_endpoints(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or not values:
        raise RemusC2ProfileError("endpointsは1件以上のlistで指定してください")
    if len(values) > 16:
        raise RemusC2ProfileError("endpointsは最大16件です")
    endpoints = [_normalise_endpoint(value, index) for index, value in enumerate(values)]
    slot_indices = [endpoint["slot_index"] for endpoint in endpoints]
    endpoint_keys = [(endpoint["host"], endpoint["port"]) for endpoint in endpoints]
    if len(set(slot_indices)) != len(slot_indices):
        raise RemusC2ProfileError("endpointのslot_indexが重複しています")
    if len(set(endpoint_keys)) != len(endpoint_keys):
        raise RemusC2ProfileError("endpointのhost/portが重複しています")
    return sorted(endpoints, key=lambda endpoint: endpoint["slot_index"])


def _normalise_selected_index(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise RemusC2ProfileError("selected_indexは0..255のintegerで指定してください")
    return value


def _blocked(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message_ja": message}


def _derive_profile_id(tag: str, host: str, port: int) -> str:
    host_slug = re.sub(r"[^a-z0-9]+", "-", host.casefold()).strip("-")[:48]
    return f"remus-{tag[:8]}-{host_slug}-{port}"


def _validate_profile_id(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or PROFILE_ID_RE.fullmatch(value) is None:
        raise RemusC2ProfileError("profile_idの形式が不正です")
    return value


def _normalise_source_reference(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or value != value.strip() or len(value) > 1024:
        raise RemusC2ProfileError("source_referenceが空、過長、または前後に空白を含みます")
    if "\\" in value or ".." in value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise RemusC2ProfileError("source_referenceにbackslash、..、制御文字は使用できません")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise RemusC2ProfileError("source_referenceはrepo相対pathで指定してください")
    if value.count(":") != 1:
        raise RemusC2ProfileError("source_referenceはrepo相対path:成果物位置で指定してください")
    relative_path, fragment = value.split(":", 1)
    parts = relative_path.split("/")
    if (
        not relative_path
        or not fragment
        or any(part in {"", ".", ".."} for part in parts)
        or any(SOURCE_PATH_PART_RE.fullmatch(part) is None for part in parts)
        or SOURCE_FRAGMENT_RE.fullmatch(fragment) is None
    ):
        raise RemusC2ProfileError("source_referenceのrepo相対pathまたは成果物位置が不正です")
    return f"{relative_path}:{fragment}"


def build_remus_c2_profile(
    *,
    endpoints: Sequence[Any],
    selected_index: int | None,
    tag_candidate: Any,
    exp: Any,
    reviewed_http_host: str | None,
    parent_sha256: str | None,
    recovered_pe_sha256: str | None,
    source_reference: str | None,
    dump_sha256: str | None = None,
    evidence_binding: Mapping[str, Any] | None = None,
    repository_root: Path | None = None,
    forbidden_evidence_paths: Sequence[Path] = (),
    profile_id: str | None = None,
) -> dict[str, Any]:
    """検証済み入力から受動profileと、条件付きの能動profileを返す。

    run依存UUID、ChaCha20 key/nonceの値を受け取らず、出力にも含めない。
    能動profileは既存 ``remus_registration_task`` handlerへ渡せるschemaである。
    """

    normalized_endpoints = _normalise_endpoints(endpoints)
    selected_index = _normalise_selected_index(selected_index)
    tag, tag_status = _normalise_tag(tag_candidate)
    normalized_exp = _normalise_exp(exp)
    parent_hash = _normalise_sha256(parent_sha256, "parent_sha256")
    dump_hash = _normalise_sha256(dump_sha256, "dump_sha256")
    recovered_hash = _normalise_sha256(recovered_pe_sha256, "recovered_pe_sha256")
    source = _normalise_source_reference(source_reference)
    explicit_profile_id = _validate_profile_id(profile_id)
    normalized_binding: dict[str, Any] | None = None
    binding_error: str | None = None
    if evidence_binding is not None:
        try:
            candidate_binding = build_evidence_binding(
                evidence_binding.get("source") if isinstance(evidence_binding, Mapping) else None,
                evidence_binding.get("sha256") if isinstance(evidence_binding, Mapping) else None,
                evidence_binding.get("review_id") if isinstance(evidence_binding, Mapping) else None,
            )
            if not isinstance(evidence_binding, Mapping) or dict(evidence_binding) != candidate_binding:
                raise RemusEvidenceError(
                    "evidence bindingのmanifest typeまたはJSON pointer集合がcanonical値と一致しません"
                )
            normalized_binding = candidate_binding
        except RemusEvidenceError as exc:
            binding_error = str(exc)

    trust_pins: dict[str, Any] | None = None
    trust_error: str | None = None
    if normalized_binding is not None:
        try:
            trust_pins = resolve_remus_review_trust(
                normalized_binding,
                repository_root=repository_root or default_repository_root(),
                forbidden_paths=forbidden_evidence_paths,
            )
        except RemusEvidenceError as exc:
            trust_error = str(exc)
    http_host: str | None = None
    if reviewed_http_host not in {None, ""}:
        http_host = _normalise_host(
            reviewed_http_host,
            "reviewed_http_host",
            allow_ip=False,
        )

    selected = next(
        (endpoint for endpoint in normalized_endpoints if endpoint["slot_index"] == selected_index),
        None,
    )
    blocked_reasons: list[dict[str, str]] = []
    if selected_index is None:
        blocked_reasons.append(_blocked("selected_index_missing", "選択endpoint indexを復元できていません"))
    elif selected is None:
        blocked_reasons.append(_blocked("selected_endpoint_not_found", "選択indexに対応するendpointがありません"))
    if tag is None:
        blocked_reasons.append(_blocked("tag_missing", "32桁hex tag候補を復元できていません"))
    elif tag_status not in ACTIVE_TAG_STATUSES:
        blocked_reasons.append(
            _blocked(
                "tag_unreviewed",
                "tagは候補として保持しますが、能動profileにはrecovered／confirmed／reviewed根拠が必要です",
            )
        )
    if normalized_exp is None:
        blocked_reasons.append(_blocked("exp_missing", "review済みexpを復元できていません"))
    if http_host is None:
        blocked_reasons.append(_blocked("reviewed_http_host_missing", "review済みHTTP Hostがありません"))
    elif http_host != "microsoft.com":
        blocked_reasons.append(
            _blocked(
                "reviewed_http_host_schema_mismatch",
                "既存Remus handlerが許可するHTTP Hostと一致しません",
            )
        )
    if parent_hash is None:
        blocked_reasons.append(_blocked("parent_sha256_missing", "親検体SHA-256がありません"))
    if dump_hash is None:
        blocked_reasons.append(_blocked("dump_sha256_missing", "process dump SHA-256がありません"))
    if recovered_hash is None:
        blocked_reasons.append(_blocked("recovered_pe_sha256_missing", "復元PE SHA-256がありません"))
    if evidence_binding is None:
        blocked_reasons.append(
            _blocked("evidence_manifest_missing", "field-level review済みevidence manifestがありません")
        )
    elif binding_error is not None:
        blocked_reasons.append(
            _blocked("evidence_manifest_invalid", f"evidence manifest bindingが不正です: {binding_error}")
        )
    if evidence_binding is not None and binding_error is None and trust_error is not None:
        blocked_reasons.append(
            _blocked(
                "evidence_review_registry_validation_failed",
                f"review registry allowlist validation failed: {trust_error}",
            )
        )
    if selected is not None:
        if selected["scheme"] != "http":
            blocked_reasons.append(_blocked("selected_scheme_unsupported", "既存Remus handlerはHTTPだけを許可します"))
        if _global_ip(selected["host"]):
            selected_pins = [selected["host"]]
        else:
            selected_pins = list(selected["pinned_ips"])
        if len(selected_pins) != 1:
            blocked_reasons.append(
                _blocked(
                    "selected_endpoint_pinned_ip_missing",
                    "domain endpointには単一のreview済みglobal pinned IPが必要です",
                )
            )
    else:
        selected_pins = []

    passive_profile = {
        "family": "remusstealer",
        "protocol": "remusstealer",
        "mode": "passive",
        "endpoints": [
            {
                "slot_index": endpoint["slot_index"],
                "uri": endpoint["uri"],
                "host": endpoint["host"],
                "port": endpoint["port"],
                "role": ("selected" if endpoint["slot_index"] == selected_index else "fallback"),
            }
            for endpoint in normalized_endpoints
        ],
        "selected_index": selected_index,
        "tag_candidate": tag,
        "tag_candidate_status": tag_status,
        "protocol_sequence": [
            {
                "phase": "registration",
                "direction": "client_to_server",
                "http_method": "POST",
                "content_type": "application/x-www-form-urlencoded",
                "form_fields": ["tag", "exp", "hwid"],
            },
            {
                "phase": "registration_response",
                "direction": "server_to_client",
                "expected_http_status": 201,
                "decrypted_json_fields": ["access_token", "vm", "ss"],
            },
            {
                "phase": "task_poll",
                "direction": "client_to_server",
                "http_method": "POST",
                "content_type": "application/x-www-form-urlencoded",
                "form_fields": ["access_token", "step"],
                "required_values": {"step": "1"},
            },
            {
                "phase": "task_response",
                "direction": "server_to_client",
                "expected_http_status": 201,
                "decrypted_json_fields": ["type", "name", "data"],
            },
        ],
        "response_envelope": {
            "layout": ["key", "nonce", "ciphertext"],
            "key_length_bytes": 32,
            "nonce_length_bytes": 8,
            "ciphertext_offset_bytes": 40,
            "cipher": "ChaCha20",
            "counter_model": "64-bit little-endian counter 0 + 64-bit nonce",
            "key_value_published": False,
            "nonce_value_published": False,
        },
        "confirmation_requirements": [
            "tag+exp+synthetic_hwid登録へのHTTP 201応答",
            "32-byte key + 8-byte nonce + ciphertext envelopeのChaCha20復号成功",
            "access_token・vm・ssを含むJSON構造",
            "access_token+step=1へのHTTP 201応答とtype・name・data JSON構造",
        ],
    }

    active_profile: dict[str, Any] | None = None
    evidence_validation: dict[str, Any] | None = None
    if not blocked_reasons:
        assert selected is not None
        assert tag is not None
        assert normalized_exp is not None
        assert http_host is not None
        assert parent_hash is not None
        assert dump_hash is not None
        assert recovered_hash is not None
        assert normalized_binding is not None
        assert trust_pins is not None
        active_profile_id = explicit_profile_id or _derive_profile_id(tag, selected["host"], selected["port"])
        candidate_profile = {
            "profile_id": active_profile_id,
            "family": "remusstealer",
            "sample_sha256s": [parent_hash],
            "host": selected["host"],
            "port": selected["port"],
            "selected_slot_index": selected["slot_index"],
            "protocol": "remusstealer",
            "method": "remus_registration_task",
            "handler": "remus_registration_task",
            "http_path": "/",
            "http_host": http_host,
            "pinned_ips": selected_pins,
            "tag": tag,
            "exp": normalized_exp,
            "request_budget": 2,
            "timeout_seconds": 3.0,
            "maximum_request_bytes": 4096,
            "maximum_response_bytes": 8192,
            "role": "Remusの合成端末登録・step=1 task取得先",
            "source": f"{normalized_binding['source']}:{EVIDENCE_POINTERS['endpoint']}",
            "dump_sha256": dump_hash,
            "recovered_pe_sha256": recovered_hash,
            "evidence_binding": normalized_binding,
            "review_id": normalized_binding["review_id"],
            "review_registry_source": trust_pins["registry_source"],
            "review_registry_sha256": trust_pins["registry_sha256"],
            "flow_artifact_source": trust_pins["review"]["flow_artifact_source"],
            "flow_artifact_sha256": trust_pins["review"]["flow_artifact_sha256"],
            "run_id": trust_pins["review"]["run_id"],
            "evidence_source": normalized_binding["source"],
            "evidence_sha256": normalized_binding["sha256"],
        }
        try:
            validated = validate_remus_profile_evidence(
                candidate_profile,
                repository_root=repository_root or default_repository_root(),
                expected_sha256=normalized_binding["sha256"],
                expected_registry_sha256=trust_pins["registry_sha256"],
                expected_flow_artifact_sha256=trust_pins["review"]["flow_artifact_sha256"],
                forbidden_paths=forbidden_evidence_paths,
            )
        except RemusEvidenceError as exc:
            blocked_reasons.append(
                _blocked(
                    "evidence_manifest_validation_failed",
                    f"field-level evidence manifestを検証できません: {exc}",
                )
            )
        else:
            active_profile = candidate_profile
            evidence_validation = {key: value for key, value in validated.items() if not key.startswith("_")}

    return {
        "schema_version": 1,
        "analysis": "remus_c2_profile",
        "status": "ready" if active_profile is not None else "blocked",
        "evidence": {
            "parent_sha256": parent_hash,
            "dump_sha256": dump_hash,
            "recovered_pe_sha256": recovered_hash,
            "endpoint_count": len(normalized_endpoints),
            "selected_index": selected_index,
            "source_reference": source,
            "tag_status": tag_status,
            "manifest_binding": normalized_binding,
            "manifest_validation": evidence_validation,
        },
        "passive_profile": passive_profile,
        "active_profile_generation": {
            "status": "ready" if active_profile is not None else "blocked",
            "blocked_reasons": blocked_reasons,
            "profile": active_profile,
        },
        "safety": {
            "network_contacted": False,
            "sample_executed": False,
            "other_sample_defaults_used": False,
            "runtime_uuid_published": False,
            "chacha_key_value_published": False,
            "chacha_nonce_value_published": False,
        },
    }


def build_remus_c2_profile_from_payload(
    payload: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    forbidden_evidence_paths: Sequence[Path] = (),
) -> dict[str, Any]:
    """JSON objectからC2 profileを生成する。

    未知のfieldは出力へ複製しないため、入力に混入したrun依存値や秘密値を
    reportへ反射しない。
    """

    if not isinstance(payload, Mapping):
        raise RemusC2ProfileError("入力JSONはobjectである必要があります")
    return build_remus_c2_profile(
        endpoints=payload.get("endpoints"),
        selected_index=payload.get("selected_index"),
        tag_candidate=payload.get("tag_candidate"),
        exp=payload.get("exp"),
        reviewed_http_host=payload.get("reviewed_http_host"),
        parent_sha256=payload.get("parent_sha256"),
        dump_sha256=payload.get("dump_sha256"),
        recovered_pe_sha256=payload.get("recovered_pe_sha256"),
        source_reference=payload.get("source_reference"),
        evidence_binding=payload.get("evidence_binding"),
        repository_root=repository_root,
        forbidden_evidence_paths=forbidden_evidence_paths,
        profile_id=payload.get("profile_id"),
    )


def _read_payload(path: Path, maximum: int) -> Mapping[str, Any]:
    if type(maximum) is not int or maximum <= 0:
        raise RemusC2ProfileError("max_input_bytesは正の整数で指定してください")
    absolute = Path(os.path.abspath(os.fspath(path)))
    reject_existing_reparse_components(absolute)
    metadata = absolute.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)
    ):
        raise RemusC2ProfileError("入力は単一リンクの通常ファイルである必要があります")
    if metadata.st_size <= 0:
        raise RemusC2ProfileError("入力JSONは空ファイルにできません")
    if metadata.st_size > maximum:
        raise RemusC2ProfileError(f"入力JSONが上限を超えています: {metadata.st_size} > {maximum}")
    chunks: list[bytes] = []
    total = 0
    with absolute.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or bool(getattr(opened, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)
            or not os.path.samestat(metadata, opened)
        ):
            raise RemusC2ProfileError("入力JSONが読み取り開始前に置換されました")
        while True:
            chunk = stream.read(min(16 * 1024, maximum - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise RemusC2ProfileError(f"入力JSONが上限を超えています: {total} > {maximum}")
        opened_after = os.fstat(stream.fileno())

    reject_existing_reparse_components(absolute)
    final = absolute.stat(follow_symlinks=False)
    observed = (metadata, opened, opened_after, final)
    if (
        any(not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 for item in observed)
        or any(bool(getattr(item, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT) for item in observed)
        or any(not os.path.samestat(metadata, item) for item in observed[1:])
        or any(item.st_size != metadata.st_size for item in observed[1:])
    ):
        raise RemusC2ProfileError("入力JSONが読み取り中に置換またはlink化されました")
    data = b"".join(chunks)
    if len(data) != metadata.st_size:
        raise RemusC2ProfileError("読み取り中に入力JSONのサイズが変化しました")
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RemusC2ProfileError("入力JSONはUTF-8で指定してください") from exc

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise RemusC2ProfileError(f"入力JSONに重複keyがあります: {key}")
            value[key] = item
        return value

    try:
        payload = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                RemusC2ProfileError(f"入力JSONに非標準数値があります: {value}")
            ),
        )
    except RemusC2ProfileError:
        raise
    except json.JSONDecodeError as exc:
        raise RemusC2ProfileError("入力JSONを解析できません") from exc
    if not isinstance(payload, Mapping):
        raise RemusC2ProfileError("入力JSONはobjectである必要があります")
    return payload


def build_parser() -> argparse.ArgumentParser:
    """JSON CLIのargument parserを返す。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="静的設定と根拠を含むJSON")
    parser.add_argument(
        "--output",
        type=Path,
        help="生成結果JSONの新規保存先。既存fileは上書きしません",
    )
    parser.add_argument(
        "--max-input-bytes",
        type=int,
        default=DEFAULT_MAX_INPUT_BYTES,
        help="入力JSONの最大byte数",
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=default_repository_root(),
        help="evidence manifestを解決するrepository root",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        destination = Path(os.path.abspath(os.fspath(args.output))) if args.output is not None else None
        report = build_remus_c2_profile_from_payload(
            _read_payload(args.input, args.max_input_bytes),
            repository_root=args.repository_root,
            forbidden_evidence_paths=tuple(path for path in (args.input, destination) if path is not None),
        )
        rendered = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        if args.output is not None:
            write_private_output(
                destination,
                rendered,
                hashlib.sha256(rendered).hexdigest(),
                allowed_root=destination.parent,
            )
        sys.stdout.buffer.write(rendered)
        return 0
    except (OSError, ValueError) as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
