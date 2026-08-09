#!/usr/bin/env python3
"""DarkComet C2 profile と公開静的解析証拠を fail-closed で結合する。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from immutable_snapshot import decode_strict_json, read_bounded_snapshot
from safe_private_output import reject_existing_reparse_components

MAXIMUM_EVIDENCE_BYTES = 64 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SOURCE_POINTER_RE = re.compile(r"config\.netdata\[(\d+)\]")


class DarkCometEvidenceError(ValueError):
    """証拠または profile の結合条件が成立しない場合のエラー。"""


def default_repository_root() -> Path:
    """この module が属する repository root を返す。"""

    return Path(__file__).resolve().parents[2]


def _required_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DarkCometEvidenceError(f"{label} は object である必要があります")
    return value


def _split_source(source: object) -> tuple[Path, int, str]:
    if not isinstance(source, str) or source.count(":") != 1:
        raise DarkCometEvidenceError("source は相対 JSON path と config.netdata[N] の組である必要があります")
    path_text, pointer = source.split(":", 1)
    match = SOURCE_POINTER_RE.fullmatch(pointer)
    path = Path(path_text)
    if (
        not path_text
        or path.is_absolute()
        or path.drive
        or any(part in {"", ".", ".."} for part in path.parts)
        or match is None
    ):
        raise DarkCometEvidenceError("source の path または pointer が安全境界外です")
    return path, int(match.group(1)), pointer


def _read_bounded_json(repository_root: Path, relative_path: Path) -> tuple[dict[str, Any], bytes]:
    lexical_root = repository_root.absolute()
    lexical_candidate = lexical_root / relative_path
    try:
        root = lexical_root.resolve(strict=True)
        candidate = lexical_candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise DarkCometEvidenceError("証拠 JSON を解決できません") from exc
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise DarkCometEvidenceError("証拠 JSON が repository root 外へ解決されました") from exc
    try:
        reject_existing_reparse_components(lexical_root)
        reject_existing_reparse_components(lexical_candidate)
        snapshot = read_bounded_snapshot(
            lexical_candidate,
            MAXIMUM_EVIDENCE_BYTES,
        )
    except ValueError as exc:
        if "上限" in str(exc):
            raise DarkCometEvidenceError("証拠 JSON が 64 KiB 上限を超えています") from exc
        raise DarkCometEvidenceError(
            "証拠 JSON が通常file・single-link・reparse-free条件を満たしません"
        ) from exc
    except OSError as exc:
        raise DarkCometEvidenceError("証拠 JSON を読み取れません") from exc
    try:
        payload = decode_strict_json(snapshot.data)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise DarkCometEvidenceError(
            "証拠 JSON は重複key・非有限数値を含まない UTF-8 の厳密な JSON である必要があります"
        ) from exc
    return _required_object(payload, "証拠 JSON root"), snapshot.data


def _profile_samples(profile: dict[str, Any]) -> tuple[str, str]:
    samples = profile.get("sample_sha256s")
    if (
        not isinstance(samples, list)
        or len(samples) != 2
        or len(set(samples)) != 2
        or any(not isinstance(value, str) or not SHA256_RE.fullmatch(value) for value in samples)
    ):
        raise DarkCometEvidenceError("profile には root/terminal の一意な SHA-256 が2件必要です")
    return samples[0], samples[1]


def _profile_key(profile: dict[str, Any]) -> bytes:
    try:
        value = base64.b64decode(
            str(profile.get("network_rc4_key_base64") or ""),
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise DarkCometEvidenceError("profile の network RC4 key が不正です") from exc
    if not 1 <= len(value) <= 256:
        raise DarkCometEvidenceError("profile の network RC4 key 長が不正です")
    return value


def validate_darkcomet_profile_evidence(
    profile: dict[str, Any],
    *,
    repository_root: Path | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """完全一致 profile と公開証拠を照合し、証拠 SHA-256 を返す。"""

    if not isinstance(profile, dict):
        raise DarkCometEvidenceError("profile は object である必要があります")
    if (
        profile.get("family") != "darkcomet"
        or profile.get("protocol") != "darkcomet"
        or profile.get("method") != "darkcomet_server_first_idtype"
        or profile.get("handler") != "darkcomet_server_first_idtype"
        or profile.get("expected_plaintext") != "IDTYPE"
        or profile.get("primary_wire_encoding") != "ascii_hex"
        or profile.get("wire_encodings") != ["raw", "ascii_hex"]
        or profile.get("key_derivation_status") != "static_verified"
        or not str(profile.get("key_derivation_evidence") or "").strip()
        or profile.get("password_concatenated") is not False
        or profile.get("config_resource_key_reused") is not False
        or int(profile.get("maximum_response_bytes", 0)) != 12
        or any(field in profile for field in ("send_hex", "payload", "checkin", "request_packet"))
    ):
        raise DarkCometEvidenceError("DarkComet profile の受信専用条件が不正です")
    root_sha256, terminal_sha256 = _profile_samples(profile)
    profile_key = _profile_key(profile)
    key_hex = profile_key.hex()
    key_base64 = base64.b64encode(profile_key).decode("ascii")

    relative_path, index, pointer = _split_source(profile.get("source"))
    root = repository_root or default_repository_root()
    evidence, raw = _read_bounded_json(Path(root), relative_path)
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and (not SHA256_RE.fullmatch(expected_sha256) or digest != expected_sha256):
        raise DarkCometEvidenceError("証拠 JSON の SHA-256 が計画時の固定値と一致しません")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("family") != "darkcomet"
        or evidence.get("root_sha256") != root_sha256
        or evidence.get("parent_sha256") != root_sha256
        or evidence.get("terminal_sha256") != terminal_sha256
    ):
        raise DarkCometEvidenceError("証拠 JSON の schema/family/root/terminal が不正です")

    verification = _required_object(evidence.get("static_verification"), "static_verification")
    if any(
        verification.get(field) is not True
        for field in (
            "static_verified",
            "root_terminal_relationship_verified",
            "config_endpoint_records_verified",
            "protocol_key_verified",
        )
    ):
        raise DarkCometEvidenceError("証拠 JSON の静的検証 flag が不足しています")

    config = _required_object(evidence.get("config"), "config")
    netdata = config.get("netdata")
    records = config.get("endpoint_records")
    if not isinstance(netdata, list) or not isinstance(records, list) or len(netdata) != len(records):
        raise DarkCometEvidenceError("NETDATA と endpoint_records が対応していません")
    endpoints: list[tuple[str, int]] = []
    for offset, (endpoint, record_value) in enumerate(zip(netdata, records, strict=True)):
        if not isinstance(endpoint, str) or endpoint.count(":") != 1:
            raise DarkCometEvidenceError("NETDATA endpoint が host:port 形式ではありません")
        host, port_text = endpoint.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise DarkCometEvidenceError("NETDATA port が整数ではありません") from exc
        if not 1 <= port <= 65535:
            raise DarkCometEvidenceError("NETDATA port が範囲外です")
        record = _required_object(record_value, f"endpoint_records[{offset}]")
        if record != {
            "host": host,
            "port": port,
            "role": "static_c2_candidate",
            "source": f"RCDATA/NETDATA[{offset}]",
        }:
            raise DarkCometEvidenceError("endpoint_records が NETDATA の完全一致記録ではありません")
        endpoints.append((host, port))
    if index >= len(endpoints) or endpoints[index] != (profile.get("host"), profile.get("port")):
        raise DarkCometEvidenceError("source pointer の endpoint が profile と一致しません")
    if pointer != f"config.netdata[{index}]":
        raise DarkCometEvidenceError("source pointer が canonical 形式ではありません")

    protocol = _required_object(evidence.get("protocol"), "protocol")
    network_key = _required_object(protocol.get("network_key"), "protocol.network_key")
    relation = _required_object(protocol.get("resource_config_key_relation"), "protocol.resource_config_key_relation")
    confirmation = _required_object(protocol.get("passive_confirmation"), "protocol.passive_confirmation")
    if (
        protocol.get("network_key_hex") != key_hex
        or protocol.get("network_key_base64") != key_base64
        or protocol.get("key_derivation_status") != "static_verified"
        or protocol.get("password_concatenated") is not False
        or protocol.get("network_key_password_concatenated") is not False
        or protocol.get("config_resource_key_reused") is not False
        or protocol.get("expected_plaintext") != "IDTYPE"
        or protocol.get("server_first_plaintext") != "IDTYPE"
        or protocol.get("no_send") is not True
        or network_key.get("value_hex") != key_hex
        or network_key.get("value_base64") != key_base64
        or network_key.get("length") != len(profile_key)
        or network_key.get("password_concatenated") is not False
        or network_key.get("static_verified") is not True
        or relation.get("identical") is not False
        or confirmation.get("accepted_wire_encodings") != ["raw_rc4", "ascii_hex_rc4"]
        or confirmation.get("exact_plaintext") != "IDTYPE"
        or confirmation.get("client_data_sent") is not False
    ):
        raise DarkCometEvidenceError("証拠 JSON の protocol/key/no-send 条件が不正です")

    return {
        "sha256": digest,
        "source": str(profile["source"]),
        "relative_path": relative_path.as_posix(),
        "pointer": pointer,
        "endpoint": f"{profile['host']}:{profile['port']}",
        "root_sha256": root_sha256,
        "terminal_sha256": terminal_sha256,
    }
