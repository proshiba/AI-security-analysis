#!/usr/bin/env python3
"""PEのエクスポート、API、復号リソースを宣言型プロファイルで評価する。"""

from __future__ import annotations

from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

import pefile


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE_PATH = FRAMEWORK_ROOT / "registry" / "pe_structural_profiles.json"
PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_CONFIDENCE = {"high", "medium", "low"}
MAX_PE_SIZE = 128 * 1024 * 1024
MAX_RESOURCE_SIZE = 16 * 1024 * 1024
MAX_RESOURCE_MATCHES = 64


class ProfileValidationError(ValueError):
    """宣言型PEプロファイルが契約を満たさない場合に送出する。"""


def _string_list(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ProfileValidationError(f"{field}は文字列配列である必要があります")
    values = tuple(dict.fromkeys(item for item in value if item))
    if len(values) != len(value):
        raise ProfileValidationError(f"{field}に空値または重複があります")
    return values


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProfileValidationError(f"{field}は整数である必要があります")
    if not minimum <= value <= maximum:
        raise ProfileValidationError(f"{field}は{minimum}から{maximum}の範囲で指定してください")
    return value


def _validate_resource_rule(value: object, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProfileValidationError(f"resource_rules[{index}]はobjectである必要があります")
    rule_id = value.get("id")
    if not isinstance(rule_id, str) or PROFILE_ID_RE.fullmatch(rule_id) is None:
        raise ProfileValidationError(f"resource_rules[{index}].idが不正です")
    type_id = _integer(value.get("type_id"), f"{rule_id}.type_id", 0, 65535)
    resource_id = value.get("resource_id")
    if resource_id is not None:
        resource_id = _integer(resource_id, f"{rule_id}.resource_id", 0, 65535)
    xor_key = value.get("xor_key")
    if xor_key is not None:
        xor_key = _integer(xor_key, f"{rule_id}.xor_key", 0, 255)
    magic_ascii = value.get("magic_ascii")
    magic_hex = value.get("magic_hex")
    if (magic_ascii is None) == (magic_hex is None):
        raise ProfileValidationError(f"{rule_id}はmagic_asciiまたはmagic_hexを一つだけ必要とします")
    if magic_ascii is not None:
        if not isinstance(magic_ascii, str) or not magic_ascii:
            raise ProfileValidationError(f"{rule_id}.magic_asciiが不正です")
        try:
            magic = magic_ascii.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ProfileValidationError(f"{rule_id}.magic_asciiはASCIIで指定してください") from exc
    else:
        if not isinstance(magic_hex, str) or not magic_hex:
            raise ProfileValidationError(f"{rule_id}.magic_hexが不正です")
        try:
            magic = bytes.fromhex(magic_hex)
        except ValueError as exc:
            raise ProfileValidationError(f"{rule_id}.magic_hexが不正です") from exc
    if not magic:
        raise ProfileValidationError(f"{rule_id}.magicを空にできません")
    return {
        "id": rule_id,
        "type_id": type_id,
        "resource_id": resource_id,
        "xor_key": xor_key,
        "magic": magic,
        "minimum_matches": _integer(
            value.get("minimum_matches", 1),
            f"{rule_id}.minimum_matches",
            1,
            MAX_RESOURCE_MATCHES,
        ),
    }


def validate_profile(value: object) -> dict[str, Any]:
    """一つのPE構造プロファイルを検証・正規化する。"""

    if not isinstance(value, Mapping):
        raise ProfileValidationError("profileはobjectである必要があります")
    profile_id = value.get("id")
    family = value.get("family")
    campaign_type = value.get("campaign_type")
    for field, item in (
        ("id", profile_id),
        ("family", family),
        ("campaign_type", campaign_type),
    ):
        if not isinstance(item, str) or PROFILE_ID_RE.fullmatch(item) is None:
            raise ProfileValidationError(f"{field}が不正です")
    reviewed = _string_list(value.get("reviewed_sha256", []), "reviewed_sha256")
    if any(SHA256_RE.fullmatch(item) is None for item in reviewed):
        raise ProfileValidationError("reviewed_sha256に不正なSHA-256があります")
    required_exports = _string_list(
        value.get("required_exports", []),
        "required_exports",
    )
    api_markers = _string_list(value.get("api_markers", []), "api_markers")
    minimum_api_markers = _integer(
        value.get("minimum_api_markers", len(api_markers)),
        "minimum_api_markers",
        0,
        len(api_markers),
    )
    resource_values = value.get("resource_rules", [])
    if not isinstance(resource_values, list):
        raise ProfileValidationError("resource_rulesは配列である必要があります")
    resource_rules = tuple(_validate_resource_rule(item, index) for index, item in enumerate(resource_values))
    confidence = value.get("structural_confidence", "medium")
    if confidence not in ALLOWED_CONFIDENCE - {"high"}:
        raise ProfileValidationError("structural_confidenceはmediumまたはlowで指定してください")
    reason_labels = value.get("reason_labels", {})
    if not isinstance(reason_labels, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in reason_labels.items()
    ):
        raise ProfileValidationError("reason_labelsは文字列mapである必要があります")
    if not (reviewed or required_exports or api_markers or resource_rules):
        raise ProfileValidationError("profileには少なくとも一つの証拠条件が必要です")
    return {
        "id": profile_id,
        "family": family,
        "campaign_type": campaign_type,
        "reviewed_sha256": frozenset(reviewed),
        "required_exports": frozenset(required_exports),
        "api_markers": frozenset(api_markers),
        "minimum_api_markers": minimum_api_markers,
        "resource_rules": resource_rules,
        "structural_confidence": confidence,
        "reason_labels": dict(reason_labels),
    }


@lru_cache(maxsize=16)
def _load_profiles_cached(
    resolved_path: str,
    modified_ns: int,
    size: int,
) -> dict[str, dict[str, Any]]:
    del modified_ns, size
    path = Path(resolved_path)
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, Mapping) or document.get("schema_version") != 1:
        raise ProfileValidationError("PE構造プロファイルのschema_versionが不正です")
    values = document.get("profiles")
    if not isinstance(values, list):
        raise ProfileValidationError("profilesは配列である必要があります")
    profiles: dict[str, dict[str, Any]] = {}
    for item in values:
        profile = validate_profile(item)
        profile_id = profile["id"]
        if profile_id in profiles:
            raise ProfileValidationError(f"profile idが重複しています: {profile_id}")
        profiles[profile_id] = profile
    return profiles


def load_profiles(path: Path = DEFAULT_PROFILE_PATH) -> dict[str, dict[str, Any]]:
    """ファイルidentityをcache keyとして検証済みプロファイルを読み込む。"""

    resolved = path.resolve(strict=True)
    stat_result = resolved.stat()
    return _load_profiles_cached(
        str(resolved),
        stat_result.st_mtime_ns,
        stat_result.st_size,
    )


def get_profile(
    profile_id: str,
    path: Path = DEFAULT_PROFILE_PATH,
) -> dict[str, Any]:
    """指定IDの検証済みプロファイルを返す。"""

    try:
        return load_profiles(path)[profile_id]
    except KeyError as exc:
        raise ProfileValidationError(f"PE構造プロファイルが見つかりません: {profile_id}") from exc


def _decode_name(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", errors="replace")
    return str(value or "")


def _resource_matches(
    pe: pefile.PE,
    rules: tuple[dict[str, Any], ...],
) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return matches
    for type_entry in root.entries:
        type_id = getattr(type_entry, "id", None)
        if not hasattr(type_entry, "directory"):
            continue
        applicable = [item for item in rules if item["type_id"] == type_id]
        if not applicable:
            continue
        for name_entry in type_entry.directory.entries:
            resource_id = getattr(name_entry, "id", None)
            if not hasattr(name_entry, "directory"):
                continue
            for language_entry in name_entry.directory.entries:
                data_entry = getattr(language_entry, "data", None)
                if data_entry is None:
                    continue
                size = int(data_entry.struct.Size)
                if size < 0 or size > MAX_RESOURCE_SIZE:
                    continue
                raw = pe.get_data(int(data_entry.struct.OffsetToData), size)
                for rule in applicable:
                    expected_id = rule["resource_id"]
                    if expected_id is not None and expected_id != resource_id:
                        continue
                    decoded = bytes(value ^ rule["xor_key"] for value in raw) if rule["xor_key"] is not None else raw
                    if not decoded.startswith(rule["magic"]):
                        continue
                    matches.append(
                        {
                            "rule_id": rule["id"],
                            "type_id": type_id,
                            "resource_id": resource_id,
                            "size": size,
                            "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                        }
                    )
                    if len(matches) >= MAX_RESOURCE_MATCHES:
                        return matches
    return matches


def inspect_pe(data: bytes, profile: Mapping[str, Any]) -> dict[str, Any]:
    """PEを一度だけ解析し、プロファイルと独立した観測値を返す。"""

    summary: dict[str, Any] = {
        "valid_pe": False,
        "exports": [],
        "required_exports": [],
        "api_markers": [],
        "resource_matches": [],
        "parse_status": "not_pe",
    }
    if not data.startswith(b"MZ") or len(data) < 64 or len(data) > MAX_PE_SIZE:
        return summary
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError:
        summary["parse_status"] = "parse_failed"
        return summary
    exports = {
        _decode_name(symbol.name)
        for symbol in getattr(
            getattr(pe, "DIRECTORY_ENTRY_EXPORT", None),
            "symbols",
            [],
        )
        if symbol.name
    }
    imports = {
        _decode_name(entry.name)
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        for entry in descriptor.imports
        if entry.name
    }
    marker_names = profile["api_markers"]
    string_markers = {name for name in marker_names if name.encode("ascii") in data or name.encode("utf-16le") in data}
    summary.update(
        {
            "valid_pe": True,
            "exports": sorted(exports),
            "required_exports": sorted(profile["required_exports"] & exports),
            "api_markers": sorted(marker_names & (imports | string_markers)),
            "resource_matches": _resource_matches(pe, profile["resource_rules"]),
            "parse_status": "parsed",
        }
    )
    return summary


def evaluate_profile(
    data: bytes,
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    """完全一致または複数構造条件を評価し、根拠付きの共通結果を返す。"""

    digest = hashlib.sha256(data).hexdigest()
    summary = inspect_pe(data, profile)
    export_match = not profile["required_exports"] or len(summary["required_exports"]) == len(
        profile["required_exports"]
    )
    api_match = len(summary["api_markers"]) >= profile["minimum_api_markers"]
    resource_counts: dict[str, int] = {}
    for item in summary["resource_matches"]:
        rule_id = str(item["rule_id"])
        resource_counts[rule_id] = resource_counts.get(rule_id, 0) + 1
    resource_match = all(
        resource_counts.get(rule["id"], 0) >= rule["minimum_matches"] for rule in profile["resource_rules"]
    )
    structural_conditions = bool(profile["required_exports"] or profile["api_markers"] or profile["resource_rules"])
    structural_match = bool(
        summary["valid_pe"] and structural_conditions and export_match and api_match and resource_match
    )
    exact_match = digest in profile["reviewed_sha256"]
    reasons: list[str] = []
    labels = profile["reason_labels"]
    if exact_match:
        reasons.append(labels.get("exact", "レビュー済みSHA-256完全一致"))
    if structural_match:
        if profile["required_exports"]:
            reasons.append(labels.get("exports", "必須エクスポート群"))
        if profile["api_markers"]:
            reasons.append(labels.get("apis", "複数のAPIマーカー"))
        if profile["resource_rules"]:
            reasons.append(labels.get("resources", "検証済み復号リソース"))
    matched = exact_match or structural_match
    confidence = "high" if exact_match else profile["structural_confidence"] if structural_match else "insufficient"
    return {
        "profile_id": profile["id"],
        "family": profile["family"],
        "campaign_type": profile["campaign_type"],
        "matched": matched,
        "confidence": confidence,
        "sha256": digest,
        "exact_match": exact_match,
        "structural_match": structural_match,
        "checks": {
            "exports": export_match,
            "api_markers": api_match,
            "resources": resource_match,
        },
        "reasons": reasons,
        "observations": summary,
        "sample_executed": False,
        "network_contacted": False,
    }


def detect_with_profile(
    data: bytes,
    profile_id: str,
    path: Path | None = None,
    *,
    profiles_path: Path = DEFAULT_PROFILE_PATH,
) -> dict[str, object]:
    """classifier互換shapeで一つのPE構造プロファイルを評価する。"""

    evaluation = evaluate_profile(data, get_profile(profile_id, profiles_path))
    observations = {
        **evaluation["observations"],
        "profile_id": profile_id,
        "exact_match": evaluation["exact_match"],
        "structural_match": evaluation["structural_match"],
        "checks": evaluation["checks"],
        "path_name": path.name if path else None,
    }
    return {
        "matched": evaluation["matched"],
        "confidence": evaluation["confidence"],
        "sha256": evaluation["sha256"],
        "campaigns": (
            [
                {
                    "campaign_type": evaluation["campaign_type"],
                    "confidence": evaluation["confidence"],
                    "reasons": evaluation["reasons"],
                }
            ]
            if evaluation["matched"]
            else []
        ),
        "observations": observations,
        "sample_executed": False,
        "network_contacted": False,
    }
