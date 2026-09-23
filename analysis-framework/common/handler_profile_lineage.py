"""認証済みhandler設定をfamily帰属とは独立した候補へ縮約する。"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any

import orchestration_outcome


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DOMAIN = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
_SELF_LABEL = re.compile(r"\s*(bwrat|dcrat|asyncrat|venomrat)\b", re.IGNORECASE)
_KNOWN_PROFILES = frozenset({"dcrat", "asyncrat", "venomrat"})
_MAX_INPUT_RECORDS = 256
_MAX_RECORDS = 64
_MAX_ENDPOINTS = 64


def _sha(value: object) -> str | None:
    return value if isinstance(value, str) and _SHA256.fullmatch(value) else None


def _host(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 253:
        return None
    host = value.strip().rstrip(".").casefold()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host if _DOMAIN.fullmatch(host) else None


def _candidate_execution_valid(record: Mapping[str, Any], assessed: Mapping[str, Any]) -> bool:
    """family帰属とは分離してcandidate handlerの品質宣言を再検証する。"""

    if assessed.get("succeeded") is True:
        return True
    if (
        record.get("source") != "candidate_verification"
        or record.get("status")
        not in {"corroborated", "handler_evidence_without_detector", "handler_evidence_route_only"}
    ):
        return False
    declared = record.get("handler_evidence")
    computed = assessed.get("quality")
    return bool(
        isinstance(declared, Mapping)
        and isinstance(computed, Mapping)
        and declared.get("sufficient") is True
        and computed.get("sufficient") is True
        and type(declared.get("tier")) is int
        and type(declared.get("score")) is int
        and declared.get("tier") == computed.get("tier")
        and declared.get("score") == computed.get("score")
    )


def _authenticated_config_shape(record: Mapping[str, Any]) -> bool:
    """上限計数前にHMAC設定候補になり得ない試行を安価に除外する。"""

    wrapper = record.get("result")
    result = wrapper.get("result") if isinstance(wrapper, Mapping) else None
    evidence = result.get("static_evidence") if isinstance(result, Mapping) else None
    config = result.get("config") if isinstance(result, Mapping) else None
    crypto = config.get("crypto_profile") if isinstance(config, Mapping) else None
    return bool(
        isinstance(evidence, Mapping)
        and evidence.get("authentication") == "hmac_sha256"
        and isinstance(config, Mapping)
        and config.get("static_config_recovered") is True
        and isinstance(crypto, Mapping)
        and crypto.get("authentication") == "HMAC-SHA256"
    )


def _validated_candidate(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """HMAC検証済み設定だけを、秘密値なしの構成候補へ変換する。"""

    assessed = orchestration_outcome.assess_handler_record(record)
    if not _candidate_execution_valid(record, assessed):
        return None
    profile = record.get("family")
    wrapper = record.get("result")
    if profile not in _KNOWN_PROFILES or not isinstance(wrapper, Mapping):
        return None
    handler = wrapper.get("handler")
    selected_layer = wrapper.get("selected_layer")
    result = wrapper.get("result")
    layer_sha = _sha(record.get("selected_layer_sha256"))
    if (
        not isinstance(handler, Mapping)
        or not isinstance(selected_layer, Mapping)
        or not isinstance(result, Mapping)
        or layer_sha is None
        or _sha(selected_layer.get("sha256")) != layer_sha
        or _sha(result.get("sample_sha256")) != layer_sha
        or handler.get("id") != record.get("handler_id")
        or handler.get("family") != profile
        or result.get("family") != profile
        or wrapper.get("executed_sample") is not False
        or wrapper.get("network_contacted") is not False
        or result.get("static_config_recovered") is not True
        or result.get("executed") is not False
        or result.get("network_contacted") is not False
    ):
        return None
    static_evidence = result.get("static_evidence")
    config = result.get("config")
    if (
        not isinstance(static_evidence, Mapping)
        or static_evidence.get("all_expected_fields_validated") is not True
        or static_evidence.get("authentication") != "hmac_sha256"
        or not isinstance(config, Mapping)
        or config.get("static_config_recovered") is not True
        or not isinstance(config.get("crypto_profile"), Mapping)
        or config["crypto_profile"].get("authentication") != "HMAC-SHA256"
    ):
        return None
    endpoints = config.get("endpoints")
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= _MAX_ENDPOINTS:
        return None
    normalized = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            return None
        host = _host(endpoint.get("host"))
        port = endpoint.get("port")
        if host is None or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            return None
        normalized.add((host, port))
    version = config.get("version")
    label = None
    if isinstance(version, str) and len(version) <= 128 and not any(ord(ch) < 32 for ch in version):
        match = _SELF_LABEL.match(version)
        if match:
            label = match.group(1).replace(" ", "").casefold()
    conflict = bool(label and label != profile)
    return {
        "source_profile": profile,
        "terminal_layer_sha256": layer_sha,
        "authentication": "hmac_sha256_verified",
        "self_declared_product": label,
        "profile_conflicts_with_self_description": conflict,
        "configured_network_candidates": [
            {"host": host, "port": port, "role": "static_config_candidate", "contacted": False}
            for host, port in sorted(normalized)
        ],
        "family_attribution_confirmed": False,
        "used_for_family_resolution": False,
        "used_for_c2_confirmation": False,
        "liveness_confirmed": False,
    }


def build_document(*, sha256: str, handler_records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """handlerの認証済み設定を上限付き・非実行で列挙する。"""

    if _sha(sha256) is None:
        raise ValueError("root SHA-256が不正です")
    if len(handler_records) > _MAX_INPUT_RECORDS:
        raise ValueError("handler input record数が安全上限を超えています")
    candidate_records = [
        record
        for record in handler_records
        if isinstance(record, Mapping) and _authenticated_config_shape(record)
    ]
    if len(candidate_records) > _MAX_RECORDS:
        raise ValueError("認証済み設定候補record数が安全上限を超えています")
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for record in candidate_records:
        candidate = _validated_candidate(record)
        if candidate is not None:
            unique[(candidate["source_profile"], candidate["terminal_layer_sha256"])] = candidate
    candidates = [unique[key] for key in sorted(unique)]
    conflicting_profiles = sorted({
        candidate["source_profile"]
        for candidate in candidates
        if candidate["profile_conflicts_with_self_description"]
    })
    return {
        "schema_version": 1,
        "sha256": sha256,
        "status": "validated_config_candidates_recovered" if candidates else "no_validated_config_candidate",
        "candidate_count": len(candidates),
        "candidates": candidates,
        "conflicting_profiles": conflicting_profiles,
        "evidence_boundary": {
            "handler_profile_is_family_confirmation": False,
            "self_description_is_family_confirmation": False,
            "configuration_candidate_is_c2_confirmation": False,
            "configuration_candidate_is_liveness_confirmation": False,
        },
        "safety": {"sample_executed": False, "network_contacted": False, "raw_config_included": False},
    }


def restrict_detector_candidates(
    candidates: Sequence[Mapping[str, Any]],
    document: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """別系統の自称と衝突するdetector-only帰属だけを保留する。"""

    conflicts = set(document.get("conflicting_profiles") or [])
    result = []
    for candidate in candidates:
        normalized = orchestration_outcome.normalize_candidates([candidate])
        if normalized and normalized[0]["family"] in conflicts and normalized[0]["source"] == "detector_selected":
            continue
        result.append(dict(candidate))
    return result
