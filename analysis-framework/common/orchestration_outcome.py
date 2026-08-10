#!/usr/bin/env python3
"""AIを使わないワンショット解析の機械判定結果を正規化する。

検体を実行せず、外部通信も行わない。分類候補と静的解析handlerの証拠を
突き合わせ、Web UIや後続ジョブが判断できる小さな契約へ変換する。
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from analysis_contract import handler_result_quality

SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HOST_PORT_RE = re.compile(
    r"^(?P<host>\[[0-9A-Fa-f:]+\]|[A-Za-z0-9][A-Za-z0-9.-]{0,252})"
    r":(?P<port>[0-9]{1,5})$"
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
NETWORK_KEYS = frozenset(
    {
        "c2",
        "c2_candidates",
        "config_endpoints",
        "endpoints",
        "network_candidates",
        "network_endpoints",
        "static_confirmed_c2",
        "urls",
    }
)
CONFIG_FLAGS = frozenset(
    {"decoded_config_recovered", "static_config_recovered", "configuration_recovered"}
)
SOURCE_STRENGTH = {
    "known_hash": 4,
    "trusted_hash_manifest": 4,
    "explicit_operator_selection": 4,
    "detector_selected": 3,
    "detector": 3,
    "detector_and_external_metadata": 3,
    "detector_candidate": 2,
    "external_metadata": 1,
    "handler_only": 0,
    "exhaustive": 0,
}
MINIMUM_HANDLER_TIER = {4: 0, 3: 1, 2: 2, 1: 4, 0: 4}


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _family(value: object) -> str | None:
    text = _text(value)
    if text is None or text.casefold() in {"unknown", "unresolved", "none"}:
        return None
    return text.casefold().replace(" ", "-")


def _source_strength(candidate: Mapping[str, Any]) -> tuple[str, int]:
    source = _text(candidate.get("source")) or _text(candidate.get("basis")) or "exhaustive"
    explicit = candidate.get("source_strength")
    if isinstance(explicit, int) and not isinstance(explicit, bool):
        return source, max(0, min(explicit, 4))
    if explicit == "high":
        evidence = candidate.get("evidence")
        if isinstance(evidence, Sequence) and any(
            isinstance(item, Mapping)
            and item.get("kind") in {"known_outer_sha256", "known_inner_sha256"}
            for item in evidence
        ):
            return source, 4
        return source, 3
    if explicit == "medium":
        if candidate.get("routing_mode") == "selected_family_analysis":
            return source, 3
        return source, 2
    if explicit == "unverified":
        return source, 1
    return source, SOURCE_STRENGTH.get(source, 0)


def normalize_candidates(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """異なる分類器の候補表現を決定的なfamily候補へ変換する。"""

    normalized: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        family = _family(candidate.get("family") or candidate.get("malware_type"))
        if family is None:
            continue
        source, strength = _source_strength(candidate)
        normalized.append(
            {
                "family": family,
                "source": source,
                "source_strength": strength,
                "routing_eligible": candidate.get("routing_eligible", True) is True,
                "layer_sha256": _text(candidate.get("layer_sha256")),
                "confidence": _text(candidate.get("confidence")),
                "reason": _text(candidate.get("reason")),
                "requirements": (
                    dict(candidate["requirements"])
                    if isinstance(candidate.get("requirements"), Mapping)
                    else {}
                ),
                "input_order": index,
            }
        )
    return sorted(
        normalized,
        key=lambda item: (-item["source_strength"], item["family"], item["input_order"]),
    )


def _execution_quality(record: Mapping[str, Any]) -> dict[str, Any]:
    selected = record.get("selected_evidence")
    if isinstance(selected, Mapping) and isinstance(selected.get("tier"), int):
        return dict(selected)
    payload = record.get("result")
    if isinstance(payload, Mapping) and "result" in payload:
        payload = payload.get("result")
    return handler_result_quality(payload)


def _handler_best_by_family(
    handler_records: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for record in handler_records:
        family = _family(record.get("family"))
        if family is None:
            continue
        quality = _execution_quality(record)
        status = _text(record.get("status")) or "unknown"
        eligible = status in {
            "succeeded",
            "candidate_evidence",
            "no_evidence",
            "ambiguous_evidence",
            "assessed",
        }
        rank = (
            int(quality.get("tier", 0)) if eligible else 0,
            int(quality.get("score", 0)) if eligible else 0,
        )
        current = best.get(family)
        if current is None or rank > current["rank"]:
            best[family] = {
                "rank": rank,
                "tier": rank[0],
                "score": rank[1],
                "status": status,
                "handler_id": _text(record.get("handler_id")),
            }
    return best


def resolve_family(
    candidates: Sequence[Mapping[str, Any]],
    handler_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """候補の出所に応じた証拠tierを要求し、一意なfamilyだけを確定する。"""

    normalized = normalize_candidates(candidates)
    handler_best = _handler_best_by_family(handler_records)
    assessed: list[dict[str, Any]] = []
    for candidate in normalized:
        handler = handler_best.get(candidate["family"], {})
        tier = int(handler.get("tier", 0))
        minimum = MINIMUM_HANDLER_TIER[candidate["source_strength"]]
        qualified = candidate["routing_eligible"] and tier >= minimum
        assessed.append(
            {
                **candidate,
                "required_handler_tier": minimum,
                "handler_tier": tier,
                "handler_score": int(handler.get("score", 0)),
                "handler_id": handler.get("handler_id"),
                "qualified": qualified,
                "rank": [candidate["source_strength"], tier, int(handler.get("score", 0))],
            }
        )
    qualified = [item for item in assessed if item["qualified"]]
    if not qualified:
        return {
            "status": "unresolved",
            "family": None,
            "reason": "no_candidate_met_evidence_threshold",
            "candidates": assessed,
        }
    best_by_family: dict[str, dict[str, Any]] = {}
    for item in qualified:
        current = best_by_family.get(item["family"])
        if current is None or tuple(item["rank"]) > tuple(current["rank"]):
            best_by_family[item["family"]] = item
    top_rank = max(tuple(item["rank"]) for item in best_by_family.values())
    winners = sorted(
        (item for item in best_by_family.values() if tuple(item["rank"]) == top_rank),
        key=lambda item: item["family"],
    )
    if len(winners) != 1:
        return {
            "status": "ambiguous",
            "family": None,
            "reason": "multiple_families_share_strongest_evidence",
            "winning_families": [item["family"] for item in winners],
            "candidates": assessed,
        }
    winner = winners[0]
    return {
        "status": "resolved",
        "family": winner["family"],
        "reason": "unique_strongest_corroborated_candidate",
        "source": winner["source"],
        "source_strength": winner["source_strength"],
        "handler_tier": winner["handler_tier"],
        "handler_id": winner["handler_id"],
        "requirements": winner["requirements"],
        "candidates": assessed,
    }


def _valid_host(value: str) -> str | None:
    host = value.strip().strip("[]").rstrip(".").casefold()
    try:
        return str(ip_address(host))
    except ValueError:
        return host if DOMAIN_RE.fullmatch(host) else None


def _endpoint_from_text(value: str) -> dict[str, Any] | None:
    text = value.strip()
    if not text or len(text) > 4_096:
        return None
    if "://" in text:
        try:
            parsed = urlsplit(text)
            host = _valid_host(parsed.hostname or "")
            port = parsed.port
        except ValueError:
            return None
        if host is None or parsed.scheme.casefold() not in {"http", "https", "ftp", "tcp", "udp"}:
            return None
        return {
            "host": host,
            "port": port,
            "scheme": parsed.scheme.casefold(),
            "path": parsed.path[:2_048] or None,
        }
    match = HOST_PORT_RE.fullmatch(text)
    if match:
        host = _valid_host(match.group("host"))
        port = int(match.group("port"))
        if host is not None and 1 <= port <= 65_535:
            return {"host": host, "port": port, "scheme": None, "path": None}
        return None
    host = _valid_host(text)
    return {"host": host, "port": None, "scheme": None, "path": None} if host else None


def _walk_evidence(
    value: Any,
    *,
    path: tuple[str, ...] = (),
    depth: int = 0,
) -> list[tuple[tuple[str, ...], Any]]:
    if depth > 24:
        return []
    found: list[tuple[tuple[str, ...], Any]] = []
    if isinstance(value, Mapping):
        for index, (raw_key, item) in enumerate(value.items()):
            if index >= 20_000:
                break
            key = str(raw_key).casefold()
            child = (*path, key)
            found.append((child, item))
            found.extend(_walk_evidence(item, path=child, depth=depth + 1))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value[:20_000]):
            found.extend(_walk_evidence(item, path=(*path, str(index)), depth=depth + 1))
    return found


def summarize_handler_outputs(
    handler_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """handler出力からconfig、通信先、後段payloadの事実だけを抽出する。"""

    config_recovered = False
    endpoints: dict[tuple[Any, ...], dict[str, Any]] = {}
    terminal_hashes: set[str] = set()
    for record in handler_records:
        handler_id = _text(record.get("handler_id"))
        payload = record.get("result")
        if isinstance(payload, Mapping) and "result" in payload:
            payload = payload.get("result")
        for path, value in _walk_evidence(payload):
            key = path[-1] if path else ""
            if key in CONFIG_FLAGS and value is True:
                config_recovered = True
            if (
                key == "sha256"
                and isinstance(value, str)
                and SHA256_RE.fullmatch(value)
                and any(
                    part in {"final_payload", "terminal_payload", "payload_sha256"}
                    for part in path
                )
            ):
                terminal_hashes.add(value)
            if not any(part in NETWORK_KEYS for part in path):
                continue
            values = [value] if isinstance(value, str) else []
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                values.extend(item for item in value if isinstance(item, str))
            for item in values:
                endpoint = _endpoint_from_text(item)
                if endpoint is None:
                    continue
                identity = (
                    endpoint["host"], endpoint["port"], endpoint["scheme"], endpoint["path"]
                )
                endpoints[identity] = {**endpoint, "handler_id": handler_id, "contacted": False}
    return {
        "config_recovered": config_recovered,
        "network_endpoints": [endpoints[key] for key in sorted(endpoints)],
        "terminal_payload_sha256": sorted(terminal_hashes),
    }


def _gate(required: object, satisfied: bool, *, observed: bool | None = None) -> dict[str, Any]:
    if required is False:
        status = "not_applicable"
    elif satisfied:
        status = "satisfied"
    elif required is True:
        status = "required_missing"
    else:
        status = "not_declared"
    return {"required": required, "satisfied": satisfied, "observed": observed, "status": status}


def build_outcome(
    *,
    sample_sha256: str,
    generic_status: str,
    layer_status: str,
    candidates: Sequence[Mapping[str, Any]],
    handler_records: Sequence[Mapping[str, Any]],
    function_analysis_available: bool,
) -> dict[str, Any]:
    """UIと自動ジョブが利用する最終品質ゲートを構築する。"""

    if not SHA256_RE.fullmatch(sample_sha256):
        raise ValueError("sample_sha256は小文字SHA-256で指定してください")
    resolution = resolve_family(candidates, handler_records)
    outputs = summarize_handler_outputs(handler_records)
    requirements = resolution.get("requirements") if resolution["status"] == "resolved" else {}
    if not isinstance(requirements, Mapping):
        requirements = {}
    handler_succeeded = any(record.get("status") == "succeeded" for record in handler_records)
    gates = {
        "generic_triage": _gate(True, generic_status == "complete"),
        "static_layers": _gate(True, layer_status in {"complete", "artifacts_recovered"}),
        "family_resolution": _gate(True, resolution["status"] == "resolved"),
        "handler_evidence": _gate(
            resolution["status"] == "resolved", handler_succeeded or resolution.get("source_strength") == 4
        ),
        "config": _gate(requirements.get("config_required"), outputs["config_recovered"]),
        "network": _gate(
            requirements.get("network_required"), bool(outputs["network_endpoints"])
        ),
        "terminal_payload": _gate(
            requirements.get("terminal_payload_required"), bool(outputs["terminal_payload_sha256"])
        ),
        "function_analysis": _gate(
            requirements.get("function_analysis_required"), function_analysis_available
        ),
    }
    blockers = sorted(name for name, gate in gates.items() if gate["status"] == "required_missing")
    if blockers:
        status = "partial"
    elif resolution["status"] == "resolved":
        status = "complete"
    elif generic_status == "complete" and layer_status in {"complete", "artifacts_recovered"}:
        status = "triaged_unknown"
    else:
        status = "partial"
    next_actions = {
        "generic_triage": "汎用静的triageの失敗または部分結果を再処理してください。",
        "static_layers": "静的展開上限と未対応containerを確認してください。",
        "family_resolution": "候補familyのdetectorまたは構造証拠を追加してください。",
        "handler_evidence": "候補familyのhandlerを修正し、構造証拠を回収してください。",
        "config": "family固有config extractorを追加または更新してください。",
        "network": "復号configから通信先を抽出する処理を追加してください。",
        "terminal_payload": "後段payloadの静的復元処理を追加してください。",
        "function_analysis": "特徴関数と全体ロジックの静的解析を追加してください。",
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_sha256": sample_sha256,
        "status": status,
        "family_resolution": resolution,
        "outputs": outputs,
        "quality_gates": gates,
        "blockers": blockers,
        "next_actions_ja": [next_actions[item] for item in blockers],
        "automation": {"ai_used": False, "sample_executed": False, "network_contacted": False},
    }
