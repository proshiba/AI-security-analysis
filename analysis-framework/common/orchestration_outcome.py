#!/usr/bin/env python3
"""AIを使わないワンショット解析の機械判定結果を正規化する。

検体を実行せず、外部通信も行わない。分類候補と静的解析handlerの証拠を
突き合わせ、Web UIや後続ジョブが判断できる小さな契約へ変換する。
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from ipaddress import ip_address
from itertools import islice
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from analysis_contract import handler_result_quality

SCHEMA_VERSION = 2
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FAMILY_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
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
        "findings",
        "network_candidates",
        "network_endpoints",
        "static_confirmed_c2",
        "urls",
    }
)
CONFIG_FLAGS = frozenset({"decoded_config_recovered", "static_config_recovered"})
CONFIG_NON_VALUE_KEYS = frozenset(
    {
        *CONFIG_FLAGS,
        "capabilities",
        "classification_confidence",
        "confidence",
        "configuration_recovered",
        "content_exported",
        "error",
        "executed",
        "executed_sample",
        "family",
        "kind",
        "label",
        "limitations",
        "logic",
        "marker_hits",
        "markers",
        "matched",
        "message",
        "name",
        "network_contacted",
        "note",
        "provenance",
        "reason",
        "reviewed",
        "safety",
        "schema_version",
        "sha256",
        "size",
        "source",
        "source_name",
        "status",
        "type",
        "validated",
        "verification",
    }
)
CONFIG_NEGATIVE_VALUES = frozenset(
    {
        "",
        "false",
        "n/a",
        "none",
        "not_applicable",
        "not_found",
        "not_present",
        "not_recovered",
        "unknown",
        "unresolved",
        "unresolved_variant",
    }
)
NETWORK_ENDPOINT_VALUE_KEYS = frozenset({"address", "endpoint", "uri", "url", "value"})
NETWORK_PROTOCOL_KEYS = frozenset({"protocol", "scheme", "transport"})
CONTROL_NETWORK_ROLES = frozenset(
    {
        "c2",
        "command_and_control",
        "control",
        "control_endpoint",
        "exfil",
        "exfiltration",
        "exfiltration_endpoint",
    }
)
NON_CONTROL_ROLE_TOKENS = frozenset(
    {
        "candidate",
        "dead_drop",
        "decoy",
        "delivery",
        "download",
        "landing",
        "legitimate",
        "mirror",
        "osint",
        "payload",
        "redirect",
        "stage",
        "update",
    }
)
REVIEWED_PROTOCOL_FLAGS = frozenset(
    {"protocol_reviewed", "protocol_verified", "reviewed_protocol"}
)
REVIEWED_PROTOCOL_CONFIDENCE = frozenset(
    {
        "confirmed",
        "confirmed_static",
        "confirmed_static_config",
        "high",
        "high_confidence",
        "reviewed",
        "reviewed_static",
    }
)
REVIEWED_PROTOCOL_SOURCE_MARKERS = (
    "decoded",
    "decompiler",
    "dotnet_user_string",
    "recovered",
    "reviewed",
    "static",
)
MINIMUM_HANDLER_TIER = {4: 0, 3: 1, 2: 2, 1: 4, 0: 4}
KNOWN_HASH_EVIDENCE = frozenset({"known_outer_sha256", "known_inner_sha256"})
DETECTOR_EVIDENCE = "type_detector_structure"
METADATA_EVIDENCE = "external_metadata_hint"
MAX_CANDIDATES = 256
MAX_CANDIDATE_EVIDENCE = 256
MAX_EVIDENCE_DEPTH = 24
MAX_EVIDENCE_NODES = 50_000
MAX_CONTAINER_ITEMS = 4_096
VERIFIED_OUTPUT_ROLES = frozenset({"terminal_payload", "final_payload"})
VERIFIED_OUTPUT_KINDS = frozenset({"binary", "pe", "elf", "macho", "script", "archive"})
VERIFIED_OUTPUT_AUDIT_KEYS = frozenset(
    {
        "schema_version",
        "maximum_outputs",
        "maximum_total_size",
        "binary_values_seen",
        "binary_bytes_seen",
        "traversal_items",
        "observed_output_count",
        "retained_output_count",
        "retained_for_follow_on_analysis",
        "follow_on_analysis_complete",
        "observation_scope",
        "truncated",
        "reasons",
    }
)
SENSITIVE_PATH_RE = re.compile(
    r"(?:^|[-_.])(?:auth|bearer|credential|key|pass(?:word)?|secret|session|token|jwt|api[-_]?key)(?:$|[-_.])",
    re.IGNORECASE,
)
OPAQUE_PATH_RE = re.compile(
    r"(?:[0-9a-f]{16,}|[A-Za-z0-9_-]{24,}={0,2}|[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})",
    re.IGNORECASE,
)


def _text(value: object, *, maximum: int = 256) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        return None
    if any(ord(character) < 0x20 for character in normalized):
        return None
    return normalized


def _family(value: object) -> str | None:
    text = _text(value)
    if text is None or text.casefold() in {"unknown", "unresolved", "none"}:
        return None
    family = text.casefold().replace(" ", "-")
    return family if FAMILY_RE.fullmatch(family) else None


def _valid_sha256(value: object) -> str | None:
    return value if isinstance(value, str) and SHA256_RE.fullmatch(value) else None


def _evidence_records(candidate: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    supplied = candidate.get("evidence")
    if not isinstance(supplied, Sequence) or isinstance(supplied, (str, bytes, bytearray)):
        return []
    return [item for item in islice(supplied, MAX_CANDIDATE_EVIDENCE) if isinstance(item, Mapping)]


def _routing_mode(candidate: Mapping[str, Any]) -> tuple[bool, bool]:
    routing = candidate.get("routing_eligibility")
    if not isinstance(routing, Mapping):
        return False, False
    mode = routing.get("mode")
    selected = (
        mode == "selected_family_analysis"
        and routing.get("selected_family_analysis") is True
        and routing.get("family_attribution") is True
    )
    verification = (
        mode == "candidate_verification"
        and routing.get("candidate_verification") is True
        and routing.get("family_attribution") is not True
    )
    return selected, verification


def _canonical_source(candidate: Mapping[str, Any]) -> tuple[str, int, dict[str, int]]:
    """自己申告strengthを無視し、canonical evidenceとroutingだけで強度を返す。"""

    counts = {"known_hash": 0, "detector": 0, "external_metadata": 0}
    for item in _evidence_records(candidate):
        kind = item.get("kind")
        digest = _valid_sha256(item.get("layer_sha256"))
        supports = item.get("supports_attribution")
        confidence = item.get("confidence")
        if kind in KNOWN_HASH_EVIDENCE and digest is not None and supports is True and confidence == "high":
            counts["known_hash"] += 1
        elif kind == DETECTOR_EVIDENCE and digest is not None and supports is True and confidence in {"high", "medium"}:
            counts["detector"] += 1
        elif kind == METADATA_EVIDENCE and supports is False:
            counts["external_metadata"] += 1
    selected, verification = _routing_mode(candidate)
    if counts["known_hash"]:
        return "known_hash", 4, counts
    if counts["detector"] and selected:
        return "detector_selected", 3, counts
    if counts["detector"] and verification:
        return "detector_candidate", 2, counts
    if counts["external_metadata"] and verification:
        return "external_metadata", 1, counts
    return "exhaustive", 0, counts


def _normalized_requirements(candidate: Mapping[str, Any]) -> dict[str, bool]:
    supplied = candidate.get("requirements")
    if not isinstance(supplied, Mapping):
        return {}
    allowed = {
        "config_required",
        "network_required",
        "terminal_payload_required",
        "function_analysis_required",
    }
    return {key: value for key, value in supplied.items() if key in allowed and isinstance(value, bool)}


def normalize_candidates(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """異なる分類器の候補表現を決定的なfamily候補へ変換する。"""

    if len(candidates) > MAX_CANDIDATES:
        raise ValueError("family候補数が安全上限を超えています")
    normalized: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        family = _family(candidate.get("family") or candidate.get("malware_type"))
        if family is None:
            continue
        source, strength, evidence_summary = _canonical_source(candidate)
        selected, verification = _routing_mode(candidate)
        layer_sha256 = candidate.get("layer_sha256")
        if isinstance(layer_sha256, str):
            layer_values = [_valid_sha256(layer_sha256)]
        elif isinstance(layer_sha256, Sequence):
            layer_values = [_valid_sha256(item) for item in layer_sha256[:512]]
        else:
            layer_values = []
        normalized.append(
            {
                "family": family,
                "source": source,
                "source_claim": _text(candidate.get("source"), maximum=128),
                "source_strength": strength,
                "routing_eligible": strength == 4 or selected or verification,
                "attribution_eligible": strength >= 3,
                "metadata_only": source == "external_metadata",
                "layer_sha256": sorted({item for item in layer_values if item}),
                "confidence": {4: "high", 3: "medium", 2: "medium", 1: "unverified", 0: "unverified"}[strength],
                "evidence_summary": evidence_summary,
                "requirements": _normalized_requirements(candidate),
                "input_order": index,
            }
        )
    return sorted(
        normalized,
        key=lambda item: (-item["source_strength"], item["family"], item["input_order"]),
    )


def _handler_payload(record: Mapping[str, Any]) -> Any:
    """execute_handler wrapperを上限付きで剥がし、handler本体の結果を返す。"""

    payload = record.get("result")
    for _depth in range(3):
        if not isinstance(payload, Mapping) or "result" not in payload:
            break
        payload = payload.get("result")
    return payload


def _execution_quality(record: Mapping[str, Any]) -> dict[str, Any]:
    payload = _handler_payload(record)
    return handler_result_quality(payload)


def _quality_declaration_matches(
    declared: object,
    computed: Mapping[str, Any],
) -> bool:
    if not isinstance(declared, Mapping) or declared.get("sufficient") is not True:
        return False
    tier = declared.get("tier")
    score = declared.get("score")
    return (
        isinstance(tier, int)
        and not isinstance(tier, bool)
        and isinstance(score, int)
        and not isinstance(score, bool)
        and tier == computed.get("tier")
        and score == computed.get("score")
        and computed.get("sufficient") is True
    )


def _corroboration_valid(
    record: Mapping[str, Any],
    quality: Mapping[str, Any],
) -> bool:
    """assessor由来のhandler・detector・lineage三点を再検証する。"""

    if record.get("source") != "candidate_verification":
        return False
    if not _quality_declaration_matches(record.get("handler_evidence"), quality):
        return False
    detector = record.get("detector_corroboration")
    if not isinstance(detector, Mapping) or detector.get("corroborated") is not True:
        return False
    if detector.get("basis") not in {
        "known_outer_sha256",
        "known_inner_sha256",
        "detector_structural_evidence",
    }:
        return False
    detector_sha = _valid_sha256(detector.get("layer_sha256"))
    selected_sha = _valid_sha256(record.get("selected_layer_sha256"))
    distance = detector.get("lineage_distance")
    if (
        detector_sha is None
        or selected_sha is None
        or not isinstance(distance, int)
        or isinstance(distance, bool)
        or not 0 <= distance <= 512
    ):
        return False
    return (distance == 0 and detector_sha == selected_sha) or (distance > 0 and detector_sha != selected_sha)


def _succeeded_valid(record: Mapping[str, Any], quality: Mapping[str, Any]) -> bool:
    """selected-family wrapperの成功と十分なhandler証拠を再検証する。"""

    return (
        record.get("source") == "selected_family_analysis"
        and _valid_sha256(record.get("selected_layer_sha256")) is not None
        and _quality_declaration_matches(record.get("selected_evidence"), quality)
    )


def assess_handler_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """flat handler recordを共通schemaで再検証して自己申告を分離する。"""

    quality = _execution_quality(record)
    status = _text(record.get("status")) or "unknown"
    succeeded = status == "succeeded" and _succeeded_valid(record, quality)
    corroborated = status == "corroborated" and _corroboration_valid(record, quality)
    return {
        "status": status,
        "quality": quality,
        "succeeded": succeeded,
        "corroborated": corroborated,
        "accepted": succeeded or corroborated,
    }


def _handler_best_by_family(
    handler_records: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for record in handler_records:
        family = _family(record.get("family"))
        if family is None:
            continue
        assessment = assess_handler_record(record)
        quality = assessment["quality"]
        eligible = assessment["accepted"]
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
                "status": assessment["status"],
                "handler_id": _text(record.get("handler_id")),
                "succeeded": assessment["succeeded"],
                "corroborated": assessment["corroborated"],
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
        if candidate["source_strength"] == 4:
            qualified = candidate["routing_eligible"]
        elif candidate["source_strength"] == 3:
            qualified = bool(candidate["routing_eligible"] and handler.get("succeeded") and tier >= minimum)
        else:
            qualified = bool(candidate["routing_eligible"] and handler.get("corroborated") and tier >= minimum)
        assessed.append(
            {
                **candidate,
                "required_handler_tier": minimum,
                "handler_tier": tier,
                "handler_score": int(handler.get("score", 0)),
                "handler_id": handler.get("handler_id"),
                "handler_corroborated": bool(handler.get("corroborated")),
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


def _sanitize_url_path(value: str) -> str | None:
    """URL pathを非機密segmentだけへ正規化し、token様値を伏字化する。"""

    if not value or value == "/":
        return value or None
    output = []
    redact_next = False
    for raw_segment in value.split("/")[:128]:
        try:
            segment = unquote(raw_segment).strip()
        except (UnicodeError, ValueError):
            segment = ""
        sensitive = bool(SENSITIVE_PATH_RE.search(segment))
        opaque = bool(OPAQUE_PATH_RE.fullmatch(segment))
        unsafe = (
            not segment
            or len(segment) > 128
            or any(ord(character) < 0x20 for character in segment)
            or re.fullmatch(r"[A-Za-z0-9._~-]+", segment) is None
        )
        if raw_segment == "":
            output.append("")
        elif redact_next or opaque or (unsafe and not sensitive):
            output.append("[redacted]")
        elif sensitive:
            output.append("[redacted]")
        else:
            output.append(segment)
        redact_next = sensitive
    rendered = "/".join(output)
    return rendered[:2_048] or None


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
            "path": _sanitize_url_path(parsed.path),
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
    _state: dict[str, Any] | None = None,
) -> Iterator[tuple[tuple[str, ...], Any]]:
    """循環検出とglobal node budget付きで証拠treeを遅延走査する。"""

    state = _state or {"remaining": MAX_EVIDENCE_NODES, "seen": set()}
    if depth > MAX_EVIDENCE_DEPTH or state["remaining"] <= 0:
        return
    is_container = isinstance(value, Mapping) or (
        isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
    )
    if is_container:
        identity = id(value)
        if identity in state["seen"]:
            return
        state["seen"].add(identity)
    if isinstance(value, Mapping):
        for raw_key, item in islice(value.items(), MAX_CONTAINER_ITEMS):
            if state["remaining"] <= 0:
                return
            state["remaining"] -= 1
            key = str(raw_key).casefold()
            child = (*path, key)
            yield child, item
            yield from _walk_evidence(
                item,
                path=child,
                depth=depth + 1,
                _state=state,
            )
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(islice(iter(value), MAX_CONTAINER_ITEMS)):
            if state["remaining"] <= 0:
                return
            state["remaining"] -= 1
            yield from _walk_evidence(
                item,
                path=(*path, str(index)),
                depth=depth + 1,
                _state=state,
            )


def _walk_mappings(value: Any) -> Iterator[tuple[tuple[str, ...], Mapping[str, Any]]]:
    """sequence直下も含め、mappingを循環・深度・総数上限付きで返す。"""

    state: dict[str, Any] = {"remaining": MAX_EVIDENCE_NODES, "seen": set()}

    def visit(
        item: Any,
        *,
        path: tuple[str, ...],
        depth: int,
    ) -> Iterator[tuple[tuple[str, ...], Mapping[str, Any]]]:
        if depth > MAX_EVIDENCE_DEPTH or state["remaining"] <= 0:
            return
        is_container = isinstance(item, Mapping) or (
            isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray))
        )
        if is_container:
            identity = id(item)
            if identity in state["seen"]:
                return
            state["seen"].add(identity)
        if isinstance(item, Mapping):
            yield path, item
            for raw_key, child in islice(item.items(), MAX_CONTAINER_ITEMS):
                if state["remaining"] <= 0:
                    return
                state["remaining"] -= 1
                yield from visit(
                    child,
                    path=(*path, str(raw_key).casefold()),
                    depth=depth + 1,
                )
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for index, child in enumerate(islice(item, MAX_CONTAINER_ITEMS)):
                if state["remaining"] <= 0:
                    return
                state["remaining"] -= 1
                yield from visit(
                    child,
                    path=(*path, str(index)),
                    depth=depth + 1,
                )

    yield from visit(value, path=(), depth=0)


def _meaningful_config_value(value: Any, *, depth: int = 0) -> bool:
    """自己申告flagやmetadataを除き、復元した設定の実値があるか判定する。"""

    if depth > 16 or value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = "_".join(value.strip().casefold().replace("-", " ").split())
        return bool(normalized) and normalized not in CONFIG_NEGATIVE_VALUES and not normalized.startswith(
            ("not_found", "not_recovered", "unknown", "unresolved")
        )
    if isinstance(value, (bytes, bytearray)):
        return bool(value)
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, Mapping):
        return any(
            str(key).casefold() not in CONFIG_NON_VALUE_KEYS
            and _meaningful_config_value(item, depth=depth + 1)
            for key, item in islice(value.items(), MAX_CONTAINER_ITEMS)
        )
    if isinstance(value, Sequence):
        return any(
            _meaningful_config_value(item, depth=depth + 1)
            for item in islice(value, MAX_CONTAINER_ITEMS)
        )
    return False


def _correlated_config_keys(value: Mapping[str, Any]) -> list[str]:
    """config復元flagと同じobjectにある実値keyだけを返す。"""

    return sorted(
        {
            str(raw_key).casefold()
            for raw_key, item in islice(value.items(), MAX_CONTAINER_ITEMS)
            if str(raw_key).casefold() not in CONFIG_NON_VALUE_KEYS
            and _meaningful_config_value(item)
        }
    )[:128]


def _config_evidence_for_record(
    record: Mapping[str, Any],
    payload: Any,
) -> list[dict[str, Any]]:
    """family handlerに相関したconfig実値と、その由来だけを公開用に抽出する。"""

    evidence: dict[tuple[Any, ...], dict[str, Any]] = {}
    for mapping_path, mapping in _walk_mappings(payload):
        correlated_keys = _correlated_config_keys(mapping)
        if not correlated_keys:
            continue
        normalized = {str(key).casefold(): item for key, item in mapping.items()}
        for flag in sorted(CONFIG_FLAGS):
            if normalized.get(flag) is not True:
                continue
            provenance = _provenance(record, (*mapping_path, flag))
            identity = (
                flag,
                tuple(correlated_keys),
                *provenance.values(),
            )
            evidence[identity] = {
                "recovery_type": flag,
                "correlated_keys": correlated_keys,
                "provenance": provenance,
            }
    return [evidence[key] for key in sorted(evidence, key=lambda item: tuple(map(str, item)))]


def _normalized_role(value: object) -> str | None:
    text = _text(value, maximum=128)
    if text is None:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", text.casefold()).strip("_")
    if not normalized or any(token in normalized for token in NON_CONTROL_ROLE_TOKENS):
        return None
    parts = set(normalized.split("_"))
    if normalized in CONTROL_NETWORK_ROLES or "c2" in parts:
        return "c2" if "c2" in parts else normalized
    if "exfil" in normalized:
        return "exfiltration"
    if normalized in {"command_control", "commandandcontrol"} or "control" in parts:
        return "control"
    return None


def _role_from_path(path: tuple[str, ...]) -> str | None:
    for item in reversed(path):
        if item.isdigit():
            continue
        role = _normalized_role(item)
        if role is not None:
            return role
    return None


def _normalized_protocol(value: object) -> str | None:
    text = _text(value, maximum=64)
    if text is None or re.fullmatch(r"[A-Za-z0-9+._()/ -]+", text) is None:
        return None
    return re.sub(r"[- /]+", "_", text.casefold()).strip("_") or None


def _mapping_protocol(value: Mapping[str, Any], endpoint: Mapping[str, Any]) -> str | None:
    normalized = {str(key).casefold(): item for key, item in value.items()}
    for key in sorted(NETWORK_PROTOCOL_KEYS):
        protocol = _normalized_protocol(normalized.get(key))
        if protocol is not None:
            return protocol
    return _normalized_protocol(endpoint.get("scheme"))


def _reviewed_protocol_evidence(value: Mapping[str, Any], protocol: str | None) -> bool:
    """明示的なreview由来または高確度の静的protocol証拠だけを受理する。"""

    if protocol is None:
        return False
    normalized = {str(key).casefold(): item for key, item in value.items()}
    source = _text(normalized.get("source"), maximum=256)
    if source is None:
        source = _text(normalized.get("provenance"), maximum=256)
    if any(normalized.get(flag) is True for flag in REVIEWED_PROTOCOL_FLAGS):
        return source is not None
    confidence = _normalized_protocol(normalized.get("confidence"))
    return bool(
        confidence in REVIEWED_PROTOCOL_CONFIDENCE
        and source is not None
        and any(marker in source.casefold() for marker in REVIEWED_PROTOCOL_SOURCE_MARKERS)
    )


def _mapping_endpoints(
    path: tuple[str, ...],
    value: Mapping[str, Any],
) -> list[tuple[tuple[str, ...], dict[str, Any]]]:
    """構造化network recordから秘密値を除いたendpoint候補を返す。"""

    normalized = {str(key).casefold(): item for key, item in value.items()}
    output: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    for key in sorted(NETWORK_ENDPOINT_VALUE_KEYS):
        supplied = normalized.get(key)
        if not isinstance(supplied, str):
            continue
        endpoint = _endpoint_from_text(supplied)
        if endpoint is not None:
            output.append(((*path, key), endpoint))
    host_value = normalized.get("host", normalized.get("domain"))
    if isinstance(host_value, str):
        host = _valid_host(host_value)
        raw_port = normalized.get("port")
        if isinstance(raw_port, str) and raw_port.isdigit():
            raw_port = int(raw_port)
        port = raw_port if isinstance(raw_port, int) and not isinstance(raw_port, bool) else None
        if host is not None and (port is None or 1 <= port <= 65_535):
            output.append(
                (
                    (*path, "host"),
                    {
                        "host": host,
                        "port": port,
                        "scheme": None,
                        "path": None,
                    },
                )
            )
    unique: dict[tuple[Any, ...], tuple[tuple[str, ...], dict[str, Any]]] = {}
    for endpoint_path, endpoint in output:
        identity = (
            endpoint["host"],
            endpoint["port"],
            endpoint["scheme"],
            endpoint["path"],
        )
        unique.setdefault(identity, (endpoint_path, endpoint))
    return [unique[key] for key in sorted(unique, key=lambda item: tuple(map(str, item)))]


def _verified_binary_output(value: object) -> dict[str, Any] | None:
    """wrapperが実bytesで検証したbinary outputだけを厳格schemaで受理する。"""

    if not isinstance(value, Mapping) or set(value) != {
        "role",
        "kind",
        "path",
        "sha256",
        "size",
        "verification",
    }:
        return None
    role = value.get("role")
    kind = value.get("kind")
    path = _text(value.get("path"), maximum=1_024)
    digest = _valid_sha256(value.get("sha256"))
    size = value.get("size")
    verification = value.get("verification")
    if (
        role not in VERIFIED_OUTPUT_ROLES
        or kind not in VERIFIED_OUTPUT_KINDS
        or path is None
        or chr(92) in path
        or ":" in path
        or PurePosixPath(path).is_absolute()
        or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
        or re.fullmatch(r"[A-Za-z0-9_$./\[\]-]+", path) is None
        or digest is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 < size <= 2**63 - 1
        or not isinstance(verification, Mapping)
        or set(verification) != {"status", "sha256_matches", "size_matches"}
        or verification.get("status") != "artifact_hash_verified"
        or verification.get("sha256_matches") is not True
        or verification.get("size_matches") is not True
    ):
        return None
    return {
        "role": role,
        "kind": kind,
        "path": path,
        "sha256": digest,
        "size": size,
        "verification": {
            "status": "artifact_hash_verified",
            "sha256_matches": True,
            "size_matches": True,
        },
    }


def _verified_output_audit(value: object, *, output_count: int) -> dict[str, Any] | None:
    """親processの再hash済み保持auditだけを厳格schemaで受理する。"""

    if not isinstance(value, Mapping) or set(value) != VERIFIED_OUTPUT_AUDIT_KEYS:
        return None
    integer_keys = (
        "maximum_outputs",
        "maximum_total_size",
        "binary_values_seen",
        "binary_bytes_seen",
        "traversal_items",
        "observed_output_count",
        "retained_output_count",
    )
    if any(
        not isinstance(value.get(key), int)
        or isinstance(value.get(key), bool)
        or int(value[key]) < 0
        for key in integer_keys
    ):
        return None
    reasons = value.get("reasons")
    if (
        value.get("schema_version") != 1
        or value.get("maximum_outputs") != 64
        or value.get("maximum_total_size") != 256 * 1024 * 1024
        or value.get("retained_output_count") != output_count
        or int(value.get("observed_output_count", 0)) < output_count
        or value.get("retained_for_follow_on_analysis") is not True
        or value.get("observation_scope") != "parent_rehashed_case_artifact"
        or type(value.get("follow_on_analysis_complete")) is not bool
        or type(value.get("truncated")) is not bool
        or not isinstance(reasons, Sequence)
        or isinstance(reasons, (str, bytes, bytearray))
        or any(not isinstance(item, str) or not item for item in reasons)
        or list(reasons) != sorted(set(reasons))
    ):
        return None
    return {
        "retained": True,
        "analysis_complete": value.get("follow_on_analysis_complete") is True,
    }


def _provenance(record: Mapping[str, Any], evidence_path: tuple[str, ...]) -> dict[str, str]:
    return {
        "family": _family(record.get("family")) or "unknown",
        "handler_id": _text(record.get("handler_id"), maximum=256) or "unknown",
        "source": _text(record.get("source"), maximum=64) or "unknown",
        "evidence_path": ".".join(evidence_path)[:1_024],
    }


def _sorted_provenance(values: set[tuple[str, str, str, str]]) -> list[dict[str, str]]:
    return [
        {
            "family": family,
            "handler_id": handler_id,
            "source": source,
            "evidence_path": evidence_path,
        }
        for family, handler_id, source, evidence_path in sorted(values)
    ]


def summarize_handler_outputs(
    handler_records: Sequence[Mapping[str, Any]],
    *,
    family_filter: str | None = None,
    verified_only: bool = True,
) -> dict[str, Any]:
    """再検証済みhandler出力からconfig・通信先・後段payloadを正規化する。"""

    config_evidence: dict[tuple[Any, ...], dict[str, Any]] = {}
    config_candidate_evidence: dict[tuple[Any, ...], dict[str, Any]] = {}
    endpoints: dict[tuple[Any, ...], dict[str, Any]] = {}
    qualified_endpoints: dict[tuple[Any, ...], dict[str, Any]] = {}
    claimed_hashes: set[str] = set()
    output_candidates: dict[tuple[Any, ...], dict[str, Any]] = {}
    retained_outputs: dict[tuple[Any, ...], dict[str, Any]] = {}
    verified_outputs: dict[tuple[Any, ...], dict[str, Any]] = {}
    for record in handler_records:
        record_family = _family(record.get("family"))
        if family_filter is not None and record_family != _family(family_filter):
            continue
        assessment = assess_handler_record(record)
        accepted = assessment["accepted"]
        if verified_only and not accepted:
            continue
        if not accepted and assessment["quality"].get("sufficient") is not True:
            continue
        payload = _handler_payload(record)
        record_config_evidence = _config_evidence_for_record(record, payload)
        config_destination = config_evidence if accepted else config_candidate_evidence
        for item in record_config_evidence:
            provenance = item["provenance"]
            identity = (
                item["recovery_type"],
                tuple(item["correlated_keys"]),
                *provenance.values(),
            )
            config_destination[identity] = item

        def retain_qualified_endpoint(
            endpoint: Mapping[str, Any],
            *,
            evidence_path: tuple[str, ...],
            role: str,
            protocol: str | None,
            evidence_basis: Sequence[str],
            _record: Mapping[str, Any] = record,
        ) -> None:
            identity = (
                endpoint["host"],
                endpoint["port"],
                endpoint["scheme"],
                endpoint["path"],
                role,
                protocol,
            )
            entry = qualified_endpoints.setdefault(
                identity,
                {
                    **endpoint,
                    "role": role,
                    "protocol": protocol,
                    "contacted": False,
                    "_evidence_basis": set(),
                    "_provenance": set(),
                },
            )
            entry["_evidence_basis"].update(evidence_basis)
            provenance = _provenance(_record, evidence_path)
            entry["_provenance"].add(tuple(provenance.values()))

        for evidence_path, value in _walk_evidence(payload):
            key = evidence_path[-1] if evidence_path else ""
            if (
                key == "sha256"
                and isinstance(value, str)
                and SHA256_RE.fullmatch(value)
                and any(part in {"final_payload", "terminal_payload", "payload_sha256"} for part in evidence_path)
            ):
                claimed_hashes.add(value)
            if not any(part in NETWORK_KEYS for part in evidence_path):
                continue
            values = [value] if isinstance(value, str) else []
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                values.extend(item for item in islice(value, MAX_CONTAINER_ITEMS) if isinstance(item, str))
            for item in values:
                endpoint = _endpoint_from_text(item)
                if endpoint is None:
                    continue
                identity = (
                    endpoint["host"],
                    endpoint["port"],
                    endpoint["scheme"],
                    endpoint["path"],
                )
                entry = endpoints.setdefault(
                    identity,
                    {**endpoint, "contacted": False, "_provenance": set()},
                )
                provenance = _provenance(record, evidence_path)
                entry["_provenance"].add(tuple(provenance.values()))
                role = _role_from_path(evidence_path)
                if accepted and role is not None and record_config_evidence:
                    retain_qualified_endpoint(
                        endpoint,
                        evidence_path=evidence_path,
                        role=role,
                        protocol=_normalized_protocol(endpoint.get("scheme")),
                        evidence_basis=("static_config_correlation",),
                    )

        for mapping_path, mapping in _walk_mappings(payload):
            role = _normalized_role(mapping.get("role")) or _role_from_path(mapping_path)
            if role is None:
                continue
            for endpoint_path, endpoint in _mapping_endpoints(mapping_path, mapping):
                protocol = _mapping_protocol(mapping, endpoint)
                evidence_basis = []
                if record_config_evidence:
                    evidence_basis.append("static_config_correlation")
                if _reviewed_protocol_evidence(mapping, protocol):
                    evidence_basis.append("reviewed_protocol_evidence")
                if accepted and evidence_basis:
                    retain_qualified_endpoint(
                        endpoint,
                        evidence_path=endpoint_path,
                        role=role,
                        protocol=protocol,
                        evidence_basis=evidence_basis,
                    )

        supplied_outputs = record.get("verified_binary_outputs")
        if isinstance(supplied_outputs, Sequence) and not isinstance(supplied_outputs, (str, bytes, bytearray)):
            bounded_outputs = list(islice(supplied_outputs, 256))
            retention = _verified_output_audit(
                record.get("verified_binary_output_audit"),
                output_count=len(bounded_outputs),
            )
            for raw_output in bounded_outputs:
                output = _verified_binary_output(raw_output)
                if output is None:
                    continue
                identity = (
                    output["role"],
                    output["kind"],
                    output["path"],
                    output["sha256"],
                    output["size"],
                )
                provenance = _provenance(record, ("verified_binary_outputs",))
                candidate = output_candidates.setdefault(identity, {**output, "_provenance": set()})
                candidate["_provenance"].add(tuple(provenance.values()))
                if accepted and retention is not None:
                    retained = retained_outputs.setdefault(identity, {**output, "_provenance": set()})
                    retained["_provenance"].add(tuple(provenance.values()))
                if accepted and retention is not None and retention["analysis_complete"]:
                    verified = verified_outputs.setdefault(identity, {**output, "_provenance": set()})
                    verified["_provenance"].add(tuple(provenance.values()))

    def public_outputs(values: Mapping[tuple[Any, ...], dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                **{key: value for key, value in values[identity].items() if key != "_provenance"},
                "provenance": _sorted_provenance(values[identity]["_provenance"]),
            }
            for identity in sorted(values, key=lambda item: tuple(map(str, item)))
        ]

    terminal_candidates = public_outputs(output_candidates)
    terminal_retained = public_outputs(retained_outputs)
    terminal_verified = public_outputs(verified_outputs)
    terminal_status = (
        "verified"
        if terminal_verified
        else "retained_pending_analysis"
        if terminal_retained
        else "candidate"
        if terminal_candidates
        else "claimed"
        if claimed_hashes
        else "unresolved"
    )
    public_config_evidence = [
        config_evidence[key]
        for key in sorted(config_evidence, key=lambda item: tuple(map(str, item)))
    ]
    public_config_candidate_evidence = [
        config_candidate_evidence[key]
        for key in sorted(config_candidate_evidence, key=lambda item: tuple(map(str, item)))
    ]
    return {
        "config_recovered": bool(public_config_evidence),
        "config_candidate_recovered": bool(public_config_candidate_evidence),
        "config_evidence": public_config_evidence,
        "config_candidate_evidence": public_config_candidate_evidence,
        "network_endpoints": [
            {
                **{key: value for key, value in endpoints[identity].items() if key != "_provenance"},
                "provenance": _sorted_provenance(endpoints[identity]["_provenance"]),
            }
            for identity in sorted(
                endpoints,
                key=lambda item: tuple("" if value is None else str(value) for value in item),
            )
        ],
        "qualified_network_endpoints": [
            {
                **{
                    key: value
                    for key, value in qualified_endpoints[identity].items()
                    if key not in {"_evidence_basis", "_provenance"}
                },
                "evidence_basis": sorted(qualified_endpoints[identity]["_evidence_basis"]),
                "provenance": _sorted_provenance(
                    qualified_endpoints[identity]["_provenance"]
                ),
            }
            for identity in sorted(
                qualified_endpoints,
                key=lambda item: tuple("" if value is None else str(value) for value in item),
            )
        ],
        "terminal_payload": {
            "status": terminal_status,
            "claimed_sha256": sorted(claimed_hashes),
            "candidates": terminal_candidates,
            "retained": terminal_retained,
            "verified": terminal_verified,
        },
        "retained_terminal_payload_sha256": sorted({item["sha256"] for item in terminal_retained}),
        "terminal_payload_sha256": sorted({item["sha256"] for item in terminal_verified}),
        "retained_binary_outputs": terminal_retained,
        "verified_binary_outputs": terminal_verified,
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
    candidate_outputs = summarize_handler_outputs(
        handler_records,
        verified_only=False,
    )
    if resolution["status"] == "resolved":
        outputs = summarize_handler_outputs(
            handler_records,
            family_filter=resolution["family"],
        )
    else:
        outputs = summarize_handler_outputs([])
    requirements = resolution.get("requirements") if resolution["status"] == "resolved" else {}
    if not isinstance(requirements, Mapping):
        requirements = {}
    resolved_family = resolution.get("family")
    handler_succeeded = any(
        _family(record.get("family")) == resolved_family and assess_handler_record(record)["accepted"]
        for record in handler_records
    )
    gates = {
        "generic_triage": _gate(True, generic_status == "complete"),
        "static_layers": _gate(True, layer_status in {"complete", "artifacts_recovered"}),
        "family_resolution": _gate(True, resolution["status"] == "resolved"),
        "handler_evidence": _gate(
            resolution["status"] == "resolved",
            handler_succeeded,
        ),
        "config": _gate(requirements.get("config_required"), outputs["config_recovered"]),
        "network": _gate(
            requirements.get("network_required"),
            bool(outputs["qualified_network_endpoints"]),
            observed=bool(outputs["network_endpoints"]),
        ),
        "terminal_payload": _gate(
            requirements.get("terminal_payload_required"), bool(outputs["terminal_payload_sha256"])
        ),
        "function_analysis": _gate(requirements.get("function_analysis_required"), function_analysis_available),
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
        "candidate_outputs": candidate_outputs,
        "quality_gates": gates,
        "blockers": blockers,
        "next_actions_ja": [next_actions[item] for item in blockers],
        "automation": {"ai_used": False, "sample_executed": False, "network_contacted": False},
    }
