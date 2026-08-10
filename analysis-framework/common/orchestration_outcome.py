#!/usr/bin/env python3
"""AIを使わないワンショット解析の機械判定結果を正規化する。

検体を実行せず、外部通信も行わない。分類候補と静的解析handlerの証拠を
突き合わせ、Web UIや後続ジョブが判断できる小さな契約へ変換する。
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from itertools import islice
from ipaddress import ip_address
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
        "network_candidates",
        "network_endpoints",
        "static_confirmed_c2",
        "urls",
    }
)
CONFIG_FLAGS = frozenset({"decoded_config_recovered", "static_config_recovered", "configuration_recovered"})
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

    config_recovered = False
    config_candidate_recovered = False
    endpoints: dict[tuple[Any, ...], dict[str, Any]] = {}
    claimed_hashes: set[str] = set()
    output_candidates: dict[tuple[Any, ...], dict[str, Any]] = {}
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
        for evidence_path, value in _walk_evidence(payload):
            key = evidence_path[-1] if evidence_path else ""
            if key in CONFIG_FLAGS and value is True:
                if accepted:
                    config_recovered = True
                else:
                    config_candidate_recovered = True
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

        supplied_outputs = record.get("verified_binary_outputs")
        if isinstance(supplied_outputs, Sequence) and not isinstance(supplied_outputs, (str, bytes, bytearray)):
            for raw_output in islice(supplied_outputs, 256):
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
                if accepted:
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
    terminal_verified = public_outputs(verified_outputs)
    terminal_status = (
        "verified"
        if terminal_verified
        else "candidate"
        if terminal_candidates
        else "claimed"
        if claimed_hashes
        else "unresolved"
    )
    return {
        "config_recovered": config_recovered,
        "config_candidate_recovered": config_candidate_recovered,
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
        "terminal_payload": {
            "status": terminal_status,
            "claimed_sha256": sorted(claimed_hashes),
            "candidates": terminal_candidates,
            "verified": terminal_verified,
        },
        "terminal_payload_sha256": sorted({item["sha256"] for item in terminal_verified}),
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
        "network": _gate(requirements.get("network_required"), bool(outputs["network_endpoints"])),
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
