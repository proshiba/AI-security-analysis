#!/usr/bin/env python3
"""公開case間の強い共有証拠から攻撃キャンペーン候補を相関する。"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit


DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
ENDPOINT_RE = re.compile(r"^(\[[0-9a-f:]+\]|[a-z0-9.-]+):(\d{1,5})$", re.IGNORECASE)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


@dataclass(frozen=True)
class Indicator:
    """campaign相関へ使う公開済み指標。"""

    type: str
    value: str
    role: str
    confidence: str
    source: str

    @property
    def key(self) -> tuple[str, str]:
        return self.type, self.value.casefold()


def load_rules(path: Path) -> dict[str, Any]:
    """相関ルールを読込み、必須schemaを検証する。"""

    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("unsupported campaign correlation rule schema")
    if not isinstance(value.get("thresholds"), dict) or not isinstance(value.get("weights"), dict):
        raise ValueError("campaign correlation rules require thresholds and weights")
    return value


def _normalize_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"http", "https", "ftp"} or not parsed.hostname:
        return None
    host = parsed.hostname.casefold().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.casefold(), netloc, path, "", ""))


def _normalize_indicator(kind: str, value: str) -> tuple[str, str] | None:
    kind = kind.strip().casefold()
    value = value.strip().strip("`\"'").rstrip(".,;)]}")
    if not value or value == "-":
        return None
    if kind == "url" or value.casefold().startswith(("http://", "https://", "ftp://")):
        normalized = _normalize_url(value)
        return ("url", normalized) if normalized else None
    if kind in {"sha256", "hash", "file_sha256", "artifact_hash"}:
        lowered = value.casefold()
        return ("artifact_hash", lowered) if SHA256_RE.fullmatch(lowered) else None
    if kind == "endpoint":
        match = ENDPOINT_RE.fullmatch(value)
        if not match or int(match.group(2)) > 65535:
            return None
        return "endpoint", value.casefold()
    if kind == "ip":
        try:
            return "ip", str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if kind == "domain":
        lowered = value.casefold().rstrip(".")
        return ("domain", lowered) if DOMAIN_RE.fullmatch(lowered) else None
    if kind == "certificate_sha256":
        lowered = value.casefold().replace(":", "")
        return ("certificate_sha256", lowered) if SHA256_RE.fullmatch(lowered) else None
    normalized_url = _normalize_url(value)
    if normalized_url:
        return "url", normalized_url
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    endpoint = ENDPOINT_RE.fullmatch(value)
    if endpoint and int(endpoint.group(2)) <= 65535:
        return "endpoint", value.casefold()
    lowered = value.casefold().rstrip(".")
    if DOMAIN_RE.fullmatch(lowered):
        return "domain", lowered
    return None


def _indicator_is_excluded(kind: str, value: str, rules: Mapping[str, Any]) -> bool:
    """正規参照先、非global address、ファイル名誤認をcampaign証拠から除外する。"""

    host = ""
    if kind == "url":
        host = (urlsplit(value).hostname or "").casefold()
    elif kind == "endpoint":
        host = value.rsplit(":", 1)[0].strip("[]").casefold()
    elif kind in {"domain", "ip"}:
        host = value.casefold()
    if kind == "domain" and any(
        value.casefold().endswith(str(suffix).casefold()) for suffix in rules.get("excluded_domain_suffixes", [])
    ):
        return True
    excluded_hosts = {str(item).casefold().rstrip(".") for item in rules.get("excluded_indicator_hosts", [])}
    if host and any(
        host == item or host.endswith(f".{item}") or re.search(rf"(?:^|\.){re.escape(item)}\d+$", host)
        for item in excluded_hosts
    ):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not address.is_global


def _parse_ioc_list(path: Path, rules: Mapping[str, Any], root_sha256: str) -> list[Indicator]:
    if not path.is_file():
        return []
    excluded = tuple(str(item).casefold() for item in rules.get("excluded_role_markers", []))
    output = []
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        if not line.startswith("|") or "---" in line:
            continue
        columns = [item.strip() for item in line.strip("|").split("|")]
        if len(columns) < 5 or columns[0] in {"種別", "種別 (Type)"}:
            continue
        kind, value, role, confidence, _ = columns[:5]
        context = f"{role} {confidence}".casefold()
        if any(marker in context for marker in excluded):
            continue
        normalized = _normalize_indicator(kind, value)
        if normalized is None:
            continue
        normalized_kind, normalized_value = normalized
        if _indicator_is_excluded(normalized_kind, normalized_value, rules):
            continue
        if normalized_kind == "artifact_hash" and normalized_value == root_sha256:
            continue
        if normalized_kind == "artifact_hash" and not any(
            marker in role.casefold()
            for marker in (
                "payload",
                "component",
                "embedded",
                "loader",
                "child",
                "内包",
                "復元",
                "子要素",
            )
        ):
            continue
        output.append(Indicator(normalized_kind, normalized_value, role, confidence, "IOC-LIST.md"))
    return output


def _walk_scalars(value: Any, parents: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk_scalars(child, (*parents, str(key)))
    elif isinstance(value, list):
        for child in value:
            yield from _walk_scalars(child, parents)
    elif isinstance(value, str):
        yield parents, value


def _json_fallback_indicators(case_dir: Path, rules: Mapping[str, Any], root_sha256: str) -> list[Indicator]:
    excluded = tuple(str(item).casefold() for item in rules.get("excluded_role_markers", []))
    output = []
    for path in sorted(case_dir.rglob("*.json")):
        if path.name in {"features.json", "campaign-labels.json"}:
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        for parents, scalar in _walk_scalars(value):
            context = " ".join(parents).casefold()
            if not any(
                marker in context for marker in ("c2", "endpoint", "domain", "host", "url", "server", "network")
            ):
                continue
            if any(marker in context for marker in excluded):
                continue
            normalized = _normalize_indicator(parents[-1] if parents else "", scalar)
            if normalized is None or normalized[1] == root_sha256:
                continue
            if _indicator_is_excluded(normalized[0], normalized[1], rules):
                continue
            output.append(Indicator(normalized[0], normalized[1], context, "candidate", path.name))
    return output


def extract_campaign_evidence(case_dir: Path, profile: Mapping[str, Any], rules: Mapping[str, Any]) -> dict[str, Any]:
    """caseからcampaign相関用の指標と特徴IDを抽出する。"""

    root_sha256 = str(profile["sha256"]).casefold()
    indicators = _parse_ioc_list(case_dir / "IOC-LIST.md", rules, root_sha256)
    if not indicators:
        indicators = _json_fallback_indicators(case_dir, rules, root_sha256)
    unique = {}
    for item in indicators:
        unique.setdefault(item.key, item)
    feature_ids = {
        str(item["id"])
        for item in (*profile.get("sample_characteristics", []), *profile.get("behaviors", []))
        if isinstance(item, Mapping) and item.get("id")
    }
    return {
        "sha256": root_sha256,
        "family": str(profile.get("family") or "unknown"),
        "campaign_type": str(profile.get("campaign_type") or "unknown"),
        "feature_ids": sorted(feature_ids),
        "indicators": [
            {
                "type": item.type,
                "value": item.value,
                "role": item.role,
                "confidence": item.confidence,
                "source": item.source,
            }
            for item in sorted(unique.values(), key=lambda value: value.key)
        ],
    }


def _indicator_map(evidence: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
    return {
        (str(item["type"]), str(item["value"]).casefold()): item
        for item in evidence.get("indicators", [])
        if isinstance(item, Mapping) and item.get("type") and item.get("value")
    }


def score_pair(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    rules: Mapping[str, Any],
    indicator_frequency: Mapping[tuple[str, str], int],
    feature_frequency: Mapping[str, int],
) -> dict[str, Any] | None:
    """2 caseの相関scoreを算出し、閾値未満ならNoneを返す。"""

    thresholds = rules["thresholds"]
    weights = rules["weights"]
    left_indicators = _indicator_map(left)
    right_indicators = _indicator_map(right)
    shared_keys = set(left_indicators) & set(right_indicators)
    shared_keys = {
        key for key in shared_keys if indicator_frequency.get(key, 0) <= thresholds["max_indicator_prevalence"]
    }
    same_family = left["family"] == right["family"] and left["family"] != "unknown"
    generic = {str(item).casefold() for item in rules["generic_campaign_types"]}
    same_campaign = (
        str(left["campaign_type"]).casefold() == str(right["campaign_type"]).casefold()
        and str(left["campaign_type"]).casefold() not in generic
    )
    shared_features = set(left.get("feature_ids", [])) & set(right.get("feature_ids", []))
    shared_features = {
        item for item in shared_features if feature_frequency.get(item, 0) <= thresholds["max_feature_prevalence"]
    }
    score = sum(int(weights.get(kind, 0)) for kind, _ in shared_keys)
    score += int(weights["same_family"]) if same_family else 0
    score += int(weights["same_non_generic_campaign_type"]) if same_campaign else 0
    score += min(2, len(shared_features)) * int(weights["shared_rare_feature"])
    has_artifact_hash = any(kind == "artifact_hash" for kind, _ in shared_keys)
    non_ip_shared = {key for key in shared_keys if key[0] != "ip"}
    if same_family:
        strong_enough = has_artifact_hash or len(non_ip_shared) >= 2 or (len(non_ip_shared) >= 1 and same_campaign)
        minimum = thresholds["same_family_min_score"]
    else:
        strong_enough = has_artifact_hash or len(non_ip_shared) >= thresholds["cross_family_min_shared_indicators"]
        minimum = thresholds["cross_family_min_score"]
    if not strong_enough or score < minimum:
        return None
    return {
        "left": left["sha256"],
        "right": right["sha256"],
        "score": score,
        "same_family": same_family,
        "same_campaign_type": same_campaign,
        "shared_indicators": [
            {
                "type": key[0],
                "value": key[1],
                "left_role": left_indicators[key].get("role"),
                "right_role": right_indicators[key].get("role"),
            }
            for key in sorted(shared_keys)
        ],
        "shared_features": sorted(shared_features),
    }


def _components(nodes: Iterable[str], edges: Iterable[Mapping[str, Any]]) -> list[list[str]]:
    parent = {node: node for node in nodes}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for edge in edges:
        union(str(edge["left"]), str(edge["right"]))
    grouped: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        grouped[find(node)].append(node)
    return [sorted(value) for value in grouped.values() if len(value) >= 2]


def correlate_cases(evidences: Iterable[Mapping[str, Any]], rules: Mapping[str, Any]) -> dict[str, Any]:
    """全caseを相関し、再現可能なcampaign候補とcase labelを返す。"""

    values = sorted(evidences, key=lambda item: str(item["sha256"]))
    by_sha = {str(item["sha256"]): item for item in values}
    indicator_frequency: Counter[tuple[str, str]] = Counter()
    feature_frequency: Counter[str] = Counter()
    for item in values:
        indicator_frequency.update(_indicator_map(item).keys())
        feature_frequency.update(set(item.get("feature_ids", [])))
    indicator_cases: dict[tuple[str, str], set[str]] = defaultdict(set)
    for item in values:
        for key in _indicator_map(item):
            if indicator_frequency[key] <= rules["thresholds"]["max_indicator_prevalence"]:
                indicator_cases[key].add(str(item["sha256"]))
    candidate_pairs = set()
    for members in indicator_cases.values():
        ordered = sorted(members)
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                candidate_pairs.add((left, right))
    edges = []
    for left_sha, right_sha in sorted(candidate_pairs):
        edge = score_pair(
            by_sha[left_sha],
            by_sha[right_sha],
            rules,
            indicator_frequency,
            feature_frequency,
        )
        if edge is not None:
            edges.append(edge)
    clusters = []
    labels: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for members in _components(by_sha, edges):
        if len(members) > rules["thresholds"]["max_cluster_size"]:
            continue
        member_edges = [edge for edge in edges if edge["left"] in members and edge["right"] in members]
        families = sorted({str(by_sha[sha]["family"]) for sha in members})
        campaign_types = sorted({str(by_sha[sha]["campaign_type"]) for sha in members})
        indicator_support: dict[tuple[str, str], set[str]] = defaultdict(set)
        for sha in members:
            for key in _indicator_map(by_sha[sha]):
                indicator_support[key].add(sha)
        shared_indicators = [
            {"type": key[0], "value": key[1], "support": len(support)}
            for key, support in sorted(indicator_support.items())
            if len(support) >= 2 and indicator_frequency[key] <= rules["thresholds"]["max_indicator_prevalence"]
        ]
        fingerprint_material = json.dumps(
            {
                "families": families,
                "campaign_types": campaign_types,
                "indicators": [{"type": item["type"], "value": item["value"]} for item in shared_indicators],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        suffix = hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest()[:12]
        family_slug = "-".join(families[:3]) or "unknown"
        campaign_id = f"correlated-{family_slug}-{suffix}"
        max_score = max(int(edge["score"]) for edge in member_edges)
        confidence = "high" if max_score >= rules["thresholds"]["high_confidence_score"] else "medium"
        cluster = {
            "campaign_id": campaign_id,
            "classification": (
                "cross_family_campaign_candidate" if len(families) > 1 else "same_family_campaign_candidate"
            ),
            "confidence": confidence,
            "families": families,
            "members": members,
            "member_count": len(members),
            "shared_indicators": shared_indicators,
            "shared_feature_ids": sorted(
                {feature for edge in member_edges for feature in edge.get("shared_features", [])}
            ),
            "edge_count": len(member_edges),
            "maximum_pair_score": max_score,
            "limitations": [
                "同一アクターまたは同一運用者への帰属を意味しません。",
                "共有インフラが再利用・転売されている可能性を排除できません。",
                "収集バッチ、ファミリー名、ファイル名だけでは相関していません。",
            ],
        }
        clusters.append(cluster)
        for sha in members:
            labels[sha].append(
                {
                    "campaign_id": campaign_id,
                    "confidence": confidence,
                    "classification": cluster["classification"],
                }
            )
    clusters.sort(key=lambda item: item["campaign_id"])
    return {
        "schema_version": 1,
        "analysis_mode": "repository_artifact_correlation",
        "counts": {
            "cases": len(values),
            "candidate_pairs": len(candidate_pairs),
            "accepted_edges": len(edges),
            "campaign_candidates": len(clusters),
            "labeled_cases": len(labels),
        },
        "campaigns": clusters,
        "labels": {key: value for key, value in sorted(labels.items())},
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    }


def build_fingerprints(report: Mapping[str, Any]) -> dict[str, Any]:
    """次回caseの自動labelに使うcampaign fingerprintを構築する。"""

    fingerprints = []
    for campaign in report.get("campaigns", []):
        indicators = campaign.get("shared_indicators", [])
        fingerprints.append(
            {
                "campaign_id": campaign["campaign_id"],
                "families": campaign["families"],
                "confidence": campaign["confidence"],
                "minimum_indicator_matches": 1 if len(indicators) == 1 else 2,
                "indicators": [{"type": item["type"], "value": item["value"]} for item in indicators],
                "feature_ids": campaign.get("shared_feature_ids", []),
                "classification": campaign["classification"],
            }
        )
    return {
        "schema_version": 1,
        "description": "過去caseの強い共有証拠から生成した自動campaign label用fingerprint。",
        "fingerprints": fingerprints,
        "safety": report.get("safety", {}),
    }


def match_fingerprints(evidence: Mapping[str, Any], fingerprints: Mapping[str, Any]) -> list[dict[str, Any]]:
    """新規case evidenceへ既知campaign fingerprintを適用する。"""

    available = set(_indicator_map(evidence))
    feature_ids = set(evidence.get("feature_ids", []))
    family = str(evidence.get("family") or "unknown")
    output = []
    for fingerprint in fingerprints.get("fingerprints", []):
        families = {str(item) for item in fingerprint.get("families", [])}
        if family not in families:
            continue
        expected = {
            (str(item["type"]), str(item["value"]).casefold())
            for item in fingerprint.get("indicators", [])
            if isinstance(item, Mapping) and item.get("type") and item.get("value")
        }
        matches = sorted(available & expected)
        required = int(fingerprint.get("minimum_indicator_matches", 2))
        if len(matches) < required:
            continue
        shared_features = sorted(feature_ids & set(fingerprint.get("feature_ids", [])))
        output.append(
            {
                "campaign_id": fingerprint["campaign_id"],
                "confidence": fingerprint.get("confidence", "medium"),
                "classification": fingerprint.get("classification"),
                "matched_indicators": [{"type": kind, "value": value} for kind, value in matches],
                "matched_feature_ids": shared_features,
            }
        )
    return sorted(output, key=lambda item: item["campaign_id"])
