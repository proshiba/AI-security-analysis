#!/usr/bin/env python3
"""検体別IOCと審査済みインフラSTIXのC2証拠を、値を公開せず監査する。"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import date
import json
from pathlib import Path
import re

from inventory_infrastructure_evidence import (
    CONFIG_C2_ROLES,
    EXCLUDED_ROLES,
    PUBLIC_ROLE_LABELS,
    _record_network_value,
    _safe_network_value,
)


SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
SAFE_FAMILY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}\Z")
CURATED_CLASSES = {
    "confirmed-c2", "confirmed-auxiliary", "configured-only", "reported-c2", "pivot-only",
}


def _read_object(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"JSONルートがobjectではありません: {path}")
    return document


def _source_class(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "not_recorded"
    if value.startswith("handler:"):
        return "static_handler"
    lowered = value.lower()
    if "triage" in lowered or "sandbox" in lowered:
        return "external_sandbox"
    if "ghidra" in lowered or "static_config" in lowered:
        return "other_static_analysis"
    if "dns" in lowered:
        return "dns_observation"
    return "other_recorded"


def _safe_family(value: str) -> str:
    return value if SAFE_FAMILY.fullmatch(value) else "other_family"


def _curated_values(endpoint: dict) -> set[str]:
    values: set[str] = set()
    for field in ("ip", "domain", "url"):
        value = endpoint.get(field)
        if not isinstance(value, str):
            continue
        if field == "url":
            candidate = value
        else:
            port = endpoint.get("port")
            candidate = value + (f":{port}" if type(port) is int else "")
        safe = _safe_network_value(candidate)
        if safe is not None:
            values.add(safe.lower())
    return values


def audit(repository: Path, curated_path: Path, as_of: str) -> dict:
    """公開値を出さずに全iocs.json network recordの階層と収録差を集計する。"""
    date.fromisoformat(as_of)
    malware_root = repository / "analysis-results" / "malware"
    if not malware_root.is_dir():
        raise ValueError("analysis-results/malware がありません")
    curated = _read_object(curated_path)
    endpoints = curated.get("endpoints")
    if not isinstance(endpoints, list):
        raise ValueError("審査済みSTIX endpoint一覧が配列ではありません")

    counts: Counter[str] = Counter()
    tiers: Counter[str] = Counter()
    roles: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    by_family: Counter[str] = Counter()
    static_values: set[str] = set()
    static_families: dict[str, set[str]] = defaultdict(set)

    for path in sorted(malware_root.rglob("iocs.json")):
        counts["malware_ioc_files"] += 1
        family = _safe_family(path.relative_to(malware_root).parts[0])
        file_has_static_c2 = False
        network = _read_object(path).get("network", [])
        if not isinstance(network, list):
            raise ValueError(f"networkが配列ではありません: {path}")
        for item in network:
            counts["network_records"] += 1
            if not isinstance(item, dict):
                counts["invalid_network_record"] += 1
                continue
            role = item.get("role")
            role = role if isinstance(role, str) else "unknown"
            confidence = item.get("confidence")
            confidence = confidence if isinstance(confidence, str) else "unknown"
            roles[role if role in PUBLIC_ROLE_LABELS else "other_role"] += 1
            sources[_source_class(item.get("source"))] += 1
            if item.get("liveness_confirmed") is True:
                counts["live_protocol_confirmed_records"] += 1
            if item.get("reachability") is None:
                counts["reachability_not_recorded"] += 1
            if not item.get("evidence"):
                counts["item_evidence_not_recorded"] += 1
            if role in EXCLUDED_ROLES or "context_only" in role or "not_c2" in role:
                tiers["excluded_non_c2"] += 1
                continue
            if role == "c2_candidate_external_sandbox_config":
                tiers["external_sandbox_candidate"] += 1
                continue
            if confidence in {"external_unverified", "unverified"}:
                tiers["external_unverified"] += 1
                continue
            if item.get("shared_service") is True:
                tiers["excluded_shared_service"] += 1
                continue
            value = _safe_network_value(_record_network_value(item))
            if value is None:
                tiers["excluded_unsafe_or_shared_value"] += 1
                if role in CONFIG_C2_ROLES and confidence.startswith("confirmed_static"):
                    counts["static_config_nonpublic_value"] += 1
                continue
            if role in CONFIG_C2_ROLES and confidence.startswith("confirmed_static"):
                file_has_static_c2 = True
                tiers["static_config_supported_c2"] += 1
                by_family[family] += 1
                normalized = value.lower()
                static_values.add(normalized)
                static_families[normalized].add(family)
                if not item.get("source"):
                    counts["static_config_item_source_missing"] += 1
                if not item.get("evidence"):
                    counts["static_config_item_evidence_missing"] += 1
                digest = item.get("sample_sha256")
                item_digest_valid = isinstance(digest, str) and SHA256.fullmatch(digest) is not None
                case_digest_valid = any(
                    path.parts[index] == "cases"
                    and index + 1 < len(path.parts)
                    and SHA256.fullmatch(path.parts[index + 1]) is not None
                    for index in range(len(path.parts) - 1)
                )
                if not item_digest_valid:
                    counts["static_config_item_sample_sha256_missing_or_invalid"] += 1
                if case_digest_valid:
                    counts["static_config_case_path_sha256_present"] += 1
                if not item_digest_valid and not case_digest_valid:
                    counts["static_config_sample_identity_not_resolved"] += 1
                if item.get("reachability") is None:
                    counts["static_config_reachability_not_recorded"] += 1
            elif any(token in role for token in ("c2", "control", "beacon", "tasking")):
                tiers["c2_candidate_not_confirmed"] += 1
            else:
                tiers["other_network_role"] += 1
        if file_has_static_c2:
            counts["static_config_ioc_files"] += 1
            classification_path = path.parent / "classification.json"
            if not classification_path.exists():
                counts["static_config_classification_file_missing"] += 1
            else:
                selected = _read_object(classification_path).get("malware_type")
                if selected == "unknown":
                    counts["static_config_initial_classification_unknown"] += 1
                elif isinstance(selected, str) and selected.replace("_", "-").lower() == family.replace("_", "-").lower():
                    counts["static_config_initial_classification_matches_directory"] += 1
                else:
                    counts["static_config_initial_classification_other_mismatch"] += 1

    curated_classes: Counter[str] = Counter()
    curated_quality: Counter[str] = Counter()
    curated_values: set[str] = set()
    curated_family_pairs: set[tuple[str, str]] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or endpoint.get("classification") not in CURATED_CLASSES:
            raise ValueError("審査済みSTIX endpointの分類が不正です")
        classification = endpoint["classification"]
        curated_classes[classification] += 1
        if classification == "confirmed-c2":
            if endpoint.get("evidence_kind") == "sample-config" and not endpoint.get("sample_sha256"):
                curated_quality["sample_config_c2_without_sample_sha256"] += 1
            if "first_observed" in endpoint and "last_observed" in endpoint:
                curated_quality["confirmed_c2_with_observation_time"] += 1
        if classification == "pivot-only" and "first_observed" in endpoint:
            curated_quality["pivot_only_with_observation_time"] += 1
        if classification in {"confirmed-c2", "configured-only"}:
            values = _curated_values(endpoint)
            curated_values.update(values)
            family = endpoint.get("family_id")
            if isinstance(family, str):
                curated_family_pairs.update((_safe_family(family), value) for value in values)

    strict_overlap = static_values & curated_values
    family_overlap = sum(
        (family, value) in curated_family_pairs
        for value, families in static_families.items()
        for family in families
    )
    return {
        "schema_version": 1,
        "as_of": as_of,
        "scope": "analysis-results/malware配下の全iocs.json network recordと審査済みSTIX endpointの集計比較",
        "counts": {
            **dict(sorted(counts.items())),
            "unique_public_static_config_c2_values": len(static_values),
            "static_config_values_shared_across_families": sum(len(families) > 1 for families in static_families.values()),
        },
        "evidence_tiers": dict(sorted(tiers.items())),
        "network_roles": dict(sorted(roles.items())),
        "source_classes": dict(sorted(sources.items())),
        "static_config_records_by_family": dict(sorted(by_family.items())),
        "curated_stix": {
            "endpoints": len(endpoints),
            "classifications": dict(sorted(curated_classes.items())),
            "quality": dict(sorted(curated_quality.items())),
            "unique_confirmed_or_configured_c2_values": len(curated_values),
            "strict_value_overlap_with_static_config": len(strict_overlap),
            "strict_family_and_value_overlap_with_static_config": family_overlap,
        },
        "assessment_boundary": {
            "raw_ioc_values_published": False,
            "raw_sample_paths_published": False,
            "strict_value_overlap_implies_exhaustive_stix_coverage": False,
            "static_config_is_live_c2_confirmation": False,
            "certificate_or_dns_is_family_attribution": False,
            "scope_includes_all_other_c2_json_files": False,
        },
        "audit_notes_ja": [
            "静的設定のC2値は検体内の宛先候補であり、実通信・現在の稼働を意味しない。",
            "厳密一致は文字列単位で、DNS履歴、URL正規化、別時点のIP再割当を推論しない。",
            "審査済みSTIXは選定されたOSINTクラスタと個別解析の集合であり、検体別IOCの全件自動取り込みではない。",
            "source/evidence欄の欠落は根拠不在の確定ではない。case内の別成果物との突合が必要。",
            "item-level sample_sha256がない場合も、cases/<SHA-256>のパスに検体識別子があるか別途数える。",
            "C2 endpointの観測時刻と証明書pivotの観測時刻は別物として数え、相互に補完しない。",
            "family別件数は保存先フォルダのラベルであり、独立した最終ファミリー判定ではない。初回classificationと後続静的レビューが異なる場合がある。",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--as-of", required=True, help="YYYY-MM-DD")
    parser.add_argument("--curated", type=Path, help="審査済みSTIX入力。既定はrepository内の定義")
    parser.add_argument("--write", type=Path, help="指定ファイルへ値非公開の監査結果を書き込む")
    parser.add_argument("--check", type=Path, help="既存の監査結果と一致するか読み取り専用で確認")
    args = parser.parse_args()
    if args.write is not None and args.check is not None:
        parser.error("--writeと--checkは併用できません")
    repository = args.repository.resolve()
    curated = args.curated or repository / "analysis-framework/knowledge/stix_infrastructure_curated.json"
    result = audit(repository, curated, args.as_of)
    serialized = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.check is not None:
        if args.check.read_text(encoding="utf-8") != serialized:
            raise SystemExit("監査結果が一致しません")
    elif args.write is not None:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
