#!/usr/bin/env python3
"""iocs.json以外の検体別C2成果物を、値を公開せず横断監査する。"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import date
import json
from pathlib import Path


ARTIFACT_NAMES = (
    "config.json",
    "indicators.json",
    "c2-analysis.json",
    "c2-observation-plan.json",
    "communication-patterns.json",
    "network-evidence.json",
    "protocol-observations.json",
    "monitoring-results.json",
)
ENDPOINT_FIELDS = frozenset(("host", "ip", "domain", "url", "value", "endpoint", "target", "address"))
TIERS = (
    "configuration_claim",
    "indicator_c2_claim",
    "static_endpoint_claim",
    "candidate_literal",
    "planned_target",
    "analysis_endpoint_claim",
    "network_evidence_claim",
    "protocol_observation_claim",
    "monitoring_claim",
)


def _at(document: object, dotted_path: str) -> object:
    value = document
    for key in dotted_path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _endpoint_count(value: object) -> int:
    """明示的なC2欄だけを数え、空値・port単独・説明文は除外する。"""
    if isinstance(value, str):
        return int(bool(value.strip()))
    if isinstance(value, list):
        return sum(_endpoint_count(item) for item in value)
    if isinstance(value, dict):
        if any(isinstance(value.get(key), str) and value[key].strip() for key in ENDPOINT_FIELDS):
            return 1
        # c2: {primary: {...}, backup: {...}} の形式も取り扱う。
        return sum(_endpoint_count(item) for item in value.values() if isinstance(item, (dict, list)))
    return 0


def _entries(document: dict, artifact_name: str) -> dict[str, int]:
    paths: dict[str, tuple[str, ...]] = {
        "config.json": (
            "configuration_claim:config_endpoints", "configuration_claim:c2",
            "configuration_claim:endpoints", "configuration_claim:network_endpoints",
            "configuration_claim:secondary_endpoints", "configuration_claim:tor_endpoints",
            "configuration_claim:config.c2", "configuration_claim:config.endpoints",
            "configuration_claim:config.c2_hosts", "configuration_claim:config.hosts",
            "configuration_claim:config.endpoint",
            "configuration_claim:config.c2_ip", "configuration_claim:config.c2_host",
            "configuration_claim:config.controller_ip", "configuration_claim:config.host",
            "candidate_literal:config.network_candidates",
            "candidate_literal:config.c2_urls_inferred",
            "candidate_literal:c2_candidate_static_config",
            "candidate_literal:c2_or_exfiltration",
            "candidate_literal:reserve_domains",
            "network_evidence_claim:behaviorally_observed_endpoints",
        ),
        "indicators.json": (
            "indicator_c2_claim:c2",
            "candidate_literal:c2_candidates",
            "candidate_literal:detection_inputs.network_candidates",
            "planned_target:c2_assessment.targets",
        ),
        "c2-analysis.json": ("analysis_endpoint_claim:c2.endpoints",),
        "c2-observation-plan.json": ("planned_target:targets",),
        "communication-patterns.json": (
            "static_endpoint_claim:communication.confirmed_static_endpoints",
            "candidate_literal:communication.candidate_patterns",
        ),
        "network-evidence.json": (
            "network_evidence_claim:confirmed_terminal_endpoints",
            "network_evidence_claim:endpoints",
            "network_evidence_claim:stage_flow.endpoint",
            "network_evidence_claim:control_flow.endpoint",
            "network_evidence_claim:http.url",
        ),
        "protocol-observations.json": (
            "protocol_observation_claim:observations",
            "protocol_observation_claim:endpoints",
        ),
        "monitoring-results.json": (
            "monitoring_claim:results", "monitoring_claim:endpoints",
        ),
    }
    counts: Counter[str] = Counter()
    for specification in paths[artifact_name]:
        tier, field = specification.split(":", 1)
        counts[tier] += _endpoint_count(_at(document, field))
    if artifact_name == "indicators.json" and isinstance(document.get("indicators"), list):
        for indicator in document["indicators"]:
            if not isinstance(indicator, dict):
                continue
            role = indicator.get("role")
            if role == "c2_candidate_static_config":
                counts["candidate_literal"] += _endpoint_count(indicator)
            elif role in {"redline_c2", "quasar_tcp_c2", "c2_endpoint", "tasking_endpoint"}:
                counts["indicator_c2_claim"] += _endpoint_count(indicator)
    return dict(counts)


def _ioc_state(case_dir: Path) -> str:
    path = case_dir / "iocs.json"
    if not path.is_file():
        return "missing"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "invalid"
    if not isinstance(document, dict) or not isinstance(document.get("network", []), list):
        return "invalid"
    return "empty" if not document.get("network") else "nonempty"


def audit(repository: Path, as_of: str) -> dict:
    """case間で重複排除せず、成果物レコード数とiocs.jsonの欠落を数える。"""
    date.fromisoformat(as_of)
    malware_root = repository / "analysis-results" / "malware"
    if not malware_root.is_dir():
        raise ValueError("analysis-results/malware がありません")

    file_counts: Counter[str] = Counter({name: 0 for name in ARTIFACT_NAMES})
    nonempty_files: Counter[str] = Counter({name: 0 for name in ARTIFACT_NAMES})
    tier_counts: Counter[str] = Counter({tier: 0 for tier in TIERS})
    case_tiers: dict[Path, Counter[str]] = defaultdict(Counter)
    invalid_json: Counter[str] = Counter({name: 0 for name in ARTIFACT_NAMES})

    for name in ARTIFACT_NAMES:
        for path in sorted(malware_root.rglob(name)):
            # 解析caseに属さない同名ファイルを誤って集計しない。
            if "cases" not in path.relative_to(malware_root).parts:
                continue
            case_dir = path.parent
            file_counts[name] += 1
            case_tiers[case_dir]  # 空成果物のみのcaseも母集団に入れる。
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                invalid_json[name] += 1
                continue
            if not isinstance(document, dict):
                invalid_json[name] += 1
                continue
            entries = _entries(document, name)
            if sum(entries.values()) > 0:
                nonempty_files[name] += 1
            for tier, count in entries.items():
                tier_counts[tier] += count
                case_tiers[case_dir][tier] += count

    ioc_states: Counter[str] = Counter({name: 0 for name in ("missing", "empty", "invalid", "nonempty")})
    ioc_states_with_artifact_endpoint: Counter[str] = Counter(ioc_states)
    for case_dir, tiers in case_tiers.items():
        state = _ioc_state(case_dir)
        ioc_states[state] += 1
        if sum(tiers.values()) > 0:
            ioc_states_with_artifact_endpoint[state] += 1

    return {
        "schema_version": 1,
        "as_of": as_of,
        "scope": "analysis-results/malware配下のcase単位C2関連JSON。iocs.json自体のnetwork値は件数の比較にのみ使用",
        "artifact_files": dict(sorted(file_counts.items())),
        "artifact_files_with_explicit_endpoint_records": dict(sorted(nonempty_files.items())),
        "invalid_json_files": dict(sorted(invalid_json.items())),
        "endpoint_record_claims_by_tier": dict(sorted(tier_counts.items())),
        "case_counts": {
            "cases_with_target_artifacts": len(case_tiers),
            "cases_with_explicit_endpoint_records": sum(bool(sum(t.values())) for t in case_tiers.values()),
            "iocs_json_state": dict(sorted(ioc_states.items())),
            "iocs_json_state_when_other_artifact_has_endpoint": dict(sorted(ioc_states_with_artifact_endpoint.items())),
        },
        "assessment_boundary": {
            "raw_ioc_values_published": False,
            "raw_sample_paths_published": False,
            "record_count_deduplicated_across_artifacts": False,
            "indicator_c2_claim_independently_verified": False,
            "candidate_or_plan_is_c2_confirmation": False,
            "static_config_is_live_c2_confirmation": False,
            "network_evidence_claim_independently_verified": False,
            "ioc_absence_means_no_c2": False,
        },
        "audit_notes_ja": [
            "件数は明示的なC2・endpoint欄のレコード数であり、検体間または成果物間の一意な宛先数ではない。",
            "candidate_literalは未検証の文字列候補、planned_targetは監視計画であり、確認済みC2へ昇格しない。",
            "indicator_c2_claimはindicators.json内のC2表明であり、独立した実通信や稼働を確認した件数ではない。",
            "network_evidence_claimは元成果物の主張を集計したもの。PCAP、能動観測、静的根拠の内訳を再審査せず、現在の稼働を意味しない。",
            "iocs.jsonのnetwork欄が空またはファイル欠落でも、別成果物に静的設定や候補が残る場合がある。",
            "未知の自由記述欄を横断的に抽出しないため、全C2値の網羅性を保証するものではない。",
            "analysis-results/research/c2-monitoring配下の日別monitoring-results.jsonは検体別成果物ではないため対象外。",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--as-of", required=True, help="YYYY-MM-DD")
    parser.add_argument("--write", type=Path, help="値を含まない集計JSONの保存先")
    parser.add_argument("--check", type=Path, help="保存済み集計JSONとの完全一致を読み取り専用で検証")
    args = parser.parse_args()
    if args.write is not None and args.check is not None:
        parser.error("--writeと--checkは併用できません")
    result = audit(args.repository.resolve(), args.as_of)
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
