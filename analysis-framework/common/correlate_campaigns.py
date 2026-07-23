#!/usr/bin/env python3
"""過去caseを相関し、campaign候補、label、再利用可能なfingerprintを生成する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from campaign_correlation import (
    build_fingerprints,
    correlate_cases,
    extract_campaign_evidence,
    load_rules,
)
from case_features import build_case_profile, discover_case_directories


DEFAULT_RULES = Path(__file__).resolve().parents[1] / "registry" / "campaign_correlation_rules.json"
DEFAULT_FINGERPRINTS = Path(__file__).resolve().parents[1] / "registry" / "campaign_fingerprints.json"


def _history_by_sha(repository: Path) -> dict[str, dict[str, Any]]:
    value = yaml.safe_load((repository / "analysis_history.yaml").read_text(encoding="utf-8-sig")) or {}
    return {
        str(item.get("sample_sha256", "")).lower(): item
        for item in value.get("analyses", [])
        if isinstance(item, dict) and item.get("sample_sha256")
    }


def _render_index(report: Mapping[str, Any]) -> str:
    lines = [
        "# 過去caseの攻撃キャンペーン相関",
        "",
        "公開済みcaseの共有インフラ、共有子要素、非汎用の配布・挙動特徴を相関し、",
        "同一攻撃キャンペーンの可能性がある集合だけを候補として切り出しました。",
        "ファミリー名、ファイル名、収集バッチ、IP単独では相関していません。",
        "",
        "## 集計",
        "",
        "| 項目 | 件数 |",
        "|---|---:|",
    ]
    labels = {
        "cases": "評価case",
        "candidate_pairs": "共有指標を持つ候補pair",
        "accepted_edges": "閾値を満たした相関pair",
        "campaign_candidates": "campaign候補",
        "labeled_cases": "campaign label付与case",
    }
    for key, value in report["counts"].items():
        lines.append(f"| {labels.get(key, key)} | {value} |")
    lines.extend(
        [
            "",
            "## campaign候補",
            "",
            "| campaign ID | ファミリー | case数 | 確度 | 分類 |",
            "|---|---|---:|---|---|",
        ]
    )
    for item in report["campaigns"]:
        campaign_id = item["campaign_id"]
        lines.append(
            f"| [`{campaign_id}`]({campaign_id}/README.md) | "
            f"{', '.join(item['families'])} | {item['member_count']} | "
            f"{item['confidence']} | {item['classification']} |"
        )
    lines.extend(
        [
            "",
            "## 判定上の注意",
            "",
            "- campaign候補は同一アクターへの帰属を意味しません。",
            "- 共有インフラの再利用、ホスティング転売、builder共有は別の説明になり得ます。",
            "- 新規caseへの自動labelは、生成したfingerprintの強い指標を再観測した場合だけ行います。",
            "- 検体の読込み・実行と外部通信は行っていません。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_campaign(campaign: Mapping[str, Any]) -> str:
    lines = [
        f"# campaign候補：{campaign['campaign_id']}",
        "",
        f"- 分類: `{campaign['classification']}`",
        f"- 確度: `{campaign['confidence']}`",
        f"- ファミリー: `{', '.join(campaign['families'])}`",
        f"- case数: {campaign['member_count']}",
        f"- 最大pair score: {campaign['maximum_pair_score']}",
        "",
        "## 相関したcase",
        "",
    ]
    lines.extend(f"- `{sha256}`" for sha256 in campaign["members"])
    lines.extend(
        [
            "",
            "## 共有証拠",
            "",
            "| 種別 | 値 | case支持数 |",
            "|---|---|---:|",
        ]
    )
    for item in campaign["shared_indicators"]:
        safe_value = str(item["value"]).replace("|", "\\|")
        lines.append(f"| {item['type']} | `{safe_value}` | {item['support']} |")
    if campaign["shared_feature_ids"]:
        lines.extend(["", "## 共有する挙動・検体特徴", ""])
        lines.extend(f"- `{item}`" for item in campaign["shared_feature_ids"])
    lines.extend(["", "## 制約", ""])
    lines.extend(f"- {item}" for item in campaign["limitations"])
    lines.append("")
    return "\n".join(lines)


def _ioc_document(campaign: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "indicators": [
            {
                "type": item["type"],
                "value": item["value"],
                "role": "shared_campaign_evidence",
                "confidence": campaign["confidence"],
                "support": item["support"],
            }
            for item in campaign["shared_indicators"]
        ],
    }


def _expected_documents(
    output_root: Path,
    report: Mapping[str, Any],
    fingerprints: Mapping[str, Any],
    case_directories: Mapping[str, Path],
) -> dict[Path, str]:
    documents = {
        output_root / "README.md": _render_index(report),
        output_root / "campaigns.json": json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        output_root / "campaign-labels.json": json.dumps(
            {"schema_version": 1, "labels": report["labels"], "safety": report["safety"]},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    }
    for campaign in report["campaigns"]:
        campaign_root = output_root / campaign["campaign_id"]
        documents[campaign_root / "README.md"] = _render_campaign(campaign)
        documents[campaign_root / "campaign.json"] = json.dumps(campaign, ensure_ascii=False, indent=2) + "\n"
        documents[campaign_root / "iocs.json"] = (
            json.dumps(_ioc_document(campaign), ensure_ascii=False, indent=2) + "\n"
        )
        rule = next(item for item in fingerprints["fingerprints"] if item["campaign_id"] == campaign["campaign_id"])
        documents[campaign_root / "rules" / "correlation-rule.json"] = (
            json.dumps(rule, ensure_ascii=False, indent=2) + "\n"
        )
    labels_by_sha = {str(sha256): labels for sha256, labels in report["labels"].items()}
    for sha256, case_dir in case_directories.items():
        labels = labels_by_sha.get(sha256, [])
        payload = {
            "schema_version": 1,
            "sha256": sha256,
            "labels": labels,
            "status": "matched" if labels else "no_strong_match",
            "rule_source": "registry/campaign_fingerprints.json",
            "executed_sample": False,
            "network_contacted": False,
            "safety": report["safety"],
        }
        documents[case_dir / "campaign-labels.json"] = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    return documents


def generate(
    repository: Path,
    *,
    output_root: Path,
    rules_path: Path,
    fingerprints_path: Path,
    write: bool = False,
    check: bool = False,
) -> dict[str, Any]:
    """campaign相関を実行し、期待成果物を生成または照合する。"""

    repository = repository.resolve()
    output_root = output_root.resolve()
    fingerprints_path = fingerprints_path.resolve()
    for path in (output_root, fingerprints_path):
        try:
            path.relative_to(repository)
        except ValueError as exc:
            raise ValueError("campaign outputs must stay within the repository") from exc
    rules = load_rules(rules_path)
    history = _history_by_sha(repository)
    evidences = []
    case_directories = {}
    for case_dir in discover_case_directories(repository / "analysis-results"):
        case_directories[case_dir.name.lower()] = case_dir
        profile_path = case_dir / "features.json"
        if profile_path.is_file():
            profile = json.loads(profile_path.read_text(encoding="utf-8-sig"))
        else:
            profile = build_case_profile(case_dir, history.get(case_dir.name.lower()))
        evidences.append(extract_campaign_evidence(case_dir, profile, rules))
    report = correlate_cases(evidences, rules)
    fingerprints = build_fingerprints(report)
    expected = _expected_documents(output_root, report, fingerprints, case_directories)
    expected[fingerprints_path] = json.dumps(fingerprints, ensure_ascii=False, indent=2) + "\n"
    mismatches = []
    for path, content in expected.items():
        current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        if current != content:
            mismatches.append(path.relative_to(repository).as_posix())
            if write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
    if write and output_root.is_dir():
        expected_campaigns = {item["campaign_id"] for item in report["campaigns"]}
        stale = [
            path
            for path in output_root.iterdir()
            if path.is_dir()
            and re.fullmatch(r"correlated-[a-z0-9-]+-[0-9a-f]{12}", path.name)
            and path.name not in expected_campaigns
        ]
        if stale:
            raise ValueError(f"stale generated campaign directories require review: {stale[0]}")
    return {
        **report["counts"],
        "mismatches": sorted(mismatches),
        "write_performed": bool(write and mismatches),
        "check_failed": bool(check and mismatches),
    }


def build_parser() -> argparse.ArgumentParser:
    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=repository / "analysis-results" / "research" / "campaigns" / "correlated-20260723",
    )
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--fingerprints", type=Path, default=DEFAULT_FINGERPRINTS)
    parser.add_argument("--write", action="store_true", help="campaign成果物を更新する")
    parser.add_argument("--check", action="store_true", help="生成差分がある場合に非0を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--write and --check are mutually exclusive")
    result = generate(
        args.repository,
        output_root=args.output_root,
        rules_path=args.rules,
        fingerprints_path=args.fingerprints,
        write=args.write,
        check=args.check,
    )
    print(
        json.dumps({key: value for key, value in result.items() if key != "mismatches"}, ensure_ascii=False, indent=2)
    )
    return int(result["check_failed"])


if __name__ == "__main__":
    raise SystemExit(main())
