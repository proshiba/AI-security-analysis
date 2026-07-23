#!/usr/bin/env python3
"""全caseの解析充足度と追加静的解析の必要性を監査する。"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any

from case_features import build_case_profile, discover_case_directories
from generate_case_features import _history_by_sha


def audit(repository: Path) -> dict[str, Any]:
    """特徴profileを共通判定器で再評価し、不足caseを全件返す。"""

    repository = repository.resolve()
    history = _history_by_sha(repository)
    records = []
    status_counts: Counter[str] = Counter()
    unresolved_counts: Counter[str] = Counter()
    family_statuses: dict[str, Counter[str]] = defaultdict(Counter)
    for case_dir in discover_case_directories(repository / "analysis-results"):
        profile_path = case_dir / "features.json"
        if profile_path.is_file():
            profile = json.loads(profile_path.read_text(encoding="utf-8-sig"))
        else:
            profile = build_case_profile(case_dir, history.get(case_dir.name.lower()))
        assessment = profile["analysis_assessment"]
        status = str(assessment["status"])
        status_counts[status] += 1
        unresolved_counts.update(assessment["unresolved"])
        family_statuses[str(profile["family"])][status] += 1
        if status != "complete" or assessment["unresolved"]:
            records.append(
                {
                    "sha256": profile["sha256"],
                    "family": profile["family"],
                    "campaign_type": profile["campaign_type"],
                    "status": status,
                    "score": assessment["score"],
                    "maximum_score": assessment["maximum_score"],
                    "missing": assessment["missing"],
                    "unresolved": assessment["unresolved"],
                    "next_actions": assessment["next_actions"],
                    "result_path": case_dir.relative_to(repository).as_posix(),
                }
            )
    return {
        "schema_version": 1,
        "analysis_mode": "repository_artifact_review",
        "counts": {
            "cases": sum(status_counts.values()),
            "complete": status_counts["complete"],
            "partial": status_counts["partial"],
            "insufficient": status_counts["insufficient"],
            "cases_with_unresolved_items": len(records),
        },
        "status_counts": dict(sorted(status_counts.items())),
        "unresolved_counts": dict(sorted(unresolved_counts.items())),
        "family_statuses": {family: dict(sorted(values.items())) for family, values in sorted(family_statuses.items())},
        "cases_requiring_follow_up": sorted(records, key=lambda item: (item["status"], item["family"], item["sha256"])),
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
            "source_scope": "public_repository_artifacts_only",
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    """全件詳細をJSONへ残し、人向け監査概要を日本語で描画する。"""

    lines = [
        "# 過去caseの解析充足度監査",
        "",
        "全公開caseを同じ基準で再評価し、挙動、検体特徴、静的復元、設定、通信役割、",
        "制約、IOC一覧、根拠の追跡可能性を確認しました。詳細なcase一覧は `audit.json` にあります。",
        "検体や復元バイナリは開かず、公開済みのREADMEとJSONだけを使用しています。",
        "",
        "## 集計",
        "",
        "| 状態 | 件数 | 意味 |",
        "|---|---:|---|",
        f"| complete | {report['counts']['complete']} | 挙動と検体特徴を含む主要項目が揃っている |",
        f"| partial | {report['counts']['partial']} | 根拠はあるが追加静的解析または文書化が必要 |",
        f"| insufficient | {report['counts']['insufficient']} | 現行成果物だけでは主要項目を説明できない |",
        "",
        "## 主な未解決理由",
        "",
        "| 理由 | case数 |",
        "|---|---:|",
    ]
    for key, value in sorted(report["unresolved_counts"].items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| `{key}` | {value} |")
    lines.extend(
        [
            "",
            "## ファミリー別状態",
            "",
            "| ファミリー | complete | partial | insufficient |",
            "|---|---:|---:|---:|",
        ]
    )
    for family, statuses in report["family_statuses"].items():
        lines.append(
            f"| `{family}` | {statuses.get('complete', 0)} | "
            f"{statuses.get('partial', 0)} | {statuses.get('insufficient', 0)} |"
        )
    insufficient = [item for item in report["cases_requiring_follow_up"] if item["status"] == "insufficient"]
    lines.extend(["", "## 優先して追加解析するcase", ""])
    if insufficient:
        lines.extend(
            f"- `{item['family']}` / `{item['sha256']}`: {', '.join(item['unresolved']) or '主要根拠不足'}"
            for item in insufficient
        )
    else:
        lines.append("- insufficient判定のcaseはありません。")
    lines.extend(
        [
            "",
            "## 追加解析の原則",
            "",
            "- `static_config_not_recovered` は、ファミリー名から設定やC2を補完せず、終端payloadの静的復元を優先します。",
            "- `packed_or_protected_inner_payload_not_recovered` は、外層のpacker所見と終端payload解析を分離します。",
            "- `behavior_not_documented` は、control flowまたはscript処理順の直接根拠を追加します。",
            "- `sample_characteristics_insufficient` は、形式、保護、resource、import、script構造を追加します。",
            "- 外部接続や検体実行を、文書不足の代替手段として行いません。",
            "",
        ]
    )
    return "\n".join(lines)


def generate(repository: Path, output_root: Path, *, write: bool = False, check: bool = False) -> dict[str, Any]:
    """監査結果の期待文書を生成または照合する。"""

    repository = repository.resolve()
    output_root = output_root.resolve()
    try:
        output_root.relative_to(repository)
    except ValueError as exc:
        raise ValueError("audit output must stay within the repository") from exc
    report = audit(repository)
    expected = {
        output_root / "audit.json": json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        output_root / "README.md": render_markdown(report),
    }
    mismatches = []
    for path, content in expected.items():
        current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        if current != content:
            mismatches.append(path.relative_to(repository).as_posix())
            if write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
    return {
        **report["counts"],
        "mismatches": mismatches,
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
        default=repository / "analysis-results" / "research" / "audits" / "case-knowledge-20260723",
    )
    parser.add_argument("--write", action="store_true", help="監査成果物を更新する")
    parser.add_argument("--check", action="store_true", help="生成差分がある場合に非0を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--write and --check are mutually exclusive")
    result = generate(args.repository, args.output_root, write=args.write, check=args.check)
    print(
        json.dumps({key: value for key, value in result.items() if key != "mismatches"}, ensure_ascii=False, indent=2)
    )
    return int(result["check_failed"])


if __name__ == "__main__":
    raise SystemExit(main())
