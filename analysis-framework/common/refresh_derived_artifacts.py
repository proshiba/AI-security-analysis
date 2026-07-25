#!/usr/bin/env python3
"""campaign、IOC、コード類似性の派生成果物を安全な順序で一括更新する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from correlate_campaigns import (
    DEFAULT_FINGERPRINTS,
    DEFAULT_RULES,
    generate as generate_campaigns,
)
from generate_code_similarity_index import generate as generate_code_similarity
from generate_ioc_lists import generate as generate_ioc_lists


def refresh(
    repository: Path,
    *,
    campaign_output_root: Path,
    rules_path: Path,
    fingerprints_path: Path,
    similarity_json: Path,
    similarity_markdown: Path,
    write: bool = False,
    check: bool = False,
    case_labels: bool = False,
) -> dict[str, Any]:
    """派生成果物を依存順に処理し、書込み後は同じ範囲を再検証する。"""

    if write and check:
        raise ValueError("--write and --check are mutually exclusive")
    repository = repository.resolve()
    mode = "write" if write else "check" if check else "dry_run"

    campaign = generate_campaigns(
        repository,
        output_root=campaign_output_root,
        rules_path=rules_path,
        fingerprints_path=fingerprints_path,
        write=write,
        check=check,
        case_labels=case_labels,
    )
    iocs = generate_ioc_lists(repository, write=write, check=check)
    similarity = generate_code_similarity(
        repository,
        output_json=similarity_json,
        output_markdown=similarity_markdown,
        write=write,
        check=check,
    )

    verification: dict[str, Any] | None = None
    if write:
        verification = {
            "campaigns": generate_campaigns(
                repository,
                output_root=campaign_output_root,
                rules_path=rules_path,
                fingerprints_path=fingerprints_path,
                check=True,
                case_labels=case_labels,
            ),
            "iocs": generate_ioc_lists(repository, check=True),
            "code_similarity": generate_code_similarity(
                repository,
                output_json=similarity_json,
                output_markdown=similarity_markdown,
                check=True,
            ),
        }

    stages = {
        "campaigns": campaign,
        "iocs": iocs,
        "code_similarity": similarity,
    }
    check_failed = any(
        bool(result.get("check_failed"))
        for result in (verification or stages).values()
    )
    return {
        "schema_version": 1,
        "mode": mode,
        "order": ["campaigns", "iocs", "code_similarity"],
        "case_labels_in_scope": case_labels,
        "stages": stages,
        "verification": verification,
        "write_performed": any(
            bool(result.get("write_performed")) for result in stages.values()
        ),
        "check_failed": check_failed,
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    """一括更新CLIの日本語引数parserを構築する。"""

    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument(
        "--campaign-output-root",
        type=Path,
        required=True,
        help="更新対象のcampaign snapshotディレクトリ",
    )
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--fingerprints", type=Path, default=DEFAULT_FINGERPRINTS)
    parser.add_argument(
        "--similarity-json",
        type=Path,
        default=repository / "analysis-results" / "catalog" / "code-similarity.json",
    )
    parser.add_argument(
        "--similarity-markdown",
        type=Path,
        default=repository / "analysis-results" / "catalog" / "CODE-SIMILARITY.md",
    )
    parser.add_argument(
        "--case-labels",
        action="store_true",
        help="case別campaign-labels.jsonも操作対象に含める",
    )
    parser.add_argument("--write", action="store_true", help="依存順に成果物を更新して再検証する")
    parser.add_argument("--check", action="store_true", help="既存成果物に差分があれば非0を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、差分検証結果を終了codeへ変換する。"""

    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--write and --check are mutually exclusive")
    report = refresh(
        args.repository,
        campaign_output_root=args.campaign_output_root,
        rules_path=args.rules,
        fingerprints_path=args.fingerprints,
        similarity_json=args.similarity_json,
        similarity_markdown=args.similarity_markdown,
        write=args.write,
        check=args.check,
        case_labels=args.case_labels,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return int(report["check_failed"])


if __name__ == "__main__":
    raise SystemExit(main())
