#!/usr/bin/env python3
"""全caseへ挙動・検体特徴の標準成果物を生成する。"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any

import yaml

from case_features import build_case_profile, discover_case_directories, render_features_markdown


def _history_by_sha(repository: Path) -> dict[str, dict[str, Any]]:
    path = repository / "analysis_history.yaml"
    if not path.is_file():
        return {}
    value = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    entries = value.get("analyses", []) if isinstance(value, dict) else []
    return {
        str(item.get("sample_sha256", "")).lower(): item
        for item in entries
        if isinstance(item, dict) and item.get("sample_sha256")
    }


def generate(repository: Path, *, write: bool = False, check: bool = False) -> dict[str, Any]:
    """全caseの期待成果物を生成または照合する。"""

    repository = repository.resolve()
    results_root = repository / "analysis-results"
    history = _history_by_sha(repository)
    mismatches = []
    statuses: Counter[str] = Counter()
    unresolved: Counter[str] = Counter()
    families: Counter[str] = Counter()
    cases = discover_case_directories(results_root)
    for case_dir in cases:
        try:
            case_dir.relative_to(results_root.resolve())
        except ValueError as exc:
            raise ValueError("case directory must stay within analysis-results") from exc
        if case_dir.is_symlink():
            raise ValueError(f"symbolic link case is not allowed: {case_dir}")
        profile = build_case_profile(case_dir, history.get(case_dir.name.lower()))
        expected_json = json.dumps(profile, ensure_ascii=False, indent=2) + "\n"
        expected_markdown = render_features_markdown(profile)
        targets = {
            case_dir / "features.json": expected_json,
            case_dir / "FEATURES.md": expected_markdown,
        }
        for path, expected in targets.items():
            current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
            if current != expected:
                mismatches.append(path.relative_to(repository).as_posix())
                if write:
                    path.write_text(expected, encoding="utf-8")
        assessment = profile["analysis_assessment"]
        statuses[assessment["status"]] += 1
        unresolved.update(assessment["unresolved"])
        families[profile["family"]] += 1
    report = {
        "schema_version": 1,
        "case_count": len(cases),
        "status_counts": dict(sorted(statuses.items())),
        "unresolved_counts": dict(sorted(unresolved.items())),
        "family_counts": dict(sorted(families.items())),
        "mismatches": sorted(mismatches),
        "write_performed": bool(write and mismatches),
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    }
    if check and mismatches:
        report["check_failed"] = True
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--write", action="store_true", help="差分がある特徴成果物を更新する")
    parser.add_argument("--check", action="store_true", help="差分がある場合に非0を返す")
    parser.add_argument("--output-summary", type=Path, help="監査集計JSONの出力先")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--write and --check are mutually exclusive")
    report = generate(args.repository, write=args.write, check=args.check)
    if args.output_summary:
        target = args.output_summary.resolve()
        repository = args.repository.resolve()
        try:
            target.relative_to(repository)
        except ValueError as exc:
            raise ValueError("output summary must stay within the repository") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "mismatches"}, ensure_ascii=False, indent=2))
    return int(bool(args.check and report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
