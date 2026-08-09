#!/usr/bin/env python3
"""全caseへ挙動・検体特徴の標準成果物を生成する。"""

from __future__ import annotations

import argparse
import json
import os
import stat
from collections import Counter
from collections.abc import Iterable
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


def _is_reparse_point(path: Path) -> bool:
    """symlinkとWindowsのjunction等のreparse pointを判定する。"""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"case指定パスを検査できません: {path}") from exc
    if path.is_symlink():
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _selected_case_directories(
    repository: Path,
    results_root: Path,
    selectors: Iterable[Path],
) -> list[Path]:
    """repository相対の明示指定を検証し、caseディレクトリへ解決する。"""

    selected: list[Path] = []
    seen: set[str] = set()
    for raw_selector in selectors:
        selector = Path(raw_selector)
        if selector.is_absolute() or selector.drive or selector.root:
            raise ValueError(f"--case-dirにはrepository相対パスを指定してください: {selector}")
        if not selector.parts or any(part in {".", ".."} for part in selector.parts):
            raise ValueError(f"--case-dirでは空要素、'.'、'..'を使用できません: {selector}")

        lexical_path = repository.joinpath(selector)
        current = repository
        for part in selector.parts:
            current = current / part
            if not current.exists():
                raise ValueError(f"指定したcaseディレクトリが存在しません: {selector}")
            if _is_reparse_point(current):
                raise ValueError(f"reparse pointを含むcase指定は使用できません: {selector}")

        try:
            case_dir = lexical_path.resolve(strict=True)
            case_dir.relative_to(repository)
            case_dir.relative_to(results_root)
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"caseディレクトリはrepository内のanalysis-results配下に指定してください: {selector}"
            ) from exc
        if not case_dir.is_dir():
            raise ValueError(f"--case-dirの指定先はディレクトリではありません: {selector}")
        if not case_dir.name or not case_dir.name.isascii() or len(case_dir.name) != 64:
            raise ValueError(f"caseディレクトリ名はSHA-256でなければなりません: {selector}")
        try:
            int(case_dir.name, 16)
        except ValueError as exc:
            raise ValueError(
                f"caseディレクトリ名はSHA-256でなければなりません: {selector}"
            ) from exc
        if not (case_dir / "README.md").is_file():
            raise ValueError(f"指定したcaseにREADME.mdがありません: {selector}")

        identity = os.path.normcase(str(case_dir)).casefold()
        if identity in seen:
            raise ValueError(f"同じcaseディレクトリが重複指定されています: {selector}")
        seen.add(identity)
        selected.append(case_dir)
    return sorted(selected, key=lambda item: item.as_posix().casefold())


def generate(
    repository: Path,
    *,
    write: bool = False,
    check: bool = False,
    case_dirs: Iterable[Path] | None = None,
) -> dict[str, Any]:
    """全caseまたは明示したcaseだけの特徴成果物を生成・照合する。"""

    repository = repository.resolve()
    results_root = (repository / "analysis-results").resolve()
    history = _history_by_sha(repository)
    mismatches = []
    statuses: Counter[str] = Counter()
    unresolved: Counter[str] = Counter()
    families: Counter[str] = Counter()
    cases = (
        discover_case_directories(results_root)
        if case_dirs is None
        else _selected_case_directories(repository, results_root, case_dirs)
    )
    for case_dir in cases:
        try:
            case_dir.relative_to(results_root.resolve())
        except ValueError as exc:
            raise ValueError("caseディレクトリはanalysis-results配下でなければなりません") from exc
        if case_dir.is_symlink():
            raise ValueError(f"symbolic linkのcaseは使用できません: {case_dir}")
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
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="解析repositoryのルート（既定: スクリプトから自動判定）",
    )
    parser.add_argument(
        "--case-dir",
        type=Path,
        action="append",
        help=(
            "処理対象のrepository相対caseディレクトリ。複数回指定可能。"
            "省略時は従来どおり全caseを処理する"
        ),
    )
    parser.add_argument("--write", action="store_true", help="差分がある特徴成果物を更新する")
    parser.add_argument("--check", action="store_true", help="差分がある場合に非0を返す")
    parser.add_argument("--output-summary", type=Path, help="監査結果JSONの出力先")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--writeと--checkは同時に指定できません")
    report = generate(
        args.repository,
        write=args.write,
        check=args.check,
        case_dirs=args.case_dir,
    )
    if args.output_summary:
        target = args.output_summary.resolve()
        repository = args.repository.resolve()
        try:
            target.relative_to(repository)
        except ValueError as exc:
            raise ValueError("監査結果JSONはrepository配下へ出力してください") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "mismatches"}, ensure_ascii=False, indent=2))
    return int(bool(args.check and report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
