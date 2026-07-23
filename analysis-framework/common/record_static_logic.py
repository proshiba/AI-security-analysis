#!/usr/bin/env python3
"""レビュー済み関数recordからcaseの静的ロジック成果物を生成する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from static_logic import (
    build_static_logic_report,
    load_function_records,
    render_static_logic_markdown,
)


def _family(case_dir: Path) -> str:
    metadata = case_dir / "metadata.json"
    if metadata.is_file():
        value = json.loads(metadata.read_text(encoding="utf-8-sig"))
        if isinstance(value, dict) and value.get("family"):
            return str(value["family"])
    parts = case_dir.parts
    if "malware" in parts:
        index = parts.index("malware")
        if index + 1 < len(parts):
            return parts[index + 1]
    return "unknown"


def generate(
    repository: Path,
    case_dir: Path,
    source_json: Path,
    *,
    write: bool = False,
    check: bool = False,
) -> dict[str, Any]:
    """review済み関数recordを検証し、2つの標準成果物へ変換する。"""

    repository = repository.resolve()
    case_dir = case_dir.resolve()
    source_json = source_json.resolve()
    for path in (case_dir, source_json):
        try:
            path.relative_to(repository)
        except ValueError as exc:
            raise ValueError("case and source JSON must stay within the repository") from exc
    if not case_dir.is_dir() or not (case_dir / "README.md").is_file():
        raise ValueError("case directory must contain README.md")
    records = load_function_records(source_json)
    report = build_static_logic_report(
        sha256=case_dir.name,
        family=_family(case_dir),
        source_name=source_json.name,
        records=records,
        analysis_source=source_json.relative_to(repository).as_posix(),
    )
    expected = {
        case_dir / "static-logic.json": json.dumps(report, ensure_ascii=False, indent=2)
        + "\n",
        case_dir / "STATIC-LOGIC.md": render_static_logic_markdown(report),
    }
    mismatches = []
    for path, content in expected.items():
        current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        if current != content:
            mismatches.append(path.relative_to(repository).as_posix())
            if write:
                path.write_text(content, encoding="utf-8")
    return {
        "schema_version": 1,
        "sha256": case_dir.name.casefold(),
        "function_count": len(report["functions"]),
        "mismatches": mismatches,
        "write_performed": bool(write and mismatches),
        "check_failed": bool(check and mismatches),
    }


def build_parser() -> argparse.ArgumentParser:
    """日本語helpを持つ関数ロジック記録CLIを構築する。"""

    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--source-json", type=Path, required=True)
    parser.add_argument("--write", action="store_true", help="標準成果物を更新する")
    parser.add_argument("--check", action="store_true", help="生成差分があれば非0を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、書込みまたは同期検証の終了codeを返す。"""

    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--write and --check are mutually exclusive")
    result = generate(
        args.repository,
        args.case_dir,
        args.source_json,
        write=args.write,
        check=args.check,
    )
    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "mismatches"},
            ensure_ascii=False,
            indent=2,
        )
    )
    return int(result["check_failed"])


if __name__ == "__main__":
    raise SystemExit(main())
