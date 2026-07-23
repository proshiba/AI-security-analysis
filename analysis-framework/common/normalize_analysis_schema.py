#!/usr/bin/env python3
"""既知の旧形式analysis.jsonへトップレベルschema_versionを安全に補う。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


LEGACY_KEYS = {"case", "config", "c2", "unpack", "layers"}
SCHEMA_VERSION = 1


def normalize_document(value: Any) -> tuple[Any, bool]:
    """既知の旧形式だけを正規化し、未知形式は変更しない。"""

    if not isinstance(value, dict) or "schema_version" in value:
        return value, False
    if set(value) != LEGACY_KEYS:
        return value, False
    normalized = {"schema_version": SCHEMA_VERSION, **value}
    return normalized, True


def normalize_repository(repository: Path, *, write: bool = False) -> dict[str, Any]:
    """全analysis.jsonを検査し、認識できた旧形式だけを移行する。"""

    repository = repository.resolve()
    results_root = repository / "analysis-results"
    if not results_root.is_dir():
        raise ValueError("repository must contain analysis-results")
    migrated = []
    unknown_without_schema = []
    parse_errors = []
    for path in sorted(results_root.rglob("analysis.json")):
        relative = path.relative_to(repository).as_posix()
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            parse_errors.append(relative)
            continue
        normalized, changed = normalize_document(value)
        if changed:
            migrated.append(relative)
            if write:
                path.write_text(
                    json.dumps(normalized, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
        elif isinstance(value, dict) and "schema_version" not in value:
            unknown_without_schema.append(relative)
    return {
        "schema_version": 1,
        "recognized_legacy_documents": len(migrated),
        "unknown_documents_without_schema": unknown_without_schema,
        "parse_errors": parse_errors,
        "write_performed": bool(write and migrated),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--write", action="store_true", help="認識済み旧形式を更新する")
    parser.add_argument(
        "--check", action="store_true", help="未移行の既知形式または異常があれば非0を返す"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--write and --check are mutually exclusive")
    report = normalize_repository(args.repository, write=args.write)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    has_findings = bool(
        report["recognized_legacy_documents"]
        or report["unknown_documents_without_schema"]
        or report["parse_errors"]
    )
    return int(args.check and has_findings)


if __name__ == "__main__":
    raise SystemExit(main())
