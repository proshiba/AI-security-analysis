#!/usr/bin/env python3
"""解析成果物レイアウトの dry-run 計画を生成し、明示時だけ適用する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from result_layout import LayoutPlanError, apply_layout_plan, build_layout_plan


def _contained_output(path: Path, repository: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(repository.resolve())
    except ValueError as exc:
        raise LayoutPlanError("plan output must stay within the repository") from exc
    return resolved


def _write_plan(path: Path, plan: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    """日本語 CLI 引数 parser を返す。"""

    parser = argparse.ArgumentParser(
        description=(
            "公開済み解析成果物だけを読み、固定 family/version/case 構成の移行計画を作ります。"
        )
    )
    parser.add_argument("--repository", type=Path, default=Path.cwd(), help="repository root")
    parser.add_argument("--output", type=Path, help="repository 内の plan JSON 出力先")
    parser.add_argument(
        "--maximum-path-length",
        type=int,
        default=220,
        help="移行後の絶対 path 上限（既定: 220）",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="preflight error が 0 の計画だけを明示的に適用する",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """既定は read-only plan、`--write` 指定時だけ移行を適用する。"""

    args = build_parser().parse_args(argv)
    repository = args.repository.resolve()
    plan = build_layout_plan(repository, args.maximum_path_length)
    if args.write:
        plan = apply_layout_plan(repository, plan)
    if args.output:
        _write_plan(_contained_output(args.output, repository), plan)
    else:
        print(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True))
    return 2 if plan.get("errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
