#!/usr/bin/env python3
"""主要な静的解析自動化moduleの日本語API文書を決定的に生成・照合する。"""

from __future__ import annotations

import argparse
from html import escape
import importlib
import inspect
from pathlib import Path
import pydoc
import re
import sys

REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
FRAMEWORK = REPOSITORY / "analysis-framework"
MODULE_SOURCES = {
    "analysis_lifecycle": "analysis-framework/common/analysis_lifecycle.py",
    "analysis_orchestrator": "analysis-framework/common/analysis_orchestrator.py",
    "analysis_resume_planner": "analysis-framework/common/analysis_resume_planner.py",
    "analyze_sample": "analysis-framework/common/analyze_sample.py",
    "extract_pyinstaller_archive": "analysis-framework/common/extract_pyinstaller_archive.py",
    "static_implementation_commitment": (
        "analysis-framework/common/static_implementation_commitment.py"
    ),
}
REPOSITORY_PATH_PLACEHOLDER = "<repo-root>"


def _prepare_imports() -> None:
    """固定repository内のmoduleだけをimportできる探索pathを準備する。"""

    for root in (COMMON, FRAMEWORK, REPOSITORY):
        value = str(root)
        if value not in sys.path:
            sys.path.insert(0, value)


def _normalize_repository_paths(value: str, *, replacement: str) -> str:
    """checkout固有のrepository絶対pathを安定した象徴表現へ置換する。"""

    raw_candidates = {str(REPOSITORY), REPOSITORY.as_posix()}
    candidates = raw_candidates | {escape(candidate) for candidate in raw_candidates}
    normalized = value
    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate:
            normalized = normalized.replace(candidate, replacement)
    return re.sub(
        r"(?<![A-Za-z0-9_])(?:WindowsPath|PosixPath)\(",
        "Path(",
        normalized,
    )


def _signature(member: object) -> str | None:
    """取得可能な場合だけHTML escape済みsignatureを返す。"""

    try:
        signature = _normalize_repository_paths(
            str(inspect.signature(member)),
            replacement=REPOSITORY_PATH_PLACEHOLDER,
        )
        return escape(signature)
    except (TypeError, ValueError):
        return None


def _render_routine(renderer: pydoc.HTMLDoc, public_name: str, member: object) -> str:
    """公開alias名をanchorと表示名へ固定してroutineを描画する。"""

    rendered = renderer.docroutine(member)
    internal_name = getattr(member, "__name__", public_name)
    if internal_name != public_name:
        rendered = rendered.replace(
            f'name="-{internal_name}"',
            f'name="-{public_name}"',
            1,
        ).replace(
            f"<strong>{escape(internal_name)}</strong>",
            f"<strong>{escape(public_name)}</strong>",
            1,
        )
    return _normalize_repository_paths(
        rendered,
        replacement=escape(REPOSITORY_PATH_PLACEHOLDER),
    )


def render_module(module_name: str) -> str:
    """許可済みmoduleの公開APIだけを日本語HTMLへ変換する。"""

    source = MODULE_SOURCES.get(module_name)
    if source is None:
        raise ValueError("API文書生成の対象外moduleです")
    _prepare_imports()
    module = importlib.import_module(module_name)
    renderer = pydoc.HTMLDoc()
    pieces = [
        '<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">',
        f"<title>{escape(module_name)} — API仕様</title></head><body>",
        f"<h1>{escape(module_name)}</h1>",
        f'<p><a href="../../{escape(source)}">実装</a></p>',
        f"<pre>{escape(pydoc.getdoc(module))}</pre>",
    ]
    for public_name, member in inspect.getmembers(module):
        if (
            public_name.startswith("_")
            or getattr(member, "__module__", None) != module_name
        ):
            continue
        escaped_name = escape(public_name)
        if inspect.isfunction(member):
            pieces.extend(
                [f"<h2>{escaped_name}</h2>", _render_routine(renderer, public_name, member)]
            )
            continue
        if not inspect.isclass(member):
            continue
        pieces.extend([f"<h2>{escaped_name}</h2>", f"<pre>{escape(pydoc.getdoc(member))}</pre>"])
        signature = _signature(member)
        if signature is not None:
            pieces.append(f"<pre>{escaped_name}{signature}</pre>")
        for method_name, method in inspect.getmembers(member):
            if method_name.startswith("_"):
                continue
            if not (inspect.isfunction(method) or inspect.ismethod(method)):
                continue
            if getattr(method, "__module__", None) == module_name:
                pieces.append(_render_routine(renderer, method_name, method))
    pieces.append("</body></html>\n")
    return "\n".join(pieces)


def main() -> int:
    """固定API文書を生成するか、既存文書との一致だけを検証する。"""

    parser = argparse.ArgumentParser(description="静的解析自動化APIの日本語文書を同期")
    parser.add_argument("--check", action="store_true", help="書き込まず差分だけを検査")
    args = parser.parse_args()
    different: list[str] = []
    output_root = REPOSITORY / "docs" / "pydoc"
    for module_name in MODULE_SOURCES:
        target = output_root / f"{module_name}.html"
        rendered = render_module(module_name)
        if args.check:
            if not target.is_file() or target.read_text(encoding="utf-8") != rendered:
                different.append(module_name)
        else:
            target.write_text(rendered, encoding="utf-8", newline="\n")
    print("API文書は同期済みです" if not different else "未同期: " + ", ".join(different))
    return int(bool(different))


if __name__ == "__main__":
    raise SystemExit(main())
