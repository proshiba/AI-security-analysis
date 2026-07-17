"""人が読む Markdown 文書の日本語化状況を、リポジトリ内だけで監査する。

コード、URL、ハッシュ、ファイルパス、機械可読な識別子は翻訳対象として
数えない。一方、日本語文字を一つも含まない文書と、英語だけで書かれた
見出し・説明行は、移行対象として完全な相対パスと行番号を返す。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Iterable

JAPANESE = re.compile(r"[ぁ-んァ-ヶ一-龯々〆ヵヶー]")
ENGLISH_WORD = re.compile(r"[A-Za-z][A-Za-z'-]{1,}")
INLINE_CODE = re.compile(r"`[^`]*`")
MARKDOWN_TARGET = re.compile(r"\]\((?:[^()]|\([^()]*\))*\)")
BARE_URL = re.compile(r"https?://\S+")
LONG_HASH = re.compile(r"\b[0-9a-fA-F]{12,}\b")
DOTTED_IDENTIFIER = re.compile(
    r"\b[A-Za-z_$<>][A-Za-z0-9_$<>]*(?:\.[A-Za-z_$<>][A-Za-z0-9_$<>]*)+\b"
)
VERSION_HEADING = re.compile(
    r"^#{1,6}\s+v?[0-9]+(?:\.[0-9A-Za-z-]+)+(?:\s*[（(][^）)]*[）)])?\s*$",
    re.IGNORECASE,
)
TABLE_SEPARATOR = re.compile(r"^\s*\|?(?:\s*:?-+:?\s*\|)+\s*$")
TECHNICAL_LIST = re.compile(
    r"^\s*[-*+]\s+[a-z][a-z0-9_.-]*(?:\s*(?:、|,)\s*[a-z][a-z0-9_.-]*)+\s*$"
)
IGNORED_PARTS = {
    ".git",
    ".work",
    ".venv",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
}
TECHNICAL_WORDS = {
    "api",
    "candidate",
    "c2",
    "cli",
    "cpu",
    "dll",
    "dns",
    "html",
    "http",
    "https",
    "ioc",
    "ip",
    "json",
    "ok",
    "recorded",
    "inferred",
    "confirmed",
    "unverified",
    "static",
    "config",
    "source",
    "false",
    "true",
    "markdown",
    "md",
    "mcp",
    "pe",
    "sha",
    "sha256",
    "sigma",
    "tcp",
    "tls",
    "url",
    "yaml",
    "yara",
}


def _machine_table_row(line: str) -> bool:
    """URL、hash、enum、数値だけの表data行を説明文から除外する。"""

    stripped = line.strip()
    if not (stripped.startswith("|") and stripped.endswith("|")):
        return False
    projected = INLINE_CODE.sub(" ", stripped)
    projected = MARKDOWN_TARGET.sub("]", projected)
    projected = BARE_URL.sub(" ", projected)
    projected = LONG_HASH.sub(" ", projected)
    projected = DOTTED_IDENTIFIER.sub(" ", projected)
    projected = re.sub(
        r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b", " ", projected
    )
    projected = re.sub(r"\b(?:sha256:)?[0-9a-fA-F]{8,}\b", " ", projected)
    projected = re.sub(r"\b\d+(?:[.,:/-]\d+)*\b", " ", projected)
    projected = JAPANESE.sub(" ", projected)
    for word in TECHNICAL_WORDS:
        projected = re.sub(
            rf"(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z0-9])",
            " ",
            projected,
            flags=re.IGNORECASE,
        )
    return not ENGLISH_WORD.search(projected)


def _display_path(path: Path, repository: Path) -> str:
    return path.resolve().relative_to(repository.resolve()).as_posix()


def discover_markdown(repository: Path, roots: Iterable[Path] | None = None) -> list[Path]:
    """監査対象の Markdown を、除外ディレクトリを避けて決定順で返す。"""
    repository = repository.resolve()
    requested = list(roots or [repository])
    found: set[Path] = set()
    for requested_root in requested:
        root = requested_root.resolve()
        try:
            root.relative_to(repository)
        except ValueError as exc:
            raise ValueError("document roots must stay within the repository") from exc
        candidates = [root] if root.is_file() else root.rglob("*.md")
        for path in candidates:
            if not path.is_file() or path.suffix.lower() != ".md":
                continue
            relative = path.resolve().relative_to(repository)
            if any(part in IGNORED_PARTS for part in relative.parts):
                continue
            found.add(path.resolve())
    return sorted(found, key=lambda item: item.as_posix().casefold())


def _english_prose_candidate(line: str) -> bool:
    stripped = line.strip()
    if not stripped or JAPANESE.search(stripped) or TABLE_SEPARATOR.fullmatch(stripped):
        return False
    if TECHNICAL_LIST.fullmatch(stripped) or VERSION_HEADING.fullmatch(stripped):
        return False
    if (
        stripped.startswith("|")
        and stripped.endswith("|")
        and (LONG_HASH.search(stripped) or _machine_table_row(stripped))
    ):
        return False
    if stripped.startswith("<!--") or stripped.endswith("-->"):
        return False
    cleaned = INLINE_CODE.sub(" ", stripped)
    cleaned = MARKDOWN_TARGET.sub("]", cleaned)
    cleaned = BARE_URL.sub(" ", cleaned)
    cleaned = LONG_HASH.sub(" ", cleaned)
    cleaned = re.sub(r"[A-Za-z]:[\\/]\S+|(?:\.{0,2}/)?[\w.-]+(?:/[\w.-]+)+", " ", cleaned)
    words = [word for word in ENGLISH_WORD.findall(cleaned)]
    meaningful = [word for word in words if word.lower() not in TECHNICAL_WORDS]
    if stripped.startswith("#"):
        return bool(meaningful)
    if stripped.startswith("|") and stripped.endswith("|"):
        return len(meaningful) >= 3
    if ":" in cleaned and len(meaningful) >= 2:
        return True
    return len(meaningful) >= 4


def analyze_markdown(path: Path, repository: Path) -> dict:
    """一つの Markdown の日本語文字数と英語のみの説明行を返す。"""
    text = path.read_text(encoding="utf-8")
    japanese_characters = len(JAPANESE.findall(text))
    english_lines: list[dict[str, object]] = []
    in_fence = False
    fence_marker = ""
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            marker = stripped[:3]
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker == fence_marker:
                in_fence, fence_marker = False, ""
            continue
        if (
            not in_fence
            and path.name != "IOC-LIST.md"
            and _english_prose_candidate(line)
        ):
            english_lines.append({"line": number, "text": line.strip()[:500]})
    return {
        "path": _display_path(path, repository),
        "japanese_characters": japanese_characters,
        "has_japanese": japanese_characters > 0,
        "english_only_prose": english_lines,
    }


def audit_repository(repository: Path, roots: Iterable[Path] | None = None) -> dict:
    """リポジトリの Markdown 日本語化状況を集計して返す。"""
    repository = repository.resolve()
    documents = [
        analyze_markdown(path, repository)
        for path in discover_markdown(repository, roots)
    ]
    without_japanese = [
        item["path"] for item in documents if not item["has_japanese"]
    ]
    english_prose = [
        {
            "path": item["path"],
            "lines": item["english_only_prose"],
        }
        for item in documents
        if item["english_only_prose"]
    ]
    return {
        "schema_version": 1,
        "scope": "human_readable_markdown",
        "counts": {
            "documents": len(documents),
            "documents_without_japanese": len(without_japanese),
            "documents_with_english_only_prose": len(english_prose),
            "english_only_prose_lines": sum(
                len(item["lines"]) for item in english_prose
            ),
        },
        "documents_without_japanese": without_japanese,
        "english_only_prose": english_prose,
    }


def render_markdown(report: dict) -> str:
    """監査結果の短い日本語サマリーを Markdown として返す。"""
    counts = report["counts"]
    lines = [
        "# 文書日本語化監査",
        "",
        "コードブロック、URL、ハッシュ、パス、識別子を除外して判定した。",
        "",
        "| 項目 | 件数 |",
        "|---|---:|",
        f"| Markdown | {counts['documents']} |",
        f"| 日本語文字がない文書 | {counts['documents_without_japanese']} |",
        f"| 英語のみの説明行を持つ文書 | {counts['documents_with_english_only_prose']} |",
        f"| 英語のみの説明行 | {counts['english_only_prose_lines']} |",
        "",
        "完全なパスと行番号は JSON 版に収録している。",
        "",
    ]
    return "\n".join(lines)


def _validate_output(repository: Path, output: Path | None) -> None:
    if output is None:
        return
    try:
        output.resolve().relative_to(repository.resolve())
    except ValueError as exc:
        raise ValueError("audit outputs must stay within the repository") from exc


def build_parser() -> argparse.ArgumentParser:
    """文書日本語化監査 CLI の引数パーサーを構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    parser.add_argument("--root", type=Path, action="append")
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    parser.add_argument("--fail-on-findings", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """監査 CLI を実行し、未日本語化を要求時だけ非ゼロで通知する。"""
    args = build_parser().parse_args(argv)
    repository = args.repository.resolve()
    roots = args.root or None
    _validate_output(repository, args.output_json)
    _validate_output(repository, args.output_markdown)
    if args.output_json and args.output_markdown:
        if args.output_json.resolve() == args.output_markdown.resolve():
            raise ValueError("JSON and Markdown outputs must differ")
    report = audit_repository(repository, roots)
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.output_markdown:
        args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
        args.output_markdown.write_text(render_markdown(report), encoding="utf-8")
    if not args.output_json and not args.output_markdown:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    findings = (
        report["counts"]["documents_without_japanese"]
        + report["counts"]["english_only_prose_lines"]
    )
    return int(args.fail_on_findings and bool(findings))


if __name__ == "__main__":
    raise SystemExit(main())
