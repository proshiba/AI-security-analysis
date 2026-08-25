#!/usr/bin/env python3
"""公開成果物と人間向けソースのUTF-8整合性および文字化けを検査する。"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Iterator

TEXT_SUFFIXES = {
    ".css",
    ".csv",
    ".html",
    ".js",
    ".json",
    ".md",
    ".py",
    ".txt",
    ".yaml",
    ".yml",
}
HUMAN_SUFFIXES = {".html", ".js", ".md", ".py", ".yaml", ".yml"}
SKIP_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".work",
    "__pycache__",
    "node_modules",
}
RAW_JSON_NAMES = {
    "generic-triage.json",
    "live-observation.json",
    "malwarebazaar-manifest.json",
    "static-layers.json",
}
DERIVED_JSON_PATHS = {
    "analysis-results/catalog/code-similarity.json",
    "analysis-results/catalog/logic-similarity.json",
}
RAW_JSON_KEYS = {
    "archive_member",
    "body_excerpt",
    "display_name",
    "file_name",
    "file_name_raw",
    "filename",
    "member_name",
    "raw",
    "source_name",
    "strings",
}
QUESTION_RUN = re.compile(r"(?<![A-Za-z0-9_.?-])\?{3,}(?![A-Za-z0-9_.?-])")
MOJIBAKE = re.compile(r"(?:縺|繧|譁|蜿|荳|螟|逕|螳|險|驥|霆|蟄|譛|邱|鬥|縲)[\uFF61-\uFF9F]")


def _iter_files(repository: Path) -> Iterator[Path]:
    for current, directories, files in os.walk(repository):
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRECTORIES)
        base = Path(current)
        for name in sorted(files):
            path = base / name
            if path.suffix.lower() in TEXT_SUFFIXES:
                yield path


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _finding(
    findings: list[dict[str, Any]],
    code: str,
    path: Path,
    repository: Path,
    message: str,
    *,
    line: int | None = None,
) -> None:
    item: dict[str, Any] = {
        "code": code,
        "path": path.relative_to(repository).as_posix(),
        "message": message,
    }
    if line is not None:
        item["line"] = line
    findings.append(item)


def _iter_json_strings(
    value: Any,
    keys: tuple[str, ...] = (),
) -> Iterator[tuple[tuple[str, ...], str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_json_strings(child, (*keys, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_json_strings(child, (*keys, str(index)))
    elif isinstance(value, str):
        yield keys, value


def _candidate_handler_machine_string(path: Path, keys: tuple[str, ...]) -> bool:
    return (
        path.name == "candidate-handler-assessment.json"
        and len(keys) == 8
        and keys[0] == "families"
        and keys[1].isdigit()
        and keys[2] == "attempts"
        and keys[3].isdigit()
        and keys[4:7] == ("result", "result", "suspicious_strings")
        and keys[7].isdigit()
    )


def _raw_json_value(relative: str, path: Path, keys: tuple[str, ...]) -> bool:
    if _candidate_handler_machine_string(path, keys):
        return True
    if path.name in RAW_JSON_NAMES or relative in DERIVED_JSON_PATHS:
        return True
    if "pe_static_summary" in keys and "sections" in keys:
        return True
    if path.name == "manifest.json" and "malwarebazaar" in relative.lower():
        return bool(set(keys) & RAW_JSON_KEYS)
    return bool(set(keys) & RAW_JSON_KEYS)


def _check_value(
    value: str,
    path: Path,
    repository: Path,
    findings: list[dict[str, Any]],
    *,
    line: int | None = None,
) -> None:
    if "\ufffd" in value:
        _finding(
            findings,
            "replacement_character",
            path,
            repository,
            "Unicode置換文字U+FFFDが含まれています。",
            line=line,
        )
    if QUESTION_RUN.search(value):
        _finding(
            findings,
            "question_mark_run",
            path,
            repository,
            "3文字以上の連続疑問符があります。日本語が置換された可能性を確認してください。",
            line=line,
        )
    if MOJIBAKE.search(value):
        _finding(
            findings,
            "japanese_mojibake",
            path,
            repository,
            "UTF-8を別encodingで再解釈した可能性が高い文字列があります。",
            line=line,
        )


def validate_text_integrity(repository: Path) -> dict[str, Any]:
    """repository内の対象テキストを走査し、機械判定結果を返す。"""

    repository = repository.resolve()
    findings: list[dict[str, Any]] = []
    scanned_files = 0
    human_files = 0
    for path in _iter_files(repository):
        scanned_files += 1
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            _finding(
                findings,
                "invalid_utf8",
                path,
                repository,
                f"UTF-8として復号できません: byte offset {error.start}",
            )
            continue
        except OSError as error:
            _finding(
                findings,
                "read_error",
                path,
                repository,
                f"読取に失敗しました: {type(error).__name__}",
            )
            continue

        relative = path.relative_to(repository).as_posix()
        suffix = path.suffix.lower()
        if suffix == ".js" and relative == "ui/data.js":
            try:
                serialized = text.split("=", 1)[1].strip().removesuffix(";")
                value = json.loads(serialized)
            except (IndexError, json.JSONDecodeError):
                _finding(
                    findings,
                    "invalid_ui_data",
                    path,
                    repository,
                    "ui/data.jsの埋込みJSONを解析できません。",
                )
                continue
            human_files += 1
            for keys, string in _iter_json_strings(value):
                if _raw_json_value(relative, path, keys):
                    continue
                _check_value(string, path, repository, findings)
            continue
        if suffix == ".json":
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                continue
            human_files += 1
            for keys, string in _iter_json_strings(value):
                if _raw_json_value(relative, path, keys):
                    continue
                _check_value(string, path, repository, findings)
            continue
        if suffix not in HUMAN_SUFFIXES:
            continue
        if suffix == ".py" and ("tests" in path.parts or path.name.startswith("test_")):
            continue
        if relative.startswith("docs/pydoc/"):
            continue
        human_files += 1
        pattern = (
            r"\ufffd|(?<![A-Za-z0-9_.?-])\?{3,}(?![A-Za-z0-9_.?-])|"
            r"(?:縺|繧|譁|蜿|荳|螟|逕|螳|險|驥|霆|蟄|譛|邱|鬥|縲)[\uFF61-\uFF9F]"
        )
        for match in re.finditer(pattern, text):
            _check_value(
                match.group(0),
                path,
                repository,
                findings,
                line=_line_number(text, match.start()),
            )

    unique = {(item["code"], item["path"], item.get("line")): item for item in findings}
    findings = list(unique.values())
    return {
        "schema_version": 1,
        "name": "text_integrity",
        "complete": not findings,
        "scanned_files": scanned_files,
        "human_files": human_files,
        "finding_count": len(findings),
        "findings": findings,
        "safety": {
            "network_contacted": False,
            "files_modified": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    """CLIから検査し、問題がある場合は非0で終了する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    arguments = parser.parse_args(argv)
    result = validate_text_integrity(arguments.repository)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
