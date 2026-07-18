#!/usr/bin/env python3
"""解析成果物の網羅性と公開 artifact 契約を読み取り専用で監査する。

明示された report 出力以外は書き込まない。検体を開く・実行する、extractor
を呼ぶ、外部通信を行う処理はなく、repository metadata と公開成果物だけを使う。
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable

import yaml

from generate_ioc_lists import IOC_HEADER
from result_layout import canonical_static_hard_case_report_path


SCHEMA_VERSION = 1
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STANDARD_IOC_HEADER = IOC_HEADER
UNRESOLVED_MARKERS = {
    "none_recovered": re.compile(r"\bnone recovered\b", re.IGNORECASE),
    "not_recovered": re.compile(r"\bnot[_ -]recovered\b", re.IGNORECASE),
    "unknown_or_nested_delivery": re.compile(
        r"\bunknown[_ -]or[_ -]nested[_ -]delivery\b", re.IGNORECASE
    ),
    "unresolved": re.compile(r"\bunresolved\b", re.IGNORECASE),
}
RAW_PROVIDER_KEYS = {
    "archive_pw",
    "code_sign",
    "comment",
    "comments",
    "file_information",
    "intelligence",
    "ole_information",
    "reporter",
    "vendor_intel",
    "yara_rules",
}
CONFIG_RECOVERY_KEYS = {"decoded_config_recovered", "static_config_recovered"}


@dataclass(frozen=True)
class JsonDocument:
    """One parsed public JSON document and its nearest case identity."""

    path: Path
    case_sha256: str | None
    value: Any


def _relative(path: Path, repository: Path) -> str:
    return path.resolve().relative_to(repository.resolve()).as_posix()


def _case_sha(path: Path, results_root: Path) -> str | None:
    for parent in (path, *path.parents):
        if parent == results_root.parent:
            break
        value = parent.name.lower()
        if SHA256.fullmatch(value):
            return value
    return None


def _walk_keys(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


def _walk_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_items(child)


def _direct_config_recovery_state(value: Any) -> bool | None:
    """Return a direct config-recovery assertion without scanning child layers."""

    if not isinstance(value, dict):
        return None
    states = [value[key] for key in CONFIG_RECOVERY_KEYS if isinstance(value.get(key), bool)]
    return any(states) if states else None


def _config_recovery_observation(value: Any) -> tuple[int, bool] | None:
    """Select the highest-authority recovery state in one public document.

    Case summaries are authoritative. If they do not assert a state, use the
    document's terminal/config result, then explicitly selected or terminal
    subtrees. Unselected child-layer failures are intentionally ignored.
    """

    if not isinstance(value, dict):
        return None
    state = _direct_config_recovery_state(value.get("case"))
    if state is not None:
        return 0, state
    state = _direct_config_recovery_state(value)
    if state is not None:
        return 1, state
    selected_states: list[bool] = []
    for key, child in _walk_items(value):
        lowered = key.lower()
        if "selected" not in lowered and "terminal" not in lowered:
            continue
        for nested_key, nested_value in _walk_items(child):
            if nested_key in CONFIG_RECOVERY_KEYS and isinstance(nested_value, bool):
                selected_states.append(nested_value)
        direct = _direct_config_recovery_state(child)
        if direct is not None:
            selected_states.append(direct)
    if selected_states:
        return 2, any(selected_states)
    config = value.get("config")
    for candidate in (
        config,
        config.get("config") if isinstance(config, dict) else None,
    ):
        state = _direct_config_recovery_state(candidate)
        if state is not None:
            return 3, state
    return None


def _load_json_documents(
    repository: Path, results_root: Path
) -> tuple[list[JsonDocument], list[str]]:
    documents: list[JsonDocument] = []
    errors: list[str] = []
    for path in sorted(results_root.rglob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append(_relative(path, repository))
            continue
        documents.append(JsonDocument(path, _case_sha(path, results_root), value))
    return documents, errors


def _load_history_hashes(repository: Path) -> tuple[set[str], list[str]]:
    path = repository / "analysis_history.yaml"
    if not path.is_file():
        return set(), ["analysis_history.yaml"]
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return set(), ["analysis_history.yaml"]
    entries = document.get("analyses", []) if isinstance(document, dict) else []
    hashes: set[str] = set()
    invalid: list[str] = []
    for index, entry in enumerate(entries):
        digest = str(entry.get("sample_sha256", "")).lower() if isinstance(entry, dict) else ""
        if SHA256.fullmatch(digest):
            hashes.add(digest)
        else:
            invalid.append(f"analysis_history.yaml#analyses[{index}]")
    return hashes, invalid


def _definition_counts(repository: Path) -> dict[str, int]:
    root = repository / "analysis-framework" / "definitions"
    malware = len(list((root / "malware").glob("*.yaml")))
    workflows = len(list((root / "workflows").glob("*.yaml")))
    registry_path = repository / "analysis-framework" / "registry" / "malware_types.json"
    registry = 0
    try:
        value = json.loads(registry_path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            candidates = value.get("malware_types", value.get("families", value))
            registry = len(candidates) if isinstance(candidates, (dict, list)) else 0
        elif isinstance(value, list):
            registry = len(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return {
        "malware_definitions": malware,
        "workflow_definitions": workflows,
        "registry_families": registry,
    }


def audit_repository(repository: Path) -> dict[str, Any]:
    """Return a deterministic repository-only coverage audit."""

    repository = repository.resolve()
    results_root = repository / "analysis-results"
    if not results_root.is_dir():
        raise ValueError("repository must contain analysis-results")

    case_directories = sorted(
        {
            path.resolve()
            for path in results_root.rglob("*")
            if path.is_dir() and SHA256.fullmatch(path.name.lower())
        },
        key=lambda value: value.as_posix().casefold(),
    )
    case_hashes = {path.name.lower() for path in case_directories}
    missing_readme = [
        _relative(path, repository) for path in case_directories if not (path / "README.md").is_file()
    ]
    missing_ioc = [
        _relative(path, repository) for path in case_directories if not (path / "IOC-LIST.md").is_file()
    ]

    documents, json_parse_errors = _load_json_documents(repository, results_root)
    status_counts: Counter[str] = Counter()
    schemaless_analysis: list[str] = []
    unresolved: dict[str, set[str]] = defaultdict(set)
    config_recovery_observations: dict[str, list[tuple[int, bool, str]]] = defaultdict(list)
    provider_boundary_violations: list[str] = []
    for document in documents:
        if document.path.name == "analysis.json" and isinstance(document.value, dict):
            case = document.value.get("case", {})
            nested_status = (
                case.get("declarative_status") if isinstance(case, dict) else None
            )
            status_counts[
                str(document.value.get("status") or nested_status or "missing")
            ] += 1
            if "schema_version" not in document.value:
                schemaless_analysis.append(_relative(document.path, repository))
        serialized = json.dumps(document.value, ensure_ascii=False, sort_keys=True)
        if document.case_sha256:
            for name, pattern in UNRESOLVED_MARKERS.items():
                if pattern.search(serialized):
                    unresolved[name].add(document.case_sha256)
            observation = _config_recovery_observation(document.value)
            if observation is not None:
                priority, state = observation
                config_recovery_observations[document.case_sha256].append(
                    (priority, state, _relative(document.path, repository))
                )
        if document.path.name == "malwarebazaar-info.json":
            keys = {key.lower() for key in _walk_keys(document.value)}
            raw_flag = (
                document.value.get("raw_provider_response_published")
                if isinstance(document.value, dict)
                else None
            )
            if keys.intersection(RAW_PROVIDER_KEYS) or raw_flag is not False:
                provider_boundary_violations.append(_relative(document.path, repository))

    # Some older workflows record their terminal limitation only in a case
    # README. Include both JSON and Markdown so unresolved coverage is not
    # understated merely because result schemas differ.
    for case_directory in case_directories:
        digest = case_directory.name.lower()
        for path in sorted(case_directory.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".json", ".md"}:
                continue
            try:
                text = path.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeDecodeError):
                continue
            for name, pattern in UNRESOLVED_MARKERS.items():
                if pattern.search(text):
                    unresolved[name].add(digest)

    ioc_files = sorted(results_root.rglob("IOC-LIST.md"))
    nonstandard_ioc: list[str] = []
    for path in ioc_files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            nonstandard_ioc.append(_relative(path, repository))
            continue
        if STANDARD_IOC_HEADER not in text:
            nonstandard_ioc.append(_relative(path, repository))

    history_hashes, invalid_history = _load_history_hashes(repository)
    missing_history = sorted(case_hashes - history_hashes)

    config_not_recovered_records: list[dict[str, Any]] = []
    for digest, observations in sorted(config_recovery_observations.items()):
        priority = min(item[0] for item in observations)
        authoritative = [item for item in observations if item[0] == priority]
        if any(item[1] for item in authoritative):
            continue
        config_not_recovered_records.append(
            {
                "sha256": digest,
                "paths": sorted({item[2] for item in authoritative}),
            }
        )

    hard_case_summary: dict[str, Any] = {}
    hard_case_path = canonical_static_hard_case_report_path(results_root)
    if not hard_case_path.is_file():
        # 実移行前の read-only 互換。新規出力先は canonical research path のみ。
        hard_case_path = results_root / "static-hard-cases" / "deep-static-triage.json"
    try:
        hard_case = json.loads(hard_case_path.read_text(encoding="utf-8"))
        summary = hard_case.get("summary", {})
        if isinstance(summary, dict):
            hard_case_summary = {
                key: summary.get(key)
                for key in (
                    "total",
                    "analyzed",
                    "partial",
                    "not_found",
                    "layers_analyzed",
                    "budget_limited_cases",
                    "protector_marker_cases",
                    "expected_children_missing_cases",
                )
            }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        hard_case_summary = {"status": "report_missing_or_invalid"}

    findings = {
        "json_parse_errors": sorted(json_parse_errors),
        "case_directories_missing_readme": sorted(missing_readme),
        "case_directories_missing_ioc_list": sorted(missing_ioc),
        "analysis_json_without_schema_version": sorted(schemaless_analysis),
        "nonstandard_ioc_lists": sorted(nonstandard_ioc),
        "provider_boundary_violations": sorted(provider_boundary_violations),
        "invalid_history_entries": sorted(invalid_history),
        "case_hashes_missing_from_history": missing_history,
        "decoded_or_static_config_not_recovered_cases": config_not_recovered_records,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_mode": "repository_metadata_only",
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "emulated": False,
            "network_contacted": False,
        },
        "counts": {
            "case_directories": len(case_directories),
            "unique_case_hashes": len(case_hashes),
            "public_json_documents": len(documents),
            "ioc_list_files": len(ioc_files),
            "history_hashes": len(history_hashes),
            "decoded_or_static_config_not_recovered_cases": len(config_not_recovered_records),
            **_definition_counts(repository),
        },
        "analysis_statuses": dict(sorted(status_counts.items())),
        "unresolved_case_hashes": {
            name: sorted(values) for name, values in sorted(unresolved.items())
        },
        "hard_case_summary": hard_case_summary,
        "findings": findings,
        "finding_counts": {name: len(values) for name, values in findings.items()},
    }


def render_markdown(report: dict[str, Any]) -> str:
    """全件一覧を JSON に残し、人向けの簡潔な日本語要約を描画する。"""

    counts = report["counts"]
    finding_counts = report["finding_counts"]
    count_labels = {
        "case_directories": "ケースディレクトリ",
        "unique_case_hashes": "一意なSHA-256",
        "public_json_documents": "公開JSON文書",
        "ioc_list_files": "IOC一覧",
        "history_hashes": "履歴登録SHA-256",
        "decoded_or_static_config_not_recovered_cases": "静的設定を復元できていないケース",
        "malware_definitions": "マルウェア定義",
        "workflow_definitions": "ワークフロー定義",
        "registry_families": "レジストリ登録ファミリー",
    }
    status_labels = {
        "needs_review": "要確認",
        "ready": "完了",
        "skipped_size_limit": "サイズ上限でスキップ",
    }
    finding_labels = {
        "json_parse_errors": "JSON解析エラー",
        "case_directories_missing_readme": "READMEがないケース",
        "case_directories_missing_ioc_list": "IOC一覧がないケース",
        "analysis_json_without_schema_version": "schema_versionがないanalysis.json",
        "nonstandard_ioc_lists": "標準外のIOC一覧",
        "provider_boundary_violations": "外部情報提供者データの公開境界違反",
        "invalid_history_entries": "不正な履歴項目",
        "case_hashes_missing_from_history": "履歴未登録のケースSHA-256",
        "decoded_or_static_config_not_recovered_cases": "静的設定を復元できていないケース",
    }
    marker_labels = {
        "none_recovered": "復元なし（`none_recovered`）",
        "not_recovered": "未復元（`not_recovered`）",
        "unknown_or_nested_delivery": "不明または多重配布（`unknown_or_nested_delivery`）",
        "unresolved": "未解決（`unresolved`）",
    }
    lines = [
        "# 静的解析カバレッジ監査",
        "",
        "この報告書はリポジトリのメタデータと公開成果物だけから作成しています。",
        "検体の読込み・実行、CPU／CILエミュレーション、外部通信はいずれも行っていません。",
        "",
        "## カバレッジ",
        "",
        "| 項目 | 件数 |",
        "|---|---:|",
    ]
    for key, value in counts.items():
        lines.append(f"| {count_labels.get(key, key)} | {value} |")
    lines.extend(
        [
            "",
            "## analysis.json の状態",
            "",
            "| 状態 | 件数 |",
            "|---|---:|",
        ]
    )
    for key, value in report["analysis_statuses"].items():
        lines.append(f"| {status_labels.get(key, key)} | {value} |")
    lines.extend(
        [
            "",
            "## 契約・完全性に関する指摘",
            "",
            "| 指摘 | 件数 |",
            "|---|---:|",
        ]
    )
    for key, value in finding_counts.items():
        lines.append(f"| {finding_labels.get(key, key)} | {value} |")
    lines.extend(
        [
            "",
            "## 未解決結果の印",
            "",
            "| 分類 | ケース数 |",
            "|---|---:|",
        ]
    )
    for key, values in report["unresolved_case_hashes"].items():
        lines.append(f"| {marker_labels.get(key, key)} | {len(values)} |")
    lines.extend(
        [
            "",
            "## 難解析ケースの構造トリアージ",
            "",
            "~~~json",
            json.dumps(report["hard_case_summary"], ensure_ascii=False, indent=2),
            "~~~",
            "",
            "対応するJSONには対象パスとSHA-256を全件収録しています。",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """repositoryカバレッジ監査のCLI引数parserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="契約または完全性の指摘が残る場合に非0を返す",
    )
    return parser


def _validate_output_paths(repository: Path, paths: Iterable[Path | None]) -> None:
    root = repository.resolve()
    resolved = [path.resolve() for path in paths if path is not None]
    if len(resolved) != len(set(resolved)):
        raise ValueError("output paths must differ")
    for path in resolved:
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError("outputs must stay within the repository") from exc


def main(argv: list[str] | None = None) -> int:
    """カバレッジ監査CLIを実行し、process終了codeを返す。"""

    args = build_parser().parse_args(argv)
    repository = args.repository.resolve()
    _validate_output_paths(repository, (args.output_json, args.output_markdown))
    report = audit_repository(repository)
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    if args.output_markdown:
        args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
        args.output_markdown.write_text(render_markdown(report), encoding="utf-8")
    if not args.output_json and not args.output_markdown:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return int(args.fail_on_findings and any(report["finding_counts"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
