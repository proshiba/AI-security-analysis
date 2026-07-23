#!/usr/bin/env python3
"""過去caseの公開成果物から静的ロジック情報を証拠ベースで補完する。"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from static_logic import (
    build_static_logic_report,
    redact_static_text,
    render_static_logic_markdown,
)


SCHEMA_VERSION = 1
BACKFILL_SOURCE = "repository_static_evidence_backfill_v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
TABLE_SEPARATOR_RE = re.compile(r"^\|?(?:\s*:?-+:?\s*\|)+\s*$")
SAFE_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,79}$")
JAPANESE_RE = re.compile(r"[\u3040-\u30ff\u3400-\u9fff]")

SECTION_ROLES = (
    ("静的解析", "static_analysis_summary"),
    ("静的所見", "static_analysis_summary"),
    ("技術解析", "static_analysis_summary"),
    ("アンパック", "unpacking_flow"),
    ("復元したレイヤー", "layer_recovery"),
    ("復元レイヤー", "layer_recovery"),
    ("復元関係", "layer_recovery"),
    ("感染チェーン", "delivery_chain"),
    ("実行チェーン", "delivery_chain"),
    ("配布チェーン", "delivery_chain"),
    ("処理フロー", "processing_flow"),
    ("実行フロー", "processing_flow"),
    ("ロジック", "logic_summary"),
    ("構造", "program_structure"),
    ("エントリ", "entrypoint_logic"),
    ("ロード", "loader_flow"),
    ("難読", "protection_logic"),
    ("保護", "protection_logic"),
    ("永続", "persistence_logic"),
    ("コマンド", "command_dispatch"),
    ("機能", "capability_logic"),
)
EXCLUDED_HEADINGS = (
    "c2",
    "ioc",
    "osint",
    "shodan",
    "yara",
    "sigma",
    "インフラ",
    "ライブ",
    "接続検証",
    "検知",
    "出典",
    "参考",
    "既知ファミリー",
    "攻撃キャンペーン",
    "制約",
    "安全",
    "概要",
    "結論",
    "対象",
    "ファイル",
    "分類",
    "公開サンドボックス",
)
STATIC_JSON_NAMES = {
    "analysis.json",
    "child-analysis.json",
    "extraction-result.json",
    "infection-chain-classification.json",
    "msi-analysis.json",
    "static-analysis.json",
    "submission-analysis.json",
    "triage-evidence.json",
    "vvas-static-summary.json",
}
STRUCTURE_KEYS = {
    "address_size",
    "architecture",
    "archive_resources_recovered",
    "archive_types",
    "classification",
    "compiler",
    "containerized",
    "declared_total_size",
    "depth",
    "endian",
    "entrypoint_section",
    "entropy",
    "format",
    "function_count",
    "high_entropy_sections",
    "imports",
    "is_dotnet",
    "is_go",
    "kind",
    "language",
    "machine",
    "memory_blocks",
    "overlay_format",
    "overlay_size",
    "packer_markers",
    "packing_suspected",
    "profile",
    "resource_count",
    "retained_members",
    "sections",
    "static_config_recovered",
    "symbol_count",
    "total_members",
    "total_memory_size",
    "unpack_status",
    "virtualized_shape",
    "zero_raw_virtual_sections",
}
SECRET_KEY_PARTS = (
    "c2",
    "credential",
    "domain",
    "email",
    "hash",
    "host",
    "ioc",
    "key",
    "member",
    "name",
    "password",
    "path",
    "port",
    "secret",
    "sha",
    "token",
    "url",
)


def _read_json(path: Path) -> Mapping[str, Any] | list[Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, (Mapping, list)) else None


def _family(case_dir: Path) -> str:
    metadata = _read_json(case_dir / "metadata.json")
    if isinstance(metadata, Mapping) and metadata.get("family"):
        return str(metadata["family"])
    parts = case_dir.parts
    try:
        return parts[parts.index("malware") + 1]
    except (ValueError, IndexError):
        return "unknown"


def discover_case_directories(results_root: Path) -> list[Path]:
    """固定depthのcaseディレクトリを決定的順序で列挙する。"""

    output = []
    malware_root = results_root / "malware"
    for readme in malware_root.glob("*/versions/*/cases/*/README.md"):
        case_dir = readme.parent
        if SHA256_RE.fullmatch(case_dir.name):
            output.append(case_dir.resolve())
    return sorted(set(output), key=lambda item: item.as_posix().casefold())


def _sections(markdown: str) -> list[tuple[str, list[str]]]:
    output: list[tuple[str, list[str]]] = []
    heading = ""
    lines: list[str] = []
    for line in markdown.splitlines():
        match = re.match(r"^#{2,6}\s+(.+?)\s*$", line)
        if match:
            if heading:
                output.append((heading, lines))
            heading = match.group(1).strip()
            lines = []
        elif heading:
            lines.append(line)
    if heading:
        output.append((heading, lines))
    return output


def _role_for_heading(heading: str) -> str | None:
    lowered = heading.casefold()
    if any(marker in lowered for marker in EXCLUDED_HEADINGS):
        return None
    for marker, role in SECTION_ROLES:
        if marker.casefold() in lowered:
            return role
    return None


def _clean_markdown_lines(lines: Iterable[str]) -> list[str]:
    output = []
    in_code = False
    for raw_line in lines:
        stripped = raw_line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_code = not in_code
            continue
        if in_code or not stripped or TABLE_SEPARATOR_RE.fullmatch(stripped):
            continue
        if stripped.startswith("![") or stripped in {"{", "}", "[", "]"}:
            continue
        stripped = LINK_RE.sub(r"\1", stripped)
        stripped = re.sub(r"^[-*+]\s+", "", stripped)
        stripped = re.sub(r"^\d+[.)]\s+", "", stripped)
        stripped = stripped.strip("| ")
        stripped = stripped.replace("**", "").replace("__", "").replace("`", "")
        stripped = re.sub(r"\s+", " ", redact_static_text(stripped)).strip()
        if not stripped or stripped in {"-", "なし", "未確認"}:
            continue
        if re.fullmatch(r"(?:SHA-?256|MD5|SHA-?1)[:：]?\s*\[hash省略\]", stripped, re.I):
            continue
        if not JAPANESE_RE.search(stripped):
            stripped = f"記録内容: {stripped}"
        if stripped not in output:
            output.append(stripped[:500])
        if len(output) >= 16:
            break
    return output


def _readme_units(case_dir: Path) -> list[dict[str, Any]]:
    path = case_dir / "README.md"
    try:
        markdown = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return []
    output = []
    for heading, lines in _sections(markdown):
        role = _role_for_heading(heading)
        if role is None:
            continue
        steps = _clean_markdown_lines(lines)
        if not steps:
            continue
        output.append(
            {
                "unit_id": f"readme_section_{len(output) + 1:02d}",
                "role": role,
                "summary_ja": f"READMEの「{redact_static_text(heading)}」に記録された静的処理を整理します。",
                "logic_steps_ja": steps,
                "source_artifacts": ["README.md"],
                "evidence_type": "case_report_section",
                "confidence": "inferred_from_existing_static_report",
            }
        )
        if len(output) >= 10:
            break
    return output


def _safe_scalar(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str) and len(value) <= 160:
        rendered = redact_static_text(value).strip()
        return rendered if rendered else None
    if isinstance(value, list) and len(value) <= 16:
        items = [_safe_scalar(item) for item in value]
        rendered = [item for item in items if item is not None]
        return ", ".join(rendered)[:300] if rendered else None
    return None


def _structured_observations(value: Any, *, limit: int = 40) -> list[str]:
    output: list[str] = []

    def visit(current: Any, path: tuple[str, ...], budget: list[int]) -> None:
        if budget[0] <= 0 or len(output) >= limit:
            return
        budget[0] -= 1
        if isinstance(current, Mapping):
            for key, child in current.items():
                if len(output) >= limit:
                    break
                key_text = str(key)
                lowered = key_text.casefold()
                child_path = (*path, key_text)
                if lowered in STRUCTURE_KEYS:
                    scalar = _safe_scalar(child)
                    if scalar is not None:
                        label = ".".join(child_path[-4:])
                        line = f"`{label}` は `{scalar}` と記録されています。"
                        if line not in output:
                            output.append(line)
                visit(child, child_path, budget)
        elif isinstance(current, list):
            for child in current[:64]:
                visit(child, path, budget)

    visit(value, (), [20_000])
    return output


def _json_units(case_dir: Path) -> list[dict[str, Any]]:
    output = []
    for path in sorted(case_dir.iterdir(), key=lambda item: item.name.casefold()):
        if not path.is_file() or path.name not in STATIC_JSON_NAMES:
            continue
        value = _read_json(path)
        if value is None:
            continue
        steps = _structured_observations(value)
        if not steps:
            continue
        output.append(
            {
                "unit_id": f"structured_{path.stem.replace('-', '_')}",
                "role": "structured_static_observation",
                "summary_ja": f"{path.name}の静的構造・復元状態を値の意味を限定して整理します。",
                "logic_steps_ja": steps,
                "source_artifacts": [path.name],
                "evidence_type": "structured_static_json",
                "confidence": "confirmed_repository_metadata",
            }
        )
        if len(output) >= 6:
            break
    return output


def _schema_paths(value: Any, *, limit: int = 64) -> list[str]:
    output: list[str] = []

    def visit(current: Any, path: tuple[str, ...]) -> None:
        if len(output) >= limit:
            return
        if isinstance(current, Mapping):
            for key, child in current.items():
                key_text = str(key)
                lowered = key_text.casefold()
                if not SAFE_KEY_RE.fullmatch(key_text):
                    continue
                if any(part in lowered for part in SECRET_KEY_PARTS):
                    continue
                child_path = (*path, key_text)
                rendered = ".".join(child_path[-5:])
                if rendered not in output:
                    output.append(rendered)
                visit(child, child_path)
        elif isinstance(current, list):
            for child in current[:8]:
                visit(child, path)

    visit(value, ())
    return output


def _config_schema_unit(case_dir: Path) -> dict[str, Any] | None:
    path = case_dir / "config.json"
    value = _read_json(path)
    if value is None:
        return None
    fields = _schema_paths(value)
    if not fields:
        return None
    return {
        "unit_id": "config_schema",
        "role": "config_schema",
        "summary_ja": "具体値を除外し、復元済み設定のfield構造だけを記録します。",
        "logic_steps_ja": [f"設定field `{field}` を記録しています。" for field in fields],
        "source_artifacts": ["config.json"],
        "evidence_type": "config_schema_only",
        "confidence": "confirmed_repository_metadata",
    }


def _load_ghidra_inventory(path: Path) -> dict[str, list[Mapping[str, Any]]]:
    value = _read_json(path)
    if not isinstance(value, Mapping) or not isinstance(value.get("cases"), Mapping):
        return {}
    output = {}
    for sha256, records in value["cases"].items():
        digest = str(sha256).casefold()
        if SHA256_RE.fullmatch(digest) and isinstance(records, list):
            output[digest] = [item for item in records if isinstance(item, Mapping)]
    return output


def _is_backfill_report(path: Path) -> bool:
    value = _read_json(path)
    return isinstance(value, Mapping) and value.get("analysis_source") == BACKFILL_SOURCE


def _build_case_report(
    case_dir: Path,
    ghidra_records: list[Mapping[str, Any]],
) -> dict[str, Any]:
    units = _readme_units(case_dir)
    units.extend(_json_units(case_dir))
    config_unit = _config_schema_unit(case_dir)
    if config_unit is not None:
        units.append(config_unit)
    report = build_static_logic_report(
        sha256=case_dir.name,
        family=_family(case_dir),
        source_name="公開済みcase成果物",
        processing_units=units,
        program_evidence=ghidra_records,
        analysis_source=BACKFILL_SOURCE,
    )
    report["limitations"].extend(
        [
            "既存の公開成果物だけを再評価し、記述のない機能をファミリー一般論から補完していません。",
            "具体的なIOC、資格情報、復号鍵、生の逆コンパイル全文は処理単位から除外しています。",
        ]
    )
    return report


def _render_audit(counts: Mapping[str, Any]) -> str:
    return "\n".join(
        [
            "# 過去ケース静的ロジック補完監査",
            "",
            "既存の公開成果物と、明示的なprogram selectorで取得したGhidra MCP構造情報から、",
            "過去caseの静的ロジック情報を補完しました。検体実行と外部通信は行っていません。",
            "",
            "## 集計",
            "",
            "| 項目 | 件数 |",
            "|---|---:|",
            f"| 対象case | {counts['cases']} |",
            f"| 既存のレビュー済み成果物を保持 | {counts['preserved']} |",
            f"| backfill対象 | {counts['backfilled']} |",
            f"| 処理単位を補完できたcase | {counts['cases_with_processing_units']} |",
            f"| 補完した処理単位 | {counts['processing_units']} |",
            f"| Ghidra構造を追加したcase | {counts['ghidra_cases']} |",
            f"| Ghidra program | {counts['ghidra_programs']} |",
            f"| Ghidra関数hash | {counts['ghidra_function_hashes']} |",
            f"| 生成対象成果物 | {counts['artifact_count']} |",
            "",
            "## 解釈",
            "",
            "- `processing_units`は過去レポートの処理順を再構成したもので、関数境界の確認結果ではありません。",
            "- Ghidra関数hashはコード共有候補の手掛かりであり、関数の意味や帰属を単独では証明しません。",
            "- 関数単位の逆コンパイルがないcaseは`function_analysis_required`のままです。",
            "- 具体的なIOC、資格情報、生の逆コンパイル全文は補完成果物へ複製していません。",
            "",
        ]
    )


def generate(
    repository: Path,
    *,
    write: bool = False,
    check: bool = False,
    ghidra_inventory: Path | None = None,
) -> dict[str, Any]:
    """全caseの補完成果物と監査を生成する。"""

    repository = repository.resolve()
    results_root = repository / "analysis-results"
    inventory_path = (
        ghidra_inventory.resolve()
        if ghidra_inventory is not None
        else repository / "analysis-framework" / "inventories" / "ghidra-program-evidence.json"
    )
    ghidra = _load_ghidra_inventory(inventory_path)
    cases = discover_case_directories(results_root)
    expected: dict[Path, str] = {}
    preserved = 0
    reports = []
    for case_dir in cases:
        logic_path = case_dir / "static-logic.json"
        if logic_path.is_file() and not _is_backfill_report(logic_path):
            preserved += 1
            continue
        report = _build_case_report(case_dir, ghidra.get(case_dir.name.casefold(), []))
        reports.append(report)
        expected[logic_path] = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        expected[case_dir / "STATIC-LOGIC.md"] = render_static_logic_markdown(report)
    mismatches = []
    for path, content in expected.items():
        current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        if current == content:
            continue
        mismatches.append(path.relative_to(repository).as_posix())
        if write:
            path.write_text(content, encoding="utf-8")
    counts = {
        "cases": len(cases),
        "preserved": preserved,
        "backfilled": len(reports),
        "cases_with_processing_units": sum(
            bool(item.get("processing_units")) for item in reports
        ),
        "processing_units": sum(len(item.get("processing_units", [])) for item in reports),
        "ghidra_cases": sum(bool(item.get("program_evidence")) for item in reports),
        "ghidra_programs": sum(len(item.get("program_evidence", [])) for item in reports),
        "ghidra_function_hashes": sum(
            len(program.get("function_hashes", []))
            for item in reports
            for program in item.get("program_evidence", [])
        ),
        "artifact_count": len(expected) + 2,
        "status_counts": dict(Counter(item["status"] for item in reports)),
    }
    audit_counts = dict(counts)
    audit_dir = results_root / "research" / "audits" / "static-logic-backfill-20260723"
    audit = {
        "schema_version": SCHEMA_VERSION,
        "analysis_mode": "repository_static_evidence_backfill",
        "counts": audit_counts,
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
            "raw_pseudocode_exported": False,
        },
    }
    audit_expected = {
        audit_dir / "audit.json": json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        audit_dir / "README.md": _render_audit(audit_counts),
    }
    for path, content in audit_expected.items():
        current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        if current == content:
            continue
        mismatches.append(path.relative_to(repository).as_posix())
        if write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    counts["mismatches"] = len(mismatches)
    return {
        **counts,
        "write_performed": bool(write and mismatches),
        "check_failed": bool(check and mismatches),
        "mismatch_paths": mismatches,
    }


def build_parser() -> argparse.ArgumentParser:
    """日本語helpを持つ補完CLIを構築する。"""

    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument("--ghidra-inventory", type=Path)
    parser.add_argument("--write", action="store_true", help="補完成果物を更新する")
    parser.add_argument("--check", action="store_true", help="生成差分があれば非0を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理する。"""

    args = build_parser().parse_args(argv)
    if args.write and args.check:
        raise ValueError("--write and --check are mutually exclusive")
    result = generate(
        args.repository,
        write=args.write,
        check=args.check,
        ghidra_inventory=args.ghidra_inventory,
    )
    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "mismatch_paths"},
            ensure_ascii=False,
            indent=2,
        )
    )
    return int(result["check_failed"])


if __name__ == "__main__":
    raise SystemExit(main())
