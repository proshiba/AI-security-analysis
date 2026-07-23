#!/usr/bin/env python3
"""case集合の代表関数静的解析と全体ロジックが完了条件を満たすか検証する。

公開成果物だけを読み、検体、Ghidra project、生の逆コンパイル本文には触れない。
発見関数のinventoryと代表関数の選定理由が記録され、代表関数の逆コンパイルまたはCIL解析が試行され、
制約付きの結果には理由と次の解析方針が残っていることを確認する。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMPLETE_STATUSES = {
    "characteristic_function_static_analysis_complete",
    "characteristic_function_static_analysis_complete_with_documented_limits",
}
EXCLUDED_DECOMPILATION_STATUSES = {
    "excluded_external_or_thunk",
    "no_managed_body",
    "static_script_structure_recorded",
}
SUCCESSFUL_DECOMPILATION_STATUSES = {"succeeded"}
UNATTEMPTED_DECOMPILATION_STATUSES = {"failed_not_attempted", "unknown"}


@dataclass
class CaseValidation:
    """1caseの検証結果を保持する。"""

    sha256: str
    case_dir: str
    status: str
    valid: bool = True
    findings: list[str] = field(default_factory=list)
    coverage: dict[str, int | bool] = field(default_factory=dict)

    def add(self, finding: str) -> None:
        """検証違反を追加する。"""

        self.valid = False
        self.findings.append(finding)

    def as_dict(self) -> dict[str, Any]:
        """JSONへ保存できる形式へ変換する。"""

        return {
            "sha256": self.sha256,
            "case_dir": self.case_dir,
            "status": self.status,
            "valid": self.valid,
            "findings": self.findings,
            "coverage": self.coverage,
        }


def _read_json(path: Path) -> dict[str, Any]:
    """UTF-8 JSON objectを読み込む。"""

    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON objectではありません: {path}")
    return value


def _case_index(repository: Path) -> dict[str, Path]:
    """リポジトリ内の正規case directoryをSHA-256で索引化する。"""

    result: dict[str, Path] = {}
    malware_root = repository / "analysis-results" / "malware"
    for path in malware_root.glob("*/versions/*/cases/*"):
        if path.is_dir() and SHA256_RE.fullmatch(path.name.casefold()):
            result[path.name.casefold()] = path
    return result


def _collection_hashes(collection_dir: Path) -> list[str]:
    """collection manifestから対象case SHA-256を順序を保って取得する。"""

    manifest = _read_json(collection_dir / "manifest.json")
    hashes: list[str] = []
    for item in manifest.get("cases", []):
        if not isinstance(item, Mapping):
            continue
        value = str(item.get("case_id") or item.get("sha256") or "")
        value = value.removeprefix("sha256:").casefold()
        if SHA256_RE.fullmatch(value):
            hashes.append(value)
    if not hashes:
        raise ValueError("collection manifestに有効なcase SHA-256がありません")
    return hashes


def _int_field(
    validation: CaseValidation,
    coverage: Mapping[str, Any],
    name: str,
) -> int:
    """coverageの非負整数を読み、異常値をfindingへ追加する。"""

    value = coverage.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        validation.add(f"coverage.{name}が非負整数ではありません")
        return 0
    return value


def _validate_function_record(
    validation: CaseValidation,
    function: Mapping[str, Any],
    index: int,
) -> str:
    """1件の関数recordを検証し、decompilation statusを返す。"""

    prefix = f"functions[{index}]"
    if not str(function.get("function_id") or "").strip():
        validation.add(f"{prefix}.function_idがありません")
    selection = function.get("selection")
    if not isinstance(selection, Mapping):
        validation.add(f"{prefix}.selectionがありません")
    else:
        if selection.get("selected") is not True:
            validation.add(f"{prefix}が代表関数として選定されていません")
        reasons = selection.get("reasons")
        if not isinstance(reasons, list) or not reasons:
            validation.add(f"{prefix}の選定理由がありません")
    evidence = function.get("evidence")
    if not isinstance(evidence, Mapping):
        validation.add(f"{prefix}.evidenceがありません")
        evidence = {}
    tool = str(evidence.get("tool") or "unknown")
    selector = str(evidence.get("program_selector") or "")
    if tool == "ghidra-mcp" and not selector.startswith("/"):
        validation.add(f"{prefix}.program_selectorが明示的なproject pathではありません")
    if tool != "ghidra-mcp" and selector in {"", "not_recorded"}:
        validation.add(f"{prefix}.program_selectorがありません")
    if not str(function.get("summary_ja") or "").strip():
        validation.add(f"{prefix}.summary_jaがありません")
    if not isinstance(function.get("logic_steps_ja"), list):
        validation.add(f"{prefix}.logic_steps_jaが配列ではありません")
    if "normalized_logic" not in function:
        validation.add(f"{prefix}.normalized_logicがありません")
    if function.get("raw_pseudocode_exported") is not False:
        validation.add(f"{prefix}.raw_pseudocode_exportedがfalseではありません")
    analysis = function.get("function_analysis")
    if not isinstance(analysis, Mapping):
        validation.add(f"{prefix}.function_analysisがありません")
        return "unknown"
    if analysis.get("static_analysis_fields_retained") is not True:
        validation.add(f"{prefix}の静的解析項目保持証跡がありません")
    source_counts = analysis.get("source_field_counts")
    if not isinstance(source_counts, Mapping):
        validation.add(f"{prefix}の静的解析元件数がありません")
        source_counts = {}
    for name in ("logic_steps", "callers", "callees", "api_calls", "constants"):
        field_name = "logic_steps_ja" if name == "logic_steps" else name
        values = function.get(field_name)
        expected_count = source_counts.get(name)
        if isinstance(expected_count, bool) or not isinstance(expected_count, int) or expected_count < 0:
            validation.add(f"{prefix}.source_field_counts.{name}が非負整数ではありません")
        elif not isinstance(values, list) or len(values) < expected_count:
            validation.add(f"{prefix}.{field_name}が静的解析元件数を保持していません")
    warning_count = source_counts.get("decompilation_warnings")
    warnings = analysis.get("decompilation_warnings")
    if isinstance(warning_count, bool) or not isinstance(warning_count, int) or warning_count < 0:
        validation.add(f"{prefix}.source_field_counts.decompilation_warningsが非負整数ではありません")
    elif not isinstance(warnings, list) or len(warnings) != warning_count:
        validation.add(f"{prefix}.decompilation_warningsが静的解析元件数を保持していません")
    fingerprints = function.get("fingerprints")
    if not isinstance(fingerprints, Mapping):
        validation.add(f"{prefix}.fingerprintsがありません")
    else:
        for name in ("normalized_logic_sha256", "semantic_sequence_sha256"):
            if not SHA256_RE.fullmatch(str(fingerprints.get(name) or "")):
                validation.add(f"{prefix}.fingerprints.{name}がSHA-256ではありません")
        if not re.fullmatch(r"[0-9a-f]{16}", str(fingerprints.get("semantic_simhash64") or "")):
            validation.add(f"{prefix}.fingerprints.semantic_simhash64が64-bit hexではありません")
    if not isinstance(function.get("control_flow"), Mapping):
        validation.add(f"{prefix}.control_flowがありません")
    status = str(analysis.get("decompilation_status") or "unknown")
    if status == "unknown":
        validation.add(f"{prefix}.decompilation_statusが未記録です")
    if status in UNATTEMPTED_DECOMPILATION_STATUSES:
        validation.add(f"{prefix}の代表関数解析が未試行です")
    if (
        status not in SUCCESSFUL_DECOMPILATION_STATUSES
        and status not in EXCLUDED_DECOMPILATION_STATUSES
        and not str(analysis.get("next_analysis") or "").strip()
    ):
        validation.add(f"{prefix}の制約に次の解析方針がありません")
    return status


def validate_case(case_dir: Path, sha256: str | None = None) -> CaseValidation:
    """公開成果物から1caseの代表関数静的解析と全体ロジックを検証する。"""

    digest = (sha256 or case_dir.name).casefold()
    validation = CaseValidation(
        sha256=digest,
        case_dir=str(case_dir),
        status="missing",
    )
    path = case_dir / "static-logic.json"
    if not path.is_file():
        validation.add("static-logic.jsonがありません")
        return validation
    try:
        report = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        validation.add(f"static-logic.jsonを読めません: {exc}")
        return validation
    validation.status = str(report.get("status") or "missing")
    if validation.status not in COMPLETE_STATUSES:
        validation.add(f"完了状態ではありません: {validation.status}")
    if str(report.get("sha256") or "").casefold() != digest:
        validation.add("成果物のSHA-256がcase directoryと一致しません")

    coverage = report.get("coverage")
    if not isinstance(coverage, Mapping):
        validation.add("coverageがありません")
        return validation
    inventory = _int_field(validation, coverage, "function_inventory_count")
    discovered = _int_field(
        validation, coverage, "discovered_function_inventory_count"
    )
    selected = _int_field(
        validation, coverage, "characteristic_function_selected_count"
    )
    analyzed = _int_field(
        validation, coverage, "characteristic_function_analyzed_count"
    )
    attempted = _int_field(validation, coverage, "decompilation_attempted_count")
    succeeded = _int_field(validation, coverage, "decompilation_succeeded_count")
    limited = _int_field(
        validation,
        coverage,
        "decompilation_limited_or_failed_count",
    )
    excluded = _int_field(validation, coverage, "decompilation_excluded_count")
    unselected = _int_field(validation, coverage, "unselected_function_count")
    programs = _int_field(validation, coverage, "ghidra_program_count")
    native_functions = _int_field(
        validation, coverage, "ghidra_function_inventory_count"
    )
    managed_methods = _int_field(
        validation, coverage, "managed_method_inventory_count"
    )
    valid_mcp_programs = _int_field(
        validation, coverage, "ghidra_programs_with_valid_mcp_responses"
    )
    validation.coverage = {
        "function_inventory_count": inventory,
        "discovered_function_inventory_count": discovered,
        "characteristic_function_selected_count": selected,
        "characteristic_function_analyzed_count": analyzed,
        "decompilation_attempted_count": attempted,
        "decompilation_succeeded_count": succeeded,
        "decompilation_limited_or_failed_count": limited,
        "decompilation_excluded_count": excluded,
        "unselected_function_count": unselected,
        "ghidra_program_count": programs,
        "ghidra_function_inventory_count": native_functions,
        "managed_method_inventory_count": managed_methods,
        "ghidra_programs_with_valid_mcp_responses": valid_mcp_programs,
        "all_discovered_functions_inventoried": bool(
            coverage.get("all_discovered_functions_inventoried")
        ),
        "all_characteristic_functions_attempted": bool(
            coverage.get("all_characteristic_functions_attempted")
        ),
        "all_characteristic_functions_explained": bool(
            coverage.get("all_characteristic_functions_explained")
        ),
    }
    if not coverage.get("all_discovered_functions_inventoried"):
        validation.add("全発見関数のinventory完了証跡がありません")
    if not coverage.get("all_characteristic_functions_attempted"):
        validation.add("全代表関数の解析試行証跡がありません")
    if not coverage.get("all_characteristic_functions_explained"):
        validation.add("全代表関数の解説完了証跡がありません")
    if not coverage.get("all_static_analysis_content_retained"):
        validation.add("取得済み静的解析内容の保持証跡がありません")
    if inventory != selected or selected != analyzed:
        validation.add("公開関数数、代表関数選定数、解析済み数が一致しません")
    if selected != attempted + excluded:
        validation.add("代表関数数と逆コンパイル試行数・静的除外数の合計が一致しません")
    if attempted != succeeded + limited:
        validation.add("解析試行数と成功数・制約数の合計が一致しません")
    if discovered < selected:
        validation.add("発見関数inventory数が代表関数数を下回っています")
    if unselected != discovered - selected:
        validation.add("選定外関数数が発見数と代表関数数の差に一致しません")
    if programs <= 0:
        validation.add("Ghidra programが記録されていません")
    if valid_mcp_programs != programs:
        validation.add("MCP成功証跡のあるprogram数がGhidra program数と一致しません")
    retention = report.get("retention")
    required_retention = {
        "all_discovered_functions_in_public_result": False,
        "all_selected_functions_in_public_result": True,
        "all_selected_normalized_logic_in_public_result": True,
        "all_selected_call_relationships_in_public_result": True,
        "full_function_inventory_retained_private": True,
        "full_raw_ghidra_index_retained_private": True,
        "all_acquired_raw_decompilations_retained_private": True,
        "all_acquired_managed_cil_retained_private": True,
        "static_analysis_content_discarded": False,
    }
    if not isinstance(retention, Mapping):
        validation.add("静的解析成果物の保持情報がありません")
    else:
        for key, expected in required_retention.items():
            if retention.get(key) is not expected:
                validation.add(f"retention.{key}が{str(expected).lower()}ではありません")

    functions = report.get("functions")
    if not isinstance(functions, list):
        validation.add("functionsが配列ではありません")
        return validation
    if len(functions) != selected:
        validation.add("functions件数と代表関数選定数が一致しません")
    statuses = [
        _validate_function_record(validation, item, index)
        for index, item in enumerate(functions)
        if isinstance(item, Mapping)
    ]
    if len(statuses) != len(functions):
        validation.add("objectではない関数recordがあります")
    observed_excluded = sum(
        value in EXCLUDED_DECOMPILATION_STATUSES for value in statuses
    )
    observed_succeeded = sum(
        value in SUCCESSFUL_DECOMPILATION_STATUSES for value in statuses
    )
    observed_limited = len(statuses) - observed_excluded - observed_succeeded
    if (observed_succeeded, observed_limited, observed_excluded) != (
        succeeded,
        limited,
        excluded,
    ):
        validation.add("関数recordの状態集計とcoverageが一致しません")

    program_evidence = report.get("program_evidence")
    if not isinstance(program_evidence, list) or len(program_evidence) != programs:
        validation.add("program evidence件数とGhidra program数が一致しません")
    else:
        for index, item in enumerate(program_evidence):
            if not isinstance(item, Mapping) or not str(
                item.get("program_selector") or ""
            ).startswith("/"):
                validation.add(
                    f"program_evidence[{index}]に明示的なprogram selectorがありません"
                )
                continue
            if item.get("mcp_responses_valid") is not True:
                validation.add(
                    f"program_evidence[{index}]にMCP成功証跡がありません"
                )
            retrieval = item.get("retrieval_coverage")
            if not isinstance(retrieval, Mapping):
                validation.add(
                    f"program_evidence[{index}]に全件ページング取得証跡がありません"
                )
                continue
            for name in ("imports", "exports", "strings", "segments"):
                evidence = retrieval.get(name)
                if not isinstance(evidence, Mapping) or evidence.get("complete") is not True:
                    validation.add(
                        f"program_evidence[{index}].retrieval_coverage.{name}が完了していません"
                    )
    overall = report.get("overall_logic")
    if not isinstance(overall, Mapping):
        validation.add("overall_logicがありません")
    else:
        if int(overall.get("selected_function_count") or 0) != selected:
            validation.add("overall_logicの代表関数数がcoverageと一致しません")
        if not isinstance(overall.get("phases"), list) or not overall.get("phases"):
            validation.add("overall_logicの処理段階がありません")
        if not str(overall.get("phase_order_basis") or "").strip():
            validation.add("overall_logicの順序根拠がありません")
    if not (case_dir / "STATIC-LOGIC.md").is_file():
        validation.add("STATIC-LOGIC.mdがありません")
    if not (case_dir / "OVERALL-LOGIC.md").is_file():
        validation.add("OVERALL-LOGIC.mdがありません")
    return validation


def validate_collection(repository: Path, collection_dir: Path) -> dict[str, Any]:
    """collection内の全caseを検証して集計を返す。"""

    repository = repository.resolve()
    collection_dir = collection_dir.resolve()
    index = _case_index(repository)
    validations: list[CaseValidation] = []
    for digest in _collection_hashes(collection_dir):
        case_dir = index.get(digest)
        if case_dir is None:
            missing = CaseValidation(
                sha256=digest,
                case_dir="",
                status="missing",
            )
            missing.add("正規case directoryがありません")
            validations.append(missing)
            continue
        validations.append(validate_case(case_dir, digest))
    return {
        "schema_version": 1,
        "collection": collection_dir.name,
        "cases": len(validations),
        "valid_cases": sum(item.valid for item in validations),
        "invalid_cases": sum(not item.valid for item in validations),
        "complete": all(item.valid for item in validations),
        "results": [item.as_dict() for item in validations],
    }


class JapaneseArgumentParser(argparse.ArgumentParser):
    """usage見出しを日本語で表示するparser。"""

    def format_usage(self) -> str:
        """usage見出しを日本語化する。"""

        return super().format_usage().replace("usage:", "使用法:", 1)

    def format_help(self) -> str:
        """helpの標準見出しを日本語化する。"""

        return (
            super()
            .format_help()
            .replace("usage:", "使用法:", 1)
            .replace("options:", "オプション:", 1)
        )


def build_parser() -> argparse.ArgumentParser:
    """CLI引数parserを構築する。"""

    parser = JapaneseArgumentParser(
        description="collectionの代表関数静的解析と全体ロジックの完了条件を検証します",
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="リポジトリroot",
    )
    parser.add_argument(
        "--collection",
        type=Path,
        required=True,
        help="検証するcollection directory",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="検証結果JSONの保存先",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    """CLI entrypoint。"""

    args = build_parser().parse_args(list(argv) if argv is not None else None)
    result = validate_collection(args.repository, args.collection)
    rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
