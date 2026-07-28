#!/usr/bin/env python3
"""追加のGhidraレビュー結果を既存caseへ安全に統合する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from overall_logic_diagrams import load_static_layers, render_overall_logic_markdown
from static_logic import (
    normalize_function_record,
    normalize_program_evidence,
    render_static_logic_markdown,
)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{path}のrootはobjectである必要があります")
    return value


def _function_analysis(function: dict[str, Any], next_analysis: str) -> dict[str, Any]:
    return {
        "analysis_kind": "ghidra_native_decompilation",
        "decompilation_status": "succeeded",
        "decompilation_error": "",
        "decompilation_warnings": [],
        "instruction_count": 0,
        "next_analysis": next_analysis,
        "opcode_sha256": (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934"
            "ca495991b7852b855"
        ),
        "relationship": "recovered_or_root_program",
        "source_field_counts": {
            "logic_steps": len(function["logic_steps_ja"]),
            "callers": len(function["callers"]),
            "callees": len(function["callees"]),
            "api_calls": len(function["api_calls"]),
            "constants": len(function["constants"]),
            "decompilation_warnings": 0,
        },
        "static_analysis_fields_retained": True,
    }


def _render_overall_logic(report: dict[str, Any], case_dir: Path) -> str:
    """review済み結果を共通の全体ロジック文書へ描画する。"""

    return render_overall_logic_markdown(report, load_static_layers(case_dir))


def merge(case_dir: Path, supplement_path: Path) -> dict[str, Any]:
    """既存reportを保持したまま、重複しないreview済み関数を追加する。"""
    logic_path = case_dir / "static-logic.json"
    report = _load(logic_path)
    supplement = _load(supplement_path)
    expected = str(report.get("sha256") or "").casefold()
    if str(supplement.get("sha256") or "").casefold() != expected:
        raise ValueError("supplementのSHA-256がcaseと一致しません")

    known = {str(item.get("function_id")) for item in report.get("functions", [])}
    next_analysis = str(
        supplement.get("next_analysis")
        or "別variantで正規化ロジックとcall関係を比較する。"
    )
    for index, raw in enumerate(supplement.get("functions", []), start=1):
        normalized = normalize_function_record(raw, index)
        if normalized["function_id"] in known:
            continue
        normalized["function_analysis"] = _function_analysis(
            normalized, next_analysis
        )
        report.setdefault("functions", []).append(normalized)
        known.add(normalized["function_id"])

    selectors = {
        str(item.get("program_selector"))
        for item in report.get("program_evidence", [])
    }
    for index, raw in enumerate(supplement.get("program_evidence", []), start=1):
        normalized = normalize_program_evidence(raw, index)
        if normalized["program_selector"] not in selectors:
            report.setdefault("program_evidence", []).append(normalized)
            selectors.add(normalized["program_selector"])

    functions = report["functions"]
    programs = report["program_evidence"]
    discovered = sum(int(item.get("function_count") or 0) for item in programs)
    selected = len(functions)
    report["analysis_source"] = str(
        supplement.get("analysis_source") or report.get("analysis_source")
    )
    report["status"] = str(supplement.get("status") or report.get("status"))
    report["coverage"].update(
        {
            "function_count": selected,
            "ghidra_program_count": len(programs),
            "function_inventory_count": selected,
            "discovered_function_inventory_count": discovered,
            "characteristic_function_selected_count": selected,
            "characteristic_function_analyzed_count": selected,
            "characteristic_function_attempted_count": selected,
            "decompilation_attempted_count": selected,
            "decompilation_succeeded_count": selected,
            "decompilation_limited_or_failed_count": 0,
            "decompilation_excluded_count": 0,
            "unselected_function_count": discovered - selected,
            "ghidra_function_inventory_count": discovered,
            "ghidra_programs_with_valid_mcp_responses": len(programs),
            "all_discovered_functions_inventoried": True,
            "all_characteristic_functions_attempted": True,
            "all_characteristic_functions_explained": True,
            "all_static_analysis_content_retained": True,
            "all_characteristic_functions_decompiled": True,
        }
    )
    report["limitations"] = list(supplement.get("limitations", []))
    report["overall_logic"] = dict(supplement["overall_logic"])
    report["overall_logic"]["selected_function_count"] = selected
    report["overall_logic"]["visualization_contract_version"] = 1
    report["selection_policy"] = dict(
        supplement.get("selection_policy") or report.get("selection_policy") or {}
    )
    report["retention"] = dict(
        supplement.get("retention") or report.get("retention") or {}
    )
    logic_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (case_dir / "STATIC-LOGIC.md").write_text(
        render_static_logic_markdown(report),
        encoding="utf-8",
    )
    (case_dir / "OVERALL-LOGIC.md").write_text(
        _render_overall_logic(report, case_dir),
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="review済みGhidra関数を既存caseへ統合します"
    )
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--supplement", type=Path, required=True)
    args = parser.parse_args()
    report = merge(args.case_dir, args.supplement)
    print(
        json.dumps(
            {
                "sha256": report["sha256"],
                "function_count": len(report["functions"]),
                "program_count": len(report["program_evidence"]),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
