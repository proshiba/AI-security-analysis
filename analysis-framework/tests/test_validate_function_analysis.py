"""代表関数静的解析と全体ロジックの完了条件検証を確認する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from validate_function_analysis import validate_case, validate_collection  # noqa: E402


SHA256 = "a" * 64


def _write_json(path: Path, value: object) -> None:
    """test fixtureのJSONを保存する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _case_report() -> dict[str, object]:
    """完了条件を満たす最小成果物を返す。"""

    selector = f"/Malware/Test/{SHA256}.quarantine.bin"
    return {
        "sha256": SHA256,
        "status": "characteristic_function_static_analysis_complete_with_documented_limits",
        "coverage": {
            "function_inventory_count": 3,
            "discovered_function_inventory_count": 5,
            "characteristic_function_selected_count": 3,
            "characteristic_function_analyzed_count": 3,
            "decompilation_attempted_count": 2,
            "decompilation_succeeded_count": 1,
            "decompilation_limited_or_failed_count": 1,
            "decompilation_excluded_count": 1,
            "unselected_function_count": 2,
            "ghidra_program_count": 1,
            "ghidra_function_inventory_count": 3,
            "managed_method_inventory_count": 0,
            "ghidra_programs_with_valid_mcp_responses": 1,
            "all_discovered_functions_inventoried": True,
            "all_characteristic_functions_attempted": True,
            "all_characteristic_functions_explained": True,
            "all_static_analysis_content_retained": True,
        },
        "retention": {
            "all_discovered_functions_in_public_result": False,
            "all_selected_functions_in_public_result": True,
            "all_selected_normalized_logic_in_public_result": True,
            "all_selected_call_relationships_in_public_result": True,
            "full_function_inventory_retained_private": True,
            "full_raw_ghidra_index_retained_private": True,
            "all_acquired_raw_decompilations_retained_private": True,
            "all_acquired_managed_cil_retained_private": True,
            "static_analysis_content_discarded": False,
        },        "functions": [
            {
                "function_id": f"sha256:{SHA256}:0x1000",
                "selection": {"selected": True, "score": 100, "reasons": ["test_representative"]},
                "evidence": {
                    "tool": "ghidra-mcp",
                    "program_selector": selector,
                },
                "summary_ja": "入口処理です。",
                "logic_steps_ja": ["初期化します。"],
                "normalized_logic": "initialize();",
                "raw_pseudocode_exported": False,
                "callers": [],
                "callees": [],
                "api_calls": [],
                "constants": [],
                "control_flow": {},
                "fingerprints": {
                    "normalized_logic_sha256": "b" * 64,
                    "semantic_sequence_sha256": "c" * 64,
                    "semantic_simhash64": "d" * 16,
                },
                "function_analysis": {
                    "static_analysis_fields_retained": True,
                    "source_field_counts": {
                        "logic_steps": 0,
                        "callers": 0,
                        "callees": 0,
                        "api_calls": 0,
                        "constants": 0,
                        "decompilation_warnings": 0,
                    },
                    "decompilation_warnings": [],
                    "decompilation_status": "succeeded",
                    "next_analysis": "",
                },
            },
            {
                "function_id": f"sha256:{SHA256}:0x2000",
                "selection": {"selected": True, "score": 100, "reasons": ["test_representative"]},
                "evidence": {
                    "tool": "ghidra-mcp",
                    "program_selector": selector,
                },
                "summary_ja": "制約付き処理です。",
                "logic_steps_ja": ["分岐を確認します。"],
                "normalized_logic": "if (<local>) { <auto_fn>(); }",
                "raw_pseudocode_exported": False,
                "callers": [],
                "callees": [],
                "api_calls": [],
                "constants": [],
                "control_flow": {},
                "fingerprints": {
                    "normalized_logic_sha256": "b" * 64,
                    "semantic_sequence_sha256": "c" * 64,
                    "semantic_simhash64": "d" * 16,
                },
                "function_analysis": {
                    "static_analysis_fields_retained": True,
                    "source_field_counts": {
                        "logic_steps": 0,
                        "callers": 0,
                        "callees": 0,
                        "api_calls": 0,
                        "constants": 0,
                        "decompilation_warnings": 0,
                    },
                    "decompilation_warnings": [],
                    "decompilation_status": "limited_bad_instruction_or_flow",
                    "next_analysis": "indirect flowを手動で追跡します。",
                },
            },
            {
                "function_id": f"sha256:{SHA256}:0x3000",
                "selection": {"selected": True, "score": 100, "reasons": ["test_representative"]},
                "evidence": {
                    "tool": "ghidra-mcp",
                    "program_selector": selector,
                },
                "summary_ja": "外部APIです。",
                "logic_steps_ja": [],
                "normalized_logic": "",
                "raw_pseudocode_exported": False,
                "callers": [],
                "callees": [],
                "api_calls": [],
                "constants": [],
                "control_flow": {},
                "fingerprints": {
                    "normalized_logic_sha256": "b" * 64,
                    "semantic_sequence_sha256": "c" * 64,
                    "semantic_simhash64": "d" * 16,
                },
                "function_analysis": {
                    "static_analysis_fields_retained": True,
                    "source_field_counts": {
                        "logic_steps": 0,
                        "callers": 0,
                        "callees": 0,
                        "api_calls": 0,
                        "constants": 0,
                        "decompilation_warnings": 0,
                    },
                    "decompilation_warnings": [],
                    "decompilation_status": "excluded_external_or_thunk",
                    "next_analysis": "",
                },
            },
        ],
        "overall_logic": {
            "selected_function_count": 3,
            "phase_order_basis": "掲載順は解析上の整理順であり、実行順を断定しません。",
            "phases": [
                {
                    "phase_id": "startup",
                    "title_ja": "起動・初期化",
                    "function_ids": [f"sha256:{SHA256}:0x1000"],
                }
            ],
            "observed_call_edges": [],
        },        "program_evidence": [
            {
                "program_selector": selector,
                "mcp_responses_valid": True,
                "retrieval_coverage": {
                    name: {"complete": True}
                    for name in ("imports", "exports", "strings", "segments")
                },
            }
        ],
    }


def _case_dir(repository: Path) -> Path:
    """正規配置のtest case directoryを返す。"""

    return (
        repository
        / "analysis-results"
        / "malware"
        / "test"
        / "versions"
        / "unknown"
        / "cases"
        / SHA256
    )


def test_validate_case_accepts_characteristic_function_records(tmp_path: Path) -> None:
    """代表関数、選定理由、全体ロジックが揃ったcaseを受理する。"""

    case_dir = _case_dir(tmp_path)
    _write_json(case_dir / "static-logic.json", _case_report())
    (case_dir / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    (case_dir / "OVERALL-LOGIC.md").write_text("# 全体ロジック\n", encoding="utf-8")

    result = validate_case(case_dir, SHA256)

    assert result.valid is True
    assert result.findings == []
    assert result.coverage["function_inventory_count"] == 3


def test_validate_case_accepts_documented_program_structure_only(
    tmp_path: Path,
) -> None:
    """Ghidra関数inventoryが0件なら構造限定の完了結果を受理する。"""

    case_dir = _case_dir(tmp_path)
    report = _case_report()
    report["coverage"].update(
        {
            "function_inventory_count": 0,
            "discovered_function_inventory_count": 0,
            "characteristic_function_selected_count": 0,
            "characteristic_function_analyzed_count": 0,
            "decompilation_attempted_count": 0,
            "decompilation_succeeded_count": 0,
            "decompilation_limited_or_failed_count": 0,
            "decompilation_excluded_count": 0,
            "unselected_function_count": 0,
            "ghidra_function_inventory_count": 0,
        }
    )
    report["functions"] = []
    report["overall_logic"] = {
        "selected_function_count": 0,
        "phase_order_basis": "掲載順は解析上の整理順であり、実行順を断定しません。",
        "phases": [
            {
                "phase_id": "program_structure",
                "title_ja": "program構造限定解析",
                "function_ids": [],
            }
        ],
        "observed_call_edges": [],
    }
    _write_json(case_dir / "static-logic.json", report)
    (case_dir / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    (case_dir / "OVERALL-LOGIC.md").write_text("# 全体ロジック\n", encoding="utf-8")

    result = validate_case(case_dir, SHA256)

    assert result.valid is True
    assert result.coverage["characteristic_function_selected_count"] == 0


def test_validate_case_rejects_undocumented_failure(tmp_path: Path) -> None:
    """制約理由の次の解析方針がないcaseを拒否する。"""

    case_dir = _case_dir(tmp_path)
    report = _case_report()
    report["functions"][1]["function_analysis"]["next_analysis"] = ""
    _write_json(case_dir / "static-logic.json", report)
    (case_dir / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    (case_dir / "OVERALL-LOGIC.md").write_text("# 全体ロジック\n", encoding="utf-8")

    result = validate_case(case_dir, SHA256)

    assert result.valid is False
    assert any("次の解析方針" in finding for finding in result.findings)


def test_validate_case_rejects_unattempted_characteristic_function(tmp_path: Path) -> None:
    """選定されたのに逆コンパイル未試行の代表関数を拒否する。"""

    case_dir = _case_dir(tmp_path)
    report = _case_report()
    report["functions"][1]["function_analysis"][
        "decompilation_status"
    ] = "failed_not_attempted"
    _write_json(case_dir / "static-logic.json", report)
    (case_dir / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    (case_dir / "OVERALL-LOGIC.md").write_text("# 全体ロジック\n", encoding="utf-8")

    result = validate_case(case_dir, SHA256)

    assert result.valid is False
    assert any("未試行" in finding for finding in result.findings)

def test_validate_case_rejects_inconsistent_selected_count(tmp_path: Path) -> None:
    """代表関数数と公開record数の不一致を拒否する。"""

    case_dir = _case_dir(tmp_path)
    report = _case_report()
    report["coverage"]["function_inventory_count"] = 4
    _write_json(case_dir / "static-logic.json", report)
    (case_dir / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    (case_dir / "OVERALL-LOGIC.md").write_text("# 全体ロジック\n", encoding="utf-8")

    result = validate_case(case_dir, SHA256)

    assert result.valid is False
    assert any("代表関数" in finding for finding in result.findings)


def test_validate_collection_requires_every_case(tmp_path: Path) -> None:
    """collectionの欠損caseを未完了として集計する。"""

    collection = tmp_path / "analysis-results" / "collections" / "test-set"
    _write_json(
        collection / "manifest.json",
        {
            "cases": [
                {"case_id": f"sha256:{SHA256}"},
                {"case_id": f"sha256:{'b' * 64}"},
            ]
        },
    )
    case_dir = _case_dir(tmp_path)
    _write_json(case_dir / "static-logic.json", _case_report())
    (case_dir / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    (case_dir / "OVERALL-LOGIC.md").write_text("# 全体ロジック\n", encoding="utf-8")

    result = validate_collection(tmp_path, collection)

    assert result["complete"] is False
    assert result["valid_cases"] == 1
    assert result["invalid_cases"] == 1
