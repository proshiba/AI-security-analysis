"""追加Ghidraレビュー統合器とiterator入力の回帰テスト。"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
FORMBOOK = ROOT / "analysis-framework" / "malware" / "formbook_loader"
for directory in (COMMON, FORMBOOK):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


STATIC = _load("merge_test_static", COMMON / "static_logic.py")
MERGE = _load(
    "merge_test_reviewed", COMMON / "merge_reviewed_static_analysis.py"
)
NATIVE = _load("merge_test_native", FORMBOOK / "native_xloader.py")


def _record(function_id: str, address: str) -> dict[str, object]:
    return {
        "function_id": function_id,
        "name": function_id,
        "address": address,
        "role": "test_role",
        "summary_ja": "合成入力の処理を確認する関数です。",
        "logic_steps_ja": ["合成値を受け取る。", "合成結果を返す。"],
        "normalized_logic": "synthetic(){ return_value(); }",
        "selected_for_characteristic_analysis": True,
        "selection_score": 100,
        "selection_reasons": ["synthetic_test"],
        "source": "ghidra-mcp",
        "tool": "ghidra-mcp",
        "program_selector": "/Synthetic/program.bin",
        "confidence": "synthetic_test",
    }


def _program(selector: str, count: int) -> dict[str, object]:
    coverage = {
        name: {
            "complete": True,
            "item_count": 0,
            "page_count": 1,
            "page_size": 10,
            "terminal_short_page_observed": True,
        }
        for name in ("imports", "exports", "strings", "segments")
    }
    return {
        "program_id": selector,
        "program_selector": selector,
        "name": Path(selector).name,
        "function_count": count,
        "ghidra_function_count": count,
        "mcp_responses_valid": True,
        "retrieval_coverage": coverage,
    }


def test_merge_is_idempotent_and_updates_inventory(tmp_path: Path) -> None:
    digest = "a" * 64
    case = tmp_path / digest
    case.mkdir()
    base = STATIC.build_static_logic_report(
        sha256=digest,
        family="synthetic",
        source_name="synthetic",
        records=[_record("first", "1000")],
        program_evidence=[_program("/Synthetic/first.bin", 2)],
    )
    base["coverage"].update(
        {
            "all_discovered_functions_inventoried": True,
            "all_characteristic_functions_attempted": True,
            "all_characteristic_functions_explained": True,
            "all_static_analysis_content_retained": True,
        }
    )
    (case / "static-logic.json").write_text(
        json.dumps(base, ensure_ascii=False), encoding="utf-8"
    )
    supplement = {
        "sha256": digest,
        "functions": [_record("second", "2000")],
        "program_evidence": [_program("/Synthetic/second.bin", 3)],
        "limitations": ["合成入力だけを使用する。"],
        "overall_logic": {
            "selected_function_count": 0,
            "phase_order_basis": "合成call順です。",
            "phases": [{"phase": "test", "summary_ja": "合成処理です。"}],
        },
    }
    supplement_path = case / "supplement.json"
    supplement_path.write_text(
        json.dumps(supplement, ensure_ascii=False), encoding="utf-8"
    )

    first = MERGE.merge(case, supplement_path)
    second = MERGE.merge(case, supplement_path)

    assert len(first["functions"]) == 2
    assert len(second["functions"]) == 2
    assert second["coverage"]["discovered_function_inventory_count"] == 5
    assert second["coverage"]["unselected_function_count"] == 3
    assert (case / "STATIC-LOGIC.md").is_file()
    assert (case / "OVERALL-LOGIC.md").is_file()


def test_network_inventory_accepts_one_shot_iterable() -> None:
    builders = (
        item
        for item in [
            NATIVE.DecodedBuilder(0x1000, 1, b"QUJDREVGR0hJSg==")
        ]
    )

    report = NATIVE.inventory_encoded_network_candidates(builders)

    assert report["builder_count"] == 1
    assert report["base64_like_candidate_count"] == 1
