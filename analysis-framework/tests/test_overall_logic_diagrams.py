"""全体ロジックの静的Mermaid図と既存case再描画を検証する。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from overall_logic_diagrams import render_overall_logic_markdown  # noqa: E402
from refresh_overall_logic_diagrams import refresh_collection  # noqa: E402

ROOT_SHA = "a" * 64
CHILD_SHA = "b" * 64


def _report() -> dict[str, object]:
    return {
        "sha256": ROOT_SHA,
        "overall_logic": {
            "summary_ja": "静的証跡から処理段階を整理しました。",
            "phase_order_basis": "観測したcall edgeだけを順序根拠にします。",
            "phases": [
                {
                    "phase_id": "startup",
                    "title_ja": "起動・初期化",
                    "description_ja": "入口処理です。",
                    "confidence": "confirmed_static_function_evidence",
                    "function_ids": ["entry"],
                },
                {
                    "phase_id": "configuration",
                    "title_ja": "設定復元",
                    "description_ja": "設定を復元します。",
                    "confidence": "confirmed_static_function_evidence",
                    "function_ids": [],
                },
                {
                    "phase_id": "communication",
                    "title_ja": "通信",
                    "description_ja": "通信候補です。",
                    "confidence": "confirmed_static_function_evidence",
                    "function_ids": [],
                },
            ],
            "observed_call_edges": [
                {
                    "caller": "entry",
                    "callee": "decode",
                    "caller_phase": "startup",
                    "callee_phase": "configuration",
                }
            ],
            "limitations_ja": ["動的実行は行っていません。"],
        },
        "functions": [
            {
                "function_id": "entry",
                "summary_ja": "入口関数です。",
                "function_analysis": {"decompilation_status": "succeeded"},
                "selection": {"reasons": ["entry_point"]},
            }
        ],
        "program_evidence": [
            {
                "program_id": f"sha256:{ROOT_SHA}",
                "name": f'{ROOT_SHA}.exe"><script>',
                "architecture": "x86",
                "relationship": "root_program",
            },
            {
                "program_id": f"sha256:{CHILD_SHA}",
                "name": "payload.dll",
                "architecture": "x86",
                "relationship": "statically_recovered_program",
            },
        ],
    }


def _layers() -> dict[str, object]:
    return {
        "layers": [
            {
                "depth": 0,
                "sha256": ROOT_SHA,
                "parent_sha256": None,
                "name": f"{ROOT_SHA}.exe",
                "format": "pe",
                "transform": "submission",
            },
            {
                "depth": 1,
                "sha256": CHILD_SHA,
                "parent_sha256": ROOT_SHA,
                "name": "payload.dll",
                "format": "pe",
                "transform": "resource_extract",
            },
        ]
    }


def test_markdown_contains_three_evidence_aware_mermaid_diagrams() -> None:
    rendered = render_overall_logic_markdown(_report(), _layers())

    assert rendered.count("```mermaid") == 3
    assert "### 実行フロー" in rendered
    assert "### 感染チェーン" in rendered
    assert "### モジュール関係" in rendered
    assert "exec_01 --> exec_02" in rendered
    assert "exec_unknown -.-> exec_03" in rendered
    assert "chain_01 -->|resource_extract| chain_02" in rendered
    assert "module_01 -->|静的復元| module_02" in rendered
    assert "<script>" not in rendered
    assert "段階間の実行順は未解決" in rendered


def test_missing_evidence_is_rendered_as_unresolved_not_invented_flow() -> None:
    rendered = render_overall_logic_markdown(
        {"sha256": ROOT_SHA, "overall_logic": {}},
        {},
    )

    assert rendered.count("```mermaid") == 3
    assert "実行フローは未解決" in rendered
    assert "初期侵入・配布経路は未観測" in rendered
    assert "内包モジュール関係は未解決" in rendered
    assert " --> exec_unknown" not in rendered


def test_refresh_collection_writes_then_reports_no_drift(tmp_path: Path) -> None:
    repository = tmp_path / "r"
    collection = (
        repository
        / "analysis-results"
        / "collections"
        / "test-collection"
    )
    case = (
        repository
        / "analysis-results"
        / "malware"
        / "x"
        / "versions"
        / "u"
        / "cases"
        / ROOT_SHA
    )
    collection.mkdir(parents=True)
    case.mkdir(parents=True)
    (collection / "manifest.json").write_text(
        json.dumps({"acquisition_items": [{"sha256": ROOT_SHA}]}),
        encoding="utf-8",
    )
    (case / "static-logic.json").write_text(
        json.dumps(_report(), ensure_ascii=False),
        encoding="utf-8",
    )
    (case / "static-layers.json").write_text(
        json.dumps(_layers(), ensure_ascii=False),
        encoding="utf-8",
    )

    first = refresh_collection(repository, collection, write=True)
    second = refresh_collection(repository, collection, write=False)

    assert first["changed_cases"] == 1
    assert second["changed_cases"] == 0
    assert (case / "OVERALL-LOGIC.md").read_text(
        encoding="utf-8"
    ).count("```mermaid") == 3
