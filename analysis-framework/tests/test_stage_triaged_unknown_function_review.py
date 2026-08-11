from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "common" / "stage_triaged_unknown_function_review.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("stage_triaged_unknown_function_review", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_stages_only_function_review_triaged_unknown(tmp_path: Path) -> None:
    digest = "a" * 64
    case = tmp_path / "cases" / digest
    _write(
        case / "report.json",
        {
            "assessment_only": False,
            "case_state": {
                "status": "triaged_unknown",
                "complete": False,
                "resumable": False,
                "blockers": [],
            },
        },
    )
    _write(case / "static-logic.json", {"status": "function_analysis_required"})
    _write(
        tmp_path / "summary.json",
        {"counts": {"triaged_unknown": 1, "partial": 0}, "cases": [{"sha256": digest, "case_state": "triaged_unknown"}]},
    )

    preview = MODULE.stage_cases(tmp_path)
    assert preview["candidate_count"] == 1
    assert json.loads((case / "report.json").read_text())["case_state"]["status"] == "triaged_unknown"

    result = MODULE.stage_cases(tmp_path, write=True)
    report = json.loads((case / "report.json").read_text())
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert result["candidate_count"] == 1
    assert report["case_state"]["status"] == "partial"
    assert report["case_state"]["blockers"] == [MODULE.FUNCTION_BLOCKER]
    assert isinstance(report.get("report_semantic_sha256"), str)
    assert summary["counts"]["triaged_unknown"] == 0
    assert summary["counts"]["partial"] == 1


def test_adds_missing_function_blocker_to_existing_partial(tmp_path: Path) -> None:
    digest = "b" * 64
    case = tmp_path / "cases" / digest
    _write(
        case / "report.json",
        {
            "assessment_only": False,
            "case_state": {
                "status": "partial",
                "complete": False,
                "resumable": False,
                "blockers": ["static_layer_incomplete"],
            },
        },
    )
    _write(case / "static-logic.json", {"status": "function_analysis_required"})
    _write(
        tmp_path / "summary.json",
        {"counts": {"triaged_unknown": 0, "partial": 1}, "cases": [{"sha256": digest, "case_state": "partial"}]},
    )

    result = MODULE.stage_cases(tmp_path, write=True)
    report = json.loads((case / "report.json").read_text())
    assert result["promoted_triaged_unknown_count"] == 0
    assert result["augmented_partial_count"] == 1
    assert report["case_state"]["blockers"] == [
        MODULE.FUNCTION_BLOCKER,
        "static_layer_incomplete",
    ]
