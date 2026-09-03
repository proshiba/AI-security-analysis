"""collection公開集計の再投影を検証する。"""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import sync_collection_publication as target

SHA = "a" * 64


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    repository = tmp_path / "repo"
    collection = repository / "analysis-results" / "collections" / "daily"
    case = repository / "analysis-results" / "malware" / "unclassified" / "versions" / "unknown" / "cases" / SHA
    relative = case.relative_to(repository).as_posix()
    coverage = {
        "discovered_function_inventory_count": 10,
        "characteristic_function_selected_count": 2,
        "decompilation_attempted_count": 2,
        "decompilation_succeeded_count": 1,
        "decompilation_limited_or_failed_count": 1,
        "decompilation_excluded_count": 0,
        "unselected_function_count": 8,
        "ghidra_function_inventory_count": 10,
        "managed_method_inventory_count": 0,
        "ghidra_programs_with_valid_mcp_responses": 1,
        "all_characteristic_functions_attempted": True,
        "raw_private_artifacts_retained": True,
        "all_static_analysis_content_retained": True,
    }
    _write(collection / "manifest.json", {"cases": [{"case_id": f"sha256:{SHA}"}], "complete": True})
    _write(
        collection / "publication-summary.json",
        {
            "cases": [
                {
                    "sha256": SHA,
                    "case_path": relative,
                    "case_state": "complete",
                    "attribution_basis": "malwarebazaar_reported_signature",
                }
            ]
        },
    )
    _write(
        case / "report.json",
        {
            "case_state": {"status": "partial", "blockers": ["terminal", "terminal"]},
            "classification": {"selected_families": []},
        },
    )
    _write(case / "c2-analysis.json", {"sha256": SHA})
    _write(
        case / "static-logic.json",
        {
            "sha256": SHA,
            "status": "characteristic_function_static_analysis_complete_with_documented_limits",
            "coverage": coverage,
            "program_evidence": [{"program_id": "sha256:" + "b" * 64}],
        },
    )
    monkeypatch.setattr(target, "case_integrity_errors", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        target,
        "validate_c2_contract",
        lambda *args, **kwargs: {"outcome": "unresolved", "complete": False, "finding_count": 7},
    )
    monkeypatch.setattr(
        target,
        "validate_function_case",
        lambda *args, **kwargs: SimpleNamespace(valid=True, findings=[]),
    )
    return repository, collection, case


def test_build_collection_projection_refreshes_case_and_top_level(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """case値とcollection全体の集計を同じ公開成果物から生成する。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    result = target.build_collection_projection(repository, collection)
    summary = result["summary"]
    manifest = result["manifest"]
    item = summary["cases"][0]
    assert item["case_state"] == "partial"
    assert item["publication_stage"] == "partial_followup_required"
    assert item["c2_analysis_finding_count"] == 7
    assert item["family_attribution_status"] == "provider_reported_not_statically_confirmed"
    assert item["statically_confirmed_family"] is None
    assert item["family_role"] == "provider_reported_grouping"
    assert item["blockers"] == ["terminal"]
    assert item["function_analysis"]["discovered_function_inventory_count"] == 10
    assert summary["case_state_counts"] == {"partial": 1}
    assert summary["case_blocker_counts"] == {"terminal": 1}
    assert summary["static_logic_status"] == {
        "characteristic_function_static_analysis_complete_with_documented_limits": 1
    }
    assert summary["function_analysis"]["unique_pe_programs"] == 1
    assert manifest["analysis_complete"] is False
    assert manifest["complete"] is False


def test_check_then_atomic_write(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """checkはstaleを検出し、write後の再checkはcurrentになる。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    before = target.synchronize_collection_projection(repository, collection, check=True)
    assert before["status"] == "stale"
    assert before["check_passed"] is False
    updated = target.synchronize_collection_projection(repository, collection, write=True)
    assert updated["status"] == "updated"
    assert updated["check_passed"] is True
    after = target.synchronize_collection_projection(repository, collection, check=True)
    assert after == {
        "status": "current",
        "stale_files": [],
        "case_count": 1,
        "write_performed": False,
        "check_passed": True,
    }


def test_write_rejects_changed_input_without_partial_update(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """projection後に入力が変わった場合は出力を置換しない。"""

    repository, collection, case = _fixture(tmp_path, monkeypatch)
    projection = target.build_collection_projection(repository, collection)
    manifest_before = (collection / "manifest.json").read_bytes()
    summary_before = (collection / "publication-summary.json").read_bytes()
    (case / "c2-analysis.json").write_text("{}", encoding="utf-8")
    with pytest.raises(target.ProjectionError, match="入力が変更"):
        target._atomic_write_documents(
            {
                collection / "manifest.json": projection["manifest"],
                collection / "publication-summary.json": projection["summary"],
            },
            projection["source_snapshots"],
        )
    assert (collection / "manifest.json").read_bytes() == manifest_before
    assert (collection / "publication-summary.json").read_bytes() == summary_before


def test_second_replace_failure_rolls_back_first_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """2file目の置換に失敗しても1file目だけ新しくならない。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    projection = target.build_collection_projection(repository, collection)
    manifest_path = collection / "manifest.json"
    summary_path = collection / "publication-summary.json"
    before = {manifest_path: manifest_path.read_bytes(), summary_path: summary_path.read_bytes()}
    real_replace = target.os.replace
    failed = False

    def fail_summary_once(source: str | Path, destination: str | Path) -> None:
        nonlocal failed
        source_path = Path(source)
        if Path(destination) == summary_path and ".rollback." not in source_path.name and not failed:
            failed = True
            raise OSError("fixture replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(target.os, "replace", fail_summary_once)
    with pytest.raises(OSError, match="fixture replace failure"):
        target._atomic_write_documents(
            {manifest_path: projection["manifest"], summary_path: projection["summary"]},
            projection["source_snapshots"],
        )
    assert manifest_path.read_bytes() == before[manifest_path]
    assert summary_path.read_bytes() == before[summary_path]


def test_post_write_verification_failure_rolls_back_both_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """置換後のbyte再検証に失敗した場合は両fileを元へ戻す。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    projection = target.build_collection_projection(repository, collection)
    manifest_path = collection / "manifest.json"
    summary_path = collection / "publication-summary.json"
    before = {manifest_path: manifest_path.read_bytes(), summary_path: summary_path.read_bytes()}
    real_replace = target.os.replace
    corrupted = False

    def corrupt_summary_once(source: str | Path, destination: str | Path) -> None:
        nonlocal corrupted
        source_path = Path(source)
        destination_path = Path(destination)
        real_replace(source, destination)
        if destination_path == summary_path and ".rollback." not in source_path.name and not corrupted:
            corrupted = True
            destination_path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(target.os, "replace", corrupt_summary_once)
    with pytest.raises(target.ProjectionError, match="原子置換後"):
        target._atomic_write_documents(
            {manifest_path: projection["manifest"], summary_path: projection["summary"]},
            projection["source_snapshots"],
        )
    assert manifest_path.read_bytes() == before[manifest_path]
    assert summary_path.read_bytes() == before[summary_path]


def test_read_only_detects_source_change_after_projection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """checkを含むread-only処理も終了直前のsource競合を拒否する。"""

    repository, collection, case = _fixture(tmp_path, monkeypatch)
    original_builder = target.build_collection_projection

    def build_then_change(*args, **kwargs):
        result = original_builder(*args, **kwargs)
        (case / "c2-analysis.json").write_text("{}", encoding="utf-8")
        return result

    monkeypatch.setattr(target, "build_collection_projection", build_then_change)
    with pytest.raises(target.ProjectionError, match="read-only検証"):
        target.synchronize_collection_projection(repository, collection, check=True)


def test_manifest_summary_case_set_must_match(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """case集合が異なる既存summaryへ部分投影しない。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    summary = json.loads((collection / "publication-summary.json").read_text(encoding="utf-8"))
    summary["cases"] = []
    _write(collection / "publication-summary.json", summary)
    with pytest.raises(target.ProjectionError, match="case集合が不一致"):
        target.build_collection_projection(repository, collection)


def test_function_validation_failure_blocks_projection(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """完了を名乗るstatic-logicがvalidatorに失敗した場合は同期しない。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        target,
        "validate_function_case",
        lambda *args, **kwargs: SimpleNamespace(valid=False, findings=["broken"]),
    )
    with pytest.raises(target.ProjectionError, match="関数解析検証に失敗"):
        target.build_collection_projection(repository, collection)


def test_complete_report_rejects_incomplete_c2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """reportだけがcompleteでもC2契約未完了ならfail-closedにする。"""

    repository, collection, case = _fixture(tmp_path, monkeypatch)
    report = json.loads((case / "report.json").read_text(encoding="utf-8"))
    report["case_state"] = {"status": "complete", "blockers": []}
    _write(case / "report.json", report)
    with pytest.raises(target.ProjectionError, match="C2解析契約が未完了"):
        target.build_collection_projection(repository, collection)


def test_complete_report_rejects_incomplete_static_logic(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """reportとC2がcompleteでも静的ロジック未完了ならfail-closedにする。"""

    repository, collection, case = _fixture(tmp_path, monkeypatch)
    report = json.loads((case / "report.json").read_text(encoding="utf-8"))
    report["case_state"] = {"status": "complete", "blockers": []}
    _write(case / "report.json", report)
    logic = json.loads((case / "static-logic.json").read_text(encoding="utf-8"))
    logic["status"] = "function_analysis_required"
    _write(case / "static-logic.json", logic)
    monkeypatch.setattr(
        target,
        "validate_c2_contract",
        lambda *args, **kwargs: {"outcome": "confirmed", "complete": True, "finding_count": 0},
    )
    with pytest.raises(target.ProjectionError, match="代表関数静的解析が未完了"):
        target.build_collection_projection(repository, collection)


def test_projection_does_not_drop_unrelated_fields(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """管理対象外の既存fieldを保持する。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    summary_path = collection / "publication-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["custom"] = {"retained": True}
    original_case = deepcopy(summary["cases"][0])
    original_case["custom_case_field"] = "retained"
    summary["cases"][0] = original_case
    _write(summary_path, summary)
    projected = target.build_collection_projection(repository, collection)["summary"]
    assert projected["custom"] == {"retained": True}
    assert projected["cases"][0]["custom_case_field"] == "retained"


def test_provider_fields_require_empty_static_family_selection() -> None:
    """静的family選択済みcaseへprovider未確認fieldを付与しない。"""

    result = target._provider_attribution_projection(
        {"classification": {"selected_families": ["vidar"]}},
        {"attribution_basis": "malwarebazaar_reported_signature"},
    )
    assert result == {}
