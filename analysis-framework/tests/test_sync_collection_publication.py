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
    (collection / "README.md").write_text(
        "# 日次collection\n\n## 静的ロジック状態\n\n| 状態 | 件数 |\n|---|---:|\n"
        "| `function_analysis_required` | 1 |\n\n"
        "個別のPE構造、静的ロジックは各ケースに記録しています。\n",
        encoding="utf-8",
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
    assert summary["family_attribution_status"] == {
        "provider_reported_not_statically_confirmed": 1
    }
    assert summary["static_logic_status"] == {
        "characteristic_function_static_analysis_complete_with_documented_limits": 1
    }
    assert summary["function_analysis"]["unique_pe_programs"] == 1
    assert manifest["analysis_complete"] is False
    assert manifest["complete"] is False


def test_build_collection_projection_downgrades_legacy_na_signature(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """旧公開物のn/a provider帰属を未解決へ戻し、raw signatureは保持する。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    summary_path = collection / "publication-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["cases"][0].update(
        {
            "attribution_basis": "unsupported_reported_signature",
            "reported_signature": " N/A ",
            "provider_reported_label": "N/A",
            "provider_reported_family": None,
            "family_attribution_status": "provider_reported_not_statically_confirmed",
            "family_role": "provider_reported_grouping",
        }
    )
    summary["family_attribution_status"] = {
        "provider_reported_not_statically_confirmed": 1
    }
    _write(summary_path, summary)

    projected = target.build_collection_projection(repository, collection)["summary"]
    item = projected["cases"][0]

    assert item["attribution_basis"] == "no_supported_family_evidence"
    assert item["family_attribution_status"] == "unresolved"
    assert item["family_role"] == "unclassified_grouping"
    assert item["provider_reported_label"] is None
    assert item["provider_reported_family"] is None
    assert item["statically_confirmed_family"] is None
    assert item["reported_signature"] == " N/A "
    assert projected["family_attribution_status"] == {"unresolved": 1}


def test_check_then_atomic_write(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """checkはstaleを検出し、write後の再checkはcurrentになる。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    before = target.synchronize_collection_projection(repository, collection, check=True)
    assert before["status"] == "stale"
    assert before["check_passed"] is False
    updated = target.synchronize_collection_projection(repository, collection, write=True)
    assert updated["status"] == "updated"
    assert updated["check_passed"] is True
    readme = (collection / "README.md").read_text(encoding="utf-8")
    assert "- 代表関数解析完了case: `1`" in readme
    assert "代表関数解析保留case" not in readme
    after = target.synchronize_collection_projection(repository, collection, check=True)
    assert after == {
        "status": "current",
        "stale_files": [],
        "case_count": 1,
        "write_performed": False,
        "check_passed": True,
    }


def test_partial_readme_projection_counts_pending_and_preserves_other_sections(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """関数未確認caseを完了扱いせず、READMEの他節を維持する。"""

    repository, collection, case = _fixture(tmp_path, monkeypatch)
    logic_path = case / "static-logic.json"
    logic = json.loads(logic_path.read_text(encoding="utf-8"))
    logic["status"] = "function_analysis_required"
    _write(logic_path, logic)
    before = (collection / "README.md").read_text(encoding="utf-8")
    assert target.synchronize_collection_projection(repository, collection, check=True)["stale_files"] == [
        "manifest.json", "publication-summary.json", "README.md"
    ]
    target.synchronize_collection_projection(repository, collection, write=True)
    readme = (collection / "README.md").read_text(encoding="utf-8")
    assert "- 代表関数解析完了case: `0`" in readme
    assert "- 代表関数解析保留case: `1`" in readme
    assert "保留caseの関数本体は未確認です。" in readme
    assert readme.split("## 静的ロジック状態", 1)[0] == before.split("## 静的ロジック状態", 1)[0]
    assert "個別のPE構造、静的ロジックは各ケースに記録しています。" in readme
    assert target.synchronize_collection_projection(repository, collection, check=True)["status"] == "current"


def test_readme_projection_exactly_48_complete_two_pending() -> None:
    """本番と同じ48/2内訳をREADMEへ決定的に描画する。"""

    summary = {
        "static_logic_status": {
            "characteristic_function_static_analysis_complete": 45,
            "characteristic_function_static_analysis_complete_with_documented_limits": 3,
            "function_analysis_required": 2,
        },
        "function_analysis": {
            "unique_pe_programs": 56,
            "discovered_function_inventory_count": 15772,
            "characteristic_function_selected_count": 617,
            "unselected_function_count": 15155,
            "ghidra_function_inventory_count": 10614,
            "managed_method_inventory_count": 5158,
            "ghidra_programs_with_valid_mcp_responses": 56,
            "characteristic_function_attempted_count": 617,
            "decompilation_succeeded_count": 560,
            "decompilation_limited_or_failed_count": 57,
        },
    }
    source = (
        "# 日次collection\n\n## 静的ロジック状態\n\n- 代表関数解析完了case: `50`\n\n"
        "個別のPE構造、静的ロジックは各ケースに記録しています。\n"
    ).encode()
    readme = target._readme_bytes(source, summary, 50).decode("utf-8")
    assert "- 代表関数解析完了case: `48`" in readme
    assert "- 代表関数解析保留case: `2`" in readme
    assert "- Ghidra／CILプログラム: `56`件の固有PE" in readme
    assert "- 発見関数／メソッドinventory: `15772`" in readme
    assert target._readme_bytes(readme.encode("utf-8"), summary, 50) == readme.encode("utf-8")


def test_complete_readme_keeps_existing_ghidra_display() -> None:
    """全件の関数解析完了時は従来の表示とbyte単位で一致する。"""

    summary = {
        "static_logic_status": {"characteristic_function_static_analysis_complete": 1},
        "function_analysis": {
            "unique_pe_programs": 1,
            "discovered_function_inventory_count": 10,
            "characteristic_function_selected_count": 2,
            "unselected_function_count": 8,
            "ghidra_function_inventory_count": 10,
            "managed_method_inventory_count": 0,
            "ghidra_programs_with_valid_mcp_responses": 1,
            "characteristic_function_attempted_count": 2,
            "decompilation_succeeded_count": 1,
            "decompilation_limited_or_failed_count": 1,
        },
    }
    source = (
        "# 日次collection\n\n## 静的ロジック状態\n\n"
        "- 代表関数解析完了case: `1`\n"
        "- Ghidra／CILプログラム: `1`件の固有PE\n"
        "- 発見関数／メソッドinventory: `10`\n"
        "- 代表関数: `2`\n"
        "- 選定外関数: `8`\n"
        "- Ghidra関数: `10`\n"
        "- managedメソッド: `0`\n"
        "- MCP成功証跡付きプログラム: `1`\n"
        "- 逆コンパイル／CIL解析試行: `2`\n"
        "- 成功: `1`\n"
        "- 制約付き／失敗: `1`\n\n"
        "全関数inventoryを保持しつつ、特徴的な代表関数を選定して解析しました。\n"
        "各caseのSTATIC-LOGIC.mdに関数解説、OVERALL-LOGIC.mdに全体処理を記録しています。\n"
        "生の逆コンパイル本文とCIL命令列はリポジトリ外へ保持しています。\n\n"
        "個別のPE構造、静的ロジックは各ケースに記録しています。\n"
    ).encode()
    assert target._readme_bytes(source, summary, 1) == source


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


def test_readme_replace_failure_rolls_back_all_outputs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """README置換に失敗しても先行するJSON集計を復元する。"""

    repository, collection, _case = _fixture(tmp_path, monkeypatch)
    paths = [collection / name for name in ("manifest.json", "publication-summary.json", "README.md")]
    before = {path: path.read_bytes() for path in paths}
    real_replace = target.os.replace
    failed = False

    def fail_readme_once(source: str | Path, destination: str | Path) -> None:
        nonlocal failed
        if Path(destination) == paths[-1] and not failed:
            failed = True
            raise OSError("fixture README replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(target.os, "replace", fail_readme_once)
    with pytest.raises(OSError, match="README replace failure"):
        target.synchronize_collection_projection(repository, collection, write=True)
    assert all(path.read_bytes() == before[path] for path in paths)


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


def test_provider_projection_treats_legacy_na_signature_as_unresolved() -> None:
    """旧summaryのn/aをprovider-onlyへ再昇格しない。"""

    result = target._provider_attribution_projection(
        {"classification": {"selected_families": []}},
        {
            "attribution_basis": "unsupported_reported_signature",
            "reported_signature": " n/A ",
        },
    )

    assert result == {
        "attribution_basis": "no_supported_family_evidence",
        "family_attribution_status": "unresolved",
        "provider_reported_label": None,
        "provider_reported_family": None,
        "statically_confirmed_family": None,
        "family_role": "unclassified_grouping",
    }
