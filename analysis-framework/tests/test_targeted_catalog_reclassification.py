"""明示allowlistによるcatalog限定再分類のfail-closed境界を検証する。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
sys.path.insert(0, str(COMMON))

import analysis_contract  # noqa: E402
import targeted_catalog_reclassification as targeted  # noqa: E402


DIGEST = "a" * 64
THIRD = "c" * 64
COLLECTION = "test-collection"


def _old_entry(digest: str) -> dict[str, str]:
    return {
        "attribution_status": "unresolved",
        "canonical_path": (
            "analysis-results/malware/unclassified/versions/unknown/cases/"
            f"{digest}"
        ),
        "case_id": f"sha256:{digest}",
        "case_kind": "unclassified",
        "family": "unclassified",
        "version_key": "unknown",
    }


def _new_entry(
    digest: str, family: str = "testfamily", version: str = "v1.2.3"
) -> dict[str, str]:
    return {
        "canonical_path": (
            f"analysis-results/malware/{family}/versions/{version}/cases/{digest}"
        ),
        "case_id": f"sha256:{digest}",
        "case_kind": "malware",
        "family": family,
        "version_key": version,
    }


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(targeted._render_json(value))


def _write_integrity_case(case_path: Path, digest: str) -> None:
    json_artifacts = {
        "static-layers.json": {"schema_version": 1, "layers": []},
        "classification.json": {
            "schema_version": 1,
            "selected_families": [],
            "root": {"one_shot_selection": {"family": None, "basis": None}},
        },
        "applicability.json": {
            "schema_version": 1,
            "selected_family": None,
            "selected_families": [],
            "selection_basis": None,
            "handlers": [],
            "executed_sample": False,
            "network_contacted": False,
        },
        "features.json": {"schema_version": 1},
        "campaign-labels.json": {"schema_version": 1, "labels": []},
        "static-logic.json": {
            "schema_version": 1,
            "status": "automated_script_structure",
        },
        "generic-triage.json": {"schema_version": 1, "type": "data"},
    }
    for name, value in json_artifacts.items():
        _write_json(case_path / name, value)
    (case_path / "FEATURES.md").write_text("# 検体特徴\n", encoding="utf-8")
    (case_path / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    report = {
        "schema_version": 1,
        "sample": {"sha256": digest, "source_name": "sample.bin"},
        "classification": {
            "family": None,
            "selected_family": None,
            "selected_families": [],
            "selection_basis": None,
        },
        "static_layers": "static-layers.json",
        "generic_triage": "complete",
        "analysis_contract": {
            "schema_version": 1,
            "pipeline_contract_version": analysis_contract.PIPELINE_CONTRACT_VERSION,
            "sha256": "b" * 64,
            "component_count": 0,
            "settings": {"assessment_only": False},
        },
        "handler_executions": [],
        "assessment_only": False,
        "executed_sample": False,
        "network_contacted": False,
        "knowledge_artifacts": dict(analysis_contract.REQUIRED_KNOWLEDGE_ARTIFACTS),
        "case_state": {
            "status": "triaged_unknown",
            "complete": False,
            "resumable": False,
            "blockers": [],
            "detector_error_families": [],
            "static_layer_issues": [],
            "incomplete_selected_layer_attempts": [],
        },
    }
    report["artifact_sha256"] = analysis_contract.artifact_hashes(
        case_path,
        analysis_contract.BASE_REQUIRED_ARTIFACTS | {"generic-triage.json"},
    )
    analysis_contract.seal_report(report)
    _write_json(case_path / "report.json", report)


def _fixture_repository(
    root: Path,
    *,
    old: dict[str, str] | None = None,
    new: dict[str, str] | None = None,
) -> tuple[dict[str, object], Path, Path]:
    old = _old_entry(DIGEST) if old is None else old
    new = _new_entry(DIGEST) if new is None else new
    catalog_path = root / targeted.CATALOG_RELATIVE
    _write_json(
        catalog_path,
        {"schema_version": 1, "cases": {DIGEST: old, THIRD: _old_entry(THIRD)}},
    )
    catalog_path.write_bytes(catalog_path.read_bytes().replace(b"\n", b"\r\n"))

    case_path = root / new["canonical_path"]
    metadata = {
        "schema_version": 1,
        "sha256": DIGEST,
        "case_id": f"sha256:{DIGEST}",
        "case_kind": new["case_kind"],
        "family": new["family"],
        "canonical_path": new["canonical_path"],
        "collections": [COLLECTION],
        "malware_version": {"normalized_key": new["version_key"]},
        "provenance": {"preserved": True},
    }
    if new["case_kind"] == "unclassified":
        metadata["attribution_status"] = new["attribution_status"]
    _write_json(case_path / "metadata.json", metadata)
    _write_integrity_case(case_path, DIGEST)

    manifest_path = root / "analysis-results" / "collections" / COLLECTION / "manifest.json"
    _write_json(
        manifest_path,
        {
            "schema_version": 1,
            "collection_id": COLLECTION,
            "family_sources": [],
            "cases": [{"case_id": f"sha256:{DIGEST}"}],
            "preserved": {"acquisition": True},
        },
    )
    layout = {
        "errors": [],
        "move_map": [],
        "catalog": {
            "path": targeted.CATALOG_RELATIVE,
            "document": {
                "schema_version": 1,
                "cases": {DIGEST: new, THIRD: _old_entry(THIRD)},
            },
        },
        "cases": [
            {
                "sha256": DIGEST,
                "source": new["canonical_path"],
                "target": new["canonical_path"],
                "family": new["family"],
                "malware_version": {"normalized_key": new["version_key"]},
                "collections": [COLLECTION],
            }
        ],
        "collections": [
            {
                "collection_id": COLLECTION,
                "cases": [{"case_id": f"sha256:{DIGEST}"}],
            }
        ],
    }
    return layout, catalog_path, case_path


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_dry_run_and_apply_change_only_catalog(tmp_path: Path) -> None:
    layout, catalog_path, _case_path = _fixture_repository(tmp_path)
    before = _file_hashes(tmp_path)

    plan = targeted.build_targeted_reclassification_plan(
        tmp_path, [DIGEST], layout_plan=layout
    )

    assert plan["write_performed"] is False
    assert plan["catalog_newline"] == "crlf"
    assert plan["target_sha256s"] == [DIGEST]
    assert plan["unchanged_catalog_cases"] == 1
    assert plan["invariants"]["catalog_only"] is True

    result = targeted.apply_targeted_reclassification_plan(tmp_path, plan)
    after = _file_hashes(tmp_path)

    assert result["write_performed"] is True
    changed = {path for path in before if before[path] != after[path]}
    assert changed == {targeted.CATALOG_RELATIVE}
    assert b"\r\n" in catalog_path.read_bytes()
    assert b"\n" not in catalog_path.read_bytes().replace(b"\r\n", b"")
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert catalog["cases"][DIGEST] == _new_entry(DIGEST)
    assert catalog["cases"][THIRD] == _old_entry(THIRD)


def test_unknown_version_target_is_canonical(tmp_path: Path) -> None:
    new = _new_entry(DIGEST, version="unknown")
    layout, _catalog_path, _case_path = _fixture_repository(tmp_path, new=new)

    plan = targeted.build_targeted_reclassification_plan(
        tmp_path, [DIGEST], layout_plan=layout
    )

    assert plan["updates"][0]["new"] == new


def test_reviewed_false_positive_can_return_to_unclassified(tmp_path: Path) -> None:
    old = _new_entry(DIGEST, family="falsepositive", version="unknown")
    new = _old_entry(DIGEST)
    layout, catalog_path, _case_path = _fixture_repository(
        tmp_path, old=old, new=new
    )

    plan = targeted.build_targeted_reclassification_plan(
        tmp_path, [DIGEST], layout_plan=layout
    )
    result = targeted.apply_targeted_reclassification_plan(tmp_path, plan)

    assert result["write_performed"] is True
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert catalog["cases"][DIGEST] == new


def test_classified_to_classified_reclassification_is_rejected(tmp_path: Path) -> None:
    old = _new_entry(DIGEST, family="oldfamily", version="unknown")
    new = _new_entry(DIGEST, family="newfamily", version="unknown")
    layout, _catalog_path, _case_path = _fixture_repository(
        tmp_path, old=old, new=new
    )

    with pytest.raises(
        targeted.TargetedCatalogError,
        match="unsupported reclassification direction",
    ):
        targeted.build_targeted_reclassification_plan(
            tmp_path, [DIGEST], layout_plan=layout
        )


def test_classified_family_correction_requires_reviewed_internal_proof(
    tmp_path: Path,
) -> None:
    case_path = tmp_path / "case"
    classification = {
        "selected_families": ["newfamily"],
        "attribution_basis": "type_detector_structure",
        "classification_conflicts": [],
        "all_type_detections": [
            {
                "attribution_basis": "type_detector_structure",
                "malware_type": "newfamily",
                "malware_type_confidence": "high",
                "detection": {"matched": True},
            }
        ],
    }
    _write_json(case_path / "classification.json", classification)
    metadata = {
        "attribution": {
            "basis": "internal_reviewed_static_structure",
            "reported_signature": "OldFamily",
        }
    }
    report = {
        "classification": {
            "family": "newfamily",
            "selected_family": "newfamily",
            "selected_families": ["newfamily"],
            "selection_basis": "type_detector_structure",
            "classification_conflicts": [],
        },
        "handler_executions": [
            {
                "handler_id": "newfamily:extractors.test:extract",
                "status": "succeeded",
                "selected_layer_sha256": DIGEST,
                "selected_evidence": {"sufficient": True, "tier": 3},
            }
        ],
    }

    evidence = targeted._validate_classified_family_correction(
        case_path, DIGEST, "oldfamily", "newfamily", metadata, report
    )

    assert evidence["handler_id"] == "newfamily:extractors.test:extract"
    assert evidence["handler_tier"] == 3
    assert evidence["reported_signature"] == "OldFamily"


def test_stale_plan_is_rejected(tmp_path: Path) -> None:
    layout, catalog_path, _case_path = _fixture_repository(tmp_path)
    plan = targeted.build_targeted_reclassification_plan(
        tmp_path, [DIGEST], layout_plan=layout
    )
    assert b"\r\n" in catalog_path.read_bytes()
    assert b"\n" not in catalog_path.read_bytes().replace(b"\r\n", b"")
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog["generation"] = 2
    _write_json(catalog_path, catalog)

    with pytest.raises(targeted.TargetedCatalogError, match="changed after planning"):
        targeted.apply_targeted_reclassification_plan(tmp_path, plan)


def test_target_missing_is_rejected(tmp_path: Path) -> None:
    layout, _catalog_path, _case_path = _fixture_repository(tmp_path)

    with pytest.raises(targeted.TargetedCatalogError, match="target is missing"):
        targeted.build_targeted_reclassification_plan(
            tmp_path, ["b" * 64], layout_plan=layout
        )


def test_old_path_exists_is_rejected(tmp_path: Path) -> None:
    layout, _catalog_path, _case_path = _fixture_repository(tmp_path)
    old_path = tmp_path / _old_entry(DIGEST)["canonical_path"]
    old_path.mkdir(parents=True)

    with pytest.raises(targeted.TargetedCatalogError, match="old case path still exists"):
        targeted.build_targeted_reclassification_plan(
            tmp_path, [DIGEST], layout_plan=layout
        )


def test_unexpected_third_catalog_diff_is_rejected(tmp_path: Path) -> None:
    layout, _catalog_path, _case_path = _fixture_repository(tmp_path)
    layout["catalog"]["document"]["cases"][THIRD] = _new_entry(THIRD, "thirdfamily")

    with pytest.raises(targeted.TargetedCatalogError, match="unexpected=.*c{64}"):
        targeted.build_targeted_reclassification_plan(
            tmp_path, [DIGEST], layout_plan=layout
        )


def test_duplicate_allowlist_entry_is_rejected(tmp_path: Path) -> None:
    layout, _catalog_path, _case_path = _fixture_repository(tmp_path)

    with pytest.raises(targeted.TargetedCatalogError, match="duplicate SHA-256"):
        targeted.build_targeted_reclassification_plan(
            tmp_path, [DIGEST, DIGEST], layout_plan=layout
        )


def test_atomic_replace_failure_preserves_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout, catalog_path, _case_path = _fixture_repository(tmp_path)
    plan = targeted.build_targeted_reclassification_plan(
        tmp_path, [DIGEST], layout_plan=layout
    )
    original = catalog_path.read_bytes()

    def reject_replace(_source: Path, _target: Path) -> None:
        raise OSError("replace refused")

    monkeypatch.setattr(targeted.os, "replace", reject_replace)
    with pytest.raises(OSError, match="replace refused"):
        targeted.apply_targeted_reclassification_plan(tmp_path, plan)

    assert catalog_path.read_bytes() == original
    assert list(catalog_path.parent.glob(".targeted-catalog-*.tmp")) == []
@pytest.mark.parametrize("tamper", ["seal", "artifact_hash"])
def test_case_integrity_mismatch_is_rejected(tmp_path: Path, tamper: str) -> None:
    layout, _catalog_path, case_path = _fixture_repository(tmp_path)
    if tamper == "seal":
        report_path = case_path / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["executed_sample"] = True
        _write_json(report_path, report)
    else:
        _write_json(case_path / "features.json", {"schema_version": 2})

    with pytest.raises(targeted.TargetedCatalogError, match="case integrity failed"):
        targeted.build_targeted_reclassification_plan(
            tmp_path, [DIGEST], layout_plan=layout
        )

def test_duplicate_report_json_key_is_rejected(tmp_path: Path) -> None:
    layout, _catalog_path, case_path = _fixture_repository(tmp_path)
    report_path = case_path / "report.json"
    report_text = report_path.read_text(encoding="utf-8")
    report_text = report_text.replace(
        '  "schema_version": 1,',
        '  "schema_version": 1,\n  "schema_version": 1,',
        1,
    )
    report_path.write_text(report_text, encoding="utf-8", newline="\n")

    with pytest.raises(targeted.TargetedCatalogError, match="duplicate JSON key"):
        targeted.build_targeted_reclassification_plan(
            tmp_path, [DIGEST], layout_plan=layout
        )
