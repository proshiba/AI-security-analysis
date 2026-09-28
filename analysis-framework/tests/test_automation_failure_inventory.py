"""公開metadata監査の母数・変更比較・読取境界を合成fixtureで検証する。"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_contract
import automation_failure_inventory as audit


def _write(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _fixture(root: Path, *, required: bool | None = True, confirmed: bool = False,
             candidate: bool = False, unknown_schema: bool = False) -> Path:
    digest = "a" * 64
    relative = f"analysis-results/malware/fixture/versions/unknown/cases/{digest}"
    case = root / relative
    _write(root / "analysis-results/catalog/cases.json", {"schema_version": 1, "cases": {
        digest: {"case_id": f"sha256:{digest}", "case_kind": "malware", "family": "fixture",
                 "version_key": "unknown", "canonical_path": relative}}})
    orch = {"schema_version": 99 if unknown_schema else 2, "sample_sha256": digest, "status": "partial",
        "family_resolution": {"status": "resolved", "family": "fixture"}, "blockers": ["config"],
        "outputs": {"config_recovered": confirmed, "network_endpoints": [
            {"value": "https://secret.example/config?token=SECRET", "role": "configuration"},
            {"value": "https://secret.example/stage", "role": "stage_download"},
            {"value": "https://secret.example/c2", "role": "static_config_c2"},
            {"value": "https://secret.example/unknown", "role": "UNSAFE-SECRET"}]},
        "candidate_outputs": {"config_candidate_recovered": candidate},
        "quality_gates": {"config": {"required": required, "satisfied": confirmed}},
        "automation": {"sample_executed": False, "network_contacted": False, "ai_used": False}}
    manifest = {"orchestration.json": _write(case / "orchestration.json", orch)}
    report = {"schema_version": 1, "sample": {"sha256": digest, "input_kind": "file",
        "size": 10, "source_name": "DO-NOT-PUBLISH-SECRET.exe"},
        "classification": {"selected_families": ["fixture"]},
        "case_state": {"status": "partial", "blockers": ["config"]},
        "analysis_contract": {"schema_version": 1, "sha256": "b" * 64},
        "assessment_only": False, "executed_sample": False, "network_contacted": False,
        "ai_used": False, "artifact_sha256": manifest}
    analysis_contract.seal_report(report)
    _write(case / "report.json", report)
    return case


def _update_report(case: Path, transform) -> None:
    path = case / "report.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    transform(report)
    analysis_contract.seal_report(report)
    _write(path, report)


def test_config_candidate_is_not_confirmed_and_roles_are_separate(tmp_path: Path) -> None:
    _fixture(tmp_path, candidate=True)
    result = audit._inventory(tmp_path)
    assert result["coverage"]["config_required_cases"] == 1
    assert result["coverage"]["recorded_config_on_required"] == {"numerator": 0, "denominator": 1, "percentage": 0.0}
    assert result["coverage"]["candidate_only_cases"] == 1
    assert result["url_role_counts"] == {"configuration": 1, "staging": 1, "c2": 1, "unknown": 1}
    assert result["automatic_dispatch_allowed"] is False
    serialized = json.dumps(result)
    assert "SECRET" not in serialized and "secret.example" not in serialized
    assert result["full_artifact_seals_verified"] is False


@pytest.mark.parametrize("required", [False, None])
def test_required_denominator_does_not_include_nonrequired(tmp_path: Path, required) -> None:
    _fixture(tmp_path, required=required, confirmed=True)
    coverage = audit._inventory(tmp_path)["coverage"]
    assert coverage["record_valid_cases"] == 1
    assert coverage["config_required_cases"] == 0
    assert coverage["recorded_config_on_required"]["percentage"] is None
    assert coverage["recorded_config_on_valid"]["numerator"] == 1


def test_unknown_schema_never_counts_as_success(tmp_path: Path) -> None:
    _fixture(tmp_path, confirmed=True, unknown_schema=True)
    result = audit._inventory(tmp_path)
    assert result["coverage"]["record_valid_cases"] == 0
    assert result["cases"][0]["config"]["status"] == "unknown"


@pytest.mark.parametrize("dimension", ["implementation_contract", "input", "evidence"])
def test_changed_conditions_require_review_not_blind_retry(tmp_path: Path, dimension: str) -> None:
    case = _fixture(tmp_path)
    initial = audit._inventory(tmp_path)
    baseline = tmp_path / "baseline.json"
    _write(baseline, initial)
    unchanged = audit._inventory(tmp_path, baseline=baseline)
    assert unchanged["cases"][0]["change_decision"] == "unchanged_no_retry"
    if dimension == "implementation_contract":
        _update_report(case, lambda report: report["analysis_contract"].update(sha256="c" * 64))
    elif dimension == "input":
        _update_report(case, lambda report: report["sample"].update(outer_sha256="d" * 64))
    else:
        path = case / "orchestration.json"
        orch = json.loads(path.read_text(encoding="utf-8"))
        orch["evidence_fixture"] = {"static_evidence_added": True}
        digest = _write(path, orch)
        _update_report(case, lambda report: report["artifact_sha256"].update({"orchestration.json": digest}))
    changed = audit._inventory(tmp_path, baseline=baseline)["cases"][0]
    assert changed["changed_dimensions"] == [dimension]
    assert changed["change_decision"] == "successor_review_required"
    assert changed["automatic_retry_allowed"] is False


def test_missing_metadata_retained_in_denominator(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    (case / "report.json").unlink()
    result = audit._inventory(tmp_path)
    assert result["coverage"]["all_cases"] == 1
    assert result["coverage"]["record_valid_cases"] == 0
    assert result["recorded_case_state_counts"] == {"unknown": 1}


def test_unbound_artifact_cannot_improve_config(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    path = case / "orchestration.json"
    orch = json.loads(path.read_text(encoding="utf-8"))
    orch["outputs"]["config_recovered"] = True
    _write(path, orch)
    result = audit._inventory(tmp_path)
    assert result["coverage"]["record_valid_cases"] == 0


@pytest.mark.parametrize("kind", ["duplicate", "escape", "bool_schema"])
def test_invalid_catalog_is_fail_closed(tmp_path: Path, kind: str) -> None:
    _fixture(tmp_path)
    path = tmp_path / "analysis-results/catalog/cases.json"
    if kind == "duplicate":
        path.write_text('{"schema_version":1,"schema_version":1,"cases":{}}', encoding="utf-8")
    else:
        value = json.loads(path.read_text(encoding="utf-8"))
        if kind == "escape":
            next(iter(value["cases"].values()))["canonical_path"] = "../secret"
        else:
            value["schema_version"] = True
        _write(path, value)
    with pytest.raises(audit.InventoryError):
        audit._inventory(tmp_path)


@pytest.mark.parametrize("kwargs", [{"max_files": 1}, {"max_bytes": 10}, {"seconds": -1}])
def test_resource_limits_never_produce_partial_success(tmp_path: Path, kwargs: dict) -> None:
    _fixture(tmp_path)
    with pytest.raises(audit.InventoryError):
        audit._inventory(tmp_path, **kwargs)


def test_hardlink_rejected_without_reading_target(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    path = case / "report.json"
    try:
        os.link(path, tmp_path / "alias.json")
    except OSError:
        pytest.skip("環境がhardlink作成に対応していません")
    with pytest.raises(audit.InventoryError, match="unsafe_metadata_file"):
        audit._inventory(tmp_path)


def test_reverification_detects_file_mutation(tmp_path: Path) -> None:
    _fixture(tmp_path)
    reader = audit._Reader(tmp_path, max_files=10, max_bytes=1_000_000, seconds=10)
    path = tmp_path / "analysis-results/catalog/cases.json"
    reader.read(path)
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(audit.InventoryError, match="file_changed"):
        reader.verify()


def test_unknown_blocker_is_redacted_and_never_dispatched(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    _update_report(case, lambda report: report["case_state"].update(blockers=["secret_password_123"]))
    result = audit._inventory(tmp_path)
    assert "secret_password_123" not in json.dumps(result)
    assert result["blocker_case_counts"]["unknown_blocker_redacted"] == 1


def test_registered_dynamic_blocker_suffix_is_not_published(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    _update_report(case, lambda report: report["case_state"].update(
        blockers=["selected_family_has_no_automatic_handler:secret_password_123"]))
    result = audit._inventory(tmp_path)
    assert "secret_password_123" not in json.dumps(result)
    assert "implement_family_handler" in {item["action_id"] for item in result["improvement_priorities"]}


def test_baseline_commitment_must_match(tmp_path: Path) -> None:
    _fixture(tmp_path)
    initial = audit._inventory(tmp_path)
    initial["cases"][0]["fingerprints"]["input"] = "e" * 64
    baseline = tmp_path / "baseline.json"
    _write(baseline, initial)
    with pytest.raises(audit.InventoryError, match="baseline_commitment_invalid"):
        audit._inventory(tmp_path, baseline=baseline)


def test_isolated_cli_help() -> None:
    result = subprocess.run([sys.executable, "-I", str(COMMON / "automation_failure_inventory.py"), "--help"],
        capture_output=True, timeout=30, check=False)
    assert result.returncode == 0


def test_normalized_url_without_role_is_unknown_not_c2() -> None:
    value = {"outputs": {"network_endpoints": [
        {"scheme": "https", "host": "secret.example", "port": 443, "path": "/secret"},
        {"scheme": "https", "host": "secret.example", "port": 443, "path": "/secret"}]}}
    assert audit._url_counts(value) == {"unknown": 1}


def test_dot_and_uppercase_version_component_is_supported(tmp_path: Path) -> None:
    digest = "a" * 64
    path, family = audit._case_path(tmp_path, digest, {
        "family": "fixture", "version_key": "v11.3.2400.33.W", "case_id": f"sha256:{digest}",
        "canonical_path": f"analysis-results/malware/fixture/versions/v11.3.2400.33.W/cases/{digest}"})
    assert family == "fixture" and path.name == digest


def test_directory_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("環境がdirectory symlink作成を許可していません")
    with pytest.raises(audit.InventoryError, match="unsafe_directory"):
        audit._Reader(link, max_files=10, max_bytes=1000, seconds=10)


def test_unrelated_shared_ancestor_membership_change_is_not_drift(tmp_path: Path) -> None:
    _fixture(tmp_path)
    reader = audit._Reader(tmp_path, max_files=10, max_bytes=10000, seconds=10)
    reader.read(tmp_path / "analysis-results/catalog/cases.json")
    (tmp_path.parent / (tmp_path.name + "_unrelated")).mkdir()
    reader.verify()


def test_membership_change_inside_audit_root_is_rejected(tmp_path: Path) -> None:
    _fixture(tmp_path)
    reader = audit._Reader(tmp_path, max_files=10, max_bytes=10000, seconds=10)
    reader.read(tmp_path / "analysis-results/catalog/cases.json")
    (tmp_path / "unexpected.json").write_text("{}", encoding="utf-8")
    with pytest.raises(audit.InventoryError, match="directory_changed"):
        reader.verify()


@pytest.mark.parametrize("raw", [b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e309}'])
def test_nonfinite_numbers_are_rejected(raw: bytes) -> None:
    with pytest.raises(audit.InventoryError, match="nonfinite_json_value"):
        audit._json(raw)


@pytest.mark.parametrize("kwargs", [
    {"max_cases": True}, {"max_cases": 1.0}, {"max_cases": audit.MAX_CASES + 1},
    {"max_files": True}, {"max_files": audit.MAX_FILES + 1},
    {"max_bytes": True}, {"max_bytes": audit.MAX_TOTAL_BYTES + 1},
    {"seconds": True}, {"seconds": float("nan")}, {"seconds": float("inf")},
    {"seconds": audit.MAX_SECONDS + 1},
])
def test_private_inventory_api_cannot_bypass_hard_limits(tmp_path: Path, kwargs: dict) -> None:
    with pytest.raises(audit.InventoryError):
        audit._inventory(tmp_path, **kwargs)


@pytest.mark.parametrize("kwargs", [
    {"max_files": True}, {"max_bytes": audit.MAX_TOTAL_BYTES + 1},
    {"seconds": float("nan")}, {"seconds": float("inf")},
])
def test_reader_api_cannot_bypass_hard_limits(tmp_path: Path, kwargs: dict) -> None:
    values = {"max_files": 10, "max_bytes": 1000, "seconds": 10, **kwargs}
    with pytest.raises(audit.InventoryError):
        audit._Reader(tmp_path, **values)


def test_missing_optional_metadata_is_snapshot_bound(tmp_path: Path) -> None:
    reader = audit._Reader(tmp_path, max_files=10, max_bytes=1000, seconds=10)
    path = tmp_path / "missing.json"
    assert reader.read(path, optional=True) == (None, None)
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(audit.InventoryError, match="missing_metadata_changed"):
        reader.verify()
