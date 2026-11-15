"""全形式の固定選定集計で母数、seal、安全境界、証拠の分離を検証する。"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import build_static_cohort_report as reporter  # noqa: E402
import test_summarize_one_shot_corpus as fixtures  # noqa: E402

SHA_A = "a" * 64
SHA_B = "b" * 64


def _selection(path: Path, hashes: list[str]) -> dict[str, object]:
    metadata = [{"sha256_hash": digest, "signature": "ProviderLabel", "file_type": "js", "first_seen": "2026-11-12 00:00:00"} for digest in hashes]
    value = {
        "schema_version": 1,
        "source": "MalwareBazaar Community API",
        "selection_mode": "recent_newest",
        "selector": "100",
        "selected_at": "2026-11-12T00:00:00+00:00",
        "requested": len(hashes),
        "selected": len(hashes),
        "excluded_hashes": 0,
        "excluded_hashes_sha256": reporter._digest([]),
        "selected_hashes": hashes,
        "selected_metadata": metadata,
        "max_download_bytes": 1024 * 1024,
        "max_total_download_bytes": len(hashes) * 1024 * 1024,
        "minimum_free_bytes": 0,
        "archives_remain_encrypted": True,
        "samples_executed": False,
        "complete": True,
        "items": [{"sha256": item["sha256_hash"], "metadata": dict(item)} for item in metadata],
    }
    value["selection_commitment_sha256"] = reporter.partitioner.compute_selection_commitment(value)
    fixtures._write_json(path, value)
    return value


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    run = tmp_path / "run"
    fixtures._write_case(run, SHA_A, family_status="unresolved", family=None, config_recovered=False, config_candidate=False, automation_status="partial", case_status="partial", blockers=["family_resolution"])
    fixtures._attach_unresolved_c2(run, SHA_A)
    fixtures._write_run_summary(run, [SHA_A])
    manifest = tmp_path / "source" / "manifest.json"
    _selection(manifest, [SHA_A])
    return run, manifest


def test_report_preserves_provider_only_family_and_unresolved_state(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)

    result = reporter.build_report(manifest, [run], expected_count=1)

    assert result["status"] == "processed_followup_required"
    assert result["scope"]["selection_mode"] == "recent_newest"
    assert result["metrics"]["family_resolved_count"] == 0
    assert result["metrics"]["config_confirmed_count"] == 0
    assert result["metrics"]["complete_count"] == 0
    assert result["cases"][0]["provider"]["family_label"]["value"] == "ProviderLabel"
    assert result["cases"][0]["provider"]["family_confirmation"] is False
    assert result["cases"][0]["followup"]["required"] is True
    assert result["safety"]["sample_executed"] is False


def test_report_rejects_expected_count_mismatch(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)

    with pytest.raises(reporter.StaticCohortReportError, match="期待件数"):
        reporter.build_report(manifest, [run], expected_count=100)


def test_report_rejects_unsealed_changed_artifact(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    path = run / "cases" / SHA_A / "generic-triage.json"
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(reporter.StaticCohortReportError, match="SHA-256"):
        reporter.build_report(manifest, [run], expected_count=1)


def test_report_rejects_unsafe_report_flag(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    path = run / "cases" / SHA_A / "report.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["network_contacted"] = True
    reporter.analysis_contract.seal_report(value)
    fixtures._write_json(path, value)

    with pytest.raises(reporter.corpus.CorpusSummaryError, match="安全flag"):
        reporter.build_report(manifest, [run], expected_count=1)


def test_report_rejects_missing_selected_case(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    _selection(manifest, [SHA_B, SHA_A])

    with pytest.raises(reporter.StaticCohortReportError, match="不足"):
        reporter.build_report(manifest, [run], expected_count=2)


def test_report_rejects_extra_root_in_summary(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    fixtures._write_case(run, SHA_B, family_status="unresolved", family=None, config_recovered=False)
    fixtures._write_run_summary(run, [SHA_A, SHA_B])

    with pytest.raises(reporter.StaticCohortReportError, match="root集合"):
        reporter.build_report(manifest, [run], expected_count=1)


def test_report_rejects_duplicate_case_across_runs(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    other = tmp_path / "run2"
    fixtures._write_case(other, SHA_A)
    fixtures._write_run_summary(other, [SHA_A])

    with pytest.raises(reporter.StaticCohortReportError, match="重複"):
        reporter.build_report(manifest, [run, other], expected_count=1)


@pytest.mark.parametrize("role", ["payload_delivery", "stage_download", "dead_drop", "c2_candidate", "shared_resolver"])
def test_non_control_role_never_becomes_static_c2(role: str) -> None:
    value = reporter._endpoint({"url": "https://user:secret@example.test/stage?token=secret#private", "role": role}, source="fixture", qualified=True)

    assert value is not None
    assert value["host"] == "example.test"
    assert value["path"] == "/stage"
    assert value["is_c2_static"] is False
    assert "secret" not in json.dumps(value)
    assert "private" not in json.dumps(value)


def test_control_endpoint_is_static_not_liveness_or_protocol_confirmation() -> None:
    value = reporter._endpoint({"host": "example.test", "port": 443, "role": "c2"}, source="fixture", qualified=True)

    assert value is not None
    assert value["is_c2_static"] is True
    assert value["c2_protocol_confirmed_by_reporter"] is False
    assert value["liveness_confirmed"] is False


def test_candidate_endpoint_never_becomes_qualified_config_or_c2() -> None:
    value = reporter._network({"outputs": {}, "candidate_outputs": {"qualified_network_endpoints": [{"host": "example.test", "port": 443, "role": "c2"}]}}, None, SHA_A)

    assert value["qualified_static_c2_count"] == 0
    assert value["endpoints"][0]["evidence_level"] == "candidate_only"


def test_unsealed_terminal_evidence_does_not_count_as_complete(tmp_path: Path) -> None:
    run = tmp_path / "run"
    fixtures._write_case(run, SHA_A)
    fixtures._write_run_summary(run, [SHA_A])
    manifest = tmp_path / "source" / "manifest.json"
    _selection(manifest, [SHA_A])

    value = reporter.build_report(manifest, [run], expected_count=1)

    assert value["cases"][0]["case_state"] == "complete"
    assert value["cases"][0]["analysis_complete"] is False
    assert value["metrics"]["complete_count"] == 0
    assert value["status"] == "processed_followup_required"


def test_stage_locator_has_separate_non_c2_projection(tmp_path: Path) -> None:
    run, _ = _fixture(tmp_path)
    case_dir = run / "cases" / SHA_A
    path = case_dir / "report.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    relative = "handlers/example.json"
    value["handler_executions"] = [{"status": "succeeded", "result": relative}]
    value["artifact_sha256"][relative] = fixtures._write_json(case_dir / relative, {"executed_sample": False, "network_contacted": False, "result": {"config": {"stage_locators": [{"url": "https://example.test/stage?token=secret", "role": "payload_delivery", "c2_confirmation": False}]}}})

    projected = reporter._stage_locators(case_dir, value, reporter.corpus._ReadBudget())

    assert len(projected) == 1
    assert projected[0]["role"] == "payload_delivery"
    assert projected[0]["is_c2_static"] is False
    assert "secret" not in json.dumps(projected)


def test_endpoint_path_credentials_and_local_paths_are_redacted_or_rejected() -> None:
    value = reporter._endpoint({"url": "https://user:password@example.test/token/abcd12345678?key=secret", "role": "c2"}, source="fixture", qualified=True)

    assert value is not None
    assert "password" not in json.dumps(value)
    assert "abcd12345678" not in json.dumps(value)
    assert "secret" not in json.dumps(value)
    assert reporter._endpoint("C:/Users/Admin/private.bin", source="fixture", qualified=True) is None
    assert reporter._code("C:/Users/Admin/private.bin") == "unrecognized"


def test_structural_projection_keeps_every_layer_without_names_or_iocs() -> None:
    value = reporter._structure({"layers": [{"sha256": SHA_A, "parent_sha256": None, "depth": 0, "format": "js", "transform": "submission", "size": 1, "name": "PRIVATE-NAME"}, {"sha256": SHA_B, "parent_sha256": SHA_A, "depth": 1, "format": "pe", "transform": "base64", "size": 4}], "steps": []}, {"type": "js", "iocs": {"urls": ["https://secret.example/path"]}})

    assert value["layer_count"] == 2
    assert value["format_counts"] == {"js": 1, "pe": 1}
    assert "PRIVATE-NAME" not in json.dumps(value)
    assert "secret.example" not in json.dumps(value)


def test_output_inside_repository_or_input_is_rejected(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    result = reporter.build_report(manifest, [run], expected_count=1)

    with pytest.raises(reporter.StaticCohortReportError, match="repository外"):
        reporter.write_report(reporter.REPOSITORY_ROOT / ".work" / "report", result, runs=[run], selection_manifest=manifest)
    with pytest.raises(reporter.StaticCohortReportError, match="入力"):
        reporter.write_report(run / "report", result, runs=[run], selection_manifest=manifest)


def test_elf_projection_keeps_architecture_segments_but_not_string_iocs() -> None:
    value = reporter._structure({"layers": [{"sha256": SHA_A, "parent_sha256": None, "depth": 0, "format": "elf", "transform": "submission", "size": 1024}], "steps": []}, {"type": "elf", "elf": {"bits": 64, "byte_order": "little", "machine": 62, "load_segments": [{"offset": 0, "virtual_address": "0x400000", "file_size": 800, "memory_size": 1024}], "iocs": {"ips": ["203.0.113.99"], "domains": ["secret.example"]}}})

    elf = value["layers"][0]["elf"]
    assert elf["bits"] == 64
    assert elf["machine"] == 62
    assert elf["load_segments"][0]["virtual_address"] == "0x400000"
    assert "203.0.113.99" not in json.dumps(value)
    assert "secret.example" not in json.dumps(value)


@pytest.mark.parametrize(
    ("layers", "message"),
    [
        ([{"sha256": SHA_B, "parent_sha256": SHA_A, "depth": 1}, {"sha256": SHA_A, "parent_sha256": SHA_B, "depth": 2}], "root"),
        ([{"sha256": SHA_A, "parent_sha256": None, "depth": 0}, {"sha256": SHA_B, "parent_sha256": None, "depth": 0}], "root"),
        ([{"sha256": SHA_A, "parent_sha256": None, "depth": 1}], "depth"),
        ([{"sha256": SHA_A, "parent_sha256": None, "depth": 0}, {"sha256": SHA_B, "parent_sha256": SHA_A, "depth": 7}], "depth"),
        ([{"sha256": SHA_A, "parent_sha256": None, "depth": 0}, {"sha256": SHA_A, "parent_sha256": None, "depth": 0}], "重複"),
    ],
)
def test_structure_rejects_cycles_multiple_roots_bad_depth_and_duplicates(layers: list[dict[str, object]], message: str) -> None:
    with pytest.raises(reporter.StaticCohortReportError, match=message):
        reporter._structure({"layers": layers, "steps": []}, None)


def test_structure_root_must_match_case_identity() -> None:
    with pytest.raises(reporter.StaticCohortReportError, match="case identity"):
        reporter._structure({"layers": [{"sha256": SHA_B, "parent_sha256": None, "depth": 0}], "steps": []}, None, expected_root_sha256=SHA_A)


def test_structure_rejects_cross_layer_step_report_identity() -> None:
    with pytest.raises(reporter.StaticCohortReportError, match="input layer"):
        reporter._structure({"layers": [{"sha256": SHA_A, "parent_sha256": None, "depth": 0}], "steps": [{"input_layer": {"sha256": SHA_A}, "report": {"sha256": SHA_B}}]}, None)


def test_structure_rejects_total_metadata_record_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporter, "MAX_STRUCTURE_RECORDS", 4)
    with pytest.raises(reporter.StaticCohortReportError, match="総record数"):
        reporter._structure({"layers": [{"sha256": SHA_A, "parent_sha256": None, "depth": 0}], "steps": [{"input_layer": {"sha256": SHA_A}, "report": {"sha256": SHA_A, "pe": {"sections": [{}, {}, {}]}}}]}, None)


def test_private_report_write_is_deterministic_and_japanese(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    result = reporter.build_report(manifest, [run], expected_count=1)
    destination = tmp_path / "evaluation"
    reporter.write_report(destination, result, runs=[run], selection_manifest=manifest)
    first = (destination / "summary.json").read_bytes()
    reporter.write_report(destination, copy.deepcopy(result), runs=[run], selection_manifest=manifest)

    assert (destination / "summary.json").read_bytes() == first
    text = (destination / "REPORT.md").read_text(encoding="utf-8")
    assert "検体別結果" in text
    assert "TOP-SECRET" not in first.decode("utf-8")
    assert str(tmp_path) not in first.decode("utf-8")


def test_isolated_help_does_not_need_network_or_samples() -> None:
    completed = subprocess.run([sys.executable, "-I", str(COMMON / "build_static_cohort_report.py"), "--help"], capture_output=True, check=False, timeout=30)

    assert completed.returncode == 0


def test_incomplete_opt_in_preserves_every_selected_record(tmp_path: Path) -> None:
    manifest = tmp_path / "source" / "manifest.json"
    value = _selection(manifest, [SHA_B, SHA_A])
    value["complete"] = False
    value["items"] = value["items"][:1]
    fixtures._write_json(manifest, value)

    result = reporter.build_report(manifest, [], expected_count=2, allow_incomplete_collection=True)

    assert result["status"] == "incomplete"
    assert result["complete"] is False
    assert len(result["cases"]) == 2
    assert result["coverage"]["acquired"] == 1
    assert result["coverage"]["pending_acquisition"] == 1
    assert result["coverage"]["analyzed"] == 0
    assert result["metrics"]["family_resolved_count"] == 0
    assert result["cases"][0]["unavailable_reason"] == "analysis_not_started"
    assert result["cases"][1]["unavailable_reason"] == "sample_not_acquired"
    assert all(case["analysis_present"] is False for case in result["cases"])


def test_default_rejects_incomplete_acquisition(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["complete"] = False
    value["items"] = []
    fixtures._write_json(manifest, value)

    with pytest.raises(reporter.StaticCohortReportError, match="完全取得"):
        reporter.build_report(manifest, [run], expected_count=1)


@pytest.mark.parametrize(("state", "terminal", "reason"), [("failed", True, "analysis_job_failed"), ("running", False, "analysis_job_not_finished")])
def test_incomplete_mode_does_not_adopt_failed_or_running_job_artifacts(tmp_path: Path, state: str, terminal: bool, reason: str) -> None:
    run, manifest = _fixture(tmp_path)
    fixtures._write_json(run.parent / "status.json", {"state": state, "terminal": terminal})
    fixtures._write_json(run.parent / "result.json", {"accepted": False})
    fixtures._write_json(run.parent / "request.json", {"inputs": [SHA_A]})
    (run / "cases" / SHA_A / "report.json").write_text("BROKEN-REPORT-MUST-NOT-BE-ADOPTED", encoding="utf-8")

    result = reporter.build_report(manifest, [run], expected_count=1, allow_incomplete_collection=True)

    assert result["status"] == "incomplete"
    assert result["coverage"]["analyzed"] == 0
    assert result["cases"][0]["unavailable_reason"] == reason
    assert result["cases"][0]["analysis_present"] is False
    assert result["excluded_runs"][0]["analysis_artifacts_adopted"] is False


def test_incomplete_mode_rejects_extra_failed_job_input(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    fixtures._write_json(run.parent / "status.json", {"state": "failed", "terminal": True})
    fixtures._write_json(run.parent / "request.json", {"inputs": [SHA_B]})

    with pytest.raises(reporter.StaticCohortReportError, match="一意subset"):
        reporter.build_report(manifest, [run], expected_count=1, allow_incomplete_collection=True)


def test_incomplete_mode_rejects_duplicate_acquisition_item(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["complete"] = False
    value["items"].append(copy.deepcopy(value["items"][0]))
    fixtures._write_json(manifest, value)

    with pytest.raises(reporter.StaticCohortReportError, match="重複"):
        reporter.build_report(manifest, [run], expected_count=1, allow_incomplete_collection=True)


def test_incomplete_mode_accepts_only_unique_successful_subset(tmp_path: Path) -> None:
    run, manifest = _fixture(tmp_path)
    _selection(manifest, [SHA_B, SHA_A])

    value = reporter.build_report(manifest, [run], expected_count=2, allow_incomplete_collection=True)

    assert value["status"] == "incomplete"
    assert value["coverage"]["acquired"] == 2
    assert value["coverage"]["analyzed"] == 1
    assert value["cases"][0]["analysis_present"] is False
    assert value["cases"][1]["analysis_present"] is True
    assert len(value["cases"]) == 2
