"""解析ジョブ成果物Schemaとproducer payloadの互換性を検証する。"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner as runner  # noqa: E402
import job_artifact_schemas as schemas  # noqa: E402


NOW = "2026-08-10T01:02:03Z"
DIGEST = "a" * 64


def _validator(schema: dict[str, Any]) -> Any:
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def _input_record() -> dict[str, Any]:
    return {
        "relative_path": "set/sample.bin",
        "kind": "file",
        "file_count": 1,
        "analyzer_file_count": 1,
        "total_bytes": 64,
    }


def _counts(*, partial: bool) -> dict[str, int]:
    values = {key: 0 for key in schemas.SUMMARY_COUNT_KEYS}
    values.update(
        {
            "input_files": 1,
            "analyzed": 1,
            "identified": 1,
            "automation_resolved": 0 if partial else 1,
            "automation_partial": 1 if partial else 0,
            "partial": 1 if partial else 0,
            "complete": 0 if partial else 1,
        }
    )
    return values


def _derived_counts() -> dict[str, int]:
    return {key: 0 for key in schemas.DERIVED_COUNT_KEYS}


def _success_result(*, partial: bool) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "job_id": "job-001",
        "request_sha256": DIGEST,
        "accepted": True,
        "analysis_state": "partial" if partial else "complete",
        "inputs": [_input_record()],
        "family_hint_manifest": None,
        "trusted_static_tools": None,
        "counts": _counts(partial=partial),
        "derived_counts": _derived_counts(),
        "follow_on_analysis": {
            "artifact": "follow-on-analysis.json",
            "sha256": "b" * 64,
            "status": "partial" if partial else "no_retained_payloads",
            "node_count": 1,
            "edge_count": 0,
            "error_count": 1 if partial else 0,
        },
        "artifacts": {
            "analysis_summary": "analysis/summary.json",
            "follow_on_analysis": "analysis/follow-on-analysis.json",
            "family_hint_manifest": None,
            "family_hint_manifest_sha256": None,
            "analysis_contract_bundle": "contract-inputs/analysis-contract-bundle.json",
            "analysis_contract_bundle_sha256": "c" * 64,
            "input_snapshot_manifest": "contract-inputs/input-snapshot-manifest.json",
            "input_snapshot_manifest_sha256": "d" * 64,
            "trusted_static_tools_manifest": None,
            "trusted_static_tools_manifest_sha256": None,
            "stdout": "stdout.log",
            "stderr": "stderr.log",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "analysis_output": {
                "entries": 4,
                "files": 3,
                "directories": 1,
                "total_bytes": 4096,
            },
        },
        "process": {
            "exit_code": 20 if partial else 0,
            "shell": False,
            "script": "analysis-framework/common/analyze_sample.py",
            "timeout_seconds": 3600,
        },
        "safety": {
            "network_or_live_options_allowed": False,
            "sample_execution_allowed": False,
            "summary_safety_contract_verified": True,
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        },
        "finished_at_utc": NOW,
    }


def _failure_result(state: str = "failed") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "job_id": "job-001",
        "request_sha256": DIGEST,
        "accepted": False,
        "analysis_state": state,
        "inputs": [_input_record()],
        "family_hint_manifest": None,
        "process": {"exit_code": None, "shell": False},
        "safety": {
            "network_or_live_options_allowed": False,
            "sample_execution_allowed": False,
            "ai_used": False,
            "summary_safety_contract_verified": False,
        },
        "error": {"code": "analyzer_timeout", "message": "解析を完了できませんでした"},
        "finished_at_utc": NOW,
    }


def _write_queued_snapshot(job_dir: Path) -> None:
    runner._write_status(job_dir, state="queued", terminal=False, created_at_utc=NOW)
    runner._write_progress(job_dir, phase="queued", percent=0, message="受理しました")


@pytest.mark.skipif(
    importlib.util.find_spec("jsonschema") is None,
    reason="jsonschemaが環境にないためmeta-validationを省略します",
)
def test_all_schemas_are_valid_draft_2020_12() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    for kind in schemas.ARTIFACT_KINDS:
        schema = schemas.job_artifact_json_schema(kind)
        jsonschema.Draft202012Validator.check_schema(schema)


def test_schema_constants_follow_runner_contract() -> None:
    assert schemas.SCHEMA_VERSION == runner.SCHEMA_VERSION
    assert schemas.MAX_REQUEST_INPUTS == runner.MAX_REQUEST_INPUTS
    assert schemas.MAX_DISCOVERED_FILES == runner.MAX_DISCOVERED_FILES
    assert schemas.MAX_TOTAL_INPUT_BYTES == runner.MAX_TOTAL_INPUT_BYTES
    assert schemas.MAX_ANALYSIS_OUTPUT_ENTRIES == runner.MAX_ANALYSIS_OUTPUT_ENTRIES
    assert schemas.MAX_ANALYSIS_OUTPUT_BYTES == runner.MAX_ANALYSIS_OUTPUT_BYTES
    assert schemas.MAX_TIMEOUT_SECONDS == runner.MAX_TIMEOUT_SECONDS
    assert schemas.SUMMARY_COUNT_KEYS == runner.SUMMARY_COUNT_KEYS
    assert schemas.DERIVED_COUNT_KEYS == runner.DERIVED_COUNT_KEYS
    assert set(schemas.FOLLOW_ON_STATUSES) == runner.FOLLOW_ON_STATUSES


def test_status_producer_variants_validate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    validator = _validator(schemas.status_json_schema())
    job_dir = tmp_path / "job-001"
    job_dir.mkdir()

    variants = (
        ("queued", False, None, None, None),
        ("validating", False, None, None, None),
        ("running", False, NOW, None, None),
        ("completed", True, NOW, NOW, None),
        ("completed_partial", True, NOW, NOW, None),
        ("failed", True, None, NOW, {"code": "input_missing", "message": "入力がありません"}),
        ("timed_out", True, None, NOW, {"code": "analyzer_timeout", "message": "時間上限です"}),
    )
    for state, terminal, started, finished, error in variants:
        runner._write_status(
            job_dir,
            state=state,
            terminal=terminal,
            created_at_utc=NOW,
            started_at_utc=started,
            finished_at_utc=finished,
            error=error,
        )
        payload = json.loads((job_dir / "status.json").read_text(encoding="utf-8"))
        validator.validate(payload)
        schemas.validate_job_artifact_document("status", payload, expected_job_id="job-001")


def test_progress_all_producer_phases_validate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    validator = _validator(schemas.progress_json_schema())
    job_dir = tmp_path / "job-001"
    job_dir.mkdir()
    variants = (
        ("queued", 0, {}),
        ("validating_inputs", 10, {}),
        ("static_analysis", 30, {"total_files": 1, "total_bytes": 64}),
        ("validating_results", 90, {}),
        ("completed", 100, {"completed_files": 1, "derived_files": 0, "total_files": 1}),
        ("completed_partial", 100, {"completed_files": 1, "derived_files": 1, "total_files": 1}),
        ("failed", 100, {}),
        ("timed_out", 100, {}),
    )
    for phase, percent, extra in variants:
        runner._write_progress(
            job_dir,
            phase=phase,
            percent=percent,
            message="進捗メッセージ",
            **extra,
        )
        payload = json.loads((job_dir / "progress.json").read_text(encoding="utf-8"))
        validator.validate(payload)
        schemas.validate_job_artifact_document("progress", payload, expected_job_id="job-001")


def test_failure_and_timeout_result_producer_payloads_validate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    validator = _validator(schemas.result_json_schema())
    request = runner.validate_request_object({"schema_version": 1, "job_id": "job-001", "inputs": ["set/sample.bin"]})
    job_dir = tmp_path / "job-001"
    job_dir.mkdir()

    for state, code in (("failed", "input_missing"), ("timed_out", "analyzer_timeout")):
        records = [runner.InputRecord("set/sample.bin", "file", 1, 1, 64)] if state == "timed_out" else []
        runner._write_failure(
            job_dir,
            request,
            created_at_utc=NOW,
            started_at_utc=NOW if state == "timed_out" else None,
            code=code,
            message="解析を完了できませんでした",
            state=state,
            inputs=records,
        )
        payload = json.loads((job_dir / "result.json").read_text(encoding="utf-8"))
        validator.validate(payload)
        schemas.validate_job_artifact_document("result", payload, expected_job_id="job-001")


@pytest.mark.parametrize("partial", [False, True])
def test_representative_success_and_partial_result_validate(partial: bool) -> None:
    payload = _success_result(partial=partial)
    _validator(schemas.result_json_schema()).validate(payload)
    schemas.validate_job_artifact_document("result", payload, expected_job_id="job-001")


def test_trusted_tool_provenance_requires_matching_manifest_artifact() -> None:
    """tool provenanceとjob-private manifest参照を常に同時に要求する。"""

    payload = _success_result(partial=False)
    payload["trusted_static_tools"] = {
        "profile_id": "windows-x64-pinned",
        "operator_manifest_sha256": "e" * 64,
        "snapshot_manifest_sha256": "f" * 64,
        "tools": {
            "upx": {"name": "upx.exe", "size": 1234, "sha256": "1" * 64},
            "sevenzip": None,
            "diec": None,
        },
    }
    payload["artifacts"]["trusted_static_tools_manifest"] = "contract-inputs/trusted-static-tools.json"
    payload["artifacts"]["trusted_static_tools_manifest_sha256"] = "f" * 64
    schemas.validate_job_artifact_document("result", payload)

    payload["artifacts"]["trusted_static_tools_manifest_sha256"] = "0" * 64
    with pytest.raises(schemas.JobArtifactValidationError):
        schemas.validate_job_artifact_document("result", payload)
    payload["artifacts"]["trusted_static_tools_manifest_sha256"] = "f" * 64

    payload["artifacts"]["trusted_static_tools_manifest"] = None
    payload["artifacts"]["trusted_static_tools_manifest_sha256"] = None
    with pytest.raises(schemas.JobArtifactValidationError):
        schemas.validate_job_artifact_document("result", payload)


def test_unknown_or_cross_state_fields_are_rejected() -> None:
    validator = _validator(schemas.result_json_schema())
    payload = _success_result(partial=False)
    payload["unexpected"] = True
    assert list(validator.iter_errors(payload))

    payload = _success_result(partial=False)
    payload["process"]["exit_code"] = 20
    assert list(validator.iter_errors(payload))

    progress = {
        "schema_version": 1,
        "job_id": "job-001",
        "phase": "queued",
        "percent": 0,
        "message": "受理しました",
        "updated_at_utc": NOW,
        "total_files": 1,
    }
    assert list(_validator(schemas.progress_json_schema()).iter_errors(progress))


def test_read_job_snapshot_producer_accepts_atomic_transition_with_optional_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    validator = _validator(schemas.read_job_snapshot_json_schema())
    jobs_root = tmp_path / "jobs"
    job_dir = jobs_root / "job-001"
    job_dir.mkdir(parents=True)
    runner._write_status(job_dir, state="queued", terminal=False, created_at_utc=NOW)
    runner._write_progress(job_dir, phase="queued", percent=0, message="受理しました")

    queued = runner.read_job_snapshot(jobs_root, "job-001")
    validator.validate(queued)

    runner.atomic_json(job_dir / "result.json", _success_result(partial=False))
    transient = runner.read_job_snapshot(jobs_root, "job-001")
    validator.validate(transient)

    runner._write_progress(
        job_dir,
        phase="completed",
        percent=100,
        message="完了しました",
        completed_files=1,
        derived_files=0,
        total_files=1,
    )
    runner._write_status(
        job_dir,
        state="completed",
        terminal=True,
        created_at_utc=NOW,
        started_at_utc=NOW,
        finished_at_utc=NOW,
    )
    terminal = runner.read_job_snapshot(jobs_root, "job-001")
    validator.validate(terminal)


def test_lightweight_validator_rejects_unknown_nested_field_and_boolean_count() -> None:
    payload = _success_result(partial=False)
    payload["safety"]["unknown"] = False
    with pytest.raises(schemas.JobArtifactValidationError):
        schemas.validate_job_artifact_document("result", payload)

    payload = _success_result(partial=False)
    payload["counts"]["input_files"] = True
    with pytest.raises(schemas.JobArtifactValidationError):
        schemas.validate_job_artifact_document("result", payload)


def test_read_job_snapshot_rejects_unknown_field_with_stable_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    jobs_root = tmp_path / "jobs"
    job_dir = jobs_root / "job-001"
    job_dir.mkdir(parents=True)
    _write_queued_snapshot(job_dir)
    status = json.loads((job_dir / "status.json").read_text(encoding="utf-8"))
    status["injected"] = "field"
    runner.atomic_json(job_dir / "status.json", status)

    with pytest.raises(runner.JobContractError) as captured:
        runner.read_job_snapshot(jobs_root, "job-001")
    assert captured.value.code == "job_state_invalid"


def test_read_job_snapshot_maps_duplicate_key_to_stable_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    jobs_root = tmp_path / "jobs"
    job_dir = jobs_root / "job-001"
    job_dir.mkdir(parents=True)
    _write_queued_snapshot(job_dir)
    original = (job_dir / "status.json").read_text(encoding="utf-8")
    duplicated = original.replace(
        '"schema_version": 1,',
        '"schema_version": 1,\n  "schema_version": 1,',
        1,
    )
    (job_dir / "status.json").write_text(duplicated, encoding="utf-8")

    with pytest.raises(runner.JobContractError) as captured:
        runner.read_job_snapshot(jobs_root, "job-001")
    assert captured.value.code == "job_state_invalid"


def test_read_job_snapshot_rejects_cross_job_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    jobs_root = tmp_path / "jobs"
    job_dir = jobs_root / "job-001"
    job_dir.mkdir(parents=True)
    _write_queued_snapshot(job_dir)
    progress = json.loads((job_dir / "progress.json").read_text(encoding="utf-8"))
    progress["job_id"] = "job-002"
    runner.atomic_json(job_dir / "progress.json", progress)

    with pytest.raises(runner.JobContractError) as captured:
        runner.read_job_snapshot(jobs_root, "job-001")
    assert captured.value.code == "job_state_invalid"


def test_read_job_snapshot_rejects_terminal_result_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    jobs_root = tmp_path / "jobs"
    job_dir = jobs_root / "job-001"
    job_dir.mkdir(parents=True)
    runner.atomic_json(job_dir / "result.json", _success_result(partial=False))
    runner._write_progress(
        job_dir,
        phase="completed_partial",
        percent=100,
        message="部分完了しました",
        completed_files=1,
        derived_files=0,
        total_files=1,
    )
    runner._write_status(
        job_dir,
        state="completed_partial",
        terminal=True,
        created_at_utc=NOW,
        started_at_utc=NOW,
        finished_at_utc=NOW,
    )

    with pytest.raises(runner.JobContractError) as captured:
        runner.read_job_snapshot(jobs_root, "job-001")
    assert captured.value.code == "job_state_invalid"


def test_read_job_snapshot_rejects_terminal_state_without_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    jobs_root = tmp_path / "jobs"
    job_dir = jobs_root / "job-001"
    job_dir.mkdir(parents=True)
    runner._write_progress(
        job_dir,
        phase="failed",
        percent=100,
        message="失敗しました",
    )
    runner._write_status(
        job_dir,
        state="failed",
        terminal=True,
        created_at_utc=NOW,
        finished_at_utc=NOW,
        error={"code": "input_missing", "message": "入力がありません"},
    )

    with pytest.raises(runner.JobContractError) as captured:
        runner.read_job_snapshot(jobs_root, "job-001")
    assert captured.value.code == "job_state_invalid"


def test_queued_failure_result_is_allowed_as_atomic_read_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    jobs_root = tmp_path / "jobs"
    job_dir = jobs_root / "job-001"
    job_dir.mkdir(parents=True)
    _write_queued_snapshot(job_dir)
    runner.atomic_json(job_dir / "result.json", _failure_result())

    snapshot = runner.read_job_snapshot(jobs_root, "job-001")
    assert snapshot["status"]["state"] == "queued"
    assert snapshot["result"]["analysis_state"] == "failed"


def test_nonterminal_status_rejects_failure_result_when_progress_is_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "utc_now", lambda: NOW)
    jobs_root = tmp_path / "jobs"
    job_dir = jobs_root / "job-001"
    job_dir.mkdir(parents=True)
    runner._write_status(job_dir, state="running", terminal=False, created_at_utc=NOW, started_at_utc=NOW)
    runner._write_progress(
        job_dir,
        phase="completed",
        percent=100,
        message="完了しました",
        completed_files=1,
        derived_files=0,
        total_files=1,
    )
    runner.atomic_json(job_dir / "result.json", _failure_result())

    with pytest.raises(runner.JobContractError) as captured:
        runner.read_job_snapshot(jobs_root, "job-001")
    assert captured.value.code == "job_state_invalid"


def test_cli_outputs_selected_machine_readable_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert schemas.main(["status"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output == schemas.status_json_schema()
    assert output["$schema"] == schemas.JSON_SCHEMA_DIALECT


@pytest.mark.parametrize("artifact", ("request", *schemas.ARTIFACT_KINDS))
def test_runner_schema_artifact_cli_selects_canonical_schema(
    artifact: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[object] = []
    monkeypatch.setattr(runner, "_print_json", lambda value, **_kwargs: captured.append(value))

    assert runner.main(["schema", "--artifact", artifact]) == 0
    expected = runner.job_request_json_schema() if artifact == "request" else schemas.job_artifact_json_schema(artifact)
    assert captured == [expected]


def test_schema_builders_return_independent_objects() -> None:
    first = schemas.status_json_schema()
    first["title"] = "変更"
    assert schemas.status_json_schema()["title"] != "変更"
