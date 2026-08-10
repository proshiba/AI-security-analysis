"""script-only静的解析ジョブrunnerの安全境界を検証する。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner as runner  # noqa: E402


def request_value(job_id: str = "job-001", **options: Any) -> dict[str, Any]:
    """テスト用の最小要求を返す。"""

    return {
        "schema_version": 1,
        "job_id": job_id,
        "inputs": ["set/sample.bin"],
        "options": options,
    }


def make_roots(tmp_path: Path, *, data: bytes = b"MZ synthetic static bytes") -> tuple[Path, Path]:
    """相互に分離した入力rootとjob rootを作る。"""

    input_root = tmp_path / "inputs"
    jobs_root = tmp_path / "jobs"
    sample = input_root / "set" / "sample.bin"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(data)
    jobs_root.mkdir()
    return input_root, jobs_root


def write_summary(output: Path, *, network_contacted: bool = False) -> None:
    """analyze_sample.pyの最小安全summaryを作る。"""

    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "counts": {"input_files": 1, "analyzed": 1, "complete": 1},
                "executed_sample": False,
                "network_contacted": network_contacted,
            }
        ),
        encoding="utf-8",
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_request_defaults_are_normalized() -> None:
    request = runner.validate_request_object(request_value())

    assert request.job_id == "job-001"
    assert request.inputs == ("set/sample.bin",)
    assert request.options["archive_mode"] == "auto"
    assert request.options["minimum_confidence"] == "medium"
    assert request.options["max_files"] == runner.MAX_DISCOVERED_FILES
    assert request.options["family"] is None


@pytest.mark.parametrize(
    "forbidden",
    [
        "allow_network",
        "allow_live_c2_check",
        "allow_authentication",
        "collect_jarm",
        "password",
        "python",
        "output",
    ],
)
def test_network_live_and_privileged_options_are_rejected(forbidden: str) -> None:
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_request_object(request_value(**{forbidden: True}))

    assert caught.value.code == "network_or_privileged_option_forbidden"


def test_unknown_keys_and_duplicate_inputs_are_rejected() -> None:
    unknown = request_value()
    unknown["callback"] = "https://example.invalid/"
    with pytest.raises(runner.JobContractError, match="top-level"):
        runner.validate_request_object(unknown)

    duplicate = request_value()
    duplicate["inputs"] = ["set/sample.bin", "SET/SAMPLE.BIN"]
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_request_object(duplicate)
    assert caught.value.code == "duplicate_input"


@pytest.mark.parametrize(
    "value",
    [
        "../sample.bin",
        "set/../sample.bin",
        "C:/sample.bin",
        "/sample.bin",
        "set\\sample.bin",
        "set//sample.bin",
        "set/CON.txt",
        "set/sample.bin.",
    ],
)
def test_ambiguous_or_escaping_input_paths_are_rejected(value: str) -> None:
    request = request_value()
    request["inputs"] = [value]
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_request_object(request)
    assert caught.value.code == "invalid_input_path"


def test_duplicate_json_keys_and_non_finite_numbers_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner.load_json_object_strict(duplicate, max_bytes=1024)
    assert caught.value.code == "duplicate_json_key"

    non_finite = tmp_path / "nan.json"
    non_finite.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner.load_json_object_strict(non_finite, max_bytes=1024)
    assert caught.value.code == "non_finite_json_number"


def test_input_tree_count_size_and_overlap_are_fail_closed(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    (input_root / "set" / "second.bin").write_bytes(b"B")
    request = runner.validate_request_object(
        {
            "schema_version": 1,
            "job_id": "job-limits",
            "inputs": ["set"],
            "options": {"max_files": 1},
        }
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_inputs(request, input_root.resolve())
    assert caught.value.code == "input_count_exceeded"

    overlap = runner.validate_request_object(
        {
            "schema_version": 1,
            "job_id": "job-overlap",
            "inputs": ["set", "set/sample.bin"],
        }
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_inputs(overlap, input_root.resolve())
    assert caught.value.code == "overlapping_inputs"


def test_input_and_job_roots_must_be_separate(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    nested_jobs = input_root / "jobs"

    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_roots(input_root, nested_jobs, create_jobs_root=False)
    assert caught.value.code == "root_overlap"
    assert not nested_jobs.exists()

    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_roots(input_root, nested_jobs, create_jobs_root=True)
    assert caught.value.code == "root_overlap"
    assert not nested_jobs.exists()


def test_symlink_input_is_rejected_when_supported(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    target = input_root / "set" / "target.bin"
    target.write_bytes(b"target")
    link = input_root / "set" / "linked.bin"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("この環境ではsymlinkを作成できません")
    request = runner.validate_request_object({"schema_version": 1, "job_id": "job-link", "inputs": ["set/linked.bin"]})

    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_inputs(request, input_root.resolve())
    assert caught.value.code == "input_reparse_forbidden"


def test_build_argv_uses_only_allowlisted_static_options(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(
        request_value(
            family="valleyrat",
            assessment_only=True,
            force_container_probe=True,
            retry_max_static_layers=128,
        )
    )
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    argv = runner.build_analyzer_argv(request, inputs, jobs_root / "output")

    assert argv[0] == str(Path(sys.executable).resolve())
    assert argv[1].endswith("analysis_job_runner.py") is False
    assert argv[1].endswith("analyze_sample.py")
    assert "--family" in argv
    assert "valleyrat" in argv
    assert "--assessment-only" in argv
    assert "--force-container-probe" in argv
    assert "--retry-max-static-layers" in argv
    assert not any("network" in item or "live" in item or "jarm" in item for item in argv)


def test_family_hint_manifest_is_validated_separately_and_forwarded(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    manifest = input_root / "hints" / "job.json"
    manifest.parent.mkdir()
    manifest.write_text(
        json.dumps({"schema_version": 1, "samples": {"0" * 64: "valleyrat"}}),
        encoding="utf-8",
    )
    value = request_value("job-manifest")
    value["family_hint_manifest"] = "hints/job.json"
    request = runner.validate_request_object(value)
    inputs, _ = runner.validate_inputs(request, input_root.resolve())

    validated = runner.validate_family_hint_manifest(request, input_root.resolve(), inputs)
    argv = runner.build_analyzer_argv(
        request,
        inputs,
        jobs_root / "output",
        family_hint_manifest=validated,
    )

    assert validated == manifest.resolve()
    assert argv[argv.index("--family-hint-manifest") + 1] == str(manifest.resolve())
    assert "hints/job.json" not in [str(path) for path in inputs]


def test_family_hint_manifest_must_be_strict_json_and_not_overlap_inputs(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    malformed = input_root / "malformed.json"
    malformed.write_text('{"schema_version":NaN}', encoding="utf-8")
    value = request_value("job-malformed-manifest")
    value["family_hint_manifest"] = "malformed.json"
    request = runner.validate_request_object(value)
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_family_hint_manifest(request, input_root.resolve(), inputs)
    assert caught.value.code == "non_finite_json_number"

    inside = input_root / "set" / "hints.json"
    inside.write_text("{}", encoding="utf-8")
    overlapping = {
        "schema_version": 1,
        "job_id": "job-overlapping-manifest",
        "inputs": ["set"],
        "family_hint_manifest": "set/hints.json",
    }
    request = runner.validate_request_object(overlapping)
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_family_hint_manifest(request, input_root.resolve(), inputs)
    assert caught.value.code == "manifest_overlaps_inputs"


def test_family_hint_manifest_size_and_direct_input_reuse_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate = request_value("job-duplicate-manifest")
    duplicate["family_hint_manifest"] = "set/sample.bin"
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_request_object(duplicate)
    assert caught.value.code == "manifest_is_input"

    input_root, _ = make_roots(tmp_path)
    manifest = input_root / "large.json"
    manifest.write_text('{"value":"larger than test cap"}', encoding="utf-8")
    value = request_value("job-large-manifest")
    value["family_hint_manifest"] = "large.json"
    request = runner.validate_request_object(value)
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    monkeypatch.setattr(runner, "MAX_FAMILY_HINT_MANIFEST_BYTES", 8)
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_family_hint_manifest(request, input_root.resolve(), inputs)
    assert caught.value.code == "json_size_out_of_bounds"


def test_child_environment_does_not_inherit_api_keys_or_python_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VT_API_KEY", "secret")
    monkeypatch.setenv("TRIAGE_API_KEY", "secret")
    monkeypatch.setenv("MAXMIND_LICENSE_KEY", "secret")
    monkeypatch.setenv("PYTHONPATH", "C:/untrusted")
    monkeypatch.setenv("PYTHONHOME", "C:/untrusted")

    environment = runner.build_sanitized_environment()

    assert "VT_API_KEY" not in environment
    assert "TRIAGE_API_KEY" not in environment
    assert "MAXMIND_LICENSE_KEY" not in environment
    assert "PYTHONPATH" not in environment
    assert "PYTHONHOME" not in environment
    assert environment["PYTHONNOUSERSITE"] == "1"


def test_complete_job_writes_atomic_machine_readable_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-complete"))
    captured: dict[str, Any] = {}
    monkeypatch.setenv("VT_API_KEY", "must-not-leak")

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        output = Path(argv[argv.index("--output") + 1])
        write_summary(output)
        return SimpleNamespace(returncode=0, stdout=b'{"complete": 1}\n', stderr=b"")

    exit_code = runner.run_job(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    job_dir = jobs_root / "job-complete"
    assert exit_code == 0
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["check"] is False
    assert captured["kwargs"]["cwd"] == runner.REPOSITORY_ROOT
    assert "VT_API_KEY" not in captured["kwargs"]["env"]
    assert load_json(job_dir / "status.json")["state"] == "completed"
    result = load_json(job_dir / "result.json")
    assert result["accepted"] is True
    assert result["analysis_state"] == "complete"
    assert result["safety"]["network_contacted"] is False
    assert result["process"]["shell"] is False
    assert load_json(job_dir / "progress.json")["percent"] == 100
    assert not list(job_dir.rglob("*.tmp"))

    snapshot = runner.read_job_snapshot(jobs_root, "job-complete")
    assert snapshot["status"]["terminal"] is True
    assert snapshot["result"]["accepted"] is True


def test_analyzer_partial_exit_is_preserved(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-partial"))

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(Path(argv[argv.index("--output") + 1]))
        return SimpleNamespace(returncode=20, stdout=b"partial", stderr=b"")

    exit_code = runner.run_job(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    assert exit_code == 20
    assert load_json(jobs_root / "job-partial" / "status.json")["state"] == "completed_partial"
    assert load_json(jobs_root / "job-partial" / "result.json")["analysis_state"] == "partial"


def test_summary_claiming_network_contact_is_rejected(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-network-claim"))

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(Path(argv[argv.index("--output") + 1]), network_contacted=True)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner.run_job(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-network-claim" / "result.json")
    assert exit_code == 2
    assert result["accepted"] is False
    assert result["error"]["code"] == "analyzer_safety_contract_failed"


def test_nonaccepted_exit_code_is_a_terminal_failure(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-failed"))

    def fake_run(*_: Any, **__: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=9, stdout=b"", stderr=b"failure")

    exit_code = runner.run_job(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-failed" / "result.json")
    assert exit_code == 1
    assert result["error"]["code"] == "analyzer_exit_nonzero"
    assert result["process"]["exit_code"] == 9


def test_timeout_is_recorded_without_retry(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-timeout"))
    calls = 0

    def fake_run(*_: Any, **__: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        raise subprocess.TimeoutExpired(["python"], timeout=60, output=b"bounded", stderr=b"timeout")

    exit_code = runner.run_job(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-timeout" / "result.json")
    assert calls == 1
    assert exit_code == 124
    assert result["analysis_state"] == "timed_out"
    assert result["error"]["code"] == "analyzer_timeout"


def test_existing_job_id_is_never_reused(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-existing"))
    (jobs_root / "job-existing").mkdir()

    with pytest.raises(runner.JobContractError) as caught:
        runner.run_job(request, input_root=input_root, jobs_root=jobs_root, timeout_seconds=60)
    assert caught.value.code == "job_already_exists"


def test_validate_job_performs_no_subprocess_or_job_write(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-validate"))

    result = runner.validate_job(request, input_root=input_root, jobs_root=jobs_root)

    assert result["valid"] is True
    assert result["network_or_live_options_allowed"] is False
    assert not (jobs_root / "job-validate").exists()


def test_real_analyzer_runs_with_sanitized_environment(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path, data=b"synthetic offline static analysis input")
    request = runner.validate_request_object(
        request_value(
            "job-real-smoke",
            archive_mode="raw",
            assessment_only=True,
            max_files=1,
            max_file_size=1024 * 1024,
            string_scan_limit=100,
            max_static_layers=4,
        )
    )

    exit_code = runner.run_job(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
    )

    assert exit_code in {0, 20}
    result = load_json(jobs_root / "job-real-smoke" / "result.json")
    assert result["accepted"] is True
    assert result["safety"]["summary_safety_contract_verified"] is True
    assert (jobs_root / "job-real-smoke" / "analysis" / "summary.json").is_file()
