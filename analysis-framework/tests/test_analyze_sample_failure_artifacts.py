"""one-shot隔離CLIのfatalとtimeout成果物を回帰検証する。"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analysis_job_runner as runner
import analyze_sample as analyzer
import bounded_process
from analysis_contract import verify_report_semantics


def _request(arguments: list[str]) -> bytes:
    """direct CLI worker用の最小private requestを返す。"""

    return json.dumps(
        {
            "schema_version": 1,
            "arguments": arguments,
            "archive_password": None,
            "inno_password": None,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _load(path: Path) -> dict:
    """テスト成果物をJSON objectとして読む。"""

    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_worker_exception_writes_only_allowlisted_failure_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """例外本文のpathやcredentialを一時failure応答へ含めない。"""

    private_value = "private-path-and-credential-must-not-leak"
    arguments = ["--input", private_value, "--output", str(tmp_path / "out")]
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(
        analyzer,
        "_execute_cli",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(private_value)),
    )
    monkeypatch.setattr(
        analyzer.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(_request(arguments))),
    )
    monkeypatch.chdir(tmp_path)

    assert analyzer._direct_cli_worker_main() == 2
    raw = (tmp_path / "failure.json").read_text(encoding="utf-8")
    failure = json.loads(raw)
    assert failure["status"] == "fatal"
    assert failure["reason_code"] == "analysis_runtime_error"
    assert failure["executed_sample"] is False
    assert failure["network_contacted"] is False
    assert private_value not in raw
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_parent_publishes_fatal_outcome_and_sealed_nonfinal_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """worker非zero終了を機械可読fatalと非最終summaryへ保存する。"""

    output = tmp_path / "out"
    output.mkdir()

    def fail_worker(_command, **kwargs):
        failure = analyzer._direct_cli_worker_failure_document(RuntimeError("private detail"))
        (Path(kwargs["cwd"]) / "failure.json").write_text(
            json.dumps(failure),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(bounded_process, "run_bounded", fail_worker)

    assert analyzer._run_isolated_cli(
        ["--input", str(tmp_path / "sample.bin"), "--output", str(output)]
    ) == 2

    outcome = _load(output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT)
    partial_path = output / analyzer.DIRECT_CLI_PARTIAL_SUMMARY_ARTIFACT
    partial = _load(partial_path)
    assert outcome["status"] == "fatal"
    assert outcome["reason_code"] == "analysis_runtime_error"
    assert outcome["analyzer_exit_code"] == 2
    assert outcome["runner_exit_code"] is None
    assert outcome["worker_returncode"] == 1
    assert outcome["partial_summary"]["sha256"] == hashlib.sha256(
        partial_path.read_bytes()
    ).hexdigest()
    assert partial["status"] == "failed"
    assert partial["final_summary"] is False
    assert partial["eligible_for_completion_evaluation"] is False
    assert partial["counts"]["verified_unattributed_terminal_cases"] == 0
    assert partial["case_membership"] == "unattributed_existing_output_evidence"
    assert verify_report_semantics(outcome) == []
    assert verify_report_semantics(partial) == []


def test_parent_publishes_timeout_without_claiming_worker_returncode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """wall-clock超過をfatalと混同せず、timeoutとして保存する。"""

    output = tmp_path / "out"
    output.mkdir()

    def timeout(command, **_kwargs):
        raise subprocess.TimeoutExpired(command, analyzer.MAX_DIRECT_CLI_SECONDS)

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(bounded_process, "run_bounded", timeout)

    assert analyzer._run_isolated_cli(
        ["--input", str(tmp_path / "sample.bin"), "--output", str(output)]
    ) == 2

    outcome = _load(output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT)
    partial = _load(output / analyzer.DIRECT_CLI_PARTIAL_SUMMARY_ARTIFACT)
    assert outcome["status"] == "timeout"
    assert outcome["reason_code"] == "wall_clock_limit_reached"
    assert outcome["analyzer_exit_code"] == 2
    assert outcome["runner_exit_code"] is None
    assert outcome["worker_returncode"] is None
    assert partial["run_status"] == "timeout"
    assert verify_report_semantics(outcome) == []
    assert verify_report_semantics(partial) == []


def test_partial_summary_keeps_only_exact_digest_directories_and_verified_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """不正名と未検証caseを除外し、検証成功caseだけを列挙する。"""

    output = tmp_path / "out"
    cases = output / "cases"
    cases.mkdir(parents=True)
    accepted = "a" * 64
    rejected = "b" * 64
    (cases / accepted).mkdir()
    (cases / rejected).mkdir()
    (cases / "not-a-digest").mkdir()

    def verified(_output: Path, digest: str) -> dict:
        if digest == rejected:
            raise ValueError("fixture rejection")
        return {
            "sha256": digest,
            "case_state": "partial",
            "selected_family": "valleyrat",
            "selected_families": ["valleyrat"],
            "report": f"cases/{digest}/report.json",
            "report_semantic_sha256": "c" * 64,
            "analysis_contract_sha256": "d" * 64,
        }

    monkeypatch.setattr(analyzer, "_safe_partial_case_record", verified)

    assert analyzer._publish_direct_cli_failure(
        output,
        status="fatal",
        stage="isolated_worker",
        reason_code="isolated_worker_failed",
        worker_returncode=1,
    )
    partial = _load(output / analyzer.DIRECT_CLI_PARTIAL_SUMMARY_ARTIFACT)
    assert partial["status"] == "partial"
    assert [item["sha256"] for item in partial["cases"]] == [accepted]
    assert partial["counts"] == {
        "scanned_case_entries": 3,
        "verified_unattributed_terminal_cases": 1,
        "rejected_or_unverified_entries": 2,
        "scan_truncated": False,
    }
    assert partial["scan_limit_reasons"] == []
    assert verify_report_semantics(partial) == []


def test_partial_summary_stops_before_hashing_beyond_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fatal診断は累積byte上限を超えたcaseの全成果物を再hashしない。"""

    output = tmp_path / "out"
    case_root = output / "cases" / ("a" * 64)
    case_root.mkdir(parents=True)
    (case_root / "large.bin").write_bytes(b"123456789")
    monkeypatch.setattr(analyzer, "MAX_DIRECT_CLI_PARTIAL_TOTAL_BYTES", 8)
    monkeypatch.setattr(
        analyzer,
        "_safe_partial_case_record",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("byte予算超過後にhash検証してはいけません")
        ),
    )

    assert analyzer._publish_direct_cli_failure(
        output,
        status="fatal",
        stage="isolated_worker",
        reason_code="isolated_worker_failed",
        worker_returncode=1,
    )
    partial = _load(output / analyzer.DIRECT_CLI_PARTIAL_SUMMARY_ARTIFACT)
    assert partial["cases"] == []
    assert partial["counts"]["scan_truncated"] is True
    assert partial["scan_limit_reasons"] == ["byte_limit"]


def test_failure_publisher_never_creates_a_missing_output_directory(tmp_path: Path) -> None:
    """出力境界未確定時に親directoryを推測作成しない。"""

    output = tmp_path / "missing"
    assert not analyzer._publish_direct_cli_failure(
        output,
        status="fatal",
        stage="request_preparation",
        reason_code="request_preparation_failed",
        worker_returncode=None,
    )
    assert not output.exists()


def test_outcome_survives_when_partial_summary_cannot_be_built(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """途中caseを安全に検証できなくてもfatal診断自体は失わない。"""

    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr(
        analyzer,
        "_build_direct_cli_partial_summary",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("fixture partial validation failure")
        ),
    )

    assert analyzer._publish_direct_cli_failure(
        output,
        status="fatal",
        stage="isolated_worker",
        reason_code="isolated_worker_failed",
        worker_returncode=1,
    )
    assert not (output / analyzer.DIRECT_CLI_PARTIAL_SUMMARY_ARTIFACT).exists()
    outcome = _load(output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT)
    assert outcome["partial_summary"] == {
        "status": "unavailable",
        "artifact": None,
        "sha256": None,
        "verified_unattributed_terminal_cases": 0,
        "final_summary": False,
    }
    assert verify_report_semantics(outcome) == []


def test_isolated_direct_main_publishes_fatal_artifact_for_nonruntime_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`python -I`相当の入口でもValueErrorを無言のexit 1にしない。"""

    output = tmp_path / "out"
    output.mkdir()
    private_detail = "private exception detail must not leak"
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(
        analyzer,
        "_execute_cli",
        lambda _argv: (_ for _ in ()).throw(ValueError(private_detail)),
    )

    assert analyzer.main(
        ["--input", str(tmp_path / "sample.bin"), "--output", str(output)]
    ) == 2
    outcome = _load(output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT)
    assert outcome["status"] == "fatal"
    assert outcome["reason_code"] == "invalid_analysis_state"
    captured = capsys.readouterr()
    assert private_detail not in captured.err
    diagnostic = json.loads(captured.err)
    assert diagnostic == {
        "artifact_written": True,
        "reason_code": "invalid_analysis_state",
        "status": "fatal",
    }


def test_isolated_direct_main_resolves_relative_failure_output_from_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`python -I`直入口の診断先を実解析と同じcwd相対へ束縛する。"""

    output = tmp_path / "relative-output"
    output.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(
        analyzer,
        "_execute_cli",
        lambda _argv: (_ for _ in ()).throw(ValueError("private detail")),
    )

    assert analyzer.main(
        ["--input", "sample.bin", "--output", "relative-output"]
    ) == 2
    outcome = _load(output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT)
    assert outcome["status"] == "fatal"
    assert json.loads(capsys.readouterr().err)["artifact_written"] is True


def test_completed_run_removes_failure_artifacts_and_passes_runner_closure(
    tmp_path: Path,
) -> None:
    """成功再実行は診断fileを除去し、実job runnerのexact closureを満たす。"""

    output = tmp_path / "out"
    output.mkdir()
    assert analyzer._publish_direct_cli_failure(
        output,
        status="fatal",
        stage="isolated_worker",
        reason_code="isolated_worker_failed",
        worker_returncode=1,
    )
    for name in (
        "summary.json",
        "follow-on-analysis.json",
        "terminal-payload-acquisition.json",
    ):
        (output / name).write_text("{}\n", encoding="utf-8")

    assert analyzer._clear_direct_cli_failure_artifacts(output, exit_code=0)
    assert not (output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT).exists()
    assert not (output / analyzer.DIRECT_CLI_PARTIAL_SUMMARY_ARTIFACT).exists()
    runner._validate_analysis_output_reference_closure(output / "summary.json", {})


def test_completed_run_fails_closed_when_diagnostic_cleanup_is_unsafe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """診断名が通常fileでない場合は0を返さず、固定理由だけを公開する。"""

    output = tmp_path / "out"
    output.mkdir()
    (output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT).mkdir()
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(
        analyzer,
        "_execute_cli",
        lambda _argv: (0, {"analyzed": 1, "errors": 0}),
    )

    assert analyzer.main(
        ["--input", str(tmp_path / "sample.bin"), "--output", str(output)]
    ) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    diagnostic = json.loads(captured.err)
    assert diagnostic == {
        "artifact_written": False,
        "reason_code": "diagnostic_cleanup_failed",
        "status": "fatal",
    }
