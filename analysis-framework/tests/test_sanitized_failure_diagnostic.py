"""private失敗診断が例外秘密値や未知pathを出さないことを検証する。"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
for root in (REPOSITORY, COMMON, REPOSITORY / "analysis-framework"):
    sys.path.insert(0, str(root))

import analyze_sample as analyzer  # noqa: E402
import sanitized_failure_diagnostic as diagnostic  # noqa: E402
import bounded_process  # noqa: E402

SECRET = "https://secret.invalid/stage?token=private-token#fragment C:\\private\\victim secret-local-value"


def _error(filename: str, *, function: str = "run_batch", error_type: type[Exception] = ValueError) -> Exception:
    """無害な合成例外を指定co_filenameから発生させる。"""

    namespace = {"SECRET": SECRET, "ERROR": error_type}
    source = f"def {function}():\n    hidden_local = SECRET\n    raise ERROR(SECRET)\n{function}()\n"
    try:
        exec(compile(source, filename, "exec"), namespace)  # noqa: S102 - 無害なtest定数だけを実行する
    except Exception as error:
        return error
    raise AssertionError("合成例外が発生しませんでした")


def test_trusted_frame_keeps_only_allowlisted_component_function_and_line() -> None:
    error = _error(str(COMMON / "analyze_sample.py"))
    value = diagnostic.build_diagnostic(error, repository_root=REPOSITORY)
    assert diagnostic.validate_diagnostic(value) == value
    assert value["exception_type"] == "ValueError"
    assert value["frames"][-1] == {
        "component": "analysis-framework/common/analyze_sample.py", "function": "run_batch", "line": 3,
    }
    raw = json.dumps(value)
    for secret in (SECRET, "secret.invalid", "token=", "private-token", "victim", "hidden_local", str(REPOSITORY)):
        assert secret not in raw


@pytest.mark.parametrize("filename", [
    "https://untrusted.invalid/path?token=bad",
    r"C:\private\private-token\outside.py",
    "relative-secret-token.py",
])
def test_outside_and_untrusted_frame_paths_are_unknown(filename: str) -> None:
    value = diagnostic.build_diagnostic(_error(filename), repository_root=REPOSITORY)
    assert value["frames"][-1] == {"component": "unknown", "function": "unknown", "line": None}
    assert filename not in json.dumps(value)
    assert diagnostic.validate_diagnostic(value) == value


def test_nonexistent_in_repository_filename_and_unknown_function_are_not_trusted() -> None:
    filename = str(COMMON / "private-token-nonexistent.py")
    value = diagnostic.build_diagnostic(_error(filename), repository_root=REPOSITORY)
    assert value["frames"][-1]["component"] == "unknown"
    assert "private-token" not in json.dumps(value)
    value = diagnostic.build_diagnostic(
        _error(str(COMMON / "analyze_sample.py"), function="private_function_token"), repository_root=REPOSITORY,
    )
    assert value["frames"][-1]["function"] == "unknown"
    assert "private_function_token" not in json.dumps(value)


def test_custom_exception_type_name_and_unraised_error_are_sanitized() -> None:
    custom = type("SecretTypeToken", (ValueError,), {})
    value = diagnostic.build_diagnostic(custom(SECRET), repository_root=REPOSITORY)
    assert value["exception_type"] == "OtherException" and value["frames"] == []
    assert "SecretTypeToken" not in json.dumps(value)
    assert SECRET not in json.dumps(value)


@pytest.mark.parametrize("mutation", [
    {"exception_type": "SecretException"}, {"exception_type": []},
    {"absolute_path_included": True}, {"extra": SECRET},
    {"frames": [{"component": "C:/private/token.py", "function": "main", "line": 1}]},
    {"frames": [{"component": "unknown", "function": "main", "line": 1}]},
    {"frames": [{"component": "analysis-framework/common/../private.py", "function": "main", "line": 1}]},
])
def test_invalid_worker_diagnostic_is_rejected(mutation: dict) -> None:
    value = diagnostic.build_diagnostic(ValueError(SECRET), repository_root=REPOSITORY)
    value.update(mutation)
    with pytest.raises(ValueError, match="private失敗診断"):
        diagnostic.validate_diagnostic(value)


def test_private_diagnostic_refuses_repository_output_and_does_not_replace_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = diagnostic.build_diagnostic(ValueError(SECRET), repository_root=REPOSITORY)
    assert analyzer._publish_private_failure_diagnostic(COMMON, value) is False
    output = tmp_path / "out"
    output.mkdir()
    assert analyzer._record_private_failure_diagnostic(output, _error(str(COMMON / "analyze_sample.py")))
    saved = json.loads((output / diagnostic.ARTIFACT_NAME).read_text(encoding="utf-8"))
    assert saved["exception_type"] == "ValueError"
    monkeypatch.setattr(diagnostic, "build_diagnostic", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(SECRET)))
    assert analyzer._record_private_failure_diagnostic(output, ValueError(SECRET)) is False


def test_direct_cli_fatal_retains_legacy_reason_and_adds_only_private_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise _error(str(COMMON / "analyze_sample.py"))

    monkeypatch.setattr(analyzer, "_execute_cli", fail)
    assert analyzer.main(["--input", "unread-fixture", "--output", str(output)]) == 2
    outcome = json.loads((output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT).read_text())
    assert outcome["reason_code"] == "invalid_analysis_state"
    assert "diagnostic" not in outcome
    assert (output / diagnostic.ARTIFACT_NAME).is_file()
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert str(output) not in captured.err


def test_worker_failure_diagnostic_keeps_failure_contract_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(analyzer, "_execute_cli", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError(SECRET)))
    request = {
        "schema_version": 1, "arguments": ["--input", "fixture", "--output", "out"],
        "archive_password": None, "inno_password": None,
    }
    monkeypatch.setattr(analyzer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode())))
    monkeypatch.chdir(tmp_path)
    assert analyzer._direct_cli_worker_main() == 2
    failure_raw = (tmp_path / "failure.json").read_bytes()
    assert analyzer._parse_direct_cli_worker_failure(failure_raw)["reason_code"] == "invalid_analysis_state"
    sidecar = json.loads((tmp_path / diagnostic.WORKER_ARTIFACT_NAME).read_text())
    assert diagnostic.validate_diagnostic(sidecar) == sidecar
    assert SECRET not in json.dumps(sidecar)


def test_success_cleanup_removes_stale_private_diagnostic(tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    assert analyzer._record_private_failure_diagnostic(output, ValueError(SECRET))
    assert analyzer._clear_direct_cli_failure_artifacts(output, exit_code=20)
    assert not (output / diagnostic.ARTIFACT_NAME).exists()


def test_parent_moves_valid_worker_diagnostic_without_changing_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "out"
    output.mkdir()
    error = _error(str(COMMON / "analyze_sample.py"))
    sidecar = diagnostic.build_diagnostic(error, repository_root=REPOSITORY)

    def fail_worker(_command: object, **kwargs: object) -> SimpleNamespace:
        worker_root = Path(kwargs["cwd"])
        failure = analyzer._direct_cli_worker_failure_document(error)
        (worker_root / "failure.json").write_text(json.dumps(failure), encoding="utf-8")
        (worker_root / diagnostic.WORKER_ARTIFACT_NAME).write_text(json.dumps(sidecar), encoding="utf-8")
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(bounded_process, "run_bounded", fail_worker)
    assert analyzer._run_isolated_cli(["--input", "fixture", "--output", str(output)]) == 2
    outcome = json.loads((output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT).read_text())
    assert outcome["reason_code"] == "invalid_analysis_state"
    assert json.loads((output / diagnostic.ARTIFACT_NAME).read_text()) == sidecar


def test_malformed_worker_diagnostic_never_overrides_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "out"
    output.mkdir()

    def fail_worker(_command: object, **kwargs: object) -> SimpleNamespace:
        worker_root = Path(kwargs["cwd"])
        failure = analyzer._direct_cli_worker_failure_document(ValueError(SECRET))
        (worker_root / "failure.json").write_text(json.dumps(failure), encoding="utf-8")
        (worker_root / diagnostic.WORKER_ARTIFACT_NAME).write_text(json.dumps({"secret": SECRET}), encoding="utf-8")
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(bounded_process, "run_bounded", fail_worker)
    assert analyzer._run_isolated_cli(["--input", "fixture", "--output", str(output)]) == 2
    outcome = json.loads((output / analyzer.DIRECT_CLI_OUTCOME_ARTIFACT).read_text())
    assert outcome["reason_code"] == "invalid_analysis_state"
    assert not (output / diagnostic.ARTIFACT_NAME).exists()


def test_traceback_frame_count_is_bounded_without_argument_values() -> None:
    namespace = {"SECRET": SECRET}
    code = (
        "def run_batch(depth):\n"
        "    if depth: return run_batch(depth - 1)\n"
        "    raise ValueError(SECRET)\n"
        "run_batch(40)\n"
    )
    try:
        exec(compile(code, str(COMMON / "analyze_sample.py"), "exec"), namespace)  # noqa: S102
    except ValueError as error:
        value = diagnostic.build_diagnostic(error, repository_root=REPOSITORY)
    assert len(value["frames"]) == diagnostic.MAXIMUM_FRAMES
    assert value["frames_truncated"] is True
    assert SECRET not in json.dumps(value)
    assert diagnostic.validate_diagnostic(value) == value
