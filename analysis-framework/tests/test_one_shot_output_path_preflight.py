"""Windowsの長い出力先を解析開始前に拒否する回帰試験。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

COMMON_ROOT = Path(__file__).resolve().parents[1] / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import analyze_sample as one_shot  # noqa: E402


def test_windows_case_artifact_length_is_checked_without_exposing_path(tmp_path: Path) -> None:
    """固定成果物名まで含め、長いWindows出力先を拒否する。"""

    short_output = tmp_path / "s"
    one_shot._validate_case_output_path_length(short_output, windows=True)

    long_output = tmp_path / ("x" * 140)
    with pytest.raises(one_shot.OutputPathLengthError) as caught:
        one_shot._validate_case_output_path_length(long_output, windows=True)
    assert "短い --output" in str(caught.value)
    assert str(long_output) not in str(caught.value)


def test_non_windows_output_is_not_rejected(tmp_path: Path) -> None:
    """非Windows環境では同じ文字数でも誤って拒否しない。"""

    one_shot._validate_case_output_path_length(tmp_path / ("x" * 140), windows=False)


def test_run_batch_checks_output_before_creating_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """出力先の事前検査失敗時にcaseや検体を読まない。"""

    output = tmp_path / "result"

    def reject(_output: Path) -> None:
        raise one_shot.OutputPathLengthError("短い --output を指定してください。")

    monkeypatch.setattr(one_shot, "_validate_case_output_path_length", reject)
    with pytest.raises(one_shot.OutputPathLengthError):
        one_shot.run_batch([tmp_path / "missing.bin"], output)
    assert not output.exists()


def test_direct_cli_reports_safe_error_before_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """隔離workerを起動せず、短い出力先への変更を案内する。"""

    def reject(_output: Path) -> None:
        raise one_shot.OutputPathLengthError("短い --output を指定してください。")

    monkeypatch.setattr(one_shot, "_validate_case_output_path_length", reject)
    code = one_shot._run_isolated_cli(
        ["--input", str(tmp_path / "missing.bin"), "--output", str(tmp_path / "result")]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "短い --output" in captured.err
    assert str(tmp_path) not in captured.err
    assert not (tmp_path / "result").exists()
