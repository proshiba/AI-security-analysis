"""子孫processを含む有界実行helperの回帰テスト。"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from unittest.mock import Mock, patch

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from common import bounded_process  # noqa: E402


def _load_module(name: str, path: Path):
    """正規fileを固有module名で読み込み、依存境界を隔離する。"""

    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"候補moduleを読み込めません: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


invoke_module = _load_module(
    "_bounded_invoke_analysis",
    FRAMEWORK_ROOT / "invoke_analysis.py",
)
ghidra_module = _load_module(
    "_bounded_ghidra",
    FRAMEWORK_ROOT / "common" / "import_ghidra_project.py",
)


def _completed_process(*, returncode: int = 0) -> Mock:
    process = Mock(spec=subprocess.Popen)
    process.pid = 4242
    process.returncode = returncode
    process.communicate.return_value = (b"stdout", b"stderr")
    process.wait.return_value = returncode
    return process


def test_normal_completion_returns_completed_process_and_starts_posix_session() -> None:
    """通常終了時はCompletedProcess相当を返し、POSIX sessionを分離する。"""

    process = _completed_process()
    with patch.object(bounded_process.subprocess, "Popen", return_value=process) as popen:
        completed = bounded_process.run_bounded(
            ["python", "stage.py"],
            timeout=3,
            capture_output=True,
            os_name="posix",
        )
    assert isinstance(completed, subprocess.CompletedProcess)
    assert completed.args == ["python", "stage.py"]
    assert completed.returncode == 0
    assert completed.stdout == b"stdout"
    assert completed.stderr == b"stderr"
    assert popen.call_args.kwargs["start_new_session"] is True
    assert "creationflags" not in popen.call_args.kwargs
    assert popen.call_args.kwargs["stdout"] is subprocess.PIPE
    assert popen.call_args.kwargs["stderr"] is subprocess.PIPE


def test_windows_starts_new_process_group() -> None:
    """Windowsではprocess-tree所有のため新しいprocess groupを作る。"""

    process = _completed_process()
    with patch.object(bounded_process.subprocess, "Popen", return_value=process) as popen:
        bounded_process.run_bounded(
            ["analyzeHeadless.bat", "project"],
            timeout=3,
            shell=True,
            os_name="nt",
        )
    assert popen.call_args.kwargs["creationflags"] == bounded_process._WINDOWS_CREATE_NEW_PROCESS_GROUP
    assert "start_new_session" not in popen.call_args.kwargs
    assert popen.call_args.kwargs["shell"] is True


def test_posix_timeout_kills_process_group_and_preserves_output() -> None:
    """POSIX timeoutは直接processだけでなくsession内の子孫もkillpgする。"""

    process = _completed_process()
    process.communicate.side_effect = [
        subprocess.TimeoutExpired(["python"], 1, output=b"early"),
        (b"all-output", b"all-error"),
    ]
    with (
        patch.object(bounded_process.subprocess, "Popen", return_value=process),
        patch.object(bounded_process.os, "killpg", create=True) as killpg,
        pytest.raises(subprocess.TimeoutExpired) as caught,
    ):
        bounded_process.run_bounded(["python", "stage.py"], timeout=1, os_name="posix")
    killpg.assert_called_once_with(process.pid, bounded_process._POSIX_KILL_SIGNAL)
    process.wait.assert_called_once_with(timeout=bounded_process.TERMINATION_WAIT_SECONDS)
    assert caught.value.output == b"all-output"
    assert caught.value.stderr == b"all-error"


def test_windows_timeout_uses_taskkill_tree_without_shell() -> None:
    """Windows timeoutは短いtaskkill /T /Fをshellなしで実行する。"""

    process = _completed_process()
    process.communicate.side_effect = [
        subprocess.TimeoutExpired(["python"], 2),
        (None, None),
    ]
    taskkill_result = subprocess.CompletedProcess([], 0)
    taskkill_path = Path(r"C:\Windows\System32\taskkill.exe")
    with (
        patch.object(bounded_process.subprocess, "Popen", return_value=process),
        patch.object(bounded_process, "_resolve_windows_taskkill_path", return_value=taskkill_path),
        patch.object(bounded_process.subprocess, "run", return_value=taskkill_result) as taskkill,
        pytest.raises(subprocess.TimeoutExpired),
    ):
        bounded_process.run_bounded(["python", "stage.py"], timeout=2, os_name="nt")
    assert taskkill.call_args.args[0] == [str(taskkill_path), "/PID", str(process.pid), "/T", "/F"]
    assert taskkill.call_args.kwargs["shell"] is False
    assert taskkill.call_args.kwargs["timeout"] == bounded_process.TASKKILL_TIMEOUT_SECONDS
    process.kill.assert_not_called()


@pytest.mark.parametrize(
    "taskkill_effect",
    [
        subprocess.CompletedProcess([], 1),
        subprocess.TimeoutExpired(["taskkill"], 5),
        OSError("taskkill unavailable"),
    ],
)
def test_windows_taskkill_failure_falls_back_to_direct_kill(taskkill_effect: object) -> None:
    """taskkillの失敗・timeout・起動失敗は直接kill/waitへfallbackする。"""

    process = _completed_process()
    process.communicate.side_effect = [
        subprocess.TimeoutExpired(["python"], 2),
        (None, None),
    ]
    run_options = (
        {"return_value": taskkill_effect}
        if isinstance(taskkill_effect, subprocess.CompletedProcess)
        else {"side_effect": taskkill_effect}
    )
    with (
        patch.object(bounded_process.subprocess, "Popen", return_value=process),
        patch.object(
            bounded_process,
            "_resolve_windows_taskkill_path",
            return_value=Path(r"C:\Windows\System32\taskkill.exe"),
        ),
        patch.object(bounded_process.subprocess, "run", **run_options),
        pytest.raises(subprocess.TimeoutExpired),
    ):
        bounded_process.run_bounded(["python", "stage.py"], timeout=2, os_name="nt")
    process.kill.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=bounded_process.TERMINATION_WAIT_SECONDS)


def test_windows_wait_timeout_also_falls_back_to_kill_and_second_wait() -> None:
    """taskkill成功後も親が残る場合はkillし、二度目のwaitも有界にする。"""

    process = _completed_process()
    process.communicate.side_effect = [
        subprocess.TimeoutExpired(["python"], 2),
        (None, None),
    ]
    process.wait.side_effect = [subprocess.TimeoutExpired(["python"], 5), 1]
    with (
        patch.object(bounded_process.subprocess, "Popen", return_value=process),
        patch.object(
            bounded_process,
            "_resolve_windows_taskkill_path",
            return_value=Path(r"C:\Windows\System32\taskkill.exe"),
        ),
        patch.object(
            bounded_process.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0),
        ),
        pytest.raises(subprocess.TimeoutExpired),
    ):
        bounded_process.run_bounded(["python", "stage.py"], timeout=2, os_name="nt")
    process.kill.assert_called_once_with()
    assert process.wait.call_count == 2


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(7), OSError("I/O failure")])
def test_unexpected_communicate_failure_terminates_tree_and_reraises(failure: BaseException) -> None:
    """timeout以外の中断でも所有するprocess treeを終了し、元の例外を再送出する。"""

    process = _completed_process()
    process.communicate.side_effect = failure
    with (
        patch.object(bounded_process.subprocess, "Popen", return_value=process),
        patch.object(bounded_process, "terminate_process_tree") as terminate,
        pytest.raises(type(failure)) as caught,
    ):
        bounded_process.run_bounded(["python", "stage.py"], timeout=1, os_name="posix")
    terminate.assert_called_once_with(process, os_name="posix")
    if isinstance(failure, SystemExit):
        assert caught.value.code == failure.code


def test_check_true_preserves_subprocess_contract() -> None:
    """check=Trueでは通常のCalledProcessError契約を維持する。"""

    process = _completed_process(returncode=7)
    with (
        patch.object(bounded_process.subprocess, "Popen", return_value=process),
        pytest.raises(subprocess.CalledProcessError) as caught,
    ):
        bounded_process.run_bounded(["python", "stage.py"], timeout=1, check=True)
    assert caught.value.returncode == 7


@pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), float("nan")])
def test_invalid_timeout_is_rejected_before_spawn(timeout: object) -> None:
    """bool、非正数、非有限timeoutではprocessを起動しない。"""

    with patch.object(bounded_process.subprocess, "Popen") as popen:
        with pytest.raises((TypeError, ValueError)):
            bounded_process.run_bounded(["python"], timeout=timeout)  # type: ignore[arg-type]
    popen.assert_not_called()


def _pid_is_alive(pid: int) -> bool:
    """POSIX integration test用にzombieを停止済みとして判定する。"""

    proc_stat = Path(f"/proc/{pid}/stat")
    try:
        fields = proc_stat.read_text(encoding="ascii").split()
    except OSError:
        fields = []
    if len(fields) > 2 and fields[2] == "Z":
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@pytest.mark.skipif(os.name == "nt", reason="POSIX process group向けintegration test")
def test_posix_timeout_terminates_real_descendant(tmp_path: Path) -> None:
    """短時間の実processで同じgroupの子孫がtimeout後に残らないことを確認する。"""

    child_pid_path = tmp_path / "child.pid"
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='ascii');"
        "time.sleep(30)"
    )
    with pytest.raises(subprocess.TimeoutExpired):
        bounded_process.run_bounded(
            [sys.executable, "-c", parent_code, str(child_pid_path)],
            timeout=0.75,
        )
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and _pid_is_alive(child_pid):
        time.sleep(0.05)
    try:
        assert not _pid_is_alive(child_pid)
    finally:
        if _pid_is_alive(child_pid):
            os.kill(child_pid, signal.SIGKILL)


def test_invoke_module_routes_python_stage_through_bounded_helper() -> None:
    """解析stageがprocess-tree対応helperを使い、秘密値を既定除外する。"""

    ambient = {
        "VT_API_KEY": "ambient-vt",
        "TRIAGE_API_KEY": "ambient-triage",
        "AWS_SESSION_TOKEN": "ambient-aws",
    }
    completed = subprocess.CompletedProcess([], 0)
    with patch.dict(os.environ, ambient, clear=False):
        with patch.object(invoke_module, "run_bounded", return_value=completed) as runner:
            result = invoke_module.run_python(
                "python",
                ["stage.py"],
                stage="fixture",
                timeout_seconds=17,
            )
    assert result == 0
    assert runner.call_args.args[0] == ["python", "stage.py"]
    assert runner.call_args.kwargs["timeout"] == 17
    assert runner.call_args.kwargs["check"] is False
    child_environment = runner.call_args.kwargs["env"]
    assert all(name not in child_environment for name in ambient)


def test_invoke_module_converts_bounded_timeout() -> None:
    """helper timeoutはstage名を含むOrchestrationErrorへ変換する。"""

    with (
        patch.object(
            invoke_module,
            "run_bounded",
            side_effect=subprocess.TimeoutExpired(["python"], 17),
        ),
        pytest.raises(invoke_module.OrchestrationError, match="17秒でtimeout"),
    ):
        invoke_module.run_python(
            "python",
            ["stage.py"],
            stage="fixture",
            timeout_seconds=17,
        )


def _ghidra_arguments(tmp_path: Path) -> argparse.Namespace:
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "module.bin").write_bytes(b"MZ")
    return argparse.Namespace(
        payload_directory=payload,
        project_directory=tmp_path / "project",
        project_name="bounded-project",
        target=["module.bin"],
        analyze_headless="analyzeHeadless.bat",
        analysis_timeout_per_file=15,
    )


def test_ghidra_module_routes_headless_tree_through_bounded_helper(tmp_path: Path) -> None:
    """Ghidra batch境界も同じhelperへshellと総timeoutを渡す。"""

    args = _ghidra_arguments(tmp_path)

    def fake_bounded(*_arguments, **_options):
        (args.project_directory / "bounded-project.gpr").write_bytes(b"fixture")
        return subprocess.CompletedProcess([], 0)

    with patch.object(ghidra_module, "uses_windows_batch_shell", return_value=True):
        with patch.object(ghidra_module, "run_bounded", side_effect=fake_bounded) as runner:
            result = ghidra_module.import_project(args)
    assert result["executed_sample"] is False
    assert isinstance(runner.call_args.args[0], list)
    assert runner.call_args.kwargs["shell"] is True
    assert runner.call_args.kwargs["timeout"] == 15 + 120


def test_ghidra_module_converts_bounded_timeout(tmp_path: Path) -> None:
    """Ghidra helper timeoutもGhidraImportErrorへ変換する。"""

    args = _ghidra_arguments(tmp_path)
    with (
        patch.object(
            ghidra_module,
            "run_bounded",
            side_effect=subprocess.TimeoutExpired(["analyzeHeadless"], 135),
        ),
        pytest.raises(ghidra_module.GhidraImportError, match="135秒でtimeout"),
    ):
        ghidra_module.import_project(args)


def test_invoke_payload_root_reparse_is_rejected_before_is_dir() -> None:
    """payload rootはis_dirでfollowする前にlstat/reparse検査で拒否する。"""

    with (
        patch.object(invoke_module, "_entry_exists", return_value=True),
        patch.object(invoke_module, "_is_symlink_or_reparse", return_value=True),
        patch.object(Path, "is_dir", side_effect=AssertionError("is_dir must not run")),
        pytest.raises(invoke_module.OrchestrationError, match="symlink"),
    ):
        invoke_module._contained_payload_input(Path("payload-link"), "module.bin")


def test_ghidra_payload_root_reparse_is_rejected_before_exists() -> None:
    """Ghidra payload rootもexistsでfollowする前にreparseを拒否する。"""

    args = argparse.Namespace(
        payload_directory=Path("payload-link"),
        project_directory=Path("project"),
        project_name="bounded-project",
        target=["module.bin"],
        analyze_headless="analyzeHeadless",
        analysis_timeout_per_file=15,
    )
    with (
        patch.object(ghidra_module, "_entry_exists", return_value=True),
        patch.object(ghidra_module, "_is_symlink_or_reparse", return_value=True),
        patch.object(Path, "exists", side_effect=AssertionError("exists must not run")),
        pytest.raises(ghidra_module.GhidraImportError, match="symlink"),
    ):
        ghidra_module.import_project(args)


def test_invoke_broken_component_symlink_is_reported_as_reparse(tmp_path: Path) -> None:
    """broken symlinkもexists=Falseとして見落とさず、中間componentで拒否する。"""

    payload = tmp_path / "payload"
    payload.mkdir()
    link = payload / "broken.bin"
    try:
        link.symlink_to(tmp_path / "missing.bin")
    except OSError:
        pytest.skip("この環境ではfile symlinkを作成できません")
    with pytest.raises(invoke_module.OrchestrationError, match="symlink|reparse"):
        invoke_module._contained_payload_input(payload, "broken.bin")


def test_ghidra_broken_component_symlink_is_reported_as_reparse(tmp_path: Path) -> None:
    """Ghidra targetのbroken symlinkもresolve前に拒否する。"""

    payload = tmp_path / "payload"
    payload.mkdir()
    link = payload / "broken.bin"
    try:
        link.symlink_to(tmp_path / "missing.bin")
    except OSError:
        pytest.skip("この環境ではfile symlinkを作成できません")
    with pytest.raises(ghidra_module.GhidraImportError, match="symlink|reparse"):
        ghidra_module.contained_target(payload, "broken.bin")


def test_ghidra_broken_project_symlink_is_rejected_before_mkdir(tmp_path: Path) -> None:
    """project出力のbroken symlinkもmkdirでfollowする前に拒否する。"""

    payload = tmp_path / "payload"
    payload.mkdir()
    project = tmp_path / "project-link"
    try:
        project.symlink_to(tmp_path / "missing-project", target_is_directory=True)
    except OSError:
        pytest.skip("この環境ではdirectory symlinkを作成できません")
    with pytest.raises(ghidra_module.GhidraImportError, match="symlink|reparse"):
        ghidra_module._prepare_project_directory(project, payload)


def test_windows_missing_system_taskkill_skips_path_search_and_falls_back() -> None:
    """System32のtaskkillがない場合はPATH検索せず直接killへfallbackする。"""

    process = _completed_process()
    process.communicate.side_effect = [
        subprocess.TimeoutExpired(["python"], 2),
        (None, None),
    ]
    with (
        patch.object(bounded_process.subprocess, "Popen", return_value=process),
        patch.object(bounded_process, "_resolve_windows_taskkill_path", return_value=None),
        patch.object(bounded_process.subprocess, "run") as taskkill,
        pytest.raises(subprocess.TimeoutExpired),
    ):
        bounded_process.run_bounded(["python", "stage.py"], timeout=2, os_name="nt")
    taskkill.assert_not_called()
    process.kill.assert_called_once_with()


def test_windows_taskkill_resolution_requires_absolute_systemroot_normal_file(tmp_path: Path) -> None:
    """taskkill解決は絶対SystemRoot配下の通常fileだけを受け入れる。"""

    windows_root = tmp_path / "Windows"
    system32 = windows_root / "System32"
    system32.mkdir(parents=True)
    taskkill = system32 / "taskkill.exe"
    taskkill.write_bytes(b"fixture")
    with patch.dict(os.environ, {"SystemRoot": str(windows_root)}, clear=False):
        assert bounded_process._resolve_windows_taskkill_path() == taskkill
    taskkill.unlink()
    taskkill.mkdir()
    with patch.dict(os.environ, {"SystemRoot": str(windows_root)}, clear=False):
        assert bounded_process._resolve_windows_taskkill_path() is None
    with patch.dict(os.environ, {"SystemRoot": "relative-windows"}, clear=False):
        assert bounded_process._resolve_windows_taskkill_path() is None


def _windows_pid_is_alive(pid: int) -> bool:
    """Windows integration testでprocess handleの終了状態を確認する。"""

    import ctypes

    process_query_limited_information = 0x1000
    still_active = 259
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.skipif(os.name != "nt", reason="Windows process tree向けintegration test")
def test_windows_timeout_terminates_real_descendant(tmp_path: Path) -> None:
    """短時間の実processでWindows子孫treeがtimeout後に残らないことを確認する。"""

    if bounded_process._resolve_windows_taskkill_path() is None:
        pytest.skip("System32のtaskkill.exeを検証できません")
    child_pid_path = tmp_path / "windows-child.pid"
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='ascii');"
        "time.sleep(30)"
    )
    with pytest.raises(subprocess.TimeoutExpired):
        bounded_process.run_bounded(
            [sys.executable, "-c", parent_code, str(child_pid_path)],
            timeout=0.75,
        )
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and _windows_pid_is_alive(child_pid):
        time.sleep(0.05)
    try:
        assert not _windows_pid_is_alive(child_pid)
    finally:
        if _windows_pid_is_alive(child_pid):
            taskkill = bounded_process._resolve_windows_taskkill_path()
            if taskkill is not None:
                subprocess.run(
                    [str(taskkill), "/PID", str(child_pid), "/T", "/F"],
                    check=False,
                    shell=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=bounded_process.TASKKILL_TIMEOUT_SECONDS,
                )
