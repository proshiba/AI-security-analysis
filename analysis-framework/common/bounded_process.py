#!/usr/bin/env python3
"""子孫processを残さず、有界時間で外部commandを実行する。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
from typing import Any

TASKKILL_TIMEOUT_SECONDS = 5.0
TERMINATION_WAIT_SECONDS = 5.0
_WINDOWS_CREATE_NEW_PROCESS_GROUP = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
_POSIX_KILL_SIGNAL = int(getattr(signal, "SIGKILL", 9))

Command = str | bytes | Sequence[str | bytes | os.PathLike[str] | os.PathLike[bytes]]


def _validate_timeout(timeout: float) -> float:
    """timeoutを有限な正数へ限定する。"""

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeoutは有限な正数で指定してください。")
    normalized = float(timeout)
    if not math.isfinite(normalized) or normalized <= 0:
        raise ValueError("timeoutは有限な正数で指定してください。")
    return normalized


def _wait_or_kill_direct(process: subprocess.Popen[Any]) -> None:
    """tree終了後も直接processが残る場合だけkillして回収する。"""

    try:
        process.wait(timeout=TERMINATION_WAIT_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=TERMINATION_WAIT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        # TimeoutExpiredは呼出元で元のstage timeoutとして報告する。ここで
        # cleanupを無期限に待たないことを優先する。
        pass


def _terminate_posix_tree(process: subprocess.Popen[Any]) -> None:
    """start_new_sessionで作成したPOSIX process group全体を終了する。"""

    try:
        os.killpg(process.pid, _POSIX_KILL_SIGNAL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    _wait_or_kill_direct(process)


def _resolve_windows_taskkill_path() -> Path | None:
    """PATHを使わずSystemRoot配下の通常fileであるtaskkillだけを返す。"""

    system_root = os.environ.get("SystemRoot")
    if not system_root or "\x00" in system_root:
        return None
    root = Path(system_root)
    if not root.is_absolute():
        return None
    candidate = root / "System32" / "taskkill.exe"
    try:
        information = candidate.lstat()
    except OSError:
        return None
    attributes = int(getattr(information, "st_file_attributes", 0))
    if not stat.S_ISREG(information.st_mode) or bool(attributes & _REPARSE_POINT):
        return None
    return candidate


def _terminate_windows_tree(process: subprocess.Popen[Any]) -> None:
    """taskkillでWindows process treeを終了し、失敗時は直接killする。"""

    taskkill_succeeded = False
    taskkill_path = _resolve_windows_taskkill_path()
    if taskkill_path is not None:
        try:
            completed = subprocess.run(
                [str(taskkill_path), "/PID", str(process.pid), "/T", "/F"],
                check=False,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=TASKKILL_TIMEOUT_SECONDS,
            )
            taskkill_succeeded = completed.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not taskkill_succeeded:
        try:
            process.kill()
        except OSError:
            pass
    _wait_or_kill_direct(process)


def terminate_process_tree(
    process: subprocess.Popen[Any],
    *,
    os_name: str | None = None,
) -> None:
    """起動時に分離したprocess treeをOS別の方法で終了する。"""

    platform_os = os.name if os_name is None else os_name
    if platform_os == "nt":
        _terminate_windows_tree(process)
    else:
        _terminate_posix_tree(process)


def run_bounded(
    command: Command,
    *,
    timeout: float,
    check: bool = False,
    shell: bool = False,
    env: Mapping[str, str] | None = None,
    cwd: str | bytes | os.PathLike[str] | os.PathLike[bytes] | None = None,
    input: str | bytes | None = None,
    stdin: int | Any | None = None,
    stdout: int | Any | None = None,
    stderr: int | Any | None = None,
    capture_output: bool = False,
    text: bool | None = None,
    encoding: str | None = None,
    errors: str | None = None,
    os_name: str | None = None,
) -> subprocess.CompletedProcess[Any]:
    """subprocess.run相当の結果を返し、timeout時は子孫treeも終了する。

    ``os_name``はplatform分岐のunit test専用であり、通常は省略する。
    ``creationflags``と``start_new_session``は呼出側へ公開せず、この関数が
    process treeの所有権を持つ。
    """

    bounded_timeout = _validate_timeout(timeout)
    if input is not None and stdin is not None:
        raise ValueError("stdinとinputを同時に指定できません。")
    if capture_output and (stdout is not None or stderr is not None):
        raise ValueError("capture_outputとstdout/stderrを同時に指定できません。")
    if capture_output:
        stdout = subprocess.PIPE
        stderr = subprocess.PIPE
    if input is not None:
        stdin = subprocess.PIPE

    platform_os = os.name if os_name is None else os_name
    platform_options: dict[str, object]
    if platform_os == "nt":
        platform_options = {"creationflags": _WINDOWS_CREATE_NEW_PROCESS_GROUP}
    else:
        platform_options = {"start_new_session": True}

    process = subprocess.Popen(
        command,
        shell=shell,
        env=env,
        cwd=cwd,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        text=text,
        encoding=encoding,
        errors=errors,
        **platform_options,
    )
    try:
        output, error_output = process.communicate(input=input, timeout=bounded_timeout)
    except subprocess.TimeoutExpired as original_timeout:
        terminate_process_tree(process, os_name=platform_os)
        try:
            output, error_output = process.communicate(timeout=TERMINATION_WAIT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            output = original_timeout.output
            error_output = original_timeout.stderr
        raise subprocess.TimeoutExpired(
            command,
            bounded_timeout,
            output=output,
            stderr=error_output,
        ) from original_timeout
    except BaseException:
        # KeyboardInterruptやI/O例外でも、所有する子孫processを残さない。
        # cleanup側の二次例外で元の中断理由を隠さない。
        try:
            terminate_process_tree(process, os_name=platform_os)
        except BaseException:
            pass
        raise

    completed = subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout=output,
        stderr=error_output,
    )
    if check:
        completed.check_returncode()
    return completed


__all__ = [
    "TASKKILL_TIMEOUT_SECONDS",
    "TERMINATION_WAIT_SECONDS",
    "run_bounded",
    "terminate_process_tree",
]
