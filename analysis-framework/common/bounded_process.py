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
import sys
from typing import Any

TASKKILL_TIMEOUT_SECONDS = 5.0
TERMINATION_WAIT_SECONDS = 5.0
_WINDOWS_CREATE_NEW_PROCESS_GROUP = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
_POSIX_KILL_SIGNAL = int(getattr(signal, "SIGKILL", 9))
DEFAULT_CONTAINED_MEMORY_BYTES = 512 * 1024 * 1024
MAX_CONTAINED_ACTIVE_PROCESSES = 65_535
MAX_CONTAINED_MEMORY_BYTES = sys.maxsize


class _WindowsJob:
    """KILL_ON_JOB_CLOSEを設定したWindows Job Object handle。"""

    def __init__(self, handle: int, close_handle: Any) -> None:
        self._handle = handle
        self._close_handle = close_handle
        self._closed = False

    def close(self) -> bool:
        """handleを1回だけ閉じ、job内の残存子孫を終了する。"""

        if self._closed:
            return True
        closed = bool(self._close_handle(self._handle))
        self._closed = closed
        return closed

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


def _assign_windows_job(
    process: subprocess.Popen[Any],
    *,
    maximum_active_processes: int | None,
    maximum_memory_bytes: int | None,
) -> _WindowsJob:
    """processをkill-on-close・resource上限付きJob Objectへ割り当てる。"""

    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
    job = _WindowsJob(handle, kernel32.CloseHandle)
    information = ExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = 0x00002000
    if maximum_active_processes is not None:
        information.BasicLimitInformation.LimitFlags |= 0x00000008
        information.BasicLimitInformation.ActiveProcessLimit = maximum_active_processes
    if maximum_memory_bytes is not None:
        information.BasicLimitInformation.LimitFlags |= 0x00000200
        information.JobMemoryLimit = maximum_memory_bytes
    if not kernel32.SetInformationJobObject(
        handle, 9, ctypes.byref(information), ctypes.sizeof(information)
    ):
        error = ctypes.get_last_error()
        job.close()
        raise OSError(error, "SetInformationJobObject failed")
    process_handle = wintypes.HANDLE(int(getattr(process, "_handle")))
    if not kernel32.AssignProcessToJobObject(handle, process_handle):
        error = ctypes.get_last_error()
        job.close()
        raise OSError(error, "AssignProcessToJobObject failed")
    return job


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


def _validate_containment_limit(
    name: str,
    value: int | None,
    *,
    maximum: int,
) -> int | None:
    """Job Object／resource limitへ安全に渡せる正整数へ限定する。"""

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"{name}は1..{maximum}の整数で指定してください。")
    return value


class ProcessContainment:
    """custom ``Popen`` 呼出しにも適用できるprocess tree所有境界。"""

    def __init__(
        self,
        *,
        os_name: str | None = None,
        maximum_active_processes: int | None = None,
        maximum_memory_bytes: int | None = None,
    ) -> None:
        self.platform_os = os.name if os_name is None else os_name
        if self.platform_os not in {"nt", "posix"}:
            raise ValueError("os_nameは'nt'または'posix'で指定してください。")
        self.maximum_active_processes = _validate_containment_limit(
            "maximum_active_processes",
            maximum_active_processes,
            maximum=MAX_CONTAINED_ACTIVE_PROCESSES,
        )
        self.maximum_memory_bytes = _validate_containment_limit(
            "maximum_memory_bytes",
            maximum_memory_bytes,
            maximum=MAX_CONTAINED_MEMORY_BYTES,
        )
        self._process: subprocess.Popen[Any] | None = None
        self._windows_job: _WindowsJob | None = None
        self._closed = False

    def popen_options(self) -> dict[str, object]:
        """process groupとPOSIX resource limitを起動時に固定する。"""

        if self._process is not None or self._closed:
            raise RuntimeError("同じcontainment境界を再利用できません。")
        if self.platform_os == "nt":
            return {"creationflags": _WINDOWS_CREATE_NEW_PROCESS_GROUP}

        import resource  # noqa: PLC0415

        maximum_memory_bytes = self.maximum_memory_bytes
        maximum_active_processes = self.maximum_active_processes

        def lower_resource_limit(kind: int, requested: int) -> None:
            current_soft, current_hard = resource.getrlimit(kind)

            def bounded(current: int) -> int:
                if current == resource.RLIM_INFINITY:
                    return requested
                return min(requested, current)

            target_hard = bounded(current_hard)
            target_soft = min(bounded(current_soft), target_hard)
            resource.setrlimit(kind, (target_soft, target_hard))

        def apply_resource_limits() -> None:
            if maximum_memory_bytes is not None:
                lower_resource_limit(resource.RLIMIT_AS, maximum_memory_bytes)
            if maximum_active_processes is not None:
                lower_resource_limit(resource.RLIMIT_NPROC, maximum_active_processes)

        return {"start_new_session": True, "preexec_fn": apply_resource_limits}

    def attach(self, process: subprocess.Popen[Any]) -> None:
        """起動直後のprocessを境界へ割り当て、失敗時はtreeを終了する。"""

        if self._process is not None or self._closed:
            raise RuntimeError("同じcontainment境界へ複数processを割り当てられません。")
        self._process = process
        if self.platform_os != "nt":
            return
        try:
            self._windows_job = _assign_windows_job(
                process,
                maximum_active_processes=self.maximum_active_processes,
                maximum_memory_bytes=self.maximum_memory_bytes,
            )
        except BaseException:
            terminate_process_tree(process, os_name=self.platform_os)
            self._closed = True
            raise

    def close(self, *, strict: bool) -> None:
        """正常終了後も境界を閉じ、残存する子孫processを終了する。"""

        if self._closed:
            return
        process = self._process
        if process is None:
            self._closed = True
            if strict:
                raise RuntimeError("processを割り当てる前にcontainment境界が閉じられました。")
            return
        self._closed = True
        if self.platform_os == "posix":
            terminate_process_tree(process, os_name=self.platform_os)
            return
        job = self._windows_job
        if job is None:
            terminate_process_tree(process, os_name=self.platform_os)
            if strict:
                raise RuntimeError("Windows Job Objectが割り当てられていません。")
            return
        if job.close():
            return
        terminate_process_tree(process, os_name=self.platform_os)
        job.close()
        if strict:
            raise RuntimeError("Windows Job Objectを安全にcloseできませんでした。")

    def abort(self) -> None:
        """例外・timeout時に境界と直接processの双方をbest-effortで終了する。"""

        process = self._process
        try:
            self.close(strict=False)
        finally:
            if process is not None:
                terminate_process_tree(process, os_name=self.platform_os)


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
    require_containment: bool = False,
    maximum_active_processes: int | None = None,
    maximum_memory_bytes: int | None = None,
) -> subprocess.CompletedProcess[Any]:
    """subprocess.run相当の結果を返し、timeout時は子孫treeも終了する。

    ``os_name``はplatform分岐のunit test専用であり、通常は省略する。
    ``creationflags``と``start_new_session``は呼出側へ公開せず、この関数が
    process treeの所有権を持つ。
    """

    bounded_timeout = _validate_timeout(timeout)
    if type(require_containment) is not bool:
        raise TypeError("require_containmentはbooleanで指定してください。")
    maximum_active_processes = _validate_containment_limit(
        "maximum_active_processes",
        maximum_active_processes,
        maximum=MAX_CONTAINED_ACTIVE_PROCESSES,
    )
    maximum_memory_bytes = _validate_containment_limit(
        "maximum_memory_bytes",
        maximum_memory_bytes,
        maximum=MAX_CONTAINED_MEMORY_BYTES,
    )
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
    containment: ProcessContainment | None = None
    platform_options: dict[str, object]
    if require_containment:
        containment = ProcessContainment(
            os_name=platform_os,
            maximum_active_processes=maximum_active_processes,
            maximum_memory_bytes=maximum_memory_bytes,
        )
        platform_options = containment.popen_options()
    elif platform_os == "nt":
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
    if containment is not None:
        containment.attach(process)

    def close_containment(*, strict: bool) -> None:
        if containment is not None:
            containment.close(strict=strict)

    def abort_owned_process() -> None:
        if containment is not None:
            containment.abort()
        else:
            terminate_process_tree(process, os_name=platform_os)

    try:
        output, error_output = process.communicate(input=input, timeout=bounded_timeout)
    except subprocess.TimeoutExpired as original_timeout:
        abort_owned_process()
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
            abort_owned_process()
        except BaseException:
            pass
        raise

    if require_containment:
        close_containment(strict=True)

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
    "DEFAULT_CONTAINED_MEMORY_BYTES",
    "MAX_CONTAINED_ACTIVE_PROCESSES",
    "MAX_CONTAINED_MEMORY_BYTES",
    "ProcessContainment",
    "TASKKILL_TIMEOUT_SECONDS",
    "TERMINATION_WAIT_SECONDS",
    "run_bounded",
    "terminate_process_tree",
]
