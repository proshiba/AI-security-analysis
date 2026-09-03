#!/usr/bin/env python3
"""検体を実行せず、上限付きで静的展開とアーティファクト復元を行う。"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import math
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import cabarchive
import dnfile
import olefile
import pefile
import pyzipper
from refinery.lib.cab import Cabinet as RefineryCabinet

from unpackers.path_safety import safe_member_name as validate_member_name

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unpackers.asar_unpacker import is_asar, recover_asar
from unpackers.bounded_pe_scan import (
    BoundedExtent,
    CarvedPeArtifacts,
    inspect_structural_pe_extent,
    scan_embedded_pe_candidates,
)
from unpackers.container_recovery import (
    recover_inflated_pe,
    recover_macho_slices,
    recover_xz,
)
from unpackers.donut_unpacker import recover_donut_payloads
from unpackers.donut_wrapper_unpacker import recover_xor32_donut_wrapper
from unpackers.dotnet_bundle_unpacker import recover_dotnet_bundle
from unpackers.embedded_installer_archive import recover_embedded_installer_archive
from unpackers.javascript_dropper_unpacker import recover_javascript_dropper
from unpackers.javascript_obfuscator import (
    decode_script_text,
    deobfuscate_plain_string_array,
    deobfuscate_string_array,
)
from unpackers.managed_il_triage import (
    _contain_parser_diagnostics,
    analyze_managed_pe,
)
from unpackers.managed_proxy_deobfuscator import analyze_managed_protector
from unpackers.nsis_unpacker import recover_nsis_scripted_layers
from unpackers.onyx_qt_loader import (
    matches_onyx_qt_profile,
    recover_onyx_qt_payload,
)
from unpackers.profiled_transform import recover_profiled_transforms
from unpackers.rotated_xor_donut import legacy_report_from_attempt
from unpackers.rzk_lece_unpacker import (
    ENCODED_LECE_MAGIC,
    find_rzk_lece_streams,
)
from unpackers.rzk_lece_unpacker import (
    candidate_report as rzk_lece_candidate_report,
)
from unpackers.static_control_flow import analyze_pe_control_flow

COMMON_ROOT = Path(__file__).resolve().parents[1] / "analysis-framework" / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

from analysis_contract import ensure_no_reparse_components  # noqa: E402
from analyze_iso9660 import (  # noqa: E402
    is_iso9660,
    recover_iso9660_members,
    validate_iso9660_members,
)
from bounded_process import ProcessContainment  # noqa: E402
from extract_pyinstaller_archive import (  # noqa: E402
    DEFAULT_FULL_VALIDATION_MAX_TOTAL_SIZE as PYINSTALLER_VALIDATION_TOTAL_LIMIT,
)
from extract_pyinstaller_archive import (  # noqa: E402
    DEFAULT_MAX_ENTRY_SIZE as PYINSTALLER_ENTRY_LIMIT,
)
from extract_pyinstaller_archive import (  # noqa: E402
    DEFAULT_SELECTIVE_MAX_TOTAL_SIZE as PYINSTALLER_RETENTION_TOTAL_LIMIT,
)
from extract_pyinstaller_archive import (  # noqa: E402
    MemoryCArchiveError,
    MemoryCArchiveReader,
    analyze_carchive_bytes,
)

MAX_ARTIFACT = 256 * 1024 * 1024
ENTROPY_FULL_LIMIT = 8 * 1024 * 1024
ENTROPY_SAMPLE_WINDOW = 1 * 1024 * 1024
MAX_EXTRACTED_TOTAL = 768 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 512
MAX_RETAINED_MEMBERS = 128
MAX_SELECTIVE_ARCHIVE_SCAN_MEMBERS = 8192
MAX_COMPRESSION_RATIO = 200.0
ARCHIVE_READ_CHUNK_SIZE = 1024 * 1024
MAX_CAB_DATA_BLOCKS = 8192
MAX_CAB_MEMBER_NAME_BYTES = 4096
MAX_CAB_BLOCK_UNCOMPRESSED_SIZE = 32 * 1024
CAB_LZX_MIN_WINDOW_BITS = 15
CAB_LZX_MAX_WINDOW_BITS = 21
CAB_LZX_UNSUPPORTED_ERROR = "LZX compression not supported"
MAX_CAB_LZX_WORKER_MEMORY_BYTES = 1024 * 1024 * 1024
CAB_LZX_RUNTIME_MEMORY_RESERVE_BYTES = 256 * 1024 * 1024
CAB_LZX_MEMBER_METADATA_RESERVE_BYTES = 8 * 1024
CAB_LZX_FOLDER_METADATA_RESERVE_BYTES = 64 * 1024
CAB_LZX_BLOCK_METADATA_RESERVE_BYTES = 1024
CAB_HEADER = struct.Struct("<4sIIIIIBBHHHHH")
CAB_RESERVE_HEADER = struct.Struct("<HBB")
CAB_FOLDER = struct.Struct("<IHH")
CAB_FILE = struct.Struct("<IIHHHH")
CAB_DATA = struct.Struct("<IHH")
MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PDF_MAGIC = b"%PDF-"
GDPF_FOOTER_MAGIC = b"GDPF"
GDPF_FOOTER_SIZE = 8
MAX_PNG_CHUNKS = 4096
MAX_DETACHED_IDAT_CANDIDATES = 256
PADDING_PREFILTER_BYTES = 64 * 1024
PADDING_COMPARE_CHUNK_BYTES = 1024 * 1024
MAX_PEFILE_EMBEDDED_CANDIDATE_BYTES = 32 * 1024 * 1024
LEGACY_PEFILE_CANDIDATE_BYTES = 64 * 1024
MAX_PE_RESOURCE_ENTRIES = 512
MAX_PE_RESOURCE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_PE_RESOURCE_ELAPSED_SECONDS = 10.0
MAX_STATIC_TOOL_STDOUT_BYTES = 1024 * 1024
MAX_STATIC_TOOL_STDERR_BYTES = 1024 * 1024
MAX_STATIC_TOOL_TEMP_BYTES = 1024 * 1024 * 1024
MAX_STATIC_TOOL_TEMP_ENTRIES = 10_000
MAX_STATIC_TOOL_ACTIVE_PROCESSES = 8
MAX_STATIC_TOOL_MEMORY_BYTES = 1024 * 1024 * 1024
MAX_STATIC_TOOL_BINARY_BYTES = 128 * 1024 * 1024
STATIC_TOOL_MONITOR_INTERVAL_SECONDS = 0.05
SCRIPT_SUFFIXES = {
    ".au3",
    ".html",
    ".htm",
    ".js",
    ".nsi",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".hta",
    ".osascript",
    ".applescript",
    ".vba",
    ".bat",
    ".cmd",
    ".sh",
}
RECOVERY_SUFFIXES = SCRIPT_SUFFIXES | {
    ".exe",
    ".dll",
    ".sys",
    ".bin",
    ".dat",
    ".json",
    ".ini",
    ".cfg",
    ".conf",
    ".a3x",
    ".sum",
    ".asar",
    ".zip",
    ".7z",
    ".cab",
}
SELECTIVE_ARCHIVE_SUFFIXES = RECOVERY_SUFFIXES | {".jsc", ".node", ".py"}
ISO_IMAGE_SUFFIXES = {".img", ".iso"}


class StaticToolExecutionError(RuntimeError):
    """外部静的toolを有界に完了できなかった理由を保持する。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _CabLzxFallbackError(ValueError):
    """LZX CABを外部processなしで安全に処理できない理由を保持する。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _CabLzxMember:
    """preflightで検証済みのCFFILE metadata。"""

    name: str
    size: int
    offset: int
    folder_index: int


@dataclass(frozen=True)
class _CabLzxMemoryBudget:
    """LZX fallbackの保守的なprocess peak memory見積り。"""

    worker_limit_bytes: int
    runtime_reserve_bytes: int
    input_bytes: int
    folder_cache_bytes: int
    member_materialization_bytes: int
    decoder_window_bytes: int
    metadata_reserve_bytes: int
    estimated_peak_bytes: int

    def public(self) -> dict[str, object]:
        """予算判定を検体内容を含めず公開する。"""

        return {
            "status": "passed",
            "worker_limit_bytes": self.worker_limit_bytes,
            "runtime_reserve_bytes": self.runtime_reserve_bytes,
            "input_bytes": self.input_bytes,
            "folder_cache_bytes": self.folder_cache_bytes,
            "member_materialization_bytes": self.member_materialization_bytes,
            "decoder_window_bytes": self.decoder_window_bytes,
            "metadata_reserve_bytes": self.metadata_reserve_bytes,
            "estimated_peak_bytes": self.estimated_peak_bytes,
            "headroom_bytes": self.worker_limit_bytes - self.estimated_peak_bytes,
        }


@dataclass(frozen=True)
class _CabLzxPreflight:
    """展開前に確定したCAB境界と出力予算。"""

    members: tuple[_CabLzxMember, ...]
    folder_output_sizes: tuple[int, ...]
    window_bits: tuple[int, ...]
    compression: str
    data_block_count: int
    checksum_blocks_verified: int
    declared_file_total_size: int
    memory_budget: _CabLzxMemoryBudget | None

    def public(self, cabinet_size: int) -> dict[str, object]:
        """検体byteやmember名を含めない公開可能な検証結果を返す。"""

        result: dict[str, object] = {
            "status": "passed",
            "cabinet_size": cabinet_size,
            "folder_count": len(self.folder_output_sizes),
            "file_count": len(self.members),
            "data_block_count": self.data_block_count,
            "declared_file_total_size": self.declared_file_total_size,
            "declared_folder_output_total_size": sum(self.folder_output_sizes),
            "compression": self.compression,
            "lzx_window_bits": sorted({value for value in self.window_bits if value}),
            "multi_volume": False,
            "checksum_blocks_required": (
                self.data_block_count if self.compression == "lzx" else 0
            ),
            "checksum_blocks_verified": self.checksum_blocks_verified,
            "path_validation": "passed",
            "bounds_validation": "passed",
        }
        if self.memory_budget is not None:
            result["lzx_peak_memory_budget"] = self.memory_budget.public()
        return result


@dataclass(frozen=True)
class StaticToolCompleted:
    """外部静的toolの公開可能な有界実行結果。"""

    returncode: int
    stdout: str
    stderr: str


class _BoundedPipeCapture:
    """pipeを最後までdrainしつつ保持量だけを上限化する。"""

    def __init__(self, maximum_bytes: int) -> None:
        self.maximum_bytes = maximum_bytes
        self.payload = bytearray()
        self.truncated = False
        self.error: BaseException | None = None
        self._lock = threading.Lock()

    def drain(self, pipe: object) -> None:
        try:
            while True:
                chunk = pipe.read(64 * 1024)  # type: ignore[attr-defined]
                if not chunk:
                    break
                with self._lock:
                    remaining = self.maximum_bytes - len(self.payload)
                    if remaining > 0:
                        self.payload.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        self.truncated = True
        except BaseException as exc:  # pragma: no cover - OS pipe障害
            self.error = exc
        finally:
            try:
                pipe.close()  # type: ignore[attr-defined]
            except OSError:
                pass


def _same_static_file_identity(
    first: os.stat_result,
    second: os.stat_result,
) -> bool:
    try:
        return os.path.samestat(first, second)
    except (AttributeError, OSError):
        return (
            first.st_dev == second.st_dev
            and first.st_ino != 0
            and first.st_ino == second.st_ino
        )


def _has_reparse_attribute(information: os.stat_result) -> bool:
    return bool(
        int(getattr(information, "st_file_attributes", 0))
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    )


def _windows_number_of_links(path: Path) -> int | None:
    """Windowsの`st_nlink=0`時にhandle metadataからlink数を取得する。"""

    if os.name != "nt":
        return None
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(path),
        0x0080,  # FILE_READ_ATTRIBUTES
        0x00000001 | 0x00000002 | 0x00000004,  # READ | WRITE | DELETE share
        None,
        3,  # OPEN_EXISTING
        0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    handle_value = (
        handle if isinstance(handle, int) else int(getattr(handle, "value", 0) or 0)
    )
    if not handle_value or handle_value == invalid_handle:
        return None
    try:
        result = ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(result)):
            return None
        return int(result.number_of_links)
    finally:
        kernel32.CloseHandle(handle)


def _has_single_link(information: os.stat_result, path: Path | None = None) -> bool:
    """複数hardlinkを拒否し、Windowsの未知値0はhandleで再確認する。"""

    if information.st_nlink == 1:
        return True
    if information.st_nlink != 0 or os.name != "nt" or path is None:
        return False
    return _windows_number_of_links(path) == 1


def _validate_static_tool_temp_tree(
    root: Path,
    *,
    expected_root: os.stat_result,
    max_entries: int,
    max_bytes: int,
) -> tuple[int, int]:
    """tool一時treeをlink非追跡で走査し、型・件数・総sizeを制限する。"""

    try:
        current_root = root.lstat()
    except OSError as exc:
        raise StaticToolExecutionError("temporary_tree_changed") from exc
    if (
        not stat.S_ISDIR(current_root.st_mode)
        or _has_reparse_attribute(current_root)
        or not _same_static_file_identity(expected_root, current_root)
    ):
        raise StaticToolExecutionError("temporary_tree_changed")
    entries = 0
    total_bytes = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            iterator = os.scandir(directory)
        except OSError as exc:
            raise StaticToolExecutionError("temporary_tree_unreadable") from exc
        with iterator:
            for child in iterator:
                entries += 1
                if entries > max_entries:
                    raise StaticToolExecutionError("temporary_entry_limit")
                try:
                    information = child.stat(follow_symlinks=False)
                except OSError as exc:
                    raise StaticToolExecutionError("temporary_tree_unreadable") from exc
                if child.is_symlink() or _has_reparse_attribute(information):
                    raise StaticToolExecutionError("temporary_reparse_forbidden")
                if stat.S_ISDIR(information.st_mode):
                    pending.append(Path(child.path))
                    continue
                if not stat.S_ISREG(information.st_mode) or not _has_single_link(
                    information, Path(child.path)
                ):
                    raise StaticToolExecutionError("temporary_special_file_forbidden")
                total_bytes += information.st_size
                if total_bytes > max_bytes:
                    raise StaticToolExecutionError("temporary_byte_limit")
    return entries, total_bytes


def _static_tool_environment(temporary_root: Path) -> dict[str, str]:
    """credentialとPython注入設定を継承しない外部tool用環境を作る。"""

    environment: dict[str, str] = {}
    for key in ("SYSTEMROOT", "WINDIR", "PATHEXT", "LANG", "LC_ALL"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    system_root = environment.get("SYSTEMROOT") or environment.get("WINDIR")
    if system_root:
        environment["PATH"] = str(Path(system_root) / "System32")
    else:
        environment["PATH"] = os.pathsep.join(("/usr/bin", "/bin"))
    private_temp = str(temporary_root)
    environment.update(
        {
            "TEMP": private_temp,
            "TMP": private_temp,
            "TMPDIR": private_temp,
        }
    )
    return environment


def _run_static_tool_process(
    command: list[str],
    *,
    cwd: Path,
    timeout: float,
    max_temp_entries: int,
    max_temp_bytes: int,
    encoding: str = "utf-8",
) -> StaticToolCompleted:
    """process tree・出力・時間・一時treeを全て有界にしてtoolを起動する。"""

    if (
        not command
        or not cwd.is_absolute()
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout <= 0
        or isinstance(max_temp_entries, bool)
        or not 1 <= max_temp_entries <= MAX_STATIC_TOOL_TEMP_ENTRIES
        or isinstance(max_temp_bytes, bool)
        or not 1 <= max_temp_bytes <= MAX_STATIC_TOOL_TEMP_BYTES
    ):
        raise ValueError("static tool実行上限が不正です")
    executable = Path(command[0])
    try:
        ensure_no_reparse_components(executable)
    except ValueError as exc:
        raise StaticToolExecutionError("tool_file_invalid") from exc
    try:
        executable_before = executable.lstat()
    except OSError as exc:
        raise StaticToolExecutionError("tool_unavailable") from exc
    if (
        not executable.is_absolute()
        or not stat.S_ISREG(executable_before.st_mode)
        or not _has_single_link(executable_before, executable)
        or _has_reparse_attribute(executable_before)
        or not 1 <= executable_before.st_size <= MAX_STATIC_TOOL_BINARY_BYTES
    ):
        raise StaticToolExecutionError("tool_file_invalid")
    try:
        ensure_no_reparse_components(cwd)
    except ValueError as exc:
        raise StaticToolExecutionError("temporary_tree_unreadable") from exc
    try:
        root_information = cwd.lstat()
    except OSError as exc:
        raise StaticToolExecutionError("temporary_tree_unreadable") from exc
    _validate_static_tool_temp_tree(
        cwd,
        expected_root=root_information,
        max_entries=max_temp_entries,
        max_bytes=max_temp_bytes,
    )
    containment = ProcessContainment(
        maximum_active_processes=MAX_STATIC_TOOL_ACTIVE_PROCESSES,
        maximum_memory_bytes=MAX_STATIC_TOOL_MEMORY_BYTES,
    )
    process: subprocess.Popen[bytes] | None = None
    stdout_capture = _BoundedPipeCapture(MAX_STATIC_TOOL_STDOUT_BYTES)
    stderr_capture = _BoundedPipeCapture(MAX_STATIC_TOOL_STDERR_BYTES)
    threads: list[threading.Thread] = []
    deadline = time.monotonic() + float(timeout)
    failure: StaticToolExecutionError | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=_static_tool_environment(cwd),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **containment.popen_options(),
        )
        containment.attach(process)
        if process.stdout is None or process.stderr is None:  # pragma: no cover
            raise StaticToolExecutionError("pipe_unavailable")
        threads = [
            threading.Thread(
                target=stdout_capture.drain,
                args=(process.stdout,),
                daemon=True,
            ),
            threading.Thread(
                target=stderr_capture.drain,
                args=(process.stderr,),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        while process.poll() is None:
            if time.monotonic() >= deadline:
                raise StaticToolExecutionError("timeout")
            if stdout_capture.truncated or stderr_capture.truncated:
                raise StaticToolExecutionError("output_limit")
            _validate_static_tool_temp_tree(
                cwd,
                expected_root=root_information,
                max_entries=max_temp_entries,
                max_bytes=max_temp_bytes,
            )
            time.sleep(STATIC_TOOL_MONITOR_INTERVAL_SECONDS)
        process.wait(timeout=5.0)
        _validate_static_tool_temp_tree(
            cwd,
            expected_root=root_information,
            max_entries=max_temp_entries,
            max_bytes=max_temp_bytes,
        )
        executable_after = executable.lstat()
        if (
            not _same_static_file_identity(executable_before, executable_after)
            or not _has_single_link(executable_after, executable)
            or executable_after.st_size != executable_before.st_size
            or getattr(executable_after, "st_mtime_ns", None)
            != getattr(executable_before, "st_mtime_ns", None)
        ):
            raise StaticToolExecutionError("tool_file_changed")
    except StaticToolExecutionError as exc:
        failure = exc
        containment.abort()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        failure = StaticToolExecutionError("containment_or_process_failed")
        containment.abort()
        failure.__cause__ = exc
    else:
        try:
            containment.close(strict=True)
        except (OSError, RuntimeError) as exc:
            failure = StaticToolExecutionError("containment_cleanup_failed")
            failure.__cause__ = exc
    finally:
        for thread in threads:
            thread.join(timeout=5.0)
        if any(thread.is_alive() for thread in threads):
            failure = failure or StaticToolExecutionError("pipe_cleanup_failed")
        if stdout_capture.error is not None or stderr_capture.error is not None:
            failure = failure or StaticToolExecutionError("pipe_read_failed")
        if stdout_capture.truncated or stderr_capture.truncated:
            failure = failure or StaticToolExecutionError("output_limit")
    if failure is not None:
        raise failure
    if process is None:  # pragma: no cover - Popen失敗は上で変換される
        raise StaticToolExecutionError("process_unavailable")
    return StaticToolCompleted(
        returncode=int(process.returncode),
        stdout=bytes(stdout_capture.payload).decode(encoding, errors="replace"),
        stderr=bytes(stderr_capture.payload).decode(encoding, errors="replace"),
    )


def _static_tool_failure_status(error: StaticToolExecutionError) -> str:
    """内部理由を機密情報を含まない安定した公開statusへ写像する。"""

    if error.reason == "timeout":
        return "timeout"
    if error.reason == "output_limit":
        return "tool_output_limit"
    if error.reason.startswith("temporary_"):
        return "temporary_quota_blocked"
    if error.reason.startswith("output_"):
        return "unsafe_tool_output"
    if error.reason in {"tool_unavailable", "tool_file_invalid", "tool_file_changed"}:
        return "tool_integrity_failed"
    return "tool_failed"


def _read_static_tool_output(
    path: Path,
    *,
    root: Path,
    maximum_size: int,
) -> bytes:
    """tool出力を単一handleから有界に読み、差替え・linkを拒否する。"""

    try:
        path.relative_to(root)
    except ValueError as exc:
        raise StaticToolExecutionError("output_path_escape") from exc
    current = root
    for component in path.relative_to(root).parts:
        current = current / component
        information = current.lstat()
        if _has_reparse_attribute(information) or current.is_symlink():
            raise StaticToolExecutionError("output_reparse_forbidden")
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or not _has_single_link(before, path)
        or not 0 <= before.st_size <= maximum_size
    ):
        raise StaticToolExecutionError("output_file_invalid")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not _same_static_file_identity(before, opened)
            or not _has_single_link(opened, path)
            or opened.st_size > maximum_size
        ):
            raise StaticToolExecutionError("output_file_changed")
        remaining = opened.st_size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    if (
        len(payload) != opened.st_size
        or not _same_static_file_identity(opened, after_handle)
        or not _same_static_file_identity(opened, after_path)
        or not _has_single_link(after_handle, path)
        or not _has_single_link(after_path, path)
        or after_handle.st_size != opened.st_size
        or getattr(after_handle, "st_mtime_ns", None)
        != getattr(opened, "st_mtime_ns", None)
    ):
        raise StaticToolExecutionError("output_file_changed")
    return payload


def sha256_bytes(data: bytes) -> str:
    """バイト列の小文字SHA-256ダイジェストを返す。"""
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    """上限付きで決定的に算出し、小数4桁へ丸めたShannonエントロピーを返す。"""
    if not data:
        return 0.0
    sample = data
    if len(data) > ENTROPY_FULL_LIMIT:
        middle = max(0, (len(data) - ENTROPY_SAMPLE_WINDOW) // 2)
        sample = (
            data[:ENTROPY_SAMPLE_WINDOW]
            + data[middle : middle + ENTROPY_SAMPLE_WINDOW]
            + data[-ENTROPY_SAMPLE_WINDOW:]
        )
    counts = [0] * 256
    for value in sample:
        counts[value] += 1
    total = len(sample)
    return round(
        -sum((count / total) * math.log2(count / total) for count in counts if count),
        4,
    )


def detect_format(data: bytes, name: str = "sample") -> str:
    """静的復元パイプラインが対応する形式を識別する。"""
    suffix = Path(name).suffix.lower()
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(PNG_MAGIC):
        return "png"
    if data.startswith(PDF_MAGIC):
        return "pdf"
    if is_asar(data):
        return "asar"
    if data[:4] in MACHO_MAGICS:
        # CAFEBABE is shared by Java class files and universal Mach-O.  Treat
        # it as Mach-O only when the bounded architecture table is plausible.
        if data[:4] in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
            endian = ">" if data[:4] == b"\xca\xfe\xba\xbe" else "<"
            if len(data) < 8:
                return "data"
            architecture_count = struct.unpack_from(endian + "I", data, 4)[0]
            if not 1 <= architecture_count <= 32 or 8 + architecture_count * 20 > len(
                data
            ):
                return "java-class" if data[:4] == b"\xca\xfe\xba\xbe" else "data"
        return "macho"
    if data.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"ER\x02\x00"):
        return "apple-disk-image"
    if data.startswith(b"MSCF"):
        return "cab"
    if data.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "rar"
    lineage_tail = name.lower().rsplit("::", 1)[-1]
    if suffix == ".a3x" or lineage_tail.endswith("autoit-a3x"):
        return "autoit-a3x"
    if zipfile.is_zipfile(io.BytesIO(data)):
        return "zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if suffix in SCRIPT_SUFFIXES or data[:256].lstrip().lower().startswith(
        (
            b"<!doctype html",
            b"<html",
            b"<script",
            b"function ",
            b"var ",
            b"$",
            b"on error",
            b"tell application",
            b"#!/bin/",
        )
    ):
        return "script"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or data[:512].count(b"\x00") >= 64:
        text_probe = decode_script_text(data[:4096]).lstrip().lower()
        if text_probe.startswith(
            ("//", "/*", "function ", "var ", "let ", "const ", "@echo", "set ")
        ):
            return "script"
    return "data"


def recover_gdpf_pdf_overlay(
    data: bytes,
    *,
    minimum_offset: int,
    maximum_size: int = MAX_ARTIFACT,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """EOFの<u32 size>GDPFからPDFデコイを境界検証付きで復元する。

    GhostDesk識別文字列を持つ検体は、自身のPE末尾からこの形式を読み、
    一時PDFとして開く。誤検出を避けるため、footer、サイズ、PE overlay
    境界、PDF magicの全条件が一致した場合だけ子レイヤーへ渡す。
    """

    report: dict[str, object] = {
        "status": "no_footer",
        "footer_magic": GDPF_FOOTER_MAGIC.decode("ascii"),
        "executed": False,
        "network_contacted": False,
    }
    if not data.endswith(GDPF_FOOTER_MAGIC):
        return report, []

    report["footer_offset"] = len(data) - len(GDPF_FOOTER_MAGIC)
    if len(data) < GDPF_FOOTER_SIZE:
        report["status"] = "truncated_footer"
        return report, []
    if (
        isinstance(minimum_offset, bool)
        or not isinstance(minimum_offset, int)
        or minimum_offset < 0
        or minimum_offset > len(data)
    ):
        report["status"] = "invalid_minimum_offset"
        return report, []
    if (
        isinstance(maximum_size, bool)
        or not isinstance(maximum_size, int)
        or maximum_size <= 0
    ):
        report["status"] = "invalid_maximum_size"
        return report, []

    payload_end = len(data) - GDPF_FOOTER_SIZE
    declared_size = struct.unpack_from("<I", data, payload_end)[0]
    payload_offset = payload_end - declared_size
    report.update(
        {
            "declared_size": declared_size,
            "payload_offset": payload_offset,
            "payload_end": payload_end,
            "minimum_offset": minimum_offset,
            "size_field_little_endian": True,
        }
    )
    if declared_size <= 100:
        report["status"] = "declared_size_below_profile_minimum"
        return report, []
    if declared_size > maximum_size:
        report["status"] = "declared_size_budget_exceeded"
        return report, []
    if payload_offset < minimum_offset or payload_offset < 0:
        report["status"] = "payload_outside_pe_overlay"
        return report, []

    payload = data[payload_offset:payload_end]
    if len(payload) != declared_size:
        report["status"] = "payload_truncated"
        return report, []
    if not payload.startswith(PDF_MAGIC):
        report["status"] = "payload_magic_mismatch"
        return report, []

    report.update(
        {
            "status": "pdf_recovered",
            "payload_format": "pdf",
            "payload_sha256": sha256_bytes(payload),
            "payload_content_in_report": False,
        }
    )
    return report, [("gdpf-pdf-decoy.pdf", payload)]


def recover_iso9660_layers(
    data: bytes,
    *,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_member_size: int = MAX_ARTIFACT,
    max_total_size: int = MAX_EXTRACTED_TOTAL,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """検証済みISO9660の通常fileをone-shot用の子レイヤーへ変換する。"""
    report, members = recover_iso9660_members(
        data,
        max_members=max_members,
        max_member_size=max_member_size,
        max_total_size=max_total_size,
    )
    artifacts: list[tuple[str, bytes]] = []
    for path, blob in members:
        kind = detect_format(blob, path)
        suffix = PurePosixPath(path).suffix.lower().lstrip(".") or "member"
        artifacts.append((f"iso9660-{kind}-{suffix}", blob))
    return report, artifacts


def recover_png_concealed_data(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """PNGのIDAT内で画像zlib終端後に連結されたデータを上限付きで復元する。"""

    if not data.startswith(PNG_MAGIC):
        return {"status": "not_png"}, []
    offset = len(PNG_MAGIC)
    chunk_count = 0
    width = height = None
    idat = bytearray()
    png_end_offset = None
    while offset + 12 <= len(data):
        if chunk_count >= MAX_PNG_CHUNKS:
            return {"status": "chunk_limit_blocked", "chunk_count": chunk_count}, []
        length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + length
        crc_end = payload_end + 4
        if length > MAX_ARTIFACT or crc_end > len(data):
            return {"status": "invalid_chunk_bounds", "chunk_count": chunk_count}, []
        payload = data[payload_start:payload_end]
        expected_crc = int.from_bytes(data[payload_end:crc_end], "big")
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            return {
                "status": "crc_mismatch",
                "chunk_count": chunk_count,
                "chunk_type": chunk_type.decode("ascii", errors="replace"),
            }, []
        chunk_count += 1
        if chunk_type == b"IHDR":
            if length != 13:
                return {"status": "invalid_ihdr_length"}, []
            width, height = struct.unpack(">II", payload[:8])
        elif chunk_type == b"IDAT":
            if len(idat) + length > MAX_ARTIFACT:
                return {"status": "idat_size_blocked", "chunk_count": chunk_count}, []
            idat.extend(payload)
        elif chunk_type == b"IEND":
            png_end_offset = crc_end
            break
        offset = crc_end
    if png_end_offset is None or width is None or height is None or not idat:
        return {"status": "incomplete_png", "chunk_count": chunk_count}, []

    inflater = zlib.decompressobj()
    try:
        pixels = inflater.decompress(bytes(idat), MAX_ARTIFACT + 1)
        if len(pixels) > MAX_ARTIFACT or not inflater.eof:
            return {
                "status": "decompressed_size_blocked",
                "chunk_count": chunk_count,
            }, []
        pixels += inflater.flush()
    except zlib.error as exc:
        return {
            "status": "invalid_zlib_stream",
            "chunk_count": chunk_count,
            "error": type(exc).__name__,
        }, []
    if len(pixels) > MAX_ARTIFACT:
        return {"status": "decompressed_size_blocked", "chunk_count": chunk_count}, []

    concealed = inflater.unused_data
    report = {
        "status": "concealed_data_recovered"
        if concealed
        else "valid_png_no_concealed_data",
        "width": width,
        "height": height,
        "chunk_count": chunk_count,
        "png_end_offset": png_end_offset,
        "trailing_after_iend": len(data) - png_end_offset,
        "idat_size": len(idat),
        "zlib_stream_size": len(idat) - len(concealed),
        "decompressed_image_size": len(pixels),
        "concealed_size": len(concealed),
        "concealed_sha256": sha256_bytes(concealed) if concealed else None,
        "concealed_entropy": entropy(concealed) if concealed else None,
        "concealed_prefix_hex": concealed[:16].hex(),
        "concealed_content_in_report": False,
    }
    artifacts = [("png-idat-zlib-unused-data", concealed)] if concealed else []
    return report, artifacts


def recover_detached_idat_stream(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """PNGヘッダを持たないCRC-validな連続IDAT/IEND列を境界付きで調べる。"""

    marker_offset = 0
    candidates_checked = 0
    while candidates_checked < MAX_DETACHED_IDAT_CANDIDATES:
        marker = data.find(b"IDAT", marker_offset)
        if marker < 4:
            if marker < 0:
                break
            marker_offset = marker + 4
            continue
        candidates_checked += 1
        start = marker - 4
        cursor = start
        idat = bytearray()
        chunk_count = 0
        end_offset = None
        while cursor + 12 <= len(data) and chunk_count < MAX_PNG_CHUNKS:
            length = int.from_bytes(data[cursor : cursor + 4], "big")
            kind = data[cursor + 4 : cursor + 8]
            payload_start = cursor + 8
            payload_end = payload_start + length
            crc_end = payload_end + 4
            if length > MAX_ARTIFACT or crc_end > len(data):
                break
            payload = data[payload_start:payload_end]
            expected_crc = int.from_bytes(data[payload_end:crc_end], "big")
            if zlib.crc32(kind + payload) & 0xFFFFFFFF != expected_crc:
                break
            if kind == b"IDAT":
                if len(idat) + length > MAX_ARTIFACT:
                    return {
                        "status": "idat_size_blocked",
                        "start_offset": start,
                        "chunk_count": chunk_count,
                    }, []
                idat.extend(payload)
                chunk_count += 1
                cursor = crc_end
                continue
            if kind == b"IEND" and length == 0 and chunk_count >= 2:
                end_offset = crc_end
            break
        if end_offset is None:
            marker_offset = marker + 4
            continue

        payload = bytes(idat)
        report: dict[str, object] = {
            "status": "detached_idat_found",
            "start_offset": start,
            "end_offset": end_offset,
            "prefix_size": start,
            "trailing_size": len(data) - end_offset,
            "chunk_count": chunk_count,
            "idat_size": len(payload),
            "idat_sha256": sha256_bytes(payload),
            "idat_entropy": entropy(payload),
            "candidates_checked": candidates_checked,
            "executed": False,
            "network_contacted": False,
        }
        inflater = zlib.decompressobj()
        try:
            recovered = inflater.decompress(payload, MAX_ARTIFACT + 1)
            if len(recovered) <= MAX_ARTIFACT and inflater.eof:
                recovered += inflater.flush()
                if len(recovered) <= MAX_ARTIFACT:
                    report.update(
                        status="detached_idat_zlib_recovered",
                        recovered_size=len(recovered),
                        recovered_sha256=sha256_bytes(recovered),
                    )
                    return report, [("detached-idat-zlib", recovered)]
        except zlib.error:
            pass
        report["status"] = "encrypted_or_non_zlib_detached_idat"
        report["recovery_limit"] = "静的zlib復号不可。鍵または独自変換の特定が必要"
        return report, []

    return {
        "status": "not_found",
        "candidates_checked": candidates_checked,
        "executed": False,
        "network_contacted": False,
    }, []


def pe_resource_children(
    blob: bytes,
) -> tuple[str, list[tuple[str, bytes]], dict[str, object] | None]:
    """PEリソースを直接検査し、次層として意味がある内容だけを返す。"""

    resource_format = detect_format(blob, "resource.bin")
    if resource_format == "png":
        png_report, concealed = recover_png_concealed_data(blob)
        return resource_format, concealed, png_report

    artifacts: list[tuple[str, bytes]] = []
    if resource_format != "data":
        artifacts.append((f"pe-resource-{resource_format}", blob))
    artifacts.extend(carve_embedded_pes(blob))
    return resource_format, artifacts, None


def should_analyze_pe_control_flow(
    *,
    packing_suspected: bool,
    classification: str,
    executable_extent: int,
) -> bool:
    """巨大overlayではなく実行image範囲を基準にCFG解析要否を決める。"""

    return (
        packing_suspected
        or classification == "managed_loader_or_obfuscated"
        or executable_extent > 32 * 1024 * 1024
    )


def repetitive_padding(data: bytes, max_period: int = 32) -> dict[str, object] | None:
    """短い周期の反復paddingかを、全長相当の巨大一時bytesを作らず判定する。"""
    if len(data) < 4096:
        return None
    probe = data[: min(len(data), PADDING_PREFILTER_BYTES)]
    for period in range(1, min(max_period, len(data)) + 1):
        pattern = data[:period]
        # 周期データなら任意のprefixでも同じ周期を満たす。大半の通常データを
        # 64 KiB以下で除外し、入力全長相当の一時bytesを最大32回作らない。
        if probe[period:] != probe[:-period]:
            continue
        matched = True
        for chunk_start in range(0, len(data), PADDING_COMPARE_CHUNK_BYTES):
            chunk_end = min(len(data), chunk_start + PADDING_COMPARE_CHUNK_BYTES)
            phase = chunk_start % period
            needed = phase + (chunk_end - chunk_start)
            expected = (pattern * ((needed + period - 1) // period))[phase:needed]
            if data[chunk_start:chunk_end] != expected:
                matched = False
                break
        if not matched:
            continue
        return {
            "period": period,
            "pattern_hex": pattern.hex(),
            "repetitions": len(data) // period,
            "trailing_bytes": len(data) % period,
        }
    return None


def safe_member_name(name: str) -> str:
    """アーカイブのパストラバーサル、絶対パス、ドライブ指定メンバー名を拒否する。"""
    return validate_member_name(name, "archive")


def valid_pe_extent(data: bytes, offset: int = 0) -> int | None:
    """*offset*のPE候補長を、巨大な末尾copyを作らず検証して返す。"""
    if offset < 0 or offset + 0x40 > len(data) or data[offset : offset + 2] != b"MZ":
        return None
    structural = inspect_structural_pe_extent(data, offset, max_extent=MAX_ARTIFACT)
    if structural.extent is None:
        # 小さなfixtureと過去の呼出契約はpefileで確認する。一方、大容量入力の
        # 偽MZ候補で ``data[offset:]`` を繰り返し複製する経路は閉じる。
        if len(data) - offset > LEGACY_PEFILE_CANDIDATE_BYTES:
            return None
        candidate = data[offset:]
        validation_method = "pefile_fast_legacy_small_candidate"
        validation_note = structural.reason
    else:
        extent_hint = structural.extent
        if extent_hint > MAX_PEFILE_EMBEDDED_CANDIDATE_BYTES:
            return BoundedExtent(
                extent_hint,
                validation_method="bounded_structural_headers",
                validation_note="pefile_validation_skipped_candidate_size_budget",
            )
        candidate = data[offset : offset + extent_hint]
        validation_method = "structural_headers_and_pefile_fast"
        validation_note = None
    try:
        image = pefile.PE(data=candidate, fast_load=True)
        if not 1 <= image.FILE_HEADER.NumberOfSections <= 96:
            return None
        if len(image.sections) != image.FILE_HEADER.NumberOfSections:
            return None
        extent = int(image.OPTIONAL_HEADER.SizeOfHeaders)
        for section in image.sections:
            extent = max(extent, int(section.PointerToRawData + section.SizeOfRawData))
        security = image.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if security.VirtualAddress and security.Size:
            extent = max(extent, int(security.VirtualAddress + security.Size))
        if extent <= 0 or extent > len(candidate) or extent > MAX_ARTIFACT:
            return None
        return BoundedExtent(
            extent,
            validation_method=validation_method,
            validation_note=validation_note,
        )
    except (AttributeError, IndexError, pefile.PEFormatError, ValueError):
        return None


def carve_embedded_pes(data: bytes, limit: int = 16) -> list[tuple[str, bytes]]:
    """実行せず、有界走査で検証済みの埋め込みPEを切り出す。"""
    if limit <= 0:
        return CarvedPeArtifacts(
            [],
            {
                "schema_version": 1,
                "status": "partial",
                "input_size": len(data),
                "recovered_candidate_count": 0,
                "budget_exhausted": True,
                "exhausted_reasons": ["result_count_budget"],
                "executed": False,
                "network_contacted": False,
            },
        )
    candidates, scan_report = scan_embedded_pe_candidates(
        data,
        valid_pe_extent,
        start_offset=min(1, len(data)),
        max_results=limit,
    )
    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    duplicate_digests = 0
    for offset, extent in candidates:
        blob = data[offset : offset + extent]
        digest = sha256_bytes(blob)
        if digest in seen:
            duplicate_digests += 1
            continue
        artifacts.append(("embedded-pe", blob))
        seen.add(digest)
    scan_report["unique_artifact_count"] = len(artifacts)
    scan_report["duplicate_digest_count"] = duplicate_digests
    return CarvedPeArtifacts(artifacts, scan_report)


def pe_summary(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """PEのパッキング証拠を分類し、埋め込みアーティファクトを上限付きで復元する。"""
    pe = pefile.PE(data=data, fast_load=True)
    directory_parse: dict[str, dict[str, str]] = {}
    parse_directories = getattr(pe, "parse_data_directories", None)
    for label, directory_name in (
        ("imports", "IMAGE_DIRECTORY_ENTRY_IMPORT"),
        ("resources", "IMAGE_DIRECTORY_ENTRY_RESOURCE"),
    ):
        if not callable(parse_directories):
            directory_parse[label] = {"status": "parser_hook_unavailable"}
            continue
        try:
            parse_directories(directories=[pefile.DIRECTORY_ENTRY[directory_name]])
            directory_parse[label] = {"status": "parsed"}
        except (
            AttributeError,
            IndexError,
            KeyError,
            pefile.PEFormatError,
            struct.error,
            ValueError,
        ) as exc:
            directory_parse[label] = {
                "status": "parse_failed",
                "error_type": type(exc).__name__,
            }
    sections = []
    for section in pe.sections:
        sections.append(
            {
                "name": section.Name.rstrip(b"\0").decode(errors="replace"),
                "raw_size": section.SizeOfRawData,
                "virtual_size": section.Misc_VirtualSize,
                "entropy": entropy(section.get_data()),
                "characteristics": hex(section.Characteristics),
            }
        )
    import_analysis_complete = directory_parse["imports"]["status"] == "parsed"
    import_entries = (
        list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
        if import_analysis_complete
        else []
    )
    imports = (
        sum(len(entry.imports) for entry in import_entries)
        if import_analysis_complete
        else None
    )
    import_libraries = (
        sorted(
            {
                entry.dll.decode("ascii", errors="replace").lower()
                for entry in import_entries
                if getattr(entry, "dll", None)
            }
        )
        if import_analysis_complete
        else None
    )
    overlay_offset = pe.get_overlay_data_start_offset()
    image_end = overlay_offset if overlay_offset is not None else len(data)
    image_marker_probe = data[: min(image_end, 32 * 1024 * 1024)].lower()
    installer_marker_probe = data[: min(len(data), 1024 * 1024)].lower()
    markers = sorted(
        {
            marker.decode()
            for marker in (
                b"UPX!",
                b"MPRESS1",
                b"MPRESS2",
                b"Themida",
                b"VMProtect",
            )
            if marker.lower() in image_marker_probe
        }
        | {
            marker.decode()
            for marker in (b"Nullsoft", b"Inno Setup")
            if marker.lower() in installer_marker_probe
        }
    )
    artifacts: list[tuple[str, bytes]] = []
    overlay = data[overlay_offset:] if overlay_offset is not None else b""
    overlay_format = detect_format(overlay, "overlay.bin") if overlay else "data"
    overlay_padding = repetitive_padding(overlay) if overlay else None
    gdpf_pdf_footer, gdpf_pdf_artifacts = recover_gdpf_pdf_overlay(
        data,
        minimum_offset=image_end,
    )
    artifacts.extend(gdpf_pdf_artifacts)
    if overlay and overlay_padding is not None and overlay_offset is not None:
        artifacts.append(("pe-overlay-padding-removed", data[:overlay_offset]))
    if (
        overlay
        and overlay_format != "data"
        and overlay_padding is None
        and not gdpf_pdf_artifacts
    ):
        artifacts.append((f"pe-overlay-{overlay_format}", overlay))
    overlay_embedded = carve_embedded_pes(overlay)
    artifacts.extend(overlay_embedded)
    overlay_embedded_scan = getattr(
        overlay_embedded,
        "scan_report",
        {
            "status": "not_reported_compatibility_hook",
            "executed": False,
            "network_contacted": False,
        },
    )
    resource_count = 0
    resource_bytes_inspected = 0
    resource_exhausted_reasons: list[str] = []
    opaque_resources = 0
    archive_resources = 0
    png_resources_inspected = 0
    png_resources_with_concealed_data = 0
    invalid_png_resources = 0
    resource_started = time.monotonic()
    if directory_parse["resources"]["status"] != "parsed":
        resource_exhausted_reasons.append(
            f"resource_directory_{directory_parse['resources']['status']}"
        )
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        resource_entries = (
            lang_entry
            for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries
            for name_entry in getattr(type_entry.directory, "entries", [])
            for lang_entry in getattr(name_entry.directory, "entries", [])
        )
        for lang_entry in resource_entries:
            if resource_count >= MAX_PE_RESOURCE_ENTRIES:
                resource_exhausted_reasons.append("resource_count_budget")
                break
            if time.monotonic() - resource_started >= MAX_PE_RESOURCE_ELAPSED_SECONDS:
                resource_exhausted_reasons.append("resource_elapsed_time_budget")
                break
            item = lang_entry.data.struct
            declared_size = int(item.Size)
            resource_count += 1
            if declared_size <= 0:
                continue
            if declared_size > MAX_ARTIFACT:
                resource_exhausted_reasons.append("resource_entry_size_budget")
                continue
            if resource_bytes_inspected + declared_size > MAX_PE_RESOURCE_TOTAL_BYTES:
                resource_exhausted_reasons.append("resource_total_bytes_budget")
                break
            blob = pe.get_data(item.OffsetToData, declared_size)
            resource_bytes_inspected += len(blob)
            if len(blob) != declared_size:
                continue
            resource_format, children, png_report = pe_resource_children(blob)
            archive_resources += int(resource_format in {"7z", "cab", "zip"})
            if png_report is not None:
                png_resources_inspected += 1
                png_status = png_report["status"]
                if png_status == "concealed_data_recovered":
                    png_resources_with_concealed_data += 1
                elif png_status != "valid_png_no_concealed_data":
                    invalid_png_resources += 1
            artifacts.extend(children)
            if (
                resource_format == "data"
                and not children
                and len(blob) >= 4096
                and entropy(blob) >= 7.2
                and opaque_resources < 32
            ):
                artifacts.append(("pe-resource-opaque", blob))
                opaque_resources += 1
    resource_scan = {
        "status": "partial" if resource_exhausted_reasons else "complete",
        "entries_inspected": resource_count,
        "bytes_inspected": resource_bytes_inspected,
        "budgets": {
            "max_entries": MAX_PE_RESOURCE_ENTRIES,
            "max_total_bytes": MAX_PE_RESOURCE_TOTAL_BYTES,
            "max_elapsed_seconds": MAX_PE_RESOURCE_ELAPSED_SECONDS,
        },
        "budget_exhausted": bool(resource_exhausted_reasons),
        "exhausted_reasons": resource_exhausted_reasons,
        "executed": False,
        "network_contacted": False,
    }
    high_entropy = [
        item["name"]
        for item in sections
        if item["entropy"] >= 7.2 and item["raw_size"] >= 4096
    ]
    is_dotnet = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
    lowered = data[: min(len(data), 16 * 1024 * 1024)].lower()
    is_go = b"go build id" in lowered or b"runtime.main" in lowered
    section_names = {item["name"].lower() for item in sections}
    entrypoint_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entrypoint_section = next(
        (
            item["name"]
            for item, raw_section in zip(sections, pe.sections, strict=True)
            if raw_section.VirtualAddress
            <= entrypoint_rva
            < raw_section.VirtualAddress
            + max(raw_section.Misc_VirtualSize, raw_section.SizeOfRawData)
        ),
        None,
    )
    zero_raw_virtual_sections = [
        item["name"]
        for item in sections
        if item["raw_size"] == 0 and item["virtual_size"] >= 4096
    ]
    strong_section_marker = any(
        token in name
        for name in section_names
        for token in ("upx", "mpress", "vmp", "themida")
    )
    strong_string_markers = [
        marker for marker in markers if marker in {"Themida", "VMProtect"}
    ]
    code_entropy = [
        item["name"]
        for item in sections
        if item["entropy"] >= 7.2
        and item["raw_size"] >= 4096
        and item["name"].lower() not in {".rsrc", ".reloc"}
    ]
    containerized = (
        bool({"Nullsoft", "Inno Setup"}.intersection(markers)) or archive_resources > 0
    )
    virtualized_shape = (
        isinstance(imports, int)
        and imports <= 2
        and len(zero_raw_virtual_sections) >= 4
        and bool(code_entropy)
        and entrypoint_section in code_entropy
    )
    common_system_libraries = {
        "advapi32.dll",
        "comctl32.dll",
        "gdi32.dll",
        "kernel32.dll",
        "ntdll.dll",
        "ole32.dll",
        "shell32.dll",
        "user32.dll",
        "wininet.dll",
        "winhttp.dll",
        "ws2_32.dll",
    }
    single_non_system_import_library = (
        import_libraries is not None
        and len(import_libraries) == 1
        and import_libraries[0] not in common_system_libraries
        and not import_libraries[0].startswith(("api-ms-win-", "ext-ms-win-"))
    )
    encrypted_sideload_host_shape = (
        not is_dotnet
        and not is_go
        and entrypoint_section in code_entropy
        and isinstance(imports, int)
        and imports >= 32
        and single_non_system_import_library
    )
    if containerized:
        classification = "self_extracting_container"
    elif is_dotnet and code_entropy:
        classification = "managed_loader_or_obfuscated"
    elif virtualized_shape:
        classification = "virtualized_or_packed"
    elif strong_section_marker or strong_string_markers:
        classification = "packed_or_protected"
    elif encrypted_sideload_host_shape:
        classification = "suspected_encrypted_sideload_host"
    elif (
        not is_dotnet
        and not is_go
        and code_entropy
        and isinstance(imports, int)
        and imports <= 8
    ):
        classification = "suspected_packed"
    else:
        classification = "not_packed"
    packed = classification in {
        "packed_or_protected",
        "suspected_packed",
        "virtualized_or_packed",
        "suspected_encrypted_sideload_host",
    }
    control_flow = None
    if should_analyze_pe_control_flow(
        packing_suspected=packed,
        classification=classification,
        executable_extent=image_end,
    ):
        control_flow = analyze_pe_control_flow(data)
        # The full block list is useful in a private analyst workspace but is
        # too large for recursive unpack reports.  Metrics retain every count
        # and address needed to route a hard case to a deeper tool.
        control_flow.pop("blocks", None)
        control_context = control_flow.get("static_context")
        if isinstance(control_context, dict):
            control_context.pop("sections", None)
            control_context.pop("import_names", None)
    managed_il = None
    managed_protector = None
    if is_dotnet:
        managed_il = analyze_managed_pe(data)
        # Preserve counts, marker provenance, resource hashes, dispatcher
        # candidates, and the method plan while avoiding tens of thousands of
        # per-token rows in recursive public reports.  Analysts can invoke the
        # dedicated CLI for the private full inventory.
        managed_il.pop("types", None)
        managed_il.pop("methods", None)
        malformed = managed_il.get("malformed_method_bodies")
        if isinstance(malformed, list) and len(malformed) > 128:
            managed_il["malformed_method_bodies"] = malformed[:128]
            managed_il["malformed_method_bodies_truncated"] = True
        managed_protector = analyze_managed_protector(data)
    coverage_limitations = []
    if not import_analysis_complete:
        coverage_limitations.append(
            f"import_directory_{directory_parse['imports']['status']}"
        )
    if resource_scan["status"] != "complete":
        coverage_limitations.extend(
            f"resource_scan_{reason}" for reason in resource_scan["exhausted_reasons"]
        )
    analysis_coverage = {
        "status": "partial" if coverage_limitations else "complete",
        "imports_known": import_analysis_complete,
        "low_import_heuristics_applied": import_analysis_complete,
        "resources_complete": resource_scan["status"] == "complete",
        "limitations": coverage_limitations,
    }
    return (
        {
            "machine": hex(pe.FILE_HEADER.Machine),
            "is_dotnet": is_dotnet,
            "is_go": is_go,
            "imports": imports,
            "import_libraries": import_libraries,
            "sections": sections,
            "high_entropy_sections": high_entropy,
            "code_entropy_sections": code_entropy,
            "packer_markers": markers,
            "classification": classification,
            "containerized": containerized,
            "entrypoint_section": entrypoint_section,
            "zero_raw_virtual_sections": zero_raw_virtual_sections,
            "virtualized_shape": virtualized_shape,
            "encrypted_sideload_host_shape": encrypted_sideload_host_shape,
            "packing_suspected": packed,
            "overlay_size": len(overlay),
            "overlay_format": overlay_format,
            "overlay_repetitive_padding": overlay_padding,
            "gdpf_pdf_footer": gdpf_pdf_footer,
            "resource_count": resource_count,
            "opaque_resources_recovered": opaque_resources,
            "archive_resources_recovered": archive_resources,
            "png_resources_inspected": png_resources_inspected,
            "png_resources_with_concealed_data": png_resources_with_concealed_data,
            "invalid_png_resources": invalid_png_resources,
            "resource_scan": resource_scan,
            "directory_parse": directory_parse,
            "analysis_coverage": analysis_coverage,
            "overlay_embedded_pe_scan": overlay_embedded_scan,
            "control_flow_triage": control_flow,
            "managed_il_triage": managed_il,
            "managed_protector_profile": managed_protector,
        },
        artifacts,
    )


@_contain_parser_diagnostics
def recover_dotnet_resources(
    data: bytes,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """.NET manifestリソースを棚卸しし、不透明な符号化ペイロード素材を保持する。"""
    try:
        image = dnfile.dnPE(data=data)
    except Exception as exc:  # dnfile raises several parser-specific exceptions
        return {"status": "parse_failed", "error": type(exc).__name__}, []
    resources = getattr(getattr(image, "net", None), "resources", []) or []
    inventory, artifacts = [], []
    for resource in resources[:MAX_ARCHIVE_MEMBERS]:
        name = str(getattr(resource, "name", "unnamed.resources"))
        size = int(getattr(resource, "size", 0) or 0)
        rva = int(getattr(resource, "rva", 0) or 0)
        if not 0 < size <= MAX_ARTIFACT or not rva:
            inventory.append(
                {"name": name, "size": size, "status": "size_or_rva_blocked"}
            )
            continue
        blob = image.get_data(rva, size)
        if not blob:
            inventory.append({"name": name, "size": size, "status": "empty"})
            continue
        resource_set = getattr(resource, "data", None)
        entries = []
        for entry in (getattr(resource_set, "entries", []) or [])[:MAX_ARCHIVE_MEMBERS]:
            entries.append(
                {
                    "name": str(getattr(entry, "name", "")),
                    "type": str(getattr(entry, "type_name", "")),
                }
            )
        kind = detect_format(blob, name)
        item = {
            "name": name,
            "size": len(blob),
            "sha256": sha256_bytes(blob),
            "entropy": entropy(blob),
            "format": kind,
            "entries": entries,
            "status": "extracted",
        }
        inventory.append(item)
        if kind != "data":
            artifacts.append((f"dotnet-resource-{kind}", blob))
        artifacts.extend(carve_embedded_pes(blob))
        if kind == "data" and len(blob) >= 4096 and entropy(blob) >= 7.0:
            artifacts.append(("dotnet-resource-opaque", blob))
        bitmap_report, bitmap_artifacts = recover_dotnet_bitmap_payloads(resource_set)
        if bitmap_report["status"] != "no_bitmap_entries":
            item["bitmap_payloads"] = bitmap_report
            artifacts.extend(bitmap_artifacts)
    return {
        "status": "resources_recovered" if inventory else "no_manifest_resources",
        "count": len(inventory),
        "inventory": inventory,
    }, artifacts


def _resource_entry_bounds(resource_set: object, index: int) -> tuple[int, int]:
    """ResourceSetエントリ1件の上限付きシリアライズデータ範囲を返す。"""
    entries = list(getattr(resource_set, "entries", []) or [])
    raw = getattr(resource_set, "_data", b"")
    header = getattr(resource_set, "struct", None)
    base = int(getattr(header, "DataSectionOffset", 0) or 0)
    start = base + int(getattr(entries[index].struct, "DataOffset", 0) or 0)
    offsets = sorted(
        base + int(getattr(entry.struct, "DataOffset", 0) or 0) for entry in entries
    )
    later = [offset for offset in offsets if offset > start]
    end = min(later) if later else len(raw)
    if not (0 <= start < end <= len(raw)):
        raise ValueError("invalid ResourceSet entry bounds")
    return start, end


def _decode_bmp_rgb_columns(data: bytes) -> bytes:
    """埋め込みBMPに対するBitmap.GetPixelの列優先RGB抽出を再現する。"""
    if len(data) < 54 or data[:2] != b"BM":
        raise ValueError("not a BMP")
    declared_size = struct.unpack_from("<I", data, 2)[0]
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    dib_size = struct.unpack_from("<I", data, 14)[0]
    width, height = struct.unpack_from("<ii", data, 18)
    planes, bits = struct.unpack_from("<HH", data, 26)
    compression = struct.unpack_from("<I", data, 30)[0]
    if (
        declared_size > len(data)
        or dib_size < 40
        or not 0 < width <= 16384
        or not 0 < abs(height) <= 16384
        or planes != 1
        or bits not in {24, 32}
        or compression != 0
    ):
        raise ValueError("unsupported or malformed BMP")
    bytes_per_pixel = bits // 8
    stride = ((width * bits + 31) // 32) * 4
    if pixel_offset + stride * abs(height) > declared_size:
        raise ValueError("truncated BMP pixels")
    output = bytearray()
    for x in range(width):
        for y in range(abs(height)):
            stored_y = abs(height) - 1 - y if height > 0 else y
            offset = pixel_offset + stored_y * stride + x * bytes_per_pixel
            blue, green, red = data[offset : offset + 3]
            output.extend((red, green, blue))
    return bytes(output)


def recover_dotnet_bitmap_payloads(
    resource_set: object,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """シリアライズ済み.NET BitmapリソースのRGB画素に隠されたPEストリームを復元する。"""
    entries = list(getattr(resource_set, "entries", []) or [])
    raw = getattr(resource_set, "_data", b"")
    bitmap_entries = [
        (index, entry)
        for index, entry in enumerate(entries)
        if "System.Drawing.Bitmap" in str(getattr(entry, "type_name", ""))
    ]
    if not bitmap_entries:
        return {"status": "no_bitmap_entries", "entries": []}, []
    inventory, artifacts = [], []
    for index, entry in bitmap_entries:
        item = {"name": str(getattr(entry, "name", "unnamed"))}
        try:
            start, end = _resource_entry_bounds(resource_set, index)
        except ValueError as exc:
            item.update(status="invalid_bounds", error=str(exc))
            inventory.append(item)
            continue
        bmp_offset = raw.find(b"BM", start, min(end, start + 4096))
        if bmp_offset < 0 or bmp_offset + 6 > end:
            item["status"] = "unsupported_bitmap_serialization"
            inventory.append(item)
            continue
        size = struct.unpack_from("<I", raw, bmp_offset + 2)[0]
        try:
            rgb = _decode_bmp_rgb_columns(raw[bmp_offset : min(end, bmp_offset + size)])
        except ValueError as exc:
            item.update(status="unsupported_bitmap", error=str(exc))
            inventory.append(item)
            continue
        extent = valid_pe_extent(rgb, 0) if rgb.startswith(b"MZ") else None
        item.update(
            status="pe_recovered" if extent else "rgb_recovered_no_pe",
            bitmap_size=size,
            rgb_size=len(rgb),
            rgb_sha256=sha256_bytes(rgb),
        )
        if extent:
            payload = rgb[:extent]
            item.update(payload_size=extent, payload_sha256=sha256_bytes(payload))
            artifacts.append(("dotnet-bitmap-rgb-pe", payload))
        inventory.append(item)
    status = "pe_recovered" if artifacts else "bitmap_entries_processed"
    return {"status": status, "entries": inventory}, artifacts


def macho_summary(data: bytes) -> dict:
    """上限付きでMach-Oまたはユニバーサルバイナリのヘッダーメタデータを解析する。"""
    magic = data[:4]
    if magic not in MACHO_MAGICS:
        raise ValueError("not a Mach-O image")
    if magic in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        endian = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
        return {
            "kind": "universal",
            "architectures": struct.unpack_from(endian + "I", data, 4)[0],
        }
    endian = "<" if magic == b"\xcf\xfa\xed\xfe" else ">"
    if len(data) < 32:
        raise ValueError("truncated Mach-O header")
    cpu_type, cpu_subtype, file_type, commands, command_size, flags = (
        struct.unpack_from(endian + "IIIIII", data, 4)
    )
    return {
        "kind": "macho64",
        "cpu_type": hex(cpu_type),
        "cpu_subtype": hex(cpu_subtype),
        "file_type": file_type,
        "load_commands": commands,
        "load_command_bytes": command_size,
        "flags": hex(flags),
    }


def _encoded_blob_kind(blob: bytes) -> str | None:
    """復号バイト列が構造上有用な場合だけ、対応種別を返す。"""
    kind = detect_format(blob)
    if kind == "pe" and valid_pe_extent(blob) is None:
        return None
    return kind if kind != "data" else None


def recover_whole_file_base64(data: bytes) -> list[tuple[str, bytes]]:
    """ファイル全体が単一のBase64ストリームである場合に静的復号する。

    GuLoaderで確認されるような、先頭がシェルコードで末尾がスクリプトの
    キャリアは既知形式を持たない。このため、ファイル全体との完全一致、
    厳密なBase64検証、再エンコード一致を満たす場合だけ data も返す。
    """
    if not 128 <= len(data) <= (MAX_ARTIFACT * 4 // 3) + 4:
        return []
    # バイナリPE等を全長splitする前に、コピーなしのC実装regexで除外する。
    # 全体がBase64文字と空白だけの場合に限り、復号に必要なcompact bytesを作る。
    if re.search(rb"[^A-Za-z0-9+/=\t\n\r\f\v ]", data) is not None:
        return []
    compact = b"".join(data.split())
    if len(compact) < 128 or len(compact) % 4:
        return []
    if re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", compact) is None:
        return []
    try:
        blob = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error):
        return []
    if not 64 <= len(blob) <= MAX_ARTIFACT:
        return []
    if base64.b64encode(blob) != compact:
        return []
    kind = _encoded_blob_kind(blob) or "data"
    return [(f"whole-file-base64-{kind}", blob)]


def recover_encoded_blobs(data: bytes) -> list[tuple[str, bytes]]:
    """スクリプトから構造上有意なBase64ブロブを上限付きで復元する。

    コマンドファイルはcertutil -decodeの前に、多数のecho行で1つのペイロードを
    出力することがある。これらの断片はリダイレクト先ごとに再構築する。
    無作為な高エントロピー引数は個別に保持しない。
    """
    text = decode_script_text(data)
    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    emitted_chunks: set[str] = set()
    streams: dict[str, list[str]] = {}
    echo_pattern = re.compile(
        r"(?im)^[ \t]*@?echo[ \t]+([A-Za-z0-9+/]{4,}={0,2})"
        r"[ \t]*(>>|>)[ \t]*([^\r\n]+?)[ \t]*\r?$"
    )
    for match in echo_pattern.finditer(text):
        chunk, operator, target = match.groups()
        target = target.strip().lower()
        emitted_chunks.add(chunk)
        if operator == ">" or target not in streams:
            streams[target] = []
        streams[target].append(chunk)
    for chunks in streams.values():
        encoded = "".join(chunks)
        if len(encoded) > (MAX_ARTIFACT * 4 // 3) + 4:
            continue
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        kind = _encoded_blob_kind(blob)
        digest = sha256_bytes(blob)
        if 64 <= len(blob) <= MAX_ARTIFACT and kind and digest not in seen:
            seen.add(digest)
            artifacts.append((f"base64-echo-reassembled-{kind}", blob))
    for match in re.finditer(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{128,}={0,2}(?![A-Za-z0-9+/])", text
    ):
        encoded = match.group()
        if encoded in emitted_chunks:
            continue
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        kind = _encoded_blob_kind(blob)
        digest = sha256_bytes(blob)
        if 64 <= len(blob) <= MAX_ARTIFACT and kind and digest not in seen:
            seen.add(digest)
            artifacts.append((f"base64-{kind}", blob))
    return artifacts[:128]


class _ZipQuotaExceeded(ValueError):
    """部分的に復元したZIPアーティファクトをすべて破棄する内部シグナル。"""

    def __init__(self, status: str, name: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.name = name
        self.detail = detail


@contextmanager
def _open_aes_zip(data: bytes):
    """pyzipper固有の破損例外を標準BadZipFileへ正規化する。"""

    try:
        with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
            yield archive
    except pyzipper.BadZipFile as exc:
        raise zipfile.BadZipFile(str(exc)) from exc


def _read_standard_zip_member_capped(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    name: str,
    max_member_size: int,
    remaining_total: int,
    max_compression_ratio: float,
    chunk_size: int,
) -> bytes:
    """ZIPメンバー1件を上限付きの断片で読み、偽装メタデータを拒否する。"""

    declared_size = int(info.file_size)
    compressed_size = int(info.compress_size)
    if compressed_size < 0:
        raise _ZipQuotaExceeded("malformed_metadata", name, "negative compressed size")
    ratio_output_limit = int(compressed_size * max_compression_ratio)
    output_limit = min(
        declared_size,
        max_member_size,
        remaining_total,
        ratio_output_limit,
    )
    output_size = 0
    chunks: list[bytes] = []
    with archive.open(info, "r") as handle:
        while True:
            read_size = min(chunk_size, output_limit - output_size + 1)
            chunk = handle.read(max(1, read_size))
            if not chunk:
                break
            output_size += len(chunk)
            if output_size > declared_size:
                raise _ZipQuotaExceeded(
                    "size_mismatch",
                    name,
                    f"declared {declared_size} bytes but output exceeded it",
                )
            if output_size > max_member_size:
                raise _ZipQuotaExceeded(
                    "size_blocked", name, f"member exceeded {max_member_size} bytes"
                )
            if output_size > remaining_total:
                raise _ZipQuotaExceeded(
                    "total_size_blocked",
                    name,
                    "archive exceeded cumulative extracted-byte limit",
                )
            if output_size > ratio_output_limit:
                raise _ZipQuotaExceeded(
                    "ratio_blocked",
                    name,
                    f"member exceeded compression ratio {max_compression_ratio:g}",
                )
            chunks.append(chunk)
    if output_size != declared_size:
        raise _ZipQuotaExceeded(
            "size_mismatch",
            name,
            f"declared {declared_size} bytes but produced {output_size}",
        )
    return b"".join(chunks)


def recover_zip(
    data: bytes,
    *,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_member_size: int = MAX_ARTIFACT,
    max_total_size: int = MAX_EXTRACTED_TOTAL,
    max_compression_ratio: float = MAX_COMPRESSION_RATIO,
    read_chunk_size: int = ARCHIVE_READ_CHUNK_SIZE,
    password: str | bytes = b"",
) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """メンバー数、総バイト数、圧縮率の上限内でZIPを棚卸しする。"""

    for value, label in (
        (max_members, "max_members"),
        (max_member_size, "max_member_size"),
        (max_total_size, "max_total_size"),
        (max_compression_ratio, "max_compression_ratio"),
        (read_chunk_size, "read_chunk_size"),
    ):
        if isinstance(value, bool) or value <= 0:
            raise ValueError(f"{label} must be positive")
    if not isinstance(password, (str, bytes)):
        raise TypeError("passwordはstrまたはbytesで指定してください")
    password_bytes = password.encode("utf-8") if isinstance(password, str) else password

    inventory: list[dict] = []
    artifacts: list[tuple[str, bytes]] = []
    with _open_aes_zip(data) as archive:
        if password_bytes:
            archive.setpassword(password_bytes)
        infos = [item for item in archive.infolist() if not item.is_dir()]
        if len(infos) > max_members:
            return [
                {
                    "name": "__archive__",
                    "status": "member_limit_applied",
                    "member_limit": max_members,
                    "total_members": len(infos),
                    "selected_members": 0,
                }
            ], []

        prepared: list[tuple[zipfile.ZipInfo, str]] = []
        declared_total = 0
        for info in infos:
            name = safe_member_name(info.filename)
            declared_size = int(info.file_size)
            compressed_size = int(info.compress_size)
            if declared_size < 0 or compressed_size < 0:
                return [
                    {
                        "name": name,
                        "status": "malformed_metadata",
                        "size": declared_size,
                        "compressed_size": compressed_size,
                    }
                ], []
            if declared_size > max_member_size:
                inventory.append(
                    {
                        "name": name,
                        "status": "size_blocked",
                        "size": declared_size,
                        "member_size_limit": max_member_size,
                    }
                )
                continue
            declared_total += declared_size
            if declared_total > max_total_size:
                return [
                    {
                        "name": "__archive__",
                        "status": "total_size_blocked",
                        "declared_total_size": declared_total,
                        "total_size_limit": max_total_size,
                    }
                ], []
            ratio_output_limit = int(compressed_size * max_compression_ratio)
            if declared_size > ratio_output_limit:
                return [
                    {
                        "name": name,
                        "status": "ratio_blocked",
                        "size": declared_size,
                        "compressed_size": compressed_size,
                        "compression_ratio_limit": max_compression_ratio,
                    }
                ], []
            prepared.append((info, name))

        extracted_total = 0
        for info, name in prepared:
            try:
                blob = _read_standard_zip_member_capped(
                    archive,
                    info,
                    name=name,
                    max_member_size=max_member_size,
                    remaining_total=max_total_size - extracted_total,
                    max_compression_ratio=max_compression_ratio,
                    chunk_size=read_chunk_size,
                )
            except RuntimeError:
                inventory.append(
                    {"name": name, "size": info.file_size, "status": "encrypted"}
                )
                continue
            except _ZipQuotaExceeded as exc:
                return [
                    {
                        "name": exc.name,
                        "status": exc.status,
                        "detail": exc.detail,
                    }
                ], []
            extracted_total += len(blob)
            kind = detect_format(blob, name)
            inventory.append(
                {
                    "name": name,
                    "size": len(blob),
                    "sha256": sha256_bytes(blob),
                    "format": kind,
                }
            )
            member_name = PurePosixPath(name).name
            artifacts.append((f"zip-{kind}-{member_name}", blob))
    return inventory, artifacts


def run_upx(
    data: bytes, executable: Path, timeout: float = 120.0
) -> tuple[dict, bytes | None]:
    """データ変換としてUPX展開を呼び出し、出力PEを検証する。"""
    if not executable.is_file():
        return {"status": "unavailable", "path": str(executable)}, None
    with tempfile.TemporaryDirectory(prefix="asa-upx-") as temp:
        root = Path(temp).resolve(strict=True)
        source, output = root / "input.bin", root / "unpacked.bin"
        source.write_bytes(data)
        try:
            completed = _run_static_tool_process(
                [str(executable), "-d", "-o", str(output), str(source)],
                cwd=root,
                timeout=timeout,
                max_temp_entries=32,
                max_temp_bytes=min(
                    MAX_STATIC_TOOL_TEMP_BYTES,
                    max(1, len(data) + MAX_ARTIFACT + 16 * 1024 * 1024),
                ),
            )
        except StaticToolExecutionError as exc:
            return {"status": _static_tool_failure_status(exc)}, None
        if completed.returncode or not output.is_file():
            return {
                "status": "not_upx_or_failed",
                "exit_code": completed.returncode,
            }, None
        try:
            blob = _read_static_tool_output(
                output,
                root=root,
                maximum_size=MAX_ARTIFACT,
            )
        except (OSError, StaticToolExecutionError):
            return {
                "status": "unsafe_tool_output",
                "exit_code": completed.returncode,
            }, None
        if not blob.startswith(b"MZ"):
            return {"status": "invalid_output", "exit_code": completed.returncode}, None
        return {
            "status": "recovered",
            "size": len(blob),
            "sha256": sha256_bytes(blob),
        }, blob


def decode_autoit_xor_literals(script: bytes) -> list[str]:
    """逆コンパイル済みAutoItソース内の反復鍵XOR文字列呼び出しを復号する。"""
    text = script.decode("utf-8", errors="ignore")
    pattern = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*\(\"0x([0-9A-Fa-f]+)\",\s*\"([^\"]+)\"\)"
    )
    decoded, seen = [], set()
    for match in pattern.finditer(text):
        if len(decoded) >= 20000 or len(match.group(1)) > 2 * 1024 * 1024:
            continue
        raw, key = bytes.fromhex(match.group(1)), match.group(2).encode()
        if not key:
            continue
        value = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(raw))
        rendered = value.decode("latin1")
        printable = sum(character.isprintable() for character in rendered)
        if rendered and printable / len(rendered) >= 0.8 and rendered not in seen:
            decoded.append(rendered)
            seen.add(rendered)
    return decoded


def recover_autoit_rc4_lznt1(
    script: bytes,
) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """AutoItのRC4・LZNT1ローダー式からPEペイロードを復元する。"""
    from Cryptodome.Cipher import ARC4
    from refinery.units.compression.lznt1 import lznt1

    text = script.decode("utf-8", errors="ignore")
    pattern = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*\(Binary\(\$([A-Za-z_][A-Za-z0-9_]*)\),\s*"
        r"Binary\([A-Za-z_][A-Za-z0-9_]*\(\"0x([0-9A-Fa-f]+)\",\s*\"([^\"]+)\"\)\)\)"
    )
    reports, artifacts, seen = [], [], set()
    for match in pattern.finditer(text):
        variable, key_hex, key_text = match.groups()
        key_raw, xor_key = bytes.fromhex(key_hex), key_text.encode()
        if not xor_key:
            continue
        key = bytes(
            byte ^ xor_key[index % len(xor_key)] for index, byte in enumerate(key_raw)
        )
        segment_pattern = re.compile(
            rf"\${re.escape(variable)}\s*=\s*(?:\${re.escape(variable)}\s*&\s*)?"
            r"\"(?:0x)?([0-9A-Fa-f]+)\""
        )
        segments = segment_pattern.findall(text)
        total_hex = sum(len(segment) for segment in segments)
        if not segments or total_hex % 2 or total_hex // 2 > MAX_ARTIFACT:
            continue
        ciphertext = bytes.fromhex("".join(segments))
        candidate_id = (sha256_bytes(ciphertext), sha256_bytes(key))
        if candidate_id in seen:
            continue
        seen.add(candidate_id)
        try:
            compressed = ARC4.new(key).decrypt(ciphertext)
            payload = bytes(lznt1()(compressed))
        except Exception as exc:
            reports.append(
                {
                    "variable": variable,
                    "status": "decode_failed",
                    "error": type(exc).__name__,
                }
            )
            continue
        if not payload.startswith(b"MZ") or valid_pe_extent(payload, 0) is None:
            reports.append(
                {
                    "variable": variable,
                    "status": "decoded_non_pe",
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                }
            )
            continue
        reports.append(
            {
                "variable": variable,
                "status": "pe_recovered",
                "segments": len(segments),
                "ciphertext_size": len(ciphertext),
                "ciphertext_sha256": sha256_bytes(ciphertext),
                "rc4_key": key.decode("ascii", errors="replace"),
                "compressed_sha256": sha256_bytes(compressed),
                "payload_size": len(payload),
                "payload_sha256": sha256_bytes(payload),
            }
        )
        artifacts.append(("autoit-rc4-lznt1-pe", payload))
    return reports, artifacts


def recover_autoit_script(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """AutoIt A3Xを逆コンパイルし、XOR・RC4・LZNT1層を静的に復元する。"""
    try:
        from refinery.units.formats.a3xs import a3xs

        script = bytes(a3xs()(data))
    except Exception as exc:  # refinery exposes multiple format/parser failures
        return {"status": "decompile_failed", "error": type(exc).__name__}, []
    if not script or len(script) > MAX_ARTIFACT:
        return {"status": "invalid_or_oversized_output", "size": len(script)}, []
    decoded_strings = decode_autoit_xor_literals(script)
    behavior_tokens = (
        "http",
        ".dll",
        "process",
        "virtualalloc",
        "writeprocessmemory",
        "createthread",
        "ntwritevirtualmemory",
        "rtl decompress",
        "socket",
        "powershell",
    )
    behavior_strings = [
        value
        for value in decoded_strings
        if len(value) <= 512
        and any(token in value.lower() for token in behavior_tokens)
    ][:256]
    payloads, recovered = recover_autoit_rc4_lznt1(script)
    return (
        {
            "status": "decompiled",
            "size": len(script),
            "sha256": sha256_bytes(script),
            "decoded_xor_strings": len(decoded_strings),
            "behavior_strings": behavior_strings,
            "payloads": payloads,
            "sample_executed": False,
        },
        [("autoit-decompiled-script.au3", script), *recovered],
    )


def run_die(
    data: bytes,
    executable: Path,
    name: str = "sample.bin",
    timeout: float = 120.0,
) -> dict:
    """Detect It Easyを静的分類器として実行し、JSON証拠を解析する。"""
    if not executable.is_file():
        return {"status": "unavailable", "path": str(executable)}
    with tempfile.TemporaryDirectory(prefix="asa-die-") as temp:
        root = Path(temp).resolve(strict=True)
        suffix = safe_temporary_suffix(name)
        source = root / f"sample{suffix}"
        source.write_bytes(data)
        try:
            completed = _run_static_tool_process(
                [str(executable), "-j", "-d", "-u", str(source)],
                cwd=root,
                timeout=timeout,
                max_temp_entries=32,
                max_temp_bytes=min(
                    MAX_STATIC_TOOL_TEMP_BYTES,
                    max(1, len(data) + 16 * 1024 * 1024),
                ),
            )
        except StaticToolExecutionError as exc:
            return {"status": _static_tool_failure_status(exc)}
        if completed.returncode:
            return {"status": "failed", "exit_code": completed.returncode}
        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {"status": "invalid_json", "exit_code": completed.returncode}
        values = []
        for detection in document.get("detects", []):
            for value in detection.get("values", []):
                if value.get("string"):
                    values.append(value["string"])
        return {
            "status": "detected",
            "values": values,
            "raw": document,
            "sample_executed": False,
        }


def select_high_value_archive_members(
    records: list[dict[str, object]],
    *,
    max_members: int = MAX_RETAINED_MEMBERS,
    max_member_size: int = MAX_ARTIFACT,
    max_total_size: int = MAX_EXTRACTED_TOTAL,
) -> list[dict[str, object]]:
    """大規模アーカイブから後段解析に必要なファイルだけを有界に選ぶ。"""

    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in (max_members, max_member_size, max_total_size)
    ):
        raise ValueError("selective archive limits must be positive integers")
    ranked: list[tuple[int, str, dict[str, object]]] = []
    for record in records[:MAX_SELECTIVE_ARCHIVE_SCAN_MEMBERS]:
        raw_name = str(record.get("name") or "")
        try:
            normalized = safe_member_name(raw_name)
        except ValueError:
            continue
        attributes = str(record.get("attributes") or "")
        try:
            size = int(record.get("size") or 0)
        except (TypeError, ValueError):
            continue
        if "D" in attributes.upper() or not 0 < size <= max_member_size:
            continue
        lowered = normalized.lower()
        suffix = PurePosixPath(lowered).suffix
        basename = PurePosixPath(lowered).name
        in_node_modules = "/node_modules/" in f"/{lowered}"
        if basename.startswith(("license", "notice", "credits")):
            continue
        if (
            suffix not in SELECTIVE_ARCHIVE_SUFFIXES
            and suffix not in ISO_IMAGE_SUFFIXES
        ):
            continue
        if not in_node_modules and (
            suffix in SCRIPT_SUFFIXES | {".jsc", ".py", ".asar"}
            or basename in {"package.json", "package-lock.json"}
        ):
            priority = 0
        elif not in_node_modules and suffix in {".json", ".ini", ".cfg", ".conf"}:
            priority = 1
        elif not in_node_modules:
            priority = 2
        elif suffix == ".node":
            priority = 3
        else:
            # node_modules配下の一般ライブラリは依存関係名だけで十分であり、
            # アプリ本体より先に保持枠を消費させない。
            continue
        ranked.append((priority, lowered, {"name": raw_name, "size": size}))

    selected: list[dict[str, object]] = []
    selected_total = 0
    seen: set[str] = set()
    for priority, lowered, record in sorted(
        ranked, key=lambda item: (item[0], item[1])
    ):
        if lowered in seen:
            continue
        size = int(record["size"])
        if selected_total + size > max_total_size:
            continue
        selected.append({**record, "priority": priority})
        selected_total += size
        seen.add(lowered)
        if len(selected) >= max_members:
            break
    return selected


def safe_temporary_suffix(name: str) -> str:
    """復元レイヤー名から外部静的ツール用の安全な拡張子だけを返す。"""

    candidate = Path(name).suffix
    return candidate if re.fullmatch(r"\.[A-Za-z0-9]{1,16}", candidate) else ".bin"


def sevenzip_inventory(data: bytes, executable: Path, password: str = "") -> dict:
    """アーカイブ候補の識別と一覧化だけに7-Zipを使用する。"""
    if not executable.is_file():
        return {"status": "unavailable", "path": str(executable)}
    with tempfile.TemporaryDirectory(prefix="asa-7z-list-") as temp:
        root = Path(temp).resolve(strict=True)
        source = root / "input.bin"
        source.write_bytes(data)
        command = [str(executable), "l", "-slt", "-sccUTF-8"]
        if password:
            command.append(f"-p{password}")
        command.extend(["--", str(source)])
        try:
            completed = _run_static_tool_process(
                command,
                cwd=root,
                timeout=60,
                max_temp_entries=32,
                max_temp_bytes=min(
                    MAX_STATIC_TOOL_TEMP_BYTES,
                    max(1, len(data) + 16 * 1024 * 1024),
                ),
                encoding="utf-8",
            )
        except StaticToolExecutionError as exc:
            return {
                "status": _static_tool_failure_status(exc),
                "archive_types": [],
                "members": [],
                "total_members": 0,
                "declared_total_size": 0,
                "password_attempted": bool(password),
                "archive_unlock_attempted": bool(password),
                "_member_records": [],
            }
        paths, types, declared_sizes = [], [], []
        member_records: list[dict[str, object]] = []
        current: dict[str, object] | None = None
        for line in completed.stdout.splitlines():
            if line.startswith("Path = "):
                value = line[7:]
                if current is not None:
                    member_records.append(current)
                current = {"name": value} if value != str(source) else None
                if value != str(source):
                    paths.append(value)
            elif line.startswith("Type = "):
                types.append(line[7:])
            elif line.startswith("Size = ") and line[7:].strip().isdigit():
                value = int(line[7:].strip())
                declared_sizes.append(value)
                if current is not None:
                    current["size"] = value
            if line.startswith("Attributes = ") and current is not None:
                current["attributes"] = line[13:]
        if current is not None:
            member_records.append(current)
        return {
            "status": "listed"
            if completed.returncode == 0
            else "encrypted_or_unsupported",
            "exit_code": completed.returncode,
            "archive_types": sorted(set(types)),
            "members": paths[:MAX_ARCHIVE_MEMBERS],
            "total_members": len(paths),
            "declared_total_size": sum(declared_sizes),
            "password_attempted": bool(password),
            # sevenzip_extract内の選択抽出にだけ使い、公開レポートへは残さない。
            "_member_records": member_records,
            # Safe public alias retained by report sanitizers that intentionally
            # remove every field whose name contains "password".
            "archive_unlock_attempted": bool(password),
        }


def reassemble_split_parts(
    files: dict[str, bytes],
    *,
    max_parts: int = MAX_ARCHIVE_MEMBERS,
    max_artifact_size: int = MAX_ARTIFACT,
) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """オフセットと長さを検証してからJadoo形式の分割ファイルを再構築する。"""

    if max_parts <= 0 or max_artifact_size <= 0:
        raise ValueError("split reassembly limits must be positive")
    reports: list[dict] = []
    artifacts: list[tuple[str, bytes]] = []
    by_basename: dict[str, list[tuple[str, bytes]]] = {}
    for name, blob in files.items():
        by_basename.setdefault(PurePosixPath(name).name, []).append((name, blob))
    for manifest_name, manifest_blob in files.items():
        if not manifest_name.lower().endswith("_info.json"):
            continue
        try:
            manifest = json.loads(manifest_blob.decode("utf-8"))
            parts = manifest["parts"]
            expected_size = int(manifest["file_size"])
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            reports.append({"manifest": manifest_name, "status": "invalid_manifest"})
            continue
        if not isinstance(parts, list) or not 1 <= len(parts) <= max_parts:
            reports.append({"manifest": manifest_name, "status": "invalid_part_count"})
            continue
        if not 0 < expected_size <= max_artifact_size:
            reports.append({"manifest": manifest_name, "status": "size_blocked"})
            continue
        chunks, cursor, failure = [], 0, None
        for part in sorted(parts, key=lambda item: int(item.get("start", -1))):
            try:
                basename = PurePosixPath(str(part["original_name"])).name
                expected_part_size = int(part["size"])
                start, end = int(part["start"]), int(part["end"])
            except (KeyError, TypeError, ValueError):
                failure = "invalid_part_metadata"
                break
            candidates = by_basename.get(basename, [])
            if len(candidates) != 1:
                failure = "missing_or_ambiguous_part"
                break
            blob = candidates[0][1]
            if start != cursor or end != start + expected_part_size - 1:
                failure = "non_contiguous_offsets"
                break
            if len(blob) != expected_part_size:
                failure = "part_size_mismatch"
                break
            chunks.append(blob)
            cursor += len(blob)
        if failure or cursor != expected_size:
            reports.append(
                {
                    "manifest": manifest_name,
                    "status": failure or "final_size_mismatch",
                    "expected_size": expected_size,
                    "observed_size": cursor,
                }
            )
            continue
        rebuilt = b"".join(chunks)
        output_name = str(manifest.get("file_name", "reassembled.bin"))
        output_kind = detect_format(rebuilt, output_name)
        reports.append(
            {
                "manifest": manifest_name,
                "status": "reassembled",
                "output_name": output_name,
                "format": output_kind,
                "size": len(rebuilt),
                "sha256": sha256_bytes(rebuilt),
            }
        )
        artifacts.append((f"split-reassembled-{output_kind}", rebuilt))
    return reports, artifacts


def recovery_candidate_priority(blob: bytes, kind: str, name: str) -> int:
    """後段の層上限で重要な候補が落ちないよう、静的証跡だけで優先度を付ける。"""

    lowered = blob.lower()
    if kind == "pe" and any(
        marker in lowered for marker in (b"loader4.cfg", b"audio_pool.tmp")
    ):
        return 0
    if kind == "data":
        detached, _ = recover_detached_idat_stream(blob)
        if detached["status"] != "not_found":
            return 0
        return 2
    return 1


def recover_pyinstaller_carchive(
    data: bytes,
    *,
    max_member_size: int = MAX_ARTIFACT,
    max_total_size: int = MAX_EXTRACTED_TOTAL,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """PyInstaller CArchiveを全件検証し、高価値entryだけをメモリへ保持する。"""

    if MemoryCArchiveReader.COOKIE_MAGIC not in data:
        return {
            "status": "not_pyinstaller_carchive",
            "executed": False,
            "network_contacted": False,
        }, []
    entry_limit = min(max_member_size, PYINSTALLER_ENTRY_LIMIT)
    retention_limit = min(max_total_size, PYINSTALLER_RETENTION_TOTAL_LIMIT)
    validation_limit = min(max_total_size, PYINSTALLER_VALIDATION_TOTAL_LIMIT)
    try:
        result = analyze_carchive_bytes(
            data,
            max_entry_compressed_size=entry_limit,
            max_entry_uncompressed_size=entry_limit,
            max_total_compressed_size=retention_limit,
            max_total_uncompressed_size=retention_limit,
            max_validation_entry_compressed_size=entry_limit,
            max_validation_entry_uncompressed_size=entry_limit,
            max_validation_total_compressed_size=validation_limit,
            max_validation_total_uncompressed_size=validation_limit,
        )
        public = dict(result.report)
        sample = public.get("sample")
        selection = public.get("selection")
        selected = (
            selection.get("selected_entries") if isinstance(selection, dict) else None
        )
        if (
            not isinstance(sample, dict)
            or sample.get("sha256") != sha256_bytes(data)
            or sample.get("size") != len(data)
            or not isinstance(selection, dict)
            or type(selection.get("retained_count")) is not int
            or selection["retained_count"] != len(result.recovered_entries)
            or not isinstance(selected, list)
            or len(selected) != len(result.recovered_entries)
        ):
            raise MemoryCArchiveError(
                "PyInstaller公開contractと復元entryが一致しません"
            )
        artifacts: list[tuple[str, bytes]] = []
        for index, (metadata, entry) in enumerate(
            zip(selected, result.recovered_entries, strict=True)
        ):
            payload = entry.payload
            if (
                not isinstance(metadata, dict)
                or metadata.get("sha256") != entry.sha256
                or metadata.get("uncompressed_size") != len(payload)
                or entry.sha256 != sha256_bytes(payload)
                or len(payload) > entry_limit
            ):
                raise MemoryCArchiveError(
                    "PyInstaller選択entryのidentityが一致しません"
                )
            basename = PurePosixPath(entry.normalized_path).name
            label = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._")
            label = (label or "entry")[:48]
            artifacts.append(
                (
                    f"pyinstaller-{entry.category}-{index:03d}-{label}",
                    payload,
                )
            )
    except MemoryCArchiveError as exc:
        return {
            "schema_version": 1,
            "status": "parse_failed",
            "error_type": type(exc).__name__,
            "reason": str(exc)[:512],
            "executed": False,
            "external_process_started": False,
            "network_contacted": False,
            "file_written": False,
        }, []

    complete = public.get("complete") is True
    public["status"] = (
        "artifacts_recovered"
        if complete and artifacts
        else "inventory_validated"
        if complete
        else "partial_artifacts_recovered"
        if artifacts
        else "partial_inventory"
    )
    public["retained_artifact_count"] = len(artifacts)
    return public, artifacts


def sevenzip_extract(
    data: bytes,
    executable: Path,
    name: str = "input.bin",
    password: str = "",
    *,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_member_size: int = MAX_ARTIFACT,
    max_total_size: int = MAX_EXTRACTED_TOTAL,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """認識済みコンテナをパス、件数、バイト数の上限付きで展開する。"""

    for value, label in (
        (max_members, "max_members"),
        (max_member_size, "max_member_size"),
        (max_total_size, "max_total_size"),
    ):
        if isinstance(value, bool) or value <= 0:
            raise ValueError(f"{label} must be positive")
    # Supplying an unrelated archive password to a PE/NSIS image makes 7-Zip
    # omit its synthetic [NSIS].nsi decompilation stream. Probe without a
    # password first and keep that mode for NSIS; other archive types retain
    # the caller-provided password for encrypted RAR/7z/ZIP cases.
    unkeyed_listing = sevenzip_inventory(data, executable, "")
    unkeyed_types = {
        str(value).lower() for value in unkeyed_listing.get("archive_types", [])
    }
    effective_password = "" if "nsis" in unkeyed_types else password
    listing = (
        unkeyed_listing
        if not effective_password
        else sevenzip_inventory(data, executable, effective_password)
    )
    member_records = listing.pop("_member_records", [])
    if listing["status"] in {
        "unavailable",
        "timeout",
        "tool_output_limit",
        "temporary_quota_blocked",
        "tool_integrity_failed",
        "tool_failed",
    }:
        return listing, []
    extractable_types = {
        "7z",
        "apm",
        "cab",
        "dmg",
        "hfs",
        "mub",
        "nsis",
        "rar",
        "zip",
    }
    archive_types = {value.lower() for value in listing.get("archive_types", [])}
    supported_archive = archive_types.intersection(extractable_types) or any(
        value.startswith("rar") for value in archive_types
    )
    if not supported_archive:
        return {**listing, "status": "not_archive_container"}, []
    selective_members: list[dict[str, object]] = []
    member_limit_exceeded = int(listing.get("total_members", 0)) > max_members
    total_size_limit_exceeded = (
        int(listing.get("declared_total_size", 0)) > max_total_size
    )
    if member_limit_exceeded or total_size_limit_exceeded:
        selective_members = select_high_value_archive_members(
            member_records,
            max_members=min(MAX_RETAINED_MEMBERS, max_members),
            max_member_size=max_member_size,
            max_total_size=max_total_size,
        )
        if not selective_members:
            status = (
                "member_and_total_size_limit_blocked"
                if member_limit_exceeded and total_size_limit_exceeded
                else "member_limit_blocked"
                if member_limit_exceeded
                else "declared_size_blocked"
            )
            return {**listing, "status": status}, []
    password_candidates = [effective_password]
    if any(value.startswith("rar") for value in archive_types):
        for candidate in ("WNcry@2ol7",):
            if candidate not in password_candidates:
                password_candidates.append(candidate)

    with tempfile.TemporaryDirectory(prefix="asa-7z-extract-") as temp:
        root = Path(temp).resolve(strict=True)
        root_information = root.lstat()
        suffix = safe_temporary_suffix(name)

        source = root / f"input{suffix}"
        source.write_bytes(data)
        attempts = []
        attempt_failures: list[str] = []
        for candidate_index, candidate_password in enumerate(password_candidates):
            output = root / f"out-{candidate_index}"
            command = [str(executable), "x", "-y", "-bd", "-bb0", "-sccUTF-8"]
            if candidate_password:
                command.append(f"-p{candidate_password}")
            command.extend([f"-o{output}", "--", str(source)])
            if selective_members:
                command.extend(str(item["name"]) for item in selective_members)
            try:
                completed = _run_static_tool_process(
                    command,
                    cwd=root,
                    timeout=180,
                    max_temp_entries=min(
                        MAX_STATIC_TOOL_TEMP_ENTRIES,
                        max(1024, max_members * 4 + 32),
                    ),
                    max_temp_bytes=min(
                        MAX_STATIC_TOOL_TEMP_BYTES,
                        max(
                            1,
                            len(data) + max_total_size + 16 * 1024 * 1024,
                        ),
                    ),
                    encoding="utf-8",
                )
            except StaticToolExecutionError as exc:
                attempt_failures.append(_static_tool_failure_status(exc))
                continue
            extracted_size = (
                sum(
                    entry.lstat().st_size
                    for entry in output.rglob("*")
                    if (
                        not entry.is_symlink()
                        and stat.S_ISREG(entry.lstat().st_mode)
                        and _has_single_link(entry.lstat(), entry)
                        and not _has_reparse_attribute(entry.lstat())
                    )
                )
                if output.is_dir()
                else 0
            )
            attempts.append((completed, output, candidate_index, extracted_size))
            if completed.returncode == 0:
                break
        if not attempts:
            status = (
                "extract_timeout"
                if attempt_failures and set(attempt_failures) == {"timeout"}
                else attempt_failures[-1]
                if attempt_failures
                else "tool_failed"
            )
            return {**listing, "status": status}, []
        completed, output, selected_candidate_index, _ = max(
            attempts,
            key=lambda item: (item[0].returncode == 0, item[3], -item[2]),
        )
        inventory, candidates = [], []
        extracted_total = 0
        try:
            _validate_static_tool_temp_tree(
                root,
                expected_root=root_information,
                max_entries=min(
                    MAX_STATIC_TOOL_TEMP_ENTRIES,
                    max(1024, max_members * 4 + 32),
                ),
                max_bytes=min(
                    MAX_STATIC_TOOL_TEMP_BYTES,
                    max(1, len(data) + max_total_size + 16 * 1024 * 1024),
                ),
            )
        except StaticToolExecutionError as exc:
            return {**listing, "status": _static_tool_failure_status(exc)}, []
        output_resolved = output.resolve()
        extracted_entries = sorted(output.rglob("*")) if output.is_dir() else []
        regular_entries = [entry for entry in extracted_entries if entry.is_file()]
        if len(regular_entries) > max_members:
            return {
                **listing,
                "status": "actual_member_limit_blocked",
                "actual_members": len(regular_entries),
            }, []
        for entry in extracted_entries:
            try:
                information = entry.lstat()
            except OSError:
                inventory.append({"name": str(entry), "status": "metadata_blocked"})
                continue
            if (
                not stat.S_ISREG(information.st_mode)
                or entry.is_symlink()
                or not _has_single_link(information, entry)
                or _has_reparse_attribute(information)
            ):
                continue
            resolved = entry.resolve()
            try:
                resolved.relative_to(output_resolved)
            except ValueError:
                inventory.append({"name": str(entry), "status": "path_blocked"})
                continue
            attributes = getattr(information, "st_file_attributes", 0)
            if attributes & 0x400:
                inventory.append({"name": str(entry), "status": "reparse_blocked"})
                continue
            relative = entry.relative_to(output).as_posix()
            try:
                safe_member_name(relative)
            except ValueError:
                inventory.append({"name": relative, "status": "path_blocked"})
                continue
            size = information.st_size
            extracted_total += size
            if size > max_member_size:
                inventory.append(
                    {"name": relative, "size": size, "status": "size_blocked"}
                )
                continue
            if extracted_total > max_total_size:
                inventory.append(
                    {"name": relative, "size": size, "status": "total_size_blocked"}
                )
                continue
            try:
                blob = _read_static_tool_output(
                    entry,
                    root=output,
                    maximum_size=max_member_size,
                )
            except (OSError, StaticToolExecutionError):
                inventory.append(
                    {"name": relative, "size": size, "status": "read_blocked"}
                )
                continue
            if not blob:
                inventory.append(
                    {
                        "name": relative,
                        "size": 0,
                        "sha256": sha256_bytes(blob),
                        "format": "data",
                        "status": "empty_file",
                    }
                )
                continue
            kind = detect_format(blob, relative)
            suffix = entry.suffix.lower()
            iso_validation: dict[str, object] | None = None
            if suffix in ISO_IMAGE_SUFFIXES:
                if not is_iso9660(blob):
                    iso_validation = {"status": "signature_mismatch"}
                else:
                    validated = validate_iso9660_members(
                        blob,
                        max_members=max_members,
                        max_member_size=max_member_size,
                        max_total_size=max_total_size,
                    )
                    iso_validation = {
                        key: validated[key]
                        for key in (
                            "status",
                            "member_count",
                            "declared_total_size",
                            "max_members",
                            "max_member_size",
                            "max_total_size",
                            "error",
                        )
                        if key in validated
                    }
                    if validated["status"] == "validated":
                        kind = "iso9660"
            item = {
                "name": relative,
                "size": len(blob),
                "sha256": sha256_bytes(blob),
                "format": kind,
                "status": "extracted",
            }
            if iso_validation is not None:
                item["iso9660_validation"] = iso_validation
            inventory.append(item)
            keep = kind != "data" or suffix in SELECTIVE_ARCHIVE_SUFFIXES
            keep = keep or ".part-" in entry.name.lower()
            keep = keep or (not suffix and len(blob) <= 16 * 1024 * 1024)
            if keep:
                priority = recovery_candidate_priority(blob, kind, relative)
                item["recovery_priority"] = priority
                candidates.append((priority, relative, blob, kind))
        candidates.sort(key=lambda item: (item[0], item[1].lower()))
        selected = candidates[: min(MAX_RETAINED_MEMBERS, max_members)]
        file_map = {name: blob for _, name, blob, _ in selected}
        split_reports, split_artifacts = reassemble_split_parts(
            file_map,
            max_parts=max_members,
            max_artifact_size=max_member_size,
        )
        nsis_report, nsis_artifacts = ({"status": "not_nsis"}, [])
        if "nsis" in archive_types:
            nsis_report, nsis_artifacts = recover_nsis_scripted_layers(file_map)
        artifacts = [(f"7z-{kind}", blob) for _, _, blob, kind in selected]
        artifacts.extend(split_artifacts)
        artifacts.extend(nsis_artifacts)
        if selective_members and completed.returncode == 0:
            status = "selectively_extracted"
        else:
            status = "extracted" if completed.returncode == 0 else "partially_extracted"
        return (
            {
                **listing,
                "status": status,
                "extract_exit_code": completed.returncode,
                "archive_unlock_attempt_count": len(attempts),
                "archive_unlock_candidate_index": selected_candidate_index,
                "inventory": inventory[:max_members],
                "extracted_total_size": extracted_total,
                "retained_members": len(selected),
                "selective_extraction": {
                    "enabled": bool(selective_members),
                    "reason": (
                        "archive_member_and_total_size_limit"
                        if selective_members
                        and member_limit_exceeded
                        and total_size_limit_exceeded
                        else "archive_member_limit"
                        if selective_members and member_limit_exceeded
                        else "archive_total_size_limit"
                        if selective_members
                        else "not_required"
                    ),
                    "selected_members": selective_members,
                    "selected_total_size": sum(
                        int(item["size"]) for item in selective_members
                    ),
                    "full_inventory_count": int(listing.get("total_members", 0)),
                },
                "split_reassembly": split_reports,
                "nsis_script_recovery": nsis_report,
            },
            artifacts,
        )


def recover_ole_streams(
    data: bytes,
    *,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_member_size: int = MAX_ARTIFACT,
    max_total_size: int = MAX_EXTRACTED_TOTAL,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """MSI/OLE streamを有界に列挙し、実行可能層とCAB等だけを復元する。"""

    if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return {"status": "not_ole"}, []
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:
        return {"status": "parse_failed", "error": f"{type(exc).__name__}: {exc}"}, []

    inventory: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    total_size = 0
    try:
        paths = ole.listdir(streams=True, storages=False)
        if len(paths) > max_members:
            return {
                "status": "member_limit_blocked",
                "stream_count": len(paths),
                "max_members": max_members,
                "inventory": [],
            }, []
        for parts in paths:
            name = "/".join(str(part) for part in parts)
            try:
                size = int(ole.get_size(parts))
            except Exception as exc:
                inventory.append(
                    {
                        "name": name,
                        "status": "metadata_error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            item: dict[str, object] = {"name": name, "size": size}
            if size < 0 or size > max_member_size:
                item["status"] = "size_blocked"
                inventory.append(item)
                continue
            total_size += size
            if total_size > max_total_size:
                item["status"] = "total_size_blocked"
                inventory.append(item)
                continue
            try:
                blob = ole.openstream(parts).read(max_member_size + 1)
            except Exception as exc:
                item.update(
                    status="read_failed",
                    error=f"{type(exc).__name__}: {exc}",
                )
                inventory.append(item)
                continue
            if len(blob) != size or len(blob) > max_member_size:
                item["status"] = "size_mismatch_blocked"
                inventory.append(item)
                continue
            kind = detect_format(blob, name)
            item.update(
                status="inspected",
                format=kind,
                sha256=sha256_bytes(blob),
            )
            inventory.append(item)
            if kind in {"cab", "pe", "zip", "script", "png", "7z", "rar"}:
                artifacts.append((f"ole-{kind}-stream", blob))
    finally:
        ole.close()

    return {
        "status": "artifacts_recovered" if artifacts else "no_artifact_recovered",
        "stream_count": len(inventory),
        "inspected_total_size": total_size,
        "inventory": inventory,
        "executed": False,
        "network_contacted": False,
    }, artifacts


def _cab_safety_fields() -> dict[str, object]:
    """CAB処理が副作用を持たないことをreportへ明示する。"""

    return {
        "executed": False,
        "network_contacted": False,
        "external_process_started": False,
        "disk_written": False,
    }


def _cab_data_checksum(payload: memoryview, seed: int) -> int:
    """MS-CAB CFDATA checksumを有界block上で計算する。"""

    checksum = seed
    trailing_size = len(payload) % 4
    body_size = len(payload) - trailing_size
    for offset in range(0, body_size, 4):
        checksum ^= struct.unpack_from("<I", payload, offset)[0]
    if trailing_size:
        checksum ^= int.from_bytes(payload[body_size:], "big")
    return checksum & 0xFFFFFFFF


def _cab_lzx_memory_budget(
    *,
    cabinet_size: int,
    members: tuple[_CabLzxMember, ...],
    folder_output_sizes: tuple[int, ...],
    window_bits: tuple[int, ...],
    data_block_count: int,
) -> _CabLzxMemoryBudget:
    """refineryのcacheとbytes化を含む最悪peakを保守的に見積もる。"""

    folder_cache_bytes = sum(folder_output_sizes)
    member_materialization_bytes = sum(member.size for member in members)
    decoder_window_bytes = 1 << max(window_bits)
    metadata_reserve_bytes = (
        len(members) * CAB_LZX_MEMBER_METADATA_RESERVE_BYTES
        + len(folder_output_sizes) * CAB_LZX_FOLDER_METADATA_RESERVE_BYTES
        + data_block_count * CAB_LZX_BLOCK_METADATA_RESERVE_BYTES
        + MAX_CAB_BLOCK_UNCOMPRESSED_SIZE
    )
    estimated_peak_bytes = (
        CAB_LZX_RUNTIME_MEMORY_RESERVE_BYTES
        + cabinet_size
        + folder_cache_bytes
        + member_materialization_bytes
        + decoder_window_bytes
        + metadata_reserve_bytes
    )
    return _CabLzxMemoryBudget(
        worker_limit_bytes=MAX_CAB_LZX_WORKER_MEMORY_BYTES,
        runtime_reserve_bytes=CAB_LZX_RUNTIME_MEMORY_RESERVE_BYTES,
        input_bytes=cabinet_size,
        folder_cache_bytes=folder_cache_bytes,
        member_materialization_bytes=member_materialization_bytes,
        decoder_window_bytes=decoder_window_bytes,
        metadata_reserve_bytes=metadata_reserve_bytes,
        estimated_peak_bytes=estimated_peak_bytes,
    )


def _cab_preflight(
    data: bytes,
    *,
    max_members: int,
    max_member_size: int,
    max_total_size: int,
) -> _CabLzxPreflight:
    """CAB parserへ渡す前に単一volume CABの全境界と予算を検証する。"""

    for value, reason in (
        (max_members, "invalid_member_limit"),
        (max_member_size, "invalid_member_size_limit"),
        (max_total_size, "invalid_total_size_limit"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise _CabLzxFallbackError(reason)
    if len(data) > MAX_ARTIFACT:
        raise _CabLzxFallbackError("cabinet_input_size_limit_exceeded")
    if len(data) < CAB_HEADER.size:
        raise _CabLzxFallbackError("truncated_header")

    (
        signature,
        reserved_1,
        cabinet_size,
        reserved_2,
        file_table_offset,
        reserved_3,
        version_minor,
        version_major,
        folder_count,
        file_count,
        flags,
        _set_id,
        cabinet_index,
    ) = CAB_HEADER.unpack_from(data)
    if signature != b"MSCF":
        raise _CabLzxFallbackError("invalid_signature")
    if any((reserved_1, reserved_2, reserved_3)):
        raise _CabLzxFallbackError("reserved_header_nonzero")
    if cabinet_size != len(data):
        raise _CabLzxFallbackError("cabinet_size_mismatch")
    if (version_major, version_minor) != (1, 3):
        raise _CabLzxFallbackError("unsupported_version")
    if flags & ~0x0007:
        raise _CabLzxFallbackError("invalid_flags")
    if flags & 0x0003 or cabinet_index != 0:
        raise _CabLzxFallbackError("multi_volume_not_supported")
    if folder_count == 0 or folder_count > max_members:
        raise _CabLzxFallbackError("folder_count_limit_exceeded")
    if file_count == 0 or file_count > max_members:
        raise _CabLzxFallbackError("file_count_limit_exceeded")

    cursor = CAB_HEADER.size
    folder_reserve_size = 0
    data_reserve_size = 0
    if flags & 0x0004:
        if cursor + CAB_RESERVE_HEADER.size > len(data):
            raise _CabLzxFallbackError("truncated_reserve_header")
        header_reserve_size, folder_reserve_size, data_reserve_size = (
            CAB_RESERVE_HEADER.unpack_from(data, cursor)
        )
        cursor += CAB_RESERVE_HEADER.size
        if cursor + header_reserve_size > len(data):
            raise _CabLzxFallbackError("header_reserve_out_of_bounds")
        cursor += header_reserve_size

    folders: list[tuple[int, int, int, int]] = []
    total_block_count = 0
    for _ in range(folder_count):
        folder_end = cursor + CAB_FOLDER.size + folder_reserve_size
        if folder_end > len(data):
            raise _CabLzxFallbackError("folder_table_out_of_bounds")
        block_offset, block_count, compression = CAB_FOLDER.unpack_from(data, cursor)
        cursor = folder_end
        if block_count == 0:
            raise _CabLzxFallbackError("empty_folder")
        total_block_count += block_count
        if total_block_count > MAX_CAB_DATA_BLOCKS:
            raise _CabLzxFallbackError("data_block_count_limit_exceeded")
        compression_type = compression & 0x000F
        window_bits = 0
        if compression_type == 3:
            window_bits = (compression >> 8) & 0x1F
            if compression != 3 | (window_bits << 8):
                raise _CabLzxFallbackError("invalid_lzx_compression_flags")
            if not CAB_LZX_MIN_WINDOW_BITS <= window_bits <= CAB_LZX_MAX_WINDOW_BITS:
                raise _CabLzxFallbackError("lzx_window_out_of_range")
        elif compression_type in {0, 1}:
            if compression != compression_type:
                raise _CabLzxFallbackError("invalid_compression_flags")
        else:
            raise _CabLzxFallbackError("unsupported_compression")
        folders.append((block_offset, block_count, compression_type, window_bits))

    compression_types = {folder[2] for folder in folders}
    if 3 in compression_types and compression_types != {3}:
        raise _CabLzxFallbackError("mixed_lzx_compression_not_supported")
    compression_name = (
        "lzx"
        if compression_types == {3}
        else "none"
        if compression_types == {0}
        else "mszip"
        if compression_types == {1}
        else "none_or_mszip"
    )

    if file_table_offset < cursor or file_table_offset >= len(data):
        raise _CabLzxFallbackError("file_table_out_of_bounds")

    members: list[_CabLzxMember] = []
    seen_names: set[str] = set()
    declared_file_total_size = 0
    cursor = file_table_offset
    for _ in range(file_count):
        if cursor + CAB_FILE.size > len(data):
            raise _CabLzxFallbackError("file_entry_out_of_bounds")
        size, offset, folder_index, _date, _time, attributes = CAB_FILE.unpack_from(
            data, cursor
        )
        name_start = cursor + CAB_FILE.size
        name_limit = min(len(data), name_start + MAX_CAB_MEMBER_NAME_BYTES + 1)
        name_end = data.find(b"\0", name_start, name_limit)
        if name_end < 0:
            raise _CabLzxFallbackError("member_name_unterminated_or_too_long")
        raw_name = data[name_start:name_end]
        if not raw_name:
            raise _CabLzxFallbackError("empty_member_name")
        try:
            decoded_name = raw_name.decode(
                "utf-8" if attributes & 0x0080 else "latin-1"
            )
            name = validate_member_name(decoded_name)
        except (UnicodeDecodeError, ValueError) as exc:
            raise _CabLzxFallbackError("unsafe_member_path") from exc
        collision_key = name.casefold()
        if collision_key in seen_names:
            raise _CabLzxFallbackError("duplicate_member_path")
        seen_names.add(collision_key)
        if folder_index >= folder_count:
            reason = (
                "multi_volume_file_not_supported"
                if folder_index in {0xFFFD, 0xFFFE, 0xFFFF}
                else "invalid_folder_index"
            )
            raise _CabLzxFallbackError(reason)
        if size > max_member_size:
            raise _CabLzxFallbackError("member_size_limit_exceeded")
        declared_file_total_size += size
        if declared_file_total_size > max_total_size:
            raise _CabLzxFallbackError("declared_file_total_size_limit_exceeded")
        members.append(
            _CabLzxMember(
                name=name,
                size=size,
                offset=offset,
                folder_index=folder_index,
            )
        )
        cursor = name_end + 1

    file_table_end = cursor
    folder_output_sizes: list[int] = []
    folder_ranges: list[tuple[int, int]] = []
    verified_checksum_count = 0
    for block_offset, block_count, compression_type, _window_bits in folders:
        if block_offset < file_table_end or block_offset >= len(data):
            raise _CabLzxFallbackError("folder_data_out_of_bounds")
        cursor = block_offset
        folder_output_size = 0
        for _ in range(block_count):
            block_header_end = cursor + CAB_DATA.size + data_reserve_size
            if block_header_end > len(data):
                raise _CabLzxFallbackError("data_block_header_out_of_bounds")
            checksum, compressed_size, uncompressed_size = CAB_DATA.unpack_from(
                data, cursor
            )
            if compressed_size == 0:
                raise _CabLzxFallbackError("empty_compressed_data_block")
            if not 0 < uncompressed_size <= MAX_CAB_BLOCK_UNCOMPRESSED_SIZE:
                raise _CabLzxFallbackError("invalid_uncompressed_data_block_size")
            block_end = block_header_end + compressed_size
            if block_end > len(data):
                raise _CabLzxFallbackError("data_block_out_of_bounds")
            if compression_type == 0 and compressed_size != uncompressed_size:
                raise _CabLzxFallbackError("uncompressed_block_size_mismatch")
            if compression_type == 1 and (
                compressed_size < 2
                or data[block_header_end : block_header_end + 2] != b"CK"
            ):
                raise _CabLzxFallbackError("invalid_mszip_block_header")
            if compression_type == 3 and checksum == 0:
                raise _CabLzxFallbackError("missing_data_block_checksum")
            if checksum:
                seed = compressed_size | (uncompressed_size << 16)
                actual_checksum = _cab_data_checksum(
                    memoryview(data)[block_header_end:block_end], seed
                )
                if actual_checksum != checksum:
                    raise _CabLzxFallbackError("data_block_checksum_mismatch")
                verified_checksum_count += 1
            folder_output_size += uncompressed_size
            if folder_output_size > max_total_size:
                raise _CabLzxFallbackError("folder_output_size_limit_exceeded")
            cursor = block_end
        folder_output_sizes.append(folder_output_size)
        folder_ranges.append((block_offset, cursor))

    previous_end = file_table_end
    for range_start, range_end in sorted(folder_ranges):
        if range_start < previous_end:
            raise _CabLzxFallbackError("folder_data_overlap")
        previous_end = range_end
    if sum(folder_output_sizes) > max_total_size:
        raise _CabLzxFallbackError("declared_folder_output_limit_exceeded")
    if compression_name == "lzx" and verified_checksum_count != total_block_count:
        raise _CabLzxFallbackError("checksum_coverage_incomplete")

    extents_by_folder: dict[int, list[tuple[int, int]]] = {}
    for member in members:
        member_end = member.offset + member.size
        if member_end > folder_output_sizes[member.folder_index]:
            raise _CabLzxFallbackError("member_extent_out_of_bounds")
        if member.size:
            extents_by_folder.setdefault(member.folder_index, []).append(
                (member.offset, member_end)
            )
    for extents in extents_by_folder.values():
        previous_end = 0
        for extent_start, extent_end in sorted(extents):
            if extent_start < previous_end:
                raise _CabLzxFallbackError("member_extent_overlap")
            previous_end = extent_end

    memory_budget: _CabLzxMemoryBudget | None = None
    if compression_name == "lzx":
        memory_budget = _cab_lzx_memory_budget(
            cabinet_size=len(data),
            members=tuple(members),
            folder_output_sizes=tuple(folder_output_sizes),
            window_bits=tuple(folder[3] for folder in folders),
            data_block_count=total_block_count,
        )
        if memory_budget.estimated_peak_bytes > memory_budget.worker_limit_bytes:
            raise _CabLzxFallbackError("lzx_peak_memory_budget_exceeded")

    return _CabLzxPreflight(
        members=tuple(members),
        folder_output_sizes=tuple(folder_output_sizes),
        window_bits=tuple(folder[3] for folder in folders),
        compression=compression_name,
        data_block_count=total_block_count,
        checksum_blocks_verified=verified_checksum_count,
        declared_file_total_size=declared_file_total_size,
        memory_budget=memory_budget,
    )


def _refinery_lzx_members(
    data: bytes,
    preflight: _CabLzxPreflight,
    *,
    max_total_size: int,
) -> list[tuple[str, bytes]]:
    """検証済みCABをbinary-refineryで一度だけin-memory展開する。"""

    if (
        preflight.compression != "lzx"
        or preflight.checksum_blocks_verified != preflight.data_block_count
    ):
        raise _CabLzxFallbackError("lzx_preflight_contract_mismatch")
    expected_memory_budget = _cab_lzx_memory_budget(
        cabinet_size=len(data),
        members=preflight.members,
        folder_output_sizes=preflight.folder_output_sizes,
        window_bits=preflight.window_bits,
        data_block_count=preflight.data_block_count,
    )
    if (
        preflight.memory_budget != expected_memory_budget
        or expected_memory_budget.estimated_peak_bytes
        > expected_memory_budget.worker_limit_bytes
    ):
        raise _CabLzxFallbackError("lzx_peak_memory_budget_contract_mismatch")
    try:
        cabinet = RefineryCabinet(memoryview(data), compute_checksums=True)
    except Exception as exc:
        raise _CabLzxFallbackError("refinery_parse_failed") from exc
    try:
        cabinet.check(checksums=True)
    except Exception as exc:
        raise _CabLzxFallbackError("refinery_checksum_validation_failed") from exc
    try:
        cabinet.process()
        disk_groups = list(cabinet.disks.values())
        if len(disk_groups) != 1 or len(disk_groups[0]) != 1:
            raise _CabLzxFallbackError("refinery_volume_contract_mismatch")
        folders = list(disk_groups[0][0].folders)
        if len(folders) != len(preflight.folder_output_sizes):
            raise _CabLzxFallbackError("refinery_folder_count_mismatch")
        for index, folder in enumerate(folders):
            method = getattr(folder, "method", None)
            if (
                not isinstance(method, tuple)
                or len(method) != 2
                or (int(method[0]) & 0x0F) != 3
                or int(method[1]) != preflight.window_bits[index]
            ):
                raise _CabLzxFallbackError("refinery_compression_contract_mismatch")
            if len(folder.decompress()) != preflight.folder_output_sizes[index]:
                raise _CabLzxFallbackError("refinery_folder_size_mismatch")
        parsed_members = list(cabinet.get_files())
    except _CabLzxFallbackError:
        raise
    except Exception as exc:
        raise _CabLzxFallbackError("refinery_decompression_failed") from exc

    expected = sorted(
        (
            member.name,
            member.size,
            member.offset,
            member.folder_index,
        )
        for member in preflight.members
    )
    parsed: list[tuple[tuple[str, int, int, int], int, object]] = []
    for ordinal, member in enumerate(parsed_members):
        raw_name = getattr(member, "name", None)
        size = getattr(member, "size", None)
        offset = getattr(member, "offset", None)
        folder_index = getattr(member, "_index", None)
        if not isinstance(raw_name, str):
            raise _CabLzxFallbackError("refinery_member_metadata_mismatch")
        try:
            name = validate_member_name(raw_name)
        except ValueError as exc:
            raise _CabLzxFallbackError("refinery_member_path_mismatch") from exc
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (size, offset, folder_index)
        ):
            raise _CabLzxFallbackError("refinery_member_metadata_mismatch")
        parsed.append(((name, size, offset, folder_index), ordinal, member))
    parsed.sort(key=lambda item: (*item[0], item[1]))
    if [metadata for metadata, _ordinal, _member in parsed] != expected:
        raise _CabLzxFallbackError("refinery_member_table_mismatch")

    recovered: list[tuple[str, bytes]] = []
    actual_total_size = 0
    for metadata, _ordinal, member in parsed:
        name, expected_size, _offset, _folder_index = metadata
        try:
            blob = bytes(member.decompress())
        except Exception as exc:
            raise _CabLzxFallbackError("refinery_member_decompression_failed") from exc
        if len(blob) != expected_size:
            raise _CabLzxFallbackError("refinery_member_size_mismatch")
        actual_total_size += len(blob)
        if actual_total_size > max_total_size:
            raise _CabLzxFallbackError("actual_total_size_limit_exceeded")
        recovered.append((name, blob))
    if actual_total_size != preflight.declared_file_total_size:
        raise _CabLzxFallbackError("actual_total_size_mismatch")
    return recovered


def _cab_inventory_report(
    members: list[tuple[str, bytes]],
    *,
    max_members: int,
    max_member_size: int,
    max_total_size: int,
    parser: str,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """展開済みCAB memberを決定的順序で再検証し、保持対象を選ぶ。"""

    members = sorted(members, key=lambda item: (str(item[0]).casefold(), str(item[0])))
    if len(members) > max_members:
        return {
            "status": "member_limit_blocked",
            "member_count": len(members),
            "max_members": max_members,
            "inventory": [],
            "parser": parser,
            "backend": "in_memory_python",
            **_cab_safety_fields(),
        }, []

    inventory: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    total_size = 0
    for raw_name, raw_blob in members:
        try:
            name = validate_member_name(str(raw_name))
        except ValueError:
            inventory.append({"name": str(raw_name), "status": "path_blocked"})
            continue
        blob = raw_blob if isinstance(raw_blob, bytes) else bytes(raw_blob)
        size = len(blob)
        item: dict[str, object] = {"name": name, "size": size}
        if size > max_member_size:
            item["status"] = "size_blocked"
            inventory.append(item)
            continue
        total_size += size
        if total_size > max_total_size:
            item["status"] = "total_size_blocked"
            inventory.append(item)
            continue
        kind = detect_format(blob, name)
        item.update(status="extracted", format=kind, sha256=sha256_bytes(blob))
        inventory.append(item)
        suffix = Path(name).suffix.lower()
        keep = kind != "data" or suffix in RECOVERY_SUFFIXES
        keep = keep or (not suffix and size <= 16 * 1024 * 1024)
        if keep:
            artifacts.append((f"cab-{kind}", blob))

    return {
        "status": "artifacts_recovered" if artifacts else "no_artifact_recovered",
        "member_count": len(inventory),
        "extracted_total_size": total_size,
        "inventory": inventory,
        "parser": parser,
        "backend": "in_memory_python",
        "deterministic_member_order": True,
        **_cab_safety_fields(),
    }, artifacts


def recover_cab_members(
    data: bytes,
    *,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_member_size: int = MAX_ARTIFACT,
    max_total_size: int = MAX_EXTRACTED_TOTAL,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """CABをPython parserだけで有界に展開し、解析価値のあるmemberを返す。"""

    if not data.startswith(b"MSCF"):
        return {"status": "not_cab", **_cab_safety_fields()}, []
    try:
        preflight = _cab_preflight(
            data,
            max_members=max_members,
            max_member_size=max_member_size,
            max_total_size=max_total_size,
        )
    except _CabLzxFallbackError as preflight_error:
        return {
            "status": "parse_failed",
            "parser": "cab-preflight",
            "lzx_fallback_attempted": False,
            "lzx_fallback_completed": False,
            "failure_reason": preflight_error.reason,
            **_cab_safety_fields(),
        }, []
    try:
        archive = cabarchive.CabArchive(data)
        archive_items = list(archive.items())
    except cabarchive.NotSupportedError as exc:
        if str(exc) != CAB_LZX_UNSUPPORTED_ERROR or preflight.compression != "lzx":
            return {
                "status": "parse_failed",
                "error": f"{type(exc).__name__}: {exc}",
                "parser": "cabarchive",
                "lzx_fallback_attempted": False,
                "lzx_fallback_completed": False,
                "preflight": preflight.public(len(data)),
                **_cab_safety_fields(),
            }, []
        try:
            member_blobs = _refinery_lzx_members(
                data,
                preflight,
                max_total_size=max_total_size,
            )
        except _CabLzxFallbackError as fallback_error:
            return {
                "status": "parse_failed",
                "parser": "cabarchive",
                "fallback_parser": "binary-refinery",
                "lzx_fallback_attempted": True,
                "lzx_fallback_completed": False,
                "failure_reason": fallback_error.reason,
                **_cab_safety_fields(),
            }, []
        report, artifacts = _cab_inventory_report(
            member_blobs,
            max_members=max_members,
            max_member_size=max_member_size,
            max_total_size=max_total_size,
            parser="binary-refinery",
        )
        complete_inventory = (
            report.get("member_count") == len(preflight.members)
            and report.get("extracted_total_size") == preflight.declared_file_total_size
            and all(
                item.get("status") == "extracted"
                for item in report.get("inventory", [])
                if isinstance(item, dict)
            )
        )
        if not complete_inventory:
            return {
                "status": "parse_failed",
                "parser": "binary-refinery",
                "lzx_fallback_attempted": True,
                "lzx_fallback_completed": False,
                "failure_reason": "post_decompression_inventory_mismatch",
                **_cab_safety_fields(),
            }, []
        report.update(
            {
                "fallback_from": "cabarchive_lzx_unsupported",
                "lzx_fallback_attempted": True,
                "lzx_fallback_completed": True,
                "preflight": preflight.public(len(data)),
                "in_memory_extraction": {
                    "contract_version": 2,
                    "status": "complete",
                    "parser": "binary-refinery",
                    "backend": "in_memory_python",
                    "compression": "lzx",
                    "preflight_status": "passed",
                    "checksum_status": "verified",
                    "checksum_blocks_verified": preflight.data_block_count,
                    "data_block_count": preflight.data_block_count,
                    "member_count": len(preflight.members),
                    "complete_member_inventory": True,
                    "path_validation": "passed",
                    "declared_size_validation": "passed",
                    "actual_size_validation": "passed",
                    "deterministic_member_order": True,
                    "multi_volume": False,
                    "peak_memory_budget": preflight.memory_budget.public(),
                    **_cab_safety_fields(),
                },
            }
        )
        return report, artifacts
    except Exception as exc:
        return {
            "status": "parse_failed",
            "error": f"{type(exc).__name__}: {exc}",
            "parser": "cabarchive",
            "lzx_fallback_attempted": False,
            "lzx_fallback_completed": False,
            "preflight": preflight.public(len(data)),
            **_cab_safety_fields(),
        }, []

    try:
        parsed_metadata = sorted(
            (validate_member_name(str(raw_name)), len(member))
            for raw_name, member in archive_items
        )
    except (TypeError, ValueError) as exc:
        return {
            "status": "parse_failed",
            "parser": "cabarchive",
            "lzx_fallback_attempted": False,
            "lzx_fallback_completed": False,
            "failure_reason": "cabarchive_member_metadata_invalid",
            "preflight": preflight.public(len(data)),
            "error_type": type(exc).__name__,
            **_cab_safety_fields(),
        }, []
    expected_metadata = sorted(
        (member.name, member.size) for member in preflight.members
    )
    if parsed_metadata != expected_metadata:
        return {
            "status": "parse_failed",
            "parser": "cabarchive",
            "lzx_fallback_attempted": False,
            "lzx_fallback_completed": False,
            "failure_reason": "cabarchive_member_table_mismatch",
            "preflight": preflight.public(len(data)),
            **_cab_safety_fields(),
        }, []
    member_blobs = [
        (validate_member_name(str(raw_name)), member.buf)
        for raw_name, member in archive_items
    ]
    report, artifacts = _cab_inventory_report(
        member_blobs,
        max_members=max_members,
        max_member_size=max_member_size,
        max_total_size=max_total_size,
        parser="cabarchive",
    )
    report.update(
        {
            "preflight": preflight.public(len(data)),
            "lzx_fallback_attempted": False,
            "lzx_fallback_completed": False,
        }
    )
    return report, artifacts


def unpack_bytes(
    data: bytes,
    name: str = "sample",
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    force_container_probe: bool = False,
    archive_password: str = "",
    max_archive_members: int = MAX_ARCHIVE_MEMBERS,
    max_archive_member_size: int = MAX_ARTIFACT,
    max_archive_total_size: int = MAX_EXTRACTED_TOTAL,
    max_archive_compression_ratio: float = MAX_COMPRESSION_RATIO,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """上限付き静的復元を実行し、メタデータとアーティファクトを返す。
    forceフラグは、汎用コンテナ判定に合致しない既知NSISキャリアなど、
    レビュー済みインベントリの手掛かりに使用する。入力は実行せず、
    設定済みアーカイブパーサーによる検査だけを許可する。
    """
    kind = detect_format(data, name)
    report = {
        "schema_version": 2,
        "name": name,
        "sha256": sha256_bytes(data),
        "size": len(data),
        "entropy": entropy(data),
        "format": kind,
        "entropy_sampled": len(data) > ENTROPY_FULL_LIMIT,
        "executed": False,
        "network_contacted": False,
    }
    iso9660_candidate = kind == "data" and is_iso9660(data)
    if iso9660_candidate:
        report["container_format"] = "iso9660"
    artifacts: list[tuple[str, bytes]] = (
        [] if iso9660_candidate else recover_whole_file_base64(data)
    )
    static_data = data
    if MemoryCArchiveReader.COOKIE_MAGIC in data:
        report["pyinstaller"], recovered = recover_pyinstaller_carchive(
            data,
            max_member_size=max_archive_member_size,
            max_total_size=max_archive_total_size,
        )
        artifacts.extend(recovered)
    if kind == "pe":
        report["inflated_pe"], recovered_blob = recover_inflated_pe(data)
        if recovered_blob:
            static_data = recovered_blob
            artifacts.append(("pe-inflated-gap-removed", recovered_blob))
    if diec and kind in {"pe", "macho"}:
        report["die"] = run_die(static_data, diec, name)
    if kind == "pe":
        try:
            report["pe"], recovered = pe_summary(static_data)
        except pefile.PEFormatError as exc:
            report["pe"] = {
                "status": "parse_failed",
                "error": str(exc),
                "classification": "corrupt_or_truncated",
                "packing_suspected": False,
            }
            report["unpack_status"] = "corrupt_or_truncated"
            return report, []
        artifacts.extend(recovered)
        report["dotnet_bundle"], recovered = recover_dotnet_bundle(
            static_data,
            max_entries=max_archive_members,
            max_entry_size=max_archive_member_size,
            max_total_size=max_archive_total_size,
        )
        artifacts.extend(recovered)
        embedded_archives = [
            (artifact_kind, artifact_data)
            for artifact_kind, artifact_data in artifacts
            if artifact_data.startswith(b"PK\x03\x04")
        ]
        embedded_report, embedded_artifacts, consumed_archives = (
            recover_embedded_installer_archive(
                static_data,
                embedded_archives,
                max_member_size=max_archive_member_size,
                max_total_size=max_archive_total_size,
            )
        )
        report["embedded_installer_archive"] = embedded_report
        if embedded_artifacts:
            artifacts = [
                item
                for item in artifacts
                if sha256_bytes(item[1]) not in consumed_archives
            ]
            artifacts.extend(embedded_artifacts)
        report["donut_wrapper"], recovered = recover_xor32_donut_wrapper(static_data)
        artifacts.extend(recovered)
        if report["pe"]["is_dotnet"]:
            report["dotnet_resources"], recovered = recover_dotnet_resources(
                static_data
            )
            artifacts.extend(recovered)
        section_names = {item["name"].lower() for item in report["pe"]["sections"]}
        likely_upx = "UPX!" in report["pe"]["packer_markers"] or any(
            "upx" in value for value in section_names
        )
        if upx and likely_upx:
            report["upx"], blob = run_upx(static_data, upx)
            if blob:
                artifacts.append(("upx", blob))
        elif upx:
            report["upx"] = {"status": "skipped_no_upx_evidence"}
        if sevenzip and (report["pe"]["containerized"] or force_container_probe):
            report["sevenzip"], recovered = sevenzip_extract(
                static_data,
                sevenzip,
                name,
                archive_password,
                max_members=max_archive_members,
                max_member_size=max_archive_member_size,
                max_total_size=max_archive_total_size,
            )
            artifacts.extend(recovered)
            report["sevenzip"]["forced_by_reviewed_hint"] = bool(
                force_container_probe and not report["pe"]["containerized"]
            )
            if (
                report["pe"]["containerized"]
                and report["sevenzip"].get("status") == "not_archive_container"
            ):
                report["unpack_status"] = "container_parser_unavailable"
        elif report["pe"]["containerized"]:
            report["unpack_status"] = "container_extractor_unavailable"
    elif kind == "macho":
        report["macho"] = macho_summary(data)
        report["macho_slices"], recovered = recover_macho_slices(data)
        artifacts.extend(recovered)
    elif kind == "png":
        report["png"], recovered = recover_png_concealed_data(data)
        artifacts.extend(recovered)
    elif kind == "xz":
        report["xz"], recovered_blob = recover_xz(data)
        if recovered_blob:
            artifacts.append(("xz-decompressed", recovered_blob))
    elif kind == "ole":
        report["ole"], recovered = recover_ole_streams(
            data,
            max_members=max_archive_members,
            max_member_size=max_archive_member_size,
            max_total_size=max_archive_total_size,
        )
        artifacts.extend(recovered)
    elif kind == "cab":
        report["cab"], recovered = recover_cab_members(
            data,
            max_members=max_archive_members,
            max_member_size=max_archive_member_size,
            max_total_size=max_archive_total_size,
        )
        artifacts.extend(recovered)
        if (
            sevenzip
            and not recovered
            and not report["cab"].get("lzx_fallback_attempted", False)
            and report["cab"].get("parser") != "cab-preflight"
            and not (
                isinstance(report["cab"].get("preflight"), dict)
                and report["cab"]["preflight"].get("compression") == "lzx"
            )
        ):
            report["sevenzip"], recovered = sevenzip_extract(
                data,
                sevenzip,
                name,
                archive_password,
                max_members=max_archive_members,
                max_member_size=max_archive_member_size,
                max_total_size=max_archive_total_size,
            )
            artifacts.extend(recovered)
    elif kind == "zip":
        try:
            report["zip"], recovered = recover_zip(
                data,
                max_members=max_archive_members,
                max_member_size=max_archive_member_size,
                max_total_size=max_archive_total_size,
                max_compression_ratio=max_archive_compression_ratio,
                password=archive_password,
            )
            artifacts.extend(recovered)
            blocked = {
                item.get("status") for item in report["zip"] if item.get("status")
            }
            serious = blocked - {"size_blocked"}
            if serious or ("size_blocked" in blocked and not recovered):
                report["unpack_status"] = "bounded_limit"
                report["recovered"] = []
                return report, []
            if "size_blocked" in blocked:
                report["unpack_status"] = "bounded_limit_with_partial_recovery"
        except (ValueError, zipfile.BadZipFile) as exc:
            report["zip_error"] = str(exc)
            report["unpack_status"] = "bounded_limit"
    elif kind in {"7z", "apple-disk-image", "rar"} and sevenzip:
        report["sevenzip"], recovered = sevenzip_extract(
            data,
            sevenzip,
            name,
            archive_password,
            max_members=max_archive_members,
            max_member_size=max_archive_member_size,
            max_total_size=max_archive_total_size,
        )
        artifacts.extend(recovered)
    elif kind == "autoit-a3x":
        report["autoit"], recovered = recover_autoit_script(data)
        artifacts.extend(recovered)
    elif kind == "asar":
        report["asar"], recovered = recover_asar(data)
        artifacts.extend(recovered)
    elif kind == "script":
        artifacts.extend(recover_encoded_blobs(data))
        if Path(name).suffix.lower() == ".au3":
            for field in (
                "javascript_dropper",
                "javascript_string_array",
                "javascript_plain_string_array",
            ):
                report[field] = {
                    "status": "not_applicable_autoit_source",
                    "executed": False,
                }
        else:
            report["javascript_dropper"], recovered = recover_javascript_dropper(data)
            artifacts.extend(recovered)
            report["javascript_string_array"], transformed = deobfuscate_string_array(
                data
            )
            if transformed:
                artifacts.append(("javascript-string-array-deobfuscated", transformed))
            report["javascript_plain_string_array"], transformed = (
                deobfuscate_plain_string_array(data)
            )
            if transformed:
                artifacts.append(
                    ("javascript-plain-string-array-deobfuscated", transformed)
                )
    elif kind == "data":
        if iso9660_candidate:
            report["iso9660"], recovered = recover_iso9660_layers(
                data,
                max_members=max_archive_members,
                max_member_size=max_archive_member_size,
                max_total_size=max_archive_total_size,
            )
            if report["iso9660"]["status"] not in {
                "artifacts_recovered",
                "no_artifact_recovered",
            }:
                report["unpack_status"] = (
                    "bounded_limit"
                    if str(report["iso9660"]["status"]).endswith("_blocked")
                    else "invalid_container"
                )
                report["recovered"] = []
                return report, []
            artifacts.extend(recovered)
        else:
            report["detached_idat"], recovered = recover_detached_idat_stream(data)
            artifacts.extend(recovered)
            report["profiled_transforms"], recovered = recover_profiled_transforms(
                static_data,
                input_format=kind,
                source_name=name,
            )
            artifacts.extend(recovered)
            legacy_attempt = next(
                (
                    item
                    for item in report["profiled_transforms"]["attempts"]
                    if item.get("profile_id") == "rotate_right_xor_c6_donut"
                ),
                None,
            )
            if legacy_attempt is not None:
                report["rotated_xor_donut"] = legacy_report_from_attempt(legacy_attempt)
    if not iso9660_candidate and len(static_data) <= 32 * 1024 * 1024:
        if b"rzk-stream-v3" in static_data and ENCODED_LECE_MAGIC in static_data:
            rzk_lece = find_rzk_lece_streams(static_data)
            report["rzk_lece"] = {
                "status": "encrypted_container_recovered"
                if rzk_lece
                else "profile_matched_recovery_failed",
                "candidates": rzk_lece_candidate_report(rzk_lece),
                "executed": False,
                "network_contacted": False,
                "family_classification": "independent_verification_required",
            }
            artifacts.extend(
                ("rzk-lece-encrypted-container", item.data) for item in rzk_lece
            )
        if matches_onyx_qt_profile(static_data):
            onyx_result = recover_onyx_qt_payload(static_data)
            if onyx_result is None:
                report["onyx_qt_loader"] = {
                    "status": "profile_matched_recovery_failed",
                    "executed": False,
                    "network_contacted": False,
                }
            else:
                report["onyx_qt_loader"] = onyx_result.metadata()
                artifacts.append(("onyx-qt-shellcode", onyx_result.payload))
        report["donut"], recovered = recover_donut_payloads(static_data)
        artifacts.extend(recovered)
    whole_file_embedded = [] if iso9660_candidate else carve_embedded_pes(static_data)
    artifacts.extend(whole_file_embedded)
    if iso9660_candidate:
        report["embedded_pe_scan"] = {
            "status": "skipped_validated_iso9660_members",
            "executed": False,
            "network_contacted": False,
        }
    else:
        report["embedded_pe_scan"] = getattr(
            whole_file_embedded,
            "scan_report",
            {
                "status": "not_reported_compatibility_hook",
                "executed": False,
                "network_contacted": False,
            },
        )
    deduplicated: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for artifact_kind, blob in artifacts:
        digest = sha256_bytes(blob)
        if digest == report["sha256"] or digest in seen:
            continue
        seen.add(digest)
        deduplicated.append((artifact_kind, blob))
    report["recovered"] = [
        {"kind": artifact_kind, "size": len(blob), "sha256": sha256_bytes(blob)}
        for artifact_kind, blob in deduplicated
    ]
    report.setdefault(
        "unpack_status",
        "artifacts_recovered" if deduplicated else "no_artifact_recovered",
    )
    return report, deduplicated


def write_artifacts(
    path: Path, artifacts: list[tuple[str, bytes]], password: str = "infected"
) -> None:
    """復元バイト列をAES暗号化した隔離アーカイブにだけ保存する。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(password.encode())
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        for kind, blob in artifacts:
            archive.writestr(f"{kind}/{sha256_bytes(blob)}.quarantine.bin", blob)


def build_parser() -> argparse.ArgumentParser:
    """静的展開器のコマンドラインパーサーを構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact-zip", type=Path)
    parser.add_argument("--upx", type=Path)
    parser.add_argument("--sevenzip", type=Path)
    parser.add_argument("--diec", type=Path)
    parser.add_argument("--force-container-probe", action="store_true")
    parser.add_argument("--archive-password", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    """生アーティファクト1件を解析し、必要に応じて復元層をアーカイブする。"""
    args = build_parser().parse_args(argv)
    if args.input.resolve() == args.output.resolve():
        raise ValueError("input and output paths must differ")
    report, artifacts = unpack_bytes(
        args.input.read_bytes(),
        args.input.name,
        args.upx,
        args.sevenzip,
        args.diec,
        args.force_container_probe,
        args.archive_password,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if args.artifact_zip and artifacts:
        write_artifacts(args.artifact_zip, artifacts)
    print(json.dumps({"output": str(args.output), "recovered": len(artifacts)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
