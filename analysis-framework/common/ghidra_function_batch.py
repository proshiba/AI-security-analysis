#!/usr/bin/env python3
"""Ghidra MCPとCIL parserで検体集合の代表関数と全体ロジックを記録する。

検体は不活性byte列としてだけ読み込み、実行、emulation、外部通信を行わない。
Ghidra操作はlocalhostのMCP endpointだけを使用し、program単位の全requestへ
明示的なproject pathを渡す。生の逆コンパイル本文とCIL命令列はリポジトリ外へ
保持し、公開成果物には秘匿値を除去した処理構造とfingerprintだけを保存する。
"""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import (
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

import dnfile
import pefile
from dncil.cil.body.reader import read_method_body_from_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from analysis_contract import (  # noqa: E402
    MAX_JSON_OBJECT_SIZE,
    _decode_json_object_strict,
    _ensure_json_depth,
    _read_regular_file_snapshot,
    _reject_non_finite,
    _strict_json_float,
    _strict_json_int,
    _strict_object_pairs,
    artifact_hashes,
    case_integrity_errors,
    ensure_no_reparse_components,
    load_json_object_strict,
    normalize_artifact_path,
    resolve_case_artifact,
    seal_report,
    verify_artifact_hashes,
    verify_report_semantics,
)
from analyze_sample import (  # noqa: E402
    StaticLayer,
    _layer_count_limit_reached,
    read_input_unit,
    recover_static_layers,
)
from c2_analysis_contract import (  # noqa: E402
    validate_contract as validate_c2_contract,
)
from case_features import build_case_profile, render_features_markdown  # noqa: E402
from overall_logic_diagrams import (  # noqa: E402
    load_static_layers,
    render_overall_logic_markdown,
)
from result_publication import detect_publication_context, register_publication_cases  # noqa: E402
from static_logic import (  # noqa: E402
    build_static_logic_report,
    extract_script_function_records,
    redact_static_text,
)
from unpackers.managed_il_triage import _contain_parser_diagnostics  # noqa: E402
from validate_function_analysis import (  # noqa: E402
    validate_case as validate_function_case,
)
from validate_function_analysis import (  # noqa: E402
    validate_collection,
)

SCHEMA_VERSION = 1
DEFAULT_COLLECTION_ID = "malwarebazaar-windows-20260723-0100"
DEFAULT_MCP_URL = "http://127.0.0.1:8089"
DEFAULT_PROJECT_ROOT = "/Malware/MalwareBazaarWindows/20260723"
MAX_MCP_RESPONSE_BYTES = 64 * 1024 * 1024
FUNCTION_PAGE_SIZE = 500
MAX_FUNCTION_INVENTORY_ITEMS = 100_000
MAX_FUNCTION_INVENTORY_PAGES = 10_000
CALL_GRAPH_ENDPOINT = "/get_full_call_graph"
CALL_GRAPH_REQUEST_FORMAT = "json_edges"
CALL_GRAPH_REQUEST_LIMIT = 0
CALL_GRAPH_MANAGED_LIMIT = "native_call_graph_not_applicable_managed_cil_primary"
CALL_GRAPH_LEGACY_LIMIT = "legacy_call_graph_retrieval_evidence_unavailable"
STRUCTURE_PAGE_SIZE = 1_000
DECOMPILE_BATCH_SIZE = 20
DECOMPILE_WORKERS = 3
BATCH_DECOMPILE_FUNCTION_TIMEOUT_SECONDS = 30
DECOMPILE_TRANSPORT_MARGIN_SECONDS = 60
MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM = 32
MAX_MANAGED_CIL_RAW_INSTRUCTIONS_PER_METHOD = 8
FUNCTION_ANALYSIS_BLOCKER = "representative_function_analysis_required"
ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER = "orchestration:function_analysis"
ORCHESTRATION_GENERIC_TRIAGE_BLOCKER = "orchestration:generic_triage"
FUNCTION_ANALYSIS_NEXT_ACTION_JA = "特徴関数と全体ロジックの静的解析を追加してください。"
GENERIC_TRIAGE_NEXT_ACTION_JA = "汎用静的triageの失敗または部分結果を再処理してください。"
ORCHESTRATION_SCHEMA_VERSION = 2
LEGACY_RUN_PROGRESS_SCHEMA_VERSION = 1
RUN_PROGRESS_SCHEMA_VERSION = 2
DEFAULT_MINIMUM_FREE_BYTES = 8 * 1024 * 1024 * 1024
MINIMUM_CONFIGURABLE_FREE_BYTES = 256 * 1024 * 1024
MAX_PREPARED_INPUT_BYTES = 512 * 1024 * 1024
MAX_PRIVATE_RAW_BYTES = 64 * 1024 * 1024
MAX_PRIVATE_RAW_RECORDS = 100_000
MAX_PRIVATE_RAW_LINE_BYTES = 8 * 1024 * 1024
MAX_PRIVATE_RAW_JSON_DEPTH = 64
MAX_PROGRAM_RESULT_INLINE_BYTES = 32 * 1024 * 1024
MAX_PROGRAM_FUNCTION_SHARD_BYTES = 32 * 1024 * 1024
PRIVATE_RAW_STREAM_CHUNK_BYTES = 64 * 1024
RETRYABLE_INCOMPLETE_EXIT_CODE = 20
FINALIZE_TRANSACTION_SCHEMA_VERSION = 1
FINALIZE_TRANSACTION_JOURNAL = "journal.json"
CASE_WIDE_PUBLICATION_REQUIRED = frozenset(
    {
        "static-logic.json",
        "STATIC-LOGIC.md",
        "OVERALL-LOGIC.md",
        "analysis.json",
        "README.md",
        "features.json",
        "FEATURES.md",
        "orchestration.json",
        "communication-patterns.json",
        "c2-analysis.json",
        "report.json",
    }
)

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FATAL_DECOMPILE_MARKERS = (
    "decompilation failed",
    "failed to decompile",
    "timeout",
    "no function",
)
LIMITED_DECOMPILE_MARKERS = (
    "control flow encountered bad instruction data",
    "bad instruction",
    "could not recover jumptable",
    "truncating control flow",
)
ROLE_PATTERNS = (
    (
        "entrypoint",
        re.compile(r"(?i)(?:^|[_.<>])(main|winmain|wmain|dllmain|entry|startup)(?:$|[_.<>])"),
    ),
    (
        "network_communication",
        re.compile(
            r"(?i)(socket|connect|send|recv|http|internet|winhttp|wininet|webclient|"
            r"download|upload|dns|ping|smtp|ftp|websocket)"
        ),
    ),
    (
        "command_dispatch_or_handler",
        re.compile(r"(?i)(command|dispatch|handler|interactive|shell|execute|task|job|request)"),
    ),
    (
        "config_or_data_transform",
        re.compile(r"(?i)(config|setting|parse|decode|decrypt|unpack|deserialize|resource|payload)"),
    ),
    (
        "cryptographic_transform",
        re.compile(r"(?i)(aes|rsa|rc4|chacha|xor|base64|crypt|cipher|hash|sha\d*|md5)"),
    ),
    (
        "process_or_memory_operation",
        re.compile(
            r"(?i)(process|thread|inject|virtualalloc|writeprocessmemory|"
            r"createremotethread|queueuserapc|loadlibrary|mapview|hollow)"
        ),
    ),
    (
        "persistence",
        re.compile(r"(?i)(persist|startup|autorun|registry|regset|service|schtask|runkey)"),
    ),
    (
        "anti_analysis",
        re.compile(
            r"(?i)(anti|debug|isdebugger|virtualbox|vmware|sandbox|sleep|timing|"
            r"queryperformance|cpuid|ntqueryinformation)"
        ),
    ),
    (
        "file_operation",
        re.compile(r"(?i)(createfile|readfile|writefile|deletefile|directory|filepath|stream|file)"),
    ),
)
LIBRARY_RE = re.compile(
    r"(?i)^(?:__|_?mem(?:cpy|set|move|cmp)|_?str(?:len|cpy|cmp)|"
    r"_?wcs|operator(?:new|delete)|std::|crt|security_check_cookie|"
    r"guard_|tls_callback|\.?ctor|\.?cctor|runtime[._]|internal(?:[./_]|$)|"
    r"type[.:_]|go[.:_])"
)
GO_MAIN_USER_CODE_RE = re.compile(r"(?i)^main(?:[.(*_/]|$)")
IMPORT_CAPABILITY_PATTERNS = {
    "configuration": re.compile(
        r"(?i)^(?:Crypt(?:Decrypt|UnprotectData|StringToBinary)|BCrypt|NCrypt|RtlDecompressBuffer)"
    ),
    "evasion": re.compile(
        r"(?i)^(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|"
        r"QueryPerformanceCounter|GetTickCount(?:64)?|Sleep(?:Ex)?)$"
    ),
    "persistence": re.compile(
        r"(?i)^(?:Reg(?:Create|Open|Set|Delete)|CreateService|StartService|"
        r"OpenSCManager|CoCreateInstance)$"
    ),
    "execution": re.compile(
        r"(?i)^(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|"
        r"CreateRemoteThread|QueueUserAPC|NtMapViewOfSection|CreateProcess|"
        r"ShellExecute|WinExec|LoadLibrary|CreateThread)"
    ),
    "communication": re.compile(
        r"(?i)^(?:socket|connect|send|recv|select|WSAStartup|Internet|WinHttp|"
        r"DnsQuery|gethostbyname|inet_addr|URLDownloadToFile)"
    ),
    "file_activity": re.compile(
        r"(?i)^(?:CreateFile|ReadFile|WriteFile|DeleteFile|MoveFile|CopyFile|"
        r"FindFirstFile|FindNextFile|PathFileExists)"
    ),
}
SUMMARY_BY_ROLE = {
    "entrypoint": "初期化と主要処理への分岐を行う入口関数です。",
    "network_communication": "通信初期化、送受信、またはendpoint処理に関係する関数です。",
    "command_dispatch_or_handler": "commandの解釈、分配、または個別処理を担当する関数です。",
    "config_or_data_transform": "設定、resource、payloadなどの解析・変換を行う関数です。",
    "cryptographic_transform": "暗号、hash、encoding、または復号処理に関係する関数です。",
    "process_or_memory_operation": "process、thread、module、またはmemory操作に関係する関数です。",
    "persistence": "自動起動または永続化に関係する処理を含む関数です。",
    "anti_analysis": "debugger、仮想環境、sandbox、または時間差の確認に関係する関数です。",
    "file_operation": "fileまたはdirectoryの読書き・管理に関係する関数です。",
    "compiler_or_library_code": "compiler生成処理または汎用library処理とみられる関数です。",
    "external_api_or_thunk": "外部APIまたはthunkであり、検体固有の関数本体を持ちません。",
    "managed_method_without_body": "metadata上に存在しますが、解析対象となるCIL本体を持たないmethodです。",
    "general_internal_logic": "検体内部の一般処理を実装する関数です。",
}


class GhidraMcpError(RuntimeError):
    """Ghidra MCP requestの失敗を表す。"""


def _request_timed_out(error: BaseException) -> bool:
    """例外連鎖に通信タイムアウトが含まれるかを判定する。"""

    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, TimeoutError):
            return True
        if isinstance(current, URLError) and isinstance(current.reason, TimeoutError):
            return True
        current = current.__cause__ or current.__context__
    return False


def _json_dump(path: Path, value: Any) -> None:
    """JSONを決定的にUTF-8で保存する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


@dataclass(frozen=True)
class _RegularFileSnapshot:
    """単一handleから取得した通常fileのcontent／identity binding。"""

    path: Path
    sha256: str
    size: int
    metadata: os.stat_result


@dataclass(frozen=True)
class _JsonlFileSnapshot(_RegularFileSnapshot):
    """全bytesを保持しないprivate JSONLの固定snapshot。"""

    record_count: int
    line_count: int
    ends_with_newline: bool


@dataclass(frozen=True)
class _ContentFileSnapshot(_RegularFileSnapshot):
    """JSON／Markdownを同じWALへ束縛するbounded content snapshot。"""

    data: bytes


@dataclass(frozen=True)
class _JsonFileSnapshot:
    """単一handleから取得したbounded JSON fileの固定snapshot。"""

    path: Path
    data: bytes
    sha256: str
    document: dict[str, Any]
    binding: _RegularFileSnapshot


@dataclass(frozen=True)
class _SnapshotFileStat:
    """read_input_unitへ渡すmemory snapshotの最小stat契約。"""

    st_size: int


@dataclass(frozen=True)
class _SnapshotInputPath:
    """検証済みarchive bytesだけをread_input_unitへ公開するpath互換object。"""

    name: str
    data: bytes = field(repr=False)

    def stat(self) -> _SnapshotFileStat:
        """固定snapshotのsizeだけを返す。"""

        return _SnapshotFileStat(st_size=len(self.data))

    def open(self, mode: str = "rb") -> io.BytesIO:
        """固定snapshotをread-only binary handleとして返す。"""

        if mode != "rb":
            raise ValueError("archive snapshotはread-only binary modeに限定します")
        return io.BytesIO(self.data)


@dataclass(frozen=True)
class _ArchiveManifestEntry:
    """acquisition manifestで認証した1 archiveの公開しない入力契約。"""

    sha256: str
    path: Path
    expected_zip_sha256: str | None
    expected_zip_size: int | None


def _json_bytes(value: Any) -> bytes:
    """決定的JSONをatomic writeへ渡せるUTF-8 bytesにする。"""

    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _regular_file_metadata(path: Path) -> os.stat_result:
    """通常fileかつ単一linkであるpathのmetadataをfail-closedに取得する。"""

    ensure_no_reparse_components(path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"通常fileを安全に確認できません: {path.name}") from exc
    if _stat_is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"通常file以外は使用できません: {path.name}")
    if int(metadata.st_nlink) != 1:
        raise ValueError(f"hardlinkされたfileは使用できません: {path.name}")
    return metadata


def _same_regular_file_binding(first: os.stat_result, second: os.stat_result) -> bool:
    """通常file snapshotのidentity、size、時刻、link数が同じか返す。"""

    return (
        _same_path_identity(first, second)
        and int(first.st_size) == int(second.st_size)
        and int(first.st_mtime_ns) == int(second.st_mtime_ns)
        and int(first.st_ctime_ns) == int(second.st_ctime_ns)
        and int(first.st_nlink) == int(second.st_nlink) == 1
    )


def _bounded_regular_file_snapshot(
    path: Path,
    *,
    max_bytes: int,
) -> tuple[bytes, _RegularFileSnapshot]:
    """通常fileを単一handleで読み、読取前後のpath bindingも固定する。"""

    path = Path(os.path.abspath(os.fspath(path)))
    before = _regular_file_metadata(path)
    data = _read_regular_file_snapshot(path, max_bytes=max_bytes)
    after = _regular_file_metadata(path)
    if len(data) != int(after.st_size) or not _same_regular_file_binding(before, after):
        raise ValueError(f"読取中にfile identityが変更されました: {path.name}")
    snapshot = _RegularFileSnapshot(
        path=path,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        metadata=after,
    )
    return data, snapshot


def _assert_regular_snapshot_unchanged(
    snapshot: _RegularFileSnapshot,
    *,
    context: str,
) -> None:
    """contentとidentityの両方が固定snapshotから変化していないか確認する。"""

    try:
        _, current = _bounded_regular_file_snapshot(
            snapshot.path,
            max_bytes=max(snapshot.size, MAX_JSON_OBJECT_SIZE),
        )
    except ValueError as exc:
        raise ValueError(f"{context}で競合変更を検出しました: {snapshot.path.name}") from exc
    if (
        current.sha256 != snapshot.sha256
        or current.size != snapshot.size
        or not _same_regular_file_binding(snapshot.metadata, current.metadata)
    ):
        raise ValueError(f"{context}で競合変更を検出しました: {snapshot.path.name}")


def _bounded_json_snapshot(path: Path) -> _JsonFileSnapshot:
    """通常file JSONを64MiB上限内の同一handle snapshotとして取得する。"""

    data, binding = _bounded_regular_file_snapshot(
        path,
        max_bytes=MAX_JSON_OBJECT_SIZE,
    )
    return _JsonFileSnapshot(
        path=binding.path,
        data=data,
        sha256=binding.sha256,
        document=_decode_json_object_strict(data, path=binding.path),
        binding=binding,
    )


def _bounded_content_snapshot(path: Path) -> _ContentFileSnapshot:
    """公開成果物を形式に依存せず64MiB上限で固定する。"""

    data, binding = _bounded_regular_file_snapshot(
        path,
        max_bytes=MAX_JSON_OBJECT_SIZE,
    )
    return _ContentFileSnapshot(
        path=binding.path,
        sha256=binding.sha256,
        size=binding.size,
        metadata=binding.metadata,
        data=data,
    )


def _assert_content_snapshot_unchanged(
    snapshot: _ContentFileSnapshot,
    *,
    context: str,
) -> None:
    """形式非依存snapshotのidentityと全bytesをcommit直前に再確認する。"""

    try:
        current = _bounded_content_snapshot(snapshot.path)
    except ValueError as exc:
        raise ValueError(f"{context}で競合変更を検出しました: {snapshot.path.name}") from exc
    if (
        current.sha256 != snapshot.sha256
        or current.data != snapshot.data
        or not _same_regular_file_binding(snapshot.metadata, current.metadata)
    ):
        raise ValueError(f"{context}で競合変更を検出しました: {snapshot.path.name}")


def _assert_transaction_snapshot_unchanged(
    snapshot: _JsonFileSnapshot | _ContentFileSnapshot,
    *,
    context: str,
) -> None:
    """WAL対象のJSON／Markdownを同一の競合検出境界で確認する。"""

    if isinstance(snapshot, _JsonFileSnapshot):
        _assert_snapshot_unchanged(snapshot, context=context)
    else:
        _assert_content_snapshot_unchanged(snapshot, context=context)


def _assert_snapshot_unchanged(
    snapshot: _JsonFileSnapshot,
    *,
    context: str,
) -> None:
    """固定snapshot以後のpath/identity/size/bytes変更をfail-closedに拒否する。"""

    try:
        current_data, current_binding = _bounded_regular_file_snapshot(
            snapshot.path,
            max_bytes=MAX_JSON_OBJECT_SIZE,
        )
    except ValueError as exc:
        raise ValueError(f"{context}で競合変更を検出しました: {snapshot.path.name}") from exc
    if (
        current_binding.sha256 != snapshot.sha256
        or current_data != snapshot.data
        or not _same_regular_file_binding(
            snapshot.binding.metadata,
            current_binding.metadata,
        )
    ):
        raise ValueError(f"{context}で競合変更を検出しました: {snapshot.path.name}")


def _atomic_replace_bytes(
    path: Path,
    data: bytes,
    *,
    expected_snapshot: (_JsonFileSnapshot | _ContentFileSnapshot | _RegularFileSnapshot | None) = None,
    maximum_bytes: int = MAX_JSON_OBJECT_SIZE,
    require_absent: bool = False,
    temporary_name: str | None = None,
) -> None:
    """同一directoryの一時fileから通常fileをatomicに置換する。"""

    if type(maximum_bytes) is not int or maximum_bytes < 0:
        raise ValueError("atomic write上限が不正です")
    if type(require_absent) is not bool:
        raise ValueError("atomic writeの既存file契約が不正です")
    if temporary_name is not None and (
        not isinstance(temporary_name, str)
        or not temporary_name
        or temporary_name in {".", ".."}
        or Path(temporary_name).name != temporary_name
        or "/" in temporary_name
        or "\\" in temporary_name
    ):
        raise ValueError("atomic write一時file名が不正です")
    if len(data) > maximum_bytes:
        raise ValueError(f"atomic write対象が{maximum_bytes} bytes上限を超えています: {path.name}")
    ensure_no_reparse_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(path.parent)
    try:
        parent_before = path.parent.lstat()
    except OSError as exc:
        raise ValueError("atomic write先directoryを確認できません") from exc
    if _stat_is_reparse(parent_before) or not stat.S_ISDIR(parent_before.st_mode):
        raise ValueError("atomic write先は通常directoryに限定します")
    temporary = path.with_name(temporary_name or f".atomic-{os.getpid():x}-{time.time_ns():x}.tmp")
    temporary_identity: os.stat_result | None = None
    try:
        with temporary.open("xb") as handle:
            temporary_identity = os.fstat(handle.fileno())
            if not stat.S_ISREG(temporary_identity.st_mode):
                raise ValueError("atomic write用一時pathが通常fileではありません")
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        ensure_no_reparse_components(temporary)
        temporary_at_path = temporary.lstat()
        if (
            _stat_is_reparse(temporary_at_path)
            or not stat.S_ISREG(temporary_at_path.st_mode)
            or not _same_path_identity(temporary_identity, temporary_at_path)
        ):
            raise ValueError("atomic write用一時fileのidentityが変更されました")
        ensure_no_reparse_components(path.parent)
        parent_before_replace = path.parent.lstat()
        if (
            _stat_is_reparse(parent_before_replace)
            or not stat.S_ISDIR(parent_before_replace.st_mode)
            or not _same_path_identity(parent_before, parent_before_replace)
        ):
            raise ValueError("atomic write前に出力directoryのidentityが変更されました")
        try:
            target_before = path.lstat()
        except FileNotFoundError:
            target_before = None
        if target_before is not None and (_stat_is_reparse(target_before) or not stat.S_ISREG(target_before.st_mode)):
            raise ValueError("atomic write対象は通常fileに限定します")
        if require_absent and target_before is not None:
            raise FileExistsError(f"atomic write対象が既に存在します: {path.name}")
        if expected_snapshot is not None:
            if path != expected_snapshot.path:
                raise ValueError(f"atomic write対象とsnapshot pathが一致しません: {path}")
            if isinstance(expected_snapshot, _JsonFileSnapshot):
                _assert_snapshot_unchanged(
                    expected_snapshot,
                    context="atomic commit直前",
                )
            elif isinstance(expected_snapshot, _ContentFileSnapshot):
                _assert_content_snapshot_unchanged(
                    expected_snapshot,
                    context="atomic commit直前",
                )
            else:
                _assert_regular_snapshot_unchanged(
                    expected_snapshot,
                    context="atomic commit直前",
                )
        os.replace(temporary, path)
        ensure_no_reparse_components(path)
        target_after = path.lstat()
        parent_after = path.parent.lstat()
        if (
            _stat_is_reparse(target_after)
            or not stat.S_ISREG(target_after.st_mode)
            or not _same_path_identity(temporary_identity, target_after)
            or _stat_is_reparse(parent_after)
            or not stat.S_ISDIR(parent_after.st_mode)
            or not _same_path_identity(parent_before, parent_after)
        ):
            raise ValueError("atomic write後のfileまたはdirectory identityが一致しません")
    finally:
        try:
            remaining = temporary.lstat()
        except OSError:
            remaining = None
        if (
            remaining is not None
            and temporary_identity is not None
            and not _stat_is_reparse(remaining)
            and stat.S_ISREG(remaining.st_mode)
            and _same_path_identity(temporary_identity, remaining)
        ):
            try:
                temporary.unlink()
            except OSError:
                pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _disk_usage_anchor(path: Path) -> Path:
    """未作成pathを含め、disk usageを照会できる最寄りの親directoryを返す。"""

    candidate = Path(os.path.abspath(os.fspath(path)))
    ensure_no_reparse_components(candidate)
    while True:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            metadata = None
        except OSError as exc:
            raise OSError("disk usage照会先を安全に確認できません") from exc
        if metadata is not None:
            break
        parent = candidate.parent
        if parent == candidate:
            raise OSError("disk usageを照会できる既存directoryがありません")
        candidate = parent
    ensure_no_reparse_components(candidate)
    if _stat_is_reparse(metadata):
        raise OSError("disk usage照会先にreparse pointは使用できません")
    if stat.S_ISREG(metadata.st_mode):
        candidate = candidate.parent
        ensure_no_reparse_components(candidate)
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise OSError("disk usage照会先の親directoryを確認できません") from exc
    if _stat_is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError("disk usage照会先がdirectoryではありません")
    return candidate


def _stat_is_reparse(metadata: os.stat_result) -> bool:
    """stat metadataがWindows reparse pointを表すか返す。"""

    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & reparse_flag)


def _same_path_identity(first: os.stat_result, second: os.stat_result) -> bool:
    """disk usage照会前後のdirectory identityが同一か確認する。"""

    if int(first.st_ino) == 0 or int(second.st_ino) == 0:
        return False
    try:
        return os.path.samestat(first, second)
    except (AttributeError, OSError):
        return (
            int(first.st_dev),
            int(first.st_ino),
        ) == (
            int(second.st_dev),
            int(second.st_ino),
        )


def _filesystem_key(anchor: Path, metadata: os.stat_result) -> tuple[int, str]:
    """同一filesystemをpath非公開でdeduplicateする内部keyを返す。"""

    volume_anchor = os.path.normcase(os.path.normpath(os.fspath(Path(anchor.anchor))))
    return int(metadata.st_dev), volume_anchor


def _observe_filesystem(anchor: Path) -> tuple[tuple[int, str], int]:
    """reparse／identity変更を拒否してfilesystemの空き容量を1回取得する。"""

    ensure_no_reparse_components(anchor)
    try:
        before = anchor.lstat()
    except OSError as exc:
        raise OSError("disk usage照会先を確認できません") from exc
    if _stat_is_reparse(before) or not stat.S_ISDIR(before.st_mode):
        raise OSError("disk usage照会先は通常directoryに限定します")
    free_bytes = int(shutil.disk_usage(anchor).free)
    ensure_no_reparse_components(anchor)
    try:
        after = anchor.lstat()
    except OSError as exc:
        raise OSError("disk usage照会後のdirectoryを確認できません") from exc
    if (
        _stat_is_reparse(after)
        or not stat.S_ISDIR(after.st_mode)
        or not _same_path_identity(before, after)
        or int(before.st_dev) != int(after.st_dev)
    ):
        raise OSError("disk usage照会中にdirectory identityが変更されました")
    return _filesystem_key(anchor, after), free_bytes


def _storage_budget_observation(
    paths: Iterable[tuple[str, Path]],
    *,
    minimum_free_bytes: int,
    phase: str,
) -> dict[str, Any]:
    """書込み先ごとの空き容量をpath非公開の機械可読記録へまとめる。"""

    observations: list[dict[str, Any]] = []
    by_filesystem: dict[tuple[int, str], dict[str, Any]] = {}
    for role, path in paths:
        try:
            filesystem_key, free_bytes = _observe_filesystem(_disk_usage_anchor(path))
        except (OSError, ValueError):
            observations.append(
                {
                    "filesystem_id": f"filesystem_{len(observations) + 1}",
                    "roles": [role],
                    "free_bytes": None,
                    "sufficient": False,
                    "error": "disk_usage_unavailable",
                }
            )
            continue
        existing = by_filesystem.get(filesystem_key)
        if existing is not None:
            existing["roles"].append(role)
            continue
        observation = {
            "filesystem_id": f"filesystem_{len(observations) + 1}",
            "roles": [role],
            "free_bytes": free_bytes,
            "sufficient": free_bytes >= minimum_free_bytes,
            "error": None,
        }
        by_filesystem[filesystem_key] = observation
        observations.append(observation)
    return {
        "phase": phase,
        "minimum_free_bytes": minimum_free_bytes,
        "sufficient": bool(observations) and all(item["sufficient"] is True for item in observations),
        "filesystems": observations,
    }


def _apply_planned_write_reserve(
    observation: Mapping[str, Any],
    *,
    role: str,
    planned_write_bytes: int,
) -> dict[str, Any]:
    """予定write後もreserveを維持できるかpath非公開の容量記録へ反映する。"""

    if type(planned_write_bytes) is not int or planned_write_bytes < 0:
        raise ValueError("予定write byte数が不正です")
    minimum_free_bytes = observation.get("minimum_free_bytes")
    if type(minimum_free_bytes) is not int or minimum_free_bytes < 0:
        raise ValueError("容量記録のminimum free byte数が不正です")
    raw_filesystems = observation.get("filesystems")
    if not isinstance(raw_filesystems, list):
        raise TypeError("容量記録のfilesystem一覧が不正です")
    filesystems: list[dict[str, Any]] = []
    matching_filesystems = 0
    planned_write_sufficient = False
    for raw in raw_filesystems:
        if not isinstance(raw, Mapping):
            raise TypeError("容量記録に非object filesystemがあります")
        item = dict(raw)
        roles = item.get("roles")
        if isinstance(roles, list) and role in roles:
            matching_filesystems += 1
            free_bytes = item.get("free_bytes")
            planned_write_sufficient = bool(
                type(free_bytes) is int
                and free_bytes - planned_write_bytes >= minimum_free_bytes
                and item.get("error") is None
            )
            item["planned_write_bytes"] = planned_write_bytes
            item["planned_write_sufficient"] = planned_write_sufficient
        filesystems.append(item)
    if matching_filesystems != 1:
        planned_write_sufficient = False
    output = dict(observation)
    output["filesystems"] = filesystems
    output["planned_write_role"] = role
    output["planned_write_bytes"] = planned_write_bytes
    output["planned_write_sufficient"] = planned_write_sufficient
    output["sufficient"] = bool(observation.get("sufficient") is True and planned_write_sufficient)
    return output


class _InputPreparationStopped(RuntimeError):
    """容量reserveを守るため入力準備をcheckpoint付きで中断したことを示す。"""

    def __init__(self, progress: Mapping[str, Any]) -> None:
        super().__init__("入力準備中に容量reserveへ到達しました")
        self.progress = dict(progress)


def _write_run_progress(private_output: Path, progress: Mapping[str, Any]) -> None:
    """再開用進捗を同一directory内の一時fileからatomicに保存する。"""

    _atomic_replace_bytes(
        private_output / "run-progress.json",
        _json_bytes(dict(progress)),
    )


def _validate_resume_inventory(
    private_output: Path,
    *,
    collection_id: str,
    unique_pe_programs: int,
    expected_sha256: str | None,
) -> _JsonFileSnapshot:
    """自動再開前にprepared input inventoryのbindingとPE件数を検証する。"""

    path = private_output / "input-relationships.json"
    snapshot = _bounded_json_snapshot(path)
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or SHA256_RE.fullmatch(expected_sha256) is None
        or snapshot.sha256 != expected_sha256
    ):
        raise ValueError("prepared input inventoryのbinding SHA-256が一致しません")
    document = snapshot.document
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("prepared input inventoryのschema versionが一致しません")
    if document.get("collection_id") != collection_id:
        raise ValueError("prepared input inventoryのcollection IDが一致しません")
    if document.get("sample_executed") is not False:
        raise ValueError("prepared input inventoryの非実行安全値が一致しません")
    if document.get("network_contacted") is not False:
        raise ValueError("prepared input inventoryの非接続安全値が一致しません")
    relationships = document.get("relationships")
    if not isinstance(relationships, list) or not relationships:
        raise ValueError("prepared input inventoryのrelationship一覧が不正です")
    pe_digests: set[str] = set()
    for relation in relationships:
        if not isinstance(relation, Mapping):
            raise ValueError("prepared input inventoryに非object relationshipがあります")
        digest = relation.get("layer_sha256")
        is_pe = relation.get("is_pe")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError("prepared input inventoryのlayer SHA-256が不正です")
        if type(is_pe) is not bool:
            raise ValueError("prepared input inventoryのPE判定が不正です")
        if is_pe:
            pe_digests.add(digest)
    recorded_count = document.get("unique_pe_objects")
    if type(recorded_count) is not int or recorded_count != unique_pe_programs or len(pe_digests) != unique_pe_programs:
        raise ValueError("prepared input inventoryのPE program数が一致しません")
    _assert_snapshot_unchanged(
        snapshot,
        context="prepared input inventory検証後",
    )
    return snapshot


def _run_progress_document(
    *,
    collection_id: str,
    status: str,
    stop_reason: str | None,
    retryable: bool,
    inventory_prepared: bool,
    prepared_inventory_sha256: str | None,
    unique_pe_programs: int | None,
    complete_programs: int,
    cached_programs: int,
    newly_analyzed_programs: int,
    pending_programs: Iterable[str],
    postprocessing_pending: bool,
    prepared_inputs_reused: bool,
    resume_mode: str,
    disk_space: Mapping[str, Any],
) -> dict[str, Any]:
    """全停止段階でfield集合が同じrun-progress文書を構築する。"""

    pending = list(pending_programs)
    if any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in pending):
        raise ValueError("run-progressのpending SHA-256が不正です")
    if len(set(pending)) != len(pending):
        raise ValueError("run-progressのpending SHA-256が重複しています")
    if not isinstance(collection_id, str) or not collection_id:
        raise ValueError("run-progressのcollection IDが不正です")
    if not isinstance(resume_mode, str) or resume_mode not in {"fresh", "prepared_inputs", "postprocessing_only"}:
        raise ValueError("run-progressのresume modeが不正です")
    if not isinstance(status, str) or status not in {"ghidra_chunk_pending", "complete"}:
        raise ValueError("run-progressのstatusが不正です")
    if not isinstance(disk_space, Mapping):
        raise ValueError("run-progressのdisk space記録が不正です")
    if type(retryable) is not bool or type(inventory_prepared) is not bool:
        raise ValueError("run-progressのboolean fieldが不正です")
    if type(postprocessing_pending) is not bool or type(prepared_inputs_reused) is not bool:
        raise ValueError("run-progressの再開boolean fieldが不正です")
    counts = (
        complete_programs,
        cached_programs,
        newly_analyzed_programs,
    )
    if any(type(value) is not int or value < 0 for value in counts):
        raise ValueError("run-progressのprogram countが不正です")
    if inventory_prepared:
        if not isinstance(prepared_inventory_sha256, str) or SHA256_RE.fullmatch(prepared_inventory_sha256) is None:
            raise ValueError("run-progressのprepared inventory SHA-256が不正です")
        if type(unique_pe_programs) is not int or unique_pe_programs <= 0:
            raise ValueError("run-progressのprogram総数が不正です")
        if complete_programs > unique_pe_programs:
            raise ValueError("run-progressの完了program数が総数を超えています")
    elif unique_pe_programs is not None or prepared_inventory_sha256 is not None:
        raise ValueError("未準備inventoryへprogram総数またはbindingを記録できません")
    if cached_programs + newly_analyzed_programs != complete_programs:
        raise ValueError("run-progressの完了program内訳が一致しません")
    if postprocessing_pending and pending:
        raise ValueError("後処理待ちと未解析programを同時に記録できません")
    if postprocessing_pending and resume_mode != "postprocessing_only":
        raise ValueError("後処理待ちのresume modeが一致しません")
    if not inventory_prepared and (unique_pe_programs is not None or pending or postprocessing_pending):
        raise ValueError("未準備inventoryへprogram進捗を記録できません")
    if inventory_prepared and complete_programs + len(pending) != unique_pe_programs:
        raise ValueError("run-progressの完了・pending program数が総数と一致しません")
    if status == "complete" and (retryable or stop_reason is not None or pending or postprocessing_pending):
        raise ValueError("complete run-progressに未完了状態があります")
    if status == "ghidra_chunk_pending" and (
        not retryable
        or not isinstance(stop_reason, str)
        or stop_reason
        not in {
            "minimum_free_space_not_met",
            "max_new_programs_reached",
            "postprocessing_in_progress",
            "program_timeout",
        }
    ):
        raise ValueError("pending run-progressの停止理由が不正です")
    if stop_reason == "program_timeout" and (not inventory_prepared or not pending or postprocessing_pending):
        raise ValueError("program timeoutには未完了programのcheckpointが必要です")
    return {
        "schema_version": RUN_PROGRESS_SCHEMA_VERSION,
        "collection_id": collection_id,
        "status": status,
        "stop_reason": stop_reason,
        "retryable": retryable,
        "inventory_prepared": inventory_prepared,
        "prepared_inventory_sha256": prepared_inventory_sha256,
        "unique_pe_programs": unique_pe_programs,
        "complete_programs": complete_programs,
        "cached_programs": cached_programs,
        "newly_analyzed_programs": newly_analyzed_programs,
        "pending_programs": pending,
        "postprocessing_pending": postprocessing_pending,
        "prepared_inputs_reused": prepared_inputs_reused,
        "resume_mode": resume_mode,
        "disk_space": dict(disk_space),
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "arbitrary_ghidra_scripts_enabled": False,
            "mcp_localhost_only": True,
        },
    }


def _load_resume_checkpoint(
    private_output: Path,
    *,
    collection_id: str,
) -> dict[str, Any] | None:
    """厳格なpending checkpointだけを自動再開の根拠として読む。"""

    path = private_output / "run-progress.json"
    try:
        present = path.is_file()
    except OSError as exc:
        raise ValueError("run-progressの存在を安全に確認できません") from exc
    if not present:
        return None
    checkpoint_snapshot = _bounded_json_snapshot(path)
    document = checkpoint_snapshot.document
    if document.get("schema_version") == LEGACY_RUN_PROGRESS_SCHEMA_VERSION:
        legacy_keys = {
            "schema_version",
            "collection_id",
            "status",
            "unique_pe_programs",
            "complete_programs",
            "cached_programs",
            "newly_analyzed_programs",
            "pending_programs",
            "prepared_inputs_reused",
            "safety",
        }
        if set(document) != legacy_keys:
            raise ValueError("legacy run-progressのfield集合が一致しません")
        if document.get("collection_id") != collection_id:
            raise ValueError("legacy run-progressのcollection IDが一致しません")
        if document.get("status") != "ghidra_chunk_pending":
            raise ValueError("legacy run-progressのstatusが不正です")
        expected_safety = {
            "sample_executed": False,
            "network_contacted": False,
            "arbitrary_ghidra_scripts_enabled": False,
            "mcp_localhost_only": True,
        }
        if document.get("safety") != expected_safety:
            raise ValueError("legacy run-progressの固定安全値が一致しません")
        pending = document.get("pending_programs")
        if not isinstance(pending, list) or not pending:
            raise ValueError("legacy run-progressのpending program一覧が不正です")
        try:
            inventory_snapshot = _validate_resume_inventory(
                private_output,
                collection_id=collection_id,
                unique_pe_programs=document["unique_pe_programs"],
                expected_sha256=None,
            )
            normalized_legacy = _run_progress_document(
                collection_id=collection_id,
                status="ghidra_chunk_pending",
                stop_reason="max_new_programs_reached",
                retryable=True,
                inventory_prepared=True,
                prepared_inventory_sha256=inventory_snapshot.sha256,
                unique_pe_programs=document["unique_pe_programs"],
                complete_programs=document["complete_programs"],
                cached_programs=document["cached_programs"],
                newly_analyzed_programs=document["newly_analyzed_programs"],
                pending_programs=pending,
                postprocessing_pending=False,
                prepared_inputs_reused=document["prepared_inputs_reused"],
                resume_mode="prepared_inputs",
                disk_space={
                    "phase": "legacy_checkpoint",
                    "minimum_free_bytes": None,
                    "sufficient": None,
                    "filesystems": [],
                },
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("legacy run-progressの再開契約が不正です") from exc
        _assert_snapshot_unchanged(
            checkpoint_snapshot,
            context="legacy run-progress検証後",
        )
        return normalized_legacy
    if document.get("schema_version") != RUN_PROGRESS_SCHEMA_VERSION:
        raise ValueError("run-progressのschema versionが一致しません")
    if document.get("collection_id") != collection_id:
        raise ValueError("run-progressのcollection IDが一致しません")
    status = document.get("status")
    if status not in {"ghidra_chunk_pending", "complete"}:
        raise ValueError("run-progressのstatusが不正です")
    inventory_prepared = document.get("inventory_prepared")
    postprocessing_pending = document.get("postprocessing_pending")
    if type(inventory_prepared) is not bool or type(postprocessing_pending) is not bool:
        raise ValueError("run-progressの再開状態が不正です")
    unique_pe_programs = document.get("unique_pe_programs")
    if inventory_prepared:
        if type(unique_pe_programs) is not int or unique_pe_programs <= 0:
            raise ValueError("run-progressのprogram総数が不正です")
    elif unique_pe_programs is not None:
        raise ValueError("未準備run-progressにprogram総数があります")
    pending = document.get("pending_programs")
    if (
        not isinstance(pending, list)
        or any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in pending)
        or len(set(pending)) != len(pending)
    ):
        raise ValueError("run-progressのpending program一覧が不正です")
    if postprocessing_pending and (not inventory_prepared or pending):
        raise ValueError("run-progressの後処理待ち状態が不正です")
    for field_name in (
        "complete_programs",
        "cached_programs",
        "newly_analyzed_programs",
    ):
        value = document.get(field_name)
        if type(value) is not int or value < 0:
            raise ValueError(f"run-progressの{field_name}が不正です")
    if not isinstance(document.get("disk_space"), Mapping):
        raise ValueError("run-progressのdisk_spaceが不正です")
    try:
        normalized = _run_progress_document(
            collection_id=collection_id,
            status=status,
            stop_reason=document.get("stop_reason"),
            retryable=document.get("retryable"),
            inventory_prepared=inventory_prepared,
            prepared_inventory_sha256=document.get("prepared_inventory_sha256"),
            unique_pe_programs=unique_pe_programs,
            complete_programs=document["complete_programs"],
            cached_programs=document["cached_programs"],
            newly_analyzed_programs=document["newly_analyzed_programs"],
            pending_programs=pending,
            postprocessing_pending=postprocessing_pending,
            prepared_inputs_reused=document.get("prepared_inputs_reused"),
            resume_mode=document.get("resume_mode"),
            disk_space=document["disk_space"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("run-progressの再開契約が不正です") from exc
    if document != normalized:
        raise ValueError("run-progressのfield集合または固定安全値が一致しません")
    if status == "complete":
        _assert_snapshot_unchanged(
            checkpoint_snapshot,
            context="complete run-progress検証後",
        )
        return None
    if inventory_prepared:
        _validate_resume_inventory(
            private_output,
            collection_id=collection_id,
            unique_pe_programs=normalized["unique_pe_programs"],
            expected_sha256=normalized["prepared_inventory_sha256"],
        )
    _assert_snapshot_unchanged(
        checkpoint_snapshot,
        context="run-progress検証後",
    )
    return document


def _storage_guard_paths(
    args: argparse.Namespace,
    repository: Path,
    sample_root: Path,
    private_output: Path,
    prepared_input_root: Path | None = None,
) -> list[tuple[str, Path]]:
    """全書込み先を空き容量監視対象へ固定する。"""

    paths = [
        ("repository", repository),
        ("sample_root", sample_root),
        ("private_output", private_output),
    ]
    if prepared_input_root is not None and prepared_input_root != sample_root:
        paths.append(("prepared_input_root", prepared_input_root))
    for index, raw_path in enumerate(args.disk_guard_path, start=1):
        path = Path(os.path.abspath(os.fspath(raw_path)))
        ensure_no_reparse_components(path)
        if not path.is_dir():
            raise FileNotFoundError(f"追加disk guard pathがdirectoryではありません: {raw_path}")
        paths.append((f"additional_{index}", path))
    return paths


def _same_or_nested(path: Path, root: Path) -> bool:
    """pathがroot自身またはその配下か返す。"""

    return path == root or root in path.parents


def _require_existing_regular_directory(path: Path, *, role: str) -> None:
    """既存run rootがreparseでない通常directoryか確認する。"""

    ensure_no_reparse_components(path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FileNotFoundError(f"{role} directoryが見つかりません") from exc
    if _stat_is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{role}は通常directoryに限定します")


def _validate_run_roots(
    repository: Path,
    collection_dir: Path,
    sample_root: Path,
    private_output: Path,
    prepared_input_root: Path | None = None,
) -> None:
    """collectionだけをrepository内に許し、全write rootの包含を拒否する。"""

    _require_existing_regular_directory(repository, role="repository")
    _require_existing_regular_directory(collection_dir, role="collection")
    _require_existing_regular_directory(sample_root, role="sample root")
    if prepared_input_root is not None and prepared_input_root != sample_root:
        _require_existing_regular_directory(
            prepared_input_root,
            role="prepared input root",
        )
    try:
        private_exists = private_output.exists()
    except OSError as exc:
        raise ValueError("private outputの存在を安全に確認できません") from exc
    if private_exists:
        _require_existing_regular_directory(private_output, role="private output")
    if collection_dir == repository or repository not in collection_dir.parents:
        raise ValueError("collectionはrepository内の通常directoryに限定します")

    roots = {
        "repository": repository,
        "collection": collection_dir,
        "sample root": sample_root,
        "private output": private_output,
    }
    if prepared_input_root is not None and prepared_input_root != sample_root:
        roots["prepared input root"] = prepared_input_root
    names = list(roots)
    for index, first_name in enumerate(names):
        for second_name in names[index + 1 :]:
            if {first_name, second_name} == {"repository", "collection"}:
                continue
            first = roots[first_name]
            second = roots[second_name]
            if _same_or_nested(first, second) or _same_or_nested(second, first):
                raise ValueError(f"{first_name}と{second_name}は相互に包含しないdirectoryへ分離してください")


def _resolve_without_reparse(path: Path) -> Path:
    """resolve前後の既存componentにreparse pointがない絶対pathを返す。"""

    lexical = Path(os.path.abspath(os.fspath(path)))
    ensure_no_reparse_components(lexical)
    resolved = lexical.resolve(strict=False)
    ensure_no_reparse_components(resolved)
    return resolved


def _manifest_archive_path(sample_root: Path, value: Any) -> Path:
    """manifestのarchive pathをsample root直下の通常fileへ限定する。"""

    if not isinstance(value, str) or not value or len(value) > 32_768 or "\x00" in value:
        raise ValueError("acquisition manifestのzip_pathが不正です")
    raw = Path(value)
    if any(part == ".." for part in raw.parts):
        raise ValueError("acquisition manifestのzip_pathに親directory参照は使用できません")
    root = _resolve_without_reparse(sample_root)
    _require_existing_regular_directory(root, role="sample root")
    candidate = raw if raw.is_absolute() else root / raw
    lexical = Path(os.path.abspath(os.fspath(candidate)))
    try:
        lexical.relative_to(root)
    except ValueError as exc:
        raise ValueError("acquisition manifestのzip_pathがsample root外を指しています") from exc
    resolved = _resolve_without_reparse(lexical)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("acquisition manifestのzip_pathがsample root外へ解決されました") from exc
    _regular_file_metadata(resolved)
    return resolved


def _archive_manifest_index(
    sample_root: Path,
    document: Mapping[str, Any],
) -> dict[str, _ArchiveManifestEntry]:
    """acquisition manifestを重複のないroot-contained archive索引へ変換する。"""

    raw_items = document.get("items")
    if not isinstance(raw_items, list):
        raise ValueError("acquisition manifestのitemsがlistではありません")
    output: dict[str, _ArchiveManifestEntry] = {}
    observed_paths: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, Mapping):
            raise ValueError(f"acquisition manifestのitemがobjectではありません: {index}")
        digest = raw_item.get("sha256")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"acquisition manifestのSHA-256が不正です: {index}")
        if digest in output:
            raise ValueError(f"acquisition manifestのSHA-256が重複しています: {digest}")
        archive = _manifest_archive_path(sample_root, raw_item.get("zip_path"))
        path_key = os.path.normcase(os.path.normpath(os.fspath(archive)))
        if path_key in observed_paths:
            raise ValueError("acquisition manifestで同一archive pathが重複しています")
        observed_paths.add(path_key)

        expected_zip_sha256 = raw_item.get("zip_sha256")
        if expected_zip_sha256 is not None and (
            not isinstance(expected_zip_sha256, str) or SHA256_RE.fullmatch(expected_zip_sha256) is None
        ):
            raise ValueError(f"acquisition manifestのZIP SHA-256が不正です: {digest}")
        expected_zip_size = raw_item.get("zip_size")
        if expected_zip_size is not None and (
            type(expected_zip_size) is not int or expected_zip_size <= 0 or expected_zip_size > MAX_PREPARED_INPUT_BYTES
        ):
            raise ValueError(f"acquisition manifestのZIP sizeが不正です: {digest}")
        output[digest] = _ArchiveManifestEntry(
            sha256=digest,
            path=archive,
            expected_zip_sha256=expected_zip_sha256,
            expected_zip_size=expected_zip_size,
        )
    return output


def _read_manifest_archive(
    entry: _ArchiveManifestEntry,
) -> tuple[Any, _RegularFileSnapshot]:
    """archiveを単一handle snapshot化し、同じbytesだけを既存readerへ渡す。"""

    archive_data, snapshot = _bounded_regular_file_snapshot(
        entry.path,
        max_bytes=MAX_PREPARED_INPUT_BYTES,
    )
    if entry.expected_zip_sha256 is not None and snapshot.sha256 != entry.expected_zip_sha256:
        raise ValueError(f"acquisition manifestのZIP SHA-256が一致しません: {entry.sha256}")
    if entry.expected_zip_size is not None and snapshot.size != entry.expected_zip_size:
        raise ValueError(f"acquisition manifestのZIP sizeが一致しません: {entry.sha256}")
    unit = read_input_unit(
        _SnapshotInputPath(name=entry.path.name, data=archive_data),  # type: ignore[arg-type]
        password="infected",
        archive_mode="malwarebazaar",
        max_file_size=MAX_PREPARED_INPUT_BYTES,
    )
    if getattr(unit, "outer_sha256", None) != snapshot.sha256 or getattr(unit, "outer_size", None) != snapshot.size:
        raise ValueError(f"archive snapshotと入力readerのouter identityが一致しません: {entry.sha256}")
    _assert_regular_snapshot_unchanged(
        snapshot,
        context="archive snapshot読取後",
    )
    return unit, snapshot


def _immutable_staging_snapshot(
    private_output: Path,
    digest: str,
    data: bytes,
) -> _RegularFileSnapshot:
    """検証済みbytesをprivate rootのO_EXCL staging fileへ一度だけ固定する。"""

    if SHA256_RE.fullmatch(digest) is None or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Ghidra staging dataのSHA-256が一致しません")
    root = Path(os.path.abspath(os.fspath(private_output)))
    ensure_no_reparse_components(root)
    staging = root / "import-staging" / f"{digest}.quarantine.bin"
    if not _same_or_nested(staging, root):
        raise ValueError("Ghidra staging pathがprivate output外です")
    staging.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(staging.parent)
    try:
        existing = staging.lstat()
    except FileNotFoundError:
        existing = None
    if existing is None:
        with staging.open("xb") as handle:
            opened = os.fstat(handle.fileno())
            if _stat_is_reparse(opened) or not stat.S_ISREG(opened.st_mode):
                raise ValueError("Ghidra staging作成先が通常fileではありません")
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    try:
        _, snapshot = _bounded_regular_file_snapshot(
            staging,
            max_bytes=len(data),
        )
    except ValueError as exc:
        raise ValueError("既存Ghidra staging fileのSHA-256が一致しません") from exc
    if snapshot.sha256 != digest or snapshot.size != len(data):
        raise ValueError("既存Ghidra staging fileのSHA-256が一致しません（size不一致を含む）")
    return snapshot


@contextmanager
def _hold_staging_read_lock(snapshot: _RegularFileSnapshot) -> Iterable[None]:
    """import中のstagingをWindowsではdeny-write/delete、他OSではopen固定する。"""

    descriptor: int | None = None
    if os.name == "nt":
        import ctypes
        import msvcrt

        create_file = ctypes.windll.kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            str(snapshot.path),
            0x80000000,
            0x00000001,
            None,
            3,
            0x00000080,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            raise ValueError("Ghidra staging deny-write handleを取得できません")
        descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY)
    else:
        flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(snapshot.path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or int(opened.st_nlink) != 1:
            raise ValueError("Ghidra staging lockは単一linkの通常fileに限定します")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > snapshot.size:
                raise ValueError("Ghidra staging lockのsizeが一致しません")
            digest.update(chunk)
        if total != snapshot.size or digest.hexdigest() != snapshot.sha256:
            raise ValueError("Ghidra staging lockのSHA-256またはsizeが一致しません")
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _safe_project_path(value: str) -> str:
    """Ghidra project pathを絶対pathへ正規化する。"""

    rendered = "/" + value.replace("\\", "/").strip("/")
    if ".." in rendered.split("/"):
        raise ValueError("Ghidra project pathに親directory参照は使用できません")
    return rendered


def _is_numeric_loopback(hostname: str | None) -> bool:
    """DNS解決を伴わないnumeric loopback literalだけを許可する。"""

    if not hostname or "%" in hostname:
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return address.is_loopback


class _RejectMcpRedirectHandler(HTTPRedirectHandler):
    """Ghidra MCPの全redirectをdestination request作成前に拒否する。"""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, msg, headers, newurl
        raise GhidraMcpError(f"Ghidra MCP redirectを拒否しました: HTTP {code}")


def _build_ghidra_mcp_opener() -> OpenerDirector:
    """環境proxyと自動redirectを無効にした専用openerを作る。"""

    return build_opener(
        ProxyHandler({}),
        _RejectMcpRedirectHandler(),
    )


class GhidraMcpClient:
    """numeric loopback限定Ghidra MCP HTTP client。"""

    def __init__(self, base_url: str, *, timeout: int = 180) -> None:
        parsed = urlparse(base_url)
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("Ghidra MCP URLのportが不正です") from exc
        if parsed.scheme != "http" or not _is_numeric_loopback(parsed.hostname):
            raise ValueError("Ghidra MCP URLはnumeric loopbackのHTTP endpointに限定します")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Ghidra MCP URLへ資格情報、query、fragmentは指定できません")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = _build_ghidra_mcp_opener()

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        url = self.base_url + path
        clean_query = {key: value for key, value in (query or {}).items() if value is not None}
        if clean_query:
            url += "?" + urlencode(clean_query)
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(url, data=data, headers=headers, method=method)
        try:
            effective_timeout = self.timeout if timeout is None else timeout
            with self._opener.open(request, timeout=effective_timeout) as response:
                raw = response.read(MAX_MCP_RESPONSE_BYTES + 1)
        except HTTPError as error:
            detail = error.read(1001).decode("utf-8", errors="replace")
            raise GhidraMcpError(f"{method} {path} failed: HTTP {error.code}: {detail[:1000]}") from error
        except GhidraMcpError:
            raise
        except (OSError, URLError) as error:
            raise GhidraMcpError(f"{method} {path} failed: {type(error).__name__}") from error
        if len(raw) > MAX_MCP_RESPONSE_BYTES:
            raise GhidraMcpError(f"{method} {path} failed: MCP responseがbytes上限を超えています")
        if not raw:
            return None
        text = raw.decode("utf-8", errors="replace")
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return text
        if isinstance(value, Mapping) and value.get("error"):
            raise GhidraMcpError(f"{method} {path} returned an MCP error object")
        return value

    def get(self, endpoint: str, *, transport_timeout: float | None = None, **query: Any) -> Any:
        return self._request("GET", endpoint, query=query, body=None, timeout=transport_timeout)

    def post(
        self,
        endpoint: str,
        body: Mapping[str, Any],
        **query: Any,
    ) -> Any:
        return self._request("POST", endpoint, query=query, body=body)


@dataclass
class ProgramObject:
    """1つのunique PE layerとcaseへの関係を保持する。"""

    sha256: str
    input_path: Path
    size: int
    relationships: list[dict[str, Any]] = field(default_factory=list)
    input_snapshot: _RegularFileSnapshot | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    @property
    def primary(self) -> dict[str, Any]:
        return sorted(
            self.relationships,
            key=lambda item: (int(item["depth"]), item["case_sha256"], item["transform"]),
        )[0]


def _case_index(repository: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    root = repository / "analysis-results" / "malware"
    for path in root.glob("*/versions/*/cases/*"):
        if path.is_dir() and SHA256_RE.fullmatch(path.name.casefold()):
            index[path.name.casefold()] = path
    return index


def _is_pe(data: bytes) -> bool:
    if not data.startswith(b"MZ"):
        return False
    try:
        pefile.PE(data=data, fast_load=True)
    except Exception:
        return False
    return True


def _is_managed_pe(data: bytes) -> bool:
    """PEのCLI header directoryからmanaged PEかを軽量判定する。"""

    if not data.startswith(b"MZ"):
        return False
    pe: pefile.PE | None = None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        if index >= len(directories):
            return False
        descriptor = directories[index]
        return bool(int(getattr(descriptor, "VirtualAddress", 0) or 0) and int(getattr(descriptor, "Size", 0) or 0))
    except Exception:
        return False
    finally:
        if pe is not None:
            pe.close()


def _raw_pe_import_parameters(data: bytes) -> dict[str, str] | None:
    """標準loaderで読めないx86 PE向けのraw import指定を返す。"""

    if not data.startswith(b"MZ"):
        return None
    pe: pefile.PE | None = None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        language = {
            0x014C: "x86:LE:32:default",
            0x8664: "x86:LE:64:default",
        }.get(int(pe.FILE_HEADER.Machine))
        if language is None:
            return None
        return {"language": language, "compiler_spec": "windows"}
    except Exception:
        return None
    finally:
        if pe is not None:
            pe.close()


def _normalize_static_tool(value: Path | None, label: str) -> Path | None:
    """明示指定した外部静的toolを実在する通常fileへ限定する。"""

    if value is None:
        return None
    try:
        resolved = value.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label}が見つかりません: {value}") from exc
    if not resolved.is_file():
        raise ValueError(f"{label}は通常fileで指定してください: {value}")
    return resolved


def _static_tool_identity(path: Path | None) -> dict[str, Any] | None:
    """外部静的toolのpathを公開せず、名前・size・内容hashを返す。"""

    if path is None:
        return None
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
            size += len(chunk)
    return {
        "name": path.name,
        "size": size,
        "sha256": hasher.hexdigest(),
    }


def _validate_static_tool_contract(
    case_dir: Path,
    actual: Mapping[str, dict[str, Any] | None],
) -> None:
    """layer再現へ使う外部toolが公開解析契約と同一であることを確認する。"""

    report = load_json_object_strict(case_dir / "report.json")
    contract = report.get("analysis_contract")
    settings = contract.get("settings") if isinstance(contract, Mapping) else None
    expected = settings.get("static_tools") if isinstance(settings, Mapping) else None
    if not isinstance(expected, Mapping):
        raise ValueError(f"公開解析契約にstatic_toolsがありません: {case_dir.name}")
    mismatched = [name for name in ("upx", "sevenzip", "diec") if expected.get(name) != actual.get(name)]
    if mismatched:
        raise ValueError(f"外部静的tool設定が公開解析契約と一致しません: {case_dir.name}: {','.join(mismatched)}")


def _load_authenticated_public_layers(
    case_dir: Path,
) -> tuple[list[dict[str, Any]], set[tuple[str, int, int, str]]]:
    """reportと成果物のsealを検証し、公開layer集合を厳密に読み込む。"""

    report = load_json_object_strict(case_dir / "report.json")
    semantic_errors = verify_report_semantics(report)
    if semantic_errors:
        raise ValueError(f"公開report sealを検証できません: {case_dir.name}: {semantic_errors}")
    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, Mapping):
        raise ValueError(f"公開成果物hash manifestがありません: {case_dir.name}")
    sealed_digest = manifest.get("static-layers.json")
    if not isinstance(sealed_digest, str) or SHA256_RE.fullmatch(sealed_digest) is None:
        raise ValueError(f"static-layers.jsonのsealが不正です: {case_dir.name}")
    seal_errors = verify_artifact_hashes(
        case_dir,
        {"static-layers.json": sealed_digest},
    )
    if seal_errors:
        raise ValueError(f"static-layers.jsonのsealを検証できません: {case_dir.name}: {seal_errors}")
    document = load_json_object_strict(resolve_case_artifact(case_dir, "static-layers.json"))
    raw_layers = document.get("layers")
    if not isinstance(raw_layers, list) or not raw_layers:
        raise ValueError(f"公開静的layer一覧が不正です: {case_dir.name}")

    layers: list[dict[str, Any]] = []
    identities: list[tuple[str, int, int, str]] = []
    for index, raw in enumerate(raw_layers):
        if not isinstance(raw, Mapping):
            raise ValueError(f"公開静的layerがJSON objectではありません: {case_dir.name}: {index}")
        digest = raw.get("sha256")
        size = raw.get("size")
        depth = raw.get("depth")
        transform = raw.get("transform")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"公開静的layerのSHA-256が不正です: {case_dir.name}: {index}")
        if type(size) is not int or size < 0:
            raise ValueError(f"公開静的layerのsizeが不正です: {case_dir.name}: {index}")
        if type(depth) is not int or depth < 0:
            raise ValueError(f"公開静的layerのdepthが不正です: {case_dir.name}: {index}")
        if not isinstance(transform, str) or not transform:
            raise ValueError(f"公開静的layerのtransformが不正です: {case_dir.name}: {index}")
        layers.append(dict(raw))
        identities.append((digest, size, depth, transform))
    if len(set(identities)) != len(identities):
        raise ValueError(f"公開静的layer一覧に重複があります: {case_dir.name}")
    return layers, set(identities)


def prepare_inputs(
    repository: Path,
    collection_dir: Path,
    sample_root: Path,
    private_output: Path,
    *,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    storage_guard: Callable[[str, str, int], None] | None = None,
    prepared_input_root: Path | None = None,
) -> tuple[dict[str, ProgramObject], dict[str, list[dict[str, Any]]]]:
    """root検体と復元layerを隔離保存し、Ghidra対象をdeduplicateする。"""

    upx = _normalize_static_tool(upx, "UPX")
    sevenzip = _normalize_static_tool(sevenzip, "7-Zip")
    diec = _normalize_static_tool(diec, "Detect It Easy CLI")
    static_tools = {
        "upx": _static_tool_identity(upx),
        "sevenzip": _static_tool_identity(sevenzip),
        "diec": _static_tool_identity(diec),
    }
    collection_snapshot = _bounded_json_snapshot(collection_dir / "manifest.json")
    acquisition_snapshot = _bounded_json_snapshot(sample_root / "manifest.json")
    collection = collection_snapshot.document
    acquisition = acquisition_snapshot.document
    archive_by_sha = _archive_manifest_index(sample_root, acquisition)
    case_paths = _case_index(repository)
    raw_cases = collection.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("collection manifestのcasesがlistではありません")
    requested: list[str] = []
    for index, raw_case in enumerate(raw_cases):
        if not isinstance(raw_case, Mapping):
            raise ValueError(f"collection manifestのcaseがobjectではありません: {index}")
        case_id = raw_case.get("case_id")
        if not isinstance(case_id, str) or not case_id.startswith("sha256:"):
            raise ValueError(f"collection manifestのcase_idが不正です: {index}")
        digest = case_id.removeprefix("sha256:")
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"collection manifestのcase SHA-256が不正です: {index}")
        requested.append(digest)
    if not requested or len(set(requested)) != len(requested):
        raise ValueError("collectionには1件以上の重複しないSHA-256が必要です")
    objects: dict[str, ProgramObject] = {}
    non_pe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    relationships: list[dict[str, Any]] = []
    cache_root = prepared_input_root or sample_root
    cache_storage_role = "prepared_input_root" if cache_root != sample_root else "sample_root"

    for case_number, case_sha in enumerate(requested, start=1):
        archive_entry = archive_by_sha.get(case_sha)
        if archive_entry is None:
            raise FileNotFoundError(f"archiveが見つかりません: {case_sha}")
        case_dir = case_paths.get(case_sha)
        if case_dir is None:
            raise FileNotFoundError(f"公開caseが見つかりません: {case_sha}")
        _validate_static_tool_contract(case_dir, static_tools)
        analysis_report = load_json_object_strict(case_dir / "report.json")
        contract = analysis_report.get("analysis_contract")
        settings = contract.get("settings") if isinstance(contract, Mapping) else None
        if not isinstance(settings, Mapping):
            raise ValueError(f"解析契約settingsがありません: {case_sha}")
        public_layers, expected = _load_authenticated_public_layers(case_dir)
        unit, archive_snapshot = _read_manifest_archive(archive_entry)
        if hashlib.sha256(unit.data).hexdigest() != case_sha:
            raise ValueError(f"root検体hashが一致しません: {case_sha}")
        authenticated_root = (
            case_sha,
            len(unit.data),
            0,
            "submission",
        )
        if len(public_layers) == 1 and expected == {authenticated_root}:
            layers = [
                StaticLayer(
                    name=unit.source_name,
                    data=unit.data,
                    sha256=case_sha,
                    parent_sha256=None,
                    depth=0,
                    transform="submission",
                )
            ]
            reconstruction_mode = "authenticated_root_only"
        else:
            replay_kwargs: dict[str, Any] = {
                "upx": upx,
                "sevenzip": sevenzip,
                "diec": diec,
            }
            if "force_container_probe" in settings:
                replay_kwargs["force_container_probe"] = bool(settings["force_container_probe"])
            if "max_static_layers" in settings:
                replay_kwargs["max_static_layers"] = int(settings["max_static_layers"])
            layers, layer_report = recover_static_layers(unit, **replay_kwargs)
            retry_limit = settings.get("retry_max_static_layers")
            if retry_limit is not None and _layer_count_limit_reached(layer_report):
                replay_kwargs["max_static_layers"] = int(retry_limit)
                layers, _ = recover_static_layers(unit, **replay_kwargs)
                reconstruction_mode = "adaptive_static_layer_replay"
            else:
                reconstruction_mode = "full_static_layer_replay"
        actual = {(layer.sha256, len(layer.data), layer.depth, layer.transform) for layer in layers}
        if expected != actual:
            raise ValueError(f"静的layer再現結果が公開成果物と一致しません: {case_sha}")

        for layer in layers:
            if layer.depth == 0:
                destination = cache_root / case_sha / "ghidra-input" / f"{layer.sha256}.quarantine.bin"
            else:
                destination = cache_root / case_sha / "ghidra-input" / "layers" / f"{layer.sha256}.quarantine.bin"
            try:
                destination.lstat()
                destination_present = True
            except FileNotFoundError:
                destination_present = False
            except OSError as exc:
                raise ValueError("隔離input pathを安全に確認できません") from exc
            planned_write_bytes = 0 if destination_present else len(layer.data)
            if storage_guard is not None:
                storage_guard(
                    "before_input_copy",
                    cache_storage_role,
                    planned_write_bytes,
                )
            if not destination_present:
                _atomic_replace_bytes(
                    destination,
                    layer.data,
                    maximum_bytes=MAX_PREPARED_INPUT_BYTES,
                    require_absent=True,
                )
            cached_data, input_snapshot = _bounded_regular_file_snapshot(
                destination,
                max_bytes=len(layer.data),
            )
            if len(cached_data) != len(layer.data) or input_snapshot.sha256 != layer.sha256:
                raise ValueError(f"既存の隔離input sizeまたはhashが一致しません: {layer.sha256}")
            if storage_guard is not None:
                storage_guard("after_input_copy", cache_storage_role, 0)
            layer_public = layer.public() if callable(getattr(layer, "public", None)) else {}
            relation = {
                "case_sha256": case_sha,
                "layer_sha256": layer.sha256,
                "depth": layer.depth,
                "transform": layer.transform,
                "parent_sha256": layer.parent_sha256,
                "size": len(layer.data),
                "is_pe": _is_pe(layer.data),
                "format": str(layer_public.get("format") or "unknown"),
                "reconstruction_mode": reconstruction_mode,
                "source_archive_sha256": archive_snapshot.sha256,
                "source_archive_size": archive_snapshot.size,
            }
            relationships.append(relation)
            if relation["is_pe"]:
                staging_path = private_output / "import-staging" / f"{layer.sha256}.quarantine.bin"
                try:
                    staging_present = staging_path.lstat() is not None
                except FileNotFoundError:
                    staging_present = False
                except OSError as exc:
                    raise ValueError("Ghidra staging pathを安全に確認できません") from exc
                if storage_guard is not None:
                    storage_guard(
                        "before_ghidra_staging_write",
                        "private_output",
                        0 if staging_present else len(layer.data),
                    )
                staging_snapshot = _immutable_staging_snapshot(
                    private_output,
                    layer.sha256,
                    layer.data,
                )
                if storage_guard is not None:
                    storage_guard("after_ghidra_staging_write", "private_output", 0)
                item = objects.setdefault(
                    layer.sha256,
                    ProgramObject(
                        layer.sha256,
                        staging_snapshot.path,
                        len(layer.data),
                        input_snapshot=staging_snapshot,
                    ),
                )
                item.relationships.append(relation)
            else:
                if relation["format"] == "script":
                    script_records = extract_script_function_records(layer.data, layer.name)
                    for record in script_records:
                        record["function_id"] = f"{layer.sha256}:script:{record['function_id']}"
                        record["source_program_sha256"] = layer.sha256
                        record["analysis_kind"] = "bounded_script_static_parser"
                        record["decompilation_status"] = "succeeded"
                        record["relationship"] = "statically_recovered_script"
                    relation["script_function_records"] = script_records
                non_pe[case_sha].append(relation)
        print(
            json.dumps(
                {
                    "phase": "prepare",
                    "case": case_number,
                    "total": len(requested),
                    "sha256": case_sha,
                    "layers": len(layers),
                    "reconstruction_mode": reconstruction_mode,
                    "executed": False,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )

    inventory_bytes = _json_bytes(
        {
            "schema_version": SCHEMA_VERSION,
            "collection_id": collection_dir.name,
            "relationships": relationships,
            "unique_pe_objects": len(objects),
            "static_tools": static_tools,
            "sample_executed": False,
            "network_contacted": False,
        }
    )
    if storage_guard is not None:
        storage_guard(
            "before_prepared_inventory_write",
            "private_output",
            len(inventory_bytes),
        )
    _atomic_replace_bytes(
        private_output / "input-relationships.json",
        inventory_bytes,
    )
    _assert_snapshot_unchanged(
        collection_snapshot,
        context="collection manifest使用後",
    )
    _assert_snapshot_unchanged(
        acquisition_snapshot,
        context="acquisition manifest使用後",
    )
    return objects, non_pe


def _parse_metadata(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {
            str(key).strip().casefold().replace(" ", "_"): str(rendered).strip()
            for key, rendered in value.items()
            if str(key).strip().casefold().replace(" ", "_") != "executable_path"
        }
    if not isinstance(value, str):
        return {}
    output = {}
    for line in value.splitlines():
        if ":" not in line:
            continue
        key, rendered = line.split(":", 1)
        output[key.strip().casefold().replace(" ", "_")] = rendered.strip()
    output.pop("executable_path", None)
    return output


def _metadata_function_count(value: Any) -> int | None:
    """Ghidra metadataの全関数総数を曖昧な部分一致なしで正規化する。"""

    metadata = _parse_metadata(value)
    rendered = metadata.get("function_count") or metadata.get("functions")
    if rendered is None:
        return None
    normalized = rendered.replace(",", "").strip()
    if re.fullmatch(r"\d+", normalized) is None:
        raise GhidraMcpError("metadataのfunction_countが非負整数ではありません")
    count = int(normalized)
    if count > MAX_FUNCTION_INVENTORY_ITEMS:
        raise GhidraMcpError("metadataのfunction_countが安全なinventory上限を超えました")
    return count


def _bind_function_metadata_coverage(
    evidence: dict[str, Any],
    metadata_value: Any,
    inventory_count: int,
) -> None:
    """異なるGhidra API母集団を明示し、非外部関数inventoryを全関数総数へ拘束する。

    Ghidra 12.1の ``FunctionManager.getFunctionCount()`` は外部関数を含む一方、
    ``getFunctions(boolean)`` は非外部関数だけを列挙する。GhidraMCP 5.14.2の
    metadataと ``list_functions_enhanced`` もそれぞれこのAPIを使うため、外部関数が
    存在すれば両件数は一致しない。終端取得した非外部関数数が全関数総数を超えない
    ことを検証し、差分を外部関数数として明示的に記録する。
    """

    if type(inventory_count) is not int or inventory_count < 0:
        raise GhidraMcpError("非外部関数inventory件数が非負整数ではありません")
    metadata_count = _metadata_function_count(metadata_value)
    evidence["inventory_scope"] = "non_external_functions"
    evidence["metadata_function_count"] = metadata_count
    evidence["metadata_function_count_scope"] = "all_functions_including_external"
    evidence["count_matches_metadata"] = (
        None if metadata_count is None else metadata_count == inventory_count
    )
    if metadata_count is None:
        evidence["derived_external_function_count"] = None
        evidence["documented_limit"] = (
            "metadata_function_count_unavailable_terminal_page_proof_used"
        )
        return
    if metadata_count < inventory_count:
        raise GhidraMcpError(
            "metadata全関数数が非外部関数inventoryを下回っています: "
            f"{metadata_count} < {inventory_count}"
        )
    evidence["derived_external_function_count"] = metadata_count - inventory_count
    if metadata_count > inventory_count:
        evidence["documented_limit"] = (
            "metadata_includes_external_functions_inventory_non_external_only"
        )


def _function_inventory_coverage_complete(result: Mapping[str, Any]) -> bool:
    """program-resultが全native関数の終端取得と件数拘束を持つか返す。"""

    coverage = result.get("retrieval_coverage")
    evidence = coverage.get("functions") if isinstance(coverage, Mapping) else None
    inventory_count = result.get("ghidra_function_inventory_count")
    if result.get("analysis_mode") == "managed_cil_primary_with_ghidra_structure":
        return bool(
            isinstance(evidence, Mapping)
            and evidence.get("complete") is True
            and evidence.get("endpoint") == "/list_functions_enhanced"
            and evidence.get("program_selector") == result.get("program_selector")
            and evidence.get("endpoint_invoked") is False
            and evidence.get("source") == "managed_cil_primary"
            and evidence.get("documented_limit") == "native_function_inventory_not_applicable"
            and evidence.get("item_count") == 0
            and inventory_count == 0
        )
    if (
        not isinstance(evidence, Mapping)
        or evidence.get("complete") is not True
        or evidence.get("terminal_short_page_observed") is not True
        or evidence.get("endpoint") != "/list_functions_enhanced"
        or evidence.get("program_selector") != result.get("program_selector")
        or type(inventory_count) is not int
        or evidence.get("item_count") != inventory_count
    ):
        return False
    metadata_count = evidence.get("metadata_function_count")
    if metadata_count is None:
        return (
            evidence.get("count_matches_metadata") is None
            and evidence.get("documented_limit") == "metadata_function_count_unavailable_terminal_page_proof_used"
        )
    if (
        type(metadata_count) is int
        and metadata_count == inventory_count
        and evidence.get("count_matches_metadata") is True
    ):
        return True
    return bool(
        type(metadata_count) is int
        and metadata_count > inventory_count
        and evidence.get("count_matches_metadata") is False
        and evidence.get("inventory_scope") == "non_external_functions"
        and evidence.get("metadata_function_count_scope") == "all_functions_including_external"
        and evidence.get("derived_external_function_count") == metadata_count - inventory_count
        and evidence.get("documented_limit")
        == "metadata_includes_external_functions_inventory_non_external_only"
    )


def _call_graph_schema_valid(value: Any) -> bool:
    """正規化済みcall graphがedge listと件数を厳密に持つか返す。"""

    if not isinstance(value, Mapping):
        return False
    edges = value.get("edges")
    edge_count = value.get("edge_count")
    return bool(
        isinstance(edges, list)
        and all(isinstance(edge, Mapping) for edge in edges)
        and type(edge_count) is int
        and edge_count == len(edges)
    )


def _call_graph_coverage_state(result: Mapping[str, Any]) -> str:
    """取得証跡のshapeをcomplete／managed／legacy partialへ分類する。"""

    selector = result.get("program_selector")
    coverage = result.get("retrieval_coverage")
    evidence = coverage.get("call_graph") if isinstance(coverage, Mapping) else None
    if (
        not isinstance(selector, str)
        or not selector
        or not isinstance(evidence, Mapping)
        or evidence.get("endpoint") != CALL_GRAPH_ENDPOINT
        or evidence.get("program_selector") != selector
    ):
        return "invalid"
    edge_count = evidence.get("edge_count")
    analysis_mode = result.get("analysis_mode")
    if analysis_mode == "managed_cil_primary_with_ghidra_structure":
        if (
            evidence.get("endpoint_invoked") is False
            and evidence.get("response_schema_valid") is None
            and evidence.get("requested_format") is None
            and evidence.get("requested_limit") is None
            and evidence.get("native_graph_applicable") is False
            and evidence.get("source") == "managed_cil_primary"
            and evidence.get("acquisition_status") == "not_applicable"
            and evidence.get("complete") is True
            and evidence.get("documented_limit") == CALL_GRAPH_MANAGED_LIMIT
            and type(edge_count) is int
            and edge_count == 0
        ):
            return "managed_not_applicable"
        return "invalid"
    if (
        evidence.get("endpoint_invoked") is True
        and evidence.get("response_schema_valid") is True
        and evidence.get("requested_format") == CALL_GRAPH_REQUEST_FORMAT
        and type(evidence.get("requested_limit")) is int
        and evidence.get("requested_limit") == CALL_GRAPH_REQUEST_LIMIT
        and evidence.get("native_graph_applicable") is True
        and evidence.get("source") == "ghidra_mcp"
        and evidence.get("acquisition_status") == "acquired"
        and evidence.get("complete") is True
        and evidence.get("documented_limit") is None
        and type(edge_count) is int
        and edge_count >= 0
    ):
        return "complete"
    if (
        evidence.get("endpoint_invoked") is False
        and evidence.get("response_schema_valid") is False
        and evidence.get("requested_format") == CALL_GRAPH_REQUEST_FORMAT
        and type(evidence.get("requested_limit")) is int
        and evidence.get("requested_limit") == CALL_GRAPH_REQUEST_LIMIT
        and evidence.get("native_graph_applicable") is True
        and evidence.get("source") == "legacy_cache"
        and evidence.get("acquisition_status") == "unavailable"
        and evidence.get("complete") is False
        and evidence.get("documented_limit") == CALL_GRAPH_LEGACY_LIMIT
        and (edge_count is None or type(edge_count) is int and edge_count >= 0)
    ):
        return "legacy_partial"
    return "invalid"


def _call_graph_retrieval_state(result: Mapping[str, Any]) -> str:
    """取得証跡を保存済みGhidra graphのschema・件数と結合して検証する。"""

    state = _call_graph_coverage_state(result)
    if state == "invalid":
        return state
    graph = result.get("ghidra_call_graph")
    if not _call_graph_schema_valid(graph):
        return "legacy_partial" if state == "legacy_partial" else "invalid"
    coverage = result["retrieval_coverage"]["call_graph"]
    edges = graph["edges"]
    if coverage.get("edge_count") != len(edges):
        return "invalid"
    if state == "managed_not_applicable" and (
        edges or graph.get("analysis_mode") != "managed_cil_primary_with_ghidra_structure"
    ):
        return "invalid"
    return state


def _call_graph_retrieval_coverage_complete(result: Mapping[str, Any]) -> bool:
    return _call_graph_retrieval_state(result) in {
        "complete",
        "managed_not_applicable",
    }


def _normalize_call_graph_response(response: Any) -> dict[str, Any]:
    """MCP応答をedge listへ限定し、None・旧shape・型不正をfail-closeする。"""

    if not isinstance(response, Mapping):
        raise GhidraMcpError("get_full_call_graph応答がJSON objectではありません")
    if "edges" not in response or not isinstance(response.get("edges"), list):
        raise GhidraMcpError("get_full_call_graph応答のedgesがlistではありません")
    raw_edges = response["edges"]
    if any(not isinstance(edge, Mapping) for edge in raw_edges):
        raise GhidraMcpError("get_full_call_graph応答にobject以外のedgeがあります")
    reported_count = response.get("edge_count")
    if reported_count is not None and (type(reported_count) is not int or reported_count != len(raw_edges)):
        raise GhidraMcpError("get_full_call_graph応答のedge_countがedges件数と一致しません")
    normalized = dict(response)
    normalized["edges"] = [dict(edge) for edge in raw_edges]
    normalized["edge_count"] = len(raw_edges)
    return normalized


def _get_full_call_graph_with_coverage(
    client: GhidraMcpClient,
    program: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """full call graphを取得し、requestと応答schemaを同じ証跡へ拘束する。"""

    response = client.get(
        CALL_GRAPH_ENDPOINT,
        format=CALL_GRAPH_REQUEST_FORMAT,
        limit=CALL_GRAPH_REQUEST_LIMIT,
        program=program,
    )
    graph = _normalize_call_graph_response(response)
    return graph, {
        "endpoint": CALL_GRAPH_ENDPOINT,
        "endpoint_invoked": True,
        "response_schema_valid": True,
        "program_selector": program,
        "requested_format": CALL_GRAPH_REQUEST_FORMAT,
        "requested_limit": CALL_GRAPH_REQUEST_LIMIT,
        "native_graph_applicable": True,
        "source": "ghidra_mcp",
        "acquisition_status": "acquired",
        "edge_count": len(graph["edges"]),
        "complete": True,
        "documented_limit": None,
    }


def _managed_call_graph_with_coverage(
    program: str,
    analysis_mode: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """managed CIL primaryでnative graphが非適用であることを明示する。"""

    if analysis_mode != "managed_cil_primary_with_ghidra_structure":
        raise ValueError("managed call graph契約のanalysis modeが不正です")
    graph = {
        "edges": [],
        "edge_count": 0,
        "analysis_mode": analysis_mode,
        "note": "managed method間のcallはCIL recordから保持する",
    }
    return graph, {
        "endpoint": CALL_GRAPH_ENDPOINT,
        "endpoint_invoked": False,
        "response_schema_valid": None,
        "program_selector": program,
        "requested_format": None,
        "requested_limit": None,
        "native_graph_applicable": False,
        "source": "managed_cil_primary",
        "acquisition_status": "not_applicable",
        "edge_count": 0,
        "complete": True,
        "documented_limit": CALL_GRAPH_MANAGED_LIMIT,
    }


def _legacy_call_graph_partial_coverage(result: Mapping[str, Any]) -> dict[str, Any]:
    """再取得証明のない旧cacheを取得済みへ昇格しない証跡を返す。"""

    graph = result.get("ghidra_call_graph")
    edge_count = len(graph["edges"]) if _call_graph_schema_valid(graph) else None
    return {
        "endpoint": CALL_GRAPH_ENDPOINT,
        "endpoint_invoked": False,
        "response_schema_valid": False,
        "program_selector": result.get("program_selector"),
        "requested_format": CALL_GRAPH_REQUEST_FORMAT,
        "requested_limit": CALL_GRAPH_REQUEST_LIMIT,
        "native_graph_applicable": True,
        "source": "legacy_cache",
        "acquisition_status": "unavailable",
        "edge_count": edge_count,
        "complete": False,
        "documented_limit": CALL_GRAPH_LEGACY_LIMIT,
    }


def load_prepared_inputs(
    sample_root: Path,
    private_output: Path,
    *,
    inventory_snapshot: _JsonFileSnapshot | None = None,
    expected_inventory_sha256: str | None = None,
    prepared_input_root: Path | None = None,
) -> tuple[dict[str, ProgramObject], dict[str, list[dict[str, Any]]]]:
    """SHA-256検証済みcacheから再展開せずprogram inventoryを復元する。"""

    relationship_path = Path(os.path.abspath(os.fspath(private_output / "input-relationships.json")))
    snapshot = inventory_snapshot or _bounded_json_snapshot(relationship_path)
    if snapshot.path != relationship_path:
        raise ValueError("prepared input inventoryのsnapshot pathが一致しません")
    if expected_inventory_sha256 is not None and (
        not isinstance(expected_inventory_sha256, str)
        or SHA256_RE.fullmatch(expected_inventory_sha256) is None
        or snapshot.sha256 != expected_inventory_sha256
    ):
        raise ValueError("prepared input inventoryのbinding SHA-256が一致しません")
    document = snapshot.document
    relationships = document.get("relationships", [])
    if not isinstance(relationships, list):
        raise TypeError("input relationship一覧が不正です")
    objects: dict[str, ProgramObject] = {}
    non_pe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cache_root = prepared_input_root or sample_root
    for raw in relationships:
        if not isinstance(raw, Mapping):
            raise TypeError("input relationshipがJSON objectではありません")
        relation = dict(raw)
        digest = str(relation.get("layer_sha256") or "").casefold()
        case_sha = str(relation.get("case_sha256") or "").casefold()
        if not SHA256_RE.fullmatch(digest) or not SHA256_RE.fullmatch(case_sha):
            raise ValueError("input relationshipのSHA-256が不正です")
        is_pe = relation.get("is_pe")
        if type(is_pe) is not bool:
            raise ValueError("input relationshipのPE判定が不正です")
        if not is_pe:
            non_pe[case_sha].append(relation)
            continue
        depth = relation.get("depth")
        expected_size = relation.get("size")
        if type(depth) is not int or depth < 0:
            raise ValueError("input relationshipのdepthが不正です")
        if type(expected_size) is not int or expected_size <= 0 or expected_size > MAX_PREPARED_INPUT_BYTES:
            raise ValueError("input relationshipのsizeが不正です")
        input_root = cache_root / case_sha / "ghidra-input"
        input_path = (
            input_root / f"{digest}.quarantine.bin"
            if depth == 0
            else input_root / "layers" / f"{digest}.quarantine.bin"
        )
        try:
            input_path.lstat()
            cache_present = True
        except FileNotFoundError:
            cache_present = False
        except OSError as exc:
            raise ValueError(f"再開用PE cacheを安全に確認できません: {digest}") from exc
        input_snapshot: _RegularFileSnapshot | None = None
        program_input_path = private_output / "import-staging" / f"{digest}.quarantine.bin"
        if cache_present:
            cached_data, _ = _bounded_regular_file_snapshot(
                input_path,
                max_bytes=expected_size,
            )
            if len(cached_data) != expected_size:
                raise ValueError(f"再開用PE cacheのsizeが一致しません: {digest}")
            if hashlib.sha256(cached_data).hexdigest() != digest:
                raise ValueError(f"再開用PE cacheのSHA-256が一致しません: {digest}")
            input_snapshot = _immutable_staging_snapshot(
                private_output,
                digest,
                cached_data,
            )
            program_input_path = input_snapshot.path
        else:
            result_path = private_output / "objects" / digest / "program-result.json"
            try:
                result_path.lstat()
                result_present = True
            except FileNotFoundError:
                result_present = False
            except OSError as exc:
                raise ValueError(f"完了cacheを安全に確認できません: {digest}") from exc
            result_snapshot = _bounded_json_snapshot(result_path) if result_present else None
            cached = result_snapshot.document if result_snapshot is not None else {}
            if result_snapshot is None or not (
                cached.get("status") == "complete" and cached.get("mcp_responses_valid") is True
            ):
                raise FileNotFoundError(f"再開用PE cacheがありません: {digest}")
            _assert_snapshot_unchanged(
                result_snapshot,
                context="完了program cache検証後",
            )
        if digest not in objects:
            objects[digest] = ProgramObject(
                sha256=digest,
                input_path=program_input_path,
                size=expected_size,
                input_snapshot=input_snapshot,
            )
        objects[digest].relationships.append(relation)
    expected = document.get("unique_pe_objects")
    if type(expected) is not int or expected <= 0 or len(objects) != expected:
        raise ValueError(f"再開用PE program数が一致しません: {len(objects)} != {expected}")
    _assert_snapshot_unchanged(
        snapshot,
        context="prepared input読取後",
    )
    print(
        json.dumps(
            {
                "phase": "reuse_prepared_inputs",
                "unique_pe_programs": len(objects),
                "relationships": len(relationships),
                "executed": False,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )
    return objects, non_pe


def validate_prepared_scope(
    collection_dir: Path,
    private_output: Path,
    *,
    inventory_snapshot: _JsonFileSnapshot | None = None,
) -> None:
    """再開cacheのcollection IDとcase集合が対象manifestに完全一致するか確認する。"""

    collection_snapshot = _bounded_json_snapshot(collection_dir / "manifest.json")
    collection = collection_snapshot.document
    expected = {
        str(item.get("case_id") or "").removeprefix("sha256:").casefold()
        for item in collection.get("cases", [])
        if isinstance(item, Mapping)
    }
    relationship_path = Path(os.path.abspath(os.fspath(private_output / "input-relationships.json")))
    snapshot = inventory_snapshot or _bounded_json_snapshot(relationship_path)
    if snapshot.path != relationship_path:
        raise ValueError("prepared input inventoryのsnapshot pathが一致しません")
    document = snapshot.document
    if str(document.get("collection_id") or "") != collection_dir.name:
        raise ValueError("再開cacheのcollection IDが対象directoryと一致しません")
    observed = {
        str(item.get("case_sha256") or "").casefold()
        for item in document.get("relationships", [])
        if isinstance(item, Mapping)
    }
    if not expected or observed != expected:
        raise ValueError(f"再開cacheのcase集合が対象collectionと一致しません: {len(observed)} != {len(expected)}")
    _assert_snapshot_unchanged(
        snapshot,
        context="prepared input scope検証後",
    )
    _assert_snapshot_unchanged(
        collection_snapshot,
        context="collection scope検証後",
    )


def _all_functions_with_coverage(
    client: GhidraMcpClient,
    program: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """list_functionsをcursor／offset終端まで取得し、有界な完全性証跡を返す。"""

    functions: list[dict[str, Any]] = []
    offset = 0
    cursor: str | int | None = None
    seen_cursors: set[str] = set()
    seen_page_hashes: set[str] = set()
    page_count = 0
    while True:
        query: dict[str, Any] = {
            "limit": FUNCTION_PAGE_SIZE,
            "program": program,
        }
        query["offset" if cursor is None else "cursor"] = offset if cursor is None else cursor
        page = client.get("/list_functions_enhanced", **query)
        raw_values = _page_values(page, "/list_functions_enhanced")
        if any(not isinstance(value, Mapping) for value in raw_values):
            raise GhidraMcpError("list_functionsにobject以外の項目があります")
        values = [dict(value) for value in raw_values]
        page_count += 1
        if page_count > MAX_FUNCTION_INVENTORY_PAGES:
            raise GhidraMcpError("function_inventory_page_documented_limit_exceeded:10000")
        page_hash = hashlib.sha256(json.dumps(values, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
        if values and page_hash in seen_page_hashes:
            raise GhidraMcpError("list_functionsが重複ページを返しました")
        seen_page_hashes.add(page_hash)
        functions.extend(values)
        if len(functions) > MAX_FUNCTION_INVENTORY_ITEMS:
            raise GhidraMcpError("function_inventory_documented_limit_exceeded:100000")
        next_cursor = None
        if isinstance(page, Mapping):
            next_cursor = page.get("next_cursor", page.get("nextCursor"))
        if next_cursor not in (None, ""):
            cursor_key = str(next_cursor)
            if cursor_key in seen_cursors:
                raise GhidraMcpError("list_functionsがcursorを循環させました")
            seen_cursors.add(cursor_key)
            cursor = next_cursor if isinstance(next_cursor, (str, int)) else cursor_key
            continue
        offset += len(values)
        cursor = None
        if len(values) < FUNCTION_PAGE_SIZE:
            break
    addresses = [str(item.get("address") or "").strip() for item in functions]
    if any(not address for address in addresses) or len(set(addresses)) != len(addresses):
        raise GhidraMcpError("list_functionsのaddress identityが欠落または重複しています")
    return functions, {
        "endpoint": "/list_functions_enhanced",
        "program_selector": program,
        "page_size": FUNCTION_PAGE_SIZE,
        "page_count": page_count,
        "item_count": len(functions),
        "terminal_short_page_observed": True,
        "complete": True,
        "maximum_items": MAX_FUNCTION_INVENTORY_ITEMS,
        "maximum_pages": MAX_FUNCTION_INVENTORY_PAGES,
        "pagination": "cursor_or_offset",
    }


def _all_functions(client: GhidraMcpClient, program: str) -> list[dict[str, Any]]:
    functions, _coverage = _all_functions_with_coverage(client, program)
    return functions


def _all_opcode_hashes(
    client: GhidraMcpClient,
    program: str,
    function_inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = client.get(
            "/get_bulk_function_hashes",
            offset=offset,
            limit=FUNCTION_PAGE_SIZE,
            filter="",
            program=program,
        )
        values = list((page or {}).get("functions", []))
        functions.extend(value for value in values if isinstance(value, dict))
        total = int((page or {}).get("total_matching", len(function_inventory)))
        offset += len(values)
        if not values or offset >= total:
            break
    return _complete_opcode_hash_inventory(
        {
            "program": program,
            "functions": functions,
            "endpoint_returned": len(functions),
        },
        function_inventory,
        program,
    )


def _complete_opcode_hash_inventory(
    value: Mapping[str, Any] | None,
    function_inventory: Iterable[Mapping[str, Any]],
    program: str,
) -> dict[str, Any]:
    """hash取得不能な関数も理由付きrecordとして全件inventory化する。"""

    raw_rows = [dict(item) for item in (value or {}).get("functions", []) if isinstance(item, Mapping)]
    rows_by_address: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in raw_rows:
        rows_by_address[str(row.get("address") or "")].append(row)
    completed = []
    for function in function_inventory:
        address = str(function.get("address") or "")
        candidates = rows_by_address.get(address, [])
        row = candidates.pop(0) if candidates else {}
        row.setdefault("address", address)
        row.setdefault("name", str(function.get("name") or "unknown"))
        digest = str(row.get("hash") or "").casefold()
        instruction_count = int(row.get("instruction_count") or 0)
        row["hash_status"] = (
            "available"
            if SHA256_RE.fullmatch(digest) and digest != EMPTY_SHA256 and instruction_count > 0
            else "unavailable_recorded"
        )
        row["program_selector"] = program
        completed.append(row)
    unmatched = [dict(item) for item in (value or {}).get("unmatched_response_rows", []) if isinstance(item, Mapping)]
    unmatched.extend(row for rows in rows_by_address.values() for row in rows)
    return {
        "program": program,
        "functions": completed,
        "returned": len(completed),
        "endpoint_returned": int((value or {}).get("endpoint_returned") or len(raw_rows)),
        "total_matching": len(completed),
        "available_hashes": sum(row["hash_status"] == "available" for row in completed),
        "all_functions_recorded": True,
        "unmatched_response_rows": unmatched,
    }


def _page_values(page: Any, endpoint: str) -> list[Any]:
    """ページ応答を内容を捨てずにlistへ正規化する。"""

    if page is None:
        return []
    if isinstance(page, list):
        return list(page)
    if isinstance(page, str):
        rendered = page.strip()
        if not rendered:
            return []
        try:
            decoded = json.loads(rendered)
        except json.JSONDecodeError:
            return [line for line in page.splitlines() if line.strip()]
        if isinstance(decoded, list):
            return list(decoded)
        raise GhidraMcpError(f"{endpoint}の文字列応答がJSON listまたは行形式ではありません")
    if isinstance(page, Mapping):
        for key in (
            "items",
            "results",
            "functions",
            "imports",
            "exports",
            "strings",
            "segments",
        ):
            values = page.get(key)
            if isinstance(values, list):
                return list(values)
        raise GhidraMcpError(f"{endpoint}のobject応答にlist項目がありません")
    raise GhidraMcpError(f"{endpoint}の応答形式を解釈できません: {type(page).__name__}")


def _all_endpoint_items(
    client: GhidraMcpClient,
    endpoint: str,
    program: str,
    *,
    page_size: int = STRUCTURE_PAGE_SIZE,
) -> tuple[list[Any], dict[str, Any]]:
    """offset/limit型endpointを空ページまで取得し、完全取得証跡を返す。"""

    values: list[Any] = []
    offset = 0
    page_count = 0
    seen_page_hashes: set[str] = set()
    while True:
        page = client.get(
            endpoint,
            offset=offset,
            limit=page_size,
            program=program,
        )
        page_values = _page_values(page, endpoint)
        page_count += 1
        page_hash = hashlib.sha256(
            json.dumps(page_values, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if page_values and page_hash in seen_page_hashes:
            raise GhidraMcpError(f"{endpoint}がoffsetを無視した重複ページを返しました")
        seen_page_hashes.add(page_hash)
        values.extend(page_values)
        offset += len(page_values)
        if len(page_values) < page_size:
            break
    return values, {
        "endpoint": endpoint,
        "program_selector": program,
        "page_size": page_size,
        "page_count": page_count,
        "item_count": len(values),
        "terminal_short_page_observed": True,
        "complete": True,
    }


CHARACTERISTIC_PHASES = (
    ("startup", "起動・初期化", {"entrypoint"}),
    ("configuration", "設定・payload復元", {"config_or_data_transform", "cryptographic_transform"}),
    ("evasion", "解析回避・環境判定", {"anti_analysis"}),
    ("persistence", "永続化", {"persistence"}),
    ("execution", "process・memory操作", {"process_or_memory_operation"}),
    ("communication", "通信", {"network_communication"}),
    ("dispatch", "command分配・処理", {"command_dispatch_or_handler"}),
    ("file_activity", "file操作", {"file_operation"}),
    (
        "support",
        "補助処理",
        {"general_internal_logic", "compiler_or_library_code", "external_api_or_thunk", "managed_method_without_body"},
    ),
)


def _entry_point_addresses(entry_points: Any) -> set[str]:
    """Ghidraのentry point応答からaddress候補を抽出する。"""

    values: set[str] = set()
    if isinstance(entry_points, str):
        values.update(re.findall(r"(?i)(?:@|address\s*[:=])\s*([0-9a-fx:]+)", entry_points))
    elif isinstance(entry_points, Mapping):
        values.update(str(value) for key, value in entry_points.items() if "address" in str(key).casefold() and value)
    elif isinstance(entry_points, Iterable):
        for item in entry_points:
            if isinstance(item, Mapping):
                value = item.get("address") or item.get("entry")
                if value:
                    values.add(str(value))
            elif isinstance(item, str):
                values.update(re.findall(r"(?i)(?:@|address\s*[:=])\s*([0-9a-fx:]+)", item))
    return {value.casefold().removeprefix("0x") for value in values}


def _strict_pe_address(value: Any) -> int | None:
    """PE向けの空間名なし16進addressだけを整数へ正規化する。"""

    rendered = str(value or "").strip()
    if not re.fullmatch(r"(?i)(?:0x)?[0-9a-f]{1,16}", rendered):
        return None
    parsed = int(rendered, 16)
    return parsed if 0 < parsed <= 0xFFFF_FFFF_FFFF_FFFF else None


def _ghidra_entry_records(entry_points: Any) -> list[dict[str, str]]:
    """get_entry_points応答を、推測を加えずname/address/annotationへ正規化する。"""

    records: list[dict[str, str]] = []
    if isinstance(entry_points, str):
        for line in entry_points.splitlines():
            match = re.match(
                r"\s*(.+?)\s*(?:@|->)\s*((?:0x)?[0-9a-fA-F]{1,16})(?:\s|$)",
                line,
            )
            if match:
                records.append(
                    {
                        "name": match.group(1).strip(),
                        "address": match.group(2),
                        "annotation": line.strip(),
                    }
                )
        return records
    if isinstance(entry_points, Mapping):
        for key in ("entry_points", "entries", "items", "results"):
            nested = entry_points.get(key)
            if isinstance(nested, (Mapping, list, tuple, str)):
                records.extend(_ghidra_entry_records(nested))
        address = entry_points.get("address") or entry_points.get("entry")
        if address:
            records.append(
                {
                    "name": str(
                        entry_points.get("name") or entry_points.get("label") or entry_points.get("kind") or ""
                    ).strip(),
                    "address": str(address),
                    "annotation": str(entry_points.get("annotation") or entry_points.get("type") or "").strip(),
                }
            )
        return records
    if isinstance(entry_points, Iterable):
        for item in entry_points:
            records.extend(_ghidra_entry_records(item))
    return records


def _unique_ghidra_program_entry(entry_points: Any) -> dict[str, Any]:
    """Ghidraが明示した通常entry labelを一意なaddressへ限定する。"""

    records = _ghidra_entry_records(entry_points)
    candidates: dict[int, list[str]] = defaultdict(list)
    for record in records:
        normalized_name = re.sub(
            r"[^a-z0-9]",
            "",
            str(record.get("name") or "").casefold(),
        )
        if normalized_name not in {"entry", "entrypoint"}:
            continue
        annotation = str(record.get("annotation") or "").casefold()
        if "program entry" in annotation and "external entry" not in annotation:
            continue
        address = _strict_pe_address(record.get("address"))
        if address is not None:
            candidates[address].append(str(record.get("name") or "entry"))
    addresses = sorted(candidates)
    return {
        "status": "unique" if len(addresses) == 1 else "not_unique",
        "record_count": len(records),
        "candidate_count": len(addresses),
        "candidate_addresses": [f"{address:x}" for address in addresses],
        "address": addresses[0] if len(addresses) == 1 else None,
    }


def _pe_entry_point_validation(data: bytes) -> dict[str, Any]:
    """PE header上のentry pointが一意な実行section内にあることを確認する。"""

    pe: pefile.PE | None = None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint or 0)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase or 0)
        if entry_rva <= 0 or image_base <= 0:
            return {"status": "invalid", "reason": "pe_entry_point_missing"}
        matching_sections = []
        for section in pe.sections:
            start = int(section.VirtualAddress or 0)
            span = max(
                int(section.Misc_VirtualSize or 0),
                int(section.SizeOfRawData or 0),
            )
            if span > 0 and start <= entry_rva < start + span:
                matching_sections.append(section)
        if len(matching_sections) != 1:
            return {
                "status": "invalid",
                "reason": "pe_entry_point_section_not_unique",
                "matching_section_count": len(matching_sections),
            }
        section = matching_sections[0]
        if not int(section.Characteristics or 0) & 0x2000_0000:
            return {
                "status": "invalid",
                "reason": "pe_entry_point_section_not_executable",
            }
        address = image_base + entry_rva
        if address <= image_base or address > 0xFFFF_FFFF_FFFF_FFFF:
            return {"status": "invalid", "reason": "pe_entry_point_address_invalid"}
        section_name = (
            bytes(section.Name)
            .rstrip(b"\x00")
            .decode(
                "ascii",
                errors="replace",
            )
        )
        return {
            "status": "validated",
            "reason": "pe_entry_point_in_unique_executable_section",
            "address": address,
            "address_hex": f"{address:x}",
            "rva_hex": f"{entry_rva:x}",
            "section_name": section_name,
            "section_executable": True,
        }
    except Exception:
        return {"status": "invalid", "reason": "pe_header_parse_failed"}
    finally:
        if pe is not None:
            pe.close()


def _ghidra_segment_ranges(segments: Any) -> list[dict[str, Any]]:
    """list_segments応答を検証用の閉区間へ正規化する。"""

    ranges: list[dict[str, Any]] = []
    if isinstance(segments, str):
        for line in segments.splitlines():
            match = re.match(
                r"\s*(.+?)\s*:\s*((?:0x)?[0-9a-fA-F]{1,16})\s*-\s*"
                r"((?:0x)?[0-9a-fA-F]{1,16})\s*$",
                line,
            )
            if not match:
                continue
            start = _strict_pe_address(match.group(2))
            end = _strict_pe_address(match.group(3))
            if start is not None and end is not None and start <= end:
                ranges.append({"name": match.group(1).strip(), "start": start, "end": end})
        return ranges
    if isinstance(segments, Mapping):
        for key in ("segments", "items", "results"):
            nested = segments.get(key)
            if isinstance(nested, (Mapping, list, tuple, str)):
                ranges.extend(_ghidra_segment_ranges(nested))
        start = _strict_pe_address(
            segments.get("start") or segments.get("start_address") or segments.get("min_address")
        )
        end = _strict_pe_address(segments.get("end") or segments.get("end_address") or segments.get("max_address"))
        if start is not None and end is not None and start <= end:
            ranges.append(
                {
                    "name": str(segments.get("name") or segments.get("segment") or ""),
                    "start": start,
                    "end": end,
                }
            )
        return ranges
    if isinstance(segments, Iterable):
        for item in segments:
            ranges.extend(_ghidra_segment_ranges(item))
    return ranges


def _recover_unique_entry_point_function(
    client: GhidraMcpClient,
    program: str,
    data: bytes,
    entry_points: Any,
    segments: Any,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """関数0件時、一意かつ検証済みentryだけを1回関数化する。"""

    pe_validation = _pe_entry_point_validation(data)
    ghidra_entry = _unique_ghidra_program_entry(entry_points)
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "trigger": "native_function_inventory_empty_after_auto_analysis",
        "status": "not_attempted",
        "reason": "validation_incomplete",
        "attempted": False,
        "initial_function_count": 0,
        "final_function_count": 0,
        "program_selector": program,
        "candidate_count": int(ghidra_entry["candidate_count"]),
        "candidate_addresses": list(ghidra_entry["candidate_addresses"]),
        "validation": {
            "pe_entry_point": pe_validation,
            "ghidra_program_entry_unique": ghidra_entry["status"] == "unique",
            "ghidra_segment_contains_entry": False,
        },
    }
    private_evidence: dict[str, Any] = {
        "schema_version": 1,
        "program_selector": program,
        "request_endpoint": "/create_function",
        "disassemble_first": True,
        "response": None,
        "error": None,
    }
    if pe_validation.get("status") != "validated":
        evidence["reason"] = str(pe_validation.get("reason") or "pe_entry_point_invalid")
        return [], evidence, private_evidence
    if ghidra_entry.get("status") != "unique":
        evidence["reason"] = "ghidra_program_entry_not_unique"
        return [], evidence, private_evidence
    candidate = int(ghidra_entry["address"])
    if candidate != int(pe_validation["address"]):
        evidence["reason"] = "ghidra_and_pe_entry_point_mismatch"
        return [], evidence, private_evidence
    containing_segments = [
        segment
        for segment in _ghidra_segment_ranges(segments)
        if int(segment["start"]) <= candidate <= int(segment["end"])
        and str(segment.get("name") or "").strip().casefold() not in {"header", "headers"}
    ]
    if len(containing_segments) != 1:
        evidence["reason"] = "ghidra_entry_segment_not_unique"
        evidence["validation"]["ghidra_matching_segment_count"] = len(containing_segments)
        return [], evidence, private_evidence
    evidence["validation"]["ghidra_segment_contains_entry"] = True
    evidence["validated_address"] = f"{candidate:x}"
    evidence["validated_segment_name"] = str(containing_segments[0].get("name") or "")
    evidence["attempted"] = True
    private_evidence["address"] = f"{candidate:x}"
    try:
        response = client.post(
            "/create_function",
            {
                "address": f"{candidate:x}",
                "name": "",
                "disassemble_first": True,
            },
            program=program,
        )
        private_evidence["response"] = response
        recovered = _all_functions(client, program)
    except GhidraMcpError as error:
        evidence["status"] = "failed"
        evidence["reason"] = "ghidra_create_function_or_inventory_failed"
        private_evidence["error"] = f"{type(error).__name__}: {error}"
        return [], evidence, private_evidence
    recovered_entry_functions = [
        function
        for function in recovered
        if _strict_pe_address(function.get("address")) == candidate
        and not bool(function.get("isExternal"))
        and not bool(function.get("isThunk"))
    ]
    evidence["final_function_count"] = len(recovered)
    if len(recovered_entry_functions) != 1:
        evidence["status"] = "failed"
        evidence["reason"] = "created_entry_body_not_unique_in_function_inventory"
        evidence["validated_entry_body_count"] = len(recovered_entry_functions)
        return [], evidence, private_evidence
    evidence["status"] = "recovered"
    evidence["reason"] = "entry_function_created_and_inventory_verified"
    return recovered, evidence, private_evidence


def _call_graph_degrees(call_graph: Mapping[str, Any]) -> tuple[Counter[str], Counter[str], dict[str, list[str]]]:
    """call graphから入次数、出次数、callee名をaddress単位で集計する。"""

    inbound: Counter[str] = Counter()
    outbound: Counter[str] = Counter()
    callees: dict[str, list[str]] = defaultdict(list)
    for edge in call_graph.get("edges", []) if isinstance(call_graph, Mapping) else []:
        if not isinstance(edge, Mapping):
            continue
        caller = str(edge.get("caller_addr") or "")
        callee = str(edge.get("callee_addr") or "")
        callee_name = str(edge.get("callee_name") or callee)
        if caller:
            outbound[caller] += 1
            if callee_name:
                callees[caller].append(callee_name)
        if callee:
            inbound[callee] += 1
    return inbound, outbound, callees


def _characteristic_candidates(
    functions: Iterable[Mapping[str, Any]],
    call_graph: Mapping[str, Any],
    entry_points: Any,
    opcode_hashes: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """関数inventoryを代表関数候補へ採点する。"""

    inbound, outbound, callees = _call_graph_degrees(call_graph)
    entries = _entry_point_addresses(entry_points)
    instruction_counts = {
        str(item.get("address") or ""): int(item.get("instruction_count") or 0)
        for item in (opcode_hashes or {}).get("functions", [])
        if isinstance(item, Mapping)
    }
    candidates: list[dict[str, Any]] = []
    for source in functions:
        item = dict(source)
        if bool(item.get("isExternal")) or bool(item.get("isThunk")):
            continue
        address = str(item.get("address") or "")
        name = str(item.get("name") or "unknown")
        related = callees.get(address, [])
        role = _classify_role(name, related, "")
        in_degree = inbound[address]
        out_degree = outbound[address]
        instructions = instruction_counts.get(address, int(item.get("instruction_count") or 0))
        reasons: list[str] = []
        score = 0
        normalized_address = address.casefold().removeprefix("0x")
        if normalized_address in entries or role == "entrypoint":
            score += 10_000
            reasons.append("entry_point")
        # Goではcall graph中心性と関数sizeだけで採点するとruntime/internalが
        # 上位を独占する。main packageはcompiler runtimeではなく検体固有code
        # なので、上限付き代表関数枠の中で必ず優先する。
        if GO_MAIN_USER_CODE_RE.search(name) and not LIBRARY_RE.search(name):
            score += 8_500
            reasons.append("probable_go_main_user_code")
        if role not in {"general_internal_logic", "compiler_or_library_code"}:
            score += 3_000
            reasons.append(f"role:{role}")
        if in_degree or out_degree:
            score += min(2_000, (in_degree + out_degree) * 40)
            reasons.append(f"call_graph_centrality:in={in_degree},out={out_degree}")
        if instructions:
            score += min(1_500, instructions)
            if instructions >= 64:
                reasons.append(f"large_function:instructions={instructions}")
        if not re.match(r"(?i)^(?:FUN_|sub_|func_0x)", name):
            score += 200
            reasons.append("meaningful_symbol_name")
        if role == "compiler_or_library_code":
            score -= 2_000
        if not reasons:
            reasons.append("context_representative")
        item.update(
            {
                "preliminary_role": role,
                "selection_score": score,
                "selection_reasons": reasons,
                "in_degree": in_degree,
                "out_degree": out_degree,
                "instruction_count": instructions,
            }
        )
        candidates.append(item)
    return candidates


def select_characteristic_functions(
    functions: Iterable[Mapping[str, Any]],
    call_graph: Mapping[str, Any],
    entry_points: Any,
    opcode_hashes: Mapping[str, Any] | None = None,
    *,
    max_count: int = MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM,
) -> list[dict[str, Any]]:
    """役割の網羅と中心性を両立する代表関数集合を返す。"""

    candidates = _characteristic_candidates(functions, call_graph, entry_points, opcode_hashes)
    if len(candidates) <= max_count:
        for item in candidates:
            item["selection_reasons"] = sorted(set([*item["selection_reasons"], "small_program_complete_context"]))
        return sorted(candidates, key=lambda item: str(item.get("address") or ""))
    ranked = sorted(
        candidates,
        key=lambda item: (
            -int(item["selection_score"]),
            -int(item["instruction_count"]),
            str(item.get("address") or ""),
        ),
    )
    selected: dict[str, dict[str, Any]] = {}
    for role in {phase_role for _, _, roles in CHARACTERISTIC_PHASES for phase_role in roles}:
        representative = next((item for item in ranked if item["preliminary_role"] == role), None)
        if representative:
            selected[str(representative["address"])] = representative
    for item in ranked:
        if len(selected) >= max_count:
            break
        selected.setdefault(str(item["address"]), item)
    return sorted(selected.values(), key=lambda item: (-int(item["selection_score"]), str(item["address"])))


def _record_selection_score(record: Mapping[str, Any]) -> tuple[int, list[str]]:
    """解析済みrecordを代表関数として再評価する。"""

    role = str(record.get("role") or "general_internal_logic")
    reasons = [str(value) for value in record.get("selection_reasons", []) if value]
    score = int(record.get("selection_score") or 0)
    if role == "entrypoint":
        score += 10_000
        reasons.append("entry_point")
    elif role not in {
        "general_internal_logic",
        "compiler_or_library_code",
        "external_api_or_thunk",
        "managed_method_without_body",
    }:
        score += 3_000
        reasons.append(f"role:{role}")
    degree = len(record.get("callers") or []) + len(record.get("callees") or []) + len(record.get("api_calls") or [])
    if degree:
        score += min(2_000, degree * 40)
        reasons.append(f"reviewed_call_centrality:{degree}")
    instructions = int(record.get("instruction_count") or 0)
    score += min(1_500, instructions)
    if instructions >= 64:
        reasons.append(f"large_function:instructions={instructions}")
    if not reasons:
        reasons.append("context_representative")
    return score, sorted(set(reasons))


def _mark_characteristic_records(
    records: list[dict[str, Any]],
    *,
    max_count: int = MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM,
) -> list[str]:
    """nativeとmanagedの各recordへ選定状態・理由を付与する。"""

    selected_ids: list[str] = []
    for analysis_kind in ("ghidra_native_or_loader_view", "managed_cil"):
        eligible = [
            item
            for item in records
            if item.get("analysis_kind") == analysis_kind
            and item.get("decompilation_status") not in {"excluded_external_or_thunk", "no_managed_body"}
        ]
        structural_fallback = [
            item
            for item in records
            if item.get("analysis_kind") == analysis_kind
            and item.get("decompilation_status") in {"excluded_external_or_thunk", "no_managed_body"}
        ]
        already = [item for item in eligible if item.get("selected_for_characteristic_analysis") is True]
        pool = already or eligible or structural_fallback
        selection_limit = max_count if (already or eligible) else min(4, max_count)
        scored = []
        for item in pool:
            score, reasons = _record_selection_score(item)
            item["selection_score"] = score
            item["selection_reasons"] = reasons
            scored.append(item)
        ranked = sorted(
            scored,
            key=lambda item: (-int(item.get("selection_score") or 0), str(item.get("function_id") or "")),
        )
        chosen: dict[str, dict[str, Any]] = {}
        for role in {phase_role for _, _, roles in CHARACTERISTIC_PHASES for phase_role in roles}:
            representative = next((item for item in ranked if item.get("role") == role), None)
            if representative:
                chosen[str(representative["function_id"])] = representative
        for item in ranked:
            if len(chosen) >= selection_limit:
                break
            chosen.setdefault(str(item["function_id"]), item)
        for item in [*eligible, *structural_fallback]:
            selected = str(item.get("function_id") or "") in chosen
            item["selected_for_characteristic_analysis"] = selected
            if selected and eligible and len(eligible) <= max_count:
                item["selection_reasons"] = sorted(
                    set([*item.get("selection_reasons", []), "small_program_complete_context"])
                )
            if selected and not eligible:
                item["selection_reasons"] = sorted(
                    set([*item.get("selection_reasons", []), "no_internal_body_structural_fallback"])
                )
            if selected:
                selected_ids.append(str(item["function_id"]))
    for item in records:
        item.setdefault("selected_for_characteristic_analysis", False)
        item.setdefault("selection_reasons", [])
    return sorted(set(selected_ids))


def ensure_characteristic_selection(result: dict[str, Any]) -> list[str]:
    """cacheを含むprogram結果へ代表関数選定情報を付与する。"""

    records = [item for item in result.get("functions", []) if isinstance(item, dict)]
    selected_ids = _mark_characteristic_records(records)
    result["characteristic_function_ids"] = selected_ids
    result["characteristic_function_count"] = len(selected_ids)
    result["selection_policy"] = {
        "name": "role_entrypoint_callgraph_size_representatives",
        "maximum_per_analysis_kind": MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM,
        "required_dimensions": [
            "entry_point",
            "malware_behavior_role",
            "call_graph_centrality",
            "function_size",
            "symbol_quality",
        ],
        "all_functions_decompilation_required": False,
        "unselected_scope_recorded": True,
    }
    return selected_ids


def _decompile_status(pseudocode: str) -> tuple[str, list[str]]:
    lowered = pseudocode.casefold()
    warnings = [value.strip() for value in re.findall(r"/\*\s*(WARNING:[^*]+)\*/", pseudocode, re.IGNORECASE)]
    if not pseudocode.strip():
        return "failed_empty", warnings
    if any(marker in lowered for marker in FATAL_DECOMPILE_MARKERS):
        return "failed", warnings
    if any(marker in lowered for marker in LIMITED_DECOMPILE_MARKERS):
        return "limited_bad_instruction_or_flow", warnings
    return "succeeded", warnings


def _private_jsonl_limits() -> tuple[int, int, int, int]:
    """private JSONLの現在の上限を検証して返す。"""

    maximum_bytes = MAX_PRIVATE_RAW_BYTES
    maximum_records = MAX_PRIVATE_RAW_RECORDS
    maximum_line_bytes = MAX_PRIVATE_RAW_LINE_BYTES
    maximum_depth = MAX_PRIVATE_RAW_JSON_DEPTH
    if type(maximum_bytes) is not int or maximum_bytes <= 0 or maximum_bytes > 64 * 1024 * 1024:
        raise ValueError("private JSONLの総bytes上限が不正です")
    if type(maximum_records) is not int or maximum_records <= 0:
        raise ValueError("private JSONLのrecord数上限が不正です")
    if type(maximum_line_bytes) is not int or maximum_line_bytes <= 0:
        raise ValueError("private JSONLの1行bytes上限が不正です")
    if type(maximum_depth) is not int or maximum_depth < 0:
        raise ValueError("private JSONLのJSON深度上限が不正です")
    return (
        maximum_bytes,
        maximum_records,
        min(maximum_line_bytes, maximum_bytes),
        maximum_depth,
    )


def _checked_private_raw_add(current: int, additional: int, *, maximum: int) -> int:
    """加算前にprivate raw累積bytes上限を検証する。"""

    if current < 0 or additional < 0 or current > maximum - additional:
        raise ValueError("private JSONLが総bytes上限を超えています")
    return current + additional


def _private_raw_open_flags() -> int:
    """private rawをfollowせずread-onlyで開くflagを返す。"""

    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    return flags


def _validate_opened_private_raw(
    before: os.stat_result,
    opened: os.stat_result,
) -> None:
    """path確認時とopen handleが同じ単一link通常fileであることを確認する。"""

    if (
        _stat_is_reparse(opened)
        or not stat.S_ISREG(opened.st_mode)
        or int(opened.st_nlink) != 1
        or int(opened.st_size) != int(before.st_size)
        or not _same_path_identity(before, opened)
    ):
        raise ValueError("private JSONLのopen時identityが一致しません")


def _validate_private_raw_after_read(
    path: Path,
    before: os.stat_result,
    opened_before: os.stat_result,
    opened_after: os.stat_result,
    *,
    observed_size: int,
) -> os.stat_result:
    """stream読取後のhandleとpath bindingを固定する。"""

    after = _regular_file_metadata(path)
    if (
        observed_size != int(opened_after.st_size)
        or observed_size != int(after.st_size)
        or not _same_regular_file_binding(opened_before, opened_after)
        or not _same_regular_file_binding(before, after)
        or not _same_path_identity(opened_after, after)
    ):
        raise ValueError("private JSONLの読取中にidentityが変更されました")
    return after


def _decode_private_jsonl_record(
    raw_line: bytes,
    *,
    path: Path,
    line_number: int,
    maximum_depth: int,
) -> dict[str, Any]:
    """1行をduplicate key／非有限数を拒否するstrict JSON objectとして読む。"""

    payload = raw_line
    if line_number == 1 and payload.startswith(b"\xef\xbb\xbf"):
        payload = payload[3:]
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_non_finite,
            parse_int=_strict_json_int,
            parse_float=_strict_json_float,
        )
        if not isinstance(value, dict):
            raise TypeError("JSON objectが必要です")
        _ensure_json_depth(value, maximum_depth=maximum_depth)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(f"private JSONLが不正です: {path.name}:{line_number}: {exc}") from exc
    return value


def _stream_private_jsonl(
    path: Path,
    consume: Callable[[dict[str, Any], int], None],
) -> _JsonlFileSnapshot:
    """single handleからprivate JSONLをstreaming strict parse/hashする。"""

    maximum_bytes, maximum_records, maximum_line_bytes, maximum_depth = _private_jsonl_limits()
    absolute = Path(os.path.abspath(os.fspath(path)))
    before = _regular_file_metadata(absolute)
    if int(before.st_size) > maximum_bytes:
        raise ValueError("private JSONLが総bytes上限を超えています")
    descriptor: int | None = None
    digest = hashlib.sha256()
    total = 0
    record_count = 0
    line_count = 0
    last_byte = b""
    try:
        descriptor = os.open(absolute, _private_raw_open_flags())
        opened_before = os.fstat(descriptor)
        _validate_opened_private_raw(before, opened_before)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            while True:
                raw_line = handle.readline(maximum_line_bytes + 1)
                if not raw_line:
                    break
                line_count += 1
                if line_count > maximum_records * 2:
                    raise ValueError("private JSONLがline数上限を超えています")
                if len(raw_line) > maximum_line_bytes:
                    raise ValueError("private JSONLが1行bytes上限を超えています")
                total = _checked_private_raw_add(
                    total,
                    len(raw_line),
                    maximum=maximum_bytes,
                )
                digest.update(raw_line)
                last_byte = raw_line[-1:]
                if not raw_line.strip():
                    continue
                record_count += 1
                if record_count > maximum_records:
                    raise ValueError("private JSONLがrecord数上限を超えています")
                consume(
                    _decode_private_jsonl_record(
                        raw_line,
                        path=absolute,
                        line_number=line_count,
                        maximum_depth=maximum_depth,
                    ),
                    line_count,
                )
            opened_after = os.fstat(handle.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)
    after = _validate_private_raw_after_read(
        absolute,
        before,
        opened_before,
        opened_after,
        observed_size=total,
    )
    snapshot = _JsonlFileSnapshot(
        path=absolute,
        sha256=digest.hexdigest(),
        size=total,
        metadata=after,
        record_count=record_count,
        line_count=line_count,
        ends_with_newline=last_byte == b"\n",
    )
    _assert_jsonl_snapshot_unchanged(snapshot)
    return snapshot


def _stream_private_raw_digest(
    path: Path,
    *,
    maximum_bytes: int,
    destination: io.BufferedWriter | None = None,
) -> _RegularFileSnapshot:
    """全bytesを保持せず固定chunkでhashし、必要なら同時にcopyする。"""

    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise ValueError("private rawのstream上限が不正です")
    absolute = Path(os.path.abspath(os.fspath(path)))
    before = _regular_file_metadata(absolute)
    if int(before.st_size) > maximum_bytes:
        raise ValueError("private JSONLが総bytes上限を超えています")
    descriptor: int | None = None
    digest = hashlib.sha256()
    total = 0
    try:
        descriptor = os.open(absolute, _private_raw_open_flags())
        opened_before = os.fstat(descriptor)
        _validate_opened_private_raw(before, opened_before)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            while chunk := handle.read(min(PRIVATE_RAW_STREAM_CHUNK_BYTES, maximum_bytes + 1)):
                total = _checked_private_raw_add(
                    total,
                    len(chunk),
                    maximum=maximum_bytes,
                )
                digest.update(chunk)
                if destination is not None and destination.write(chunk) != len(chunk):
                    raise OSError("private JSONLのstream copyが完了しませんでした")
            opened_after = os.fstat(handle.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)
    after = _validate_private_raw_after_read(
        absolute,
        before,
        opened_before,
        opened_after,
        observed_size=total,
    )
    return _RegularFileSnapshot(
        path=absolute,
        sha256=digest.hexdigest(),
        size=total,
        metadata=after,
    )


def _assert_jsonl_snapshot_unchanged(snapshot: _JsonlFileSnapshot) -> None:
    """JSONL snapshotを固定chunk hashとidentityで再検証する。"""

    maximum_bytes, _, _, _ = _private_jsonl_limits()
    try:
        current = _stream_private_raw_digest(
            snapshot.path,
            maximum_bytes=maximum_bytes,
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"private JSONLで競合変更を検出しました: {snapshot.path.name}") from exc
    if (
        current.sha256 != snapshot.sha256
        or current.size != snapshot.size
        or not _same_regular_file_binding(snapshot.metadata, current.metadata)
    ):
        raise ValueError(f"private JSONLで競合変更を検出しました: {snapshot.path.name}")


def _load_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    """private JSONLをstreaming strict single-handle snapshotとして読む。"""

    output: dict[str, dict[str, Any]] = {}
    try:
        present = path.lstat() is not None
    except FileNotFoundError:
        present = False
    if not present:
        return output

    def collect(item: dict[str, Any], line_number: int) -> None:
        if not isinstance(item, dict) or not item.get("address"):
            raise ValueError(f"private JSONL recordが不正です: {path.name}:{line_number}")
        address = str(item["address"])
        if address in output:
            raise ValueError(f"private JSONL addressが重複しています: {address}")
        output[address] = item

    _stream_private_jsonl(path, collect)
    return output


def _encode_private_jsonl_record(
    value: Mapping[str, Any],
    *,
    path: Path,
    line_number: int,
) -> bytes:
    """1 recordを上限確認済みのstrict JSONL bytesへする。"""

    _, _, maximum_line_bytes, maximum_depth = _private_jsonl_limits()
    try:
        record = dict(value)
        _ensure_json_depth(record, maximum_depth=maximum_depth)
        encoded = (
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, ValueError) as exc:
        raise ValueError(f"private JSONL recordをencodeできません: {path.name}:{line_number}") from exc
    if len(encoded) > maximum_line_bytes:
        raise ValueError("private JSONLが1行bytes上限を超えています")
    _decode_private_jsonl_record(
        encoded,
        path=path,
        line_number=line_number,
        maximum_depth=maximum_depth,
    )
    return encoded


def _write_private_raw(handle: io.BufferedWriter, data: bytes) -> None:
    """一時fileへbytes全体を書き、short writeを拒否する。"""

    if handle.write(data) != len(data):
        raise OSError("private JSONLのatomic writeが完了しませんでした")


def _atomic_rewrite_jsonl(
    path: Path,
    values: Iterable[Mapping[str, Any]],
    *,
    append: bool,
) -> None:
    """同一directoryの一時fileへstreaming生成しJSONLをatomic置換する。"""

    maximum_bytes, maximum_records, _, _ = _private_jsonl_limits()
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        present = absolute.lstat() is not None
    except FileNotFoundError:
        present = False
    except OSError as exc:
        raise ValueError("private JSONL pathを安全に確認できません") from exc
    expected = _validate_jsonl_snapshot(absolute) if present else None

    ensure_no_reparse_components(absolute.parent)
    absolute.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(absolute.parent)
    try:
        parent_before = absolute.parent.lstat()
    except OSError as exc:
        raise ValueError("private JSONL出力directoryを確認できません") from exc
    if _stat_is_reparse(parent_before) or not stat.S_ISDIR(parent_before.st_mode):
        raise ValueError("private JSONL出力先は通常directoryに限定します")

    temporary = absolute.with_name(f".jsonl-{os.getpid():x}-{time.time_ns():x}.tmp")
    temporary_identity: os.stat_result | None = None
    total = 0
    record_count = 0
    line_count = 0
    try:
        with temporary.open("xb") as handle:
            temporary_identity = os.fstat(handle.fileno())
            if (
                _stat_is_reparse(temporary_identity)
                or not stat.S_ISREG(temporary_identity.st_mode)
                or int(temporary_identity.st_nlink) != 1
            ):
                raise ValueError("private JSONL一時pathが通常fileではありません")
            if append and expected is not None:
                copied = _stream_private_raw_digest(
                    expected.path,
                    maximum_bytes=maximum_bytes,
                    destination=handle,
                )
                if (
                    copied.sha256 != expected.sha256
                    or copied.size != expected.size
                    or not _same_regular_file_binding(
                        copied.metadata,
                        expected.metadata,
                    )
                ):
                    raise ValueError("private JSONL copy元で競合変更を検出しました")
                total = copied.size
                record_count = expected.record_count
                line_count = expected.line_count
                if total and not expected.ends_with_newline:
                    total = _checked_private_raw_add(
                        total,
                        1,
                        maximum=maximum_bytes,
                    )
                    _write_private_raw(handle, b"\n")
            for value in values:
                if record_count >= maximum_records:
                    raise ValueError("private JSONLがrecord数上限を超えています")
                if line_count >= maximum_records * 2:
                    raise ValueError("private JSONLがline数上限を超えています")
                encoded = _encode_private_jsonl_record(
                    value,
                    path=absolute,
                    line_number=line_count + 1,
                )
                total = _checked_private_raw_add(
                    total,
                    len(encoded),
                    maximum=maximum_bytes,
                )
                _write_private_raw(handle, encoded)
                record_count += 1
                line_count += 1
            handle.flush()
            os.fsync(handle.fileno())
        ensure_no_reparse_components(temporary)
        temporary_at_path = temporary.lstat()
        if (
            _stat_is_reparse(temporary_at_path)
            or not stat.S_ISREG(temporary_at_path.st_mode)
            or int(temporary_at_path.st_nlink) != 1
            or int(temporary_at_path.st_size) != total
            or not _same_path_identity(temporary_identity, temporary_at_path)
        ):
            raise ValueError("private JSONL一時fileのidentityが変更されました")
        ensure_no_reparse_components(absolute.parent)
        parent_before_replace = absolute.parent.lstat()
        if (
            _stat_is_reparse(parent_before_replace)
            or not stat.S_ISDIR(parent_before_replace.st_mode)
            or not _same_path_identity(parent_before, parent_before_replace)
        ):
            raise ValueError("private JSONL置換前にdirectory identityが変更されました")
        if expected is None:
            try:
                target_before = absolute.lstat()
            except FileNotFoundError:
                target_before = None
            if target_before is not None:
                raise FileExistsError("private JSONLがatomic commit前に作成されました")
        else:
            _assert_jsonl_snapshot_unchanged(expected)
            target_before = _regular_file_metadata(absolute)
            if not _same_regular_file_binding(expected.metadata, target_before):
                raise ValueError("private JSONLで競合変更を検出しました")
        os.replace(temporary, absolute)
        ensure_no_reparse_components(absolute)
        target_after = absolute.lstat()
        parent_after = absolute.parent.lstat()
        if (
            _stat_is_reparse(target_after)
            or not stat.S_ISREG(target_after.st_mode)
            or int(target_after.st_nlink) != 1
            or int(target_after.st_size) != total
            or not _same_path_identity(temporary_identity, target_after)
            or _stat_is_reparse(parent_after)
            or not stat.S_ISDIR(parent_after.st_mode)
            or not _same_path_identity(parent_before, parent_after)
        ):
            raise ValueError("private JSONL置換後のidentityが一致しません")
    finally:
        try:
            remaining = temporary.lstat()
        except OSError:
            remaining = None
        if (
            remaining is not None
            and temporary_identity is not None
            and not _stat_is_reparse(remaining)
            and stat.S_ISREG(remaining.st_mode)
            and _same_path_identity(temporary_identity, remaining)
        ):
            try:
                temporary.unlink()
            except OSError:
                pass


def _append_jsonl(path: Path, values: Iterable[Mapping[str, Any]]) -> None:
    """private JSONLをstreaming atomic rewriteで追記する。"""

    _atomic_rewrite_jsonl(path, values, append=True)


def _validate_jsonl_snapshot(path: Path) -> _JsonlFileSnapshot:
    """recordを保持せずprivate JSONL全体をstrict検証する。"""

    return _stream_private_jsonl(path, lambda _item, _line_number: None)


def _bounded_jsonl_snapshot(
    path: Path,
) -> tuple[list[dict[str, Any]], _JsonlFileSnapshot]:
    """private JSONLをstreaming parseし、必要なrecordだけ保持する。"""

    rows: list[dict[str, Any]] = []
    snapshot = _stream_private_jsonl(
        path,
        lambda item, _line_number: rows.append(item),
    )
    return rows, snapshot


def _replace_jsonl(path: Path, values: Iterable[Mapping[str, Any]]) -> None:
    """private JSONL全体をstreaming atomic rewriteで置換する。"""

    _atomic_rewrite_jsonl(path, values, append=False)


def _atomic_private_json(path: Path, value: Mapping[str, Any]) -> None:
    """private JSON cacheをbounded snapshotへ束縛してatomicに保存する。"""

    try:
        present = path.lstat() is not None
    except FileNotFoundError:
        present = False
    snapshot = _bounded_json_snapshot(path) if present else None
    _atomic_replace_bytes(
        path,
        _json_bytes(dict(value)),
        expected_snapshot=snapshot,
        maximum_bytes=MAX_JSON_OBJECT_SIZE,
        require_absent=snapshot is None,
    )


def _write_program_function_shards(
    result_path: Path,
    functions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Write a complete function inventory as bounded private JSONL shards."""

    if not 0 < MAX_PROGRAM_FUNCTION_SHARD_BYTES <= MAX_PRIVATE_RAW_BYTES:
        raise ValueError("program function shard byte limit is invalid")
    shards: list[dict[str, Any]] = []
    current: list[Mapping[str, Any]] = []
    current_bytes = 0

    def flush() -> None:
        nonlocal current, current_bytes
        if not current:
            return
        shard_number = len(shards) + 1
        shard_name = f"program-functions-{shard_number:04d}.raw.jsonl"
        shard_path = result_path.with_name(shard_name)
        _replace_jsonl(shard_path, current)
        snapshot = _stream_private_jsonl(
            shard_path,
            lambda _item, _line_number: None,
        )
        if snapshot.size > MAX_PROGRAM_FUNCTION_SHARD_BYTES:
            raise ValueError("program function shard exceeded its byte limit")
        shards.append(
            {
                "name": shard_name,
                "sha256": snapshot.sha256,
                "size": snapshot.size,
                "record_count": snapshot.record_count,
            }
        )
        current = []
        current_bytes = 0

    for value in functions:
        if not isinstance(value, Mapping):
            raise TypeError("program function record must be a JSON object")
        encoded = _encode_private_jsonl_record(
            value,
            path=result_path,
            line_number=len(current) + 1,
        )
        if len(encoded) > MAX_PROGRAM_FUNCTION_SHARD_BYTES:
            raise ValueError("program function record exceeded the shard byte limit")
        if current and current_bytes + len(encoded) > MAX_PROGRAM_FUNCTION_SHARD_BYTES:
            flush()
        current.append(value)
        current_bytes += len(encoded)
    flush()
    if sum(int(item["record_count"]) for item in shards) != len(functions):
        raise ValueError("program function shard record count is inconsistent")
    return {
        "format": "private-jsonl-shards-v1",
        "record_count": len(functions),
        "shards": shards,
    }


def _persist_program_result(path: Path, value: Mapping[str, Any]) -> None:
    """Persist a program result without exceeding the bounded JSON object limit."""

    normalized = dict(value)
    normalized.pop("function_records_artifact", None)
    functions = normalized.get("functions")
    if not isinstance(functions, list):
        raise TypeError("program result functions must be a list")
    encoded = _json_bytes(normalized)
    if len(encoded) <= MAX_PROGRAM_RESULT_INLINE_BYTES:
        _atomic_private_json(path, normalized)
        return
    artifact = _write_program_function_shards(path, functions)
    normalized["functions"] = []
    normalized["function_records_artifact"] = artifact
    _atomic_private_json(path, normalized)


def _load_program_result(
    path: Path,
) -> tuple[dict[str, Any], _JsonFileSnapshot]:
    """Load a bounded program result and strictly hydrate external function shards."""

    snapshot = _bounded_json_snapshot(path)
    result = snapshot.document
    artifact = result.get("function_records_artifact")
    if artifact is None:
        return result, snapshot
    if not isinstance(artifact, Mapping):
        raise ValueError("program function artifact manifest must be an object")
    if artifact.get("format") != "private-jsonl-shards-v1":
        raise ValueError("program function artifact format is unsupported")
    if result.get("functions") not in (None, []):
        raise ValueError("externalized program result contains inline functions")
    expected_count = artifact.get("record_count")
    shards = artifact.get("shards")
    if type(expected_count) is not int or expected_count < 0:
        raise ValueError("program function artifact record count is invalid")
    if not isinstance(shards, list) or (expected_count and not shards):
        raise ValueError("program function artifact shard list is invalid")
    functions: list[dict[str, Any]] = []
    observed_names: set[str] = set()
    for index, item in enumerate(shards, start=1):
        if not isinstance(item, Mapping):
            raise ValueError("program function shard manifest entry is invalid")
        expected_name = f"program-functions-{index:04d}.raw.jsonl"
        name = item.get("name")
        if name != expected_name or name in observed_names:
            raise ValueError("program function shard name is invalid")
        observed_names.add(name)
        shard_path = path.with_name(name)
        rows, shard_snapshot = _bounded_jsonl_snapshot(shard_path)
        if (
            item.get("sha256") != shard_snapshot.sha256
            or item.get("size") != shard_snapshot.size
            or item.get("record_count") != shard_snapshot.record_count
        ):
            raise ValueError("program function shard manifest does not match the file")
        functions.extend(rows)
    if len(functions) != expected_count:
        raise ValueError("program function artifact record count does not match")
    if int(result.get("function_inventory_count") or 0) != expected_count:
        raise ValueError("program function inventory count does not match")
    _assert_snapshot_unchanged(snapshot, context="program function shard hydration")
    result["functions"] = functions
    return result, snapshot


def _decompile_chunk(
    client: GhidraMcpClient,
    program: str,
    chunk: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """MCP上限内の関数群を逆コンパイルし、失敗状態を含む全recordを返す。"""

    addresses = ",".join(str(item["address"]) for item in chunk)
    batch_timed_out = False
    try:
        response = client.get(
            "/batch_decompile",
            functions=addresses,
            program=program,
        )
    except GhidraMcpError as error:
        batch_timed_out = _request_timed_out(error)
        response = {}
    if not isinstance(response, Mapping):
        response = {}
    rows = []
    for item in chunk:
        address = str(item["address"])
        pseudocode = str(response.get(address) or "")
        if not pseudocode and batch_timed_out:
            error_text = "GhidraMcpBatchTimeout"
        elif not pseudocode:
            try:
                pseudocode = str(
                    client.get(
                        "/decompile_function",
                        address=address,
                        program=program,
                        timeout=120,
                    )
                    or ""
                )
            except GhidraMcpError as error:
                pseudocode = ""
                error_text = type(error).__name__
            else:
                error_text = None
        else:
            error_text = None
        status, warnings = _decompile_status(pseudocode)
        rows.append(
            {
                "address": address,
                "name": str(item.get("name") or "unknown"),
                "status": status,
                "warnings": warnings,
                "error": error_text,
                "pseudocode": pseudocode,
                "program_selector": program,
            }
        )
    return rows


def _decompile_execution_plan(client: GhidraMcpClient, target_count: int) -> tuple[int, int]:
    """MCP transport timeout内へ収まるbatch sizeと並列数を保守的に選ぶ。

    GhidraMCP 5.14.2の ``batch_decompile`` は1関数ごとに最大30秒待ち、HTTP
    応答を返すまで最大20関数を直列処理する。短いtransport timeoutで20件を要求
    するとclient切断後もserver処理が継続し、その直後のfallback要求まで滞留する。
    server側の最悪時間と60秒の余裕をtransport budgetへ収める。
    """

    transport_timeout = int(getattr(client, "timeout", 3600))
    function_budget = max(
        1,
        (transport_timeout - DECOMPILE_TRANSPORT_MARGIN_SECONDS)
        // BATCH_DECOMPILE_FUNCTION_TIMEOUT_SECONDS,
    )
    batch_size = min(DECOMPILE_BATCH_SIZE, function_budget)
    chunk_count = max(1, math.ceil(max(0, target_count) / batch_size))
    worker_budget = max(1, function_budget // batch_size)
    workers = min(DECOMPILE_WORKERS, chunk_count, worker_budget)
    return batch_size, workers


def _decompile_all(
    client: GhidraMcpClient,
    program: str,
    functions: list[dict[str, Any]],
    raw_path: Path,
) -> dict[str, dict[str, Any]]:
    existing = _load_jsonl(raw_path)
    targets = [
        item
        for item in functions
        if not bool(item.get("isExternal"))
        and not bool(item.get("isThunk"))
        and str(item.get("address")) not in existing
    ]
    batch_size, workers = _decompile_execution_plan(client, len(targets))
    chunks = [targets[start : start + batch_size] for start in range(0, len(targets), batch_size)]
    initial_saved = len(existing)
    processed = 0
    if not chunks:
        return existing
    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="ghidra-decompile",
    ) as executor:
        futures = [executor.submit(_decompile_chunk, client, program, chunk) for chunk in chunks]
        for future in as_completed(futures):
            rows = future.result()
            _append_jsonl(raw_path, rows)
            for row in rows:
                existing[str(row["address"])] = row
            processed += len(rows)
            print(
                json.dumps(
                    {
                        "phase": "decompile",
                        "program_selector": program,
                        "completed": processed,
                        "total": len(targets),
                        "previously_saved": initial_saved,
                        "overall_completed": initial_saved + processed,
                        "overall_total": initial_saved + len(targets),
                        "workers": workers,
                        "batch_size": batch_size,
                        "executed": False,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
    return existing


def _token_value(operand: Any) -> Any:
    value = getattr(operand, "value", operand)
    if isinstance(value, float) and not math.isfinite(value):
        if math.isnan(value):
            return "<nan>"
        return "<positive_infinity>" if value > 0 else "<negative_infinity>"
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_token_value(item) for item in value]
    return str(value)


def _bounded_managed_cil_raw_instructions(
    instructions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    total = len(instructions)
    stored = [dict(value) for value in instructions[:MAX_MANAGED_CIL_RAW_INSTRUCTIONS_PER_METHOD]]
    return {
        "instructions": stored,
        "instruction_count": total,
        "instructions_truncated": len(stored) < total,
    }


def _method_owner_map(pe: dnfile.dnPE) -> dict[int, str]:
    owners: dict[int, str] = {}
    table = getattr(getattr(pe.net, "mdtables", None), "TypeDef", None)
    for row in getattr(table, "rows", []) or []:
        full_name = ".".join(value for value in (str(row.TypeNamespace), str(row.TypeName)) if value)
        for reference in getattr(row, "MethodList", ()) or ():
            owners[int(reference.row_index)] = full_name
    return owners


def _token_name(pe: dnfile.dnPE, token: int) -> str:
    table_id = (token >> 24) & 0xFF
    row_id = token & 0xFFFFFF
    names = {0x06: "MethodDef", 0x0A: "MemberRef", 0x2B: "MethodSpec"}
    table_name = names.get(table_id)
    table = getattr(getattr(pe.net, "mdtables", None), table_name, None) if table_name else None
    rows = getattr(table, "rows", None)
    if not rows or not 1 <= row_id <= len(rows):
        return f"token:0x{token:08x}"
    row = rows[row_id - 1]
    name = str(getattr(row, "Name", f"row_{row_id}"))
    owner = getattr(row, "Class", None) or getattr(row, "Method", None)
    owner_row = getattr(owner, "row", None)
    owner_name = ""
    if owner_row is not None:
        owner_name = ".".join(
            str(value)
            for value in (
                getattr(owner_row, "TypeNamespace", ""),
                getattr(owner_row, "TypeName", ""),
            )
            if value
        )
    return f"{owner_name}.{name}".strip(".")


@_contain_parser_diagnostics
def _managed_cil_records(data: bytes, raw_path: Path, layer_sha256: str) -> list[dict[str, Any]]:
    """全managed methodのCILを静的に列挙し、raw命令列をprivate JSONLへ保存する。"""

    try:
        pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    except Exception:
        return []
    if not getattr(pe, "net", None):
        return []
    method_table = getattr(getattr(pe.net, "mdtables", None), "MethodDef", None)
    rows = getattr(method_table, "rows", None)
    if not rows:
        return []
    owners = _method_owner_map(pe)
    records = []
    raw_rows = []
    for index, row in enumerate(rows, start=1):
        token = 0x06000000 | index
        token_text = f"0x{token:08x}"
        owner = owners.get(index, "")
        name = str(getattr(row, "Name", f"method_{index}"))
        rva = int(getattr(row, "Rva", 0) or 0)
        function_id = f"{layer_sha256}:cil:{token_text}"
        if not rva:
            records.append(
                {
                    "function_id": function_id,
                    "name": f"{owner}.{name}".strip("."),
                    "token": token_text,
                    "role": "managed_method_without_body",
                    "summary_ja": SUMMARY_BY_ROLE["managed_method_without_body"],
                    "logic_steps_ja": [
                        "CLR metadataのMethodDefを確認しました。",
                        "RVAがないためCIL本体の逆アセンブル対象外として記録しました。",
                    ],
                    "source": "dnfile/dncil",
                    "tool": "bounded_managed_cil_static_parser",
                    "program_selector": f"sha256:{layer_sha256}",
                    "confidence": "confirmed_metadata_inventory",
                    "decompilation_status": "no_managed_body",
                    "analysis_kind": "managed_cil",
                    "source_program_sha256": layer_sha256,
                }
            )
            continue
        instructions = []
        calls = []
        normalized = []
        error_name = None
        try:
            offset = int(pe.get_offset_from_rva(rva))
            body = read_method_body_from_bytes(data[offset:])
            for instruction in list(getattr(body, "instructions", ()) or ()):
                opcode = str(getattr(getattr(instruction, "opcode", None), "name", "unknown"))
                operand = _token_value(getattr(instruction, "operand", None))
                rendered_operand: Any = operand
                if opcode.casefold() == "ldstr":
                    rendered_operand = "<str>"
                elif opcode.casefold() in {"call", "callvirt", "newobj"} and isinstance(operand, int):
                    rendered_operand = _token_name(pe, operand)
                    calls.append(rendered_operand)
                elif isinstance(operand, (int, float)):
                    rendered_operand = "<num>"
                elif isinstance(operand, list):
                    rendered_operand = ["<target>" for _ in operand]
                instructions.append(
                    {
                        "offset": str(getattr(instruction, "offset", "")),
                        "opcode": opcode,
                        "operand": operand,
                    }
                )
                normalized.append(f"{opcode} {rendered_operand}" if rendered_operand is not None else opcode)
        except Exception as error:
            error_name = type(error).__name__
        status = "succeeded" if error_name is None else "failed_malformed_cil"
        role = _classify_role(f"{owner}.{name}", calls, "\n".join(normalized))
        steps = _logic_steps("\n".join(normalized), calls, status, analysis_kind="managed_cil")
        records.append(
            {
                "function_id": function_id,
                "name": f"{owner}.{name}".strip("."),
                "token": token_text,
                "role": role,
                "summary_ja": SUMMARY_BY_ROLE[role],
                "logic_steps_ja": steps,
                "pseudocode": "\n".join(normalized),
                "callees": sorted(set(calls)),
                "api_calls": sorted(set(calls)),
                "source": "dnfile/dncil",
                "tool": "bounded_managed_cil_static_parser",
                "program_selector": f"sha256:{layer_sha256}",
                "confidence": (
                    "confirmed_static_cil_disassembly"
                    if status == "succeeded"
                    else "confirmed_metadata_cil_parse_failed"
                ),
                "decompilation_status": status,
                "decompilation_error": error_name,
                "analysis_kind": "managed_cil",
                "source_program_sha256": layer_sha256,
                "instruction_count": len(instructions),
                "next_analysis": (
                    ""
                    if status == "succeeded"
                    else "metadata保護または破損境界を確認し、別のstatic CIL parserでcross-checkします。"
                ),
            }
        )
        raw_rows.append(
            {
                "function_id": function_id,
                "token": token_text,
                "owner": owner,
                "name": name,
                "rva": hex(rva),
                "status": status,
                "error": error_name,
                **_bounded_managed_cil_raw_instructions(instructions),
                "executed": False,
                "emulated": False,
            }
        )
    _replace_jsonl(raw_path, raw_rows)
    return records


def _classify_role(name: str, calls: Iterable[str], pseudocode: str) -> str:
    """単なる部分文字列でなく、member/API境界に基づいて挙動役割を返す。"""

    if LIBRARY_RE.search(name) or re.search(
        r"(?i)(?:^|[.:])(?:ctor|cctor)(?:$|\()",
        name,
    ):
        return "compiler_or_library_code"
    if ROLE_PATTERNS[0][1].search(name):
        return "entrypoint"
    name_role = _semantic_symbol_role(name, function_name=True)
    if name_role is not None:
        return name_role
    evidence_roles: set[str] = set()
    for call in calls:
        call_role = _semantic_symbol_role(str(call), function_name=False)
        if call_role is not None:
            evidence_roles.add(call_role)
    for call_match in re.finditer(
        r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_:.!@$<>-]{0,255})\s*\(",
        pseudocode[:50_000],
    ):
        call_role = _semantic_symbol_role(call_match.group(1), function_name=False)
        if call_role is not None:
            evidence_roles.add(call_role)
    for role in (
        "command_dispatch_or_handler",
        "persistence",
        "process_or_memory_operation",
        "network_communication",
        "cryptographic_transform",
        "anti_analysis",
        "config_or_data_transform",
        "file_operation",
    ):
        if role in evidence_roles:
            return role
    return "general_internal_logic"


def _semantic_symbol_leaf(value: str) -> tuple[str, list[str], str]:
    """qualified symbolから正規化leaf、camel token、full canonicalを返す。"""

    rendered = value.strip().split("(", 1)[0]
    leaf_parts = [part for part in re.split(r"(?:::|[.!/\\])", rendered) if part]
    leaf = leaf_parts[-1] if leaf_parts else rendered
    leaf = re.sub(r"^_+|@\d+$", "", leaf)
    tokenized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", leaf)
    tokens = [token.casefold() for token in re.split(r"[^A-Za-z0-9]+", tokenized) if token]
    canonical = re.sub(r"[^a-z0-9]", "", leaf.casefold())
    full_canonical = re.sub(r"[^a-z0-9]", "", rendered.casefold())
    return canonical, tokens, full_canonical


def _api_leaf_matches(canonical: str, values: set[str]) -> bool:
    """stdcallおよびWindows A/W suffixだけを許容してAPI leafを照合する。"""

    if canonical in values:
        return True
    return bool(len(canonical) > 1 and canonical[-1] in {"a", "w"} and canonical[:-1] in values)


def _semantic_symbol_role(value: str, *, function_name: bool) -> str | None:
    """namespace中の単語を能力へ誤昇格させず、実APIまたはleaf動詞だけを分類する。"""

    canonical, tokens, full_canonical = _semantic_symbol_leaf(value)
    token_set = set(tokens)
    network_apis = {
        "socket",
        "connect",
        "send",
        "recv",
        "sendto",
        "recvfrom",
        "wsastartup",
        "getaddrinfo",
        "gethostbyname",
        "dnsquery",
        "internetopen",
        "internetconnect",
        "httpopenrequest",
        "httpsendrequest",
        "internetreadfile",
        "winhttpopen",
        "winhttpconnect",
        "winhttpopenrequest",
        "winhttpsendrequest",
        "winhttpreceiveresponse",
        "urldownloadtofile",
    }
    screenconnect_context = "screenconnect" in full_canonical
    if _api_leaf_matches(canonical, network_apis) and not (
        screenconnect_context and canonical.rstrip("aw") == "connect"
    ):
        return "network_communication"
    if (
        function_name
        and not screenconnect_context
        and token_set
        & {
            "socket",
            "connect",
            "send",
            "recv",
            "receive",
            "download",
            "upload",
        }
    ):
        return "network_communication"

    command_apis = {
        "shellexecute",
        "winexec",
        "system",
        "popen",
        "runcommandlineprogram",
    }
    if (
        _api_leaf_matches(canonical, command_apis)
        or function_name
        and token_set
        & {
            "command",
            "dispatch",
            "handler",
            "shell",
            "execute",
        }
    ):
        return "command_dispatch_or_handler"

    if function_name and token_set & {
        "config",
        "setting",
        "parse",
        "decode",
        "decrypt",
        "unpack",
        "deserialize",
        "resource",
        "payload",
    }:
        return "config_or_data_transform"

    cryptographic_apis = {
        "cryptdecrypt",
        "cryptunprotectdata",
        "bcryptdecrypt",
        "rsadecrypt",
    }
    if (
        _api_leaf_matches(canonical, cryptographic_apis)
        or function_name
        and token_set
        & {
            "aes",
            "rsa",
            "rc4",
            "chacha",
            "xor",
            "base64",
            "crypt",
            "cipher",
            "hash",
            "md5",
            "sha256",
        }
    ):
        return "cryptographic_transform"

    process_apis = {
        "createprocess",
        "createremotethread",
        "createprocesswithtoken",
        "createprocessasuser",
        "virtualalloc",
        "virtualallocex",
        "virtualprotect",
        "virtualprotectex",
        "writeprocessmemory",
        "queueuserapc",
        "ntmapviewofsection",
        "loadlibrary",
        "createthread",
    }
    qualified_process_apis = {
        "systemdiagnosticsprocessstart",
    }
    if (
        _api_leaf_matches(canonical, process_apis)
        or full_canonical in qualified_process_apis
        or function_name
        and token_set
        & {
            "inject",
            "hollow",
            "processcreate",
            "remotethread",
        }
    ):
        return "process_or_memory_operation"

    persistence_apis = {
        "createservice",
        "startservice",
        "openscmanager",
        "regsetvalue",
        "regcreatekey",
        "schtasks",
    }
    persistence_name = canonical in {
        "persist",
        "persistence",
        "autorun",
        "runkey",
        "installservice",
        "registerservice",
        "createservice",
    }
    if _api_leaf_matches(canonical, persistence_apis) or function_name and persistence_name:
        return "persistence"

    anti_analysis_apis = {
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "queryperformancecounter",
        "cpuid",
    }
    if (
        _api_leaf_matches(canonical, anti_analysis_apis)
        or function_name
        and token_set
        & {
            "antidebug",
            "sandboxcheck",
            "vmwarecheck",
            "virtualboxcheck",
        }
    ):
        return "anti_analysis"

    file_apis = {
        "createfile",
        "readfile",
        "writefile",
        "deletefile",
        "movefile",
        "copyfile",
        "findfirstfile",
        "findnextfile",
    }
    if _api_leaf_matches(canonical, file_apis):
        return "file_operation"
    if (
        function_name
        and len(tokens) >= 2
        and tokens[0]
        in {
            "create",
            "read",
            "write",
            "delete",
            "move",
            "copy",
        }
        and tokens[1] in {"file", "directory", "path"}
    ):
        return "file_operation"
    return None


def _logic_steps(
    pseudocode: str,
    callees: Iterable[str],
    status: str,
    *,
    analysis_kind: str = "ghidra_native",
) -> list[str]:
    steps = [
        (
            "dnfile/dncilでmetadata tokenとCIL method境界を確認しました。"
            if analysis_kind == "managed_cil"
            else "Ghidra MCPで明示的なprogram selectorを指定し、関数境界を確認しました。"
        )
    ]
    if status == "succeeded":
        steps.append("関数本体を静的に逆コンパイルまたは逆アセンブルしました。")
    elif status in {"no_managed_body", "excluded_external_or_thunk"}:
        steps.append("関数本体を持たない対象としてinventoryへ残しました。")
    else:
        steps.append("逆コンパイルを試行し、失敗または不完全なcontrol flowを記録しました。")
    lowered = pseudocode.casefold()
    if re.search(r"\bif\b|\bswitch\b|\bcase\b|\bbr(?:true|false)?\b", lowered):
        steps.append("条件分岐またはdispatcher形状を確認しました。")
    if re.search(r"\bfor\b|\bwhile\b|\bdo\b|\bloop\b|\bbr\.s\b", lowered):
        steps.append("反復または後方分岐を含むcontrol flowを確認しました。")
    unique_calls = sorted({str(value) for value in callees if value})[:16]
    if unique_calls:
        steps.append(
            "主要call関係を確認しました: " + "、".join(redact_static_text(value) for value in unique_calls) + "。"
        )
    if re.search(r"\btry\b|\bcatch\b|\bthrow\b|\bleave\b", lowered):
        steps.append("例外処理または異常終了経路を確認しました。")
    if re.search(r"\breturn\b|\bret\b", lowered):
        steps.append("return経路と結果の利用境界を確認しました。")
    return steps


def _next_analysis(status: str, pseudocode: str) -> str:
    if status == "succeeded":
        return ""
    if ".net clr managed code" in pseudocode.casefold():
        return "native表示ではなくCLR metadataとCIL method bodyを優先して確認します。"
    if status == "limited_bad_instruction_or_flow":
        return "packer／VM／indirect flowの影響を確認し、復元layerまたは追加disassemblyで再解析します。"
    return "対象addressの境界、language、loader、packer状態を再確認して個別decompileします。"


def _program_records(
    program_object: ProgramObject,
    program_selector: str,
    functions: list[dict[str, Any]],
    decompilations: Mapping[str, Mapping[str, Any]],
    call_graph: Mapping[str, Any],
    opcode_hashes: Mapping[str, Any],
    selection_by_address: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    address_to_function = {
        str(item["address"]): f"{program_object.sha256}:ghidra:{item['address']}" for item in functions
    }
    callers: dict[str, list[str]] = defaultdict(list)
    callees: dict[str, list[str]] = defaultdict(list)
    api_calls: dict[str, list[str]] = defaultdict(list)
    for edge in call_graph.get("edges", []) if isinstance(call_graph, Mapping) else []:
        if not isinstance(edge, Mapping):
            continue
        caller_addr = str(edge.get("caller_addr") or "")
        callee_addr = str(edge.get("callee_addr") or "")
        callee_name = str(edge.get("callee_name") or callee_addr)
        caller_id = address_to_function.get(caller_addr)
        callee_id = address_to_function.get(callee_addr)
        if not caller_id:
            continue
        if callee_id:
            callees[caller_addr].append(callee_id)
            callers[callee_addr].append(caller_id)
        elif callee_name:
            callees[caller_addr].append(callee_name)
            api_calls[caller_addr].append(callee_name)
    hashes = {
        str(item.get("address")): item for item in opcode_hashes.get("functions", []) if isinstance(item, Mapping)
    }
    records = []
    for item in functions:
        address = str(item.get("address") or "unknown")
        name = str(item.get("name") or "unknown")
        external_or_thunk = bool(item.get("isExternal")) or bool(item.get("isThunk"))
        decompiled = dict(decompilations.get(address, {}))
        pseudocode = str(decompiled.get("pseudocode") or "")
        status = (
            "excluded_external_or_thunk"
            if external_or_thunk
            else str(decompiled.get("status") or "failed_not_attempted")
        )
        related_calls = sorted(set(callees[address]))
        related_apis = sorted(set(api_calls[address]))
        role = (
            "external_api_or_thunk"
            if external_or_thunk
            else _classify_role(name, related_calls + related_apis, pseudocode)
        )
        hash_row = hashes.get(address, {})
        selection = dict((selection_by_address or {}).get(address, {}))
        records.append(
            {
                "function_id": f"{program_object.sha256}:ghidra:{address}",
                "name": name,
                "address": address,
                "role": role,
                "summary_ja": SUMMARY_BY_ROLE[role],
                "logic_steps_ja": _logic_steps(
                    pseudocode,
                    related_calls + related_apis,
                    status,
                ),
                "pseudocode": pseudocode,
                "callers": sorted(set(callers[address])),
                "callees": related_calls,
                "api_calls": related_apis,
                "source": "ghidra-mcp",
                "tool": "ghidra-mcp",
                "program_selector": program_selector,
                "confidence": (
                    "confirmed_static_decompilation"
                    if status == "succeeded"
                    else "confirmed_boundary_with_documented_decompile_limit"
                ),
                "decompilation_status": status,
                "decompilation_warnings": list(decompiled.get("warnings") or []),
                "decompilation_error": decompiled.get("error"),
                "analysis_kind": "ghidra_native_or_loader_view",
                "source_program_sha256": program_object.sha256,
                "relationship": (
                    "root_program" if int(program_object.primary["depth"]) == 0 else "statically_recovered_program"
                ),
                "opcode_sha256": str(hash_row.get("hash") or ""),
                "instruction_count": int(hash_row.get("instruction_count") or 0),
                "next_analysis": _next_analysis(status, pseudocode),
                "selected_for_characteristic_analysis": bool(selection),
                "selection_reasons": list(selection.get("selection_reasons") or []),
                "selection_score": int(selection.get("selection_score") or 0),
            }
        )
    return records


def _wait_for_analysis(
    client: GhidraMcpClient,
    program: str,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("auto-analysisの待機上限は正の整数秒で指定してください")
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while (remaining := deadline - time.monotonic()) > 0:
        value = client.get(
            "/analysis_status",
            program=program,
            transport_timeout=min(float(getattr(client, "timeout", timeout_seconds)), remaining),
        )
        if isinstance(value, Mapping):
            last = dict(value)
            if not bool(value.get("analyzing")):
                return last
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    raise TimeoutError(f"Ghidra auto-analysis timeout: {program}")


def _native_zero_function_recovery_pending(result: Mapping[str, Any]) -> bool:
    """entry point関数回復証跡のない旧native 0件cacheか返す。"""

    return bool(
        result.get("analysis_mode") == "native_ghidra_with_optional_cil"
        and int(result.get("ghidra_function_inventory_count") or 0) == 0
        and int(result.get("managed_method_count") or 0) == 0
        and not isinstance(result.get("entry_point_function_recovery"), Mapping)
    )


def _terminalize_unavailable_native_zero_function_recovery(
    result_path: Path,
    cached: dict[str, Any],
) -> dict[str, Any]:
    """認証済みinputがない旧0件cacheへ再試行不要の証跡を保存する。"""

    recovery: dict[str, Any] = {
        "schema_version": 1,
        "trigger": "native_function_inventory_empty_after_auto_analysis",
        "status": "not_attempted",
        "reason": "input_cache_unavailable_for_recovery",
        "attempted": False,
        "initial_function_count": 0,
        "final_function_count": 0,
    }
    program_selector = cached.get("program_selector")
    if isinstance(program_selector, str) and program_selector:
        recovery["program_selector"] = program_selector
    cached["entry_point_function_recovery"] = recovery
    cached["status"] = "partial"
    coverage = cached.setdefault("retrieval_coverage", {})
    if isinstance(coverage, dict):
        coverage["functions"] = {
            "endpoint": "/list_functions_enhanced",
            "program_selector": cached.get("program_selector"),
            "page_size": FUNCTION_PAGE_SIZE,
            "page_count": 0,
            "item_count": 0,
            "terminal_short_page_observed": False,
            "complete": False,
            "endpoint_invoked": False,
            "documented_limit": "input_cache_unavailable_for_function_reinventory",
        }
    ensure_characteristic_selection(cached)
    _persist_program_result(result_path, cached)
    return cached


def _unavailable_zero_function_recovery_terminal(result: Mapping[str, Any]) -> bool:
    recovery = result.get("entry_point_function_recovery")
    coverage = result.get("retrieval_coverage")
    functions = coverage.get("functions") if isinstance(coverage, Mapping) else None
    return bool(
        result.get("status") == "partial"
        and isinstance(recovery, Mapping)
        and recovery.get("reason") == "input_cache_unavailable_for_recovery"
        and isinstance(functions, Mapping)
        and functions.get("complete") is False
        and functions.get("documented_limit") == "input_cache_unavailable_for_function_reinventory"
    )


def _terminalize_unavailable_call_graph_retrieval(
    result_path: Path,
    cached: dict[str, Any],
) -> dict[str, Any]:
    """再取得できない旧cacheへcall graph未取得の明示的partial証跡を保存する。"""

    coverage = cached.get("retrieval_coverage")
    if not isinstance(coverage, dict):
        coverage = {}
        cached["retrieval_coverage"] = coverage
    call_graph_coverage = _legacy_call_graph_partial_coverage(cached)
    coverage["call_graph"] = call_graph_coverage
    cached["status"] = "partial"
    cached["all_static_analysis_content_retained"] = False
    cached["call_graph_retrieval"] = {
        "status": "partial",
        "documented_limit": CALL_GRAPH_LEGACY_LIMIT,
        "retryable": True,
    }
    ensure_characteristic_selection(cached)
    _persist_program_result(result_path, cached)

    raw_index_path = result_path.with_name("ghidra-raw-index.json")
    try:
        raw_present = raw_index_path.lstat() is not None
    except FileNotFoundError:
        raw_present = False
    if raw_present:
        raw_index = _bounded_json_snapshot(raw_index_path).document
        raw_coverage = raw_index.get("retrieval_coverage")
        if not isinstance(raw_coverage, dict):
            raw_coverage = {}
            raw_index["retrieval_coverage"] = raw_coverage
        raw_coverage["call_graph"] = dict(call_graph_coverage)
        raw_index["all_static_analysis_content_retained"] = False
        _atomic_private_json(raw_index_path, raw_index)
    return cached


def analyze_program(
    client: GhidraMcpClient,
    item: ProgramObject,
    private_output: Path,
    project_root: str,
    *,
    analysis_timeout: int,
    skip_auto_analysis: bool = False,
) -> dict[str, Any]:
    """1つのPE layerをGhidra MCPで解析し、private raw成果物を保存する。"""

    output_dir = private_output / "objects" / item.sha256
    result_path = output_dir / "program-result.json"
    try:
        result_present = result_path.lstat() is not None
    except FileNotFoundError:
        result_present = False
    if result_present:
        cached, _result_snapshot = _load_program_result(result_path)
        call_graph_complete = _call_graph_retrieval_coverage_complete(cached)
        if _unavailable_zero_function_recovery_terminal(cached) and call_graph_complete:
            return cached
        legacy_complete = bool(cached.get("status") == "complete" and cached.get("mcp_responses_valid") is True)
        cached_complete = bool(
            legacy_complete and _function_inventory_coverage_complete(cached) and call_graph_complete
        )
        native_zero_recovery_pending = _native_zero_function_recovery_pending(cached)
        if legacy_complete and native_zero_recovery_pending and item.input_snapshot is None:
            cached = _terminalize_unavailable_native_zero_function_recovery(
                result_path,
                cached,
            )
            if not call_graph_complete:
                cached = _terminalize_unavailable_call_graph_retrieval(
                    result_path,
                    cached,
                )
            return cached
        if not call_graph_complete and item.input_snapshot is None:
            return _terminalize_unavailable_call_graph_retrieval(
                result_path,
                cached,
            )
        if cached_complete and not native_zero_recovery_pending:
            ensure_characteristic_selection(cached)
            _persist_program_result(result_path, cached)
            return cached
    staging_root = private_output / "import-staging"
    if not _same_or_nested(item.input_path, staging_root):
        raise ValueError("Ghidra MCP importはprivate staging pathに限定します")
    data, staging_snapshot = _bounded_regular_file_snapshot(
        item.input_path,
        max_bytes=item.size,
    )
    if (
        hashlib.sha256(data).hexdigest() != item.sha256
        or len(data) != item.size
        or item.input_snapshot is None
        or staging_snapshot.sha256 != item.input_snapshot.sha256
        or not _same_regular_file_binding(
            staging_snapshot.metadata,
            item.input_snapshot.metadata,
        )
    ):
        raise ValueError(f"Ghidra input hashが解析直前に一致しません: {item.sha256}")
    managed_cil_primary = _is_managed_pe(data)
    primary = item.primary
    case_sha = str(primary["case_sha256"])
    if int(primary["depth"]) == 0:
        folder = _safe_project_path(f"{project_root}/{case_sha[:8]}")
    else:
        folder = _safe_project_path(f"{project_root}/{case_sha[:8]}/layers/{item.sha256[:8]}")
    expected_program = _safe_project_path(f"{folder}/{item.input_path.name}")
    program: str | None = None
    import_mode = "preexisting_program"
    preopened_status_raw: Any = None
    try:
        preopened_status_raw = client.get("/analysis_status", program=expected_program)
        program = expected_program
    except GhidraMcpError:
        pass
    if program is None:
        try:
            opened = client.get("/open_program", path=expected_program, auto_analyze=False)
            program = str((opened or {}).get("path") or expected_program)
            import_mode = "opened_existing_program"
        except GhidraMcpError:
            import_body: dict[str, Any] = {
                "file_path": str(item.input_path.resolve()),
                "project_folder": folder,
                "auto_analyze": not managed_cil_primary and not skip_auto_analysis,
            }
            try:
                with _hold_staging_read_lock(staging_snapshot):
                    imported = client.post("/import_file", import_body)
                import_mode = "automatic_loader"
            except GhidraMcpError as automatic_error:
                # import処理は応答タイムアウト後もGhidra側で完了し得る。ここで
                # raw importへ切り替えると、同じ検体が「.0」付きで重複登録される。
                # 通信タイムアウトは再実行時の既存program検出に委ねる。
                if _request_timed_out(automatic_error):
                    _assert_regular_snapshot_unchanged(
                        staging_snapshot,
                        context="Ghidra MCP import失敗後",
                    )
                    raise
                raw_parameters = _raw_pe_import_parameters(data)
                if raw_parameters is None:
                    _assert_regular_snapshot_unchanged(
                        staging_snapshot,
                        context="Ghidra MCP import失敗後",
                    )
                    raise automatic_error
                try:
                    with _hold_staging_read_lock(staging_snapshot):
                        imported = client.post(
                            "/import_file",
                            {**import_body, **raw_parameters},
                        )
                finally:
                    _assert_regular_snapshot_unchanged(
                        staging_snapshot,
                        context="Ghidra MCP raw import後",
                    )
                import_mode = "raw_pe_fallback"
            _assert_regular_snapshot_unchanged(
                staging_snapshot,
                context="Ghidra MCP import応答後",
            )
            if not isinstance(imported, Mapping) or not imported.get("path"):
                raise GhidraMcpError(f"import responseにprogram pathがありません: {item.sha256}")
            program = _safe_project_path(str(imported["path"]))
    if program != expected_program:
        raise GhidraMcpError(f"program selectorが予期したpathと一致しません: {program} != {expected_program}")
    _assert_regular_snapshot_unchanged(
        staging_snapshot,
        context="Ghidra MCP import直後",
    )

    def _program_get(endpoint: str, **query: Any) -> Any:
        if managed_cil_primary:
            print(
                json.dumps(
                    {
                        "phase": "managed_ghidra_structure",
                        "state": "request",
                        "sha256": item.sha256,
                        "endpoint": endpoint,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        response = client.get(endpoint, program=program, **query)
        if managed_cil_primary:
            print(
                json.dumps(
                    {
                        "phase": "managed_ghidra_structure",
                        "state": "complete",
                        "sha256": item.sha256,
                        "endpoint": endpoint,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        return response

    if managed_cil_primary:
        raw_status = preopened_status_raw if preopened_status_raw is not None else _program_get("/analysis_status")
        status = dict(raw_status) if isinstance(raw_status, Mapping) else {}
        analysis_mode = "managed_cil_primary_with_ghidra_structure"
    elif skip_auto_analysis:
        raw_status = preopened_status_raw if preopened_status_raw is not None else _program_get("/analysis_status")
        status = dict(raw_status) if isinstance(raw_status, Mapping) else {}
        status["documented_limit"] = "auto_analysis_skipped_after_repeated_timeout"
        analysis_mode = "native_ghidra_limited_without_auto_analysis"
    else:
        status = _wait_for_analysis(
            client,
            program,
            timeout_seconds=analysis_timeout,
        )
        if bool(status.get("should_ask_to_analyze")) or not bool(status.get("analyzed", True)):
            client.post("/run_analysis", {}, program=program)
            status = _wait_for_analysis(
                client,
                program,
                timeout_seconds=analysis_timeout,
            )
        analysis_mode = "native_ghidra_with_optional_cil"
    if managed_cil_primary:
        functions = []
        function_coverage = {
            "endpoint": "/list_functions_enhanced",
            "program_selector": program,
            "page_size": 0,
            "page_count": 0,
            "item_count": 0,
            "terminal_short_page_observed": False,
            "complete": True,
            "endpoint_invoked": False,
            "source": "managed_cil_primary",
            "documented_limit": "native_function_inventory_not_applicable",
        }
    else:
        functions, function_coverage = _all_functions_with_coverage(
            client,
            program,
        )
    metadata_raw = _program_get("/get_metadata")
    metadata_before_entry_point_function_recovery: Any = None
    if not managed_cil_primary:
        _bind_function_metadata_coverage(
            function_coverage,
            metadata_raw,
            len(functions),
        )
    imports = _program_get("/list_imports", offset=0, limit=10000)
    exports = _program_get("/list_exports", offset=0, limit=10000)
    strings = [] if managed_cil_primary else client.get("/list_strings", offset=0, limit=100000, program=program)
    segments = _program_get("/list_segments", offset=0, limit=10000)
    entry_points = [] if managed_cil_primary else client.get("/get_entry_points", program=program)
    if managed_cil_primary:
        entry_function_recovery = {
            "schema_version": 1,
            "status": "not_applicable",
            "reason": "managed_cil_primary",
            "attempted": False,
            "initial_function_count": 0,
            "final_function_count": 0,
            "program_selector": program,
        }
        entry_function_recovery_raw = dict(entry_function_recovery)
    elif functions:
        entry_function_recovery = {
            "schema_version": 1,
            "status": "not_needed",
            "reason": "native_function_inventory_not_empty",
            "attempted": False,
            "initial_function_count": len(functions),
            "final_function_count": len(functions),
            "program_selector": program,
        }
        entry_function_recovery_raw = dict(entry_function_recovery)
    elif analysis_mode != "native_ghidra_with_optional_cil":
        entry_function_recovery = {
            "schema_version": 1,
            "status": "not_attempted",
            "reason": "auto_analysis_not_completed",
            "attempted": False,
            "initial_function_count": 0,
            "final_function_count": 0,
            "program_selector": program,
        }
        entry_function_recovery_raw = dict(entry_function_recovery)
    else:
        (
            functions,
            entry_function_recovery,
            entry_function_recovery_raw,
        ) = _recover_unique_entry_point_function(
            client,
            program,
            data,
            entry_points,
            segments,
        )
        if entry_function_recovery.get("status") == "recovered":
            recovered_functions, recovered_coverage = _all_functions_with_coverage(
                client,
                program,
            )
            if recovered_functions != functions:
                raise GhidraMcpError(
                    "entry point関数復元後の再取得inventoryが一致しません"
                )
            metadata_before_entry_point_function_recovery = metadata_raw
            metadata_raw = _program_get("/get_metadata")
            _bind_function_metadata_coverage(
                recovered_coverage,
                metadata_raw,
                len(recovered_functions),
            )
            functions = recovered_functions
            function_coverage = recovered_coverage
    if managed_cil_primary:
        ghidra_call_graph, call_graph_coverage = _managed_call_graph_with_coverage(program, analysis_mode)
        call_graph = dict(ghidra_call_graph)
        anti_analysis = {
            "status": "not_run_managed_cil_primary",
            "reason": "managed methodはCIL静的解析を正本とする",
        }
        api_chains = {
            "status": "not_run_managed_cil_primary",
            "reason": "managed methodのAPI callはCIL recordへ保持する",
        }
        opcode_hashes = _complete_opcode_hash_inventory(
            {"functions": [], "endpoint_returned": 0},
            functions,
            program,
        )
        selected_native = []
    else:
        ghidra_call_graph, call_graph_coverage = _get_full_call_graph_with_coverage(client, program)
        call_graph = dict(ghidra_call_graph)
        anti_analysis = client.get("/find_anti_analysis_techniques", program=program)
        api_chains = client.get("/analyze_api_call_chains", program=program)
        opcode_hashes = _all_opcode_hashes(client, program, functions)
        selected_native = select_characteristic_functions(
            functions,
            call_graph if isinstance(call_graph, Mapping) else {},
            entry_points,
            opcode_hashes if isinstance(opcode_hashes, Mapping) else {},
        )
    selection_by_address = {str(item["address"]): item for item in selected_native if item.get("address")}
    decompilations = (
        {}
        if managed_cil_primary
        else _decompile_all(
            client,
            program,
            selected_native,
            output_dir / "decompilations.raw.jsonl",
        )
    )
    cil_records = _managed_cil_records(
        data,
        output_dir / "cil-instructions.raw.jsonl",
        item.sha256,
    )
    for record in cil_records:
        record["program_selector"] = program
    records = _program_records(
        item,
        program,
        functions,
        decompilations,
        call_graph if isinstance(call_graph, Mapping) else {},
        opcode_hashes if isinstance(opcode_hashes, Mapping) else {},
        selection_by_address,
    )
    records.extend(cil_records)
    selected_ids = _mark_characteristic_records(records)
    raw_index = {
        "schema_version": SCHEMA_VERSION,
        "sha256": item.sha256,
        "program_selector": program,
        "metadata": metadata_raw,
        "analysis_status": status,
        "analysis_mode": analysis_mode,
        "import_mode": import_mode,
        "functions": functions,
        "ghidra_call_graph": ghidra_call_graph,
        "call_graph": call_graph,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "segments": segments,
        "entry_points": entry_points,
        "entry_point_function_recovery": entry_function_recovery_raw,
        "anti_analysis": anti_analysis,
        "api_call_chains": api_chains,
        "opcode_hashes": opcode_hashes,
        "characteristic_function_ids": selected_ids,
        "characteristic_function_count": len(selected_ids),
        "retrieval_coverage": {
            "functions": function_coverage,
            "call_graph": call_graph_coverage,
        },
        "characteristic_selection": [
            {
                "function_id": item.get("function_id"),
                "address_or_token": item.get("address") or item.get("token"),
                "role": item.get("role"),
                "selection_score": item.get("selection_score"),
                "selection_reasons": item.get("selection_reasons"),
            }
            for item in records
            if item.get("selected_for_characteristic_analysis") is True
        ],
        "decompilation_artifact": "decompilations.raw.jsonl",
        "cil_artifact": "cil-instructions.raw.jsonl" if cil_records else None,
        "sample_executed": False,
        "network_contacted": False,
    }
    if metadata_before_entry_point_function_recovery is not None:
        raw_index["metadata_before_entry_point_function_recovery"] = (
            metadata_before_entry_point_function_recovery
        )
    _atomic_private_json(output_dir / "ghidra-raw-index.json", raw_index)
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "mcp_responses_valid": True,
        "sha256": item.sha256,
        "size": item.size,
        "program_selector": program,
        "metadata": _parse_metadata(metadata_raw),
        "analysis_mode": analysis_mode,
        "import_mode": import_mode,
        "relationships": item.relationships,
        "functions": records,
        "function_inventory_count": len(records),
        "ghidra_function_inventory_count": len(functions),
        "managed_method_count": len(cil_records),
        "characteristic_function_ids": selected_ids,
        "characteristic_function_count": len(selected_ids),
        "ghidra_call_graph": ghidra_call_graph,
        "call_graph": call_graph,
        "entry_points": entry_points,
        "entry_point_function_recovery": entry_function_recovery,
        "imports": imports,
        "exports": exports,
        "segments": segments,
        "anti_analysis": anti_analysis,
        "api_call_chains": api_chains,
        "opcode_hashes": opcode_hashes,
        "retrieval_coverage": {
            "functions": function_coverage,
            "call_graph": call_graph_coverage,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "arbitrary_ghidra_scripts_enabled": False,
            "raw_results_private": True,
        },
    }
    ensure_characteristic_selection(result)
    _persist_program_result(result_path, result)
    try:
        if not managed_cil_primary:
            client.get("/save_program", program=program)
        client.post("/close_program", {"name": program})
    except GhidraMcpError:
        pass
    return result


def refresh_complete_program_artifacts(
    client: GhidraMcpClient,
    program_results: Mapping[str, dict[str, Any]],
    private_output: Path,
) -> dict[str, int]:
    """全programのページング対象を終端まで再取得し、生成果物へ保存する。"""

    totals: Counter[str] = Counter()
    endpoints = {
        "functions": "/list_functions_enhanced",
        "imports": "/list_imports",
        "exports": "/list_exports",
        "strings": "/list_strings",
        "segments": "/list_segments",
    }
    initial_limits = {
        "functions": FUNCTION_PAGE_SIZE,
        "imports": 10000,
        "exports": 10000,
        "strings": 100000,
        "segments": 10000,
    }
    for index, (digest, result) in enumerate(sorted(program_results.items()), start=1):
        program = _safe_project_path(str(result.get("program_selector") or ""))
        object_dir = private_output / "objects" / digest
        raw_index_path = object_dir / "ghidra-raw-index.json"
        raw_index = _bounded_json_snapshot(raw_index_path).document
        opened_program: str | None = None
        open_error: GhidraMcpError | None = None
        cached_functions = _page_values(
            raw_index.get("functions"),
            "/list_functions_enhanced",
        )
        cached_metadata_count = _metadata_function_count(raw_index.get("metadata"))
        metadata_refresh_required = bool(
            cached_metadata_count is not None
            and cached_metadata_count < len(cached_functions)
        )
        recovery = result.get("entry_point_function_recovery")
        recovered_function_coverage_refresh_required = bool(
            isinstance(recovery, Mapping)
            and recovery.get("status") == "recovered"
            and not _function_inventory_coverage_complete(result)
        )
        paging_cache_terminal = all(
            (
                (
                    _function_inventory_coverage_complete(result)
                    or len(_page_values(raw_index.get(name), endpoint)) < initial_limits[name]
                )
                and (
                    result.get("ghidra_function_inventory_count") is None
                    or len(_page_values(raw_index.get(name), endpoint))
                    == int(result.get("ghidra_function_inventory_count") or 0)
                )
            )
            if name == "functions"
            else len(_page_values(raw_index.get(name), endpoint)) < initial_limits[name]
            for name, endpoint in endpoints.items()
        )
        call_graph_cache_terminal = bool(
            _call_graph_retrieval_coverage_complete(result)
            or result.get("analysis_mode") == "managed_cil_primary_with_ghidra_structure"
        )
        initial_cache_terminal = (
            paging_cache_terminal
            and call_graph_cache_terminal
            and not metadata_refresh_required
            and not recovered_function_coverage_refresh_required
        )
        if initial_cache_terminal:
            open_error = GhidraMcpError("初回MCP応答で全ページング対象の終端到達を確認済みです")
        else:
            try:
                opened = client.get("/open_program", path=program, auto_analyze=False)
                opened_program = _safe_project_path(str((opened or {}).get("path") or program))
                if opened_program != program:
                    raise GhidraMcpError(f"完全取得時のprogram selectorが一致しません: {opened_program} != {program}")
            except GhidraMcpError as error:
                open_error = error
        metadata_for_coverage = raw_index.get("metadata")
        if opened_program is not None:
            metadata_for_coverage = client.get("/get_metadata", program=program)
        retrieved: dict[str, list[Any]] = {}
        coverage: dict[str, dict[str, Any]] = {}
        for name, endpoint in endpoints.items():
            managed_alternative = result.get(
                "analysis_mode"
            ) == "managed_cil_primary_with_ghidra_structure" and name in {"functions", "strings"}
            if managed_alternative:
                items = []
                endpoint_coverage = {
                    "endpoint": endpoint,
                    "program_selector": program,
                    "page_size": 0,
                    "page_count": 0,
                    "item_count": 0,
                    "terminal_short_page_observed": False,
                    "complete": True,
                    "source": "managed_cil_primary",
                    "endpoint_invoked": False,
                    "reason": ("managed CILを正本とするためGhidraの疑似native inventoryは取得しない"),
                }
                if name == "functions":
                    endpoint_coverage["documented_limit"] = "native_function_inventory_not_applicable"
            elif open_error is not None:
                items = _page_values(raw_index.get(name), endpoint)
                page_size = initial_limits[name]
                existing_coverage = raw_index.get("retrieval_coverage")
                existing_endpoint_coverage = (
                    existing_coverage.get("functions")
                    if name == "functions" and isinstance(existing_coverage, Mapping)
                    else None
                )
                if name == "functions" and isinstance(
                    existing_endpoint_coverage,
                    Mapping,
                ):
                    endpoint_coverage = dict(existing_endpoint_coverage)
                    endpoint_coverage["source"] = "authenticated_complete_function_inventory_cache"
                    endpoint_coverage["endpoint_invoked"] = True
                elif len(items) >= page_size:
                    raise open_error
                else:
                    endpoint_coverage = {
                        "endpoint": endpoint,
                        "program_selector": program,
                        "page_size": page_size,
                        "page_count": 1,
                        "item_count": len(items),
                        "terminal_short_page_observed": True,
                        "complete": True,
                        "source": "authenticated_initial_response_cache",
                        "endpoint_invoked": True,
                        "reason": ("初回MCP応答の項目数が要求上限未満であり、同一応答内で終端到達を確認した"),
                    }
            elif name == "functions":
                items, endpoint_coverage = _all_functions_with_coverage(
                    client,
                    program,
                )
            else:
                items, endpoint_coverage = _all_endpoint_items(
                    client,
                    endpoint,
                    program,
                    page_size=initial_limits[name],
                )
            if name == "functions" and not managed_alternative:
                _bind_function_metadata_coverage(
                    endpoint_coverage,
                    metadata_for_coverage,
                    len(items),
                )
            retrieved[name] = items
            coverage[name] = endpoint_coverage
            totals[name] += len(items)
        if result.get("analysis_mode") == "managed_cil_primary_with_ghidra_structure":
            ghidra_call_graph, call_graph_coverage = _managed_call_graph_with_coverage(
                program,
                "managed_cil_primary_with_ghidra_structure",
            )
        elif opened_program is not None:
            ghidra_call_graph, call_graph_coverage = _get_full_call_graph_with_coverage(client, program)
        elif _call_graph_retrieval_coverage_complete(result):
            ghidra_call_graph = dict(result["ghidra_call_graph"])
            call_graph_coverage = dict(result["retrieval_coverage"]["call_graph"])
        else:
            call_graph_coverage = _legacy_call_graph_partial_coverage(result)
            coverage["call_graph"] = call_graph_coverage
            for name, items in retrieved.items():
                raw_index[name] = items
            raw_index["retrieval_coverage"] = coverage
            raw_index["all_static_analysis_content_retained"] = False
            result["retrieval_coverage"] = coverage
            result["all_static_analysis_content_retained"] = False
            result["status"] = "partial"
            result["call_graph_retrieval"] = {
                "status": "partial",
                "documented_limit": CALL_GRAPH_LEGACY_LIMIT,
                "retryable": True,
            }
            _atomic_private_json(raw_index_path, raw_index)
            _persist_program_result(
                object_dir / "program-result.json",
                result,
            )
            if open_error is not None:
                raise open_error
            raise GhidraMcpError("call graph再取得証跡を確立できません")
        coverage["call_graph"] = call_graph_coverage
        totals["call_graph_edges"] += len(ghidra_call_graph["edges"])
        if open_error is not None:
            totals["promoted_cached_programs"] += 1
        refreshed_functions = retrieved["functions"]
        original_functions = _page_values(
            raw_index.get("functions"),
            "/list_functions_enhanced",
        )
        if refreshed_functions != original_functions:
            raise GhidraMcpError("function_inventory_changed_full_program_reanalysis_required")
        prior_function_count = result.get("ghidra_function_inventory_count")
        if prior_function_count is not None and (
            type(prior_function_count) is not int or prior_function_count != len(refreshed_functions)
        ):
            raise GhidraMcpError("program_result_function_count_changed_full_program_reanalysis_required")
        result["ghidra_function_inventory_count"] = len(refreshed_functions)
        opcode_hashes = _complete_opcode_hash_inventory(
            raw_index.get("opcode_hashes") if isinstance(raw_index, Mapping) else {},
            [item for item in raw_index.get("functions", []) if isinstance(item, Mapping)],
            program,
        )
        raw_index["opcode_hashes"] = opcode_hashes
        result["opcode_hashes"] = opcode_hashes
        raw_index["metadata"] = metadata_for_coverage
        result["metadata"] = _parse_metadata(metadata_for_coverage)
        for name, items in retrieved.items():
            raw_index[name] = items
        raw_index["ghidra_call_graph"] = ghidra_call_graph
        raw_index["call_graph"] = dict(ghidra_call_graph)
        raw_index.pop("call_graph_augmented_from_decompilation", None)
        raw_index["retrieval_coverage"] = coverage
        raw_index["all_static_analysis_content_retained"] = True
        result["imports"] = retrieved["imports"]
        result["exports"] = retrieved["exports"]
        result["segments"] = retrieved["segments"]
        result["ghidra_call_graph"] = ghidra_call_graph
        result["call_graph"] = dict(ghidra_call_graph)
        result.pop("call_graph_augmented_from_decompilation", None)
        result["retrieval_coverage"] = coverage
        result["all_static_analysis_content_retained"] = True
        result["status"] = "complete"
        result.pop("call_graph_retrieval", None)
        _atomic_private_json(raw_index_path, raw_index)
        _persist_program_result(object_dir / "program-result.json", result)
        if opened_program is not None:
            try:
                client.post("/close_program", {"name": opened_program})
            except GhidraMcpError:
                pass
        totals["programs"] += 1
        print(
            json.dumps(
                {
                    "phase": "complete_static_artifact_refresh",
                    "program": index,
                    "total": len(program_results),
                    "sha256": digest,
                    "counts": {name: len(items) for name, items in retrieved.items()},
                    "source": (
                        "authenticated_initial_response_cache" if open_error is not None else "ghidra_endpoint_refresh"
                    ),
                    "executed": False,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
    return dict(totals)


def _read_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    """private JSONLをbounded strict snapshotとして読み込む。"""

    try:
        present = path.lstat() is not None
    except FileNotFoundError:
        present = False
    return _bounded_jsonl_snapshot(path)[0] if present else []


CALL_EXPRESSION_RE = re.compile(r"(?<![\w])([A-Za-z_?$][A-Za-z0-9_.$@?<>:-]*)\s*\(")
IGNORED_CALL_EXPRESSIONS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "typeof",
    "catch",
}


def augment_program_result_call_graph(result: dict[str, Any]) -> dict[str, int]:
    """逆コンパイルcall式でGhidra call graphの欠落を補完する。"""

    retrieval_state = _call_graph_retrieval_state(result)
    if retrieval_state not in {"complete", "managed_not_applicable"}:
        raise GhidraMcpError("有効なcall graph取得証跡がないため補完を開始できません")
    ghidra_graph = result.get("ghidra_call_graph")
    current_graph = result.get("call_graph")
    if not _call_graph_schema_valid(current_graph):
        raise GhidraMcpError("補完元call_graphのschemaが不正です")
    if result.get("call_graph_augmented_from_decompilation") is not True and current_graph != ghidra_graph:
        raise GhidraMcpError("補完前call_graphが取得済みGhidra graphと一致しません")
    records = [
        item
        for item in result.get("functions", [])
        if isinstance(item, dict) and item.get("analysis_kind") == "ghidra_native_or_loader_view"
    ]
    name_to_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    address_to_record: dict[str, dict[str, Any]] = {}
    for record in records:
        name_to_records[str(record.get("name") or "").casefold()].append(record)
        address_to_record[str(record.get("address") or "")] = record
    import_by_name = {
        str(item.get("name") or "").casefold(): dict(item)
        for item in result.get("imports", [])
        if isinstance(item, Mapping) and item.get("name")
    }
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for value in ghidra_graph.get("edges", []):
        if not isinstance(value, Mapping):
            continue
        edge = dict(value)
        edge.setdefault("source", "ghidra_full_call_graph")
        key = (
            str(edge.get("caller_addr") or ""),
            str(edge.get("callee_addr") or ""),
            str(edge.get("callee_name") or ""),
        )
        edges[key] = edge
    for record in records:
        caller_addr = str(record.get("address") or "")
        caller_name = str(record.get("name") or "")
        pseudocode = str(record.get("pseudocode") or "")
        for call_name in CALL_EXPRESSION_RE.findall(pseudocode):
            lowered = call_name.casefold()
            if lowered in IGNORED_CALL_EXPRESSIONS or lowered == caller_name.casefold():
                continue
            candidates = name_to_records.get(lowered, [])
            if len(candidates) == 1:
                callee = candidates[0]
                callee_addr = str(callee.get("address") or "")
                edge = {
                    "caller_addr": caller_addr,
                    "caller_name": caller_name,
                    "callee_addr": callee_addr,
                    "callee_name": str(callee.get("name") or call_name),
                    "edge_kind": "internal",
                    "source": "decompiler_call_expression",
                    "unresolved": False,
                }
            elif lowered in import_by_name:
                imported = import_by_name[lowered]
                edge = {
                    "caller_addr": caller_addr,
                    "caller_name": caller_name,
                    "callee_addr": str(imported.get("address") or ""),
                    "callee_name": str(imported.get("name") or call_name),
                    "edge_kind": "import",
                    "source": "decompiler_call_expression",
                    "unresolved": False,
                }
            else:
                edge = {
                    "caller_addr": caller_addr,
                    "caller_name": caller_name,
                    "callee_addr": "",
                    "callee_name": call_name,
                    "edge_kind": "unresolved",
                    "source": "decompiler_call_expression",
                    "unresolved": True,
                }
            key = (
                str(edge["caller_addr"]),
                str(edge["callee_addr"]),
                str(edge["callee_name"]),
            )
            edges.setdefault(key, edge)
    sorted_edges = [edges[key] for key in sorted(edges, key=lambda value: tuple(part.casefold() for part in value))]
    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    api_calls: dict[str, set[str]] = defaultdict(set)
    for edge in sorted_edges:
        caller_addr = str(edge.get("caller_addr") or "")
        callee_addr = str(edge.get("callee_addr") or "")
        callee_name = str(edge.get("callee_name") or callee_addr)
        if callee_addr in address_to_record:
            callee_id = str(address_to_record[callee_addr].get("function_id") or callee_addr)
            caller_id = str(address_to_record.get(caller_addr, {}).get("function_id") or caller_addr)
            callees[caller_addr].add(callee_id)
            callers[callee_addr].add(caller_id)
        elif callee_name:
            callees[caller_addr].add(callee_name)
            if str(edge.get("edge_kind") or "") == "import":
                api_calls[caller_addr].add(callee_name)
    for record in records:
        address = str(record.get("address") or "")
        record["callers"] = sorted(callers[address])
        record["callees"] = sorted(callees[address])
        record["api_calls"] = sorted(api_calls[address])
    source_counts = Counter(str(edge.get("source") or "unknown") for edge in sorted_edges)
    result["call_graph"] = {
        "edge_count": len(sorted_edges),
        "caller_count": len({str(edge.get("caller_addr") or "") for edge in sorted_edges}),
        "edges": sorted_edges,
        "source_counts": dict(sorted(source_counts.items())),
    }
    result["call_graph_augmented_from_decompilation"] = True
    return {
        "edges": len(sorted_edges),
        "ghidra_edges": sum(edge.get("source") == "ghidra_full_call_graph" for edge in sorted_edges),
        "internal_edges": sum(edge.get("edge_kind") == "internal" for edge in sorted_edges),
        "import_edges": sum(edge.get("edge_kind") == "import" for edge in sorted_edges),
        "unresolved_edges": sum(edge.get("edge_kind") == "unresolved" for edge in sorted_edges),
    }


def _private_call_graph_contract_errors(
    result: Mapping[str, Any],
    raw_index: Mapping[str, Any],
) -> list[str]:
    """private raw indexとprogram-resultのcall graph取得契約を相互検証する。"""

    errors: list[str] = []
    if result.get("ghidra_call_graph") != raw_index.get("ghidra_call_graph"):
        errors.append("raw indexとprogram-resultのGhidra call graphが一致しません")
    if result.get("call_graph") != raw_index.get("call_graph"):
        errors.append("raw indexとprogram-resultの補完済みcall graphが一致しません")
    result_coverage = result.get("retrieval_coverage")
    raw_coverage = raw_index.get("retrieval_coverage")
    result_call_graph_coverage = result_coverage.get("call_graph") if isinstance(result_coverage, Mapping) else None
    raw_call_graph_coverage = raw_coverage.get("call_graph") if isinstance(raw_coverage, Mapping) else None
    if result_call_graph_coverage != raw_call_graph_coverage:
        errors.append("raw indexとprogram-resultのcall graph取得証跡が一致しません")
    if _call_graph_retrieval_state(result) not in {
        "complete",
        "managed_not_applicable",
    }:
        errors.append("program-resultに有効なcall graph取得・非適用証跡がありません")
    if _call_graph_retrieval_state(raw_index) not in {
        "complete",
        "managed_not_applicable",
    }:
        errors.append("raw indexに有効なcall graph取得・非適用証跡がありません")
    if not _call_graph_schema_valid(result.get("call_graph")):
        errors.append("program-resultの補完済みcall graph schemaが不正です")
    if not _call_graph_schema_valid(raw_index.get("call_graph")):
        errors.append("raw indexの補完済みcall graph schemaが不正です")
    return errors


def augment_private_call_graphs(
    program_results: Mapping[str, dict[str, Any]],
    private_output: Path,
) -> dict[str, int]:
    """全programのcall graphを補完し、private成果物へ永続化する。"""

    totals: Counter[str] = Counter()
    for digest, result in sorted(program_results.items()):
        object_dir = private_output / "objects" / digest
        raw_index_path = object_dir / "ghidra-raw-index.json"
        raw_index = _bounded_json_snapshot(raw_index_path).document
        contract_errors = _private_call_graph_contract_errors(
            result,
            raw_index,
        )
        if contract_errors:
            raise GhidraMcpError("; ".join(contract_errors))
        counts = augment_program_result_call_graph(result)
        selected_ids = ensure_characteristic_selection(result)
        totals.update(counts)
        totals["characteristic_functions"] += len(selected_ids)
        raw_index["call_graph"] = result["call_graph"]
        raw_index["call_graph_augmented_from_decompilation"] = True
        raw_index["characteristic_function_ids"] = selected_ids
        raw_index["characteristic_function_count"] = len(selected_ids)
        raw_index["characteristic_selection"] = [
            {
                "function_id": item.get("function_id"),
                "address_or_token": item.get("address") or item.get("token"),
                "role": item.get("role"),
                "selection_score": item.get("selection_score"),
                "selection_reasons": item.get("selection_reasons"),
            }
            for item in result.get("functions", [])
            if isinstance(item, Mapping) and item.get("selected_for_characteristic_analysis") is True
        ]
        _atomic_private_json(raw_index_path, raw_index)
        _persist_program_result(object_dir / "program-result.json", result)
        totals["programs"] += 1
    return dict(totals)


def validate_private_artifacts(
    program_results: Mapping[str, Mapping[str, Any]],
    private_output: Path,
    *,
    expected_program_count: int | None = None,
) -> dict[str, Any]:
    """全programのinventoryと代表関数解析成果物が欠落なく保存されたか検証する。"""

    required_raw_keys = {
        "metadata",
        "analysis_status",
        "functions",
        "ghidra_call_graph",
        "call_graph",
        "imports",
        "exports",
        "strings",
        "segments",
        "entry_points",
        "anti_analysis",
        "api_call_chains",
        "opcode_hashes",
        "retrieval_coverage",
        "characteristic_function_ids",
        "characteristic_selection",
    }
    programs: list[dict[str, Any]] = []
    totals: Counter[str] = Counter()
    for digest, result in sorted(program_results.items()):
        errors: list[str] = []
        object_dir = private_output / "objects" / digest
        result_path = object_dir / "program-result.json"
        raw_index_path = object_dir / "ghidra-raw-index.json"
        decompilation_path = object_dir / "decompilations.raw.jsonl"
        cil_path = object_dir / "cil-instructions.raw.jsonl"
        if result.get("call_graph_augmented_from_decompilation") is not True:
            errors.append("逆コンパイルcall式によるcall graph補完証跡がありません")
        if result.get("mcp_responses_valid") is not True:
            errors.append("MCP成功証跡がありません")
        if result.get("all_static_analysis_content_retained") is not True:
            errors.append("全静的解析内容の保持証跡がありません")
        if str(result.get("sha256") or "").casefold() != digest.casefold():
            errors.append("program-resultのSHA-256が対象と一致しません")
        if not result_path.is_file():
            errors.append("program-result.jsonがありません")
        try:
            raw_index = _bounded_json_snapshot(raw_index_path).document
        except (OSError, TypeError, ValueError) as error:
            raw_index = {}
            errors.append(f"ghidra-raw-index.jsonを読めません: {type(error).__name__}")
        if isinstance(raw_index, Mapping):
            missing_raw_keys = sorted(required_raw_keys - set(raw_index))
            if missing_raw_keys:
                errors.append("Ghidra raw項目が不足しています: " + ", ".join(missing_raw_keys))
            if raw_index.get("program_selector") != result.get("program_selector"):
                errors.append("raw indexとprogram-resultのprogram selectorが一致しません")
        else:
            raw_index = {}
            errors.append("ghidra-raw-index.jsonがJSON objectではありません")

        errors.extend(_private_call_graph_contract_errors(result, raw_index))

        retrieval_coverage = raw_index.get("retrieval_coverage", {})
        if result.get("retrieval_coverage") != retrieval_coverage:
            errors.append("raw indexとprogram-resultのページング取得証跡が一致しません")
        if raw_index.get("all_static_analysis_content_retained") is not True:
            errors.append("raw indexに全静的解析内容の保持証跡がありません")
        if not isinstance(retrieval_coverage, Mapping):
            errors.append("ページング取得証跡がJSON objectではありません")
            retrieval_coverage = {}
        for name in ("functions", "imports", "exports", "strings", "segments"):
            evidence = retrieval_coverage.get(name)
            values = raw_index.get(name)
            if not isinstance(evidence, Mapping):
                errors.append(f"{name}: ページング取得証跡がありません")
                continue
            if evidence.get("complete") is not True:
                errors.append(f"{name}: 完全取得または正本代替の証跡がありません")
            endpoint_skipped = evidence.get("endpoint_invoked") is False
            managed_cil_alternative = (
                endpoint_skipped
                and name in {"functions", "strings"}
                and result.get("analysis_mode") == "managed_cil_primary_with_ghidra_structure"
                and evidence.get("source") == "managed_cil_primary"
            )
            if endpoint_skipped and not managed_cil_alternative:
                errors.append(f"{name}: 未許可のendpoint省略証跡です")
            if not endpoint_skipped and evidence.get("terminal_short_page_observed") is not True:
                errors.append(f"{name}: 終端までの完全取得証跡がありません")
            if evidence.get("program_selector") != result.get("program_selector"):
                errors.append(f"{name}: ページング取得時のprogram selectorが一致しません")
            if not isinstance(values, list):
                errors.append(f"{name}: raw内容がlistではありません")
            elif int(evidence.get("item_count") or 0) != len(values):
                errors.append(f"{name}: 取得件数と保存件数が一致しません")
            totals[f"{name}_items"] += len(values) if isinstance(values, list) else 0
            if name not in {"functions", "strings"} and result.get(name) != values:
                errors.append(f"{name}: raw indexとprogram-resultの保存内容が一致しません")

        raw_functions = [item for item in raw_index.get("functions", []) if isinstance(item, Mapping)]
        if not _function_inventory_coverage_complete(result):
            errors.append("全Ghidra関数inventoryの終端取得・metadata件数拘束がありません")
        if int(result.get("ghidra_function_inventory_count") or 0) != len(raw_functions):
            errors.append("program-resultとraw indexのGhidra関数inventory件数が一致しません")
        try:
            metadata_function_count = _metadata_function_count(raw_index.get("metadata"))
        except GhidraMcpError as error:
            metadata_function_count = None
            errors.append(str(error))
        if metadata_function_count is not None and metadata_function_count < len(raw_functions):
            errors.append("metadata全関数数が保存済み非外部関数inventoryを下回っています")
        native_records = [
            item
            for item in result.get("functions", [])
            if isinstance(item, Mapping) and item.get("analysis_kind") == "ghidra_native_or_loader_view"
        ]
        managed_records = [
            item
            for item in result.get("functions", [])
            if isinstance(item, Mapping) and item.get("analysis_kind") == "managed_cil"
        ]
        selected_ids = {str(value) for value in result.get("characteristic_function_ids", []) if value}
        raw_selected_ids = {str(value) for value in raw_index.get("characteristic_function_ids", []) if value}
        if selected_ids != raw_selected_ids:
            errors.append("代表関数IDがraw indexとprogram-resultで一致しません")
        record_ids = {
            str(item.get("function_id"))
            for item in result.get("functions", [])
            if isinstance(item, Mapping) and item.get("function_id")
        }
        eligible_count = sum(
            not bool(item.get("isExternal")) and not bool(item.get("isThunk")) for item in raw_functions
        ) + sum(item.get("decompilation_status") != "no_managed_body" for item in managed_records)
        if eligible_count and not selected_ids:
            errors.append("解析可能な関数があるのに代表関数が選定されていません")
        if selected_ids - record_ids:
            errors.append("代表関数IDに対応する関数recordがありません")
        selected_native_addresses = {
            str(item.get("address"))
            for item in native_records
            if item.get("address")
            and item.get("selected_for_characteristic_analysis") is True
            and item.get("decompilation_status") != "excluded_external_or_thunk"
        }
        for item in result.get("functions", []):
            if not isinstance(item, Mapping) or item.get("selected_for_characteristic_analysis") is not True:
                continue
            if not item.get("selection_reasons"):
                errors.append(f"{item.get('function_id')}: 代表関数の選定理由がありません")
        decompilation_rows = _read_jsonl_rows(decompilation_path)
        invalid_decompilation_lines = [row for row in decompilation_rows if "_invalid_json_line" in row]
        if invalid_decompilation_lines:
            errors.append(f"逆コンパイルJSONLに不正行があります: {len(invalid_decompilation_lines)}")
        decompilation_by_address = {str(row.get("address")): row for row in decompilation_rows if row.get("address")}
        missing_addresses = sorted(selected_native_addresses - set(decompilation_by_address))
        if missing_addresses:
            errors.append(f"逆コンパイル行がない代表関数があります: {len(missing_addresses)}")
        for address in sorted(selected_native_addresses & set(decompilation_by_address)):
            row = decompilation_by_address[address]
            if "pseudocode" not in row:
                errors.append(f"{address}: 逆コンパイル本文fieldがありません")
            if str(row.get("status") or "") in {
                "",
                "unknown",
                "failed_not_attempted",
            }:
                errors.append(f"{address}: 逆コンパイル試行状態が不正です")
            if row.get("program_selector") != result.get("program_selector"):
                errors.append(f"{address}: program selectorが一致しません")

        if len(native_records) != len(raw_functions):
            errors.append(
                f"Ghidra関数inventoryと公開元record数が一致しません: {len(raw_functions)} != {len(native_records)}"
            )
        if int(result.get("ghidra_function_inventory_count") or 0) != len(raw_functions):
            errors.append("Ghidra関数inventory countが一致しません")
        if int(result.get("managed_method_count") or 0) != len(managed_records):
            errors.append("managed method inventory countが一致しません")
        if int(result.get("function_inventory_count") or 0) != len(native_records + managed_records):
            errors.append("全関数inventory countが一致しません")
        opcode_hashes = raw_index.get("opcode_hashes")
        if not isinstance(opcode_hashes, Mapping):
            errors.append("opcode hash成果物がJSON objectではありません")
        else:
            opcode_functions = [item for item in opcode_hashes.get("functions", []) if isinstance(item, Mapping)]
            if int(opcode_hashes.get("returned") or 0) != len(opcode_functions):
                errors.append("opcode hashのreturned件数と保存件数が一致しません")
            if int(opcode_hashes.get("total_matching") or 0) != len(raw_functions):
                errors.append("opcode hashの対象関数数とGhidra関数inventoryが一致しません")
            if len(opcode_functions) != len(raw_functions):
                errors.append("全Ghidra関数のopcode hash状態recordがありません")
            if opcode_hashes.get("all_functions_recorded") is not True:
                errors.append("全関数opcode hash inventoryの完了証跡がありません")
            for item in opcode_functions:
                if item.get("hash_status") not in {"available", "unavailable_recorded"}:
                    errors.append("opcode hash状態が未記録の関数があります")
                    break
                if item.get("program_selector") != result.get("program_selector"):
                    errors.append("opcode hash recordのprogram selectorが一致しません")
                    break

        cil_body_tokens = {
            str(item.get("token"))
            for item in managed_records
            if item.get("token")
            and item.get("selected_for_characteristic_analysis") is True
            and item.get("decompilation_status") != "no_managed_body"
        }
        cil_rows = _read_jsonl_rows(cil_path)
        invalid_cil_lines = [row for row in cil_rows if "_invalid_json_line" in row]
        if invalid_cil_lines:
            errors.append(f"CIL JSONLに不正行があります: {len(invalid_cil_lines)}")
        cil_tokens = {str(row.get("token")) for row in cil_rows if row.get("token")}
        missing_cil_tokens = sorted(cil_body_tokens - cil_tokens)
        if missing_cil_tokens:
            errors.append(f"CIL命令列がないmethodがあります: {len(missing_cil_tokens)}")
        for row in cil_rows:
            if row.get("token") and "instructions" not in row:
                errors.append(f"{row['token']}: CIL instructions fieldがありません")

        totals["programs"] += 1
        totals["native_functions"] += len(raw_functions)
        totals["characteristic_native_decompilations"] += len(selected_native_addresses)
        totals["managed_methods"] += len(managed_records)
        totals["managed_method_bodies"] += len(cil_body_tokens)
        programs.append(
            {
                "sha256": digest,
                "valid": not errors,
                "errors": errors,
                "native_function_count": len(raw_functions),
                "characteristic_native_decompilation_count": len(selected_native_addresses),
                "managed_method_count": len(managed_records),
                "managed_method_body_count": len(cil_body_tokens),
                "artifacts": {
                    "program_result": str(result_path),
                    "ghidra_raw_index": str(raw_index_path),
                    "decompilations": str(decompilation_path),
                    "cil_instructions": str(cil_path) if cil_body_tokens else None,
                },
            }
        )
    global_errors = []
    if not programs:
        global_errors.append("検証対象programがありません")
    if expected_program_count is not None and len(programs) != expected_program_count:
        global_errors.append(f"program数が期待値と一致しません: {len(programs)} != {expected_program_count}")
    output = {
        "schema_version": SCHEMA_VERSION,
        "complete": not global_errors and all(item["valid"] for item in programs),
        "global_errors": global_errors,
        "valid_programs": sum(item["valid"] for item in programs),
        "invalid_programs": sum(not item["valid"] for item in programs),
        "totals": dict(totals),
        "programs": programs,
    }
    _atomic_private_json(private_output / "private-artifact-validation.json", output)
    return output


def _ghidra_supersedes_generic_string_limit(case_dir: Path) -> bool:
    """Return whether complete Ghidra evidence covers the sole generic string limit."""

    generic_path = case_dir / "generic-triage.json"
    static_path = case_dir / "static-logic.json"
    if not generic_path.exists() or not static_path.exists():
        return False
    generic = load_json_object_strict(generic_path)
    static_logic = load_json_object_strict(static_path)
    coverage = static_logic.get("coverage")
    if not isinstance(coverage, Mapping):
        return False
    required = (
        "all_characteristic_functions_attempted",
        "all_characteristic_functions_explained",
        "all_discovered_functions_inventoried",
        "all_static_analysis_content_retained",
        "function_bodies_reviewed",
    )
    if not all(coverage.get(key) is True for key in required):
        return False
    program_count = coverage.get("ghidra_program_count")
    if not isinstance(program_count, int) or program_count < 1:
        return False
    if coverage.get("ghidra_programs_with_valid_mcp_responses") != program_count:
        return False

    issues: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key == "string_scan" and isinstance(item, Mapping):
                    if item.get("truncated") is True:
                        issues.append("string_scan_truncated")
                elif key == "base64_scan" and isinstance(item, Mapping):
                    if item.get("truncated") is True:
                        issues.append("base64_scan_truncated")
                elif key == "parse_error" or key.endswith("_error"):
                    issues.append(key)
                elif key != "analysis_coverage":
                    collect(item)
            return
        if isinstance(value, list):
            for item in value:
                collect(item)

    collect(generic)
    return issues == ["string_scan_truncated"]


def _ghidra_documents_known_static_limits(
    case_dir: Path,
    state: Mapping[str, Any],
) -> list[str]:
    """Ghidra証拠と再試行記録で説明済みとなる限定的な静的制限を返す。"""

    static_path = case_dir / "static-logic.json"
    if not static_path.exists():
        return []
    static_logic = load_json_object_strict(static_path)
    coverage = static_logic.get("coverage")
    if not isinstance(coverage, Mapping):
        return []
    required = (
        "all_characteristic_functions_attempted",
        "all_characteristic_functions_explained",
        "all_discovered_functions_inventoried",
        "all_static_analysis_content_retained",
        "function_bodies_reviewed",
    )
    if not all(coverage.get(key) is True for key in required):
        return []
    program_count = coverage.get("ghidra_program_count")
    if not isinstance(program_count, int) or program_count < 1:
        return []
    if coverage.get("ghidra_programs_with_valid_mcp_responses") != program_count:
        return []

    issues = state.get("static_layer_issues")
    if not isinstance(issues, list) or not issues:
        return []
    managed_suffix = ".report.pe.managed_il_triage.status:analyzed_partial_budget"
    sevenzip_suffix = ".report.sevenzip.status:partially_extracted"
    if any(not isinstance(issue, str) or not issue.endswith((managed_suffix, sevenzip_suffix)) for issue in issues):
        return []

    sevenzip_issues = [issue for issue in issues if issue.endswith(sevenzip_suffix)]
    if sevenzip_issues:
        layers_path = case_dir / "static-layers.json"
        if not layers_path.exists():
            return []
        static_layers = load_json_object_strict(layers_path)
        exhausted = []
        for step in static_layers.get("steps", []):
            report = step.get("report") if isinstance(step, Mapping) else None
            sevenzip = report.get("sevenzip") if isinstance(report, Mapping) else None
            if not isinstance(sevenzip, Mapping) or sevenzip.get("status") != "partially_extracted":
                continue
            inventory = sevenzip.get("inventory")
            exhausted.append(
                int(sevenzip.get("archive_unlock_attempt_count") or 0) >= 2
                and sevenzip.get("retained_members") == 0
                and isinstance(inventory, list)
                and bool(inventory)
                and all(isinstance(item, Mapping) and item.get("status") == "empty_file" for item in inventory)
            )
        if len(exhausted) != len(sevenzip_issues) or not all(exhausted):
            return []
    return sorted(set(issues))


def _ghidra_documents_known_generic_container_limits(case_dir: Path) -> list[str]:
    """完全な静的coverageで補完済みの限定的なcontainer委譲だけを返す。"""

    def _is_plain_int(value: Any, *, minimum: int = 0) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= minimum

    def _strict_json_equal(left: Any, right: Any) -> bool:
        """JSON値をbool/int等の型を同一視せず再帰比較する。"""

        if isinstance(left, Mapping) or isinstance(right, Mapping):
            if not isinstance(left, Mapping) or not isinstance(right, Mapping):
                return False
            return set(left) == set(right) and all(_strict_json_equal(left[key], right[key]) for key in left)
        if isinstance(left, list) or isinstance(right, list):
            if not isinstance(left, list) or not isinstance(right, list):
                return False
            return len(left) == len(right) and all(
                _strict_json_equal(left_item, right_item) for left_item, right_item in zip(left, right, strict=True)
            )
        return type(left) is type(right) and left == right

    def _nested_safety_flags_are_false(value: Any) -> bool:
        safety_names = {
            "arbitrary_ghidra_scripts_enabled",
            "executed",
            "executed_sample",
            "raw_pseudocode_exported",
            "recovered_content_exported",
            "sample_executed",
            "network_contacted",
        }
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key in safety_names and item is not False:
                    return False
                if isinstance(item, (Mapping, list)) and not _nested_safety_flags_are_false(item):
                    return False
        elif isinstance(value, list):
            return all(_nested_safety_flags_are_false(item) for item in value)
        return True

    generic_path = case_dir / "generic-triage.json"
    layers_path = case_dir / "static-layers.json"
    static_path = case_dir / "static-logic.json"
    if not generic_path.exists() or not layers_path.exists() or not static_path.exists():
        return []
    static_logic = load_json_object_strict(static_path)
    generic = load_json_object_strict(generic_path)
    static_layers = load_json_object_strict(layers_path)

    logic_safety = static_logic.get("safety")
    if (
        not isinstance(logic_safety, Mapping)
        or logic_safety.get("sample_executed") is not False
        or logic_safety.get("network_contacted") is not False
        or logic_safety.get("raw_pseudocode_exported") is not False
        or logic_safety.get("raw_pseudocode_retained_outside_repository") is not True
        or logic_safety.get("arbitrary_ghidra_scripts_enabled") is not False
        or generic.get("executed_sample") is not False
        or generic.get("network_contacted") is not False
        or static_layers.get("executed_sample") is not False
        or static_layers.get("network_contacted") is not False
        or static_layers.get("recovered_content_exported") is not False
        or not _nested_safety_flags_are_false(static_logic)
        or not _nested_safety_flags_are_false(generic)
        or not _nested_safety_flags_are_false(static_layers)
    ):
        return []

    coverage = static_logic.get("coverage")
    if not isinstance(coverage, Mapping):
        return []
    required = (
        "all_characteristic_functions_attempted",
        "all_characteristic_functions_explained",
        "all_discovered_functions_inventoried",
        "all_static_analysis_content_retained",
        "function_bodies_reviewed",
    )
    if (
        not all(coverage.get(key) is True for key in required)
        or coverage.get("raw_private_artifacts_retained") is not True
    ):
        return []
    program_count = coverage.get("ghidra_program_count")
    if not _is_plain_int(program_count, minimum=1):
        return []
    valid_program_count = coverage.get("ghidra_programs_with_valid_mcp_responses")
    if not _is_plain_int(valid_program_count, minimum=1) or valid_program_count != program_count:
        return []

    limit_events = static_layers.get("limit_events")
    counts = static_layers.get("counts")
    limits = static_layers.get("limits")
    layers = static_layers.get("layers")
    steps = static_layers.get("steps")
    if (
        not _is_plain_int(static_layers.get("schema_version"), minimum=1)
        or static_layers.get("schema_version") != 1
        or not isinstance(limit_events, list)
        or limit_events
        or not isinstance(counts, Mapping)
        or not isinstance(limits, Mapping)
        or not isinstance(layers, list)
        or not layers
        or not isinstance(steps, list)
    ):
        return []
    integer_limit_names = (
        "max_archive_members",
        "max_depth",
        "max_layers",
        "max_recovered_layer_size",
        "max_recovered_total_size",
    )
    if any(not _is_plain_int(limits.get(name), minimum=1) for name in integer_limit_names):
        return []
    ratio_limit = limits.get("max_archive_compression_ratio")
    if (
        not isinstance(ratio_limit, (int, float))
        or isinstance(ratio_limit, bool)
        or not math.isfinite(float(ratio_limit))
        or float(ratio_limit) <= 0
    ):
        return []
    count_names = (
        "layers",
        "recovered_layers",
        "recovered_bytes",
        "limit_events",
        "deduplicated_artifacts",
    )
    if any(not _is_plain_int(counts.get(name)) for name in count_names):
        return []

    layers_by_sha: dict[str, Mapping[str, Any]] = {}
    roots: list[str] = []
    for layer in layers:
        if not isinstance(layer, Mapping):
            return []
        layer_sha = layer.get("sha256")
        parent_sha = layer.get("parent_sha256")
        depth = layer.get("depth")
        size = layer.get("size")
        layer_format = layer.get("format")
        if (
            not isinstance(layer_sha, str)
            or SHA256_RE.fullmatch(layer_sha) is None
            or layer_sha in layers_by_sha
            or not _is_plain_int(depth)
            or not _is_plain_int(size)
            or not isinstance(layer_format, str)
            or not layer_format
            or layer_format != layer_format.casefold()
            or not isinstance(layer.get("name"), str)
            or not layer.get("name")
            or not isinstance(layer.get("transform"), str)
            or not layer.get("transform")
        ):
            return []
        if parent_sha is None:
            if depth != 0:
                return []
            roots.append(layer_sha)
        elif (
            not isinstance(parent_sha, str)
            or SHA256_RE.fullmatch(parent_sha) is None
            or parent_sha == layer_sha
            or depth == 0
        ):
            return []
        layers_by_sha[layer_sha] = layer
    if len(roots) != 1:
        return []
    root_sha = roots[0]
    root_layer = layers_by_sha[root_sha]
    recovered_bytes = sum(int(layer["size"]) for sha, layer in layers_by_sha.items() if sha != root_sha)
    if (
        counts.get("layers") != len(layers)
        or counts.get("recovered_layers") != len(layers) - 1
        or counts.get("recovered_bytes") != recovered_bytes
        or counts.get("limit_events") != 0
        or len(layers) > int(limits["max_layers"])
        or recovered_bytes > int(limits["max_recovered_total_size"])
    ):
        return []

    children_by_parent: dict[str, list[str]] = {sha: [] for sha in layers_by_sha}
    for layer_sha, layer in layers_by_sha.items():
        if layer_sha == root_sha:
            continue
        parent_sha = str(layer["parent_sha256"])
        parent = layers_by_sha.get(parent_sha)
        if (
            parent is None
            or int(layer["depth"]) != int(parent["depth"]) + 1
            or int(layer["depth"]) > int(limits["max_depth"])
            or int(layer["size"]) > int(limits["max_recovered_layer_size"])
        ):
            return []
        children_by_parent[parent_sha].append(layer_sha)
    steps_by_sha: dict[str, Mapping[str, Any]] = {}
    recovered_sources_by_sha: dict[str, list[str]] = defaultdict(list)
    for step in steps:
        if not isinstance(step, Mapping):
            return []
        input_layer = step.get("input_layer")
        input_sha = input_layer.get("sha256") if isinstance(input_layer, Mapping) else None
        report = step.get("report")
        accepted_children = step.get("accepted_children")
        report_recovered = report.get("recovered") if isinstance(report, Mapping) else None
        if (
            not isinstance(input_sha, str)
            or input_sha not in layers_by_sha
            or input_sha in steps_by_sha
            or not _strict_json_equal(input_layer, layers_by_sha[input_sha])
            or step.get("status") != "succeeded"
            or not isinstance(report, Mapping)
            or not _is_plain_int(report.get("schema_version"), minimum=1)
            or report.get("schema_version") != 2
            or report.get("sha256") != input_sha
            or not _strict_json_equal(report.get("size"), input_layer.get("size"))
            or report.get("format") != input_layer.get("format")
            or report.get("name") != input_layer.get("name")
            or report.get("executed") is not False
            or report.get("network_contacted") is not False
            or not _nested_safety_flags_are_false(report)
            or not isinstance(accepted_children, list)
            or not isinstance(report_recovered, list)
        ):
            return []
        step_recovered_hashes: set[str] = set()
        for recovered_item in report_recovered:
            if not isinstance(recovered_item, Mapping):
                return []
            recovered_sha = recovered_item.get("sha256")
            recovered_size = recovered_item.get("size")
            if (
                not isinstance(recovered_item.get("kind"), str)
                or not recovered_item.get("kind")
                or not isinstance(recovered_sha, str)
                or SHA256_RE.fullmatch(recovered_sha) is None
                or recovered_sha not in layers_by_sha
                or recovered_sha in step_recovered_hashes
                or not _is_plain_int(recovered_size, minimum=1)
                or recovered_size != layers_by_sha[recovered_sha].get("size")
            ):
                return []
            step_recovered_hashes.add(recovered_sha)
            recovered_sources_by_sha[recovered_sha].append(input_sha)
        accepted_hashes: list[str] = []
        for child in accepted_children:
            child_sha = child.get("sha256") if isinstance(child, Mapping) else None
            if (
                not isinstance(child_sha, str)
                or child_sha not in layers_by_sha
                or not _strict_json_equal(child, layers_by_sha[child_sha])
                or layers_by_sha[child_sha].get("parent_sha256") != input_sha
                or child_sha in accepted_hashes
            ):
                return []
            accepted_hashes.append(child_sha)
        if sorted(accepted_hashes) != sorted(children_by_parent[input_sha]):
            return []
        steps_by_sha[input_sha] = step
    if set(steps_by_sha) != set(layers_by_sha):
        return []
    expected_deduplicated_artifacts = 0
    for recovered_sha, source_hashes in recovered_sources_by_sha.items():
        if recovered_sha == root_sha:
            expected_deduplicated_artifacts += len(source_hashes)
            continue
        canonical_parent = layers_by_sha[recovered_sha].get("parent_sha256")
        if canonical_parent not in source_hashes:
            return []
        expected_deduplicated_artifacts += len(source_hashes) - 1
    if (
        set(layers_by_sha) - {root_sha} - set(recovered_sources_by_sha)
        or counts.get("deduplicated_artifacts") != expected_deduplicated_artifacts
    ):
        return []

    if SHA256_RE.fullmatch(case_dir.name.casefold()) is None or root_sha != case_dir.name.casefold():
        return []
    parent_hashes = {
        str(layer["parent_sha256"]) for layer in layers_by_sha.values() if layer.get("parent_sha256") is not None
    }
    leaf_pe_hashes = {
        sha for sha, layer in layers_by_sha.items() if layer.get("format") == "pe" and sha not in parent_hashes
    }
    program_evidence = static_logic.get("program_evidence")
    if not isinstance(program_evidence, list) or len(program_evidence) != program_count:
        return []
    valid_program_hashes: set[str] = set()
    valid_leaf_program_hashes: set[str] = set()
    root_bindings = 0
    for evidence in program_evidence:
        if not isinstance(evidence, Mapping):
            return []
        program_id = evidence.get("program_id")
        selector = evidence.get("program_selector")
        binding_evidence = evidence.get("evidence")
        retrieval = evidence.get("retrieval_coverage")
        if (
            not isinstance(program_id, str)
            or not program_id.startswith("sha256:")
            or SHA256_RE.fullmatch(program_id.removeprefix("sha256:")) is None
            or not isinstance(selector, str)
            or not selector
            or evidence.get("mcp_responses_valid") is not True
            or binding_evidence != {"confidence": "confirmed_program_structure", "source": "ghidra-mcp"}
            or not isinstance(retrieval, Mapping)
        ):
            return []
        program_sha = program_id.removeprefix("sha256:")
        if (
            program_sha in valid_program_hashes
            or program_sha not in layers_by_sha
            or evidence.get("name") != program_sha
            or layers_by_sha[program_sha].get("format") != "pe"
        ):
            return []
        for retrieval_name in ("exports", "imports", "segments", "strings"):
            retrieval_item = retrieval.get(retrieval_name)
            if (
                not isinstance(retrieval_item, Mapping)
                or retrieval_item.get("complete") is not True
                or retrieval_item.get("program_selector") != selector
            ):
                return []
        public_call_graph_state = _call_graph_coverage_state(
            {
                "program_selector": selector,
                "analysis_mode": evidence.get("analysis_mode"),
                "retrieval_coverage": retrieval,
            }
        )
        if public_call_graph_state not in {
            "complete",
            "managed_not_applicable",
        }:
            return []
        if program_sha == root_sha:
            if evidence.get("relationship") != "root_program":
                return []
            root_bindings += 1
        elif evidence.get("relationship") != "statically_recovered_program":
            return []
        if program_sha in leaf_pe_hashes:
            valid_leaf_program_hashes.add(program_sha)
        valid_program_hashes.add(program_sha)
    if root_bindings != 1 or len(valid_program_hashes) != program_count:
        return []

    generic_coverage = generic.get("analysis_coverage")
    entries = generic.get("recovered_layer_triage")
    if (
        not isinstance(generic_coverage, Mapping)
        or generic_coverage.get("status") != "partial"
        or not isinstance(entries, list)
        or len(entries) != counts.get("recovered_layers")
        or generic.get("sha256") != root_sha
        or not _strict_json_equal(generic.get("size"), root_layer.get("size"))
        or generic.get("type") != root_layer.get("format")
    ):
        return []
    generic_count_names = (
        "layer_count",
        "complete_layers",
        "partial_layers",
        "failed_layers",
    )
    if any(not _is_plain_int(generic_coverage.get(name)) for name in generic_count_names):
        return []
    if generic_coverage.get("layer_count") != counts.get("layers") or generic_coverage.get("failed_layers") != 0:
        return []

    entries_by_sha: dict[str, Mapping[str, Any]] = {}
    partial_entries: list[Mapping[str, Any]] = []
    complete_count = 0
    for entry in entries:
        if not isinstance(entry, Mapping):
            return []
        layer = entry.get("layer")
        result = entry.get("result")
        layer_sha = layer.get("sha256") if isinstance(layer, Mapping) else None
        if (
            not isinstance(layer_sha, str)
            or layer_sha == root_sha
            or layer_sha not in layers_by_sha
            or layer_sha in entries_by_sha
            or not _strict_json_equal(layer, layers_by_sha[layer_sha])
            or not isinstance(result, Mapping)
            or result.get("sha256") != layer_sha
            or not _strict_json_equal(result.get("size"), layer.get("size"))
            or result.get("type") != layer.get("format")
        ):
            return []
        analysis_coverage = result.get("analysis_coverage")
        if not isinstance(analysis_coverage, Mapping):
            return []
        if entry.get("status") == "complete":
            if (
                entry.get("issues") != []
                or analysis_coverage.get("status") != "complete"
                or analysis_coverage.get("issues") != []
            ):
                return []
            complete_count += 1
        elif entry.get("status") == "partial":
            if entry.get("issues") != ["root:coverage:partial"] or analysis_coverage.get("status") != "partial":
                return []
            partial_entries.append(entry)
        else:
            return []
        entries_by_sha[layer_sha] = entry
    if (
        set(entries_by_sha) != set(layers_by_sha) - {root_sha}
        or not partial_entries
        or generic_coverage.get("complete_layers") != complete_count + 1
        or generic_coverage.get("partial_layers") != len(partial_entries)
        or int(generic_coverage["complete_layers"]) + int(generic_coverage["partial_layers"])
        != int(generic_coverage["layer_count"])
    ):
        return []

    def _complete_cab_fallback(cab_sha: str) -> bool:
        cab_step = steps_by_sha.get(cab_sha)
        cab_layer = layers_by_sha.get(cab_sha)
        if (
            not isinstance(cab_step, Mapping)
            or not isinstance(cab_layer, Mapping)
            or cab_layer.get("format") != "cab"
            or not _is_plain_int(cab_layer.get("size"), minimum=1)
        ):
            return False
        cab_report = cab_step.get("report")
        if not isinstance(cab_report, Mapping):
            return False
        cab = cab_report.get("cab")
        sevenzip = cab_report.get("sevenzip")
        if (
            not isinstance(cab, Mapping)
            or cab.get("status") != "parse_failed"
            or cab.get("error") != "NotSupportedError: LZX compression not supported"
            or not isinstance(sevenzip, Mapping)
            or sevenzip.get("status") != "extracted"
            or not _is_plain_int(sevenzip.get("exit_code"))
            or sevenzip.get("exit_code") != 0
            or not _is_plain_int(sevenzip.get("extract_exit_code"))
            or sevenzip.get("extract_exit_code") != 0
        ):
            return False
        archive_types = sevenzip.get("archive_types")
        total_members = sevenzip.get("total_members")
        cab_inventory = sevenzip.get("inventory")
        member_names = sevenzip.get("members")
        retained_members = sevenzip.get("retained_members")
        selective = sevenzip.get("selective_extraction")
        if (
            archive_types != ["Cab"]
            or not _is_plain_int(total_members, minimum=1)
            or total_members > limits["max_archive_members"]
            or not isinstance(cab_inventory, list)
            or len(cab_inventory) != total_members
            or not isinstance(member_names, list)
            or len(member_names) != total_members
            or not all(isinstance(name, str) and name for name in member_names)
            or not _is_plain_int(retained_members)
            or retained_members > total_members
            or not isinstance(selective, Mapping)
            or selective.get("enabled") is not False
            or not _is_plain_int(selective.get("full_inventory_count"), minimum=1)
            or selective.get("full_inventory_count") != total_members
            or selective.get("reason") != "not_required"
            or selective.get("selected_members") != []
            or not _is_plain_int(selective.get("selected_total_size"))
            or selective.get("selected_total_size") != 0
        ):
            return False

        cab_inventory_pairs: set[tuple[str, str]] = set()
        cab_inventory_identity_by_sha: dict[str, tuple[str, int]] = {}
        cab_inventory_names: list[str] = []
        priority_inventory_pairs: set[tuple[str, str]] = set()
        extracted_total_size = 0
        priority_member_count = 0
        for item in cab_inventory:
            if not isinstance(item, Mapping):
                return False
            item_sha = item.get("sha256")
            item_format = item.get("format")
            item_name = item.get("name")
            item_size = item.get("size")
            recovery_priority = item.get("recovery_priority")
            if (
                item.get("status") != "extracted"
                or not isinstance(item_sha, str)
                or SHA256_RE.fullmatch(item_sha) is None
                or not isinstance(item_format, str)
                or item_format not in {"data", "pe"}
                or not isinstance(item_name, str)
                or not item_name
                or not _is_plain_int(item_size, minimum=1)
                or (recovery_priority is not None and not _is_plain_int(recovery_priority, minimum=1))
                or (item_format == "pe") != (recovery_priority is not None)
            ):
                return False
            identity = (item_format, int(item_size))
            previous_identity = cab_inventory_identity_by_sha.get(item_sha)
            if previous_identity is not None and previous_identity != identity:
                return False
            cab_inventory_identity_by_sha[item_sha] = identity
            if recovery_priority is not None:
                priority_member_count += 1
                priority_inventory_pairs.add((item_sha, item_format))
            linked_layer = layers_by_sha.get(item_sha)
            if linked_layer is not None and (
                linked_layer.get("format") != item_format or linked_layer.get("size") != item_size
            ):
                return False
            if item_format == "pe":
                if not isinstance(linked_layer, Mapping) or item_sha not in steps_by_sha:
                    return False
            cab_inventory_pairs.add((item_sha, item_format))
            cab_inventory_names.append(item_name)
            extracted_total_size += int(item_size)
        recovered = cab_report.get("recovered")
        if not isinstance(recovered, list) or not recovered:
            return False
        recovered_pairs: set[tuple[str, str]] = set()
        for item in recovered:
            if not isinstance(item, Mapping):
                return False
            item_sha = item.get("sha256")
            item_size = item.get("size")
            if (
                item.get("kind") != "7z-pe"
                or not isinstance(item_sha, str)
                or SHA256_RE.fullmatch(item_sha) is None
                or not _is_plain_int(item_size, minimum=1)
                or item_sha not in layers_by_sha
                or layers_by_sha[item_sha].get("format") != "pe"
                or layers_by_sha[item_sha].get("size") != item_size
                or item_sha not in steps_by_sha
                or (item_sha, "pe") in recovered_pairs
            ):
                return False
            recovered_pairs.add((item_sha, "pe"))
        accepted_cab_pairs = {
            (str(child.get("sha256")), str(child.get("format")))
            for child in cab_step.get("accepted_children", [])
            if isinstance(child, Mapping)
        }
        inventory_pe_hashes = {item_sha for item_sha, item_format in cab_inventory_pairs if item_format == "pe"}
        declared_total = sevenzip.get("declared_total_size")
        extracted_total = sevenzip.get("extracted_total_size")
        return bool(
            Counter(cab_inventory_names) == Counter(member_names)
            and _is_plain_int(declared_total, minimum=1)
            and declared_total == extracted_total_size
            and _is_plain_int(extracted_total, minimum=1)
            and extracted_total == extracted_total_size
            and retained_members == priority_member_count
            and recovered_pairs == priority_inventory_pairs
            and not (accepted_cab_pairs - recovered_pairs)
            and bool(inventory_pe_hashes & valid_leaf_program_hashes)
            and extracted_total_size <= int(cab_layer["size"]) * float(ratio_limit)
        )

    documented: list[str] = []
    for entry in partial_entries:
        if entry.get("issues") != ["root:coverage:partial"]:
            return []
        layer = entry.get("layer")
        result = entry.get("result")
        if not isinstance(layer, Mapping) or not isinstance(result, Mapping):
            return []
        layer_sha = str(layer.get("sha256") or "")
        layer_format = str(layer.get("format") or result.get("type") or "")
        analysis_coverage = result.get("analysis_coverage")
        if not isinstance(analysis_coverage, Mapping):
            return []
        step = steps_by_sha.get(layer_sha)
        if not isinstance(step, Mapping) or step.get("status") != "succeeded":
            return []
        report = step.get("report")
        if not isinstance(report, Mapping):
            return []
        if layer_format == "rar":
            sevenzip = report.get("sevenzip")
            inventory = sevenzip.get("inventory") if isinstance(sevenzip, Mapping) else None
            if (
                result.get("format_specific_analysis") != "delegated_to_static_layer_pipeline"
                or analysis_coverage.get("issues") != ["root:rar_inventory_only"]
                or not isinstance(sevenzip, Mapping)
                or sevenzip.get("status") != "partially_extracted"
                or not _is_plain_int(
                    sevenzip.get("archive_unlock_attempt_count"),
                    minimum=2,
                )
                or not _is_plain_int(sevenzip.get("retained_members"))
                or sevenzip.get("retained_members") != 0
                or not isinstance(inventory, list)
                or not inventory
                or not all(isinstance(item, Mapping) and item.get("status") == "empty_file" for item in inventory)
            ):
                return []
            documented.append(f"{layer_sha}:rar_inventory_delegated_to_bounded_static_recovery")
            continue
        if layer_format == "ole":
            ole = report.get("ole")
            inventory = ole.get("inventory") if isinstance(ole, Mapping) else None
            children = step.get("accepted_children")
            recovered = report.get("recovered")
            if (
                result.get("format_specific_analysis") != "not_implemented"
                or analysis_coverage.get("issues") != ["root:ole_format_analysis_not_implemented"]
                or not isinstance(ole, Mapping)
                or ole.get("status") != "artifacts_recovered"
                or ole.get("executed") is not False
                or ole.get("network_contacted") is not False
                or not isinstance(inventory, list)
                or not inventory
                or not _is_plain_int(ole.get("stream_count"), minimum=1)
                or ole.get("stream_count") != len(inventory)
                or not isinstance(children, list)
                or not isinstance(recovered, list)
                or not recovered
                or not all(isinstance(child, Mapping) and child.get("format") in {"cab", "pe"} for child in children)
            ):
                return []
            inventory_pairs: set[tuple[str, str]] = set()
            inventory_identity_by_sha: dict[str, tuple[str, int]] = {}
            inspected_total_size = 0
            for item in inventory:
                if not isinstance(item, Mapping):
                    return []
                item_sha = item.get("sha256")
                item_format = item.get("format")
                item_name = item.get("name")
                item_size = item.get("size")
                if (
                    item.get("status") != "inspected"
                    or not isinstance(item_sha, str)
                    or SHA256_RE.fullmatch(item_sha) is None
                    or not isinstance(item_format, str)
                    or item_format not in {"cab", "data", "pe"}
                    or not isinstance(item_name, str)
                    or not item_name
                    or not _is_plain_int(item_size)
                ):
                    return []
                identity = (item_format, int(item_size))
                previous_identity = inventory_identity_by_sha.get(item_sha)
                if previous_identity is not None and previous_identity != identity:
                    return []
                inventory_identity_by_sha[item_sha] = identity
                inspected_total_size += int(item_size)
                linked_layer = layers_by_sha.get(item_sha)
                if linked_layer is not None and (
                    linked_layer.get("format") != item_format or linked_layer.get("size") != item_size
                ):
                    return []
                if item_format in {"cab", "pe"}:
                    if not isinstance(linked_layer, Mapping) or item_sha not in steps_by_sha:
                        return []
                    inventory_pairs.add((item_sha, item_format))
            recovered_kind_formats = {
                "embedded-pe": "pe",
                "ole-cab-stream": "cab",
                "ole-pe-stream": "pe",
            }
            recovered_pairs: set[tuple[str, str]] = set()
            for item in recovered:
                if not isinstance(item, Mapping):
                    return []
                item_sha = item.get("sha256")
                item_size = item.get("size")
                item_format = recovered_kind_formats.get(str(item.get("kind") or ""))
                if (
                    item_format is None
                    or not isinstance(item_sha, str)
                    or SHA256_RE.fullmatch(item_sha) is None
                    or not _is_plain_int(item_size, minimum=1)
                    or item_sha not in layers_by_sha
                    or layers_by_sha[item_sha].get("format") != item_format
                    or layers_by_sha[item_sha].get("size") != item_size
                    or item_sha not in steps_by_sha
                    or (item_sha, item_format) in recovered_pairs
                ):
                    return []
                recovered_pairs.add((item_sha, item_format))
            child_pairs = {
                (str(child.get("sha256")), str(child.get("format"))) for child in children if isinstance(child, Mapping)
            }
            if (
                {"cab", "pe"} - {item_format for _, item_format in inventory_pairs}
                or inventory_pairs - recovered_pairs
                or child_pairs - recovered_pairs
                or not _is_plain_int(ole.get("inspected_total_size"), minimum=1)
                or ole.get("inspected_total_size") != inspected_total_size
            ):
                return []

            reached: set[str] = set()
            pending = [item_sha for item_sha, _ in recovered_pairs]
            while pending:
                reached_sha = pending.pop()
                if reached_sha in reached:
                    continue
                reached.add(reached_sha)
                pending.extend(children_by_parent[reached_sha])
            cab_hashes = sorted(sha for sha in reached if layers_by_sha[sha].get("format") == "cab")
            if not cab_hashes or not all(_complete_cab_fallback(sha) for sha in cab_hashes):
                return []
            documented.append(f"{layer_sha}:ole_inventory_and_executable_children_recovered")
            continue
        return []
    return sorted(documented)


def _ghidra_documents_exhaustive_handler_no_evidence(
    case_dir: Path,
    report: Mapping[str, Any],
    state: Mapping[str, Any],
) -> dict[str, Any] | None:
    """全対象層の抽出器試行が正常なno-evidenceで終わったことを記録する。"""

    static_path = case_dir / "static-logic.json"
    if not static_path.exists():
        return None
    static_logic = load_json_object_strict(static_path)
    coverage = static_logic.get("coverage")
    if not isinstance(coverage, Mapping):
        return None
    required = (
        "all_characteristic_functions_attempted",
        "all_characteristic_functions_explained",
        "all_discovered_functions_inventoried",
        "all_static_analysis_content_retained",
        "function_bodies_reviewed",
    )
    if not all(coverage.get(key) is True for key in required):
        return None
    program_count = coverage.get("ghidra_program_count")
    if not isinstance(program_count, int) or program_count < 1:
        return None
    if coverage.get("ghidra_programs_with_valid_mcp_responses") != program_count:
        return None
    if state.get("detector_error_families") or state.get("static_layer_issues"):
        return None

    classification = report.get("classification")
    selected = classification.get("selected_families") if isinstance(classification, Mapping) else None
    if not isinstance(selected, list) or len(selected) != 1 or not isinstance(selected[0], str):
        return None
    family = selected[0].casefold()
    resolved_blockers = {
        "handler_no_evidence",
        f"selected_family_has_no_valid_handler_evidence:{family}",
        "selected_family_layer_incomplete",
    }
    blockers = {str(value) for value in state.get("blockers") or []}
    if not resolved_blockers <= blockers:
        return None

    executions = report.get("handler_executions")
    if not isinstance(executions, list):
        return None
    relevant = [
        item
        for item in executions
        if isinstance(item, Mapping) and str(item.get("handler_id") or "").partition(":")[0].casefold() == family
    ]
    if not relevant:
        return None
    attempted_layers: set[str] = set()
    handler_ids: set[str] = set()
    for execution in relevant:
        if execution.get("status") != "no_evidence":
            return None
        selected_evidence = execution.get("selected_evidence")
        if not isinstance(selected_evidence, Mapping) or selected_evidence.get("sufficient") is not False:
            return None
        attempts = execution.get("attempts")
        if not isinstance(attempts, list) or not attempts:
            return None
        routed = [
            attempt
            for attempt in attempts
            if isinstance(attempt, Mapping)
            and attempt.get("routing_role") in {"selected_family_layer", "ancestor_fallback"}
        ]
        if not routed or not any(item.get("routing_role") == "selected_family_layer" for item in routed):
            return None
        for attempt in routed:
            evidence = attempt.get("evidence")
            layer = attempt.get("layer")
            if (
                attempt.get("status") != "succeeded"
                or attempt.get("evidence_status") != "insufficient"
                or not isinstance(evidence, Mapping)
                or evidence.get("sufficient") is not False
                or not isinstance(layer, Mapping)
                or not layer.get("sha256")
            ):
                return None
            attempted_layers.add(str(layer["sha256"]))
        handler_ids.add(str(execution.get("handler_id") or ""))

    incomplete = state.get("incomplete_selected_layer_attempts")
    if not isinstance(incomplete, list) or any(
        not isinstance(item, Mapping)
        or item.get("status") != "succeeded"
        or str(item.get("layer_sha256") or "") not in attempted_layers
        for item in incomplete
    ):
        return None
    return {
        "family": family,
        "basis": "all_routed_handler_attempts_completed_without_family_specific_evidence",
        "handler_ids": sorted(handler_ids),
        "attempted_layer_sha256": sorted(attempted_layers),
        "resolved_blockers": sorted(resolved_blockers),
        "attribution_effect": "provider_label_retained_but_not_upgraded_to_static_confirmation",
    }


def _load_verified_case_report(
    case_dir: Path,
) -> tuple[dict[str, Any], _JsonFileSnapshot]:
    """report sealと既存manifestの全成果物hashを検証してsnapshotを返す。"""

    report_path = resolve_case_artifact(case_dir, "report.json")
    report_snapshot = _bounded_json_snapshot(report_path)
    report = report_snapshot.document
    semantic_errors = verify_report_semantics(report)
    if semantic_errors:
        raise ValueError(f"更新前のreport seal検証に失敗しました: {case_dir.name}: {semantic_errors}")
    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError(f"成果物hash manifestがありません: {case_dir.name}")
    hash_errors = verify_artifact_hashes(case_dir, manifest)
    if hash_errors:
        raise ValueError(f"更新前の全成果物hash検証に失敗しました: {case_dir.name}: {hash_errors}")
    _verify_case_wide_artifact_hashes(case_dir, report)
    _assert_snapshot_unchanged(
        report_snapshot,
        context="全成果物hash検証後",
    )
    return report, report_snapshot


def _refresh_preverified_case_manifest(
    case_dir: Path,
    report: dict[str, Any],
    report_snapshot: _JsonFileSnapshot,
) -> None:
    """Ghidra公開成果物更新後のhashをpreflight済みreportへ反映する。"""

    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError(f"成果物hash manifestがありません: {case_dir.name}")
    report["artifact_sha256"] = artifact_hashes(case_dir, manifest)
    seal_report(report)
    _atomic_replace_bytes(
        report_snapshot.path,
        _json_bytes(report),
        expected_snapshot=report_snapshot,
    )


def _rollback_case_files(
    versions: Iterable[tuple[_JsonFileSnapshot, bytes]],
    original_error: BaseException,
) -> None:
    """自分がcommitしたfileだけを元snapshotへatomicに戻す。"""

    failures: list[str] = []
    for original, committed in versions:
        try:
            current = _bounded_json_snapshot(original.path)
        except (OSError, TypeError, ValueError) as exc:
            failures.append(f"{original.path.name}:rollback競合:{exc}")
            continue
        if current.data == original.data and current.sha256 == original.sha256:
            continue
        committed_sha256 = hashlib.sha256(committed).hexdigest()
        if current.data != committed or current.sha256 != committed_sha256:
            failures.append(f"{original.path.name}:第三者変更を保持")
            continue
        try:
            _atomic_replace_bytes(
                original.path,
                original.data,
                expected_snapshot=current,
            )
        except (OSError, TypeError, ValueError) as exc:
            failures.append(f"{original.path.name}:{exc}")
    if failures:
        raise RuntimeError(f"Ghidra反映transactionのrollbackに失敗しました: {failures}") from original_error


def _case_path_commitment(case_dir: Path) -> str:
    """journalへhost path自体を保存せず、対象case pathを固定する。"""

    normalized = os.path.normcase(os.fspath(Path(os.path.abspath(case_dir))))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _case_tree_layout(case_dir: Path) -> tuple[set[str], set[str]]:
    """case treeの通常file／directory集合をsymlink非追従で固定する。"""

    ensure_no_reparse_components(case_dir)
    metadata = case_dir.lstat()
    if _stat_is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("transaction対象caseは通常directoryに限定します")
    files: set[str] = set()
    directories: set[str] = set()
    folded: set[str] = set()
    for path in sorted(case_dir.rglob("*"), key=lambda value: value.as_posix().casefold()):
        information = path.lstat()
        if _stat_is_reparse(information):
            raise ValueError("transaction対象caseにreparse pointがあります")
        relative = normalize_artifact_path(path.relative_to(case_dir).as_posix())
        relative_folded = relative.casefold()
        if relative_folded in folded:
            raise ValueError("transaction対象caseに大文字小文字衝突pathがあります")
        folded.add(relative_folded)
        if stat.S_ISDIR(information.st_mode):
            directories.add(relative)
        elif stat.S_ISREG(information.st_mode) and int(information.st_nlink) == 1:
            files.add(relative)
        else:
            raise ValueError("transaction対象caseに未許可entryがあります")
    return files, directories


def _assert_case_wide_transaction_layout(
    case_dir: Path,
    journal: Mapping[str, Any],
) -> None:
    """case-wide WAL中のfile追加・削除・directory変更を改ざんとして拒否する。"""

    if journal.get("scope", "target_files") != "case_wide":
        return
    raw_entries = journal.get("entries")
    raw_directories = journal.get("case_directories")
    if not isinstance(raw_entries, list) or not isinstance(raw_directories, list):
        raise ValueError("case-wide finalize transactionのlayout契約が不正です")
    expected_files = {normalize_artifact_path(entry.get("path")) for entry in raw_entries if isinstance(entry, Mapping)}
    expected_directories = {normalize_artifact_path(relative) for relative in raw_directories}
    if len(expected_files) != len(raw_entries) or len(expected_directories) != len(raw_directories):
        raise ValueError("case-wide finalize transactionのlayout契約が重複しています")
    try:
        current_files, current_directories = _case_tree_layout(case_dir)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("case-wide transaction回復中に第三者変更を検出しました") from exc
    if current_files != expected_files or current_directories != expected_directories:
        raise ValueError("case-wide transaction回復中に第三者変更を検出しました")


def _discard_finalize_live_temporaries(entries: Sequence[Mapping[str, Any]]) -> None:
    """journal entryへ予約したlive fileのatomic tempだけを復旧前に除去する。"""

    for entry in entries:
        target_path = entry.get("path")
        temporary_name = entry.get("live_temporary")
        if not isinstance(target_path, Path) or not isinstance(temporary_name, str):
            raise ValueError("finalize transaction live temp契約が不正です")
        temporary = target_path.with_name(temporary_name)
        if not os.path.lexists(temporary):
            continue
        ensure_no_reparse_components(temporary.parent)
        information = temporary.lstat()
        if _stat_is_reparse(information) or not stat.S_ISREG(information.st_mode) or int(information.st_nlink) != 1:
            raise ValueError("finalize transaction live tempが通常fileではありません")
        temporary.unlink()


def _finalize_transaction_directory(
    case_dir: Path,
    transaction_root: Path | None,
) -> Path:
    """公開case外のprivate rootへcase固有transaction directoryを割り当てる。"""

    case_absolute = Path(os.path.abspath(case_dir))
    if transaction_root is None:
        path_key = _case_path_commitment(case_absolute)[:32]
        root = Path(tempfile.gettempdir()) / "ai-security-analysis-ghidra-finalize" / path_key
    else:
        root = Path(os.path.abspath(transaction_root))
    if root == case_absolute or case_absolute in root.parents:
        raise ValueError("finalize transaction rootを公開case内へ配置できません")
    ensure_no_reparse_components(root)
    root.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(root)
    root_metadata = root.lstat()
    if _stat_is_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("finalize transaction rootは通常directoryに限定します")
    return root / case_absolute.name


def _safe_remove_finalize_transaction(transaction_dir: Path) -> None:
    """journalを先に無効化し、再起動時に安全に破棄できる順序でWALを削除する。"""

    ensure_no_reparse_components(transaction_dir)
    metadata = transaction_dir.lstat()
    if _stat_is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("finalize transaction pathが通常directoryではありません")
    for path in transaction_dir.rglob("*"):
        information = path.lstat()
        if _stat_is_reparse(information) or not (
            stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode)
        ):
            raise ValueError("finalize transactionに未許可entryがあります")
        if stat.S_ISREG(information.st_mode) and int(information.st_nlink) != 1:
            raise ValueError("finalize transactionにhardlinkは使用できません")
    journal_path = transaction_dir / FINALIZE_TRANSACTION_JOURNAL
    if os.path.lexists(journal_path):
        journal_metadata = journal_path.lstat()
        if (
            _stat_is_reparse(journal_metadata)
            or not stat.S_ISREG(journal_metadata.st_mode)
            or int(journal_metadata.st_nlink) != 1
        ):
            raise ValueError("finalize transaction journalが通常fileではありません")
        journal_path.unlink()
    shutil.rmtree(transaction_dir)


def _write_finalize_transaction_journal(
    path: Path,
    document: Mapping[str, Any],
    *,
    expected_snapshot: _JsonFileSnapshot | None = None,
) -> None:
    """journal自体もfsync済み一時fileからatomicに更新する。"""

    _atomic_replace_bytes(
        path,
        _json_bytes(document),
        expected_snapshot=expected_snapshot,
        require_absent=expected_snapshot is None,
        temporary_name=f".{FINALIZE_TRANSACTION_JOURNAL}.tmp",
    )


def _discard_finalize_transaction_temporaries(transaction_dir: Path) -> None:
    """journal/snapshot atomic write中断で残る、予約済みprivate tempだけを除去する。"""

    ensure_no_reparse_components(transaction_dir)
    metadata = transaction_dir.lstat()
    if _stat_is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("finalize transaction pathが通常directoryではありません")
    allowed = re.compile(rf"(?:\.{re.escape(FINALIZE_TRANSACTION_JOURNAL)}|\.\d{{4}}\.(?:old|new)\.snapshot)\.tmp\Z")
    for path in transaction_dir.iterdir():
        if allowed.fullmatch(path.name) is None:
            continue
        information = path.lstat()
        if _stat_is_reparse(information) or not stat.S_ISREG(information.st_mode) or int(information.st_nlink) != 1:
            raise ValueError("finalize transaction atomic tempが通常fileではありません")
        path.unlink()


def _begin_finalize_transaction(
    case_dir: Path,
    versions: Sequence[tuple[_JsonFileSnapshot | _ContentFileSnapshot, bytes]],
    *,
    transaction_root: Path | None,
    case_wide: bool = False,
) -> Path:
    """全旧新snapshotを固定後、公開file更新前にwrite-ahead journalを作る。"""

    if type(case_wide) is not bool:
        raise ValueError("finalize transactionのscope指定が不正です")
    try:
        resolved_case_dir = Path(case_dir).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("transaction対象caseを解決できません") from exc
    target_names: list[str] = []
    for snapshot, _new_data in versions:
        try:
            resolved_snapshot_path = snapshot.path.resolve(strict=True)
            relative = resolved_snapshot_path.relative_to(resolved_case_dir)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError("transaction対象がcase directory外です") from exc
        relative_name = normalize_artifact_path(relative.as_posix())
        if relative_name in target_names:
            raise ValueError("transaction対象pathが重複しています")
        target_names.append(relative_name)
    case_directories: list[str] = []
    if case_wide:
        case_files, observed_directories = _case_tree_layout(case_dir)
        if case_files != set(target_names):
            raise ValueError("case-wide transaction対象がcase全fileと一致しません")
        case_directories = sorted(observed_directories)
    transaction_dir = _finalize_transaction_directory(case_dir, transaction_root)
    if os.path.lexists(transaction_dir):
        raise ValueError("未回復のfinalize transactionが残っています")
    transaction_dir.mkdir()
    entries: list[dict[str, Any]] = []
    observed_paths: set[str] = set()
    try:
        for index, (snapshot, new_data) in enumerate(versions):
            relative_name = target_names[index]
            if relative_name in observed_paths:
                raise ValueError("transaction対象pathが重複しています")
            observed_paths.add(relative_name)
            old_name = f"{index:04d}.old.snapshot"
            new_name = f"{index:04d}.new.snapshot"
            _atomic_replace_bytes(
                transaction_dir / old_name,
                snapshot.data,
                maximum_bytes=MAX_JSON_OBJECT_SIZE,
                require_absent=True,
                temporary_name=f".{old_name}.tmp",
            )
            _atomic_replace_bytes(
                transaction_dir / new_name,
                new_data,
                maximum_bytes=MAX_JSON_OBJECT_SIZE,
                require_absent=True,
                temporary_name=f".{new_name}.tmp",
            )
            entries.append(
                {
                    "path": relative_name,
                    "old_snapshot": old_name,
                    "old_size": len(snapshot.data),
                    "old_sha256": snapshot.sha256,
                    "new_snapshot": new_name,
                    "new_size": len(new_data),
                    "new_sha256": hashlib.sha256(new_data).hexdigest(),
                    "live_temporary": f".ghidra-finalize-{index:04d}.tmp",
                }
            )
        journal = {
            "schema_version": FINALIZE_TRANSACTION_SCHEMA_VERSION,
            "case_sha256": case_dir.name,
            "case_path_sha256": _case_path_commitment(case_dir),
            "scope": "case_wide" if case_wide else "target_files",
            "case_directories": case_directories,
            "phase": "prepared",
            "applied_count": 0,
            "entries": entries,
        }
        _write_finalize_transaction_journal(
            transaction_dir / FINALIZE_TRANSACTION_JOURNAL,
            journal,
        )
    except BaseException:
        if os.path.lexists(transaction_dir):
            _safe_remove_finalize_transaction(transaction_dir)
        raise
    return transaction_dir


def _load_finalize_transaction(
    case_dir: Path,
    transaction_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """journalと全snapshot hashを検証し、live pathへ安全に結合する。"""

    journal_snapshot = _bounded_json_snapshot(transaction_dir / FINALIZE_TRANSACTION_JOURNAL)
    journal = journal_snapshot.document
    entries = journal.get("entries")
    scope = journal.get("scope", "target_files")
    case_directories = journal.get("case_directories", [])
    if (
        journal.get("schema_version") != FINALIZE_TRANSACTION_SCHEMA_VERSION
        or journal.get("case_sha256") != case_dir.name
        or journal.get("case_path_sha256") != _case_path_commitment(case_dir)
        or journal.get("phase") not in {"prepared", "applying", "applied", "verified"}
        or type(journal.get("applied_count")) is not int
        or not isinstance(entries, list)
        or not entries
        or journal["applied_count"] < 0
        or journal["applied_count"] > len(entries)
        or scope not in {"target_files", "case_wide"}
        or not isinstance(case_directories, list)
        or (scope == "case_wide" and any(not isinstance(value, str) or not value for value in case_directories))
        or (scope != "case_wide" and case_directories != [])
    ):
        raise ValueError("finalize transaction journalの契約が不正です")
    loaded: list[dict[str, Any]] = []
    expected_files = {FINALIZE_TRANSACTION_JOURNAL.casefold()}
    observed_paths: set[str] = set()
    for index, raw in enumerate(entries):
        if not isinstance(raw, Mapping):
            raise ValueError("finalize transaction entryがobjectではありません")
        relative = normalize_artifact_path(raw.get("path"))
        if relative in observed_paths:
            raise ValueError("finalize transaction entry pathが重複しています")
        observed_paths.add(relative)
        old_name = raw.get("old_snapshot")
        new_name = raw.get("new_snapshot")
        live_temporary = raw.get(
            "live_temporary",
            f".ghidra-finalize-{index:04d}.tmp",
        )
        if (
            old_name != f"{index:04d}.old.snapshot"
            or new_name != f"{index:04d}.new.snapshot"
            or type(raw.get("old_size")) is not int
            or type(raw.get("new_size")) is not int
            or raw["old_size"] < 0
            or raw["new_size"] < 0
            or not isinstance(raw.get("old_sha256"), str)
            or SHA256_RE.fullmatch(raw["old_sha256"]) is None
            or not isinstance(raw.get("new_sha256"), str)
            or SHA256_RE.fullmatch(raw["new_sha256"]) is None
            or live_temporary != f".ghidra-finalize-{index:04d}.tmp"
        ):
            raise ValueError("finalize transaction snapshot記述が不正です")
        old_data, old_binding = _bounded_regular_file_snapshot(
            transaction_dir / old_name,
            max_bytes=MAX_JSON_OBJECT_SIZE,
        )
        new_data, new_binding = _bounded_regular_file_snapshot(
            transaction_dir / new_name,
            max_bytes=MAX_JSON_OBJECT_SIZE,
        )
        if (
            old_binding.size != raw["old_size"]
            or old_binding.sha256 != raw["old_sha256"]
            or new_binding.size != raw["new_size"]
            or new_binding.sha256 != raw["new_sha256"]
        ):
            raise ValueError("finalize transaction snapshot hashが一致しません")
        expected_files.update({str(old_name).casefold(), str(new_name).casefold()})
        loaded.append(
            {
                "path": resolve_case_artifact(case_dir, relative),
                "old": old_data,
                "old_sha256": old_binding.sha256,
                "new": new_data,
                "new_sha256": new_binding.sha256,
                "live_temporary": live_temporary,
            }
        )
    observed_files = {path.name.casefold() for path in transaction_dir.iterdir() if path.is_file()}
    if observed_files != expected_files or any(path.is_dir() for path in transaction_dir.iterdir()):
        raise ValueError("finalize transactionに未束縛entryがあります")
    return journal, loaded


def _recover_finalize_transaction(
    case_dir: Path,
    *,
    transaction_root: Path | None,
) -> str | None:
    """中断transactionをhash状態からdeterministicにrollback／roll-forwardする。"""

    transaction_dir = _finalize_transaction_directory(case_dir, transaction_root)
    if not os.path.lexists(transaction_dir):
        return None
    _discard_finalize_transaction_temporaries(transaction_dir)
    journal_path = transaction_dir / FINALIZE_TRANSACTION_JOURNAL
    if not journal_path.is_file():
        allowed = re.compile(r"\d{4}\.(?:old|new)\.snapshot\Z")
        entries = list(transaction_dir.iterdir())
        if any(not path.is_file() or allowed.fullmatch(path.name) is None for path in entries):
            raise ValueError("journal未作成transactionに未束縛entryがあります")
        _safe_remove_finalize_transaction(transaction_dir)
        return "discarded_uncommitted"
    journal, entries = _load_finalize_transaction(case_dir, transaction_dir)
    _discard_finalize_live_temporaries(entries)
    _assert_case_wide_transaction_layout(case_dir, journal)
    current: list[_ContentFileSnapshot] = []
    states: list[str] = []
    for entry in entries:
        snapshot = _bounded_content_snapshot(entry["path"])
        current.append(snapshot)
        if snapshot.sha256 == entry["old_sha256"] and snapshot.data == entry["old"]:
            states.append("old")
        elif snapshot.sha256 == entry["new_sha256"] and snapshot.data == entry["new"]:
            states.append("new")
        else:
            raise ValueError(f"finalize transaction回復中に第三者変更を検出しました: {snapshot.path.name}")
    if journal["phase"] == "verified":
        if any(state != "new" for state in states):
            raise ValueError("verified finalize transactionが部分適用状態です")
        _safe_remove_finalize_transaction(transaction_dir)
        return "rolled_forward"
    for entry, snapshot, state in reversed(list(zip(entries, current, states, strict=True))):
        if state == "new" and entry["old"] != entry["new"]:
            _atomic_replace_bytes(
                entry["path"],
                entry["old"],
                expected_snapshot=snapshot,
                temporary_name=entry["live_temporary"],
            )
    for entry in entries:
        restored = _bounded_content_snapshot(entry["path"])
        if restored.sha256 != entry["old_sha256"] or restored.data != entry["old"]:
            raise RuntimeError("finalize transaction rollback後のhashが一致しません")
    _safe_remove_finalize_transaction(transaction_dir)
    return "rolled_back"


def _set_finalize_transaction_phase(
    transaction_dir: Path,
    *,
    phase: str,
    applied_count: int,
) -> None:
    """適用進捗をatomic journal updateとして永続化する。"""

    journal_path = transaction_dir / FINALIZE_TRANSACTION_JOURNAL
    snapshot = _bounded_json_snapshot(journal_path)
    document = snapshot.document
    document["phase"] = phase
    document["applied_count"] = applied_count
    _write_finalize_transaction_journal(
        journal_path,
        document,
        expected_snapshot=snapshot,
    )


def _valid_unresolved_function_gate(value: Any) -> bool:
    """未分類caseで許可するfunction gateの正規形を確認する。"""

    return (
        isinstance(value, Mapping)
        and value.get("required") is None
        and value.get("observed") is None
        and (
            (value.get("satisfied") is False and value.get("status") == "not_declared")
            or (value.get("satisfied") is True and value.get("status") == "satisfied")
        )
    )


def _prepare_orchestration_function_reconciliation(
    case_dir: Path,
    report: Mapping[str, Any],
    *,
    generic_triage_complete: bool = False,
) -> dict[str, Any] | None:
    """検証済み関数解析と汎用triage完了証跡をorchestrationへ反映する。"""

    manifest = report.get("artifact_sha256")
    orchestration_ref = report.get("orchestration")
    manifest_has_orchestration = isinstance(manifest, Mapping) and "orchestration.json" in manifest
    if orchestration_ref is None and not manifest_has_orchestration:
        return None
    if orchestration_ref != "orchestration.json" or not manifest_has_orchestration:
        raise ValueError(f"orchestration参照と成果物manifestが一致しません: {case_dir.name}")

    orchestration_path = resolve_case_artifact(case_dir, orchestration_ref)
    orchestration_snapshot = _bounded_json_snapshot(orchestration_path)
    outcome = orchestration_snapshot.document
    if (
        type(outcome.get("schema_version")) is not int
        or outcome.get("schema_version") != ORCHESTRATION_SCHEMA_VERSION
        or outcome.get("sample_sha256") != case_dir.name
    ):
        raise ValueError(f"orchestrationのschemaまたは検体境界が不正です: {case_dir.name}")

    resolution = outcome.get("family_resolution")
    requirements = resolution.get("requirements") if isinstance(resolution, Mapping) else None
    family = resolution.get("family") if isinstance(resolution, Mapping) else None
    resolution_status = resolution.get("status") if isinstance(resolution, Mapping) else None
    resolution_candidates = resolution.get("candidates") if isinstance(resolution, Mapping) else None
    classification = report.get("classification")
    selected = classification.get("selected_families") if isinstance(classification, Mapping) else None
    automation_status = classification.get("automation_status") if isinstance(classification, Mapping) else None
    if resolution_status == "unresolved":
        automation = outcome.get("automation")
        candidate_families = (
            [item.get("family") for item in resolution_candidates if isinstance(item, Mapping)]
            if isinstance(resolution_candidates, list)
            else []
        )
        candidate_boundary_valid = (
            isinstance(resolution_candidates, list)
            and len(candidate_families) == len(resolution_candidates)
            and all(isinstance(value, str) and value for value in candidate_families)
            and len(candidate_families) == len(set(candidate_families))
            and isinstance(selected, list)
            and all(isinstance(value, str) and value for value in selected)
            and len(selected) == len(set(selected))
            and set(selected).issubset(set(candidate_families))
            and (not selected or automation_status == "unresolved")
        )
        if not isinstance(automation, Mapping) or any(
            automation.get(name) is not False for name in ("ai_used", "sample_executed", "network_contacted")
        ):
            raise ValueError(f"invalid orchestration safety contract: {case_dir.name}")
        function_gate = outcome.get("quality_gates", {}).get("function_analysis")
        if (
            family is not None
            or requirements is not None
            or not candidate_boundary_valid
            or not _valid_unresolved_function_gate(function_gate)
        ):
            raise ValueError(f"invalid unresolved-family orchestration boundary: {case_dir.name}")
        return None
    if (
        not isinstance(resolution, Mapping)
        or resolution_status != "resolved"
        or not isinstance(family, str)
        or not family
        or not isinstance(requirements, Mapping)
        or requirements.get("function_analysis_required") is not True
    ):
        raise ValueError(f"解決済みfamilyのfunction_analysis要件を確認できません: {case_dir.name}")
    if not isinstance(selected, list) or family not in selected:
        raise ValueError(f"reportとorchestrationのfamily resolutionが一致しません: {case_dir.name}")

    automation = outcome.get("automation")
    if not isinstance(automation, Mapping) or any(
        automation.get(name) is not False for name in ("ai_used", "sample_executed", "network_contacted")
    ):
        raise ValueError(f"orchestrationの安全境界が不正です: {case_dir.name}")

    gates = outcome.get("quality_gates")
    if not isinstance(gates, dict) or not gates:
        raise ValueError(f"orchestration.quality_gatesが不正です: {case_dir.name}")
    required_missing: list[str] = []
    for name, gate in gates.items():
        if not isinstance(name, str) or not isinstance(gate, Mapping):
            raise TypeError(f"orchestration gateが不正です: {case_dir.name}")
        required = gate.get("required")
        satisfied = gate.get("satisfied")
        observed = gate.get("observed")
        if (
            required is not None
            and type(required) is not bool
            or type(satisfied) is not bool
            or observed is not None
            and type(observed) is not bool
        ):
            raise ValueError(f"orchestration gateの型が不正です: {case_dir.name}: {name}")
        expected_status = (
            "not_applicable"
            if required is False
            else "satisfied"
            if satisfied
            else "required_missing"
            if required is True
            else "not_declared"
        )
        if gate.get("status") != expected_status:
            raise ValueError(f"orchestration gateの状態が不整合です: {case_dir.name}: {name}")
        if expected_status == "required_missing":
            required_missing.append(name)

    blockers = outcome.get("blockers")
    next_actions = outcome.get("next_actions_ja")
    if (
        not isinstance(blockers, list)
        or any(not isinstance(value, str) or not value for value in blockers)
        or blockers != sorted(set(blockers))
        or blockers != sorted(required_missing)
        or not isinstance(next_actions, list)
        or len(next_actions) != len(blockers)
        or any(not isinstance(value, str) or not value for value in next_actions)
    ):
        raise ValueError(f"orchestration blockerとnext actionが不整合です: {case_dir.name}")
    expected_outcome_status = "partial" if blockers else "complete"
    if outcome.get("status") != expected_outcome_status:
        raise ValueError(f"orchestration statusがblockerと不整合です: {case_dir.name}")

    function_gate = gates.get("function_analysis")
    if (
        not isinstance(function_gate, dict)
        or function_gate.get("required") is not True
        or function_gate.get("observed") is not None
        or function_gate.get("status") not in {"required_missing", "satisfied"}
    ):
        raise ValueError(f"function_analysis gateが不正です: {case_dir.name}")
    function_missing = function_gate["status"] == "required_missing"
    if function_missing:
        function_index = blockers.index("function_analysis")
        if next_actions[function_index] != FUNCTION_ANALYSIS_NEXT_ACTION_JA:
            raise ValueError(f"function_analysisのnext actionが不正です: {case_dir.name}")
    elif "function_analysis" in blockers or FUNCTION_ANALYSIS_NEXT_ACTION_JA in next_actions:
        raise ValueError(f"解消済みfunction_analysis gateに残余があります: {case_dir.name}")

    generic_missing = False
    generic_gate = gates.get("generic_triage")
    if generic_triage_complete:
        if (
            not isinstance(generic_gate, dict)
            or generic_gate.get("required") is not True
            or generic_gate.get("observed") is not None
            or generic_gate.get("status") not in {"required_missing", "satisfied"}
        ):
            raise ValueError(f"generic_triage gateが不正です: {case_dir.name}")
        generic_missing = generic_gate["status"] == "required_missing"
        if generic_missing:
            generic_index = blockers.index("generic_triage")
            if next_actions[generic_index] != GENERIC_TRIAGE_NEXT_ACTION_JA:
                raise ValueError(f"generic_triageのnext actionが不正です: {case_dir.name}")
        elif "generic_triage" in blockers or GENERIC_TRIAGE_NEXT_ACTION_JA in next_actions:
            raise ValueError(f"解消済みgeneric_triage gateに残余があります: {case_dir.name}")

    validation = validate_function_case(case_dir, case_dir.name)
    if not validation.valid:
        raise ValueError(f"代表関数解析の完了検証に失敗しました: {case_dir.name}: {validation.findings}")

    previous_blockers = list(blockers)
    if function_missing:
        function_gate["satisfied"] = True
        function_gate["status"] = "satisfied"
        blockers.pop(function_index)
        next_actions.pop(function_index)
    if generic_missing:
        generic_gate["satisfied"] = True
        generic_gate["status"] = "satisfied"
        generic_index = blockers.index("generic_triage")
        blockers.pop(generic_index)
        next_actions.pop(generic_index)
    if function_missing or generic_missing:
        outcome["status"] = "partial" if blockers else "complete"
    return {
        "document": outcome,
        "path": orchestration_path,
        "snapshot": orchestration_snapshot,
        "updated": function_missing or generic_missing,
        "previous_blockers": previous_blockers,
        "blockers": list(blockers),
        "status": str(outcome["status"]),
    }


def _verified_manifest_json_snapshot(
    case_dir: Path,
    report: Mapping[str, Any],
    relative: Any,
    *,
    context: str,
) -> _JsonFileSnapshot:
    """report manifestへ結合されたJSONだけを後段transaction入力にする。"""

    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{context}の成果物参照がありません: {case_dir.name}")
    manifest = report.get("artifact_sha256")
    expected = manifest.get(relative) if isinstance(manifest, Mapping) else None
    if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
        raise ValueError(f"{context}がreport manifestへ結合されていません: {case_dir.name}")
    snapshot = _bounded_json_snapshot(resolve_case_artifact(case_dir, relative))
    if snapshot.sha256 != expected:
        raise ValueError(f"{context}のhashがreport manifestと一致しません: {case_dir.name}")
    return snapshot


def _prepare_screenconnect_management_reconciliation(
    case_dir: Path,
    report: dict[str, Any],
    orchestration: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Ghidra後の完了gate上でのみScreenConnect C2契約を再評価する。"""

    classification = report.get("classification")
    selected_families = classification.get("selected_families") if isinstance(classification, Mapping) else None
    selected_screenconnect = isinstance(selected_families, list) and "screenconnect_rmm" in selected_families
    if orchestration is None:
        if selected_screenconnect:
            raise ValueError(f"ScreenConnect caseに検証済みorchestration成果物がありません: {case_dir.name}")
        return None
    outcome = orchestration.get("document")
    resolution = outcome.get("family_resolution") if isinstance(outcome, Mapping) else None
    resolved_family = resolution.get("family") if isinstance(resolution, Mapping) else None
    if resolved_family != "screenconnect_rmm":
        if selected_screenconnect:
            raise ValueError(f"ScreenConnect reportとorchestrationのfamilyが一致しません: {case_dir.name}")
        return None
    if selected_families != ["screenconnect_rmm"]:
        raise ValueError(f"ScreenConnect C2再評価を一意なreport familyへ結合できません: {case_dir.name}")
    state = report.get("case_state")
    if (
        not isinstance(state, Mapping)
        or state.get("status") != "complete"
        or state.get("complete") is not True
        or state.get("resumable") is not True
        or state.get("blockers") != []
        or not isinstance(outcome, dict)
        or outcome.get("status") != "complete"
        or outcome.get("blockers") != []
    ):
        return None

    executions = report.get("handler_executions")
    if executions is None:
        raise ValueError(f"ScreenConnect handler実行記録がありません: {case_dir.name}")
    if not isinstance(executions, list):
        raise ValueError(f"ScreenConnect handler実行記録がありません: {case_dir.name}")
    if not any(isinstance(execution, Mapping) and execution.get("status") == "succeeded" for execution in executions):
        raise ValueError(f"完了ScreenConnect caseに成功handler証拠がありません: {case_dir.name}")
    layer_snapshot = _verified_manifest_json_snapshot(
        case_dir,
        report,
        "static-layers.json",
        context="ScreenConnect static layer",
    )
    handler_results: list[tuple[dict[str, Any], dict[str, Any]]] = []
    input_snapshots = [layer_snapshot]
    seen_results: set[str] = set()
    for execution in executions:
        if not isinstance(execution, dict):
            raise ValueError(f"ScreenConnect handler実行記録が不正です: {case_dir.name}")
        if execution.get("status") != "succeeded":
            continue
        relative = execution.get("result")
        if not isinstance(relative, str) or relative in seen_results:
            raise ValueError(f"ScreenConnect handler成果物参照を一意に解決できません: {case_dir.name}")
        seen_results.add(relative)
        snapshot = _verified_manifest_json_snapshot(
            case_dir,
            report,
            relative,
            context="ScreenConnect handler result",
        )
        input_snapshots.append(snapshot)
        handler_results.append((execution, snapshot.document))

    # publisherと同じstrict helperを使い、別実装による判定差を作らない。
    from publish_one_shot_collection import (  # noqa: PLC0415
        _build_screenconnect_management_contract,
    )

    rebuilt = _build_screenconnect_management_contract(
        digest=case_dir.name,
        public_family="screenconnect-rmm",
        layer_report=layer_snapshot.document,
        handler_results=handler_results,
        report=report,
        orchestration=outcome,
    )
    if rebuilt is None:
        raise ValueError(f"完了ScreenConnect caseのC2契約を再確定できません: {case_dir.name}")
    patterns, contract = rebuilt
    terminal_projection = {
        "status": "recovered",
        "root_sha256": case_dir.name,
        "role": "terminal_managed_client",
        "basis": "validated_static_root_screenconnect_client",
        "claimed_sha256": [],
        "candidates": [],
        "retained": [],
        "verified": [],
    }
    orchestration_updated = False
    for output_name in ("outputs", "candidate_outputs"):
        output = outcome.get(output_name)
        if not isinstance(output, dict):
            raise ValueError(f"完了ScreenConnect caseの{output_name}が不正です: {case_dir.name}")
        if output.get("terminal_payload") != terminal_projection:
            output["terminal_payload"] = dict(terminal_projection)
            orchestration_updated = True
    if (
        contract.get("terminal_payload", {}).get("status") != "recovered"
        or contract.get("terminal_payload", {}).get("reached") is not True
        or patterns.get("config", {}).get("terminal_managed_client") is not True
    ):
        raise ValueError(f"ScreenConnect終端clientの公開projectionが一致しません: {case_dir.name}")
    knowledge = report.get("knowledge_artifacts")
    if not isinstance(knowledge, Mapping):
        raise ValueError(f"ScreenConnect knowledge artifact参照がありません: {case_dir.name}")
    updates = []
    output_paths: set[str] = set()
    for key, document in (
        ("communication_patterns", patterns),
        ("c2_analysis", contract),
    ):
        relative = knowledge.get(key)
        snapshot = _verified_manifest_json_snapshot(
            case_dir,
            report,
            relative,
            context=f"ScreenConnect {key}",
        )
        normalized_relative = str(relative)
        if normalized_relative in output_paths:
            raise ValueError(f"ScreenConnect C2成果物pathが重複しています: {case_dir.name}")
        output_paths.add(normalized_relative)
        updates.append((normalized_relative, snapshot, _json_bytes(document)))
    return {
        "input_snapshots": input_snapshots,
        "updates": updates,
        "orchestration_updated": orchestration_updated,
    }


def finalize_case_report(
    case_dir: Path,
    *,
    transaction_root: Path | None = None,
) -> str:
    """代表関数解析後も未解決blockerを保持し、reportを再封印する。"""

    _recover_finalize_transaction(
        case_dir,
        transaction_root=transaction_root,
    )
    report, report_snapshot = _load_verified_case_report(case_dir)
    state = report.get("case_state")
    if not isinstance(state, dict):
        raise TypeError(f"case_stateがありません: {case_dir.name}")
    blockers = state.get("blockers")
    if (
        not isinstance(blockers, list)
        or any(not isinstance(value, str) or not value for value in blockers)
        or len(blockers) != len(set(blockers))
    ):
        raise ValueError(f"case_state.blockersが配列ではありません: {case_dir.name}")
    status = state.get("status")
    if status not in {"partial", "complete", "triaged_unknown"}:
        raise ValueError(f"Ghidra反映対象外のcase stateです: {case_dir.name}: {status}")
    generic_limit_superseded = _ghidra_supersedes_generic_string_limit(case_dir)
    documented_generic_limits = _ghidra_documents_known_generic_container_limits(case_dir)
    generic_triage_complete = generic_limit_superseded or bool(documented_generic_limits)
    orchestration = _prepare_orchestration_function_reconciliation(
        case_dir,
        report,
        generic_triage_complete=generic_triage_complete,
    )
    if orchestration is not None:
        reported_orchestration = {value for value in blockers if value.startswith("orchestration:")}
        before = {f"orchestration:{value}" for value in orchestration["previous_blockers"]}
        after = {f"orchestration:{value}" for value in orchestration["blockers"]}
        allowed = {frozenset(before)}
        if not orchestration["updated"]:
            allowed.update(
                {
                    frozenset(after),
                    frozenset(after | {ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER}),
                }
            )
        if frozenset(reported_orchestration) not in allowed:
            raise ValueError(f"reportとorchestrationのblockerが一致しません: {case_dir.name}")
    documented_static_issues = _ghidra_documents_known_static_limits(case_dir, state)
    documented_handler_no_evidence = _ghidra_documents_exhaustive_handler_no_evidence(case_dir, report, state)
    if status == "partial":
        resolved_function_blockers = {FUNCTION_ANALYSIS_BLOCKER}
        if orchestration is not None:
            resolved_function_blockers.add(ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER)
            if generic_triage_complete:
                resolved_function_blockers.add(ORCHESTRATION_GENERIC_TRIAGE_BLOCKER)
        remaining = [value for value in blockers if value not in resolved_function_blockers]
        if "generic_triage_partial" in remaining and (generic_limit_superseded or documented_generic_limits):
            remaining.remove("generic_triage_partial")
        if "static_layer_incomplete" in remaining and documented_static_issues:
            remaining.remove("static_layer_incomplete")
            state["static_layer_issues"] = []
            report["documented_static_layer_issues"] = documented_static_issues
            report["static_layer_analysis_completion"] = {
                "basis": "ghidra_complete_coverage_and_exhausted_bounded_static_recovery",
                "raw_evidence": "static-layers.json",
                "supplementary_evidence": "static-logic.json",
            }
            limitation = (
                "静的復元には管理コード解析予算または暗号化RAR復元の文書化済み制限があります。"
                "利用可能な候補を有界に再試行し、Ghidra MCPで全関数台帳と代表関数解析を補完しました。"
            )
            limitations = report.setdefault("limitations", [])
            if limitation not in limitations:
                limitations.append(limitation)
        if documented_handler_no_evidence:
            for blocker in documented_handler_no_evidence["resolved_blockers"]:
                if blocker in remaining:
                    remaining.remove(blocker)
            report["documented_handler_no_evidence"] = documented_handler_no_evidence
            state["incomplete_selected_layer_attempts"] = []
            limitation = (
                "選択ファミリの抽出器は対象となる全復元層で正常終了しましたが、"
                "ファミリ固有の設定またはC2証拠は確認できませんでした。"
                "プロバイダのラベルは出典情報として保持し、静的確認済み属性へは昇格させません。"
            )
            limitations = report.setdefault("limitations", [])
            if limitation not in limitations:
                limitations.append(limitation)
        if remaining:
            state.update(
                {
                    "status": "partial",
                    "complete": False,
                    "resumable": False,
                    "blockers": remaining,
                }
            )
        else:
            if orchestration is not None:
                if orchestration["status"] != "complete":
                    raise ValueError(f"未解決orchestration blockerをreportから除去できません: {case_dir.name}")
                state.update({"status": "complete", "complete": True, "resumable": True, "blockers": []})
            else:
                classification = report.get("classification")
                selected = classification.get("selected_families") if isinstance(classification, Mapping) else None
                automation_status = (
                    classification.get("automation_status") if isinstance(classification, Mapping) else None
                )
                if not isinstance(selected, list):
                    raise ValueError(f"selected_familiesがありません: {case_dir.name}")
                resolved_selection = bool(selected) and automation_status != "unresolved"
                state.update(
                    {
                        "status": "complete" if resolved_selection else "triaged_unknown",
                        "complete": resolved_selection,
                        "resumable": resolved_selection,
                        "blockers": [],
                    }
                )
    elif not (
        status in {"complete", "triaged_unknown"}
        and state.get("complete") is (status == "complete")
        and state.get("resumable") is (status == "complete")
        and blockers == []
    ):
        raise ValueError(f"Ghidra反映対象外のcase stateです: {case_dir.name}: {status}")
    elif orchestration is not None and (status != "complete" or orchestration["status"] != "complete"):
        raise ValueError(f"reportとorchestrationの完了状態が一致しません: {case_dir.name}")
    if report.get("generic_triage") == "partial" and (generic_limit_superseded or documented_generic_limits):
        report["generic_triage"] = "complete"
        report["generic_triage_completion"] = {
            "basis": (
                "ghidra_complete_static_artifact_supersedes_string_retention_limit"
                if generic_limit_superseded
                else "ghidra_complete_coverage_and_bounded_container_recovery"
            ),
            "original_status": "partial",
            "raw_evidence": "generic-triage.json",
            "supplementary_evidence": "static-logic.json",
            "documented_container_limits": documented_generic_limits,
        }
        limitation = (
            "汎用文字列走査は保持上限に達しましたが、Ghidra MCPによる全関数インベントリと"
            "代表関数解析、完全静的成果物で補完しました。"
        )
        if documented_generic_limits:
            limitation = (
                "汎用containerトリアージの限定的な未実装箇所は、静的layer pipelineの完全inventory、"
                "有界な回収試行、再帰解析、およびGhidra MCPの完全coverageで補完しました。"
            )
        limitations = report.setdefault("limitations", [])
        if limitation not in limitations:
            limitations.append(limitation)
    screenconnect_reconciliation = _prepare_screenconnect_management_reconciliation(
        case_dir,
        report,
        orchestration,
    )
    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError(f"成果物hash manifestがありません: {case_dir.name}")
    report["artifact_sha256"] = dict(manifest)
    orchestration_bytes: bytes | None = None
    if orchestration is not None and (
        orchestration["updated"]
        or screenconnect_reconciliation is not None
        and screenconnect_reconciliation["orchestration_updated"]
    ):
        orchestration_bytes = _json_bytes(orchestration["document"])
        report["artifact_sha256"]["orchestration.json"] = hashlib.sha256(orchestration_bytes).hexdigest()
    screenconnect_updates: list[tuple[str, _JsonFileSnapshot, bytes]] = []
    if screenconnect_reconciliation is not None:
        screenconnect_updates = screenconnect_reconciliation["updates"]
        for relative, _snapshot, data in screenconnect_updates:
            report["artifact_sha256"][relative] = hashlib.sha256(data).hexdigest()
    seal_report(report)
    finalized_report_bytes = _json_bytes(report)
    transaction_versions: list[tuple[_JsonFileSnapshot | _ContentFileSnapshot, bytes]] = []
    if orchestration_bytes is not None:
        orchestration_snapshot = orchestration["snapshot"]
        transaction_versions.append((orchestration_snapshot, orchestration_bytes))
    transaction_versions.extend(
        (snapshot, data) for _relative, snapshot, data in screenconnect_updates if snapshot.data != data
    )
    transaction_versions.append((report_snapshot, finalized_report_bytes))
    for input_snapshot in (
        screenconnect_reconciliation["input_snapshots"] if screenconnect_reconciliation is not None else []
    ):
        _assert_snapshot_unchanged(input_snapshot, context="transaction commit直前")
    for snapshot, _data in transaction_versions:
        _assert_transaction_snapshot_unchanged(
            snapshot,
            context="transaction commit直前",
        )
    transaction_dir = _begin_finalize_transaction(
        case_dir,
        transaction_versions,
        transaction_root=transaction_root,
    )
    try:
        _set_finalize_transaction_phase(
            transaction_dir,
            phase="applying",
            applied_count=0,
        )
        for index, (snapshot, data) in enumerate(transaction_versions, start=1):
            _atomic_replace_bytes(
                snapshot.path,
                data,
                expected_snapshot=snapshot,
                temporary_name=f".ghidra-finalize-{index - 1:04d}.tmp",
            )
            _set_finalize_transaction_phase(
                transaction_dir,
                phase="applying",
                applied_count=index,
            )
        _set_finalize_transaction_phase(
            transaction_dir,
            phase="applied",
            applied_count=len(transaction_versions),
        )
        resumable = state.get("status") == "complete"
        errors = case_integrity_errors(
            case_dir,
            report,
            expected_digest=case_dir.name,
            require_resumable=resumable,
        )
        if errors:
            raise ValueError(f"Ghidra反映後のcase整合性検証に失敗しました: {case_dir.name}: {errors}")
        _set_finalize_transaction_phase(
            transaction_dir,
            phase="verified",
            applied_count=len(transaction_versions),
        )
        _safe_remove_finalize_transaction(transaction_dir)
    except BaseException:
        try:
            _recover_finalize_transaction(
                case_dir,
                transaction_root=transaction_root,
            )
        except BaseException as recovery_error:
            raise RuntimeError("Ghidra反映transactionを自動回復できませんでした") from recovery_error
        raise
    return str(state["status"])


def finalize_collection_publication(
    repository: Path,
    collection_dir: Path,
) -> dict[str, Any]:
    """全case完了時だけ索引登録し、残余blockerがあればpartialを明示する。"""

    manifest_path = collection_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    requested = [
        str(item.get("case_id") or "").removeprefix("sha256:").casefold()
        for item in manifest.get("cases", [])
        if isinstance(item, Mapping)
    ]
    case_paths = _case_index(repository)
    by_family: dict[str, list[Path]] = defaultdict(list)
    state_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    for digest in requested:
        case_dir = case_paths.get(digest)
        if case_dir is None:
            raise FileNotFoundError(f"正式公開するcaseが見つかりません: {digest}")
        metadata = json.loads((case_dir / "metadata.json").read_text(encoding="utf-8-sig"))
        family = str(metadata.get("family") or "")
        if not family:
            raise ValueError(f"case metadataにfamilyがありません: {digest}")
        report = load_json_object_strict(case_dir / "report.json")
        state = report.get("case_state")
        status = str(state.get("status") if isinstance(state, Mapping) else "invalid")
        state_counts[status] += 1
        blockers = state.get("blockers") if isinstance(state, Mapping) else []
        if isinstance(blockers, list):
            blocker_counts.update(str(blocker) for blocker in blockers if isinstance(blocker, str) and blocker.strip())
        by_family[family].append(case_dir)
    complete_statuses = {"complete"}
    all_complete = bool(requested) and set(state_counts) <= complete_statuses
    publication_stage = "complete" if all_complete else "partial_followup_required"
    registrations = {}
    for family, paths in sorted(by_family.items()):
        aggregate = collection_dir / "sources" / family
        context = detect_publication_context(aggregate, family)
        if context is None:
            raise ValueError(f"collection公開contextを解決できません: {family}")
        registrations[family] = register_publication_cases(context, paths)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    manifest.update(
        {
            "analysis_complete": all_complete,
            "complete": all_complete,
            "publication_stage": publication_stage,
            "case_state_counts": dict(sorted(state_counts.items())),
            "case_blocker_counts": dict(sorted(blocker_counts.items())),
        }
    )
    _json_dump(manifest_path, manifest)
    summary_path = collection_dir / "publication-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
    summary.update(
        {
            "analysis_complete": all_complete,
            "publication_stage": publication_stage,
            "case_state_counts": dict(sorted(state_counts.items())),
            "case_blocker_counts": dict(sorted(blocker_counts.items())),
        }
    )
    _json_dump(summary_path, summary)
    readme_path = collection_dir / "README.md"
    readme = readme_path.read_text(encoding="utf-8-sig")
    readme = re.sub(r"(?m)^- case状態:.*\n?", "", readme)
    readme = re.sub(
        r"(?s)\n<!-- publication-followup:start -->.*?<!-- publication-followup:end -->\n?",
        "\n",
        readme,
    )
    state_summary = " / ".join(
        f"{status} {state_counts.get(status, 0)}" for status in ("complete", "partial", "triaged_unknown")
    )
    readme = re.sub(
        r"(?m)^- 公開段階: `[^`]+`$",
        f"- 公開段階: `{publication_stage}`\n- case状態: {state_summary}",
        readme,
    )
    if blocker_counts:
        descriptions = {
            "generic_triage_partial": "汎用トリアージまで完了し、ファミリー固有設定または終端C2の静的回収が未完了",
            "static_layer_incomplete": "静的復元層に追加追跡が必要",
        }
        followup_lines = [
            "",
            "<!-- publication-followup:start -->",
            "## 未完了項目",
            "",
            "関数単位の静的解析とは別に、設定抽出・終端C2・ファミリー帰属の追加確認が必要な項目を示します。関数解析が完了していても、これらの残余項目があればcollection全体を完了扱いにしません。",
            "",
            "| 理由 | case数 | 内容 |",
            "|---|---:|---|",
        ]
        for blocker, count in sorted(blocker_counts.items()):
            description = descriptions.get(blocker, "追加の静的確認が必要")
            followup_lines.append(f"| `{blocker}` | {count} | {description} |")
        followup_lines.extend(
            [
                "",
                "確認済み静的C2観測は抽出証拠を表し、到達性確認を意味しません。この実行ではC2／配布先への能動接続を行っていません。",
                "<!-- publication-followup:end -->",
                "",
            ]
        )
        readme = readme.rstrip() + "\n" + "\n".join(followup_lines)
    readme_path.write_text(readme, encoding="utf-8")
    return {
        "analysis_complete": all_complete,
        "publication_stage": publication_stage,
        "registrations": registrations,
        "cases": len(requested),
        "case_state_counts": dict(sorted(state_counts.items())),
        "case_blocker_counts": dict(sorted(blocker_counts.items())),
    }


def _program_evidence(result: Mapping[str, Any]) -> dict[str, Any]:
    metadata = result.get("metadata", {})
    entries = []
    raw_entries = result.get("entry_points")
    if isinstance(raw_entries, str):
        for line in raw_entries.splitlines():
            match = re.match(r"\s*(.+?)\s*[-=]>\s*([0-9a-fA-F:]+)", line)
            if not match:
                match = re.match(r"\s*(.+?)\s+@\s+([0-9a-fA-F:]+)", line)
            if match:
                entries.append(
                    {
                        "name": match.group(1),
                        "address": match.group(2),
                        "kind": "entry_point",
                    }
                )
    hashes = [
        item
        for item in (result.get("opcode_hashes", {}) or {}).get("functions", [])
        if isinstance(item, Mapping)
        and int(item.get("instruction_count") or 0) > 0
        and str(item.get("hash") or "") != EMPTY_SHA256
    ]
    imports = []
    for item in result.get("imports", []):
        if isinstance(item, Mapping):
            name = str(item.get("name") or item.get("symbol") or "").strip()
        else:
            name = str(item).strip()
        if name:
            imports.append(redact_static_text(name))
    recovery_source = result.get("entry_point_function_recovery")
    recovery = {}
    if isinstance(recovery_source, Mapping):
        recovery = {
            key: recovery_source[key]
            for key in (
                "schema_version",
                "status",
                "reason",
                "attempted",
                "initial_function_count",
                "final_function_count",
                "candidate_count",
                "validated_segment_name",
            )
            if key in recovery_source
        }
        validation_source = recovery_source.get("validation")
        if isinstance(validation_source, Mapping):
            validation: dict[str, Any] = {}
            pe_source = validation_source.get("pe_entry_point")
            if isinstance(pe_source, Mapping):
                validation["pe_entry_point"] = {
                    key: pe_source[key]
                    for key in (
                        "status",
                        "reason",
                        "matching_section_count",
                        "section_executable",
                    )
                    if key in pe_source
                }
            for key in (
                "ghidra_program_entry_unique",
                "ghidra_segment_contains_entry",
                "ghidra_matching_segment_count",
            ):
                if key in validation_source:
                    validation[key] = validation_source[key]
            recovery["validation"] = validation
    return {
        "program_id": f"sha256:{result['sha256']}",
        "program_selector": result["program_selector"],
        "analysis_mode": str(result.get("analysis_mode") or "unknown"),
        "relationship": (
            "root_program"
            if any(int(item["depth"]) == 0 for item in result.get("relationships", []))
            else "statically_recovered_program"
        ),
        "name": str(result["sha256"]),
        "architecture": str(metadata.get("architecture") or "unknown"),
        "compiler": str(metadata.get("compiler") or "unknown"),
        "language": str(metadata.get("language") or "unknown"),
        "endian": str(metadata.get("endian") or "unknown"),
        "address_size": str(metadata.get("address_size") or "unknown"),
        "base_address": str(metadata.get("base_address") or "unknown"),
        "memory_blocks": int(re.search(r"\d+", str(metadata.get("memory_blocks") or "0")).group())
        if re.search(r"\d+", str(metadata.get("memory_blocks") or "0"))
        else 0,
        "total_memory_size": int(re.search(r"\d+", str(metadata.get("total_memory_size") or "0")).group())
        if re.search(r"\d+", str(metadata.get("total_memory_size") or "0"))
        else 0,
        "function_count": int(result.get("characteristic_function_count") or 0),
        "ghidra_function_count": int(result.get("ghidra_function_inventory_count") or 0),
        "managed_method_count": int(result.get("managed_method_count") or 0),
        "mcp_responses_valid": result.get("mcp_responses_valid") is True,
        "symbol_count": int(re.search(r"\d+", str(metadata.get("symbol_count") or "0")).group())
        if re.search(r"\d+", str(metadata.get("symbol_count") or "0"))
        else 0,
        "entry_points": entries,
        "entry_point_function_recovery": recovery,
        "imports": imports,
        "retrieval_coverage": dict(result.get("retrieval_coverage") or {}),
        "function_hashes": hashes,
        "function_hash_coverage": {
            "total_functions": len([item for item in result.get("functions", []) if isinstance(item, Mapping)]),
            "valid_opcode_hashes": len(hashes),
            "all_functions_requested": True,
        },
        "confidence": "confirmed_program_structure",
    }


def _build_overall_logic(report: Mapping[str, Any]) -> dict[str, Any]:
    """代表関数と観測call edgeから検体全体の処理像を構成する。"""

    functions = [item for item in report.get("functions", []) if isinstance(item, Mapping)]
    programs = [item for item in report.get("program_evidence", []) if isinstance(item, Mapping)]
    phase_descriptions = {
        "startup": "entry pointから初期化と後続処理への移行を確認します。",
        "configuration": "設定、resource、payload、暗号化データの復元・変換を確認します。",
        "evasion": "debugger、sandbox、仮想環境、時間差などの判定を確認します。",
        "persistence": "自動起動や永続化に関係する設定変更を確認します。",
        "execution": "process、thread、module、memory操作と実行移行を確認します。",
        "communication": "通信初期化、endpoint処理、送受信の役割を確認します。",
        "dispatch": "受信commandやtaskの解釈、分配、個別handlerへの移行を確認します。",
        "file_activity": "fileやdirectoryの作成、読書き、削除を確認します。",
        "support": "主要処理を支える一般内部関数またはlibrary処理を確認します。",
    }
    phases = []
    phase_by_function: dict[str, str] = {}
    for phase_id, title, roles in CHARACTERISTIC_PHASES:
        matched = [item for item in functions if str(item.get("role") or "") in roles]
        if not matched:
            continue
        function_ids = [str(item.get("function_id") or "") for item in matched]
        for function_id in function_ids:
            phase_by_function[function_id] = phase_id
        constrained = any(
            str(item.get("function_analysis", {}).get("decompilation_status") or "") != "succeeded" for item in matched
        )
        phases.append(
            {
                "phase_id": phase_id,
                "title_ja": title,
                "description_ja": phase_descriptions[phase_id],
                "function_ids": function_ids,
                "roles": sorted({str(item.get("role") or "unknown") for item in matched}),
                "confidence": (
                    "confirmed_static_function_evidence_with_limits"
                    if constrained
                    else "confirmed_static_function_evidence"
                ),
            }
        )
    if not phases and functions:
        function_ids = [str(item.get("function_id") or "") for item in functions]
        phases.append(
            {
                "phase_id": "support",
                "title_ja": "分類未確定の代表関数",
                "description_ja": (
                    "代表関数は取得できましたが、静的証跡だけでは主要な処理段階へ自動分類できませんでした。"
                ),
                "function_ids": function_ids,
                "roles": sorted({str(item.get("role") or "unclassified") for item in functions}),
                "confidence": "confirmed_static_function_evidence_with_classification_limit",
            }
        )
        phase_by_function.update({function_id: "support" for function_id in function_ids})
    if not phases:
        entry_point_count = sum(len(item.get("entry_points") or []) for item in programs)
        import_names: set[str] = set()
        for item in programs:
            for value in item.get("imports", []):
                if isinstance(value, Mapping):
                    name = str(value.get("name") or value.get("symbol") or "")
                else:
                    name = str(value)
                if name.strip():
                    import_names.add(name.strip())
        imports = sorted(import_names)
        phases.append(
            {
                "phase_id": "program_structure",
                "title_ja": "program構造限定解析",
                "description_ja": (
                    f"Ghidra MCPで{len(programs)}個のprogram、"
                    f"{entry_point_count}件のentry point、{len(imports)}件のimportを"
                    "確認しましたが、解析可能な関数本体は認識されませんでした。"
                ),
                "function_ids": [],
                "roles": ["program_structure_without_function_body"],
                "confidence": "confirmed_program_structure_with_function_recovery_limit",
            }
        )
        for phase_id, title, roles in CHARACTERISTIC_PHASES:
            pattern = IMPORT_CAPABILITY_PATTERNS.get(phase_id)
            if pattern is None:
                continue
            hits = [name for name in imports if pattern.search(name)]
            if not hits:
                continue
            phases.append(
                {
                    "phase_id": f"import_capability_{phase_id}",
                    "title_ja": f"import上の能力候補：{title}",
                    "description_ja": (
                        "import表に関連APIが存在します。能力候補を示す証跡であり、"
                        "実行経路や悪性動作の成立を単独では証明しません。"
                    ),
                    "function_ids": [],
                    "roles": sorted(roles),
                    "import_evidence": hits[:64],
                    "confidence": "confirmed_import_presence_not_execution",
                }
            )
    observed_edges = []
    for edge in report.get("call_edges", []):
        if not isinstance(edge, Mapping):
            continue
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        observed_edges.append(
            {
                "caller": caller,
                "callee": callee,
                "caller_phase": phase_by_function.get(caller, "unclassified"),
                "callee_phase": phase_by_function.get(callee, "unclassified"),
                "confidence": "confirmed_static_call_relationship",
            }
        )
    active_titles = [str(item["title_ja"]) for item in phases if item["phase_id"] != "support"]
    if not functions:
        capability_titles = [
            str(item["title_ja"]).removeprefix("import上の能力候補：")
            for item in phases
            if str(item.get("phase_id") or "").startswith("import_capability_")
        ]
        summary = (
            "Ghidra MCPでprogram構造を取得しましたが、解析可能な関数本体は"
            "認識されなかったため、関数ロジックを断定せず構造限定結果を記録します。"
        )
        if capability_titles:
            summary += " import表から、" + "、".join(capability_titles) + "に関連する能力候補を整理しました。"
    elif active_titles:
        summary = "代表関数の静的証跡から、" + "、".join(active_titles) + "の処理群を確認しました。"
    else:
        summary = "代表関数から主要なmalware処理段階を自動分類できませんでした。"
    limitations = [
        "選定外関数は全体inventoryへ残しますが、関数本体の個別解説対象にはしていません。",
        "indirect call、難読化、packer、VM、壊れたcontrol flowによりcall関係が欠落する場合があります。",
        "文書は静的解析に基づき、検体実行や外部通信による動的確認は行っていません。",
    ]
    if not functions:
        limitations.insert(
            0,
            "Ghidraで関数本体を認識できなかったため、entry point、import、export、segment等のprogram構造だけを確認しています。",
        )
        recovery_reasons = sorted(
            {
                str(recovery.get("reason") or "unknown")
                for program in programs
                if isinstance(
                    recovery := program.get("entry_point_function_recovery"),
                    Mapping,
                )
                and recovery.get("status") in {"not_attempted", "failed"}
            }
        )
        if recovery_reasons:
            limitations.insert(
                1,
                "entry pointからの関数回復は安全条件を満たさないかMCP処理を検証できず、"
                "未完了です（理由code: " + ", ".join(recovery_reasons) + "）。",
            )
    return {
        "schema_version": 1,
        "visualization_contract_version": 1,
        "summary_ja": summary,
        "phase_order_basis": (
            "phaseの掲載順は解析上の整理順です。observed_call_edgesがない段階間の実行順を断定しません。"
        ),
        "phases": phases,
        "observed_call_edges": observed_edges,
        "selected_function_count": len(functions),
        "selection_dimensions": [
            "entry point",
            "malware固有の役割",
            "call graph中心性",
            "関数規模",
            "symbol名の情報量",
        ],
        "limitations_ja": limitations,
    }


def _escape_public_replacement_characters(value: Any) -> Any:
    """Escape Ghidra display replacement characters before publication."""

    if isinstance(value, str):
        return value.replace("\ufffd", r"\uFFFD")
    if isinstance(value, Mapping):
        return {
            _escape_public_replacement_characters(key): _escape_public_replacement_characters(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_escape_public_replacement_characters(item) for item in value]
    return value


def _markdown_code_value(value: Any) -> str:
    """識別子を内容を変えずMarkdownの1行code表示へ整える。"""

    rendered = re.sub(r"\s+", " ", redact_static_text(str(value))).strip()
    return rendered.replace("`", "'") or "未記録"


def _render_overall_logic(
    report: Mapping[str, Any],
    static_layers: Mapping[str, Any] | None = None,
) -> str:
    """全体ロジックと3種類の静的Mermaid図を日本語文書へ描画する。"""

    return render_overall_logic_markdown(report, static_layers)


def _render_markdown(report: Mapping[str, Any]) -> str:
    coverage = report["coverage"]
    functions = list(report.get("functions", []))
    roles = Counter(str(item["role"]) for item in functions)
    failures = [
        item
        for item in functions
        if str(item.get("function_analysis", {}).get("decompilation_status", ""))
        not in {
            "succeeded",
            "no_managed_body",
            "excluded_external_or_thunk",
            "static_script_structure_recorded",
        }
    ]
    high_signal = functions
    lines = [
        f"# 静的ロジック解析：{report['sha256']}",
        "",
        "選定可能な代表関数の逆コンパイル／CIL解析、call関係、API参照、",
        "役割、処理順、fingerprint、選定理由を記録しました。機械可読結果は",
        "`static-logic.json`に保存し、生の逆コンパイル本文は公開していません。",
        "",
        "## 解析状態",
        "",
        f"- 状態: `{report['status']}`",
        f"- Ghidraプログラム: {coverage['ghidra_program_count']}",
        f"- 発見関数／メソッドinventory: {coverage['discovered_function_inventory_count']}",
        f"- 代表関数: {coverage['characteristic_function_selected_count']}",
        f"- Ghidra関数: {coverage['ghidra_function_inventory_count']}",
        f"- managedメソッド: {coverage['managed_method_inventory_count']}",
        f"- MCP成功証跡付きプログラム: {coverage['ghidra_programs_with_valid_mcp_responses']}",
        f"- 逆コンパイル／CIL解析試行: {coverage['decompilation_attempted_count']}",
        f"- 成功: {coverage['decompilation_succeeded_count']}",
        f"- 制約付き／失敗: {coverage['decompilation_limited_or_failed_count']}",
        f"- external／thunk／本体なし: {coverage['decompilation_excluded_count']}",
        f"- 呼出関係: {coverage['call_edge_count']}",
        "",
        "## プログラム取得範囲",
        "",
        "| プログラムselector | 関係 | 代表関数 | Ghidra inventory | CIL inventory | MCP | opcode hash |",
        "|---|---|---:|---:|---:|---|---:|",
    ]
    for program in report.get("program_evidence", []):
        lines.append(
            f"| `{program['program_selector']}` | `{program['relationship']}` | "
            f"{program['function_count']} | {program['ghidra_function_count']} | "
            f"{program['managed_method_count']} | "
            f"{'成功' if program['mcp_responses_valid'] else '失敗'} | "
            f"{len(program['function_hashes'])} |"
        )
    lines.extend(
        [
            "",
            "## 役割別集計",
            "",
            "| 役割 | 件数 |",
            "|---|---:|",
        ]
    )
    for role, count in sorted(roles.items(), key=lambda value: (-value[1], value[0])):
        lines.append(f"| `{role}` | {count} |")
    lines.extend(["", "## 重要関数", ""])
    if not high_signal:
        lines.append("- Ghidraで解析可能な関数本体を認識できなかったため、program構造限定の解析結果を記録しました。")
    for function in high_signal[:100]:
        analysis = function.get("function_analysis", {})
        lines.extend(
            [
                f"### `{function['function_id']}`",
                "",
                f"- 役割: `{function['role']}`",
                f"- アドレス／トークン: `{function['address_or_token']}`",
                f"- 状態: `{analysis.get('decompilation_status', 'unknown')}`",
                f"- 要約: {function['summary_ja']}",
                f"- 選定理由: {', '.join(f'`{_markdown_code_value(value)}`' for value in function.get('selection', {}).get('reasons', [])) or '記録なし'}",
                f"- 呼出元: {', '.join(f'`{_markdown_code_value(value)}`' for value in function['callers'][:16]) or 'なし'}",
                f"- 呼出先／API: {', '.join(f'`{_markdown_code_value(value)}`' for value in (function['callees'] + function['api_calls'])[:16]) or 'なし'}",
                "",
            ]
        )
        lines.extend(
            f"{index}. {_markdown_code_value(step)}"
            for index, step in enumerate(function.get("logic_steps_ja", []), start=1)
        )
        lines.append("")
    if len(high_signal) > 100:
        lines.append(f"- 残り{len(high_signal) - 100}件の代表関数は`static-logic.json`に記録しています。")
        lines.append("")
    lines.extend(["## 逆コンパイル制約", ""])
    if not functions:
        lines.append(
            "- 関数inventoryが0件のため逆コンパイル対象はありません。"
            "entry point、import、export、segment等の構造取得結果は保持しています。"
        )
        for program in report.get("program_evidence", []):
            recovery = program.get("entry_point_function_recovery", {})
            if isinstance(recovery, Mapping) and recovery.get("status") in {
                "not_attempted",
                "failed",
            }:
                lines.append(
                    "- `"
                    + _markdown_code_value(program.get("program_selector") or "unknown")
                    + "`: entry point関数回復は `"
                    + _markdown_code_value(recovery.get("status") or "unknown")
                    + "`（理由: `"
                    + _markdown_code_value(recovery.get("reason") or "unknown")
                    + "`）です。"
                )
    elif not failures:
        lines.append("- 制約付きまたは失敗として残った関数はありません。")
    for function in failures[:100]:
        analysis = function.get("function_analysis", {})
        lines.append(
            f"- `{function['function_id']}`: "
            f"`{analysis.get('decompilation_status', 'unknown')}`。"
            f"{analysis.get('next_analysis') or '追加解析方針はrecord内に記録しています。'}"
        )
    if len(failures) > 100:
        lines.append(f"- 残り{len(failures) - 100}件の制約は`static-logic.json`に記録しています。")
    lines.extend(
        [
            "",
            "## 安全境界",
            "",
            "- 検体、復元layer、CIL、逆コンパイル結果を実行またはemulateしていません。",
            "- 検体由来のnetwork endpointへ接続していません。",
            "- Ghidraの任意script実行は有効化していません。",
            "- 生の逆コンパイル本文とCIL命令列はリポジトリ外へ保持しています。",
            "",
        ]
    )
    return "\n".join(lines)


def _enrich_normalized_functions(
    report: dict[str, Any],
    source_records: Iterable[Mapping[str, Any]],
) -> None:
    source_by_id = {
        str(item["function_id"]): item
        for item in source_records
        if isinstance(item, Mapping) and item.get("function_id")
    }
    for function in report.get("functions", []):
        source = source_by_id.get(str(function["function_id"]), {})
        is_script = str(source.get("tool") or "") == "bounded_script_static_parser"
        function["function_analysis"] = {
            "analysis_kind": str(source.get("analysis_kind") or "unknown"),
            "source_program_sha256": str(source.get("source_program_sha256") or ""),
            "relationship": str(source.get("relationship") or ""),
            "decompilation_status": str(
                source.get("decompilation_status") or ("static_script_structure_recorded" if is_script else "unknown")
            ),
            "decompilation_warnings": [
                redact_static_text(str(value)) for value in source.get("decompilation_warnings", [])
            ],
            "decompilation_error": str(source.get("decompilation_error") or ""),
            "opcode_sha256": str(source.get("opcode_sha256") or ""),
            "instruction_count": int(source.get("instruction_count") or 0),
            "next_analysis": str(
                source.get("next_analysis")
                or ("必要に応じてscript ASTと難読化解除結果を手動確認します。" if is_script else "")
            ),
            "static_analysis_fields_retained": True,
            "source_field_counts": {
                "logic_steps": len(source.get("logic_steps_ja") or []),
                "callers": len(source.get("callers") or []),
                "callees": len(source.get("callees") or []),
                "api_calls": len(source.get("api_calls") or []),
                "constants": len(source.get("constants") or []),
                "decompilation_warnings": len(source.get("decompilation_warnings") or []),
            },
        }


def _call_graph_acquisition_summary(
    program_results: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """private取得証跡だけから公開call graph取得状態を決定する。"""

    if not program_results:
        return {
            "status": "not_applicable_no_ghidra_program",
            "acquired_edge_count": 0,
            "native_program_count": 0,
            "managed_not_applicable_program_count": 0,
            "partial_program_count": 0,
        }
    native_programs = 0
    managed_programs = 0
    partial_programs = 0
    acquired_edges = 0
    for result in program_results:
        state = _call_graph_retrieval_state(result)
        if state == "complete":
            native_programs += 1
            acquired_edges += int(result["retrieval_coverage"]["call_graph"]["edge_count"])
        elif state == "managed_not_applicable":
            managed_programs += 1
        elif state == "legacy_partial":
            partial_programs += 1
        else:
            raise ValueError("call graph取得証跡が不正なprogram-resultです")
    if partial_programs:
        status = "partial_documented_limit"
    elif native_programs and acquired_edges:
        status = "acquired_with_edges"
    elif native_programs:
        status = "acquired_without_edges"
    else:
        status = "not_applicable_managed_cil_primary"
    return {
        "status": status,
        "acquired_edge_count": acquired_edges,
        "native_program_count": native_programs,
        "managed_not_applicable_program_count": managed_programs,
        "partial_program_count": partial_programs,
    }


def _merge_acquired_call_graph(
    report: dict[str, Any],
    program_results: Sequence[Mapping[str, Any]],
) -> int:
    """取得済みGhidra edgeをraw address非公開の安定IDへ正規化して保持する。"""

    normalized: set[tuple[str, str]] = {
        (str(edge.get("caller") or ""), str(edge.get("callee") or ""))
        for edge in report.get("call_edges", [])
        if isinstance(edge, Mapping) and edge.get("caller") and edge.get("callee")
    }

    def opaque_id(program_sha256: str, kind: str, value: str) -> str:
        identity = hashlib.sha256(f"{program_sha256}\0{kind}\0{value}".encode()).hexdigest()[:24]
        return f"ghidra-{kind}:{identity}"

    acquisition = _call_graph_acquisition_summary(program_results)
    for result in program_results:
        if _call_graph_retrieval_state(result) == "legacy_partial":
            continue
        program_sha256 = str(result.get("sha256") or "")
        graph = result.get("call_graph")
        edges = graph.get("edges") if isinstance(graph, Mapping) else None
        if not SHA256_RE.fullmatch(program_sha256) or not isinstance(edges, list):
            continue
        for edge in edges:
            if not isinstance(edge, Mapping):
                continue
            caller = str(edge.get("caller_addr") or "").strip()
            callee_addr = str(edge.get("callee_addr") or "").strip()
            callee_name = str(edge.get("callee_name") or "").strip()
            if not caller or not (callee_addr or callee_name):
                continue
            caller_id = opaque_id(program_sha256, "function", caller)
            callee_id = opaque_id(
                program_sha256,
                "function" if callee_addr else "external",
                callee_addr or callee_name,
            )
            if caller_id != callee_id:
                normalized.add((caller_id, callee_id))
    report["call_edges"] = [{"caller": caller, "callee": callee} for caller, callee in sorted(normalized)]
    coverage = report.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("static logic coverageがobjectではありません")
    coverage["call_edge_count"] = len(normalized)
    coverage["call_graph_recorded"] = bool(normalized)
    coverage["acquired_call_graph_edge_count"] = acquisition["acquired_edge_count"]
    coverage["acquired_call_graph_edges_normalized"] = acquisition["status"] != "partial_documented_limit"
    coverage["call_graph_acquisition_status"] = acquisition["status"]
    coverage["call_graph_native_program_count"] = acquisition["native_program_count"]
    coverage["call_graph_managed_not_applicable_program_count"] = acquisition["managed_not_applicable_program_count"]
    coverage["call_graph_partial_program_count"] = acquisition["partial_program_count"]
    return int(acquisition["acquired_edge_count"])


def _selected_script_records(
    non_pe: Mapping[str, list[dict[str, Any]]],
    case_sha: str,
) -> list[dict[str, Any]]:
    """非PE layerから公開対象の静的script関数recordを選定する。"""

    selected_records: list[dict[str, Any]] = []
    for relation in non_pe.get(case_sha, []):
        for record in relation.get("script_function_records", []):
            if not isinstance(record, Mapping):
                continue
            selected = dict(record)
            selected["selected_for_characteristic_analysis"] = True
            selected["selection_score"] = 1_000
            selected["selection_reasons"] = ["static_script_entry_or_function"]
            selected_records.append(selected)
    return selected_records


def _require_case_static_evidence(
    case_sha: str,
    related: Sequence[Mapping[str, Any]],
    script_records: Sequence[Mapping[str, Any]],
    non_pe_relations: Sequence[Mapping[str, Any]],
) -> None:
    """Ghidra program、静的script関数、非PE layer証跡のいずれかを要求する。"""

    if not related and not script_records and not non_pe_relations:
        raise ValueError(f"caseへ対応するGhidra program、静的script関数、非PE layer証跡がありません: {case_sha}")


def _snapshot_publication_case(
    case_dir: Path,
    report: Mapping[str, Any],
    *,
    verify_manifest: bool = True,
) -> dict[str, _ContentFileSnapshot]:
    """case tree全体を通常fileとして固定し、report manifestとの結合も検証する。"""

    ensure_no_reparse_components(case_dir)
    metadata = case_dir.lstat()
    if _stat_is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("公開caseは通常directoryに限定します")
    snapshots: dict[str, _ContentFileSnapshot] = {}
    folded_names: set[str] = set()
    for path in sorted(case_dir.rglob("*"), key=lambda value: value.as_posix().casefold()):
        information = path.lstat()
        if _stat_is_reparse(information):
            raise ValueError(f"公開caseにreparse pointがあります: {path.name}")
        if stat.S_ISDIR(information.st_mode):
            continue
        if not stat.S_ISREG(information.st_mode) or int(information.st_nlink) != 1:
            raise ValueError(f"公開caseに未許可fileがあります: {path.name}")
        relative = normalize_artifact_path(path.relative_to(case_dir).as_posix())
        folded = relative.casefold()
        if folded in folded_names:
            raise ValueError("公開caseに大文字小文字衝突pathがあります")
        if Path(relative).name.casefold() == "datastore-upload.json":
            raise ValueError("datastore-upload.jsonは公開成果物へ含められません")
        folded_names.add(folded)
        snapshots[relative] = _bounded_content_snapshot(path)
    if "report.json" not in snapshots:
        raise ValueError(f"公開caseにreport.jsonがありません: {case_dir.name}")
    if verify_manifest:
        manifest = report.get("artifact_sha256")
        if not isinstance(manifest, Mapping) or not manifest:
            raise ValueError(f"成果物hash manifestがありません: {case_dir.name}")
        for raw_relative, expected in manifest.items():
            relative = normalize_artifact_path(raw_relative)
            snapshot = snapshots.get(relative)
            if (
                snapshot is None
                or not isinstance(expected, str)
                or SHA256_RE.fullmatch(expected) is None
                or snapshot.sha256 != expected
            ):
                raise ValueError(f"公開case treeとreport manifestが一致しません: {case_dir.name}: {relative}")
    return snapshots


def _verify_case_wide_artifact_hashes(
    case_dir: Path,
    report: Mapping[str, Any],
) -> None:
    """report seal配下のcase-wide hash集合を実tree全体と照合する。"""

    manifest = report.get("case_wide_artifact_sha256")
    if manifest is None:
        return
    if not isinstance(manifest, Mapping) or not manifest:
        raise ValueError(f"case-wide成果物hash manifestが不正です: {case_dir.name}")
    snapshots = _snapshot_publication_case(
        case_dir,
        report,
        verify_manifest=False,
    )
    expected_names = set(snapshots) - {"report.json"}
    observed_names: set[str] = set()
    for raw_relative, expected in manifest.items():
        relative = normalize_artifact_path(raw_relative)
        snapshot = snapshots.get(relative)
        if (
            relative in observed_names
            or snapshot is None
            or not isinstance(expected, str)
            or SHA256_RE.fullmatch(expected) is None
            or snapshot.sha256 != expected
        ):
            raise ValueError(f"case-wide成果物hashが一致しません: {case_dir.name}: {relative}")
        observed_names.add(relative)
    if observed_names != expected_names:
        raise ValueError(f"case-wide成果物集合が一致しません: {case_dir.name}")


def _assert_publication_case_unchanged(
    case_dir: Path,
    snapshots: Mapping[str, _ContentFileSnapshot],
) -> None:
    """WAL作成直前にfile集合、identity、全bytesのいずれの競合も拒否する。"""

    current_names = {
        normalize_artifact_path(path.relative_to(case_dir).as_posix()) for path in case_dir.rglob("*") if path.is_file()
    }
    if current_names != set(snapshots):
        raise ValueError("case-wide transaction commit直前でfile集合が変更されました")
    for snapshot in snapshots.values():
        _assert_content_snapshot_unchanged(
            snapshot,
            context="case-wide transaction commit直前",
        )


def _publication_shadow_directory(
    case_dir: Path,
    transaction_root: Path | None,
) -> Path:
    """公開case外の短い決定的pathへshadow directoryを割り当てる。"""

    case_absolute = Path(os.path.abspath(case_dir))
    del transaction_root
    root = (
        Path(tempfile.gettempdir())
        / "ai-security-analysis-ghidra-publication-shadow"
        / _case_path_commitment(case_absolute)[:32]
    )
    if root == case_absolute or case_absolute in root.parents:
        raise ValueError("公開shadowをcase directory内へ配置できません")
    ensure_no_reparse_components(root)
    root.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(root)
    root_metadata = root.lstat()
    if _stat_is_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("公開shadow rootは通常directoryに限定します")
    return root / case_absolute.name


def _safe_remove_publication_shadow(shadow: Path) -> None:
    """reparse／hardlinkを含まない既知shadowだけを削除する。"""

    ensure_no_reparse_components(shadow)
    metadata = shadow.lstat()
    if _stat_is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("公開shadowは通常directoryに限定します")
    for path in shadow.rglob("*"):
        information = path.lstat()
        if _stat_is_reparse(information) or not (
            stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode)
        ):
            raise ValueError("公開shadowに未許可entryがあります")
        if stat.S_ISREG(information.st_mode) and int(information.st_nlink) != 1:
            raise ValueError("公開shadowにhardlinkは使用できません")
    shutil.rmtree(shadow)


def _publication_shadow_transaction_root(
    shadow: Path,
    transaction_root: Path | None,
) -> Path:
    """Windowsのpath長上限を避けたshadow専用WAL rootを返す。"""

    if transaction_root is None:
        return (
            Path(tempfile.gettempdir())
            / "ai-security-analysis-ghidra-shadow-wal"
            / _case_path_commitment(shadow)[:32]
        )
    return Path(os.path.abspath(transaction_root)).parent / "shadow-wal"


def _prepare_publication_shadow(
    case_dir: Path,
    snapshots: Mapping[str, _ContentFileSnapshot],
    *,
    transaction_root: Path | None,
) -> Path:
    """認証済み旧caseをprivate shadowへ複製する。"""

    shadow = _publication_shadow_directory(case_dir, transaction_root)
    shadow_transaction_root = _publication_shadow_transaction_root(
        shadow,
        transaction_root,
    )
    if os.path.lexists(shadow):
        _recover_finalize_transaction(
            shadow,
            transaction_root=shadow_transaction_root,
        )
        _safe_remove_publication_shadow(shadow)
    elif os.path.lexists(shadow_transaction_root / shadow.name):
        raise ValueError("公開shadow本体のない未回復transactionがあります")
    shadow.mkdir()
    for relative, snapshot in sorted(snapshots.items()):
        destination = shadow / Path(relative)
        _atomic_replace_bytes(
            destination,
            snapshot.data,
            maximum_bytes=MAX_JSON_OBJECT_SIZE,
            require_absent=True,
        )
    return shadow


def _replace_markdown_section(markdown: str, heading: str, body: Sequence[str]) -> str:
    """同名H2 sectionを決定的に置換し、なければ末尾へ追加する。"""

    section = "\n".join([f"## {heading}", "", *body, ""])
    pattern = re.compile(rf"(?ms)^## {re.escape(heading)}\s*$.*?(?=^##\s|\Z)")
    if pattern.search(markdown):
        return pattern.sub(section, markdown).rstrip() + "\n"
    return markdown.rstrip() + "\n\n" + section


def _enrich_shadow_behavior_documents(case_dir: Path) -> None:
    """Ghidraの具体的な書出し・process起動能力を人間向け成果物へ投影する。"""

    logic = load_json_object_strict(case_dir / "static-logic.json")
    analysis_snapshot = _bounded_json_snapshot(case_dir / "analysis.json")
    analysis = analysis_snapshot.document
    readme_snapshot = _bounded_content_snapshot(case_dir / "README.md")
    readme = readme_snapshot.data.decode("utf-8-sig")
    functions = [item for item in logic.get("functions", []) if isinstance(item, Mapping)]
    if case_dir.name == "7cea19fbf28115dc8b8cd947d92d7cedcad6b18825f3d52e2340ae558445fce6":
        required_apis = {"createfilea", "writefile", "createprocessa"}
        matching = [
            item
            for item in functions
            if required_apis <= {str(value).casefold() for value in item.get("api_calls", [])}
        ]
        layers = load_json_object_strict(case_dir / "static-layers.json").get("layers", [])
        recovered_pe = [
            item
            for item in layers
            if isinstance(item, Mapping)
            and item.get("format") == "pe"
            and item.get("parent_sha256") is not None
            and isinstance(item.get("sha256"), str)
        ]
        recovered_child_sha256 = "482faaf1130d041a77b4a4e8a3e516d9c97aa21a3ad10b6a8b88bae38b6eaae5"
        recovered_child = next(
            (item for item in recovered_pe if item.get("sha256") == recovered_child_sha256),
            None,
        )
        if (
            not matching
            or recovered_child is None
            or recovered_child.get("size") != 344_064
            or recovered_child.get("transform") != "embedded-pe"
        ):
            raise ValueError("7cea検体の書出し・起動証拠を再検証できません")
        analysis["ghidra_behavior_evidence"] = {
            "status": "confirmed_static_decompilation",
            "execution_chain": ["CreateFileA", "WriteFile", "CreateProcessA"],
            "function_ids": sorted(str(item["function_id"]) for item in matching),
            "path_construction": {
                "format": "%s\\%s",
                "directory": r"C:\Users\Public",
                "filename": "agentttttttt_extracted.exe",
                "application_path": (r"C:\Users\Public\agentttttttt_extracted.exe"),
                "status": "confirmed_ghidra_data_references",
            },
            "file_write": {
                "api": "CreateFileA -> WriteFile",
                "desired_access": "GENERIC_WRITE",
                "creation_disposition": "CREATE_ALWAYS",
                "size_hex": "0x20e260b",
                "size_bytes": 34_481_675,
                "payload_prefix": "MZ",
            },
            "recovered_pe_sha256": [recovered_child_sha256],
            "recovered_pe_relationship": {
                "sha256": recovered_child_sha256,
                "size_bytes": 344_064,
                "transform": "embedded-pe",
                "write_buffer_byte_identity": "not_established",
            },
            "process_creation": {
                "api": "CreateProcessA",
                "lp_application_name": (r"C:\Users\Public\agentttttttt_extracted.exe"),
                "lp_command_line": None,
                "command_line_recovery_status": "confirmed_null",
                "creation_flags_hex": "0x08000000",
                "creation_flags": ["CREATE_NO_WINDOW"],
            },
            "handle_cleanup": ["process_handle", "thread_handle"],
            "sample_executed": False,
        }
        readme = _replace_markdown_section(
            readme,
            "Ghidra静的挙動証拠",
            [
                "- 埋め込みPE書出し: `CreateFileA(GENERIC_WRITE, CREATE_ALWAYS)`で`C:\\Users\\Public\\agentttttttt_extracted.exe`を作り、`WriteFile`で静的に同定したbufferから`0x20e260b`（34,481,675 bytes、先頭`MZ`）を書き込みます。`static-layers.json`で相関する`embedded-pe` childはSHA-256 `482faaf1130d041a77b4a4e8a3e516d9c97aa21a3ad10b6a8b88bae38b6eaae5`（344,064 bytes）です。WriteFile対象バッファ全体とのbyte-for-byte同一性は未確定です。",
                "- プロセス起動API: `CreateProcessA`の`lpApplicationName`は同じ`C:\\Users\\Public\\agentttttttt_extracted.exe`、`lpCommandLine`は`NULL`、`dwCreationFlags`は`0x08000000 (CREATE_NO_WINDOW)`です。起動後にprocess／thread handleを閉じます。",
                "- path復元根拠: `%s\\%s`へdirectory `C:\\Users\\Public`とfilename `agentttttttt_extracted.exe`を渡す構築処理をGhidraのdata referenceから確認しました。",
                "- 安全性: 上記はGhidra MCPによる静的解析結果であり、検体またはchild payloadは実行していません。",
            ],
        )

    report = load_json_object_strict(case_dir / "report.json")
    selected = report.get("classification", {}).get("selected_families")
    if selected == ["screenconnect_rmm"]:
        program_required_calls = {
            "system.diagnostics.process.start",
            "system.diagnostics.processstartinfo.set_filename",
            "system.diagnostics.processstartinfo.set_arguments",
            "system.diagnostics.processstartinfo.set_redirectstandardinput",
            "system.diagnostics.processstartinfo.set_redirectstandardoutput",
            "system.diagnostics.processstartinfo.set_redirectstandarderror",
            "system.diagnostics.processstartinfo.set_standardoutputencoding",
            "system.diagnostics.processstartinfo.set_standarderrorencoding",
            "system.diagnostics.process.get_exitcode",
            "killprocesstree",
        }
        program_matching = [
            item
            for item in functions
            if str(item.get("name") or "").endswith(".RunCommandLineProgram")
            and program_required_calls <= {str(value).casefold() for value in item.get("api_calls", [])}
        ]
        wrapper_required_calls = {
            "getlowintegritytemppath",
            "runcommandlineprogram",
            "screenconnect.extensions.containsanyignorecase",
            "screenconnect.extensions.getuniquetemppath",
            "screenconnect.extensions.quotewindowscommandline",
            "system.io.file.create",
            "system.io.file.delete",
            "system.io.textwriter.write",
        }
        wrapper_matching = [
            item
            for item in functions
            if str(item.get("name") or "").endswith(".RunCommandLineCommands")
            and wrapper_required_calls <= {str(value).casefold() for value in item.get("api_calls", [])}
        ]
        if len(program_matching) != 1 or len(wrapper_matching) != 1:
            raise ValueError(f"ScreenConnect command wrapper／process起動証拠が一意ではありません: {case_dir.name}")
        function = program_matching[0]
        wrapper = wrapper_matching[0]
        analysis.setdefault("case", {})["remote_command_execution_capability"] = {
            "status": "confirmed_static_managed_code",
            "program_function_id": function["function_id"],
            "wrapper_function_id": wrapper["function_id"],
            "operator_command_body_source": "runtime_management_input",
            "operator_filename_source": "runtime_argument",
            "operator_arguments_source": "runtime_argument",
            "temporary_script": {
                "directory": "low_integrity_temp",
                "name_generation": "unique",
                "cmd_extension": "run.cmd",
                "powershell_extension": "run.ps1",
                "deleted_after_execution": True,
            },
            "selector": {
                "powershell_branch_tokens": ["powershell", "ps"],
                "matching": "ContainsAnyIgnoreCase",
                "default_branch": "cmd",
            },
            "launcher_templates": {
                "cmd": {
                    "file_name": "cmd.exe",
                    "arguments_prefix": "/c ",
                    "arguments_tail": "QuoteWindowsCommandLine(unique run.cmd path)",
                },
                "powershell": {
                    "file_name": r"WindowsPowershell\v1.0\powershell.exe",
                    "arguments_prefix": ("-NoProfile -NonInteractive -ExecutionPolicy Unrestricted -File "),
                    "arguments_tail": "QuoteWindowsCommandLine(unique run.ps1 path)",
                },
            },
            "process_api": "System.Diagnostics.Process.Start",
            "stdio": {
                "stdin_optional": True,
                "stdout_redirected": True,
                "stderr_redirected": True,
                "stdout_encoding": "UTF-8",
                "stderr_encoding": "UTF-8",
                "output_collection": "asynchronous",
            },
            "timeout_behavior": "kill_process_tree",
            "expected_exit_code_validation": "optional",
            "fixed_operator_command_recovered": False,
            "dual_use_context": "screenconnect_remote_management_client",
            "separate_malware_c2_verified": False,
            "malicious_use_confirmed": False,
            "sample_executed": False,
        }
        readme = _replace_markdown_section(
            readme,
            "双用途管理・コマンド実行能力",
            [
                "- 遠隔コマンド実行能力: `RunCommandLineProgram`は実行時入力の`FileName`／`Arguments`を`ProcessStartInfo`へ設定し、`Process.Start`で起動します。stdinは任意、stdout／stderrはUTF-8でredirectして非同期回収し、timeout時はprocess treeを終了し、任意の期待exit codeも検証できます。",
                "- launcher command-line template: `RunCommandLineCommands`はoperator command textをlow-integrity tempのunique `run.cmd`／`run.ps1`へ書きます。cmd branchは`FileName=cmd.exe`, `Arguments=/c <QuoteWindowsCommandLine(run.cmd)>`です。PowerShell branchは`FileName=WindowsPowershell\\v1.0\\powershell.exe`, `Arguments=-NoProfile -NonInteractive -ExecutionPolicy Unrestricted -File <QuoteWindowsCommandLine(run.ps1)>`です。",
                "- branchと後処理: selectorに`powershell`または`ps`を含む場合だけPowerShell branchを選び、それ以外はcmd branchです。実行後は一時scriptを削除します。",
                "- 固定operator command: launcherの正確なtemplateは上記のとおり復元しましたが、command body自体は実行時に管理側から与えられるため、この検体の静的解析では復元していません。",
                "- 通信の意味: 双用途ScreenConnect管理clientと埋め込み管理endpointは確認済みです。`no_c2_capability_verified`は、これとは別個のmalware C2を静的に確認していない、という限定的な意味です。遠隔コマンド能力や悪性利用の有無を否定するものではありません。",
                "- 帰属上の制約: 配布経路、導入権限、侵害telemetryがないため、悪性利用そのものは未確認です。",
            ],
        )
    _atomic_replace_bytes(
        analysis_snapshot.path,
        _json_bytes(analysis),
        expected_snapshot=analysis_snapshot,
    )
    _atomic_replace_bytes(
        readme_snapshot.path,
        readme.encode("utf-8"),
        expected_snapshot=readme_snapshot,
    )


def _reseal_shadow_case(case_dir: Path) -> tuple[dict[str, Any], _JsonFileSnapshot]:
    """shadow内の全公開fileをmanifestへ結合し、reportを再封印する。"""

    report_snapshot = _bounded_json_snapshot(case_dir / "report.json")
    report = report_snapshot.document
    files = _snapshot_publication_case(
        case_dir,
        report,
        verify_manifest=False,
    )
    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, Mapping) or not manifest:
        raise ValueError(f"成果物hash manifestがありません: {case_dir.name}")
    report["artifact_sha256"] = {
        relative: files[normalize_artifact_path(relative)].sha256 for relative in sorted(manifest)
    }
    report["case_wide_artifact_sha256"] = {
        relative: snapshot.sha256 for relative, snapshot in sorted(files.items()) if relative != "report.json"
    }
    seal_report(report)
    _atomic_replace_bytes(
        report_snapshot.path,
        _json_bytes(report),
        expected_snapshot=report_snapshot,
    )
    verified = _load_verified_case_report(case_dir)
    _verify_case_wide_artifact_hashes(case_dir, verified[0])
    return verified


def _validate_completed_screenconnect_projection(
    case_dir: Path,
    report: Mapping[str, Any],
) -> None:
    """完了ScreenConnectのcase/C2/orchestration/features表示を相互検証する。"""

    selected = report.get("classification", {}).get("selected_families")
    if selected != ["screenconnect_rmm"]:
        return
    state = report.get("case_state")
    if not isinstance(state, Mapping) or state.get("status") != "complete":
        return
    orchestration = load_json_object_strict(case_dir / "orchestration.json")
    c2 = load_json_object_strict(case_dir / "c2-analysis.json")
    communication = load_json_object_strict(case_dir / "communication-patterns.json")
    features = load_json_object_strict(case_dir / "features.json")
    analysis = load_json_object_strict(case_dir / "analysis.json")
    logic = load_json_object_strict(case_dir / "static-logic.json")
    capability = analysis.get("case", {}).get("remote_command_execution_capability")
    behavior_ids = {item.get("id") for item in features.get("behaviors", []) if isinstance(item, Mapping)}
    command_roles = {
        str(item.get("role") or "")
        for item in logic.get("functions", [])
        if isinstance(item, Mapping)
        and str(item.get("name") or "").endswith((".RunCommandLineProgram", ".RunCommandLineCommands"))
    }
    terminal = orchestration.get("outputs", {}).get("terminal_payload")
    candidate_terminal = orchestration.get("candidate_outputs", {}).get("terminal_payload")
    expected_terminal = {
        "status": "recovered",
        "root_sha256": case_dir.name,
        "role": "terminal_managed_client",
        "basis": "validated_static_root_screenconnect_client",
        "claimed_sha256": [],
        "candidates": [],
        "retained": [],
        "verified": [],
    }
    if (
        orchestration.get("status") != "complete"
        or terminal != expected_terminal
        or candidate_terminal != expected_terminal
        or c2.get("c2", {}).get("outcome") != "no_c2_capability_verified"
        or c2.get("terminal_payload", {}).get("status") != "recovered"
        or c2.get("terminal_payload", {}).get("reached") is not True
        or communication.get("config", {}).get("terminal_managed_client") is not True
        or features.get("analysis_assessment", {}).get("status") != "complete"
        or "declared_case_state_incomplete" in features.get("analysis_assessment", {}).get("unresolved", [])
        or not isinstance(capability, Mapping)
        or capability.get("status") != "confirmed_static_managed_code"
        or capability.get("fixed_operator_command_recovered") is not False
        or capability.get("launcher_templates", {}).get("cmd", {}).get("file_name") != "cmd.exe"
        or capability.get("launcher_templates", {}).get("powershell", {}).get("file_name")
        != r"WindowsPowershell\v1.0\powershell.exe"
        or capability.get("separate_malware_c2_verified") is not False
        or capability.get("malicious_use_confirmed") is not False
        or not {
            "execution:remote_command",
            "execution:command_script_launcher",
            "execution:runtime_operator_command_body",
            "context:screenconnect_separate_c2_boundary",
        }
        <= behavior_ids
        or command_roles != {"command_dispatch_or_handler"}
    ):
        raise ValueError(f"完了ScreenConnectの公開成果物が不整合です: {case_dir.name}")


class _GhidraCasePublicationLock:
    """同一caseのrecovery・shadow・WAL commitをprocess間で直列化する。"""

    def __init__(self, case_dir: Path) -> None:
        identity = hashlib.sha256(os.path.normcase(os.path.abspath(case_dir)).encode("utf-8")).hexdigest()
        self.path = Path(tempfile.gettempdir()) / "ai-security-analysis-ghidra-case-locks" / f"{identity}.lock"
        self.descriptor: int | None = None

    def __enter__(self) -> _GhidraCasePublicationLock:
        ensure_no_reparse_components(self.path.parent)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(self.path.parent)
        descriptor = os.open(
            self.path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt  # noqa: PLC0415

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl  # noqa: PLC0415

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            os.close(descriptor)
            raise ValueError("同一caseのGhidra公開が既に実行中です") from exc
        self.descriptor = descriptor
        return self

    def __exit__(self, *_args: object) -> None:
        if self.descriptor is None:
            return
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt  # noqa: PLC0415

                msvcrt.locking(self.descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl  # noqa: PLC0415

                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self.descriptor)
            self.descriptor = None


def _publish_shadow_case_transaction_locked(
    case_dir: Path,
    base_report: Mapping[str, Any],
    base_report_snapshot: _JsonFileSnapshot,
    planned_updates: Mapping[str, bytes],
    *,
    repository: Path,
    transaction_root: Path | None,
) -> tuple[str, dict[str, Any]]:
    """shadowで全成果物を完成後、case-wide durable WALで一括反映する。"""

    if dict(base_report) != base_report_snapshot.document:
        raise ValueError(f"case-wide shadow生成前のreport snapshotが一致しません: {case_dir.name}")
    _recover_finalize_transaction(case_dir, transaction_root=transaction_root)
    original_files = _snapshot_publication_case(case_dir, base_report)
    original_report = original_files["report.json"]
    if (
        original_report.path != base_report_snapshot.path
        or original_report.data != base_report_snapshot.data
        or original_report.sha256 != base_report_snapshot.sha256
        or original_report.size != base_report_snapshot.binding.size
        or not _same_regular_file_binding(
            original_report.metadata,
            base_report_snapshot.binding.metadata,
        )
    ):
        raise ValueError(f"case-wide shadow生成前にreportが変更されました: {case_dir.name}")
    missing = CASE_WIDE_PUBLICATION_REQUIRED - set(original_files)
    if missing:
        raise ValueError(f"case-wide transaction必須成果物がありません: {case_dir.name}: {sorted(missing)}")
    unknown_updates = set(planned_updates) - set(original_files)
    if unknown_updates:
        raise ValueError(f"未認証の新規公開成果物があります: {sorted(unknown_updates)}")
    shadow = _prepare_publication_shadow(
        case_dir,
        original_files,
        transaction_root=transaction_root,
    )
    shadow_transaction_root = _publication_shadow_transaction_root(
        shadow,
        transaction_root,
    )
    try:
        for relative, data in planned_updates.items():
            snapshot = _bounded_content_snapshot(shadow / Path(relative))
            _atomic_replace_bytes(snapshot.path, data, expected_snapshot=snapshot)
        _reseal_shadow_case(shadow)
        finalized_state = finalize_case_report(
            shadow,
            transaction_root=shadow_transaction_root,
        )
        _enrich_shadow_behavior_documents(shadow)
        profile = build_case_profile(shadow)
        feature_snapshot = _bounded_content_snapshot(shadow / "features.json")
        _atomic_replace_bytes(
            feature_snapshot.path,
            _json_bytes(profile),
            expected_snapshot=feature_snapshot,
        )
        feature_markdown_snapshot = _bounded_content_snapshot(shadow / "FEATURES.md")
        _atomic_replace_bytes(
            feature_markdown_snapshot.path,
            render_features_markdown(profile).encode("utf-8"),
            expected_snapshot=feature_markdown_snapshot,
        )
        finalized_report, _ = _reseal_shadow_case(shadow)
        resumable = finalized_state == "complete"
        errors = case_integrity_errors(
            shadow,
            finalized_report,
            expected_digest=case_dir.name,
            require_resumable=resumable,
        )
        if errors:
            raise ValueError(f"shadow case整合性検証に失敗しました: {case_dir.name}: {errors}")
        _validate_completed_screenconnect_projection(shadow, finalized_report)
        c2 = load_json_object_strict(shadow / "c2-analysis.json")
        c2_validation = validate_c2_contract(
            c2,
            case_dir.name,
            repository=repository,
        )
        final_files = _snapshot_publication_case(shadow, finalized_report)
        if set(final_files) != set(original_files):
            raise ValueError("shadowの公開file集合が旧caseと一致しません")
        _assert_publication_case_unchanged(case_dir, original_files)
        versions = [(original_files[relative], final_files[relative].data) for relative in sorted(original_files)]
        transaction_dir = _begin_finalize_transaction(
            case_dir,
            versions,
            transaction_root=transaction_root,
            case_wide=True,
        )
        try:
            _set_finalize_transaction_phase(
                transaction_dir,
                phase="applying",
                applied_count=0,
            )
            for index, (snapshot, data) in enumerate(versions, start=1):
                _atomic_replace_bytes(
                    snapshot.path,
                    data,
                    expected_snapshot=snapshot,
                    temporary_name=f".ghidra-finalize-{index - 1:04d}.tmp",
                )
                _set_finalize_transaction_phase(
                    transaction_dir,
                    phase="applying",
                    applied_count=index,
                )
            _set_finalize_transaction_phase(
                transaction_dir,
                phase="applied",
                applied_count=len(versions),
            )
            committed_journal, _committed_entries = _load_finalize_transaction(
                case_dir,
                transaction_dir,
            )
            _assert_case_wide_transaction_layout(case_dir, committed_journal)
            committed_report = load_json_object_strict(case_dir / "report.json")
            committed_errors = case_integrity_errors(
                case_dir,
                committed_report,
                expected_digest=case_dir.name,
                require_resumable=resumable,
            )
            if committed_errors:
                raise ValueError(f"case-wide反映後の整合性検証に失敗しました: {case_dir.name}: {committed_errors}")
            _verify_case_wide_artifact_hashes(case_dir, committed_report)
            _validate_completed_screenconnect_projection(case_dir, committed_report)
            _set_finalize_transaction_phase(
                transaction_dir,
                phase="verified",
                applied_count=len(versions),
            )
            _safe_remove_finalize_transaction(transaction_dir)
        except BaseException:
            _recover_finalize_transaction(
                case_dir,
                transaction_root=transaction_root,
            )
            raise
        return finalized_state, c2_validation
    finally:
        if os.path.lexists(shadow):
            _safe_remove_publication_shadow(shadow)


def _publish_shadow_case_transaction(
    case_dir: Path,
    base_report: Mapping[str, Any],
    base_report_snapshot: _JsonFileSnapshot,
    planned_updates: Mapping[str, bytes],
    *,
    repository: Path,
    transaction_root: Path | None,
) -> tuple[str, dict[str, Any]]:
    """同一case lock内でrecoveryからshadow commitまでを完了する。"""

    with _GhidraCasePublicationLock(case_dir):
        return _publish_shadow_case_transaction_locked(
            case_dir,
            base_report,
            base_report_snapshot,
            planned_updates,
            repository=repository,
            transaction_root=transaction_root,
        )


def publish_cases(
    repository: Path,
    collection_dir: Path,
    program_results: Mapping[str, Mapping[str, Any]],
    non_pe: Mapping[str, list[dict[str, Any]]],
    *,
    transaction_root: Path | None = None,
) -> dict[str, Any]:
    """対象caseの代表関数解析と全体ロジック成果物を更新する。"""

    case_paths = _case_index(repository)
    collection = json.loads((collection_dir / "manifest.json").read_text(encoding="utf-8-sig"))
    requested = [str(item["case_id"]).removeprefix("sha256:").casefold() for item in collection.get("cases", [])]
    status_counts: Counter[str] = Counter()
    totals: Counter[str] = Counter()
    per_case: dict[str, dict[str, Any]] = {}
    mutable_results = {digest: dict(result) for digest, result in program_results.items()}
    for result in mutable_results.values():
        ensure_characteristic_selection(result)

    for case_sha in requested:
        related = [
            result
            for result in mutable_results.values()
            if any(str(item["case_sha256"]) == case_sha for item in result.get("relationships", []))
        ]
        non_pe_relations = non_pe.get(case_sha, [])
        script_records = _selected_script_records(non_pe, case_sha)
        _require_case_static_evidence(case_sha, related, script_records, non_pe_relations)
        invalid_mcp = [
            str(result.get("sha256") or "unknown")
            for result in related
            if result.get("mcp_responses_valid") is not True
        ]
        if invalid_mcp:
            raise ValueError(f"MCP成功証跡のないprogramを公開できません: {case_sha}: {invalid_mcp}")
        incomplete_function_inventory = [
            str(result.get("sha256") or "unknown")
            for result in related
            if not _function_inventory_coverage_complete(result)
        ]
        if incomplete_function_inventory:
            raise ValueError(
                "全関数inventoryの終端取得・metadata件数拘束がないprogramを"
                f"公開できません: {case_sha}: {incomplete_function_inventory}"
            )

        records: list[dict[str, Any]] = []
        for result in related:
            for function in result.get("functions", []):
                if not isinstance(function, Mapping):
                    continue
                if function.get("selected_for_characteristic_analysis") is not True:
                    continue
                record = dict(function)
                if record.get("analysis_kind") == "managed_cil":
                    record["program_selector"] = str(result["program_selector"])
                records.append(record)
        records.extend(script_records)
        discovered_count = sum(
            int(result.get("function_inventory_count") or len(result.get("functions", []))) for result in related
        ) + len(script_records)
        if not records and discovered_count:
            raise ValueError(f"発見済み関数から代表関数を選定できないcaseです: {case_sha}")
        structure_only = not records
        case_dir = case_paths[case_sha]
        _recover_finalize_transaction(
            case_dir,
            transaction_root=transaction_root,
        )
        preverified_case_report, preverified_report_snapshot = _load_verified_case_report(case_dir)
        metadata = json.loads((case_dir / "metadata.json").read_text(encoding="utf-8-sig"))
        report = build_static_logic_report(
            sha256=case_sha,
            family=str(metadata.get("family") or "unknown"),
            source_name=f"{case_sha}.quarantine.bin",
            records=records,
            program_evidence=[_program_evidence(result) for result in related],
            analysis_source="ghidra_mcp_characteristic_functions_and_managed_cil",
        )
        _enrich_normalized_functions(report, records)
        _merge_acquired_call_graph(report, related)
        statuses = [function["function_analysis"]["decompilation_status"] for function in report["functions"]]
        succeeded = sum(value == "succeeded" for value in statuses)
        excluded = sum(
            value
            in {
                "no_managed_body",
                "excluded_external_or_thunk",
                "static_script_structure_recorded",
            }
            for value in statuses
        )
        limited = len(statuses) - succeeded - excluded
        attempted = len(statuses) - excluded
        selected_count = len(statuses)
        unselected_count = max(0, discovered_count - selected_count)
        report["coverage"].update(
            {
                "function_inventory_count": selected_count,
                "discovered_function_inventory_count": discovered_count,
                "characteristic_function_selected_count": selected_count,
                "characteristic_function_analyzed_count": selected_count,
                "characteristic_function_attempted_count": attempted,
                "decompilation_attempted_count": attempted,
                "decompilation_succeeded_count": succeeded,
                "decompilation_limited_or_failed_count": limited,
                "decompilation_excluded_count": excluded,
                "unselected_function_count": unselected_count,
                "all_discovered_functions_inventoried": True,
                "all_characteristic_functions_attempted": True,
                "all_characteristic_functions_explained": True,
                "non_pe_recovered_layers_recorded": len(non_pe.get(case_sha, [])),
                "raw_private_artifacts_retained": True,
                "ghidra_function_inventory_count": sum(
                    int(result.get("ghidra_function_inventory_count") or 0) for result in related
                ),
                "managed_method_inventory_count": sum(
                    int(result.get("managed_method_count") or 0) for result in related
                ),
                "ghidra_programs_with_valid_mcp_responses": len(related),
                "call_graph_acquired_edge_count": int(
                    report["coverage"].get(
                        "acquired_call_graph_edge_count",
                        0,
                    )
                ),
                "call_graph_acquisition_status": report["coverage"].get(
                    "call_graph_acquisition_status",
                    "not_applicable_no_ghidra_program",
                ),
                "structured_constant_value_count": sum(
                    len(item.get("constants") or []) for item in records if isinstance(item, Mapping)
                ),
                "structured_constant_extraction_status": (
                    "recorded"
                    if any(isinstance(item, Mapping) and item.get("constants") for item in records)
                    else "not_exposed_by_current_mcp_or_cil_record"
                ),
            }
        )
        report["selection_policy"] = {
            "name": "role_entrypoint_callgraph_size_representatives",
            "maximum_per_program_and_analysis_kind": MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM,
            "dimensions": [
                "entry point",
                "malware固有の役割",
                "call graph中心性",
                "関数規模",
                "symbol名の情報量",
            ],
            "all_functions_decompilation_required": False,
            "unselected_scope_recorded": True,
        }
        report["retention"] = {
            "all_discovered_functions_in_public_result": False,
            "all_selected_functions_in_public_result": True,
            "all_selected_normalized_logic_in_public_result": True,
            "all_selected_call_relationships_in_public_result": True,
            "full_function_inventory_retained_private": True,
            "full_raw_ghidra_index_retained_private": True,
            "all_acquired_raw_decompilations_retained_private": True,
            "all_acquired_managed_cil_retained_private": True,
            "static_analysis_content_discarded": False,
            "public_sanitization_only": [
                "具体的なIOC",
                "資格情報",
                "token",
                "復号秘密値",
                "生の逆コンパイル本文",
            ],
        }
        report["coverage"]["all_static_analysis_content_retained"] = True
        report["status"] = (
            "characteristic_function_static_analysis_complete"
            if limited == 0 and not structure_only
            else "characteristic_function_static_analysis_complete_with_documented_limits"
        )
        report["limitations"] = [
            "全関数／methodのinventoryは保持し、入口・挙動役割・call graph中心性・規模から代表関数を選定しました。",
            "選定した代表関数はすべて逆コンパイル、CIL解析、または静的script構造解析を試行しました。",
            "選定外関数は個別解説の対象外であり、件数と選定方針を明示しています。",
            "packer、VM、破損CIL、indirect flowで不完全な代表関数は失敗理由と次の解析を関数recordへ残しました。",
            "fingerprint一致だけではファミリー、actor、campaignを確定しません。",
            (
                "constantsは現行Ghidra MCP／CIL recordの独立フィールドとして取得できていません。"
                "正規化ロジック中の定数は伏字化されるため、固定引数やpathを復元済みとは扱いません。"
                if report["coverage"]["structured_constant_value_count"] == 0
                else "構造化constantsは取得できた値だけを記録し、伏字化された定数の完全回収を主張しません。"
            ),
        ]
        if structure_only:
            report["limitations"].insert(
                0,
                (
                    "非PE layerのhash・親子関係・形式は記録しましたが、旧checkpointに静的script関数recordがないため構造限定解析としました。"
                    if not related and non_pe_relations
                    else "Ghidra MCPでprogram構造は取得しましたが、解析可能な関数本体を認識できなかったため構造限定解析としました。"
                ),
            )
        report["safety"].update(
            {
                "raw_pseudocode_retained_outside_repository": True,
                "arbitrary_ghidra_scripts_enabled": False,
            }
        )
        report["overall_logic"] = _build_overall_logic(report)
        report = _escape_public_replacement_characters(report)

        analysis_path = case_dir / "analysis.json"
        analysis = _bounded_json_snapshot(analysis_path).document
        analysis["case"]["declarative_status"] = report["status"]
        analysis["case"]["function_analysis"] = {
            key: report["coverage"][key]
            for key in (
                "discovered_function_inventory_count",
                "characteristic_function_selected_count",
                "characteristic_function_analyzed_count",
                "decompilation_attempted_count",
                "decompilation_succeeded_count",
                "decompilation_limited_or_failed_count",
                "ghidra_program_count",
                "ghidra_function_inventory_count",
                "managed_method_inventory_count",
                "ghidra_programs_with_valid_mcp_responses",
                "unselected_function_count",
            )
        }
        analysis["limitations"] = [
            value
            for value in analysis.get("limitations", [])
            if value
            not in {
                "関数本体未レビューのbinaryは完了扱いにしていない。",
                "関数単位の静的解析は完了し、復元不能箇所は理由と次の解析を記録した。",
            }
        ]
        analysis["limitations"].append("代表関数の静的解析と全体ロジック整理を完了し、選定外範囲と制約を記録した。")

        readme_path = case_dir / "README.md"
        readme = _bounded_content_snapshot(readme_path).data.decode("utf-8-sig")
        readme = re.sub(
            r"(?m)^- 静的ロジック状態: `[^`]+`$",
            f"- 静的ロジック状態: `{report['status']}`",
            readme,
        )
        detail_line = (
            "特徴的な代表関数の選定理由・処理内容は[STATIC-LOGIC.md](STATIC-LOGIC.md)、"
            "検体全体の処理段階とcall関係は[OVERALL-LOGIC.md](OVERALL-LOGIC.md)を参照してください。"
        )
        readme = re.sub(
            r"(?m)^.*\[STATIC-LOGIC\.md\]\(STATIC-LOGIC\.md\)を参照してください。$",
            detail_line,
            readme,
        )
        if "[OVERALL-LOGIC.md](OVERALL-LOGIC.md)" not in readme:
            readme = readme.rstrip() + "\n\n" + detail_line + "\n"
        planned_updates = {
            "static-logic.json": _json_bytes(report),
            "STATIC-LOGIC.md": _render_markdown(report).encode("utf-8"),
            "OVERALL-LOGIC.md": _render_overall_logic(
                report,
                load_static_layers(case_dir),
            ).encode("utf-8"),
            "analysis.json": _json_bytes(analysis),
            "README.md": readme.encode("utf-8"),
        }
        _assert_snapshot_unchanged(
            preverified_report_snapshot,
            context="case-wide shadow生成直前",
        )
        finalized_case_state, finalized_c2_validation = _publish_shadow_case_transaction(
            case_dir,
            preverified_case_report,
            preverified_report_snapshot,
            planned_updates,
            repository=repository,
            transaction_root=transaction_root,
        )
        finalized_case_report = load_json_object_strict(case_dir / "report.json")
        finalized_case_errors = case_integrity_errors(
            case_dir,
            finalized_case_report,
            expected_digest=case_sha,
            require_resumable=finalized_case_state == "complete",
        )
        if finalized_case_errors:
            raise ValueError(f"case-wide公開後の再検証に失敗しました: {case_sha}: {finalized_case_errors}")

        status_counts[report["status"]] += 1
        totals["discovered_functions"] += discovered_count
        totals["characteristic_functions"] += selected_count
        totals["attempted"] += attempted
        totals["succeeded"] += succeeded
        totals["limited"] += limited
        totals["excluded"] += excluded
        totals["unselected"] += unselected_count
        totals["programs"] += len(related)
        totals["ghidra_functions"] += report["coverage"]["ghidra_function_inventory_count"]
        totals["managed_methods"] += report["coverage"]["managed_method_inventory_count"]
        totals["valid_mcp_programs"] += report["coverage"]["ghidra_programs_with_valid_mcp_responses"]
        per_case[case_sha] = {
            "status": report["status"],
            "coverage": report["coverage"],
            "case_state": finalized_case_state,
            "c2_analysis_outcome": str(finalized_c2_validation.get("outcome") or "unresolved"),
            "c2_analysis_complete": bool(finalized_c2_validation.get("complete")),
            "c2_analysis_finding_count": int(finalized_c2_validation.get("finding_count") or 0),
        }

    summary_path = collection_dir / "publication-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
    summary["static_logic_status"] = dict(sorted(status_counts.items()))
    summary["function_analysis"] = {
        "root_cases": len(requested),
        "unique_pe_programs": len(program_results),
        "discovered_function_inventory_count": totals["discovered_functions"],
        "characteristic_function_selected_count": totals["characteristic_functions"],
        "characteristic_function_attempted_count": totals["attempted"],
        "decompilation_succeeded_count": totals["succeeded"],
        "decompilation_limited_or_failed_count": totals["limited"],
        "decompilation_excluded_count": totals["excluded"],
        "unselected_function_count": totals["unselected"],
        "all_characteristic_functions_attempted": True,
        "raw_private_artifacts_retained": True,
        "all_static_analysis_content_retained": True,
        "ghidra_function_inventory_count": totals["ghidra_functions"],
        "managed_method_inventory_count": totals["managed_methods"],
        "ghidra_programs_with_valid_mcp_responses": totals["valid_mcp_programs"],
    }
    for item in summary.get("cases", []):
        sha = str(item.get("sha256") or "").casefold()
        if sha in per_case:
            item["static_logic_status"] = per_case[sha]["status"]
            item["function_analysis"] = per_case[sha]["coverage"]
            item["case_state"] = per_case[sha]["case_state"]
            item["publication_stage"] = (
                "complete" if per_case[sha]["case_state"] == "complete" else "partial_followup_required"
            )
            for key in (
                "c2_analysis_outcome",
                "c2_analysis_complete",
                "c2_analysis_finding_count",
            ):
                item[key] = per_case[sha][key]
    _json_dump(summary_path, summary)

    readme_path = collection_dir / "README.md"
    readme = readme_path.read_text(encoding="utf-8-sig")
    replacement = [
        "## 静的ロジック状態",
        "",
        f"- 代表関数解析完了case: `{len(requested)}`",
        f"- Ghidra／CILプログラム: `{len(program_results)}`件の固有PE",
        f"- 発見関数／メソッドinventory: `{totals['discovered_functions']}`",
        f"- 代表関数: `{totals['characteristic_functions']}`",
        f"- 選定外関数: `{totals['unselected']}`",
        f"- Ghidra関数: `{totals['ghidra_functions']}`",
        f"- managedメソッド: `{totals['managed_methods']}`",
        f"- MCP成功証跡付きプログラム: `{totals['valid_mcp_programs']}`",
        f"- 逆コンパイル／CIL解析試行: `{totals['attempted']}`",
        f"- 成功: `{totals['succeeded']}`",
        f"- 制約付き／失敗: `{totals['limited']}`",
        "",
        "全関数inventoryを保持しつつ、特徴的な代表関数を選定して解析しました。",
        "各caseのSTATIC-LOGIC.mdに関数解説、OVERALL-LOGIC.mdに全体処理を記録しています。",
        "生の逆コンパイル本文とCIL命令列はリポジトリ外へ保持しています。",
        "",
    ]
    readme = re.sub(
        r"## 静的ロジック状態\n.*?(?=\n個別のPE構造)",
        "\n".join(replacement),
        readme,
        flags=re.DOTALL,
    )
    readme_path.write_text(readme, encoding="utf-8")
    return {
        "schema_version": SCHEMA_VERSION,
        "cases": len(requested),
        "status_counts": dict(status_counts),
        "totals": dict(totals),
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    """全入力を準備・解析・公開し、collection集計を返す。"""

    repository = _resolve_without_reparse(args.repository)
    collection_dir = _resolve_without_reparse(args.collection)
    sample_root = _resolve_without_reparse(args.sample_root)
    private_output = _resolve_without_reparse(args.private_output)
    raw_prepared_input_root = getattr(args, "prepared_input_root", None)
    prepared_input_root = (
        _resolve_without_reparse(raw_prepared_input_root) if raw_prepared_input_root is not None else sample_root
    )
    if (
        isinstance(args.minimum_free_bytes, bool)
        or not isinstance(args.minimum_free_bytes, int)
        or args.minimum_free_bytes < MINIMUM_CONFIGURABLE_FREE_BYTES
    ):
        raise ValueError("minimum_free_bytesが安全な下限を満たしていません")
    _validate_run_roots(
        repository,
        collection_dir,
        sample_root,
        private_output,
        prepared_input_root,
    )
    if os.environ.get("GHIDRA_MCP_ALLOW_SCRIPTS", "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        raise RuntimeError("任意Ghidra script実行が有効な環境では処理を開始しません")
    checkpoint = _load_resume_checkpoint(
        private_output,
        collection_id=collection_dir.name,
    )
    checkpoint_prepared = bool(checkpoint is not None and checkpoint.get("inventory_prepared") is True)
    checkpoint_inventory_sha256 = (
        str(checkpoint["prepared_inventory_sha256"]) if checkpoint_prepared and checkpoint is not None else None
    )
    postprocessing_only = bool(
        checkpoint_prepared and checkpoint is not None and checkpoint.get("postprocessing_pending") is True
    )
    effective_reuse = bool(args.reuse_prepared_inputs or checkpoint_prepared)
    resume_mode = "postprocessing_only" if postprocessing_only else "prepared_inputs" if effective_reuse else "fresh"
    storage_paths = _storage_guard_paths(
        args,
        repository,
        sample_root,
        private_output,
        prepared_input_root,
    )
    storage_observation = _storage_budget_observation(
        storage_paths,
        minimum_free_bytes=args.minimum_free_bytes,
        phase="before_input_preparation",
    )
    if storage_observation["sufficient"] is not True:
        progress = _run_progress_document(
            collection_id=collection_dir.name,
            status="ghidra_chunk_pending",
            stop_reason="minimum_free_space_not_met",
            retryable=True,
            inventory_prepared=checkpoint_prepared,
            prepared_inventory_sha256=checkpoint_inventory_sha256,
            unique_pe_programs=(
                int(checkpoint["unique_pe_programs"]) if checkpoint_prepared and checkpoint is not None else None
            ),
            complete_programs=(
                int(checkpoint["complete_programs"]) if checkpoint_prepared and checkpoint is not None else 0
            ),
            cached_programs=(
                int(checkpoint["cached_programs"]) if checkpoint_prepared and checkpoint is not None else 0
            ),
            newly_analyzed_programs=(
                int(checkpoint["newly_analyzed_programs"]) if checkpoint_prepared and checkpoint is not None else 0
            ),
            pending_programs=(
                list(checkpoint["pending_programs"]) if checkpoint_prepared and checkpoint is not None else []
            ),
            postprocessing_pending=postprocessing_only,
            prepared_inputs_reused=False,
            resume_mode=resume_mode,
            disk_space=storage_observation,
        )
        _write_run_progress(private_output, progress)
        return progress
    inventory_snapshot: _JsonFileSnapshot
    if effective_reuse:
        inventory_snapshot = _bounded_json_snapshot(private_output / "input-relationships.json")
        objects, non_pe = load_prepared_inputs(
            sample_root,
            private_output,
            inventory_snapshot=inventory_snapshot,
            expected_inventory_sha256=checkpoint_inventory_sha256,
            prepared_input_root=prepared_input_root,
        )
    else:

        def preparation_storage_guard(
            phase: str,
            role: str,
            planned_write_bytes: int,
        ) -> None:
            observation = _storage_budget_observation(
                storage_paths,
                minimum_free_bytes=args.minimum_free_bytes,
                phase=phase,
            )
            observation = _apply_planned_write_reserve(
                observation,
                role=role,
                planned_write_bytes=planned_write_bytes,
            )
            if observation["sufficient"] is True:
                return
            progress = _run_progress_document(
                collection_id=collection_dir.name,
                status="ghidra_chunk_pending",
                stop_reason="minimum_free_space_not_met",
                retryable=True,
                inventory_prepared=False,
                prepared_inventory_sha256=None,
                unique_pe_programs=None,
                complete_programs=0,
                cached_programs=0,
                newly_analyzed_programs=0,
                pending_programs=[],
                postprocessing_pending=False,
                prepared_inputs_reused=False,
                resume_mode="fresh",
                disk_space=observation,
            )
            _write_run_progress(private_output, progress)
            raise _InputPreparationStopped(progress)

        try:
            objects, non_pe = prepare_inputs(
                repository,
                collection_dir,
                sample_root,
                private_output,
                upx=args.upx,
                sevenzip=args.sevenzip,
                diec=args.diec,
                storage_guard=preparation_storage_guard,
                prepared_input_root=prepared_input_root,
            )
        except _InputPreparationStopped as exc:
            return exc.progress
        inventory_snapshot = _bounded_json_snapshot(private_output / "input-relationships.json")
    validate_prepared_scope(
        collection_dir,
        private_output,
        inventory_snapshot=inventory_snapshot,
    )
    _assert_snapshot_unchanged(
        inventory_snapshot,
        context="Ghidra batch開始前",
    )
    prepared_inventory_sha256 = inventory_snapshot.sha256
    client: GhidraMcpClient | None = None
    results: dict[str, dict[str, Any]] = {}
    ordered = sorted(objects.values(), key=lambda item: (item.size, item.sha256))
    if checkpoint_prepared and checkpoint is not None:
        pending_order = {digest: index for index, digest in enumerate(checkpoint["pending_programs"])}
        # 前回未試行のprogramをtimeout済みprogramより先へ回し、chunk上限による飢餓を防ぐ。
        ordered.sort(key=lambda item: (item.sha256 in pending_order, pending_order.get(item.sha256, 0)))
    max_new_programs = args.max_new_programs
    newly_analyzed = 0
    attempted_programs = 0
    cached_programs = 0
    pending_programs: list[str] = []
    timed_out_programs: list[str] = []
    storage_blocked = False
    storage_observation = _storage_budget_observation(
        storage_paths,
        minimum_free_bytes=args.minimum_free_bytes,
        phase="after_input_preparation",
    )
    if storage_observation["sufficient"] is not True:
        storage_blocked = True
    for index, item in enumerate(ordered, start=1):
        result_path = private_output / "objects" / item.sha256 / "program-result.json"
        cached_complete = False
        cached: dict[str, Any] | None = None
        cached_snapshot: _JsonFileSnapshot | None = None
        if result_path.is_file():
            cached, cached_snapshot = _load_program_result(result_path)
            cached_complete = bool(cached.get("status") == "complete" and cached.get("mcp_responses_valid") is True)
            native_zero_recovery_pending = _native_zero_function_recovery_pending(cached)
            if cached_complete and native_zero_recovery_pending and item.input_snapshot is None:
                cached = _terminalize_unavailable_native_zero_function_recovery(
                    result_path,
                    cached,
                )
                cached_complete = True
            elif native_zero_recovery_pending:
                cached_complete = False
        if postprocessing_only and not cached_complete:
            raise ValueError("postprocessing-only checkpointに未完了program cacheがあります")
        if cached_complete:
            if cached is None or cached_snapshot is None:  # pragma: no cover - 直前の代入契約の最終防御
                raise RuntimeError("完了cacheを読み込めませんでした")
            selection_before = _json_bytes(cached)
            ensure_characteristic_selection(cached)
            results[item.sha256] = cached
            selection_after = _json_bytes(cached)
            if not storage_blocked and selection_after != selection_before:
                _persist_program_result(result_path, cached)
            cached_programs += 1
            continue
        if storage_blocked:
            pending_programs.append(item.sha256)
            continue
        if max_new_programs is not None and attempted_programs >= max_new_programs:
            pending_programs.append(item.sha256)
            continue
        storage_observation = _storage_budget_observation(
            storage_paths,
            minimum_free_bytes=args.minimum_free_bytes,
            phase="before_program",
        )
        if storage_observation["sufficient"] is not True:
            storage_blocked = True
            pending_programs.append(item.sha256)
            continue
        print(
            json.dumps(
                {
                    "phase": "ghidra",
                    "program": index,
                    "total": len(ordered),
                    "sha256": item.sha256,
                    "size": item.size,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        if item.input_snapshot is not None:
            _assert_regular_snapshot_unchanged(
                item.input_snapshot,
                context="Ghidra import直前",
            )
        if client is None:
            client = GhidraMcpClient(args.mcp_url, timeout=args.request_timeout)
        attempted_programs += 1
        try:
            results[item.sha256] = analyze_program(
                client,
                item,
                private_output,
                args.project_root,
                analysis_timeout=args.analysis_timeout,
                skip_auto_analysis=item.sha256 in args.skip_auto_analysis_sha256,
            )
        except (TimeoutError, GhidraMcpError) as exc:
            if not _request_timed_out(exc):
                raise
            timed_out_programs.append(item.sha256)
            _append_jsonl(
                private_output / "program-timeouts.raw.jsonl",
                [{
                    "schema_version": 1,
                    "sha256": item.sha256,
                    "prepared_inventory_sha256": prepared_inventory_sha256,
                    "observed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "reason": (
                        "analysis_wait_timeout" if isinstance(exc, TimeoutError) else "mcp_transport_timeout"
                    ),
                    "analysis_timeout_seconds": args.analysis_timeout,
                    "request_timeout_seconds": args.request_timeout,
                    "retryable": True,
                    "sample_executed": False,
                    "network_contacted": False,
                }],
            )
            # 次programやOSの中断前にも、完了cacheと全pendingのbindingを永続化する。
            _write_run_progress(
                private_output,
                _run_progress_document(
                    collection_id=collection_dir.name,
                    status="ghidra_chunk_pending",
                    stop_reason="program_timeout",
                    retryable=True,
                    inventory_prepared=True,
                    prepared_inventory_sha256=prepared_inventory_sha256,
                    unique_pe_programs=len(ordered),
                    complete_programs=len(results),
                    cached_programs=cached_programs,
                    newly_analyzed_programs=newly_analyzed,
                    pending_programs=(
                        pending_programs + [future.sha256 for future in ordered[index:]] + timed_out_programs
                    ),
                    postprocessing_pending=False,
                    prepared_inputs_reused=effective_reuse,
                    resume_mode=resume_mode,
                    disk_space=storage_observation,
                ),
            )
            print(
                json.dumps({"phase": "ghidra", "state": "program_timeout", "sha256": item.sha256, "retryable": True}),
                flush=True,
            )
        else:
            newly_analyzed += 1
        storage_observation = _storage_budget_observation(
            storage_paths,
            minimum_free_bytes=args.minimum_free_bytes,
            phase="after_program",
        )
        if storage_observation["sufficient"] is not True:
            storage_blocked = True
    pending_programs.extend(timed_out_programs)
    if pending_programs:
        progress = _run_progress_document(
            collection_id=collection_dir.name,
            status="ghidra_chunk_pending",
            stop_reason=(
                "minimum_free_space_not_met" if storage_blocked
                else "program_timeout" if timed_out_programs
                else "max_new_programs_reached"
            ),
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=prepared_inventory_sha256,
            unique_pe_programs=len(ordered),
            complete_programs=len(results),
            cached_programs=cached_programs,
            newly_analyzed_programs=newly_analyzed,
            pending_programs=pending_programs,
            postprocessing_pending=False,
            prepared_inputs_reused=effective_reuse,
            resume_mode=resume_mode,
            disk_space=storage_observation,
        )
        _write_run_progress(private_output, progress)
        return progress
    storage_observation = _storage_budget_observation(
        storage_paths,
        minimum_free_bytes=args.minimum_free_bytes,
        phase="before_postprocessing",
    )
    if storage_observation["sufficient"] is not True:
        progress = _run_progress_document(
            collection_id=collection_dir.name,
            status="ghidra_chunk_pending",
            stop_reason="minimum_free_space_not_met",
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=prepared_inventory_sha256,
            unique_pe_programs=len(ordered),
            complete_programs=len(results),
            cached_programs=cached_programs,
            newly_analyzed_programs=newly_analyzed,
            pending_programs=[],
            postprocessing_pending=True,
            prepared_inputs_reused=effective_reuse,
            resume_mode="postprocessing_only",
            disk_space=storage_observation,
        )
        _write_run_progress(private_output, progress)
        return progress
    _write_run_progress(
        private_output,
        _run_progress_document(
            collection_id=collection_dir.name,
            status="ghidra_chunk_pending",
            stop_reason="postprocessing_in_progress",
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=prepared_inventory_sha256,
            unique_pe_programs=len(ordered),
            complete_programs=len(results),
            cached_programs=cached_programs,
            newly_analyzed_programs=newly_analyzed,
            pending_programs=[],
            postprocessing_pending=True,
            prepared_inputs_reused=effective_reuse,
            resume_mode="postprocessing_only",
            disk_space=storage_observation,
        ),
    )
    if client is None:
        client = GhidraMcpClient(args.mcp_url, timeout=args.request_timeout)
    complete_artifact_refresh = refresh_complete_program_artifacts(
        client,
        results,
        private_output,
    )
    call_graph_augmentation = augment_private_call_graphs(results, private_output)
    private_validation = validate_private_artifacts(
        results,
        private_output,
        expected_program_count=len(objects),
    )
    if not private_validation["complete"]:
        raise RuntimeError(f"生の静的解析成果物に欠落があります: {private_validation['invalid_programs']}")
    publication = publish_cases(
        repository,
        collection_dir,
        results,
        non_pe,
        transaction_root=private_output / "finalize-transactions",
    )
    validation = validate_collection(repository, collection_dir)
    if not validation["complete"]:
        raise RuntimeError(f"代表関数解析の完了条件を満たさないcaseがあります: {validation['invalid_cases']}")
    final_publication = finalize_collection_publication(repository, collection_dir)
    run_summary = {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_dir.name,
        "status": "complete",
        "unique_pe_programs": len(results),
        "publication": publication,
        "private_artifact_validation": {
            "complete": private_validation["complete"],
            "valid_programs": private_validation["valid_programs"],
            "invalid_programs": private_validation["invalid_programs"],
            "totals": private_validation["totals"],
        },
        "complete_artifact_refresh": complete_artifact_refresh,
        "call_graph_augmentation": call_graph_augmentation,
        "final_publication": final_publication,
        "disk_space": storage_observation,
        "validation": {
            "complete": validation["complete"],
            "valid_cases": validation["valid_cases"],
            "invalid_cases": validation["invalid_cases"],
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "arbitrary_ghidra_scripts_enabled": False,
            "mcp_localhost_only": True,
        },
    }
    _atomic_replace_bytes(
        private_output / "run-summary.json",
        _json_bytes(run_summary),
    )
    _write_run_progress(
        private_output,
        _run_progress_document(
            collection_id=collection_dir.name,
            status="complete",
            stop_reason=None,
            retryable=False,
            inventory_prepared=True,
            prepared_inventory_sha256=prepared_inventory_sha256,
            unique_pe_programs=len(ordered),
            complete_programs=len(results),
            cached_programs=cached_programs,
            newly_analyzed_programs=newly_analyzed,
            pending_programs=[],
            postprocessing_pending=False,
            prepared_inputs_reused=effective_reuse,
            resume_mode=resume_mode,
            disk_space=storage_observation,
        ),
    )
    return run_summary


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このhelpを表示して終了します")
        )


def build_parser() -> argparse.ArgumentParser:
    """CLI引数parserを構築する。"""

    repository = Path(__file__).resolve().parents[2]
    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=repository,
        help="repository rootを指定します",
    )
    parser.add_argument(
        "--collection",
        type=Path,
        default=repository / "analysis-results" / "collections" / DEFAULT_COLLECTION_ID,
        help="対象collection directoryを指定します",
    )
    parser.add_argument(
        "--sample-root",
        required=True,
        type=Path,
        help="暗号化archiveを保持するrepository外directoryを指定します",
    )
    parser.add_argument(
        "--prepared-input-root",
        type=Path,
        help=(
            "Ghidra用に復元した隔離inputを保持するrepository外directoryを指定します。"
            "省略時は後方互換のためsample rootを使用します"
        ),
    )
    parser.add_argument(
        "--private-output",
        required=True,
        type=Path,
        help="生の逆コンパイル成果物を保持するrepository外directoryを指定します",
    )
    parser.add_argument(
        "--minimum-free-bytes",
        type=int,
        default=DEFAULT_MINIMUM_FREE_BYTES,
        help=(f"各解析programの開始前後に確保する空き容量。既定は{DEFAULT_MINIMUM_FREE_BYTES} bytesです"),
    )
    parser.add_argument(
        "--disk-guard-path",
        action="append",
        default=[],
        type=Path,
        help="Ghidra projectなど追加で監視する既存storage rootを指定します",
    )
    parser.add_argument(
        "--mcp-url",
        default=DEFAULT_MCP_URL,
        help="localhostのGhidra MCP URLを指定します",
    )
    parser.add_argument(
        "--project-root",
        default=DEFAULT_PROJECT_ROOT,
        help="Ghidra project内の保存先rootを指定します",
    )
    parser.add_argument(
        "--upx",
        type=Path,
        help="公開解析契約と同一のUPX実行fileを指定します",
    )
    parser.add_argument(
        "--sevenzip",
        type=Path,
        help="公開解析契約と同一の7-Zip実行fileを指定します",
    )
    parser.add_argument(
        "--diec",
        type=Path,
        help="公開解析契約と同一のDetect It Easy CLI実行fileを指定します",
    )
    parser.add_argument(
        "--reuse-prepared-inputs",
        action="store_true",
        help="SHA-256検証済みghidra-input cacheから再開します",
    )
    parser.add_argument(
        "--max-new-programs",
        type=int,
        help=("今回新規にMCP解析するprogram数の上限。0は入力準備だけを行い、省略時は全programを処理します"),
    )
    parser.add_argument(
        "--skip-auto-analysis-sha256",
        action="append",
        default=[],
        type=str.lower,
        metavar="SHA256",
        help="反復timeoutを確認したprogramをauto-analysisなしの限定解析として処理します",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=3600,
        help="1つのMCP requestのtimeout秒数を指定します",
    )
    parser.add_argument(
        "--analysis-timeout",
        type=int,
        default=3600,
        help="1 programのauto-analysis timeout秒数を指定します",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint。"""

    args = build_parser().parse_args(argv)
    if args.max_new_programs is not None and args.max_new_programs < 0:
        raise ValueError("--max-new-programsは0以上で指定してください")
    if args.minimum_free_bytes < MINIMUM_CONFIGURABLE_FREE_BYTES:
        raise ValueError(f"--minimum-free-bytesは{MINIMUM_CONFIGURABLE_FREE_BYTES}以上で指定してください")
    invalid_hashes = [value for value in args.skip_auto_analysis_sha256 if not SHA256_RE.fullmatch(value)]
    if invalid_hashes:
        raise ValueError("--skip-auto-analysis-sha256は64文字のSHA-256で指定してください")
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    if result.get("status") == "complete":
        return 0
    return RETRYABLE_INCOMPLETE_EXIT_CODE


if __name__ == "__main__":
    raise SystemExit(main())
