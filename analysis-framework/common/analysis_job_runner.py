#!/usr/bin/env python3
"""WebUI／ローカルAPIから安全に呼び出せる静的解析ジョブrunner。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from analysis_contract import ensure_no_reparse_components, ensure_tree_without_reparse
from bounded_process import TERMINATION_WAIT_SECONDS, terminate_process_tree


COMMON_ROOT = Path(__file__).resolve().parent
FRAMEWORK_ROOT = COMMON_ROOT.parent
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
ANALYZER = COMMON_ROOT / "analyze_sample.py"
REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"

SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
MAX_FAMILY_HINT_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_REGISTRY_BYTES = 8 * 1024 * 1024
MAX_SUMMARY_BYTES = 64 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
MAX_ANALYSIS_OUTPUT_ENTRIES = 100_000
MAX_ANALYSIS_OUTPUT_BYTES = 1024 * 1024 * 1024
MIN_FREE_DISK_RESERVE_BYTES = 256 * 1024 * 1024
MAX_REQUEST_INPUTS = 64
MAX_DISCOVERED_FILES = 1_000
MAX_TREE_ENTRIES = 10_000
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 2 * 1024 * 1024 * 1024
MAX_STRING_SCAN_LIMIT = 1_000_000
MAX_STATIC_LAYERS = 64
MAX_RETRY_STATIC_LAYERS = 256
DEFAULT_TIMEOUT_SECONDS = 6 * 60 * 60
MAX_TIMEOUT_SECONDS = 24 * 60 * 60
PIPE_DRAIN_CHUNK_BYTES = 64 * 1024
OUTPUT_MONITOR_INTERVAL_SECONDS = 0.5

JOB_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
FAMILY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
RESERVED_WINDOWS_NAMES = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}

ALLOWED_TOP_LEVEL_KEYS = frozenset({"schema_version", "job_id", "inputs", "family_hint_manifest", "options"})
REQUIRED_TOP_LEVEL_KEYS = frozenset({"schema_version", "job_id", "inputs"})
ALLOWED_OPTION_KEYS = frozenset(
    {
        "archive_mode",
        "family",
        "minimum_confidence",
        "assessment_only",
        "force_container_probe",
        "max_files",
        "max_file_size",
        "string_scan_limit",
        "max_static_layers",
        "retry_max_static_layers",
    }
)
FORBIDDEN_OPTION_KEYS = frozenset(
    {
        "allow_network",
        "allow_live_c2_check",
        "allow_live_c2_emulation",
        "allow_reviewed_application_probes",
        "allow_authentication",
        "allow_malware_registration_tasking",
        "collect_jarm",
        "profile",
        "profile_path",
        "endpoint",
        "url",
        "password",
        "registry",
        "python",
        "output",
        "upx",
        "sevenzip",
        "diec",
        "command",
        "environment",
    }
)
DEFAULT_OPTIONS: dict[str, Any] = {
    "archive_mode": "auto",
    "family": None,
    "minimum_confidence": "medium",
    "assessment_only": False,
    "force_container_probe": False,
    "max_files": MAX_DISCOVERED_FILES,
    "max_file_size": MAX_FILE_SIZE,
    "string_scan_limit": MAX_STRING_SCAN_LIMIT,
    "max_static_layers": MAX_STATIC_LAYERS,
    "retry_max_static_layers": None,
}
SUMMARY_COUNT_KEYS = (
    "input_files",
    "analyzed",
    "duplicates",
    "errors",
    "identified",
    "unknown_or_ambiguous",
    "handler_successes",
    "handler_failures",
    "handler_no_evidence",
    "handler_ambiguous",
    "handler_incompatible",
    "analysis_stage_failures",
    "analysis_stage_partial",
    "complete",
    "triaged_unknown",
    "partial",
    "failed",
    "resumed",
)


class JobContractError(ValueError):
    """ジョブ契約違反を機械可読code付きで表す。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        """日本語化したhelpを返す。"""

        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("positional arguments:", "サブコマンド:")
            .replace("show this help message and exit", "このヘルプを表示して終了します")
        )


@dataclass(frozen=True)
class JobRequest:
    """検証済みジョブ要求。"""

    job_id: str
    inputs: tuple[str, ...]
    family_hint_manifest: str | None
    options: Mapping[str, Any]

    def public(self) -> dict[str, Any]:
        """保存可能な正規化済み要求を返す。"""

        return {
            "schema_version": SCHEMA_VERSION,
            "job_id": self.job_id,
            "inputs": list(self.inputs),
            "family_hint_manifest": self.family_hint_manifest,
            "options": dict(self.options),
        }


@dataclass(frozen=True)
class InputRecord:
    """入力境界検証の公開可能な集計。"""

    relative_path: str
    kind: str
    file_count: int
    total_bytes: int

    def public(self) -> dict[str, Any]:
        """絶対pathを含まないJSON表現を返す。"""

        return {
            "relative_path": self.relative_path,
            "kind": self.kind,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


def utc_now() -> str:
    """秒精度のcanonical UTC時刻を返す。"""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ensure_no_reparse(path: Path, *, code: str, message: str) -> None:
    try:
        ensure_no_reparse_components(path)
    except ValueError as exc:
        raise JobContractError(code, message) from exc


def _ensure_tree_no_reparse(path: Path, *, max_entries: int, code: str, message: str) -> None:
    try:
        ensure_tree_without_reparse(path, max_entries=max_entries)
    except ValueError as exc:
        raise JobContractError(code, message) from exc


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JobContractError("duplicate_json_key", f"JSON keyが重複しています: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise JobContractError("non_finite_json_number", f"非有限数は使用できません: {value}")


def _stat_has_reparse_attribute(information: os.stat_result) -> bool:
    return bool(int(getattr(information, "st_file_attributes", 0)) & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    try:
        return os.path.samestat(first, second)
    except (AttributeError, OSError):
        return first.st_dev == second.st_dev and first.st_ino != 0 and first.st_ino == second.st_ino


def _read_regular_file_once(path: Path, *, max_bytes: int) -> bytes:
    """単一handleから上限+1 byteだけ読み、置換・hardlink・reparseを拒否する。"""

    _ensure_no_reparse(path, code="json_reparse_forbidden", message="reparse pointを含むJSON pathは禁止です")
    try:
        before = path.lstat()
    except OSError as exc:
        raise JobContractError("json_unreadable", "JSON fileを安全に確認できません") from exc
    if not stat.S_ISREG(before.st_mode) or _stat_has_reparse_attribute(before):
        raise JobContractError("json_not_regular_file", "JSONはreparseではない通常fileで指定してください")
    if before.st_nlink != 1:
        raise JobContractError("json_hardlink_forbidden", "hardlinkされたJSONは使用できません")
    if before.st_size <= 0 or before.st_size > max_bytes:
        raise JobContractError("json_size_out_of_bounds", f"JSON sizeは1..{max_bytes} bytesで指定してください")

    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise JobContractError("json_unreadable", "JSON fileを安全に開けません") from exc
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or _stat_has_reparse_attribute(opened):
                raise JobContractError("json_not_regular_file", "JSONはreparseではない通常fileで指定してください")
            if opened.st_nlink != 1:
                raise JobContractError("json_hardlink_forbidden", "hardlinkされたJSONは使用できません")
            if not _same_file_identity(before, opened):
                raise JobContractError("json_changed_during_read", "JSON pathが検証中に置換されました")
            data = handle.read(max_bytes + 1)
            after_handle = os.fstat(handle.fileno())
    except JobContractError:
        raise
    except OSError as exc:
        raise JobContractError("json_unreadable", "JSON fileを安全に読み取れません") from exc

    if len(data) == 0 or len(data) > max_bytes:
        raise JobContractError("json_size_out_of_bounds", f"JSON sizeは1..{max_bytes} bytesで指定してください")
    try:
        after_path = path.lstat()
    except OSError as exc:
        raise JobContractError("json_changed_during_read", "JSON pathが検証中に変更されました") from exc
    stable_metadata = (
        opened.st_size == len(data) == after_handle.st_size
        and opened.st_mtime_ns == after_handle.st_mtime_ns
        and opened.st_ctime_ns == after_handle.st_ctime_ns
    )
    if not stable_metadata or not _same_file_identity(opened, after_path) or after_path.st_nlink != 1:
        raise JobContractError("json_changed_during_read", "JSON fileが検証中に変更されました")
    return data


def _decode_json_object_strict(data: bytes) -> dict[str, Any]:
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
        )
    except UnicodeDecodeError as exc:
        raise JobContractError("json_not_utf8", "JSONはBOMなしUTF-8で保存してください") from exc
    except json.JSONDecodeError as exc:
        raise JobContractError("json_invalid", f"JSON構文が不正です: line {exc.lineno}, column {exc.colno}") from exc
    if not isinstance(value, dict):
        raise JobContractError("json_root_not_object", "JSON rootはobjectである必要があります")
    return value


def load_json_object_strict(path: Path, *, max_bytes: int) -> dict[str, Any]:
    """UTF-8、重複key禁止、size上限付きでJSON objectを単一handleから読む。"""

    return _decode_json_object_strict(_read_regular_file_once(path, max_bytes=max_bytes))


def _bounded_integer(value: Any, *, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise JobContractError("option_out_of_bounds", f"{name}は1..{maximum}の整数で指定してください")
    return value


def _normalize_relative_input(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 512:
        raise JobContractError("invalid_input_path", "inputsは512文字以下の空でない相対pathで指定してください")
    if "\\" in value or "\x00" in value or value.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", value):
        raise JobContractError("invalid_input_path", f"絶対pathまたはbackslashは使用できません: {value!r}")
    parts = value.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise JobContractError("invalid_input_path", f"空component、'.'、'..'は使用できません: {value!r}")
    for part in parts:
        if part.endswith((" ", ".")) or any(ord(character) < 32 for character in part):
            raise JobContractError("invalid_input_path", f"曖昧なpath componentは使用できません: {value!r}")
        stem = part.split(".", 1)[0].casefold()
        if stem in RESERVED_WINDOWS_NAMES:
            raise JobContractError("invalid_input_path", f"予約device名は使用できません: {value!r}")
    return "/".join(parts)


def _registered_families() -> set[str]:
    value = load_json_object_strict(REGISTRY, max_bytes=MAX_REGISTRY_BYTES)
    malware_types = value.get("malware_types")
    if not isinstance(malware_types, dict) or not malware_types:
        raise JobContractError("registry_invalid", "malware registryにmalware_typesがありません")
    return {key for key in malware_types if isinstance(key, str)}


def validate_request_object(value: Mapping[str, Any]) -> JobRequest:
    """厳格schemaと固定allowlistでジョブ要求を検証する。"""

    keys = set(value)
    missing = REQUIRED_TOP_LEVEL_KEYS - keys
    unknown = keys - ALLOWED_TOP_LEVEL_KEYS
    if missing:
        raise JobContractError("missing_request_key", f"必須keyがありません: {', '.join(sorted(missing))}")
    if unknown:
        raise JobContractError("unknown_request_key", f"未許可のtop-level keyです: {', '.join(sorted(unknown))}")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise JobContractError("unsupported_schema_version", f"schema_versionは{SCHEMA_VERSION}だけを許可します")

    job_id = value.get("job_id")
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        raise JobContractError("invalid_job_id", "job_idは1..64文字の小文字英数字、'.'、'_'、'-'に限定します")

    raw_inputs = value.get("inputs")
    if not isinstance(raw_inputs, list) or not 1 <= len(raw_inputs) <= MAX_REQUEST_INPUTS:
        raise JobContractError("invalid_input_count", f"inputsは1..{MAX_REQUEST_INPUTS}件のarrayで指定してください")
    inputs = tuple(_normalize_relative_input(item) for item in raw_inputs)
    folded = [item.casefold() for item in inputs]
    if len(folded) != len(set(folded)):
        raise JobContractError("duplicate_input", "inputsに大文字小文字だけが異なる重複pathがあります")

    raw_manifest = value.get("family_hint_manifest")
    family_hint_manifest = None if raw_manifest is None else _normalize_relative_input(raw_manifest)
    if family_hint_manifest and family_hint_manifest.casefold() in set(folded):
        raise JobContractError("manifest_is_input", "family_hint_manifestを通常inputsへ重複指定できません")

    raw_options = value.get("options", {})
    if not isinstance(raw_options, dict):
        raise JobContractError("invalid_options", "optionsはobjectで指定してください")
    option_keys = set(raw_options)
    forbidden = option_keys & FORBIDDEN_OPTION_KEYS
    if forbidden:
        raise JobContractError(
            "network_or_privileged_option_forbidden",
            f"ネットワーク、live、秘密値、任意実行fileのoptionは禁止です: {', '.join(sorted(forbidden))}",
        )
    unknown_options = option_keys - ALLOWED_OPTION_KEYS
    if unknown_options:
        raise JobContractError("unknown_option", f"未許可のoptionです: {', '.join(sorted(unknown_options))}")

    options = dict(DEFAULT_OPTIONS)
    options.update(raw_options)
    if options["archive_mode"] not in {"auto", "raw", "malwarebazaar"}:
        raise JobContractError("invalid_option", "archive_modeはauto、raw、malwarebazaarのいずれかです")
    if options["minimum_confidence"] not in {"low", "medium", "high"}:
        raise JobContractError("invalid_option", "minimum_confidenceはlow、medium、highのいずれかです")
    for key in ("assessment_only", "force_container_probe"):
        if not isinstance(options[key], bool):
            raise JobContractError("invalid_option", f"{key}はbooleanで指定してください")

    options["max_files"] = _bounded_integer(options["max_files"], name="max_files", maximum=MAX_DISCOVERED_FILES)
    options["max_file_size"] = _bounded_integer(options["max_file_size"], name="max_file_size", maximum=MAX_FILE_SIZE)
    options["string_scan_limit"] = _bounded_integer(
        options["string_scan_limit"], name="string_scan_limit", maximum=MAX_STRING_SCAN_LIMIT
    )
    options["max_static_layers"] = _bounded_integer(
        options["max_static_layers"], name="max_static_layers", maximum=MAX_STATIC_LAYERS
    )
    retry_layers = options["retry_max_static_layers"]
    if retry_layers is not None:
        retry_layers = _bounded_integer(
            retry_layers,
            name="retry_max_static_layers",
            maximum=MAX_RETRY_STATIC_LAYERS,
        )
        if retry_layers <= options["max_static_layers"]:
            raise JobContractError(
                "invalid_option",
                "retry_max_static_layersはmax_static_layersより大きく指定してください",
            )
        options["retry_max_static_layers"] = retry_layers

    family = options["family"]
    if family is not None:
        if not isinstance(family, str) or not FAMILY_RE.fullmatch(family):
            raise JobContractError("invalid_family", "familyはregistryの小文字IDで指定してください")
        if family not in _registered_families():
            raise JobContractError("unregistered_family", f"未登録のfamilyです: {family}")

    return JobRequest(
        job_id=job_id,
        inputs=inputs,
        family_hint_manifest=family_hint_manifest,
        options=options,
    )


def load_job_request(path: Path) -> JobRequest:
    """fileから厳格なジョブ要求を読む。"""

    return validate_request_object(load_json_object_strict(path, max_bytes=MAX_REQUEST_BYTES))


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _paths_overlap(first: Path, second: Path) -> bool:
    return _is_within(first, second) or _is_within(second, first)


def validate_roots(input_root: Path, jobs_root: Path, *, create_jobs_root: bool) -> tuple[Path, Path]:
    """入力rootとジョブrootを固定し、相互包含を拒否する。"""

    input_absolute = _absolute_path(input_root)
    jobs_absolute = _absolute_path(jobs_root)
    _ensure_no_reparse(
        input_absolute,
        code="input_root_reparse_forbidden",
        message="input-rootにreparse pointを使用できません",
    )
    _ensure_no_reparse(
        jobs_absolute,
        code="jobs_root_reparse_forbidden",
        message="jobs-rootにreparse pointを使用できません",
    )
    if not input_absolute.is_dir():
        raise JobContractError("input_root_invalid", "input-rootは既存directoryで指定してください")
    if jobs_absolute.exists() and not jobs_absolute.is_dir():
        raise JobContractError("jobs_root_invalid", "jobs-rootはdirectoryで指定してください")
    input_resolved = input_absolute.resolve(strict=True)
    prospective_jobs = jobs_absolute.resolve(strict=False)
    if _paths_overlap(input_resolved, prospective_jobs):
        raise JobContractError("root_overlap", "input-rootとjobs-rootは相互に含まれない別directoryへ分離してください")
    if not jobs_absolute.exists():
        if not create_jobs_root:
            parent = jobs_absolute.parent
            if not parent.is_dir():
                raise JobContractError("jobs_root_parent_invalid", "jobs-rootの親directoryがありません")
        else:
            jobs_absolute.mkdir(parents=True, exist_ok=False)
            _ensure_no_reparse(
                jobs_absolute,
                code="jobs_root_reparse_forbidden",
                message="jobs-rootにreparse pointを使用できません",
            )
    jobs_resolved = jobs_absolute.resolve(strict=jobs_absolute.exists())
    if _paths_overlap(input_resolved, jobs_resolved):
        raise JobContractError("root_overlap", "input-rootとjobs-rootは相互に含まれない別directoryへ分離してください")
    return input_resolved, jobs_resolved


def _scan_directory(path: Path, *, max_file_size: int) -> tuple[int, int]:
    _ensure_tree_no_reparse(
        path,
        max_entries=MAX_TREE_ENTRIES,
        code="input_tree_reparse_forbidden",
        message="入力treeにreparse pointを使用できません",
    )
    pending = [path]
    file_count = 0
    total_bytes = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError as exc:
            raise JobContractError("input_unreadable", "入力directoryを安全に列挙できません") from exc
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise JobContractError("unsupported_input_entry", "通常file／directory以外の入力は使用できません")
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise JobContractError("input_unreadable", "入力entryを安全に確認できません") from exc
            if not stat.S_ISREG(info.st_mode):
                raise JobContractError("unsupported_input_entry", "通常file以外の入力は使用できません")
            if info.st_size > max_file_size:
                raise JobContractError("input_file_too_large", f"入力fileが{max_file_size} bytes上限を超えています")
            file_count += 1
            total_bytes += info.st_size
    return file_count, total_bytes


def validate_inputs(request: JobRequest, input_root: Path) -> tuple[list[Path], list[InputRecord]]:
    """要求された相対pathをroot内へ固定し、全treeの件数と容量を検証する。"""

    resolved_inputs: list[Path] = []
    records: list[InputRecord] = []
    for relative in request.inputs:
        candidate = input_root.joinpath(*relative.split("/"))
        _ensure_no_reparse(
            candidate,
            code="input_reparse_forbidden",
            message=f"入力pathにreparse pointを使用できません: {relative}",
        )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise JobContractError("input_missing", f"入力が見つかりません: {relative}") from exc
        if not _is_within(resolved, input_root):
            raise JobContractError("input_boundary_escape", f"input-root外へ解決されるpathです: {relative}")
        for existing in resolved_inputs:
            if _paths_overlap(resolved, existing):
                raise JobContractError("overlapping_inputs", "親directoryと子fileなど重複するinputsは指定できません")
        if resolved.is_file():
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode):
                raise JobContractError("unsupported_input_entry", "通常file以外の入力は使用できません")
            if info.st_size > request.options["max_file_size"]:
                raise JobContractError(
                    "input_file_too_large",
                    f"入力fileが{request.options['max_file_size']} bytes上限を超えています: {relative}",
                )
            file_count, total_bytes, kind = 1, info.st_size, "file"
        elif resolved.is_dir():
            file_count, total_bytes = _scan_directory(
                resolved,
                max_file_size=request.options["max_file_size"],
            )
            kind = "directory"
        else:
            raise JobContractError("unsupported_input_entry", "通常file／directory以外の入力は使用できません")
        resolved_inputs.append(resolved)
        records.append(InputRecord(relative, kind, file_count, total_bytes))

    total_files = sum(item.file_count for item in records)
    total_bytes = sum(item.total_bytes for item in records)
    if total_files == 0:
        raise JobContractError("no_input_files", "解析対象fileがありません")
    if total_files > request.options["max_files"]:
        raise JobContractError("input_count_exceeded", f"入力file数が{request.options['max_files']}件を超えています")
    if total_bytes > MAX_TOTAL_INPUT_BYTES:
        raise JobContractError("total_input_size_exceeded", f"入力合計が{MAX_TOTAL_INPUT_BYTES} bytesを超えています")
    if request.options["archive_mode"] == "malwarebazaar":
        candidates = [path for path in resolved_inputs if path.is_file() and path.suffix.casefold() == ".zip"]
        directory_present = any(path.is_dir() for path in resolved_inputs)
        if not candidates and not directory_present:
            raise JobContractError("no_malwarebazaar_zip", "malwarebazaar modeにはZIP入力が必要です")
    return resolved_inputs, records


def _validated_family_hint_manifest_payload(
    request: JobRequest,
    input_root: Path,
    inputs: Sequence[Path],
) -> tuple[Path, bytes] | None:
    """family hint manifestの固定pathと単一handleで読んだbytesを返す。"""

    if request.family_hint_manifest is None:
        return None
    relative = request.family_hint_manifest
    candidate = input_root.joinpath(*relative.split("/"))
    _ensure_no_reparse(
        candidate,
        code="manifest_reparse_forbidden",
        message="family_hint_manifestにreparse pointを使用できません",
    )
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise JobContractError("manifest_missing", "family_hint_manifestが見つかりません") from exc
    if not _is_within(resolved, input_root):
        raise JobContractError("manifest_boundary_escape", "family_hint_manifestがinput-root外へ解決されます")
    if any(_paths_overlap(resolved, input_path) for input_path in inputs):
        raise JobContractError(
            "manifest_overlaps_inputs",
            "family_hint_manifestは通常inputsと重複しないpathへ分離してください",
        )
    try:
        payload = _read_regular_file_once(resolved, max_bytes=MAX_FAMILY_HINT_MANIFEST_BYTES)
    except JobContractError as exc:
        if exc.code == "json_not_regular_file":
            raise JobContractError(
                "manifest_not_regular_file",
                "family_hint_manifestは通常fileで指定してください",
            ) from exc
        raise
    _decode_json_object_strict(payload)
    return resolved, payload


def validate_family_hint_manifest(
    request: JobRequest,
    input_root: Path,
    inputs: Sequence[Path],
) -> Path | None:
    """family hint manifestを通常入力から分離してstrict JSONとして検証する。"""

    validated = _validated_family_hint_manifest_payload(request, input_root, inputs)
    return validated[0] if validated is not None else None


def stage_family_hint_manifest(
    request: JobRequest,
    input_root: Path,
    inputs: Sequence[Path],
    job_dir: Path,
) -> tuple[Path | None, str | None]:
    """検証時bytesをjob-localへatomicに固定し、そのcopyだけを子processへ渡す。"""

    validated = _validated_family_hint_manifest_payload(request, input_root, inputs)
    if validated is None:
        return None, None
    _, payload = validated
    staged = job_dir / "contract-inputs" / "family-hint-manifest.json"
    _atomic_bytes(staged, payload)
    load_json_object_strict(staged, max_bytes=MAX_FAMILY_HINT_MANIFEST_BYTES)
    return staged, hashlib.sha256(payload).hexdigest()


def build_analyzer_argv(
    request: JobRequest,
    inputs: Sequence[Path],
    output: Path,
    *,
    python_executable: Path | None = None,
    family_hint_manifest: Path | None = None,
) -> list[str]:
    """固定scriptとallowlist optionだけからshellを介さないargvを作る。"""

    executable = Path(python_executable or sys.executable).resolve(strict=True)
    argv = [str(executable), str(ANALYZER)]
    for path in inputs:
        argv.extend(("--input", str(path)))
    options = request.options
    argv.extend(
        (
            "--output",
            str(output),
            "--registry",
            str(REGISTRY),
            "--archive-mode",
            options["archive_mode"],
            "--minimum-confidence",
            options["minimum_confidence"],
            "--max-files",
            str(options["max_files"]),
            "--max-file-size",
            str(options["max_file_size"]),
            "--string-scan-limit",
            str(options["string_scan_limit"]),
            "--max-static-layers",
            str(options["max_static_layers"]),
        )
    )
    if options["family"]:
        argv.extend(("--family", options["family"]))
    if family_hint_manifest is not None:
        argv.extend(("--family-hint-manifest", str(family_hint_manifest)))
    if options["assessment_only"]:
        argv.append("--assessment-only")
    if options["force_container_probe"]:
        argv.append("--force-container-probe")
    if options["retry_max_static_layers"] is not None:
        argv.extend(("--retry-max-static-layers", str(options["retry_max_static_layers"])))
    return argv


def build_sanitized_environment(*, python_executable: Path | None = None) -> dict[str, str]:
    """API keyやPython注入設定を子processへ渡さない最小環境を作る。"""

    executable = Path(python_executable or sys.executable).resolve(strict=True)
    environment: dict[str, str] = {}
    for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "PATHEXT"):
        if os.environ.get(key):
            environment[key] = os.environ[key]
    path_parts = [str(executable.parent)]
    system_root = environment.get("SYSTEMROOT") or environment.get("WINDIR")
    if system_root:
        path_parts.append(str(Path(system_root) / "System32"))
    elif os.name != "nt":
        path_parts.extend(("/usr/bin", "/bin"))
    environment.update(
        {
            "PATH": os.pathsep.join(path_parts),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
        }
    )
    return environment


def _atomic_bytes(path: Path, data: bytes) -> None:
    _ensure_no_reparse(
        path.parent,
        code="output_reparse_forbidden",
        message="job出力pathにreparse pointを使用できません",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def atomic_json(path: Path, value: Any) -> None:
    """同一directory内の一時fileからJSONをatomicに置換する。"""

    _atomic_bytes(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def _write_progress(job_dir: Path, *, phase: str, percent: int, message: str, **extra: Any) -> None:
    value = {
        "schema_version": SCHEMA_VERSION,
        "job_id": job_dir.name,
        "phase": phase,
        "percent": percent,
        "message": message,
        "updated_at_utc": utc_now(),
    }
    value.update(extra)
    atomic_json(job_dir / "progress.json", value)


def _write_status(
    job_dir: Path,
    *,
    state: str,
    terminal: bool,
    created_at_utc: str,
    started_at_utc: str | None = None,
    finished_at_utc: str | None = None,
    error: Mapping[str, str] | None = None,
) -> None:
    atomic_json(
        job_dir / "status.json",
        {
            "schema_version": SCHEMA_VERSION,
            "job_id": job_dir.name,
            "state": state,
            "terminal": terminal,
            "created_at_utc": created_at_utc,
            "started_at_utc": started_at_utc,
            "finished_at_utc": finished_at_utc,
            "progress_path": "progress.json",
            "result_path": "result.json" if terminal else None,
            "error": dict(error) if error else None,
        },
    )


def _request_digest(request: JobRequest) -> str:
    encoded = json.dumps(request.public(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _bounded_log(value: bytes | str | None) -> tuple[bytes, bool]:
    if value is None:
        return b"", False
    encoded = value.encode("utf-8", errors="replace") if isinstance(value, str) else value
    return encoded[:MAX_LOG_BYTES], len(encoded) > MAX_LOG_BYTES


@dataclass
class _PipeCapture:
    retained: bytearray
    truncated: bool = False
    error: BaseException | None = None


@dataclass(frozen=True)
class _BoundedProcessResult:
    args: Sequence[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool

    def check_returncode(self) -> None:
        if self.returncode:
            raise subprocess.CalledProcessError(
                self.returncode,
                self.args,
                output=self.stdout,
                stderr=self.stderr,
            )


def _drain_pipe(stream: Any, capture: _PipeCapture) -> None:
    """pipeをEOFまで消費し、先頭1 MiBだけをmemoryへ保持する。"""

    try:
        while True:
            chunk = stream.read(PIPE_DRAIN_CHUNK_BYTES)
            if not chunk:
                break
            remaining = MAX_LOG_BYTES - len(capture.retained)
            if remaining > 0:
                capture.retained.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                capture.truncated = True
    except BaseException as exc:  # pragma: no cover - OS pipe故障時の最終境界
        capture.error = exc
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _run_process_with_bounded_output(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    shell: bool,
    check: bool,
    stdout: int,
    stderr: int,
    timeout: int,
    monitored_output: Path | None = None,
) -> _BoundedProcessResult:
    """子孫treeを所有し、logと解析出力を有界に保ってprocessを実行する。"""

    if shell is not False or stdout is not subprocess.PIPE or stderr is not subprocess.PIPE:
        raise ValueError("bounded runnerはshell=Falseとstdout/stderr=PIPEだけを許可します")
    if monitored_output is not None:
        validate_analysis_output_tree(monitored_output)
        if shutil.disk_usage(monitored_output).free <= MIN_FREE_DISK_RESERVE_BYTES:
            raise JobContractError(
                "analysis_output_disk_reserve_exceeded",
                f"job filesystemの空き容量が{MIN_FREE_DISK_RESERVE_BYTES} bytes以下です",
            )
    platform_options: dict[str, Any]
    if os.name == "nt":
        platform_options = {"creationflags": int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))}
    else:
        platform_options = {"start_new_session": True}
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **platform_options,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen契約の最終確認
        terminate_process_tree(process)
        raise RuntimeError("stdout/stderr pipeを確立できません")
    stdout_capture = _PipeCapture(bytearray())
    stderr_capture = _PipeCapture(bytearray())
    drains = (
        threading.Thread(target=_drain_pipe, args=(process.stdout, stdout_capture), daemon=True),
        threading.Thread(target=_drain_pipe, args=(process.stderr, stderr_capture), daemon=True),
    )
    for thread in drains:
        thread.start()

    try:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            try:
                return_code = process.wait(timeout=min(OUTPUT_MONITOR_INTERVAL_SECONDS, remaining))
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    raise
                if monitored_output is not None:
                    validate_analysis_output_tree(monitored_output)
                    if shutil.disk_usage(monitored_output).free <= MIN_FREE_DISK_RESERVE_BYTES:
                        raise JobContractError(
                            "analysis_output_disk_reserve_exceeded",
                            f"job filesystemの空き容量が{MIN_FREE_DISK_RESERVE_BYTES} bytes以下になりました",
                        )
    except subprocess.TimeoutExpired as original_timeout:
        terminate_process_tree(process)
        for thread in drains:
            thread.join(timeout=TERMINATION_WAIT_SECONDS)
        raise subprocess.TimeoutExpired(
            command,
            timeout,
            output=bytes(stdout_capture.retained),
            stderr=bytes(stderr_capture.retained),
        ) from original_timeout
    except BaseException:
        try:
            terminate_process_tree(process)
        except BaseException:
            pass
        for thread in drains:
            thread.join(timeout=TERMINATION_WAIT_SECONDS)
        raise

    for thread in drains:
        thread.join(timeout=TERMINATION_WAIT_SECONDS)
    if any(thread.is_alive() for thread in drains):
        terminate_process_tree(process)
        raise RuntimeError("stdout/stderr drainが時間内に終了しませんでした")
    for capture in (stdout_capture, stderr_capture):
        if capture.error is not None:
            raise RuntimeError("stdout/stderr drainに失敗しました") from capture.error
    completed = _BoundedProcessResult(
        args=command,
        returncode=return_code,
        stdout=bytes(stdout_capture.retained),
        stderr=bytes(stderr_capture.retained),
        stdout_truncated=stdout_capture.truncated,
        stderr_truncated=stderr_capture.truncated,
    )
    if check:
        completed.check_returncode()
    return completed


def validate_analysis_output_tree(path: Path) -> dict[str, int]:
    """解析出力treeの種類・件数・合計sizeをhard quotaで検証する。"""

    _ensure_tree_no_reparse(
        path,
        max_entries=MAX_ANALYSIS_OUTPUT_ENTRIES,
        code="analysis_output_reparse_forbidden",
        message="解析出力にreparse pointが含まれています",
    )
    pending = [path]
    entries = 0
    files = 0
    directories = 0
    total_bytes = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name.casefold())
        except OSError as exc:
            raise JobContractError("analysis_output_unreadable", "解析出力treeを安全に列挙できません") from exc
        for entry in children:
            entries += 1
            if entries > MAX_ANALYSIS_OUTPUT_ENTRIES:
                raise JobContractError(
                    "analysis_output_entry_quota_exceeded",
                    f"解析出力が{MAX_ANALYSIS_OUTPUT_ENTRIES} entry上限を超えています",
                )
            try:
                entry_path = Path(entry.path)
                information = entry_path.lstat()
            except OSError as exc:
                raise JobContractError("analysis_output_unreadable", "解析出力entryを安全に確認できません") from exc
            if _stat_has_reparse_attribute(information):
                raise JobContractError("analysis_output_reparse_forbidden", "解析出力にreparse pointが含まれています")
            if entry.is_dir(follow_symlinks=False):
                directories += 1
                pending.append(entry_path)
                continue
            if not entry.is_file(follow_symlinks=False) or not stat.S_ISREG(information.st_mode):
                raise JobContractError("analysis_output_entry_forbidden", "解析出力には通常file／directoryだけを許可します")
            if information.st_nlink != 1:
                raise JobContractError("analysis_output_hardlink_forbidden", "解析出力にhardlinkを使用できません")
            files += 1
            total_bytes += information.st_size
            if total_bytes > MAX_ANALYSIS_OUTPUT_BYTES:
                raise JobContractError(
                    "analysis_output_size_quota_exceeded",
                    f"解析出力が{MAX_ANALYSIS_OUTPUT_BYTES} bytes上限を超えています",
                )
    return {"entries": entries, "files": files, "directories": directories, "total_bytes": total_bytes}


def _validated_summary(path: Path, *, expected_input_files: int) -> tuple[dict[str, Any], dict[str, int]]:
    summary = load_json_object_strict(path, max_bytes=MAX_SUMMARY_BYTES)
    if summary.get("schema_version") != SCHEMA_VERSION:
        raise JobContractError("summary_invalid", "summary.jsonのschema_versionが一致しません")
    if (
        summary.get("executed_sample") is not False
        or summary.get("network_contacted") is not False
        or summary.get("ai_used") is not False
    ):
        raise JobContractError(
            "analyzer_safety_contract_failed",
            "summaryのexecuted_sample／network_contacted／ai_usedが明示的なfalseではありません",
        )
    raw_counts = summary.get("counts")
    if not isinstance(raw_counts, dict):
        raise JobContractError("summary_invalid", "summary.jsonにcounts objectがありません")
    counts: dict[str, int] = {}
    for key in SUMMARY_COUNT_KEYS:
        value = raw_counts.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise JobContractError("summary_invalid", f"summary counts.{key}が非負整数ではありません")
        counts[key] = value
    for key, expected_type in (("cases", list), ("duplicates", list), ("errors", list)):
        if not isinstance(summary.get(key), expected_type):
            raise JobContractError("summary_invalid", f"summary.{key}はarrayである必要があります")
    if counts["input_files"] != expected_input_files:
        raise JobContractError("summary_count_mismatch", "summary input_filesが検証済み入力file数と一致しません")
    if counts["input_files"] != counts["analyzed"] + counts["duplicates"] + counts["errors"]:
        raise JobContractError("summary_count_mismatch", "analyzed、duplicates、errorsの合計がinput_filesと一致しません")
    if counts["identified"] + counts["unknown_or_ambiguous"] != counts["analyzed"]:
        raise JobContractError("summary_count_mismatch", "family分類件数の合計がanalyzedと一致しません")
    terminal_state_total = counts["complete"] + counts["triaged_unknown"] + counts["partial"] + counts["failed"]
    assessment_only_count = sum(
        isinstance(case, dict) and case.get("case_state") == "assessment_only_complete" for case in summary["cases"]
    )
    settings = summary.get("settings")
    assessment_only = isinstance(settings, dict) and settings.get("assessment_only") is True
    if terminal_state_total + (assessment_only_count if assessment_only else 0) != counts["analyzed"]:
        raise JobContractError("summary_count_mismatch", "case状態件数の合計がanalyzedと一致しません")
    if counts["resumed"] > counts["analyzed"]:
        raise JobContractError("summary_count_mismatch", "resumedがanalyzedを超えています")
    if len(summary["cases"]) != counts["analyzed"]:
        raise JobContractError("summary_count_mismatch", "cases件数がanalyzedと一致しません")
    if len(summary["duplicates"]) != counts["duplicates"] or len(summary["errors"]) != counts["errors"]:
        raise JobContractError("summary_count_mismatch", "duplicates／errors配列件数がcountsと一致しません")
    return summary, counts


def _write_failure(
    job_dir: Path,
    request: JobRequest,
    *,
    created_at_utc: str,
    started_at_utc: str | None,
    code: str,
    message: str,
    state: str = "failed",
    process_exit_code: int | None = None,
    inputs: Sequence[InputRecord] = (),
) -> None:
    finished = utc_now()
    atomic_json(
        job_dir / "result.json",
        {
            "schema_version": SCHEMA_VERSION,
            "job_id": request.job_id,
            "request_sha256": _request_digest(request),
            "accepted": False,
            "analysis_state": state,
            "inputs": [item.public() for item in inputs],
            "family_hint_manifest": request.family_hint_manifest,
            "process": {"exit_code": process_exit_code, "shell": False},
            "safety": {
                "network_or_live_options_allowed": False,
                "sample_execution_allowed": False,
                "ai_used": False,
                "summary_safety_contract_verified": False,
            },
            "error": {"code": code, "message": message},
            "finished_at_utc": finished,
        },
    )
    _write_progress(job_dir, phase=state, percent=100, message=message)
    _write_status(
        job_dir,
        state=state,
        terminal=True,
        created_at_utc=created_at_utc,
        started_at_utc=started_at_utc,
        finished_at_utc=finished,
        error={"code": code, "message": message},
    )


def run_job(
    request: JobRequest,
    *,
    input_root: Path,
    jobs_root: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    run_process: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
) -> int:
    """検証済み要求を1回だけ実行し、状態・進捗・結果をatomicに保存する。"""

    timeout_seconds = _bounded_integer(
        timeout_seconds,
        name="timeout_seconds",
        maximum=MAX_TIMEOUT_SECONDS,
    )
    input_root, jobs_root = validate_roots(input_root, jobs_root, create_jobs_root=True)
    job_dir = jobs_root / request.job_id
    try:
        job_dir.mkdir(exist_ok=False)
    except FileExistsError as exc:
        raise JobContractError("job_already_exists", "同じjob_idは再利用できません") from exc
    _ensure_no_reparse(
        job_dir,
        code="output_reparse_forbidden",
        message="job出力pathにreparse pointを使用できません",
    )
    analysis_output = job_dir / "analysis"
    analysis_output.mkdir(exist_ok=False)
    created = utc_now()
    atomic_json(job_dir / "request.json", request.public())
    _write_status(job_dir, state="queued", terminal=False, created_at_utc=created)
    _write_progress(job_dir, phase="queued", percent=0, message="ジョブ要求を受理しました")

    records: list[InputRecord] = []
    started: str | None = None
    try:
        _write_status(job_dir, state="validating", terminal=False, created_at_utc=created)
        _write_progress(job_dir, phase="validating_inputs", percent=10, message="入力境界と上限を検証しています")
        inputs, records = validate_inputs(request, input_root)
        family_hint_manifest, family_hint_manifest_sha256 = stage_family_hint_manifest(
            request,
            input_root,
            inputs,
            job_dir,
        )
        total_files = sum(item.file_count for item in records)
        total_bytes = sum(item.total_bytes for item in records)
        argv = build_analyzer_argv(
            request,
            inputs,
            analysis_output,
            family_hint_manifest=family_hint_manifest,
        )
        started = utc_now()
        _write_status(
            job_dir,
            state="running",
            terminal=False,
            created_at_utc=created,
            started_at_utc=started,
        )
        _write_progress(
            job_dir,
            phase="static_analysis",
            percent=30,
            message="オフライン静的解析を実行しています",
            total_files=total_files,
            total_bytes=total_bytes,
        )
        process_kwargs = {
            "cwd": REPOSITORY_ROOT,
            "env": build_sanitized_environment(),
            "shell": False,
            "check": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "timeout": timeout_seconds,
        }
        if run_process is None:
            completed = _run_process_with_bounded_output(
                argv,
                monitored_output=analysis_output,
                **process_kwargs,
            )
        else:
            completed = run_process(argv, **process_kwargs)
        stdout, bounded_stdout_truncated = _bounded_log(completed.stdout)
        stderr, bounded_stderr_truncated = _bounded_log(completed.stderr)
        stdout_truncated = bool(getattr(completed, "stdout_truncated", False)) or bounded_stdout_truncated
        stderr_truncated = bool(getattr(completed, "stderr_truncated", False)) or bounded_stderr_truncated
        _atomic_bytes(job_dir / "stdout.log", stdout)
        _atomic_bytes(job_dir / "stderr.log", stderr)
        _write_progress(job_dir, phase="validating_results", percent=90, message="解析結果の安全契約を検証しています")
        output_tree = validate_analysis_output_tree(analysis_output)
        if completed.returncode not in {0, 20}:
            _write_failure(
                job_dir,
                request,
                created_at_utc=created,
                started_at_utc=started,
                code="analyzer_exit_nonzero",
                message="analyze_sample.pyが受理対象外の終了codeを返しました",
                process_exit_code=completed.returncode,
                inputs=records,
            )
            return 1
        _, counts = _validated_summary(
            analysis_output / "summary.json",
            expected_input_files=total_files,
        )
        partial = completed.returncode == 20
        state = "completed_partial" if partial else "completed"
        finished = utc_now()
        atomic_json(
            job_dir / "result.json",
            {
                "schema_version": SCHEMA_VERSION,
                "job_id": request.job_id,
                "request_sha256": _request_digest(request),
                "accepted": True,
                "analysis_state": "partial" if partial else "complete",
                "inputs": [item.public() for item in records],
                "family_hint_manifest": request.family_hint_manifest,
                "counts": counts,
                "artifacts": {
                    "analysis_summary": "analysis/summary.json",
                    "family_hint_manifest": (
                        "contract-inputs/family-hint-manifest.json" if family_hint_manifest is not None else None
                    ),
                    "family_hint_manifest_sha256": family_hint_manifest_sha256,
                    "stdout": "stdout.log",
                    "stderr": "stderr.log",
                    "stdout_truncated": stdout_truncated,
                    "stderr_truncated": stderr_truncated,
                    "analysis_output": output_tree,
                },
                "process": {
                    "exit_code": completed.returncode,
                    "shell": False,
                    "script": "analysis-framework/common/analyze_sample.py",
                    "timeout_seconds": timeout_seconds,
                },
                "safety": {
                    "network_or_live_options_allowed": False,
                    "sample_execution_allowed": False,
                    "summary_safety_contract_verified": True,
                    "executed_sample": False,
                    "network_contacted": False,
                    "ai_used": False,
                },
                "finished_at_utc": finished,
            },
        )
        _write_progress(
            job_dir,
            phase=state,
            percent=100,
            message="静的解析が完了しました" if not partial else "静的解析は追加解析待ちを含んで完了しました",
            completed_files=counts["analyzed"],
            total_files=total_files,
        )
        _write_status(
            job_dir,
            state=state,
            terminal=True,
            created_at_utc=created,
            started_at_utc=started,
            finished_at_utc=finished,
        )
        return 20 if partial else 0
    except subprocess.TimeoutExpired as exc:
        stdout, _ = _bounded_log(exc.output)
        stderr, _ = _bounded_log(exc.stderr)
        _atomic_bytes(job_dir / "stdout.log", stdout)
        _atomic_bytes(job_dir / "stderr.log", stderr)
        _write_failure(
            job_dir,
            request,
            created_at_utc=created,
            started_at_utc=started,
            code="analyzer_timeout",
            message="静的解析が設定された時間上限へ達しました",
            state="timed_out",
            inputs=records,
        )
        return 124
    except JobContractError as exc:
        _write_failure(
            job_dir,
            request,
            created_at_utc=created,
            started_at_utc=started,
            code=exc.code,
            message=str(exc),
            inputs=records,
        )
        return 2
    except Exception as exc:  # pragma: no cover - 最終防御境界
        _write_failure(
            job_dir,
            request,
            created_at_utc=created,
            started_at_utc=started,
            code="internal_runner_error",
            message=f"runner内部error: {type(exc).__name__}",
            inputs=records,
        )
        return 1


def validate_job(request: JobRequest, *, input_root: Path, jobs_root: Path) -> dict[str, Any]:
    """file書込みやsubprocess起動なしでジョブ計画を検証する。"""

    input_root, jobs_root = validate_roots(input_root, jobs_root, create_jobs_root=False)
    inputs, records = validate_inputs(request, input_root)
    family_hint_manifest = validate_family_hint_manifest(request, input_root, inputs)
    return {
        "schema_version": SCHEMA_VERSION,
        "job_id": request.job_id,
        "valid": True,
        "request_sha256": _request_digest(request),
        "inputs": [item.public() for item in records],
        "family_hint_manifest": request.family_hint_manifest,
        "family_hint_manifest_validated": family_hint_manifest is not None,
        "resolved_input_count": len(inputs),
        "jobs_root_exists": jobs_root.exists(),
        "network_or_live_options_allowed": False,
        "sample_execution_allowed": False,
        "ai_used": False,
    }


def read_job_snapshot(jobs_root: Path, job_id: str) -> dict[str, Any]:
    """atomic JSONだけを読み、WebUI／API向けsnapshotを返す。"""

    if not JOB_ID_RE.fullmatch(job_id):
        raise JobContractError("invalid_job_id", "不正なjob_idです")
    root = _absolute_path(jobs_root)
    _ensure_no_reparse(
        root,
        code="jobs_root_reparse_forbidden",
        message="jobs-rootにreparse pointを使用できません",
    )
    if not root.is_dir():
        raise JobContractError("jobs_root_invalid", "jobs-rootがありません")
    job_dir = root / job_id
    _ensure_no_reparse(
        job_dir,
        code="job_reparse_forbidden",
        message="job pathにreparse pointを使用できません",
    )
    if not job_dir.is_dir():
        raise JobContractError("job_not_found", "指定したjob_idがありません")
    snapshot: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "job_id": job_id}
    for name, limit in (
        ("status.json", MAX_REQUEST_BYTES),
        ("progress.json", MAX_REQUEST_BYTES),
        ("result.json", MAX_SUMMARY_BYTES),
    ):
        path = job_dir / name
        if path.exists():
            snapshot[name.removesuffix(".json")] = load_json_object_strict(path, max_bytes=limit)
    if "status" not in snapshot or "progress" not in snapshot:
        raise JobContractError("job_state_incomplete", "status.jsonまたはprogress.jsonがありません")
    return snapshot


def _timeout_type(value: str) -> int:
    try:
        parsed = int(value)
        return _bounded_integer(parsed, name="timeout_seconds", maximum=MAX_TIMEOUT_SECONDS)
    except JobContractError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout-secondsは整数で指定してください") from exc


def build_parser() -> argparse.ArgumentParser:
    """ローカルjob runnerのCLI parserを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="要求、入力、出力境界だけを検証します")
    validate.add_argument("--request", required=True, type=Path, help="UTF-8 JSON job request。")
    validate.add_argument("--input-root", required=True, type=Path, help="検体を置く専用root。")
    validate.add_argument("--jobs-root", required=True, type=Path, help="job成果物を置く専用root。")

    run = commands.add_parser("run", help="検証済み要求を同期実行します")
    run.add_argument("--request", required=True, type=Path, help="UTF-8 JSON job request。")
    run.add_argument("--input-root", required=True, type=Path, help="検体を置く専用root。")
    run.add_argument("--jobs-root", required=True, type=Path, help="job成果物を置く専用root。")
    run.add_argument(
        "--timeout-seconds",
        type=_timeout_type,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"静的解析の時間上限。既定{DEFAULT_TIMEOUT_SECONDS}秒、最大{MAX_TIMEOUT_SECONDS}秒。",
    )

    status_parser = commands.add_parser("status", help="atomic JSONから現在状態を読みます")
    status_parser.add_argument("--jobs-root", required=True, type=Path, help="job成果物を置く専用root。")
    status_parser.add_argument("--job-id", required=True, help="取得するjob ID。")
    return parser


def _print_json(value: Any, *, stream: Any = sys.stdout) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True), file=stream)


def main(argv: list[str] | None = None) -> int:
    """CLIを実行し、machine-readableな結果またはerrorを返す。"""

    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            _print_json(read_job_snapshot(args.jobs_root, args.job_id))
            return 0
        request = load_job_request(args.request)
        if args.command == "validate":
            _print_json(validate_job(request, input_root=args.input_root, jobs_root=args.jobs_root))
            return 0
        return run_job(
            request,
            input_root=args.input_root,
            jobs_root=args.jobs_root,
            timeout_seconds=args.timeout_seconds,
        )
    except JobContractError as exc:
        _print_json({"ok": False, "error": {"code": exc.code, "message": str(exc)}}, stream=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
