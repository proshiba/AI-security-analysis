#!/usr/bin/env python3
"""識別から公開・保管までを固定stageで安全に自動化する解析lifecycle runner。"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager, redirect_stdout
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import analysis_job_runner
import archive_analysis_datastore
import batch_error_contract
import build_terminal_payload_gap_inventory
import c2_analysis_contract
import publish_one_shot_collection
import refresh_case_inventory
import remediation_registry
import terminal_payload_acquisition
import validate_function_analysis

SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 1024 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_ATTEMPTS = 5
MAX_PUBLIC_BLOCKERS = 256
MAX_PUBLIC_CASES = 256
MAX_REMEDIATION_ACTIONS = 256
WORKFLOW_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
COLLECTION_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BLOCKER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}$")
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
STAGE_STATUSES = frozenset({"pending", "running", "succeeded", "blocked", "failed", "skipped"})
WORKFLOW_STATUSES = frozenset({"pending", "partial", "complete", "failed"})
STAGE_RECORD_KEYS = frozenset(
    {
        "status",
        "enabled",
        "dependencies",
        "attempts",
        "fingerprint",
        "started_at_utc",
        "finished_at_utc",
        "blockers",
        "result",
    }
)

TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "workflow_id",
        "job",
        "publication",
        "maintenance",
        "private_archive",
    }
)
PUBLICATION_KEYS = frozenset(
    {
        "enabled",
        "manifest",
        "collection_id",
        "expected_contract_sha256",
        "allow_partial_staging",
    }
)
MAINTENANCE_KEYS = frozenset({"refresh_repository"})
ARCHIVE_KEYS = frozenset({"enabled", "target", "include"})
ARCHIVE_INCLUDE_VALUES = frozenset({"inputs", "job_output"})
STAGE_ORDER = (
    "preflight",
    "static_analysis",
    "publication",
    "function_validation",
    "completion_gate",
    "derived_refresh",
    "private_archive",
)
STAGE_DEPENDENCIES: Mapping[str, tuple[str, ...]] = {
    "preflight": (),
    "static_analysis": ("preflight",),
    "publication": ("static_analysis",),
    "function_validation": ("publication",),
    "completion_gate": ("static_analysis",),
    "derived_refresh": ("publication",),
    "private_archive": ("static_analysis",),
}
STAGE_CODE_FILES: Mapping[str, tuple[str, ...]] = {
    "preflight": ("analysis_lifecycle.py", "analysis_job_runner.py"),
    "static_analysis": ("analysis_lifecycle.py", "analysis_job_runner.py", "analyze_sample.py"),
    "publication": ("analysis_lifecycle.py", "publish_one_shot_collection.py"),
    "function_validation": ("analysis_lifecycle.py", "validate_function_analysis.py"),
    "completion_gate": (
        "analysis_lifecycle.py",
        "analysis_job_runner.py",
        "batch_error_contract.py",
        "c2_analysis_contract.py",
        "remediation_registry.py",
        "terminal_payload_acquisition.py",
    ),
    "derived_refresh": (
        "analysis_lifecycle.py",
        "refresh_case_inventory.py",
        "build_terminal_payload_gap_inventory.py",
    ),
    "private_archive": ("analysis_lifecycle.py", "archive_analysis_datastore.py"),
}

# lifecycle／resume planner／terminal台帳の分類語彙は単一registryを正本とする。
_ACTION_SPECS = remediation_registry.ACTION_SPECS
_BLOCKER_ACTION_KEYS = remediation_registry.BLOCKER_ACTION_KEYS
_ORCHESTRATION_GATE_ACTION_KEYS = remediation_registry.ORCHESTRATION_GATE_ACTION_KEYS
_TERMINAL_ACQUISITION_REASONS = remediation_registry.TERMINAL_ACQUISITION_REASONS
_TERMINAL_EDGE_BLOCKER_BY_STATUS: Mapping[str, str] = {
    "artifact_count_limit": "artifact_count_limit",
    "child_incomplete": "child_analysis_incomplete",
    "cycle_excluded": "cycle_detected",
    "depth_limit": "depth_limit",
    "payload_size_limit": "payload_size_limit",
    "shared_sha256_reused_incomplete": "child_analysis_incomplete",
    "total_bytes_limit": "total_bytes_limit",
}


class LifecycleError(RuntimeError):
    """lifecycle契約違反を機械可読code付きで表す。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LifecycleRequest:
    """検証済みの正規化済みworkflow要求。"""

    workflow_id: str
    job: analysis_job_runner.JobRequest
    publication: Mapping[str, Any]
    maintenance: Mapping[str, Any]
    private_archive: Mapping[str, Any]

    def public(self) -> dict[str, Any]:
        """絶対pathや秘密値を含まない正規化済みJSONを返す。"""

        return {
            "schema_version": SCHEMA_VERSION,
            "workflow_id": self.workflow_id,
            "job": self.job.public(),
            "publication": dict(self.publication),
            "maintenance": dict(self.maintenance),
            "private_archive": {
                "enabled": self.private_archive["enabled"],
                "target": self.private_archive["target"],
                "include": list(self.private_archive["include"]),
            },
        }


@dataclass(frozen=True)
class LifecycleContext:
    """固定stageへ渡す検証済みoperator境界。"""

    repository: Path
    input_root: Path
    work_root: Path
    jobs_root: Path
    lifecycle_root: Path
    request: LifecycleRequest
    timeout_seconds: int


@dataclass(frozen=True)
class StageOutcome:
    """1 stageのallowlist済み結果。"""

    status: str
    result: Mapping[str, Any]
    blockers: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Actions:
    """productionでは固定実装だけを使う内部adapter集合。"""

    preflight: Callable[[LifecycleContext, Mapping[str, Any]], StageOutcome]
    static_analysis: Callable[[LifecycleContext, Mapping[str, Any]], StageOutcome]
    publication: Callable[[LifecycleContext, Mapping[str, Any]], StageOutcome]
    function_validation: Callable[[LifecycleContext, Mapping[str, Any]], StageOutcome]
    completion_gate: Callable[[LifecycleContext, Mapping[str, Any]], StageOutcome]
    derived_refresh: Callable[[LifecycleContext, Mapping[str, Any]], StageOutcome]
    private_archive: Callable[[LifecycleContext, Mapping[str, Any]], StageOutcome]


def utc_now() -> str:
    """UTC時刻を固定表現で返す。"""

    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_value(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, *, maximum_bytes: int) -> dict[str, Any]:
    try:
        return analysis_job_runner.load_json_object_strict(path, max_bytes=maximum_bytes)
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise LifecycleError("json_invalid", f"JSONを安全に検証できません: {path.name}") from exc


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    """同一directory内の排他temporary fileからJSONを原子的に置換する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _is_reparse(path: Path) -> bool:
    metadata = path.lstat()
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _reject_existing_reparse_components(path: Path, *, label: str) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not parts:
        raise LifecycleError("path_invalid", f"{label}が空です")
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        if not current.exists():
            break
        if _is_reparse(current):
            raise LifecycleError("reparse_forbidden", f"{label}にreparse pointは使えません")


@contextmanager
def _execution_lock(root: Path):
    """同じworkflowを複数processが同時更新しないようOS lockを保持する。"""

    _reject_existing_reparse_components(root, label="workflow lock")
    if not root.is_dir():
        raise LifecycleError("workflow_missing", "workflow directoryがありません")
    lock_path = root / "execution.lock"
    if lock_path.exists() and _is_reparse(lock_path):
        raise LifecycleError("workflow_lock_invalid", "workflow lockにreparse pointは使用できません")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise LifecycleError("workflow_lock_invalid", "workflow lockを安全に開けません") from exc
    acquired = False
    try:
        information = os.fstat(descriptor)
        if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
            raise LifecycleError("workflow_lock_invalid", "workflow lockは単一linkの通常fileに限定します")
        if information.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (ImportError, OSError) as exc:
            raise LifecycleError("workflow_locked", "同じworkflowを別processが更新中です") from exc
        acquired = True
        yield
    finally:
        if acquired:
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
        os.close(descriptor)


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _normalize_relative_path(value: Any, *, label: str, suffix: str | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise LifecycleError("relative_path_invalid", f"{label}は1..512文字で指定してください")
    if "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise LifecycleError("relative_path_invalid", f"{label}に安全でない文字があります")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} or ":" in part for part in pure.parts):
        raise LifecycleError("relative_path_invalid", f"{label}は正規化済み相対pathで指定してください")
    normalized = pure.as_posix()
    if suffix is not None and not normalized.casefold().endswith(suffix.casefold()):
        raise LifecycleError("relative_path_invalid", f"{label}は{suffix} fileで指定してください")
    return normalized


def _exact_keys(value: Any, expected: frozenset[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise LifecycleError("request_schema_invalid", f"{label}のkey集合が固定schemaと一致しません")
    return value


def _boolean(value: Any, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise LifecycleError("request_schema_invalid", f"{label}はbooleanで指定してください")
    return value


def validate_request_object(value: Mapping[str, Any]) -> LifecycleRequest:
    """任意実行fieldを持たない固定schemaとしてworkflow要求を検証する。"""

    raw = _exact_keys(dict(value), TOP_LEVEL_KEYS, label="workflow request")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleError("schema_version_unsupported", "schema_versionは1だけを許可します")
    workflow_id = raw.get("workflow_id")
    if not isinstance(workflow_id, str) or WORKFLOW_ID_RE.fullmatch(workflow_id) is None:
        raise LifecycleError("workflow_id_invalid", "workflow_idの形式が不正です")
    try:
        job = analysis_job_runner.validate_request_object(raw.get("job"))
    except (analysis_job_runner.JobContractError, TypeError) as exc:
        code = getattr(exc, "code", "job_request_invalid")
        raise LifecycleError(str(code), "job requestが固定静的解析契約に適合しません") from exc

    publication_raw = _exact_keys(raw.get("publication"), PUBLICATION_KEYS, label="publication")
    publication_enabled = _boolean(publication_raw.get("enabled"), label="publication.enabled")
    allow_partial = _boolean(
        publication_raw.get("allow_partial_staging"),
        label="publication.allow_partial_staging",
    )
    manifest = publication_raw.get("manifest")
    collection_id = publication_raw.get("collection_id")
    expected_contract = publication_raw.get("expected_contract_sha256")
    if publication_enabled:
        manifest = _normalize_relative_path(manifest, label="publication.manifest", suffix=".json")
        if not isinstance(collection_id, str) or COLLECTION_ID_RE.fullmatch(collection_id) is None:
            raise LifecycleError("collection_id_invalid", "publication.collection_idの形式が不正です")
        if expected_contract is not None and (
            not isinstance(expected_contract, str) or SHA256_RE.fullmatch(expected_contract) is None
        ):
            raise LifecycleError("contract_pin_invalid", "analysis contract pinは小文字SHA-256で指定してください")
    elif any(value is not None for value in (manifest, collection_id, expected_contract)) or allow_partial:
        raise LifecycleError("publication_disabled_fields", "publication無効時は関連fieldをnull／falseにしてください")

    maintenance_raw = _exact_keys(raw.get("maintenance"), MAINTENANCE_KEYS, label="maintenance")
    refresh_repository = _boolean(
        maintenance_raw.get("refresh_repository"),
        label="maintenance.refresh_repository",
    )
    if refresh_repository and not publication_enabled:
        raise LifecycleError("refresh_without_publication", "repository更新はpublication有効時だけ指定できます")

    archive_raw = _exact_keys(raw.get("private_archive"), ARCHIVE_KEYS, label="private_archive")
    archive_enabled = _boolean(archive_raw.get("enabled"), label="private_archive.enabled")
    archive_target = archive_raw.get("target")
    archive_include = archive_raw.get("include")
    if not isinstance(archive_include, list) or any(not isinstance(item, str) for item in archive_include):
        raise LifecycleError("archive_include_invalid", "private_archive.includeは文字列arrayで指定してください")
    if len(archive_include) != len(set(archive_include)):
        raise LifecycleError("archive_include_invalid", "private_archive.includeに重複があります")
    if set(archive_include) - ARCHIVE_INCLUDE_VALUES:
        raise LifecycleError("archive_include_invalid", "private_archive.includeに未許可のsource種別があります")
    if archive_enabled:
        try:
            archive_target = archive_analysis_datastore.validate_target(archive_target)
        except (archive_analysis_datastore.DatastoreError, TypeError) as exc:
            raise LifecycleError("archive_target_invalid", "private archive targetの形式が不正です") from exc
        if not archive_include:
            raise LifecycleError("archive_include_invalid", "private archive有効時はincludeが必要です")
    elif archive_target is not None or archive_include:
        raise LifecycleError("archive_disabled_fields", "private archive無効時はtargetをnull、includeを空にしてください")

    return LifecycleRequest(
        workflow_id=workflow_id,
        job=job,
        publication={
            "enabled": publication_enabled,
            "manifest": manifest,
            "collection_id": collection_id,
            "expected_contract_sha256": expected_contract,
            "allow_partial_staging": allow_partial,
        },
        maintenance={"refresh_repository": refresh_repository},
        private_archive={
            "enabled": archive_enabled,
            "target": archive_target,
            "include": tuple(archive_include),
        },
    )


def load_request(path: Path) -> LifecycleRequest:
    """UTF-8 strict JSONから検証済みworkflow要求を読み込む。"""

    path = Path(os.path.abspath(os.fspath(path)))
    _reject_existing_reparse_components(path, label="lifecycle request")
    if not path.is_file() or _is_reparse(path):
        raise LifecycleError("request_file_invalid", "lifecycle requestは通常fileで指定してください")
    return validate_request_object(_load_json(path, maximum_bytes=MAX_REQUEST_BYTES))


def request_json_schema() -> dict[str, Any]:
    """WebUIやoperator toolが共有できる厳格JSON Schemaを返す。"""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Static malware analysis lifecycle request",
        "type": "object",
        "additionalProperties": False,
        "required": sorted(TOP_LEVEL_KEYS),
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "workflow_id": {"type": "string", "pattern": WORKFLOW_ID_RE.pattern},
            "job": analysis_job_runner.job_request_json_schema(),
            "publication": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(PUBLICATION_KEYS),
                "properties": {
                    "enabled": {"type": "boolean"},
                    "manifest": {"type": ["string", "null"]},
                    "collection_id": {"type": ["string", "null"]},
                    "expected_contract_sha256": {
                        "type": ["string", "null"],
                        "pattern": SHA256_RE.pattern,
                    },
                    "allow_partial_staging": {"type": "boolean"},
                },
            },
            "maintenance": {
                "type": "object",
                "additionalProperties": False,
                "required": ["refresh_repository"],
                "properties": {"refresh_repository": {"type": "boolean"}},
            },
            "private_archive": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(ARCHIVE_KEYS),
                "properties": {
                    "enabled": {"type": "boolean"},
                    "target": {"type": ["string", "null"]},
                    "include": {
                        "type": "array",
                        "uniqueItems": True,
                        "items": {"enum": sorted(ARCHIVE_INCLUDE_VALUES)},
                    },
                },
            },
        },
    }


def _validate_repository(repository: Path) -> Path:
    root = Path(os.path.abspath(os.fspath(repository)))
    _reject_existing_reparse_components(root, label="repository")
    required = (
        root / "analysis-framework" / "common" / "analyze_sample.py",
        root / "analysis-framework" / "common" / "publish_one_shot_collection.py",
        root / "analysis-results",
        root / "ui",
    )
    if not root.is_dir() or any(not item.exists() for item in required):
        raise LifecycleError("repository_invalid", "AI-security-analysis repository構造を確認できません")
    return root


def _validate_context_roots(
    request: LifecycleRequest,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
    create: bool,
) -> LifecycleContext:
    repository = _validate_repository(repository)
    input_root = Path(os.path.abspath(os.fspath(input_root)))
    work_root = Path(os.path.abspath(os.fspath(work_root)))
    _reject_existing_reparse_components(input_root, label="input-root")
    _reject_existing_reparse_components(work_root, label="work-root")
    if not input_root.is_dir():
        raise LifecycleError("input_root_invalid", "input-rootが通常directoryではありません")
    if _overlaps(repository, input_root) or _overlaps(repository, work_root) or _overlaps(input_root, work_root):
        raise LifecycleError("root_overlap", "repository、input-root、work-rootは互いに分離してください")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
        raise LifecycleError("timeout_invalid", "timeoutは整数で指定してください")
    if not 1 <= timeout_seconds <= analysis_job_runner.MAX_TIMEOUT_SECONDS:
        raise LifecycleError("timeout_invalid", "timeoutが固定上限の範囲外です")
    if create:
        work_root.mkdir(parents=True, exist_ok=True)
    if not work_root.is_dir():
        raise LifecycleError("work_root_invalid", "work-rootがありません")
    jobs_root = work_root / "jobs"
    if create:
        jobs_root.mkdir(exist_ok=True)
    lifecycle_root = work_root / "lifecycles" / request.workflow_id
    if request.publication["enabled"]:
        _resolve_repository_file(repository, request.publication["manifest"])
    return LifecycleContext(
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        jobs_root=jobs_root,
        lifecycle_root=lifecycle_root,
        request=request,
        timeout_seconds=timeout_seconds,
    )


def _resolve_repository_file(repository: Path, relative: str) -> Path:
    normalized = _normalize_relative_path(relative, label="repository file")
    path = repository.joinpath(*PurePosixPath(normalized).parts)
    _reject_existing_reparse_components(path, label="repository file")
    if not path.is_file() or _is_reparse(path):
        raise LifecycleError("repository_file_invalid", "repository内の要求fileがありません")
    return path


def _stage_enabled(request: LifecycleRequest, stage: str) -> bool:
    if stage in {"preflight", "static_analysis", "completion_gate"}:
        return True
    if stage in {"publication", "function_validation"}:
        return bool(request.publication["enabled"])
    if stage == "derived_refresh":
        return bool(request.maintenance["refresh_repository"])
    if stage == "private_archive":
        return bool(request.private_archive["enabled"])
    raise LifecycleError("stage_unknown", "固定stage集合にないstageです")


def build_plan(request: LifecycleRequest) -> dict[str, Any]:
    """副作用なしで固定stage graphと安全境界を返す。"""

    stages = []
    for stage in STAGE_ORDER:
        enabled = _stage_enabled(request, stage)
        stages.append(
            {
                "id": stage,
                "enabled": enabled,
                "dependencies": list(STAGE_DEPENDENCIES[stage]),
                "repository_write": enabled and stage in {"publication", "derived_refresh"},
                "external_network": enabled and stage == "private_archive",
                "sample_execution": False,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "workflow_id": request.workflow_id,
        "request_sha256": _sha256_value(request.public()),
        "stages": stages,
        "safety": {
            "arbitrary_commands_allowed": False,
            "arbitrary_modules_allowed": False,
            "sample_execution_allowed": False,
            "live_c2_allowed": False,
            "analysis_network_allowed": False,
            "datastore_network_enabled": bool(request.private_archive["enabled"]),
        },
    }


def _stage_fingerprint(context: LifecycleContext, stage: str) -> str:
    common = Path(__file__).resolve().parent
    source_hashes = {}
    for name in STAGE_CODE_FILES[stage]:
        path = common / name
        if not path.is_file():
            raise LifecycleError("stage_code_missing", f"固定stage実装がありません: {name}")
        source_hashes[name] = _sha256_file(path)
    anchored_inputs: dict[str, str] = {}
    if stage == "publication" and context.request.publication["enabled"]:
        manifest = _resolve_repository_file(
            context.repository,
            context.request.publication["manifest"],
        )
        anchored_inputs[context.request.publication["manifest"]] = _sha256_file(manifest)
    return _sha256_value(
        {
            "schema_version": SCHEMA_VERSION,
            "stage": stage,
            "request_sha256": _sha256_value(context.request.public()),
            "source_sha256": source_hashes,
            "anchored_input_sha256": anchored_inputs,
        }
    )


def _new_state(context: LifecycleContext) -> dict[str, Any]:
    now = utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "workflow_id": context.request.workflow_id,
        "request_sha256": _sha256_value(context.request.public()),
        "status": "pending",
        "created_at_utc": now,
        "updated_at_utc": now,
        "stage_order": list(STAGE_ORDER),
        "stages": {
            stage: {
                "status": "pending" if _stage_enabled(context.request, stage) else "skipped",
                "enabled": _stage_enabled(context.request, stage),
                "dependencies": list(STAGE_DEPENDENCIES[stage]),
                "attempts": 0,
                "fingerprint": _stage_fingerprint(context, stage),
                "started_at_utc": None,
                "finished_at_utc": now if not _stage_enabled(context.request, stage) else None,
                "blockers": [],
                "result": {"reason": "disabled_by_request"} if not _stage_enabled(context.request, stage) else {},
            }
            for stage in STAGE_ORDER
        },
        "safety": build_plan(context.request)["safety"],
    }


def _write_state(context: LifecycleContext, state: dict[str, Any]) -> None:
    state["updated_at_utc"] = utc_now()
    _atomic_json(context.lifecycle_root / "state.json", state)


def _valid_optional_timestamp(value: Any) -> bool:
    return value is None or (isinstance(value, str) and 1 <= len(value) <= 64)


def _stage_semantics_valid(record: Mapping[str, Any], *, enabled: bool) -> bool:
    """stage statusと試行・時刻・blockerの意味的整合を返す。"""

    status = record.get("status")
    attempts = record.get("attempts")
    started = record.get("started_at_utc")
    finished = record.get("finished_at_utc")
    blockers = record.get("blockers")
    result = record.get("result")
    if not enabled:
        return (
            status == "skipped"
            and attempts == 0
            and started is None
            and isinstance(finished, str)
            and blockers == []
            and result == {"reason": "disabled_by_request"}
        )
    if status == "pending":
        return started is None and finished is None and blockers == [] and result == {}
    if status == "running":
        return attempts >= 1 and isinstance(started, str) and finished is None and blockers == [] and result == {}
    if status == "succeeded":
        return attempts >= 1 and isinstance(started, str) and isinstance(finished, str) and blockers == []
    if status in {"blocked", "failed"}:
        return attempts >= 1 and isinstance(started, str) and isinstance(finished, str) and bool(blockers)
    return (
        status == "skipped"
        and attempts == 0
        and started is None
        and isinstance(finished, str)
        and bool(blockers)
        and result == {"reason": "dependency_not_succeeded"}
    )


def _workflow_semantics_valid(state: Mapping[str, Any]) -> bool:
    """final workflow statusと有効stage集合の整合を返す。"""

    overall = state.get("status")
    enabled_statuses = [record["status"] for record in state["stages"].values() if record["enabled"]]
    if overall == "complete":
        return all(status == "succeeded" for status in enabled_statuses)
    if overall == "failed":
        return "failed" in enabled_statuses and not any(status in {"pending", "running"} for status in enabled_statuses)
    if overall == "partial":
        return (
            "failed" not in enabled_statuses
            and not all(status == "succeeded" for status in enabled_statuses)
            and not any(status in {"pending", "running"} for status in enabled_statuses)
        )
    return True


def _safe_blocker(value: Any) -> str:
    if isinstance(value, str) and BLOCKER_RE.fullmatch(value):
        return value
    return "analysis_blocked"


def _load_state(context: LifecycleContext) -> dict[str, Any]:
    state = _load_json(context.lifecycle_root / "state.json", maximum_bytes=MAX_STATE_BYTES)
    required = {
        "schema_version",
        "workflow_id",
        "request_sha256",
        "status",
        "created_at_utc",
        "updated_at_utc",
        "stage_order",
        "stages",
        "safety",
    }
    if set(state) != required or state.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleError("state_invalid", "lifecycle state schemaが不正です")
    if (
        state.get("workflow_id") != context.request.workflow_id
        or state.get("status") not in WORKFLOW_STATUSES
        or not _valid_optional_timestamp(state.get("created_at_utc"))
        or not _valid_optional_timestamp(state.get("updated_at_utc"))
    ):
        raise LifecycleError("state_invalid", "workflowのstate fieldが不正です")
    request_sha256 = state.get("request_sha256")
    if (
        not isinstance(request_sha256, str)
        or SHA256_RE.fullmatch(request_sha256) is None
        or request_sha256 != _sha256_value(context.request.public())
    ):
        raise LifecycleError("request_changed", "保存済みrequest digestが一致しません")
    if (
        state.get("stage_order") != list(STAGE_ORDER)
        or not isinstance(state.get("stages"), dict)
        or set(state["stages"]) != set(STAGE_ORDER)
        or state.get("safety") != build_plan(context.request)["safety"]
    ):
        raise LifecycleError("state_invalid", "固定stage graphが一致しません")
    for stage in STAGE_ORDER:
        record = state["stages"].get(stage)
        if not isinstance(record, dict) or set(record) != STAGE_RECORD_KEYS:
            raise LifecycleError("state_invalid", f"{stage}のstate schemaが不正です")
        enabled = _stage_enabled(context.request, stage)
        attempts = record.get("attempts")
        blockers = record.get("blockers")
        fingerprint = record.get("fingerprint")
        if (
            record.get("status") not in STAGE_STATUSES
            or record.get("enabled") is not enabled
            or record.get("dependencies") != list(STAGE_DEPENDENCIES[stage])
            or isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 0 <= attempts <= MAX_ATTEMPTS
            or not isinstance(fingerprint, str)
            or SHA256_RE.fullmatch(fingerprint) is None
            or not _valid_optional_timestamp(record.get("started_at_utc"))
            or not _valid_optional_timestamp(record.get("finished_at_utc"))
            or not isinstance(blockers, list)
            or len(blockers) > MAX_PUBLIC_BLOCKERS
            or blockers != sorted(set(blockers))
            or any(not isinstance(item, str) or BLOCKER_RE.fullmatch(item) is None for item in blockers)
            or not isinstance(record.get("result"), dict)
            or (not enabled and record.get("status") != "skipped")
            or (record.get("status") == "succeeded" and blockers)
            or not _stage_semantics_valid(record, enabled=enabled)
        ):
            raise LifecycleError("state_invalid", f"{stage}のstate fieldが不正です")
        if fingerprint != _stage_fingerprint(context, stage):
            raise LifecycleError("stage_contract_changed", f"{stage}の実装契約が保存時から変更されました")
    if not _workflow_semantics_valid(state):
        raise LifecycleError("state_invalid", "workflow statusとstage stateが一致しません")
    return state


def _bounded_blockers(values: Sequence[Any]) -> list[str]:
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        return ["analysis_blocked"]
    return sorted({_safe_blocker(value) for value in values})[:MAX_PUBLIC_BLOCKERS]


def _stage_public_error(stage: str, exc: BaseException) -> tuple[str, str]:
    code = getattr(exc, "code", None)
    if not isinstance(code, str) or BLOCKER_RE.fullmatch(code) is None:
        code = f"{stage}_failed"
    return code, f"{stage}を安全に完了できませんでした ({type(exc).__name__})"


def _production_preflight(context: LifecycleContext, _: Mapping[str, Any]) -> StageOutcome:
    result = analysis_job_runner.validate_job(
        context.request.job,
        input_root=context.input_root,
        jobs_root=context.jobs_root,
    )
    return StageOutcome(
        "succeeded",
        {
            "valid": result["valid"],
            "request_sha256": result["request_sha256"],
            "resolved_input_count": result["resolved_input_count"],
            "family_hint_manifest_validated": result["family_hint_manifest_validated"],
            "network_or_live_options_allowed": False,
            "sample_execution_allowed": False,
            "ai_used": False,
        },
    )


def _revalidated_static_bundle(context: LifecycleContext) -> dict[str, Any] | None:
    """既存jobの意味、exact tree、raw artifact hashを同じ再検証で固定する。"""

    job_dir = context.jobs_root / context.request.job.job_id
    if not job_dir.exists():
        return None
    with tempfile.TemporaryDirectory(
        prefix=f"{context.request.workflow_id}-existing-job-validation-",
        dir=context.work_root,
    ) as temporary:
        validation = analysis_job_runner.revalidate_completed_job(
            context.jobs_root,
            context.request.job,
            temporary_root=Path(temporary),
            expected_timeout_seconds=context.timeout_seconds,
        )
    result = validation.get("result")
    if (
        not isinstance(result, dict)
        or result.get("accepted") is not True
        or result.get("job_id") != context.request.job.job_id
        or result.get("request_sha256") != _sha256_value(context.request.job.public())
    ):
        raise LifecycleError("existing_job_incomplete", "既存jobが検証済み完了状態ではありません")
    safety = result.get("safety")
    if not isinstance(safety, dict) or any(
        safety.get(key) is not False for key in ("executed_sample", "network_contacted", "ai_used")
    ):
        raise LifecycleError("static_safety_invalid", "既存jobの安全flagが不正です")
    return validation


def _verified_static_result(context: LifecycleContext) -> dict[str, Any] | None:
    """後方互換用に再検証済みresultだけを返す。"""

    validation = _revalidated_static_bundle(context)
    if validation is None:
        return None
    result = validation.get("result")
    return result if isinstance(result, dict) else None


def _static_stage_result(
    context: LifecycleContext,
    validation: Mapping[str, Any],
) -> dict[str, Any]:
    """再検証bundleだけからstatic stageのexact保存値を構築する。"""

    result = validation.get("result")
    if not isinstance(result, Mapping):
        raise LifecycleError("static_result_missing", "再検証済み静的解析結果がありません")
    values = {
        "analysis_state": result.get("analysis_state"),
        "counts": result.get("counts"),
        "derived_counts": result.get("derived_counts"),
        "follow_on_analysis": result.get("follow_on_analysis"),
        "result_sha256": validation.get("result_sha256"),
        "summary_sha256": validation.get("summary_sha256"),
        "analysis_tree_sha256": validation.get("analysis_output_sha256"),
        "job_relative_path": f"jobs/{context.request.job.job_id}",
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }
    if any(
        not isinstance(values[key], str) or SHA256_RE.fullmatch(values[key]) is None
        for key in ("result_sha256", "summary_sha256", "analysis_tree_sha256")
    ):
        raise LifecycleError("static_result_invalid", "再検証済みartifact sealが不正です")
    return values


def _resolve_job_artifact(job_dir: Path, value: Any, *, label: str) -> Path:
    relative = _normalize_relative_path(value, label=label)
    path = job_dir.joinpath(*PurePosixPath(relative).parts)
    _reject_existing_reparse_components(path, label=label)
    try:
        information = path.lstat()
    except OSError as exc:
        raise LifecycleError("static_artifact_missing", f"{label}がありません") from exc
    if (
        not path.is_file()
        or _is_reparse(path)
        or not stat.S_ISREG(information.st_mode)
        or information.st_nlink != 1
    ):
        raise LifecycleError("static_artifact_invalid", f"{label}は単一linkの通常fileに限定します")
    return path


def _verify_input_snapshot_manifest(job_dir: Path, manifest_path: Path) -> None:
    manifest = _load_json(manifest_path, maximum_bytes=analysis_job_runner.MAX_INPUT_SNAPSHOT_MANIFEST_BYTES)
    if set(manifest) != {
        "schema_version",
        "archive_mode",
        "input_records",
        "source_inventory",
        "file_count",
        "total_bytes",
        "files",
    }:
        raise LifecycleError("input_snapshot_changed", "入力snapshot manifest schemaが不正です")
    input_records = manifest.get("input_records")
    source_inventory = manifest.get("source_inventory")
    files = manifest.get("files")
    file_count = manifest.get("file_count")
    total_bytes = manifest.get("total_bytes")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("archive_mode") not in {"raw", "malwarebazaar"}
        or not isinstance(input_records, list)
        or not input_records
        or len(input_records) > analysis_job_runner.MAX_REQUEST_INPUTS
        or not isinstance(source_inventory, list)
        or len(source_inventory) != len(input_records)
        or not isinstance(files, list)
        or len(files) > analysis_job_runner.MAX_DISCOVERED_FILES
        or isinstance(file_count, bool)
        or not isinstance(file_count, int)
        or file_count != len(files)
        or isinstance(total_bytes, bool)
        or not isinstance(total_bytes, int)
        or not 0 <= total_bytes <= analysis_job_runner.MAX_TOTAL_INPUT_BYTES
    ):
        raise LifecycleError("input_snapshot_changed", "入力snapshot manifest fieldが不正です")
    selected_inventory: list[dict[str, Any]] = []
    inventory_snapshots: list[dict[str, Any]] = []
    observed_sources: set[str] = set()
    observed_snapshot_paths: set[str] = set()
    source_total_bytes = 0
    source_total_files = 0
    ignored_index = 0
    for input_index, (record, inventory) in enumerate(zip(input_records, source_inventory, strict=True)):
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "relative_path",
                "kind",
                "file_count",
                "analyzer_file_count",
                "total_bytes",
            }
            or not isinstance(inventory, dict)
            or set(inventory) != {"input_index", "relative_path", "files"}
        ):
            raise LifecycleError("input_snapshot_changed", "入力source inventory schemaが不正です")
        record_relative = _normalize_relative_path(record.get("relative_path"), label="input record")
        inventory_files = inventory.get("files")
        if (
            record.get("kind") not in {"file", "directory"}
            or type(record.get("file_count")) is not int
            or not 1 <= record["file_count"] <= analysis_job_runner.MAX_DISCOVERED_FILES
            or type(record.get("analyzer_file_count")) is not int
            or not 0 <= record["analyzer_file_count"] <= record["file_count"]
            or type(record.get("total_bytes")) is not int
            or not 0 <= record["total_bytes"] <= analysis_job_runner.MAX_TOTAL_INPUT_BYTES
            or inventory.get("input_index") != input_index
            or inventory.get("relative_path") != record_relative
            or not isinstance(inventory_files, list)
            or len(inventory_files) != record["file_count"]
        ):
            raise LifecycleError("input_snapshot_changed", "入力source inventory fieldが不正です")
        record_bytes = 0
        record_selected = 0
        record_source_order: list[str] = []
        for source in inventory_files:
            if not isinstance(source, dict) or set(source) != {
                "source_relative_path",
                "snapshot_relative_path",
                "size",
                "sha256",
            }:
                raise LifecycleError("input_snapshot_changed", "入力source identity schemaが不正です")
            source_relative = _normalize_relative_path(
                source.get("source_relative_path"),
                label="input source",
            )
            snapshot_relative = _normalize_relative_path(
                source.get("snapshot_relative_path"),
                label="input inventory snapshot",
            )
            size = source.get("size")
            digest = source.get("sha256")
            folded_source = source_relative.casefold()
            folded_snapshot = snapshot_relative.casefold()
            folded_record = record_relative.casefold()
            owned = (
                record["kind"] == "file"
                and folded_source == folded_record
            ) or (
                record["kind"] == "directory"
                and folded_source.startswith(f"{folded_record}/")
            )
            selected = (
                manifest["archive_mode"] != "malwarebazaar"
                or PurePosixPath(source_relative).suffix.casefold() == ".zip"
            )
            snapshot_parts = PurePosixPath(snapshot_relative).parts
            if selected:
                snapshot_path_valid = (
                    len(snapshot_parts) == 4
                    and snapshot_parts[:2] == ("contract-inputs", "samples")
                    and snapshot_parts[2].isascii()
                    and snapshot_parts[2].isdigit()
                    and len(snapshot_parts[2]) == 6
                )
            else:
                expected_ignored = (
                    f"contract-inputs/inventory/{ignored_index:06d}/"
                    f"{PurePosixPath(source_relative).name}"
                )
                snapshot_path_valid = snapshot_relative == expected_ignored
            if (
                not owned
                or folded_source in observed_sources
                or folded_snapshot in observed_snapshot_paths
                or not snapshot_path_valid
                or PurePosixPath(snapshot_relative).name
                != PurePosixPath(source_relative).name
                or isinstance(size, bool)
                or not isinstance(size, int)
                or not 0 <= size <= analysis_job_runner.MAX_FILE_SIZE
                or not isinstance(digest, str)
                or SHA256_RE.fullmatch(digest) is None
            ):
                raise LifecycleError("input_snapshot_changed", "入力source identity fieldが不正です")
            observed_sources.add(folded_source)
            observed_snapshot_paths.add(folded_snapshot)
            record_source_order.append(source_relative)
            record_bytes += size
            source_total_bytes += size
            source_total_files += 1
            inventory_snapshots.append(
                {
                    "source_relative_path": source_relative,
                    "snapshot_relative_path": snapshot_relative,
                    "size": size,
                    "sha256": digest,
                    "selected": selected,
                }
            )
            if selected:
                record_selected += 1
                selected_inventory.append(
                    {
                        "source_relative_path": source_relative,
                        "snapshot_relative_path": snapshot_relative,
                        "size": size,
                        "sha256": digest,
                    }
                )
            else:
                ignored_index += 1
        if record_source_order != sorted(record_source_order, key=str.casefold):
            raise LifecycleError(
                "input_snapshot_changed",
                "入力source inventoryがcanonical順ではありません",
            )
        if record_bytes != record["total_bytes"] or record_selected != record["analyzer_file_count"]:
            raise LifecycleError(
                "input_snapshot_changed",
                "入力source inventoryとrequest単位集計が一致しません",
            )
    selected_inventory.sort(key=lambda item: item["source_relative_path"].casefold())
    if (
        source_total_files > analysis_job_runner.MAX_DISCOVERED_FILES
        or source_total_bytes > analysis_job_runner.MAX_TOTAL_INPUT_BYTES
        or len(selected_inventory) != file_count
    ):
        raise LifecycleError("input_snapshot_changed", "入力source inventory全体集計が不正です")
    samples_root = job_dir / "contract-inputs" / "samples"
    inventory_root = job_dir / "contract-inputs" / "inventory"
    _reject_existing_reparse_components(samples_root, label="input snapshot root")
    _reject_existing_reparse_components(inventory_root, label="input inventory snapshot root")
    if (
        not samples_root.is_dir()
        or _is_reparse(samples_root)
        or not inventory_root.is_dir()
        or _is_reparse(inventory_root)
    ):
        raise LifecycleError("input_snapshot_changed", "入力snapshot rootが不正です")
    expected_entries_by_root: dict[Path, set[str]] = {
        samples_root: set(),
        inventory_root: set(),
    }
    for inventory_snapshot in inventory_snapshots:
        snapshot_relative = inventory_snapshot["snapshot_relative_path"]
        path = _resolve_job_artifact(job_dir, snapshot_relative, label="input inventory snapshot")
        size = inventory_snapshot["size"]
        digest = inventory_snapshot["sha256"]
        information = path.stat()
        if information.st_size != size or _sha256_file(path) != digest:
            raise LifecycleError(
                "input_snapshot_changed",
                "入力inventory snapshotのsizeまたはSHA-256が変化しました",
            )
        root = samples_root if inventory_snapshot["selected"] else inventory_root
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise LifecycleError(
                "input_snapshot_changed",
                "入力inventory snapshot pathが契約外です",
            ) from exc
        expected_entries = expected_entries_by_root[root]
        expected_entries.add(relative.as_posix())
        expected_entries.update(parent.as_posix() for parent in relative.parents if parent != Path("."))
    observed_bytes = 0
    for index, item in enumerate(files):
        if not isinstance(item, dict) or set(item) != {
            "index",
            "source_relative_path",
            "snapshot_relative_path",
            "source_name",
            "size",
            "sha256",
        }:
            raise LifecycleError("input_snapshot_changed", "入力snapshot record schemaが不正です")
        size = item.get("size")
        digest = item.get("sha256")
        snapshot_relative = _normalize_relative_path(
            item.get("snapshot_relative_path"),
            label="input snapshot path",
        )
        source_relative = _normalize_relative_path(item.get("source_relative_path"), label="input source path")
        expected_source = selected_inventory[index]
        pure = PurePosixPath(snapshot_relative)
        if (
            item.get("index") != index
            or len(pure.parts) < 4
            or pure.parts[:2] != ("contract-inputs", "samples")
            or item.get("source_name") != pure.name
            or source_relative != expected_source["source_relative_path"]
            or snapshot_relative != expected_source["snapshot_relative_path"]
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= analysis_job_runner.MAX_TOTAL_INPUT_BYTES
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or size != expected_source["size"]
            or digest != expected_source["sha256"]
        ):
            raise LifecycleError("input_snapshot_changed", "入力snapshot record fieldが不正です")
        path = _resolve_job_artifact(job_dir, snapshot_relative, label="input snapshot")
        information = path.stat()
        if information.st_size != size or _sha256_file(path) != digest:
            raise LifecycleError("input_snapshot_changed", "入力snapshotのsizeまたはSHA-256が変化しました")
        relative = path.relative_to(samples_root)
        expected_entries = expected_entries_by_root[samples_root]
        expected_entries.add(relative.as_posix())
        expected_entries.update(parent.as_posix() for parent in relative.parents if parent != Path("."))
        observed_bytes += size
    if observed_bytes != total_bytes:
        raise LifecycleError("input_snapshot_changed", "入力snapshot合計sizeが一致しません")
    for root, expected_entries in expected_entries_by_root.items():
        actual_entries: set[str] = set()
        try:
            for count, path in enumerate(root.rglob("*"), start=1):
                if count > analysis_job_runner.MAX_TREE_ENTRIES:
                    raise LifecycleError("input_snapshot_changed", "入力snapshot entry上限を超えています")
                information = path.lstat()
                if _is_reparse(path):
                    raise LifecycleError("input_snapshot_changed", "入力snapshotにreparse pointがあります")
                if path.is_file() and (not stat.S_ISREG(information.st_mode) or information.st_nlink != 1):
                    raise LifecycleError("input_snapshot_changed", "入力snapshotに不正なfileがあります")
                if not path.is_dir() and not path.is_file():
                    raise LifecycleError("input_snapshot_changed", "入力snapshotに通常file以外があります")
                actual_entries.add(path.relative_to(root).as_posix())
        except OSError as exc:
            raise LifecycleError("input_snapshot_changed", "入力snapshot treeを再列挙できません") from exc
        if actual_entries != expected_entries:
            raise LifecycleError("input_snapshot_changed", "入力snapshot treeのentry集合が変化しました")


def _analysis_tree_sha256(path: Path) -> str:
    """解析treeの全通常file内容と既存quota集計を決定的にsealする。"""

    try:
        manifest = analysis_job_runner.analysis_output_content_manifest(path)
    except analysis_job_runner.JobContractError as exc:
        raise LifecycleError(
            "static_output_tree_changed",
            "解析treeをexact content manifestへ固定できません",
        ) from exc
    return analysis_job_runner.analysis_output_content_sha256(manifest)


def _static_artifact_errors(context: LifecycleContext, record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        validation = _revalidated_static_bundle(context)
        if validation is None:
            return ["static_result_missing"]
        result = validation["result"]
        job_dir = context.jobs_root / context.request.job.job_id
        result_path = job_dir / "result.json"
        summary_path = job_dir / "analysis" / "summary.json"
        stored = record.get("result")
        if not isinstance(stored, Mapping):
            return ["static_state_invalid"]
        expected_stage_result = _static_stage_result(context, validation)
        if dict(stored) != expected_stage_result:
            errors.append("static_state_mismatch")
        if stored.get("result_sha256") != _sha256_file(result_path):
            errors.append("static_result_hash_mismatch")
        if not summary_path.is_file() or stored.get("summary_sha256") != _sha256_file(summary_path):
            errors.append("static_summary_hash_mismatch")
        if stored.get("analysis_tree_sha256") != _analysis_tree_sha256(job_dir / "analysis"):
            errors.append("static_output_content_changed")
        artifacts = result.get("artifacts")
        if not isinstance(artifacts, dict):
            errors.append("static_artifact_manifest_invalid")
            return sorted(set(errors))
        for path_key, digest_key in (
            ("analysis_contract_bundle", "analysis_contract_bundle_sha256"),
            ("input_snapshot_manifest", "input_snapshot_manifest_sha256"),
        ):
            if artifacts.get(path_key) is None or artifacts.get(digest_key) is None:
                errors.append(f"{path_key}_missing")
        tree = analysis_job_runner.validate_analysis_output_tree(job_dir / "analysis")
        if artifacts.get("analysis_output") != tree:
            errors.append("static_output_tree_changed")
        pinned = (
            ("analysis_contract_bundle", "analysis_contract_bundle_sha256", "analysis_contract_bundle_changed"),
            ("input_snapshot_manifest", "input_snapshot_manifest_sha256", "input_snapshot_manifest_changed"),
            ("family_hint_manifest", "family_hint_manifest_sha256", "family_hint_manifest_changed"),
            (
                "trusted_static_tools_manifest",
                "trusted_static_tools_manifest_sha256",
                "trusted_static_tools_manifest_changed",
            ),
        )
        resolved: dict[str, Path] = {}
        for path_key, digest_key, error_code in pinned:
            relative = artifacts.get(path_key)
            digest = artifacts.get(digest_key)
            if relative is None and digest is None:
                continue
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                errors.append(error_code)
                continue
            path = _resolve_job_artifact(job_dir, relative, label=path_key)
            resolved[path_key] = path
            if _sha256_file(path) != digest:
                errors.append(error_code)
        snapshot_manifest = resolved.get("input_snapshot_manifest")
        if snapshot_manifest is not None and "input_snapshot_manifest_changed" not in errors:
            _verify_input_snapshot_manifest(job_dir, snapshot_manifest)
    except (LifecycleError, analysis_job_runner.JobContractError, OSError) as exc:
        code = getattr(exc, "code", "static_artifact_verification_failed")
        errors.append(code if isinstance(code, str) and BLOCKER_RE.fullmatch(code) else "static_artifact_verification_failed")
    return sorted(set(errors))


def _production_static(context: LifecycleContext, _: Mapping[str, Any]) -> StageOutcome:
    validation = _revalidated_static_bundle(context)
    if validation is None:
        exit_code = analysis_job_runner.run_job(
            context.request.job,
            input_root=context.input_root,
            jobs_root=context.jobs_root,
            timeout_seconds=context.timeout_seconds,
        )
        if exit_code not in {0, 20}:
            raise LifecycleError("static_analysis_failed", "静的解析jobが受理可能な終了状態ではありません")
        validation = _revalidated_static_bundle(context)
    if validation is None:
        raise LifecycleError("static_result_missing", "静的解析結果がありません")
    return StageOutcome(
        "succeeded",
        _static_stage_result(context, validation),
    )


def _analysis_summary(context: LifecycleContext) -> dict[str, Any]:
    return _load_json(
        context.jobs_root / context.request.job.job_id / "analysis" / "summary.json",
        maximum_bytes=analysis_job_runner.MAX_SUMMARY_BYTES,
    )


def _revalidated_current_static_stage(
    context: LifecycleContext,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    """保存済みstatic stageを現在の全成果物再検証へexactに再結合する。"""

    stages = state.get("stages")
    static_record = stages.get("static_analysis") if isinstance(stages, Mapping) else None
    stored = static_record.get("result") if isinstance(static_record, Mapping) else None
    if not isinstance(stored, Mapping):
        raise LifecycleError("static_state_invalid", "保存済みstatic stage状態が不正です")
    validation = _revalidated_static_bundle(context)
    if validation is None:
        raise LifecycleError("static_result_missing", "再検証できる静的解析結果がありません")
    if dict(stored) != _static_stage_result(context, validation):
        raise LifecycleError(
            "static_state_mismatch",
            "保存済みstatic stageと現在の再検証済み成果物が一致しません",
        )
    return validation


def _production_publication(context: LifecycleContext, state: Mapping[str, Any]) -> StageOutcome:
    static = state["stages"]["static_analysis"]["result"]
    if static.get("analysis_state") == "partial" and not context.request.publication["allow_partial_staging"]:
        blocker = "publication_requires_complete_or_partial_staging_opt_in"
        return StageOutcome("blocked", {"published": 0}, (blocker,))
    validation = _revalidated_current_static_stage(context, state)
    summary = validation.get("summary")
    if not isinstance(summary, dict):
        raise LifecycleError("static_result_invalid", "再検証済みsummaryがありません")
    contract = summary.get("analysis_contract")
    observed_contract = contract.get("sha256") if isinstance(contract, dict) else None
    if not isinstance(observed_contract, str) or SHA256_RE.fullmatch(observed_contract) is None:
        raise LifecycleError("analysis_contract_missing", "one-shot summaryにanalysis contractがありません")
    requested_contract = context.request.publication["expected_contract_sha256"]
    if requested_contract is not None and requested_contract != observed_contract:
        raise LifecycleError("analysis_contract_mismatch", "request pinとone-shot contractが一致しません")
    source = context.jobs_root / context.request.job.job_id / "analysis"
    with tempfile.TemporaryDirectory(
        prefix=f"{context.request.workflow_id}-publication-snapshot-",
        dir=context.work_root,
    ) as temporary:
        snapshot = Path(temporary) / "analysis"
        try:
            shutil.copytree(source, snapshot, symlinks=True)
        except OSError as exc:
            raise LifecycleError(
                "publication_snapshot_failed",
                "公開用解析snapshotを安全に作成できません",
            ) from exc
        try:
            snapshot_manifest = analysis_job_runner.analysis_output_content_manifest(snapshot)
        except analysis_job_runner.JobContractError as exc:
            raise LifecycleError(
                "publication_snapshot_invalid",
                "公開用解析snapshotのexact contentを検証できません",
            ) from exc
        snapshot_sha256 = analysis_job_runner.analysis_output_content_sha256(snapshot_manifest)
        if snapshot_sha256 != static.get("analysis_tree_sha256"):
            raise LifecycleError(
                "publication_snapshot_mismatch",
                "公開用解析snapshotがstatic stageのsealと一致しません",
            )
        current = _revalidated_current_static_stage(context, state)
        current_summary = current.get("summary")
        if not isinstance(current_summary, dict) or current_summary.get("analysis_contract") != contract:
            raise LifecycleError(
                "static_state_mismatch",
                "公開snapshot作成中にstatic成果物が変更されました",
            )
        try:
            final_snapshot_manifest = analysis_job_runner.analysis_output_content_manifest(snapshot)
        except analysis_job_runner.JobContractError as exc:
            raise LifecycleError(
                "publication_snapshot_invalid",
                "公開用解析snapshotをpublisher呼出直前に再検証できません",
            ) from exc
        if (
            final_snapshot_manifest != snapshot_manifest
            or analysis_job_runner.analysis_output_content_sha256(final_snapshot_manifest)
            != snapshot_sha256
        ):
            raise LifecycleError(
                "publication_snapshot_mismatch",
                "公開用解析snapshotがpublisher呼出前に変更されました",
            )
        result = publish_one_shot_collection.publish(
            context.repository,
            _resolve_repository_file(context.repository, context.request.publication["manifest"]),
            [snapshot],
            context.request.publication["collection_id"],
            allow_function_staging=context.request.publication["allow_partial_staging"],
            expected_contract_sha256=observed_contract,
        )
    collection = Path(result["collection"]).resolve()
    try:
        collection_relative = collection.relative_to(context.repository).as_posix()
    except ValueError as exc:
        raise LifecycleError("publication_path_invalid", "collectionがrepository外を指しています") from exc
    return StageOutcome(
        "succeeded",
        {
            "published": int(result["published"]),
            "publication_stage": result["publication_stage"],
            "analysis_contract_sha256": result["analysis_contract_sha256"],
            "families": result["families"],
            "collection": collection_relative,
        },
    )


def _production_function_validation(context: LifecycleContext, state: Mapping[str, Any]) -> StageOutcome:
    publication = state["stages"]["publication"]["result"]
    relative = _normalize_relative_path(publication.get("collection"), label="published collection")
    collection = context.repository.joinpath(*PurePosixPath(relative).parts)
    result = validate_function_analysis.validate_collection(context.repository, collection)
    failures = [
        {
            "sha256": item.get("sha256"),
            "status": item.get("status"),
            "error_count": len(item.get("errors") or []),
        }
        for item in result["results"]
        if not item.get("valid")
    ][:256]
    public = {
        "collection": result["collection"],
        "cases": result["cases"],
        "valid_cases": result["valid_cases"],
        "invalid_cases": result["invalid_cases"],
        "complete": result["complete"],
        "failures": failures,
    }
    if result["complete"]:
        return StageOutcome("succeeded", public)
    return StageOutcome("blocked", public, ("representative_function_analysis_required",))


def _validated_terminal_acquisition(
    context: LifecycleContext,
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    """runnerが封印した終端frontierをfollow-on graphから再計算する。"""

    reference = summary.get("terminal_payload_acquisition")
    expected_keys = {
        "artifact",
        "sha256",
        "status",
        "frontier_count",
        "selected_count",
        "pending_count",
    }
    if not isinstance(reference, Mapping) or set(reference) != expected_keys:
        raise LifecycleError(
            "terminal_acquisition_invalid",
            "終端payload取得台帳のsummary参照が不正です",
        )
    job_dir = context.jobs_root / context.request.job.job_id
    acquisition_path = _resolve_job_artifact(
        job_dir,
        "analysis/terminal-payload-acquisition.json",
        label="terminal payload acquisition",
    )
    follow_on_path = _resolve_job_artifact(
        job_dir,
        "analysis/follow-on-analysis.json",
        label="follow-on analysis",
    )
    try:
        acquisition_payload, acquisition = analysis_job_runner.load_json_object_snapshot(
            acquisition_path,
            max_bytes=analysis_job_runner.MAX_SUMMARY_BYTES,
        )
        follow_on_payload, follow_on = analysis_job_runner.load_json_object_snapshot(
            follow_on_path,
            max_bytes=analysis_job_runner.MAX_SUMMARY_BYTES,
        )
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise LifecycleError(
            "terminal_acquisition_invalid",
            "終端payload取得台帳またはfollow-on graphを安全に固定できません",
        ) from exc
    follow_on_reference = summary.get("follow_on_analysis")
    follow_on_keys = {
        "artifact",
        "sha256",
        "status",
        "node_count",
        "edge_count",
        "error_count",
    }
    if (
        reference.get("artifact") != "terminal-payload-acquisition.json"
        or reference.get("sha256") != hashlib.sha256(acquisition_payload).hexdigest()
        or not isinstance(follow_on_reference, Mapping)
        or set(follow_on_reference) != follow_on_keys
        or follow_on_reference.get("artifact") != "follow-on-analysis.json"
        or follow_on_reference.get("sha256") != hashlib.sha256(follow_on_payload).hexdigest()
    ):
        raise LifecycleError(
            "terminal_acquisition_invalid",
            "終端payload取得台帳またはfollow-on graphの参照／SHA-256が一致しません",
        )
    root_case_states: dict[str, str] | None = None
    if follow_on.get("status") in terminal_payload_acquisition.OPERATIONAL_STATUSES:
        roots = follow_on.get("roots")
        cases = summary.get("cases")
        if not isinstance(roots, list) or not isinstance(cases, list):
            raise LifecycleError(
                "terminal_acquisition_invalid",
                "終端payload root case一覧が不正です",
            )
        root_set = set(roots)
        root_case_states = {}
        for case in cases:
            if not isinstance(case, Mapping):
                raise LifecycleError(
                    "terminal_acquisition_invalid",
                    "終端payload root case schemaが不正です",
                )
            digest = case.get("sha256")
            case_state = case.get("case_state")
            if digest not in root_set:
                continue
            if (
                not isinstance(digest, str)
                or SHA256_RE.fullmatch(digest) is None
                or digest in root_case_states
                or case_state not in terminal_payload_acquisition.NODE_CASE_STATES
            ):
                raise LifecycleError(
                    "terminal_acquisition_invalid",
                    "終端payload root case fieldが不正です",
                )
            root_case_states[digest] = case_state
        if set(root_case_states) != root_set:
            raise LifecycleError(
                "terminal_acquisition_invalid",
                "終端payload rootsとroot case一覧が一致しません",
            )
    try:
        expected = terminal_payload_acquisition.build_terminal_payload_acquisition(
            follow_on,
            root_case_states=root_case_states,
        )
    except terminal_payload_acquisition.TerminalPayloadAcquisitionError as exc:
        raise LifecycleError(
            "terminal_acquisition_invalid",
            "follow-on graphから終端payload取得台帳を再計算できません",
        ) from exc
    if acquisition != expected:
        raise LifecycleError(
            "terminal_acquisition_invalid",
            "終端payload取得台帳がfollow-on graphと一致しません",
        )
    follow_on_counts = {
        "status": follow_on.get("status"),
        "node_count": len(follow_on.get("nodes") or []),
        "edge_count": len(follow_on.get("edges") or []),
        "error_count": len(follow_on.get("errors") or []),
    }
    if any(follow_on_reference.get(key) != value for key, value in follow_on_counts.items()):
        raise LifecycleError(
            "terminal_acquisition_invalid",
            "follow-on graphの状態または件数がsummaryと一致しません",
        )
    counts = {
        "status": acquisition.get("status"),
        "frontier_count": len(acquisition.get("frontier") or []),
        "selected_count": len(acquisition.get("selected_sha256") or []),
        "pending_count": len(acquisition.get("pending_sha256") or []),
    }
    if any(reference.get(key) != value for key, value in counts.items()):
        raise LifecycleError(
            "terminal_acquisition_invalid",
            "終端payload取得台帳の状態または件数が一致しません",
        )
    if (
        acquisition.get("external_retrieval_attempted") is not False
        or acquisition.get("executed_sample") is not False
        or acquisition.get("network_contacted") is not False
    ):
        raise LifecycleError(
            "terminal_acquisition_invalid",
            "終端payload取得台帳の安全flagが不正です",
        )
    return acquisition


def _terminal_acquisition_blockers(
    acquisition: Mapping[str, Any],
) -> tuple[dict[str, list[str]], list[str]]:
    """終端frontierの理由をcase別blockerとworkflow blockerへ分離する。"""

    by_case: dict[str, set[str]] = {}
    attributed: set[str] = set()
    frontier = acquisition.get("frontier")
    if not isinstance(frontier, list):
        raise LifecycleError("terminal_acquisition_invalid", "終端frontierが配列ではありません")
    for item in frontier:
        if not isinstance(item, Mapping) or item.get("disposition") != "pending_terminal":
            continue
        reason = item.get("reason")
        digest = item.get("sha256")
        parents = item.get("parent_sha256")
        if (
            reason not in _TERMINAL_ACQUISITION_REASONS
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or not isinstance(parents, list)
            or any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in parents)
        ):
            raise LifecycleError("terminal_acquisition_invalid", "終端frontierのfieldが不正です")
        blocker = f"terminal_acquisition:{reason}"
        case_blockers = {blocker}
        edge_statuses = item.get("edge_statuses")
        if isinstance(edge_statuses, list):
            case_blockers.update(
                f"terminal_acquisition:{mapped}"
                for status in edge_statuses
                if isinstance(status, str)
                and (mapped := _TERMINAL_EDGE_BLOCKER_BY_STATUS.get(status)) is not None
            )
        for target in sorted({digest, *parents}):
            by_case.setdefault(target, set()).update(case_blockers)
        attributed.update(value.removeprefix("terminal_acquisition:") for value in case_blockers)
    raw_blockers = acquisition.get("blockers")
    if (
        not isinstance(raw_blockers, list)
        or raw_blockers != sorted(set(raw_blockers))
        or any(value not in _TERMINAL_ACQUISITION_REASONS for value in raw_blockers)
    ):
        raise LifecycleError("terminal_acquisition_invalid", "終端payload blocker集合が不正です")
    workflow = [
        f"terminal_acquisition:{value}"
        for value in raw_blockers
        if value not in attributed
    ]
    return (
        {digest: sorted(values) for digest, values in sorted(by_case.items())},
        workflow,
    )


def _validated_case_c2(
    context: LifecycleContext,
    case_dir: Path,
    digest: str,
    orchestration: Mapping[str, Any],
) -> tuple[str, str, list[str]]:
    """caseのC2契約を厳格検証し、未解決だけを再解析blockerへ変換する。"""

    c2_path = case_dir / "c2-analysis.json"
    _reject_existing_reparse_components(c2_path, label="c2 analysis")
    c2_document = _load_json(
        c2_path,
        maximum_bytes=analysis_job_runner.MAX_SUMMARY_BYTES,
    )
    validation = c2_analysis_contract.validate_contract(
        c2_document,
        digest,
        repository=context.repository,
    )
    if (
        validation.get("daily_ready") is not True
        or isinstance(validation.get("daily_blocking_finding_count"), bool)
        or not isinstance(validation.get("daily_blocking_finding_count"), int)
        or validation["daily_blocking_finding_count"] != 0
    ):
        raise LifecycleError("c2_contract_invalid", "C2解析契約の必須証拠または安全契約が不正です")
    outcome = validation.get("outcome")
    if outcome not in c2_analysis_contract.C2_OUTCOMES:
        raise LifecycleError("c2_contract_invalid", "C2解析結果の状態が不正です")
    quality_gates = orchestration.get("quality_gates")
    network_gate = quality_gates.get("network") if isinstance(quality_gates, Mapping) else None
    if not isinstance(network_gate, Mapping) or type(network_gate.get("required")) is not bool:
        raise LifecycleError("c2_contract_invalid", "orchestrationのnetwork要件を確認できません")
    if network_gate["required"] and outcome == "no_c2_capability_verified":
        raise LifecycleError(
            "c2_contract_invalid",
            "network必須familyとC2機能なし判定が矛盾しています",
        )
    blockers = ["c2_analysis_unresolved"] if outcome == "unresolved" else []
    status = "complete" if validation.get("complete") is True else "deferred"
    return status, str(outcome), blockers


def _validated_batch_errors(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    """非機密の固定schemaだけをcompletion gateへ渡す。"""

    values = summary.get("errors")
    if not isinstance(values, list):
        raise LifecycleError("batch_error_contract_invalid", "batch error一覧がありません")
    validated: list[dict[str, Any]] = []
    for value in values:
        try:
            validated.append(batch_error_contract.validate_record(value))
        except batch_error_contract.BatchErrorContractError as exc:
            raise LifecycleError(
                "batch_error_contract_invalid",
                "batch errorの固定schemaが不正です",
            ) from exc
    return validated


def _case_blockers(
    context: LifecycleContext,
    *,
    summary: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """case別の根拠を保持したまま公開可能blockerを集約する。"""

    summary = summary if summary is not None else _analysis_summary(context)
    analysis_root = context.jobs_root / context.request.job.job_id / "analysis"
    acquisition = _validated_terminal_acquisition(context, summary)
    terminal_by_case, terminal_workflow_blockers = _terminal_acquisition_blockers(acquisition)
    cases: list[dict[str, Any]] = []
    blockers: list[str] = list(terminal_workflow_blockers)
    blockers.extend(
        f"batch_error:{value['error_code']}"
        for value in _validated_batch_errors(summary)
    )
    items: list[Any] = []
    for field in ("cases", "derived_cases"):
        values = summary.get(field)
        if not isinstance(values, list):
            blockers.append("analysis_blocked")
            continue
        items.extend(values)
    for item in items:
        if not isinstance(item, dict):
            blockers.append("analysis_blocked")
            continue
        digest = item.get("sha256")
        status = item.get("case_state")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            blockers.append("analysis_blocked")
            continue
        if status not in {
            "assessment_only_complete",
            "complete",
            "failed",
            "partial",
            "triaged_unknown",
        }:
            status = "invalid"
            blockers.append("analysis_blocked")
        case_dir = analysis_root / "cases" / digest
        report_path = case_dir / "report.json"
        orchestration_path = case_dir / "orchestration.json"
        report_blockers: list[str] = []
        orchestration_blockers: list[str] = []
        c2_blockers: list[str] = []
        c2_status = "invalid"
        c2_outcome = "invalid"
        terminal_blockers = terminal_by_case.get(digest, [])
        if report_path.is_file():
            report = _load_json(report_path, maximum_bytes=analysis_job_runner.MAX_SUMMARY_BYTES)
            state = report.get("case_state")
            if isinstance(state, dict):
                report_blockers = _bounded_blockers(state.get("blockers") or [])
        if status in {"failed", "partial", "triaged_unknown"}:
            report_blockers = _bounded_blockers([*report_blockers, "analysis_partial"])
        if not orchestration_path.is_file():
            raise LifecycleError("static_artifact_missing", "orchestration.jsonがありません")
        orchestration = _load_json(orchestration_path, maximum_bytes=analysis_job_runner.MAX_SUMMARY_BYTES)
        orchestration_blockers = _bounded_blockers(orchestration.get("blockers") or [])
        c2_status, c2_outcome, c2_blockers = _validated_case_c2(
            context,
            case_dir,
            digest,
            orchestration,
        )
        cases.append(
            {
                "sha256": digest,
                "status": status,
                "report_blockers": report_blockers,
                "orchestration_blockers": orchestration_blockers,
                "c2_status": c2_status,
                "c2_outcome": c2_outcome,
                "c2_blockers": c2_blockers,
                "terminal_acquisition_blockers": terminal_blockers,
            }
        )
        blockers.extend(report_blockers)
        blockers.extend(orchestration_blockers)
        blockers.extend(c2_blockers)
        blockers.extend(terminal_blockers)
    return cases, _bounded_blockers(blockers)


def _remediation_action(blocker: str, *, case_sha256: str | None) -> dict[str, Any]:
    """厳格なblocker registryから1件のfail-closed actionを返す。"""

    normalized = _safe_blocker(blocker)
    key = remediation_registry.action_key_for_blocker(normalized)
    if key is None:
        key = "manual"
    action_id, target_phase, executor, automatic, changed, prerequisites = _ACTION_SPECS[key]
    return {
        "case_sha256": case_sha256,
        "blocker_code": normalized,
        "action_id": action_id,
        "target_phase": target_phase,
        "executor": executor,
        "automatic": automatic,
        "requires_changed_evidence": changed,
        "prerequisites": list(prerequisites),
    }


def _remediation_actions(
    cases: Sequence[Mapping[str, Any]],
    workflow_blockers: Sequence[str],
) -> list[dict[str, Any]]:
    """case attributionを失わず、決定論的な次工程を返す。"""

    actions: list[dict[str, Any]] = []
    case_blockers: set[str] = set()
    for case in cases:
        digest = case.get("sha256")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            continue
        for field in (
            "report_blockers",
            "orchestration_blockers",
            "c2_blockers",
            "terminal_acquisition_blockers",
        ):
            values = case.get(field)
            if not isinstance(values, list):
                continue
            for blocker in values:
                normalized = _safe_blocker(blocker)
                case_blockers.add(normalized)
                actions.append(_remediation_action(normalized, case_sha256=digest))
    for blocker in _bounded_blockers(workflow_blockers):
        if blocker not in case_blockers:
            actions.append(_remediation_action(blocker, case_sha256=None))
    unique = {
        (
            action["case_sha256"] or "",
            action["blocker_code"],
            action["action_id"],
        ): action
        for action in actions
    }
    return [unique[key] for key in sorted(unique)][:MAX_REMEDIATION_ACTIONS]


def _next_actions(actions: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted(
        {
            action["action_id"]
            for action in actions
            if isinstance(action.get("action_id"), str)
        }
    )


def _public_remediation_plan(
    cases: Sequence[Mapping[str, Any]],
    workflow_blockers: Sequence[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """公開case上限とaction attributionを同じcase集合へ固定する。"""

    public_cases = [dict(case) for case in cases[:MAX_PUBLIC_CASES]]
    return public_cases, _remediation_actions(public_cases, workflow_blockers)


def _production_completion(context: LifecycleContext, state: Mapping[str, Any]) -> StageOutcome:
    static = state["stages"]["static_analysis"]["result"]
    validation = _revalidated_current_static_stage(context, state)
    expected_tree = validation.get("analysis_output_sha256")
    analysis_root = context.jobs_root / context.request.job.job_id / "analysis"
    if (
        not isinstance(expected_tree, str)
        or SHA256_RE.fullmatch(expected_tree) is None
        or _analysis_tree_sha256(analysis_root) != expected_tree
    ):
        raise LifecycleError(
            "static_output_tree_changed",
            "completion開始時の解析treeがstatic stageのsealと一致しません",
        )
    summary = validation.get("summary")
    if not isinstance(summary, dict):
        raise LifecycleError("static_result_invalid", "再検証済みsummaryがありません")
    if (
        static.get("counts") != summary.get("counts")
        or static.get("derived_counts") != summary.get("derived_counts")
        or static.get("follow_on_analysis") != summary.get("follow_on_analysis")
    ):
        raise LifecycleError(
            "static_state_mismatch",
            "static stageの件数またはfollow-on参照がsummaryと一致しません",
        )
    cases, blockers = _case_blockers(context, summary=summary)
    analysis_errors = _validated_batch_errors(summary)
    if static.get("analysis_state") != "complete" and not blockers:
        blockers.append("analysis_partial")
    for stage in ("publication", "function_validation"):
        record = state["stages"][stage]
        if record["enabled"] and record["status"] in {"blocked", "failed"}:
            blockers.extend(record.get("blockers") or [f"{stage}_incomplete"])
    blockers = _bounded_blockers(blockers)
    public_cases, actions = _public_remediation_plan(cases, blockers)
    if _analysis_tree_sha256(analysis_root) != expected_tree:
        raise LifecycleError(
            "static_output_tree_changed",
            "completion検証中に解析treeが変更されました",
        )
    _revalidated_current_static_stage(context, state)
    result = {
        "complete": not blockers and static.get("analysis_state") == "complete",
        "case_count": len(cases),
        "cases": public_cases,
        "analysis_error_count": len(analysis_errors),
        "analysis_errors": analysis_errors,
        "blockers": blockers,
        "next_actions": _next_actions(actions),
        "remediation_actions": actions,
        "remediation_plan_sha256": _sha256_value({"actions": actions}),
        "same_workflow_resume_allowed": False,
        "executed_sample": False,
        "network_contacted": False,
    }
    if result["complete"]:
        return StageOutcome("succeeded", result)
    return StageOutcome("blocked", result, tuple(blockers))


def _production_refresh(context: LifecycleContext, _: Mapping[str, Any]) -> StageOutcome:
    terminal = build_terminal_payload_gap_inventory.sync_outputs(
        context.repository,
        Path("intelligence/terminal-payload-recovery"),
        write=True,
    )
    refreshed = refresh_case_inventory.refresh(context.repository, write=True, check=False)
    terminal_check = build_terminal_payload_gap_inventory.sync_outputs(
        context.repository,
        Path("intelligence/terminal-payload-recovery"),
        write=False,
    )
    verification = refreshed.get("verification")
    if terminal_check["mismatches"] or not isinstance(verification, dict) or verification.get("check_failed"):
        raise LifecycleError("derived_refresh_verification_failed", "派生成果物の再検証に失敗しました")
    safety = refreshed.get("safety")
    if not isinstance(safety, dict) or any(
        safety.get(key) is not False for key in ("samples_opened", "samples_executed", "network_contacted")
    ):
        raise LifecycleError("derived_refresh_safety_invalid", "派生更新の安全flagが不正です")
    return StageOutcome(
        "succeeded",
        {
            "case_count": refreshed["case_count"],
            "terminal_inventory_updated": terminal["write_performed"],
            "terminal_inventory_mismatches": [],
            "repository_verification_passed": True,
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    )


def _archive_sources(
    context: LifecycleContext,
    state: Mapping[str, Any] | None = None,
) -> list[Path]:
    if state is not None and (errors := _static_artifact_errors(context, state["stages"]["static_analysis"])):
        raise LifecycleError("archive_source_changed", f"archive前の静的成果物検証に失敗しました: {errors[0]}")
    sources: list[Path] = []
    include = set(context.request.private_archive["include"])
    if "inputs" in include:
        snapshots = context.jobs_root / context.request.job.job_id / "contract-inputs" / "samples"
        if not snapshots.is_dir() or _is_reparse(snapshots):
            raise LifecycleError(
                "archive_source_invalid",
                "解析時に検証済みのinput snapshotがありません",
            )
        sources.append(snapshots)
    if "job_output" in include:
        sources.append(context.jobs_root / context.request.job.job_id)
    folded = [str(path.resolve()).casefold() for path in sources]
    if len(folded) != len(set(folded)):
        raise LifecycleError("archive_source_duplicate", "archive sourceが重複しています")
    return sources


def _production_archive(context: LifecycleContext, state: Mapping[str, Any]) -> StageOutcome:
    sources = _archive_sources(context, state)
    report_path = context.lifecycle_root / "private-archive-report.json"
    if report_path.exists():
        report = _load_json(report_path, maximum_bytes=MAX_STATE_BYTES)
    else:
        argv = ["--target", context.request.private_archive["target"]]
        for source in sources:
            argv.extend(("--source", str(source)))
        argv.extend(("--report", str(report_path)))
        with redirect_stdout(io.StringIO()):
            exit_code = archive_analysis_datastore.main(argv)
        if exit_code != 0:
            raise LifecycleError("private_archive_failed", "標準datastore archiverが失敗しました")
        report = _load_json(report_path, maximum_bytes=MAX_STATE_BYTES)
    verification = report.get("s3_verification")
    if (
        report.get("status") != "verified"
        or report.get("target") != context.request.private_archive["target"]
        or report.get("local_source_deleted") is not False
        or not isinstance(verification, dict)
        or verification.get("server_side_encryption") != "AES256"
        or not SHA256_RE.fullmatch(str(report.get("archive_sha256") or ""))
        or not SHA256_RE.fullmatch(str(report.get("manifest_sha256") or ""))
    ):
        raise LifecycleError("private_archive_verification_failed", "S3側のsize／SSE／hash検証が不正です")
    return StageOutcome(
        "succeeded",
        {
            "status": "verified",
            "target": report["target"],
            "object_uri": report["object_uri"],
            "archive_sha256": report["archive_sha256"],
            "manifest_sha256": report["manifest_sha256"],
            "archive_size": report["archive_size"],
            "file_count": report["file_count"],
            "server_side_encryption": verification["server_side_encryption"],
            "local_source_deleted": False,
            "network_contacted": True,
        },
    )


PRODUCTION_ACTIONS = _Actions(
    preflight=_production_preflight,
    static_analysis=_production_static,
    publication=_production_publication,
    function_validation=_production_function_validation,
    completion_gate=_production_completion,
    derived_refresh=_production_refresh,
    private_archive=_production_archive,
)


def _dependencies_succeeded(state: Mapping[str, Any], stage: str) -> bool:
    return all(state["stages"][dependency]["status"] == "succeeded" for dependency in STAGE_DEPENDENCIES[stage])


def _execute(context: LifecycleContext, state: dict[str, Any], actions: _Actions) -> dict[str, Any]:
    for stage in STAGE_ORDER:
        record = state["stages"][stage]
        if not record["enabled"] or record["status"] == "succeeded":
            continue
        if record["status"] == "skipped" and record["result"].get("reason") == "disabled_by_request":
            continue
        if not _dependencies_succeeded(state, stage):
            record.update(
                {
                    "status": "skipped",
                    "finished_at_utc": utc_now(),
                    "blockers": ["dependency_not_succeeded"],
                    "result": {"reason": "dependency_not_succeeded"},
                }
            )
            _write_state(context, state)
            continue
        if record["fingerprint"] != _stage_fingerprint(context, stage):
            record.update(
                {
                    "status": "failed",
                    "finished_at_utc": utc_now(),
                    "blockers": ["stage_contract_changed"],
                    "result": {"error": "stage_contract_changed"},
                }
            )
            _write_state(context, state)
            continue
        if record["attempts"] >= MAX_ATTEMPTS:
            record.update(
                {
                    "status": "failed",
                    "finished_at_utc": utc_now(),
                    "blockers": ["maximum_stage_attempts_exceeded"],
                    "result": {"error": "maximum_stage_attempts_exceeded"},
                }
            )
            _write_state(context, state)
            continue
        record["status"] = "running"
        record["attempts"] += 1
        record["started_at_utc"] = utc_now()
        record["finished_at_utc"] = None
        record["blockers"] = []
        record["result"] = {}
        _write_state(context, state)
        try:
            outcome = getattr(actions, stage)(context, state)
            if outcome.status not in {"succeeded", "blocked"}:
                raise LifecycleError("stage_outcome_invalid", "stage outcome statusが不正です")
            record.update(
                {
                    "status": outcome.status,
                    "finished_at_utc": utc_now(),
                    "blockers": _bounded_blockers(outcome.blockers),
                    "result": dict(outcome.result),
                }
            )
        except Exception as exc:  # noqa: BLE001 - 固定stage境界で公開errorを正規化する
            code, message = _stage_public_error(stage, exc)
            record.update(
                {
                    "status": "failed",
                    "finished_at_utc": utc_now(),
                    "blockers": [code],
                    "result": {"error": {"code": code, "message": message}},
                }
            )
        _write_state(context, state)
    _finalize_state(context, state)
    return state


def _public_report_from_state(context: LifecycleContext, state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "workflow_id": context.request.workflow_id,
        "request_sha256": state["request_sha256"],
        "status": state["status"],
        "stages": {
            stage: {
                "status": state["stages"][stage]["status"],
                "attempts": state["stages"][stage]["attempts"],
                "blockers": state["stages"][stage]["blockers"],
                "result": state["stages"][stage]["result"],
            }
            for stage in STAGE_ORDER
        },
        "safety": {
            "sample_executed": False,
            "live_c2_contacted": False,
            "analysis_network_contacted": False,
            "datastore_network_contacted": (
                state["stages"]["private_archive"]["status"] == "succeeded"
            ),
            "arbitrary_command_executed": False,
        },
    }


def _finalize_state(context: LifecycleContext, state: dict[str, Any]) -> None:
    enabled = [record for record in state["stages"].values() if record["enabled"]]
    if any(record["status"] == "failed" for record in enabled):
        overall = "failed"
    elif any(record["status"] in {"blocked", "skipped", "pending", "running"} for record in enabled):
        overall = "partial"
    else:
        overall = "complete"
    state["status"] = overall
    _write_state(context, state)
    _atomic_json(context.lifecycle_root / "report.json", _public_report_from_state(context, state))


def _initialize_context(
    request: LifecycleRequest,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
) -> tuple[LifecycleContext, dict[str, Any]]:
    context = _validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
        create=True,
    )
    try:
        context.lifecycle_root.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise LifecycleError("workflow_already_exists", "同じworkflow_idはrunで再利用できません") from exc
    _atomic_json(context.lifecycle_root / "request.json", request.public())
    state = _new_state(context)
    _write_state(context, state)
    return context, state


def run_lifecycle(
    request: LifecycleRequest,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int = analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """production固定stageだけで新規workflowを実行する。"""

    context, state = _initialize_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    with _execution_lock(context.lifecycle_root):
        return _execute(context, state, PRODUCTION_ACTIONS)


def _run_lifecycle_for_test(
    request: LifecycleRequest,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
    actions: _Actions,
) -> dict[str, Any]:
    """production APIへ注入点を公開しないunit test専用入口。"""

    context, state = _initialize_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    with _execution_lock(context.lifecycle_root):
        return _execute(context, state, actions)


def _existing_context(
    workflow_id: str,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
) -> tuple[LifecycleContext, dict[str, Any]]:
    if WORKFLOW_ID_RE.fullmatch(workflow_id) is None:
        raise LifecycleError("workflow_id_invalid", "workflow_idの形式が不正です")
    request_path = Path(os.path.abspath(os.fspath(work_root))) / "lifecycles" / workflow_id / "request.json"
    request = load_request(request_path)
    context = _validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
        create=False,
    )
    state = _load_state(context)
    return context, state


def _resume_context(
    workflow_id: str,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
    verify_succeeded_artifacts: bool = True,
) -> tuple[LifecycleContext, dict[str, Any]]:
    context, state = _existing_context(
        workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    if verify_succeeded_artifacts:
        finalized = all(
            not record["enabled"] or record["status"] not in {"pending", "running"}
            for record in state["stages"].values()
        )
        errors = _verification_errors(
            context,
            state,
            include_report=finalized,
        )
        if errors:
            raise LifecycleError(
                "succeeded_artifact_changed", f"成功済みstageの再検証に失敗しました: {errors[0]}"
            )
    if state["status"] == "partial":
        raise LifecycleError(
            "successor_workflow_required",
            "partial workflowは同じ証拠を再試行せず、新しいworkflow_idで後続解析を開始してください",
        )
    reset = False
    for stage in STAGE_ORDER:
        record = state["stages"][stage]
        if record["status"] in {"running", "failed", "blocked"} or (
            record["status"] == "skipped" and record["enabled"]
        ):
            reset = True
            record.update(
                {
                    "status": "pending",
                    "started_at_utc": None,
                    "finished_at_utc": None,
                    "blockers": [],
                    "result": {},
                }
            )
    if reset:
        state["status"] = "pending"
    _write_state(context, state)
    return context, state


def resume_lifecycle(
    workflow_id: str,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int = analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """保存済みrequestとstage fingerprintを検証して未完stageだけ再開する。"""

    existing, _ = _existing_context(
        workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    with _execution_lock(existing.lifecycle_root):
        context, state = _resume_context(
            workflow_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=timeout_seconds,
        )
        return _execute(context, state, PRODUCTION_ACTIONS)


def read_status(work_root: Path, workflow_id: str) -> dict[str, Any]:
    """repository外のworkflow reportを副作用なしで読み込む。"""

    if WORKFLOW_ID_RE.fullmatch(workflow_id) is None:
        raise LifecycleError("workflow_id_invalid", "workflow_idの形式が不正です")
    root = Path(os.path.abspath(os.fspath(work_root))) / "lifecycles" / workflow_id
    _reject_existing_reparse_components(root, label="lifecycle state")
    return _load_json(root / "report.json", maximum_bytes=MAX_STATE_BYTES)


def _verification_errors(
    context: LifecycleContext,
    state: Mapping[str, Any],
    *,
    include_report: bool,
) -> list[str]:
    errors: list[str] = []
    static = state["stages"]["static_analysis"]
    if static["status"] == "succeeded":
        errors.extend(_static_artifact_errors(context, static))
    publication = state["stages"]["publication"]
    if publication["status"] == "succeeded":
        try:
            relative = _normalize_relative_path(publication["result"].get("collection"), label="collection")
            collection = context.repository.joinpath(*PurePosixPath(relative).parts)
            _reject_existing_reparse_components(collection, label="published collection")
            if (
                not collection.is_dir()
                or _is_reparse(collection)
                or not collection.resolve().is_relative_to(context.repository)
            ):
                errors.append("publication_collection_missing")
            else:
                function_result = validate_function_analysis.validate_collection(context.repository, collection)
                function_record = state["stages"]["function_validation"]
                if function_record["status"] in {"succeeded", "blocked"}:
                    function_succeeded = function_record["status"] == "succeeded"
                    if bool(function_result["complete"]) != function_succeeded:
                        errors.append("function_validation_state_mismatch")
                    for key in ("cases", "valid_cases", "invalid_cases", "complete"):
                        if key in function_record["result"] and function_record["result"].get(key) != function_result.get(key):
                            errors.append("function_validation_result_mismatch")
                            break
        except Exception:  # noqa: BLE001 - read-only publication検証境界でerrorを正規化する
            errors.append("publication_verification_failed")
    refresh = state["stages"]["derived_refresh"]
    if refresh["status"] == "succeeded":
        try:
            refreshed = refresh_case_inventory.refresh(context.repository, write=False, check=True)
            terminal = build_terminal_payload_gap_inventory.sync_outputs(
                context.repository,
                Path("intelligence/terminal-payload-recovery"),
                write=False,
            )
            if refreshed["check_failed"] or terminal["mismatches"]:
                errors.append("derived_refresh_stale")
        except Exception:  # noqa: BLE001 - read-only generator検証境界でerrorを正規化する
            errors.append("derived_refresh_verification_failed")
    archive = state["stages"]["private_archive"]
    if archive["status"] == "succeeded":
        try:
            report = _load_json(
                context.lifecycle_root / "private-archive-report.json",
                maximum_bytes=MAX_STATE_BYTES,
            )
            verification = report.get("s3_verification")
            if (
                report.get("status") != "verified"
                or report.get("archive_sha256") != archive["result"].get("archive_sha256")
                or report.get("manifest_sha256") != archive["result"].get("manifest_sha256")
                or not isinstance(verification, dict)
                or verification.get("server_side_encryption") != "AES256"
            ):
                errors.append("private_archive_report_mismatch")
        except LifecycleError as exc:
            errors.append(exc.code)
    if include_report:
        try:
            report = _load_json(context.lifecycle_root / "report.json", maximum_bytes=MAX_STATE_BYTES)
            if report != _public_report_from_state(context, state):
                errors.append("lifecycle_report_state_mismatch")
        except LifecycleError:
            errors.append("lifecycle_report_missing")
    return sorted(set(errors))


def verify_lifecycle(
    workflow_id: str,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int = analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """成果物を書かず、request、fingerprint、job安全契約、archive reportを再検証する。"""

    context, state = _existing_context(
        workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    errors = _verification_errors(context, state, include_report=True)
    return {
        "schema_version": SCHEMA_VERSION,
        "workflow_id": workflow_id,
        "valid": not errors,
        "errors": sorted(set(errors)),
        "request_sha256": state["request_sha256"],
        "stage_status": {stage: state["stages"][stage]["status"] for stage in STAGE_ORDER},
        "sample_executed": False,
        "analysis_network_contacted": False,
    }


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("positional arguments:", "サブコマンド:")
            .replace("show this help message and exit", "このhelpを表示して終了します")
        )


def _add_roots(parser: argparse.ArgumentParser, *, request: bool) -> None:
    if request:
        parser.add_argument("--request", required=True, type=Path, help="UTF-8 lifecycle request JSON")
    else:
        parser.add_argument("--workflow-id", required=True, help="保存済みworkflow ID")
    parser.add_argument("--repository", required=True, type=Path, help="解析repository root")
    parser.add_argument("--input-root", required=True, type=Path, help="検体を置くrepository外root")
    parser.add_argument("--work-root", required=True, type=Path, help="jobとstateを置くrepository外root")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
        help="静的解析jobの時間上限",
    )


def build_parser() -> argparse.ArgumentParser:
    """固定subcommandだけを持つCLI parserを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema", help="固定request JSON Schemaを出力します")
    plan = commands.add_parser("plan", help="副作用なしでstage graphと安全境界を検証します")
    _add_roots(plan, request=True)
    run = commands.add_parser("run", help="新規workflowを固定stageで実行します")
    _add_roots(run, request=True)
    resume = commands.add_parser("resume", help="保存済みfingerprintを検証して再開します")
    _add_roots(resume, request=False)
    verify = commands.add_parser("verify", help="保存済み成果物をread-onlyで再検証します")
    _add_roots(verify, request=False)
    status = commands.add_parser("status", help="公開可能なworkflow reportを読みます")
    status.add_argument("--work-root", required=True, type=Path)
    status.add_argument("--workflow-id", required=True)
    return parser


def _print_json(value: Any, *, stream: Any | None = None) -> None:
    print(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False),
        file=sys.stdout if stream is None else stream,
    )


def main(argv: list[str] | None = None) -> int:
    """CLIを実行し、JSON結果と状態別終了codeを返す。"""

    args = build_parser().parse_args(argv)
    try:
        if args.command == "schema":
            _print_json(request_json_schema())
            return 0
        if args.command == "status":
            _print_json(read_status(args.work_root, args.workflow_id))
            return 0
        if args.command == "plan":
            request = load_request(args.request)
            _validate_context_roots(
                request,
                repository=args.repository,
                input_root=args.input_root,
                work_root=args.work_root,
                timeout_seconds=args.timeout_seconds,
                create=False,
            )
            _print_json(build_plan(request))
            return 0
        if args.command == "run":
            result = run_lifecycle(
                load_request(args.request),
                repository=args.repository,
                input_root=args.input_root,
                work_root=args.work_root,
                timeout_seconds=args.timeout_seconds,
            )
            _print_json(_load_json(args.work_root / "lifecycles" / result["workflow_id"] / "report.json", maximum_bytes=MAX_STATE_BYTES))
            return 0 if result["status"] == "complete" else 20 if result["status"] == "partial" else 1
        if args.command == "resume":
            result = resume_lifecycle(
                args.workflow_id,
                repository=args.repository,
                input_root=args.input_root,
                work_root=args.work_root,
                timeout_seconds=args.timeout_seconds,
            )
            _print_json(_load_json(args.work_root / "lifecycles" / result["workflow_id"] / "report.json", maximum_bytes=MAX_STATE_BYTES))
            return 0 if result["status"] == "complete" else 20 if result["status"] == "partial" else 1
        result = verify_lifecycle(
            args.workflow_id,
            repository=args.repository,
            input_root=args.input_root,
            work_root=args.work_root,
            timeout_seconds=args.timeout_seconds,
        )
        _print_json(result)
        return 0 if result["valid"] else 1
    except LifecycleError as exc:
        _print_json(
            {"schema_version": SCHEMA_VERSION, "error": {"code": exc.code, "message": str(exc)}},
            stream=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
