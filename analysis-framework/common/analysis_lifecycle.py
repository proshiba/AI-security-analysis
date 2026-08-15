#!/usr/bin/env python3
"""識別から公開・保管までを固定stageで安全に自動化する解析lifecycle runner。"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any
from contextlib import redirect_stdout

import analysis_job_runner
import archive_analysis_datastore
import build_terminal_payload_gap_inventory
import publish_one_shot_collection
import refresh_case_inventory
import validate_function_analysis


SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 1024 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_ATTEMPTS = 5
WORKFLOW_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
COLLECTION_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BLOCKER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}$")
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

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
    "completion_gate": ("analysis_lifecycle.py", "analysis_job_runner.py"),
    "derived_refresh": (
        "analysis_lifecycle.py",
        "refresh_case_inventory.py",
        "build_terminal_payload_gap_inventory.py",
    ),
    "private_archive": ("analysis_lifecycle.py", "archive_analysis_datastore.py"),
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

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
    if state.get("workflow_id") != context.request.workflow_id:
        raise LifecycleError("state_invalid", "workflow_idがrequestと一致しません")
    if state.get("request_sha256") != _sha256_value(context.request.public()):
        raise LifecycleError("request_changed", "保存済みrequest digestが一致しません")
    if state.get("stage_order") != list(STAGE_ORDER) or not isinstance(state.get("stages"), dict):
        raise LifecycleError("state_invalid", "固定stage graphが一致しません")
    for stage in STAGE_ORDER:
        record = state["stages"].get(stage)
        if not isinstance(record, dict) or record.get("fingerprint") != _stage_fingerprint(context, stage):
            raise LifecycleError("stage_contract_changed", f"{stage}の実装契約が保存時から変更されました")
    return state


def _safe_blocker(value: Any) -> str:
    if isinstance(value, str) and BLOCKER_RE.fullmatch(value):
        return value
    return "analysis_blocked"


def _bounded_blockers(values: Sequence[Any]) -> list[str]:
    return sorted({_safe_blocker(value) for value in values})[:256]


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


def _verified_static_result(context: LifecycleContext) -> dict[str, Any] | None:
    job_dir = context.jobs_root / context.request.job.job_id
    if not job_dir.exists():
        return None
    snapshot = analysis_job_runner.read_job_snapshot(context.jobs_root, context.request.job.job_id)
    result = snapshot.get("result")
    if not isinstance(result, dict) or result.get("accepted") is not True:
        raise LifecycleError("existing_job_incomplete", "既存jobが検証済み完了状態ではありません")
    safety = result.get("safety")
    if not isinstance(safety, dict) or any(
        safety.get(key) is not False for key in ("executed_sample", "network_contacted", "ai_used")
    ):
        raise LifecycleError("static_safety_invalid", "既存jobの安全flagが不正です")
    return result


def _production_static(context: LifecycleContext, _: Mapping[str, Any]) -> StageOutcome:
    result = _verified_static_result(context)
    if result is None:
        exit_code = analysis_job_runner.run_job(
            context.request.job,
            input_root=context.input_root,
            jobs_root=context.jobs_root,
            timeout_seconds=context.timeout_seconds,
        )
        if exit_code not in {0, 20}:
            raise LifecycleError("static_analysis_failed", "静的解析jobが受理可能な終了状態ではありません")
        result = _verified_static_result(context)
    if result is None:
        raise LifecycleError("static_result_missing", "静的解析結果がありません")
    result_path = context.jobs_root / context.request.job.job_id / "result.json"
    summary_path = context.jobs_root / context.request.job.job_id / "analysis" / "summary.json"
    return StageOutcome(
        "succeeded",
        {
            "analysis_state": result["analysis_state"],
            "counts": result["counts"],
            "derived_counts": result["derived_counts"],
            "follow_on_analysis": result["follow_on_analysis"],
            "result_sha256": _sha256_file(result_path),
            "summary_sha256": _sha256_file(summary_path),
            "job_relative_path": f"jobs/{context.request.job.job_id}",
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        },
    )


def _analysis_summary(context: LifecycleContext) -> dict[str, Any]:
    return _load_json(
        context.jobs_root / context.request.job.job_id / "analysis" / "summary.json",
        maximum_bytes=analysis_job_runner.MAX_SUMMARY_BYTES,
    )


def _production_publication(context: LifecycleContext, state: Mapping[str, Any]) -> StageOutcome:
    static = state["stages"]["static_analysis"]["result"]
    if static.get("analysis_state") == "partial" and not context.request.publication["allow_partial_staging"]:
        blocker = "publication_requires_complete_or_partial_staging_opt_in"
        return StageOutcome("blocked", {"published": 0}, (blocker,))
    summary = _analysis_summary(context)
    contract = summary.get("analysis_contract")
    observed_contract = contract.get("sha256") if isinstance(contract, dict) else None
    if not isinstance(observed_contract, str) or SHA256_RE.fullmatch(observed_contract) is None:
        raise LifecycleError("analysis_contract_missing", "one-shot summaryにanalysis contractがありません")
    requested_contract = context.request.publication["expected_contract_sha256"]
    if requested_contract is not None and requested_contract != observed_contract:
        raise LifecycleError("analysis_contract_mismatch", "request pinとone-shot contractが一致しません")
    result = publish_one_shot_collection.publish(
        context.repository,
        _resolve_repository_file(context.repository, context.request.publication["manifest"]),
        [context.jobs_root / context.request.job.job_id / "analysis"],
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


def _case_blockers(context: LifecycleContext) -> tuple[list[dict[str, Any]], list[str]]:
    summary = _analysis_summary(context)
    analysis_root = context.jobs_root / context.request.job.job_id / "analysis"
    cases: list[dict[str, Any]] = []
    blockers: list[str] = []
    for item in [*summary.get("cases", []), *summary.get("derived_cases", [])]:
        if not isinstance(item, dict):
            continue
        digest = item.get("sha256")
        status = item.get("case_state")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            continue
        cases.append({"sha256": digest, "status": status})
        report_path = analysis_root / "cases" / digest / "report.json"
        orchestration_path = analysis_root / "cases" / digest / "orchestration.json"
        if report_path.is_file():
            report = _load_json(report_path, maximum_bytes=analysis_job_runner.MAX_SUMMARY_BYTES)
            state = report.get("case_state")
            if isinstance(state, dict):
                blockers.extend(state.get("blockers") or [])
        if orchestration_path.is_file():
            orchestration = _load_json(orchestration_path, maximum_bytes=analysis_job_runner.MAX_SUMMARY_BYTES)
            blockers.extend(orchestration.get("blockers") or [])
    return cases, _bounded_blockers(blockers)


def _next_actions(blockers: Sequence[str]) -> list[str]:
    actions: set[str] = set()
    for blocker in blockers:
        lowered = blocker.casefold()
        if "function" in lowered:
            actions.add("representative_function_static_review")
        elif "terminal" in lowered or "payload" in lowered:
            actions.add("terminal_payload_static_recovery")
        elif "config" in lowered or "c2" in lowered or "network" in lowered:
            actions.add("configuration_and_c2_static_recovery")
        elif "family" in lowered or "classification" in lowered:
            actions.add("family_attribution_review")
        elif "publication" in lowered:
            actions.add("complete_case_or_enable_reviewed_partial_staging")
        else:
            actions.add("review_machine_readable_blocker")
    return sorted(actions)


def _production_completion(context: LifecycleContext, state: Mapping[str, Any]) -> StageOutcome:
    static = state["stages"]["static_analysis"]["result"]
    cases, blockers = _case_blockers(context)
    if static.get("analysis_state") != "complete" and not blockers:
        blockers.append("analysis_partial")
    for stage in ("publication", "function_validation"):
        record = state["stages"][stage]
        if record["enabled"] and record["status"] in {"blocked", "failed"}:
            blockers.extend(record.get("blockers") or [f"{stage}_incomplete"])
    blockers = _bounded_blockers(blockers)
    result = {
        "complete": not blockers and static.get("analysis_state") == "complete",
        "case_count": len(cases),
        "cases": cases[:256],
        "blockers": blockers,
        "next_actions": _next_actions(blockers),
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


def _archive_sources(context: LifecycleContext) -> list[Path]:
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


def _production_archive(context: LifecycleContext, _: Mapping[str, Any]) -> StageOutcome:
    report_path = context.lifecycle_root / "private-archive-report.json"
    if report_path.exists():
        report = _load_json(report_path, maximum_bytes=MAX_STATE_BYTES)
    else:
        argv = ["--target", context.request.private_archive["target"]]
        for source in _archive_sources(context):
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
    report = {
        "schema_version": SCHEMA_VERSION,
        "workflow_id": context.request.workflow_id,
        "request_sha256": state["request_sha256"],
        "status": overall,
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
    _atomic_json(context.lifecycle_root / "report.json", report)


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
) -> tuple[LifecycleContext, dict[str, Any]]:
    context, state = _existing_context(
        workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    for stage in STAGE_ORDER:
        record = state["stages"][stage]
        if record["status"] == "running":
            record["status"] = "pending"
            record["blockers"] = ["interrupted_stage_recovered"]
        elif record["status"] in {"failed", "blocked"}:
            record["status"] = "pending"
        elif record["status"] == "skipped" and record["enabled"]:
            record["status"] = "pending"
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
    errors: list[str] = []
    static = state["stages"]["static_analysis"]
    if static["status"] == "succeeded":
        try:
            result = _verified_static_result(context)
            if result is None:
                errors.append("static_result_missing")
            else:
                path = context.jobs_root / context.request.job.job_id / "result.json"
                if static["result"].get("result_sha256") != _sha256_file(path):
                    errors.append("static_result_hash_mismatch")
                summary = context.jobs_root / context.request.job.job_id / "analysis" / "summary.json"
                if not summary.is_file() or static["result"].get("summary_sha256") != _sha256_file(summary):
                    errors.append("static_summary_hash_mismatch")
        except LifecycleError as exc:
            errors.append(exc.code)
    publication = state["stages"]["publication"]
    if publication["status"] == "succeeded":
        try:
            relative = _normalize_relative_path(publication["result"].get("collection"), label="collection")
            collection = context.repository.joinpath(*PurePosixPath(relative).parts)
            if not collection.is_dir() or not collection.resolve().is_relative_to(context.repository):
                errors.append("publication_collection_missing")
            else:
                function_result = validate_function_analysis.validate_collection(context.repository, collection)
                function_succeeded = state["stages"]["function_validation"]["status"] == "succeeded"
                if bool(function_result["complete"]) != function_succeeded:
                    errors.append("function_validation_state_mismatch")
        except LifecycleError as exc:
            errors.append(exc.code)
    refresh = state["stages"]["derived_refresh"]
    if refresh["status"] == "succeeded":
        refreshed = refresh_case_inventory.refresh(context.repository, write=False, check=True)
        terminal = build_terminal_payload_gap_inventory.sync_outputs(
            context.repository,
            Path("intelligence/terminal-payload-recovery"),
            write=False,
        )
        if refreshed["check_failed"] or terminal["mismatches"]:
            errors.append("derived_refresh_stale")
    archive = state["stages"]["private_archive"]
    if archive["status"] == "succeeded":
        try:
            report = _load_json(context.lifecycle_root / "private-archive-report.json", maximum_bytes=MAX_STATE_BYTES)
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
