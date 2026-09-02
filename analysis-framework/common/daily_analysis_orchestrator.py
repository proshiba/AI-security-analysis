#!/usr/bin/env python3
"""日次解析の既存laneを固定順・再開可能なcheckpointで統括する。"""

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
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import analysis_job_runner


SCHEMA_VERSION = 2
STATE_SCHEMA_VERSION = 1
STATE_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "request_sha256",
        "implementation_sha256",
        "status",
        "created_at_utc",
        "updated_at_utc",
        "stages",
        "capacity_remediation",
        "safety",
    }
)
RUN_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_ATTEMPTS = 5
MAX_STAGE_ATTEMPTS = {
    "ghidra": 1024,
    "validation": 1024,
    "private_archive": 1024,
}
STAGES = (
    "news_intake",
    "malwarebazaar_acquisition",
    "static_analysis",
    "publication",
    "ghidra",
    "c2_monitoring",
    "validation",
    "private_archive",
)
NETWORK_KEYS = frozenset(
    {
        "provider_lookups",
        "sample_download",
        "c2_monitoring",
        "datastore_upload",
    }
)
LIMIT_KEYS = frozenset(
    {
        "query_limit",
        "static_timeout_seconds",
        "ghidra_minimum_free_bytes",
        "ghidra_max_new_programs",
    }
)
REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "analysis_date",
        "news_source_date",
        "source_manifest_sha256",
        "malwarebazaar_count",
        "tech_memo",
        "stages",
        "network",
        "limits",
    }
)
MIN_GHIDRA_FREE_BYTES = 256 * 1024 * 1024
MAX_GHIDRA_FREE_BYTES = 1024 * 1024 * 1024 * 1024
MAX_STATIC_TIMEOUT_SECONDS = analysis_job_runner.MAX_TIMEOUT_SECONDS
MIB = 1024 * 1024
PREFLIGHT_SAMPLE_ARCHIVE_BYTES = 24 * MIB
PREFLIGHT_ANALYSIS_BYTES = 8 * MIB
PREFLIGHT_REPOSITORY_BYTES = 256 * MIB
PREFLIGHT_C2_PRIVATE_BYTES = 256 * MIB
PREFLIGHT_ARCHIVE_STAGING_BYTES = 512 * MIB
SAMPLE_DOWNLOAD_MAX_BYTES = 256 * MIB
SAMPLE_DOWNLOAD_MINIMUM_FREE_BYTES = 256 * MIB
DAILY_SOURCE_MAX_FILE_BYTES = 64 * MIB
MAX_SOURCE_DISCOVERY_FILES = 20_000
MAX_SOURCE_DISCOVERY_DEPTH = 8
MAX_DATASTORE_TARGET_LENGTH = 128
MAX_DRIVE_CYCLES = 1024
CAPACITY_STOP_REASONS = frozenset(
    {
        "minimum_free_space_not_met",
        "preflight_capacity_insufficient",
        "archive_staging_capacity_insufficient",
    }
)
NEWS_PUBLIC_FILES = frozenset(
    {
        "ioc-summary.json",
        "provider-summary.json",
        "infrastructure-summary.json",
        "README.md",
        "sample-static-summary.json",
        "STATIC-ANALYSIS.md",
        "THREAT-ANALYSIS.md",
        "DETECTION.md",
    }
)


class DailyOrchestrationError(RuntimeError):
    """公開可能な固定codeを持つ日次制御層の契約違反。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DailyRequest:
    """厳格検証済みの日次解析request。"""

    run_id: str
    analysis_date: str
    news_source_date: str
    source_manifest_sha256: str
    malwarebazaar_count: int
    tech_memo: str
    stages: Mapping[str, bool]
    network: Mapping[str, bool]
    limits: Mapping[str, int | None]

    def public(self) -> dict[str, Any]:
        """秘密値と絶対pathを含まない正規requestを返す。"""

        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "analysis_date": self.analysis_date,
            "news_source_date": self.news_source_date,
            "source_manifest_sha256": self.source_manifest_sha256,
            "malwarebazaar_count": self.malwarebazaar_count,
            "tech_memo": self.tech_memo,
            "stages": dict(self.stages),
            "network": dict(self.network),
            "limits": dict(self.limits),
        }


@dataclass(frozen=True)
class DailyContext:
    """実行時だけ保持するrepository外pathと安全gate。"""

    repository: Path
    intelligence_root: Path
    private_root: Path
    work_root: Path
    state_root: Path
    ghidra_project_store: Path
    request: DailyRequest
    allow_live_c2: bool

    @property
    def collection_id(self) -> str:
        compact = self.request.analysis_date.replace("-", "")
        return f"malwarebazaar-windows-{compact}-{self.request.malwarebazaar_count:04d}"

    @property
    def collection_root(self) -> Path:
        return self.private_root / "daily-runs" / self.request.run_id / self.collection_id

    @property
    def source_root(self) -> Path:
        return self.collection_root / "source"

    @property
    def jobs_root(self) -> Path:
        return self.work_root / "jobs"

    @property
    def ghidra_sample_root(self) -> Path:
        return self.work_root / "gi" / self.request.run_id

    @property
    def ghidra_private_output(self) -> Path:
        return self.collection_root / "ghidra-static-results"

    @property
    def maxmind_cache(self) -> Path:
        return self.private_root / "maxmind"

    @property
    def daily_news_private_output(self) -> Path:
        return self.private_root / "daily-runs" / self.request.run_id / "daily-news-malware"

    @property
    def orchestration_root(self) -> Path:
        return self.work_root / "daily-orchestrations"


@dataclass(frozen=True)
class StageOutcome:
    """1段階の無害化済み結果。"""

    status: str
    result: Mapping[str, Any]
    retryable: bool = False


@dataclass(frozen=True)
class DailyActions:
    """productionとunit testで共有する固定stage adapter。"""

    news_intake: Callable[[DailyContext], StageOutcome]
    malwarebazaar_acquisition: Callable[[DailyContext], StageOutcome]
    static_analysis: Callable[[DailyContext], StageOutcome]
    publication: Callable[[DailyContext], StageOutcome]
    ghidra: Callable[[DailyContext], StageOutcome]
    c2_monitoring: Callable[[DailyContext], StageOutcome]
    validation: Callable[[DailyContext], StageOutcome]
    private_archive: Callable[[DailyContext], StageOutcome]


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


def _sha256_string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DailyOrchestrationError(
            "sha256_invalid",
            f"{label}は小文字64桁のSHA-256で指定してください",
        )
    return value


def _iso_date(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise DailyOrchestrationError("date_invalid", f"{label}はYYYY-MM-DDで指定してください")
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise DailyOrchestrationError("date_invalid", f"{label}はYYYY-MM-DDで指定してください") from exc


def _bounded_integer(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DailyOrchestrationError(
            "limit_invalid",
            f"{label}は{minimum}以上{maximum}以下の整数で指定してください",
        )
    return value


def _relative_repository_file(value: Any) -> str:
    windows = PureWindowsPath(value) if isinstance(value, str) else None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or "\\" in value
        or ":" in value
        or windows is None
        or bool(windows.drive)
        or bool(windows.root)
    ):
        raise DailyOrchestrationError(
            "tech_memo_invalid",
            "tech_memoはrepositoryからのPOSIX相対pathで指定してください",
        )
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise DailyOrchestrationError(
            "tech_memo_invalid",
            "tech_memoはrepository内の正規化済み相対pathに限定します",
        )
    return path.as_posix()


def _exact_boolean_map(value: Any, *, keys: frozenset[str], label: str) -> dict[str, bool]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise DailyOrchestrationError(
            "request_schema_invalid",
            f"{label}のfield集合が一致しません",
        )
    normalized: dict[str, bool] = {}
    for key in sorted(keys):
        item = value[key]
        if type(item) is not bool:
            raise DailyOrchestrationError(
                "request_schema_invalid",
                f"{label}.{key}はbooleanで指定してください",
            )
        normalized[key] = item
    return normalized


def validate_request_object(value: Mapping[str, Any]) -> DailyRequest:
    """日次requestを未知fieldなしで厳格検証する。"""

    if not isinstance(value, Mapping) or set(value) != REQUEST_KEYS:
        raise DailyOrchestrationError(
            "request_schema_invalid",
            "日次requestのfield集合が一致しません",
        )
    if value.get("schema_version") != SCHEMA_VERSION:
        raise DailyOrchestrationError(
            "request_schema_invalid",
            f"schema_versionは{SCHEMA_VERSION}だけを許可します",
        )
    run_id = value.get("run_id")
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise DailyOrchestrationError(
            "run_id_invalid",
            "run_idは小文字英数字、'.'、'_'、'-'の1..64文字に限定します",
        )
    stages = _exact_boolean_map(
        value.get("stages"),
        keys=frozenset(STAGES),
        label="stages",
    )
    network = _exact_boolean_map(
        value.get("network"),
        keys=NETWORK_KEYS,
        label="network",
    )
    raw_limits = value.get("limits")
    if not isinstance(raw_limits, Mapping) or set(raw_limits) != LIMIT_KEYS:
        raise DailyOrchestrationError(
            "request_schema_invalid",
            "limitsのfield集合が一致しません",
        )
    malwarebazaar_count = _bounded_integer(
        value.get("malwarebazaar_count"),
        label="malwarebazaar_count",
        minimum=1,
        maximum=analysis_job_runner.MAX_REQUEST_INPUTS,
    )
    query_limit = _bounded_integer(
        raw_limits.get("query_limit"),
        label="limits.query_limit",
        minimum=malwarebazaar_count,
        maximum=1000,
    )
    static_timeout = _bounded_integer(
        raw_limits.get("static_timeout_seconds"),
        label="limits.static_timeout_seconds",
        minimum=1,
        maximum=MAX_STATIC_TIMEOUT_SECONDS,
    )
    ghidra_free = _bounded_integer(
        raw_limits.get("ghidra_minimum_free_bytes"),
        label="limits.ghidra_minimum_free_bytes",
        minimum=MIN_GHIDRA_FREE_BYTES,
        maximum=MAX_GHIDRA_FREE_BYTES,
    )
    max_new = raw_limits.get("ghidra_max_new_programs")
    if max_new is not None:
        max_new = _bounded_integer(
            max_new,
            label="limits.ghidra_max_new_programs",
            minimum=0,
            maximum=analysis_job_runner.MAX_REQUEST_INPUTS * 16,
        )
    if network["provider_lookups"] and not stages["news_intake"]:
        raise DailyOrchestrationError(
            "network_stage_disabled",
            "provider lookupを有効にする場合はnews_intakeも有効にしてください",
        )
    if network["sample_download"] and not stages["malwarebazaar_acquisition"]:
        raise DailyOrchestrationError(
            "network_stage_disabled",
            "sample downloadを有効にする場合はmalwarebazaar_acquisitionも有効にしてください",
        )
    if network["c2_monitoring"] and not stages["c2_monitoring"]:
        raise DailyOrchestrationError(
            "network_stage_disabled",
            "C2監視networkを有効にする場合はc2_monitoringも有効にしてください",
        )
    if network["datastore_upload"] and not stages["private_archive"]:
        raise DailyOrchestrationError(
            "network_stage_disabled",
            "datastore uploadを有効にする場合はprivate_archiveも有効にしてください",
        )
    for stage, prerequisite in (
        ("static_analysis", "malwarebazaar_acquisition"),
        ("publication", "static_analysis"),
        ("ghidra", "publication"),
    ):
        if stages[stage] and not stages[prerequisite]:
            raise DailyOrchestrationError(
                "stage_dependency_disabled",
                f"{stage}を有効にする場合は{prerequisite}も有効にしてください",
            )
    return DailyRequest(
        run_id=run_id,
        analysis_date=_iso_date(value.get("analysis_date"), label="analysis_date"),
        news_source_date=_iso_date(value.get("news_source_date"), label="news_source_date"),
        source_manifest_sha256=_sha256_string(
            value.get("source_manifest_sha256"),
            label="source_manifest_sha256",
        ),
        malwarebazaar_count=malwarebazaar_count,
        tech_memo=_relative_repository_file(value.get("tech_memo")),
        stages=stages,
        network=network,
        limits={
            "query_limit": query_limit,
            "static_timeout_seconds": static_timeout,
            "ghidra_minimum_free_bytes": ghidra_free,
            "ghidra_max_new_programs": max_new,
        },
    )


def request_json_schema() -> dict[str, Any]:
    """operator UIとCLIで共有するrequest JSON Schemaを返す。"""

    def boolean_properties(keys: frozenset[str]) -> dict[str, dict[str, str]]:
        return {key: {"type": "boolean"} for key in sorted(keys)}

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://local.invalid/ai-security-analysis/daily-orchestration-v2.schema.json",
        "type": "object",
        "additionalProperties": False,
        "required": sorted(REQUEST_KEYS),
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "run_id": {"type": "string", "pattern": RUN_ID_RE.pattern, "maxLength": 64},
            "analysis_date": {"type": "string", "format": "date"},
            "news_source_date": {"type": "string", "format": "date"},
            "source_manifest_sha256": {
                "type": "string",
                "pattern": SHA256_RE.pattern,
            },
            "malwarebazaar_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": analysis_job_runner.MAX_REQUEST_INPUTS,
            },
            "tech_memo": {"type": "string", "minLength": 1, "maxLength": 512},
            "stages": {
                "type": "object",
                "additionalProperties": False,
                "required": list(STAGES),
                "properties": boolean_properties(frozenset(STAGES)),
            },
            "network": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(NETWORK_KEYS),
                "properties": boolean_properties(NETWORK_KEYS),
            },
            "limits": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(LIMIT_KEYS),
                "properties": {
                    "query_limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "static_timeout_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_STATIC_TIMEOUT_SECONDS,
                    },
                    "ghidra_minimum_free_bytes": {
                        "type": "integer",
                        "minimum": MIN_GHIDRA_FREE_BYTES,
                        "maximum": MAX_GHIDRA_FREE_BYTES,
                    },
                    "ghidra_max_new_programs": {
                        "type": ["integer", "null"],
                        "minimum": 0,
                    },
                },
            },
        },
    }


def load_request(path: Path) -> DailyRequest:
    """通常fileのrequestをsize上限付きstrict JSONとして読む。"""

    try:
        document = analysis_job_runner.load_json_object_strict(
            path,
            max_bytes=analysis_job_runner.MAX_REQUEST_BYTES,
        )
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise DailyOrchestrationError(
            "request_invalid",
            "日次requestを安全に読み取れません",
        ) from exc
    return validate_request_object(document)


def _implementation_sha256() -> str:
    """control planeと固定adapterの実装をresume契約へ束縛する。"""

    root = Path(__file__).resolve().parent
    names = (
        "daily_analysis_orchestrator.py",
        "daily_news_malware_intake.py",
        "malwarebazaar_batch.py",
        "analysis_job_runner.py",
        "analysis_contract.py",
        "bounded_process.py",
        "batch_error_contract.py",
        "job_artifact_schemas.py",
        "orchestration_outcome.py",
        "runtime_contract.py",
        "terminal_payload_acquisition.py",
        "follow_on_commitment.py",
        "publish_one_shot_collection.py",
        "ghidra_function_batch.py",
        "build_all_c2_monitoring_targets.py",
        "run_c2_monitoring_pipeline.py",
        "validate_daily_analysis.py",
        "archive_analysis_datastore.py",
    )
    records = []
    for name in names:
        path = root / name
        records.append({"name": name, "sha256": _sha256_file(path), "size": path.stat().st_size})
    return _sha256_value(records)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _canonical_path(path: Path) -> Path:
    """既存ancestorをreal pathへ固定し、未作成suffixだけを再構成する。"""

    absolute = _absolute(path)
    current = absolute
    missing: list[str] = []
    while not os.path.lexists(current):
        parent = current.parent
        if parent == current:
            raise DailyOrchestrationError(
                "path_canonicalization_failed",
                "pathの既存ancestorを確認できません",
            )
        missing.append(current.name)
        current = parent
    try:
        resolved = current.resolve(strict=True)
    except OSError as exc:
        raise DailyOrchestrationError(
            "path_canonicalization_failed",
            "pathの既存ancestorをcanonicalizeできません",
        ) from exc
    for part in reversed(missing):
        resolved /= part
    return resolved


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _reject_reparse_components(path: Path, *, label: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            break
        information = current.lstat()
        if current.is_symlink() or bool(
            getattr(information, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise DailyOrchestrationError(
                "reparse_forbidden",
                f"{label}にreparse pointは使用できません",
            )


def _regular_file_without_reparse(path: Path) -> bool:
    """source discoveryでlinkを候補として扱わない。"""

    try:
        information = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(information.st_mode)
        and information.st_nlink == 1
        and information.st_size > 0
        and not path.is_symlink()
        and not bool(
            getattr(information, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    )


def _bounded_tree_files(root: Path) -> list[Path]:
    """全entryとdepthを数え、reparseを辿らない決定的walker。"""

    _reject_reparse_components(root, label="日次source root")
    pending: list[tuple[Path, int]] = [(root, 0)]
    files: list[Path] = []
    observed = 0
    while pending:
        current, depth = pending.pop()
        try:
            with os.scandir(current) as iterator:
                entries = []
                for entry in iterator:
                    observed += 1
                    if observed > MAX_SOURCE_DISCOVERY_FILES:
                        raise DailyOrchestrationError(
                            "news_source_discovery_limit",
                            "日次source探索の全entry件数が上限を超えました",
                        )
                    entries.append(entry)
                entries.sort(key=lambda item: item.name.casefold())
        except OSError as exc:
            raise DailyOrchestrationError(
                "news_source_discovery_failed",
                "日次source treeを安全に列挙できません",
            ) from exc
        for entry in entries:
            try:
                information = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise DailyOrchestrationError(
                    "news_source_discovery_failed",
                    "日次source entryを安全に確認できません",
                ) from exc
            reparse = entry.is_symlink() or bool(
                getattr(information, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
            if reparse:
                raise DailyOrchestrationError(
                    "news_source_reparse_forbidden",
                    "日次source treeにreparse pointは使用できません",
                )
            path = Path(entry.path)
            if stat.S_ISDIR(information.st_mode):
                if depth >= MAX_SOURCE_DISCOVERY_DEPTH:
                    raise DailyOrchestrationError(
                        "news_source_discovery_depth",
                        "日次source探索のdirectory depthが上限を超えました",
                    )
                pending.append((path, depth + 1))
            elif stat.S_ISREG(information.st_mode):
                files.append(path)
    return sorted(files, key=lambda path: path.as_posix().casefold())


def discover_latest_news_source(tech_memo: Path) -> dict[str, Any]:
    """news、IOC CSV、IOC logがそろった最新source日を有界探索する。"""

    root = _absolute(tech_memo)
    _reject_reparse_components(root, label="tech-memo")
    root = _canonical_path(root)
    news_root = root / "daily-news" / "news"
    ioc_root = root / "daily-news" / "iocs"
    if not news_root.is_dir() or not ioc_root.is_dir():
        raise DailyOrchestrationError(
            "news_source_layout_invalid",
            "tech-memoにdaily-news/newsとdaily-news/iocsがありません",
        )
    candidates: dict[str, dict[str, list[Path]]] = {}
    observed = 0
    for kind, search_root, suffix in (
        ("news", news_root, ".md"),
        ("ioc_csv", ioc_root, ".csv"),
        ("ioc_log", ioc_root, ".md"),
    ):
        for path in _bounded_tree_files(search_root):
            if path.suffix.casefold() != suffix:
                continue
            observed += 1
            _reject_reparse_components(path, label="日次source")
            if not _regular_file_without_reparse(path):
                continue
            compact = path.stem
            try:
                source_date = datetime.strptime(compact, "%Y%m%d").date().isoformat()
            except ValueError:
                continue
            record = candidates.setdefault(
                source_date,
                {"news": [], "ioc_csv": [], "ioc_log": []},
            )
            record[kind].append(path)
    complete: list[tuple[str, dict[str, list[Path]]]] = []
    for source_date, record in candidates.items():
        if all(len(record[name]) == 1 for name in ("news", "ioc_csv", "ioc_log")):
            complete.append((source_date, record))
        elif all(record[name] for name in ("news", "ioc_csv", "ioc_log")):
            raise DailyOrchestrationError(
                "news_source_ambiguous",
                f"{source_date}の日次sourceが複数存在します",
            )
    if not complete:
        raise DailyOrchestrationError(
            "news_source_missing",
            "完全な日次news／IOC CSV／IOC logがありません",
        )
    source_date, record = max(complete, key=lambda item: item[0])
    result = {
        "schema_version": 1,
        "source_date": source_date,
        "files": {
            name: paths[0].relative_to(root).as_posix()
            for name, paths in sorted(record.items())
        },
        "network_contacted": False,
    }
    verified = verify_news_source_date(root, source_date)
    result["source_manifest_sha256"] = verified["source_manifest_sha256"]
    return result


def verify_news_source_date(tech_memo: Path, source_date: str) -> dict[str, Any]:
    """指定日の3点sourceを通常file identityとSHA-256へ固定する。"""

    root = _absolute(tech_memo)
    _reject_reparse_components(root, label="tech-memo")
    root = _canonical_path(root)
    normalized = _iso_date(source_date, label="news_source_date")
    compact = normalized.replace("-", "")
    specifications = (
        ("news", root / "daily-news" / "news", ".md"),
        ("ioc_csv", root / "daily-news" / "iocs", ".csv"),
        ("ioc_log", root / "daily-news" / "iocs", ".md"),
    )
    records: list[dict[str, Any]] = []
    for role, search_root, suffix in specifications:
        if not search_root.is_dir():
            raise DailyOrchestrationError(
                "news_source_layout_invalid",
                "tech-memoの日次source配置が不正です",
            )
        candidates = [
            path
            for path in _bounded_tree_files(search_root)
            if path.name == f"{compact}{suffix}"
        ]
        if len(candidates) != 1:
            raise DailyOrchestrationError(
                "news_source_incomplete",
                f"{normalized}の{role}が一意に存在しません",
            )
        path = candidates[0]
        _reject_reparse_components(path, label="日次source")
        if not _regular_file_without_reparse(path):
            raise DailyOrchestrationError(
                "news_source_invalid",
                f"{normalized}の{role}が空でない通常fileではありません",
            )
        try:
            raw = analysis_job_runner._read_regular_file_once(
                path,
                max_bytes=DAILY_SOURCE_MAX_FILE_BYTES,
            )
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise DailyOrchestrationError(
                "news_source_invalid",
                f"{normalized}の{role}を安全な単一handleへ固定できません",
            ) from exc
        records.append(
            {
                "role": role,
                "path": path.relative_to(root).as_posix(),
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return {
        "schema_version": 1,
        "source_date": normalized,
        "files": records,
        "source_manifest_sha256": _sha256_value(records),
        "network_contacted": False,
    }


def _validate_context(
    request: DailyRequest,
    *,
    repository: Path,
    intelligence_root: Path,
    private_root: Path,
    work_root: Path,
    ghidra_project_store: Path,
    allow_live_c2: bool,
    create_roots: bool,
) -> DailyContext:
    repository = _absolute(repository)
    intelligence_root = _absolute(intelligence_root)
    private_root = _absolute(private_root)
    work_root = _absolute(work_root)
    ghidra_project_store = _absolute(ghidra_project_store)
    for label, path in (
        ("repository", repository),
        ("intelligence root", intelligence_root),
        ("private root", private_root),
        ("work root", work_root),
        ("Ghidra project store", ghidra_project_store),
    ):
        _reject_reparse_components(path, label=label)
    repository = _canonical_path(repository)
    intelligence_root = _canonical_path(intelligence_root)
    private_root = _canonical_path(private_root)
    work_root = _canonical_path(work_root)
    ghidra_project_store = _canonical_path(ghidra_project_store)
    if not repository.is_dir():
        raise DailyOrchestrationError("repository_invalid", "repositoryが通常directoryではありません")
    if any(
        _overlaps(left, right)
        for left, right in (
            (repository, private_root),
            (repository, work_root),
            (repository, ghidra_project_store),
            (private_root, work_root),
            (private_root, ghidra_project_store),
            (work_root, ghidra_project_store),
        )
    ):
        raise DailyOrchestrationError(
            "root_overlap",
            "repository、private root、work root、Ghidra project storeは相互に分離してください",
        )
    memo = intelligence_root.joinpath(*PurePosixPath(request.tech_memo).parts)
    _reject_reparse_components(memo, label="tech-memo")
    try:
        resolved_memo = memo.resolve(strict=True)
    except OSError as exc:
        raise DailyOrchestrationError("tech_memo_missing", "tech-memo入力がありません") from exc
    if not resolved_memo.is_file() and not resolved_memo.is_dir():
        raise DailyOrchestrationError("tech_memo_invalid", "tech-memo入力が通常fileまたはdirectoryではありません")
    if intelligence_root != resolved_memo and intelligence_root not in resolved_memo.parents:
        raise DailyOrchestrationError("tech_memo_invalid", "tech-memo入力がintelligence root外です")
    if any(
        _overlaps(resolved_memo, root)
        for root in (private_root, work_root, ghidra_project_store)
    ):
        raise DailyOrchestrationError(
            "tech_memo_overlap",
            "tech-memo入力をprivate／work／Ghidra project rootと分離してください",
        )
    if request.network["c2_monitoring"] and not allow_live_c2 and create_roots:
        raise DailyOrchestrationError(
            "live_c2_not_authorized",
            "C2ライブ監視には現在の実行で--allow-live-c2も必要です",
        )
    if create_roots:
        for root in (private_root, work_root, ghidra_project_store):
            root.mkdir(parents=True, exist_ok=True)
            _reject_reparse_components(root, label="作業root")
            if _canonical_path(root) != root:
                raise DailyOrchestrationError(
                    "root_identity_changed",
                    "作業rootのcanonical identityが作成中に変化しました",
                )
    for label, root in (
        ("private root", private_root),
        ("work root", work_root),
        ("Ghidra project store", ghidra_project_store),
    ):
        if root.exists() and not root.is_dir():
            raise DailyOrchestrationError("root_invalid", f"{label}が通常directoryではありません")
    state_root = work_root / "daily-orchestrations" / request.run_id
    context = DailyContext(
        repository=repository,
        intelligence_root=intelligence_root,
        private_root=private_root,
        work_root=work_root,
        state_root=state_root,
        ghidra_project_store=ghidra_project_store,
        request=request,
        allow_live_c2=allow_live_c2,
    )
    _validate_context_derived_paths(context)
    return context


def _validate_derived_path(
    path: Path,
    *,
    root: Path,
    label: str,
) -> Path:
    absolute = _absolute(path)
    _reject_reparse_components(absolute, label=label)
    canonical = _canonical_path(absolute)
    if canonical != root and root not in canonical.parents:
        raise DailyOrchestrationError(
            "derived_path_escape",
            f"{label}が管理root外です",
        )
    if canonical.exists() and not canonical.is_dir():
        raise DailyOrchestrationError(
            "derived_path_invalid",
            f"{label}が通常directoryではありません",
        )
    return canonical


def _validate_context_derived_paths(context: DailyContext) -> None:
    """書込み対象の派生rootを毎stage前に再検証する。"""

    paths = (
        (context.orchestration_root, context.work_root, "orchestration root"),
        (context.state_root, context.work_root, "state root"),
        (context.jobs_root, context.work_root, "jobs root"),
        (context.ghidra_sample_root, context.work_root, "Ghidra sample root"),
        (context.source_root, context.private_root, "MalwareBazaar source root"),
        (context.collection_root, context.private_root, "collection private root"),
        (
            context.ghidra_private_output,
            context.private_root,
            "Ghidra private output",
        ),
        (context.maxmind_cache, context.private_root, "MaxMind cache"),
        (
            context.daily_news_private_output,
            context.private_root,
            "daily news private output",
        ),
    )
    for path, root, label in paths:
        if _validate_derived_path(path, root=root, label=label) != path:
            raise DailyOrchestrationError(
                "derived_path_identity_changed",
                f"{label}のcanonical identityが変化しました",
            )


def draft_request_document(
    *,
    intelligence_root: Path,
    tech_memo: str,
    analysis_date: str,
    run_id: str | None,
    malwarebazaar_count: int,
) -> dict[str, Any]:
    """最新完全sourceからstrictな標準日次requestを生成する。"""

    normalized_tech_memo = _relative_repository_file(tech_memo)
    normalized_date = _iso_date(analysis_date, label="analysis_date")
    root = _absolute(intelligence_root)
    _reject_reparse_components(root, label="intelligence root")
    root = _canonical_path(root)
    memo = root.joinpath(
        *PurePosixPath(normalized_tech_memo).parts
    )
    _reject_reparse_components(memo, label="tech-memo")
    canonical_memo = _canonical_path(memo)
    if root != canonical_memo and root not in canonical_memo.parents:
        raise DailyOrchestrationError(
            "tech_memo_invalid",
            "tech-memo入力がintelligence root外です",
        )
    source = discover_latest_news_source(canonical_memo)
    document = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id or f"daily-{normalized_date.replace('-', '')}",
        "analysis_date": normalized_date,
        "news_source_date": source["source_date"],
        "source_manifest_sha256": source["source_manifest_sha256"],
        "malwarebazaar_count": malwarebazaar_count,
        "tech_memo": normalized_tech_memo,
        "stages": {name: True for name in STAGES},
        "network": {
            "provider_lookups": True,
            "sample_download": True,
            "c2_monitoring": True,
            "datastore_upload": True,
        },
        "limits": {
            "query_limit": max(200, malwarebazaar_count),
            "static_timeout_seconds": 14_400,
            "ghidra_minimum_free_bytes": 8 * 1024 * 1024 * 1024,
            "ghidra_max_new_programs": 4,
        },
    }
    return validate_request_object(document).public()


def _pending_capacity_stages(
    context: DailyContext,
    state: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    pending: list[str] = []
    for name in STAGES:
        if not context.request.stages[name]:
            continue
        if state is None:
            pending.append(name)
            continue
        stages = state.get("stages")
        record = stages.get(name) if isinstance(stages, Mapping) else None
        if not isinstance(record, Mapping):
            raise DailyOrchestrationError(
                "state_invalid",
                "容量preflightで日次stage状態を確認できません",
            )
        if record.get("status") in {"complete", "skipped"}:
            continue
        if record.get("status") == "partial" and record.get("retryable") is False:
            continue
        pending.append(name)
    return tuple(pending)


def _existing_directory_ancestor(path: Path) -> Path:
    current = _absolute(path)
    while not os.path.lexists(current):
        parent = current.parent
        if parent == current:
            raise DailyOrchestrationError(
                "capacity_path_invalid",
                "容量確認対象の既存parentがありません",
            )
        current = parent
    if not current.is_dir():
        raise DailyOrchestrationError(
            "capacity_path_invalid",
            "容量確認対象の既存parentがdirectoryではありません",
        )
    _reject_reparse_components(current, label="容量確認対象")
    return _canonical_path(current)


def _archive_preflight_source_bytes(
    path: Path,
    *,
    projected_bytes: int,
    producer_pending: bool,
) -> int:
    """既存treeの実測値と未完stageの最大見積りからstaging必要量を返す。"""

    actual = 0
    if os.path.lexists(path):
        if not path.is_dir():
            raise DailyOrchestrationError(
                "archive_source_type_invalid",
                "archive preflight対象は通常directoryである必要があります",
            )
        actual = _tree_size(path)
    if producer_pending:
        return actual + projected_bytes
    if not os.path.lexists(path):
        return projected_bytes
    return actual


def _projected_archive_staging_bytes(
    context: DailyContext,
    pending: tuple[str, ...],
) -> int:
    """対象別archiveを同時に複製できる安全側のstaging byte数を算定する。"""

    count = context.request.malwarebazaar_count
    candidates: list[int] = []
    if context.request.stages["news_intake"]:
        news_projection = 8 * MIB
        if context.request.network["provider_lookups"]:
            news_projection += 32 * MIB
        if context.request.network["sample_download"]:
            news_projection += count * (
                PREFLIGHT_SAMPLE_ARCHIVE_BYTES + PREFLIGHT_ANALYSIS_BYTES
            )
        candidates.append(
            _archive_preflight_source_bytes(
                context.daily_news_private_output,
                projected_bytes=news_projection,
                producer_pending="news_intake" in pending,
            )
        )
    if context.request.stages["malwarebazaar_acquisition"]:
        candidates.append(
            _archive_preflight_source_bytes(
                context.source_root,
                projected_bytes=count * PREFLIGHT_SAMPLE_ARCHIVE_BYTES,
                producer_pending="malwarebazaar_acquisition" in pending,
            )
        )
    if context.request.stages["static_analysis"]:
        job_path: Path | None = None
        if "malwarebazaar_acquisition" not in pending:
            request, _identity = _static_request(context)
            job_path = context.jobs_root / request.job_id
        candidates.append(
            _archive_preflight_source_bytes(
                job_path if job_path is not None else context.jobs_root / ".pending-daily-job",
                projected_bytes=count * PREFLIGHT_ANALYSIS_BYTES,
                producer_pending="static_analysis" in pending,
            )
        )
    if context.request.stages["ghidra"]:
        candidates.append(
            _archive_preflight_source_bytes(
                context.ghidra_private_output,
                projected_bytes=count * PREFLIGHT_ANALYSIS_BYTES,
                producer_pending="ghidra" in pending,
            )
        )
    return PREFLIGHT_ARCHIVE_STAGING_BYTES + max(candidates, default=0)


def build_capacity_preflight(
    context: DailyContext,
    state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """全出力先をfilesystem単位へ集約し、network接触前の容量を判定する。"""

    pending = _pending_capacity_stages(context, state)
    count = context.request.malwarebazaar_count
    requirements: list[tuple[str, Path, int]] = []

    def add(role: str, path: Path, required: int) -> None:
        if required > 0:
            requirements.append((role, path, required))

    if "news_intake" in pending:
        add("repository_publication", context.repository, 64 * MIB)
        if context.request.network["provider_lookups"]:
            add("provider_cache", context.private_root, 32 * MIB)
        if context.request.network["sample_download"]:
            add(
                "news_private_samples",
                context.private_root,
                count * (PREFLIGHT_SAMPLE_ARCHIVE_BYTES + PREFLIGHT_ANALYSIS_BYTES),
            )
    if "malwarebazaar_acquisition" in pending:
        add(
            "malwarebazaar_source",
            context.private_root,
            count * PREFLIGHT_SAMPLE_ARCHIVE_BYTES,
        )
    if (
        context.request.network["sample_download"]
        and (
            "news_intake" in pending
            or "malwarebazaar_acquisition" in pending
        )
    ):
        add(
            "sample_download_reserve",
            context.private_root,
            SAMPLE_DOWNLOAD_MINIMUM_FREE_BYTES,
        )
    if "static_analysis" in pending:
        add("static_work", context.work_root, count * PREFLIGHT_ANALYSIS_BYTES)
    if "publication" in pending:
        add("repository_collection", context.repository, PREFLIGHT_REPOSITORY_BYTES)
    if "ghidra" in pending:
        add(
            "ghidra_project_reserve",
            context.ghidra_project_store,
            int(context.request.limits["ghidra_minimum_free_bytes"]),
        )
        add(
            "ghidra_private_results",
            context.private_root,
            count * PREFLIGHT_ANALYSIS_BYTES,
        )
    if "c2_monitoring" in pending:
        add("repository_c2_results", context.repository, 128 * MIB)
        add("maxmind_cache", context.private_root, PREFLIGHT_C2_PRIVATE_BYTES)
    if "validation" in pending:
        add("repository_validation_margin", context.repository, 64 * MIB)
    if "private_archive" in pending:
        add(
            "archive_staging",
            Path(tempfile.gettempdir()),
            _projected_archive_staging_bytes(context, pending),
        )

    groups: dict[int, dict[str, Any]] = {}
    for role, path, required in requirements:
        existing = _existing_directory_ancestor(path)
        try:
            device = int(existing.stat().st_dev)
            free = int(shutil.disk_usage(existing).free)
        except OSError as exc:
            raise DailyOrchestrationError(
                "capacity_probe_failed",
                "filesystemの空き容量を確認できません",
            ) from exc
        group = groups.setdefault(
            device,
            {"roles": set(), "required_free_bytes": 0, "free_bytes": free},
        )
        group["roles"].add(role)
        group["required_free_bytes"] += required
        group["free_bytes"] = min(group["free_bytes"], free)

    ordered = sorted(groups.values(), key=lambda item: sorted(item["roles"]))
    filesystems: list[dict[str, Any]] = []
    for index, group in enumerate(ordered, start=1):
        required = int(group["required_free_bytes"])
        free = int(group["free_bytes"])
        filesystems.append(
            {
                "filesystem": f"filesystem-{index}",
                "roles": sorted(group["roles"]),
                "required_free_bytes": required,
                "free_bytes": free,
                "shortfall_bytes": max(0, required - free),
            }
        )
    recovery = sum(item["shortfall_bytes"] for item in filesystems)
    return {
        "schema_version": 1,
        "ready": recovery == 0,
        "pending_stages": list(pending),
        "filesystems": filesystems,
        "required_recovery_bytes": recovery,
        "automatic_source_deletion": False,
        "sample_execution": False,
        "network_contacted": False,
    }


def build_preflight_report(
    context: DailyContext,
    state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    capacity = build_capacity_preflight(context, state)
    pending = _pending_capacity_stages(context, state)
    source = (
        _verify_context_news_source(context)
        if "news_intake" in pending
        else {
            "schema_version": 1,
            "source_date": context.request.news_source_date,
            "required_for_pending_stages": False,
            "network_contacted": False,
        }
    )
    live_required = bool(context.request.network["c2_monitoring"])
    provider_required = (
        "news_intake" in pending
        and context.request.network["provider_lookups"]
    )
    sample_credential_required = (
        context.request.network["sample_download"]
        and bool(
            {"news_intake", "malwarebazaar_acquisition"}.intersection(pending)
        )
    )
    provider_ready = not provider_required or bool(
        os.environ.get("MALWAREBAZAAR_AUTH_KEY") or os.environ.get("VT_API_KEY")
    )
    sample_credential_ready = not sample_credential_required or bool(
        os.environ.get("MALWAREBAZAAR_AUTH_KEY")
    )
    datastore_required = (
        "private_archive" in pending
        and context.request.network["datastore_upload"]
    )
    datastore_tool_ready = True
    if datastore_required:
        try:
            import archive_analysis_datastore

            archive_analysis_datastore.find_aws_cli()
        except (ImportError, RuntimeError):
            datastore_tool_ready = False
    authorization_ready = (
        (not live_required or context.allow_live_c2)
        and provider_ready
        and sample_credential_ready
        and datastore_tool_ready
    )
    return {
        "schema_version": 1,
        "run_id": context.request.run_id,
        "ready": capacity["ready"] and authorization_ready,
        "source": source,
        "capacity": capacity,
        "authorization": {
            "live_c2_required": live_required,
            "live_c2_authorized_for_invocation": context.allow_live_c2,
            "provider_credential_required": provider_required,
            "provider_credential_ready": provider_ready,
            "sample_download_credential_required": sample_credential_required,
            "sample_download_credential_ready": sample_credential_ready,
            "datastore_tool_required": datastore_required,
            "datastore_tool_ready": datastore_tool_ready,
            "ready": authorization_ready,
        },
        "safety": _expected_safety(),
    }


def build_plan(
    request: DailyRequest,
    *,
    preflight: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """副作用前に固定stageとnetwork境界を表示する。"""

    network_stage = {
        "news_intake": request.network["provider_lookups"],
        "malwarebazaar_acquisition": request.network["sample_download"],
        "static_analysis": False,
        "publication": False,
        "ghidra": False,
        "c2_monitoring": request.network["c2_monitoring"],
        "validation": False,
        "private_archive": request.network["datastore_upload"],
    }
    repository_write = {
        "news_intake": True,
        "malwarebazaar_acquisition": False,
        "static_analysis": False,
        "publication": True,
        "ghidra": True,
        "c2_monitoring": True,
        "validation": False,
        "private_archive": False,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": request.run_id,
        "request_sha256": _sha256_value(request.public()),
        "execution": {
            "mode": "sequential_checkpointed",
            "maximum_parallel_stages": 1,
            "continue_after_partial": True,
            "preflight_before_network": True,
            "bounded_drive_supported": True,
            "automatic_source_deletion": False,
            "sample_execution": False,
            "arbitrary_command_execution": False,
        },
        "stages": [
            {
                "name": name,
                "enabled": request.stages[name],
                "position": index,
                "network_enabled": network_stage[name],
                "repository_write": repository_write[name],
            }
            for index, name in enumerate(STAGES, start=1)
        ],
        **({"preflight": dict(preflight)} if preflight is not None else {}),
    }


def _new_state(context: DailyContext) -> dict[str, Any]:
    now = _utc_now()
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "run_id": context.request.run_id,
        "request_sha256": _sha256_value(context.request.public()),
        "implementation_sha256": _implementation_sha256(),
        "status": "running",
        "created_at_utc": now,
        "updated_at_utc": now,
        "stages": {
            name: {
                "status": "pending" if context.request.stages[name] else "skipped",
                "attempts": 0,
                "retryable": False,
                "result": {},
                "error": None,
            }
            for name in STAGES
        },
        "capacity_remediation": None,
        "safety": _expected_safety(),
    }


def _expected_safety() -> dict[str, bool]:
    return {
        "sample_executed": False,
        "arbitrary_command_executed": False,
        "automatic_source_deletion": False,
        "source_retained_after_archive": True,
    }


def _capacity_semantics_valid(value: Any) -> bool:
    return value is None or (
        isinstance(value, Mapping)
        and value.get("automatic_source_deletion") is False
        and value.get("source_deletion_supported") is False
        and value.get("user_approval_required_for_material_deletion") is True
    )


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    if len(payload) > MAX_STATE_BYTES:
        raise DailyOrchestrationError("state_too_large", "日次stateがsize上限を超えています")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
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
        if os.path.lexists(temporary):
            temporary.unlink()


def _write_state(context: DailyContext, state: dict[str, Any]) -> None:
    _validate_context_derived_paths(context)
    state["updated_at_utc"] = _utc_now()
    _atomic_json(context.state_root / "state.json", state)


def _load_state(context: DailyContext) -> dict[str, Any]:
    path = context.state_root / "state.json"
    try:
        state = analysis_job_runner.load_json_object_strict(path, max_bytes=MAX_STATE_BYTES)
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise DailyOrchestrationError("state_invalid", "保存済み日次stateを安全に読めません") from exc
    if (
        set(state) != STATE_KEYS
        or state.get("schema_version") != STATE_SCHEMA_VERSION
        or state.get("run_id") != context.request.run_id
        or state.get("request_sha256") != _sha256_value(context.request.public())
        or state.get("implementation_sha256") != _implementation_sha256()
        or not isinstance(state.get("stages"), Mapping)
        or set(state["stages"]) != set(STAGES)
    ):
        raise DailyOrchestrationError(
            "state_contract_changed",
            "保存済み日次stateとrequestまたは実装契約が一致しません",
        )
    try:
        saved_request = analysis_job_runner.load_json_object_strict(
            context.state_root / "request.json",
            max_bytes=analysis_job_runner.MAX_REQUEST_BYTES,
        )
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise DailyOrchestrationError(
            "state_request_invalid",
            "保存済み日次requestを安全に読めません",
        ) from exc
    if saved_request != context.request.public():
        raise DailyOrchestrationError(
            "state_request_changed",
            "保存済み日次requestが現在のrequestと一致しません",
        )
    if (
        state.get("safety") != _expected_safety()
        or state.get("status") not in {"running", "partial", "complete", "failed"}
        or not isinstance(state.get("created_at_utc"), str)
        or not isinstance(state.get("updated_at_utc"), str)
        or not _capacity_semantics_valid(state.get("capacity_remediation"))
    ):
        raise DailyOrchestrationError(
            "state_semantics_invalid",
            "保存済み日次stateの安全値または全体状態が不正です",
        )
    for name in STAGES:
        record = state["stages"][name]
        if (
            not isinstance(record, Mapping)
            or set(record) != {"status", "attempts", "retryable", "result", "error"}
            or record.get("status") not in {"pending", "running", "complete", "partial", "failed", "skipped"}
            or type(record.get("attempts")) is not int
            or not 0 <= record["attempts"] <= MAX_STAGE_ATTEMPTS.get(name, MAX_ATTEMPTS)
            or type(record.get("retryable")) is not bool
            or not isinstance(record.get("result"), Mapping)
            or record.get("error") is not None
            and not isinstance(record.get("error"), Mapping)
        ):
            raise DailyOrchestrationError("state_invalid", "保存済みstage状態が不正です")
        if (
            context.request.stages[name] is False
            and (
                record["status"] != "skipped"
                or record["attempts"] != 0
                or record["retryable"] is not False
                or record["result"] != {}
                or record["error"] is not None
            )
        ):
            raise DailyOrchestrationError(
                "state_stage_mismatch",
                "無効stageの保存状態がrequestと一致しません",
            )
        if context.request.stages[name] is True and record["status"] == "skipped":
            raise DailyOrchestrationError(
                "state_stage_mismatch",
                "有効stageがskippedになっています",
            )
        if record["status"] == "complete" and record["retryable"] is not False:
            raise DailyOrchestrationError(
                "state_stage_mismatch",
                "完了stageが再試行可能になっています",
            )
        if record["status"] == "failed":
            error = record["error"]
            if (
                not isinstance(error, Mapping)
                or set(error) != {"code", "message"}
                or not all(isinstance(error.get(key), str) and error.get(key) for key in error)
            ):
                raise DailyOrchestrationError(
                    "state_stage_mismatch",
                    "失敗stageのerror契約が不正です",
                )
        elif record["error"] is not None:
            raise DailyOrchestrationError(
                "state_stage_mismatch",
                "失敗以外のstageにerrorが残っています",
            )
        if record["status"] == "running":
            record["status"] = "pending"
            record["retryable"] = True
    statuses = [state["stages"][name]["status"] for name in STAGES]
    expected_status = (
        "running"
        if state["status"] == "running"
        else "failed"
        if "failed" in statuses
        else "partial"
        if any(value in {"pending", "running", "partial"} for value in statuses)
        else "complete"
    )
    if state["status"] != expected_status:
        raise DailyOrchestrationError(
            "state_status_mismatch",
            "日次state全体とstage状態が一致しません",
        )
    return state


def _capacity_remediation(outcome: StageOutcome) -> dict[str, Any] | None:
    if (
        outcome.status == "partial"
        and outcome.result.get("status") == "archive_staging_capacity_insufficient"
    ):
        required = outcome.result.get("required_staging_bytes")
        reserve = outcome.result.get("minimum_reserve_bytes")
        free = outcome.result.get("observed_free_bytes")
        minimum = (
            required + reserve
            if type(required) is int and type(reserve) is int
            else None
        )
        deficit = (
            max(0, minimum - free)
            if type(minimum) is int and type(free) is int
            else None
        )
        return {
            "reason": "archive_staging_capacity_insufficient",
            "minimum_free_bytes": minimum,
            "lowest_observed_free_bytes": free if type(free) is int else None,
            "required_recovery_bytes": deficit,
            "automatic_source_deletion": False,
            "source_deletion_supported": False,
            "user_approval_required_for_material_deletion": True,
            "safe_next_actions": [
                "別volumeをarchive stagingに利用できる構成へ変更する",
                "非破壊の圧縮または追加volumeを検討する",
                "容量回復後に同じrequestでresumeする",
            ],
        }
    if outcome.status != "partial" or outcome.result.get("stop_reason") != "minimum_free_space_not_met":
        return None
    disk = outcome.result.get("disk_space")
    if not isinstance(disk, Mapping):
        return None
    minimum = disk.get("minimum_free_bytes")
    filesystems = disk.get("filesystems")
    global_planned = disk.get("planned_write_bytes")
    global_planned = global_planned if type(global_planned) is int and global_planned >= 0 else 0
    free_values: list[int] = []
    deficits: list[int] = []
    if isinstance(filesystems, list) and type(minimum) is int:
        for item in filesystems:
            if not isinstance(item, Mapping) or type(item.get("free_bytes")) is not int:
                continue
            free = item["free_bytes"]
            planned = item.get("planned_write_bytes", 0)
            planned = planned if type(planned) is int and planned >= 0 else 0
            free_values.append(free)
            deficits.append(max(0, minimum + planned - free))
    lowest = min(free_values) if free_values else None
    deficit = sum(deficits) if deficits else None
    return {
        "reason": "minimum_free_space_not_met",
        "minimum_free_bytes": minimum if type(minimum) is int else None,
        "lowest_observed_free_bytes": lowest,
        "required_recovery_bytes": deficit,
        "planned_write_bytes": global_planned,
        "automatic_source_deletion": False,
        "source_deletion_supported": False,
        "user_approval_required_for_material_deletion": True,
        "safe_next_actions": [
            "S3検証済みreportと対象を照合する",
            "非破壊の圧縮または別volumeへの新規出力を検討する",
            "容量回復後に同じrequestでresumeする",
        ],
    }


def _preflight_remediation(report: Mapping[str, Any]) -> dict[str, Any]:
    filesystems = report.get("filesystems")
    recovery = report.get("required_recovery_bytes")
    if (
        report.get("ready") is not False
        or type(recovery) is not int
        or recovery <= 0
        or not isinstance(filesystems, list)
    ):
        raise DailyOrchestrationError(
            "capacity_report_invalid",
            "容量preflight結果が不正です",
        )
    normalized: list[dict[str, Any]] = []
    for item in filesystems:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("filesystem"), str)
            or not isinstance(item.get("roles"), list)
            or any(not isinstance(role, str) for role in item["roles"])
            or type(item.get("required_free_bytes")) is not int
            or type(item.get("free_bytes")) is not int
            or type(item.get("shortfall_bytes")) is not int
        ):
            raise DailyOrchestrationError(
                "capacity_report_invalid",
                "容量preflightのfilesystem結果が不正です",
            )
        normalized.append(
            {
                "filesystem": item["filesystem"],
                "roles": list(item["roles"]),
                "required_free_bytes": item["required_free_bytes"],
                "free_bytes": item["free_bytes"],
                "shortfall_bytes": item["shortfall_bytes"],
            }
        )
    return {
        "reason": "preflight_capacity_insufficient",
        "minimum_free_bytes": max(
            (item["required_free_bytes"] for item in normalized),
            default=None,
        ),
        "lowest_observed_free_bytes": min(
            (item["free_bytes"] for item in normalized),
            default=None,
        ),
        "required_recovery_bytes": recovery,
        "filesystems": normalized,
        "automatic_source_deletion": False,
        "source_deletion_supported": False,
        "user_approval_required_for_material_deletion": True,
        "safe_next_actions": [
            "12 GiB以上の追加volumeへprivate／work／Ghidra rootを分離する",
            "再生成可能dataは非破壊圧縮を優先する",
            "source削除は行わず、容量回復後に同じrequestでresumeする",
        ],
    }


def _apply_capacity_preflight(
    context: DailyContext,
    state: dict[str, Any],
    capacity_probe: Callable[
        [DailyContext, Mapping[str, Any] | None],
        Mapping[str, Any],
    ],
) -> bool:
    report = capacity_probe(context, state)
    if report.get("ready") is True:
        state["capacity_remediation"] = None
        return True
    state["capacity_remediation"] = _preflight_remediation(report)
    statuses = [state["stages"][name]["status"] for name in STAGES]
    state["status"] = "failed" if "failed" in statuses else "partial"
    _write_state(context, state)
    return False


def _verify_pending_news_source(
    context: DailyContext,
    state: Mapping[str, Any] | None,
) -> None:
    if "news_intake" not in _pending_capacity_stages(context, state):
        return
    _verify_context_news_source(context)


def _verify_context_news_source(context: DailyContext) -> dict[str, Any]:
    memo = context.intelligence_root.joinpath(
        *PurePosixPath(context.request.tech_memo).parts
    )
    source = verify_news_source_date(memo, context.request.news_source_date)
    if source["source_manifest_sha256"] != context.request.source_manifest_sha256:
        raise DailyOrchestrationError(
            "news_source_changed",
            "日次source三点のSHA-256 commitmentがrequest作成後に変化しました",
        )
    return source


def _collection_binding(context: DailyContext) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "collection_id": context.collection_id,
        "run_id": context.request.run_id,
        "request_sha256": _sha256_value(context.request.public()),
        "implementation_sha256": _implementation_sha256(),
        "source_manifest_sha256": context.request.source_manifest_sha256,
        "automatic_source_deletion": False,
    }


def _ensure_collection_binding(
    context: DailyContext,
    *,
    create: bool,
) -> None:
    """同日同件数collectionを単一run／実装契約へ所有権固定する。"""

    expected = _collection_binding(context)
    root = context.collection_root
    binding_path = root / "collection-binding.json"
    _validate_context_derived_paths(context)
    if binding_path.is_file():
        try:
            observed = analysis_job_runner.load_json_object_strict(
                binding_path,
                max_bytes=analysis_job_runner.MAX_REQUEST_BYTES,
            )
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise DailyOrchestrationError(
                "collection_binding_invalid",
                "collection ownership bindingを安全に読めません",
            ) from exc
        if observed != expected:
            raise DailyOrchestrationError(
                "collection_owned_by_other_run",
                "同じcollection IDが別runまたは実装契約に所有されています",
            )
        return
    if root.exists():
        try:
            with os.scandir(root) as iterator:
                has_entries = next(iterator, None) is not None
        except OSError as exc:
            raise DailyOrchestrationError(
                "collection_binding_invalid",
                "collection private rootを安全に確認できません",
            ) from exc
        if has_entries:
            raise DailyOrchestrationError(
                "collection_binding_missing",
                "既存collection dataにownership bindingがありません",
            )
    if not create:
        raise DailyOrchestrationError(
            "collection_binding_missing",
            "collection ownership bindingがありません",
        )
    root.mkdir(parents=True, exist_ok=True)
    _validate_context_derived_paths(context)
    _atomic_json(binding_path, expected)
    _validate_context_derived_paths(context)


@contextmanager
def _run_lock(context: DailyContext) -> Iterator[None]:
    """全daily runのrepository／private更新をOS lockで直列化する。"""

    _validate_context_derived_paths(context)
    lock_root = _absolute(Path(tempfile.gettempdir()) / "ai-security-analysis-locks")
    _reject_reparse_components(lock_root, label="global run lock root")
    lock_root.mkdir(parents=True, exist_ok=True)
    _reject_reparse_components(lock_root, label="global run lock root")
    lock_root = _canonical_path(lock_root)
    repository_key = hashlib.sha256(
        os.path.normcase(os.fspath(context.repository)).encode("utf-8")
    ).hexdigest()[:32]
    lock_path = lock_root / f"{repository_key}.lock"
    _reject_reparse_components(lock_path, label="run lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise DailyOrchestrationError(
            "run_lock_failed",
            "日次run lockを安全に開けません",
        ) from exc
    acquired = False
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or information.st_size not in {0, 1}
        ):
            raise DailyOrchestrationError(
                "run_lock_invalid",
                "日次run lockのfile identityが不正です",
            )
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
        except OSError as exc:
            raise DailyOrchestrationError(
                "run_locked",
                "別の日次解析が同じrepositoryで実行中です",
            ) from exc
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
            except OSError:
                pass
        os.close(descriptor)


def _execute(context: DailyContext, state: dict[str, Any], actions: DailyActions) -> dict[str, Any]:
    checkpoint_after_failure = False
    for name in STAGES:
        if checkpoint_after_failure and name != "private_archive":
            continue
        _validate_context_derived_paths(context)
        record = state["stages"][name]
        if record["status"] in {"complete", "skipped"}:
            continue
        if record["status"] == "partial" and record["retryable"] is False:
            continue
        if record["attempts"] >= MAX_STAGE_ATTEMPTS.get(name, MAX_ATTEMPTS):
            record["status"] = "failed"
            record["error"] = {
                "code": "maximum_attempts_exceeded",
                "message": "stageの最大試行回数を超えました",
            }
            _write_state(context, state)
            if (
                name != "private_archive"
                and context.request.stages["private_archive"]
                and context.request.network["datastore_upload"]
            ):
                checkpoint_after_failure = True
                continue
            break
        record["status"] = "running"
        record["attempts"] += 1
        record["error"] = None
        _write_state(context, state)
        try:
            outcome = getattr(actions, name)(context)
            if outcome.status not in {"complete", "partial"}:
                raise DailyOrchestrationError(
                    "stage_outcome_invalid",
                    "stage adapterが不正な状態を返しました",
                )
            record["status"] = outcome.status
            record["retryable"] = outcome.retryable
            record["result"] = dict(outcome.result)
            remediation = _capacity_remediation(outcome)
            if remediation is not None:
                state["capacity_remediation"] = remediation
        except DailyOrchestrationError as exc:
            record["status"] = "failed"
            record["retryable"] = True
            record["result"] = {}
            record["error"] = {"code": exc.code, "message": str(exc)}
            _write_state(context, state)
            if (
                name != "private_archive"
                and context.request.stages["private_archive"]
                and context.request.network["datastore_upload"]
            ):
                checkpoint_after_failure = True
                continue
            break
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            record["status"] = "failed"
            record["retryable"] = True
            record["result"] = {}
            record["error"] = {
                "code": "stage_execution_failed",
                "message": f"{name}を安全に完了できませんでした: {type(exc).__name__}",
            }
            _write_state(context, state)
            if (
                name != "private_archive"
                and context.request.stages["private_archive"]
                and context.request.network["datastore_upload"]
            ):
                checkpoint_after_failure = True
                continue
            break
        _validate_context_derived_paths(context)
        _write_state(context, state)
    statuses = [state["stages"][name]["status"] for name in STAGES]
    state["status"] = (
        "failed"
        if "failed" in statuses
        else "partial"
        if any(value in {"pending", "running", "partial"} for value in statuses)
        else "complete"
    )
    _write_state(context, state)
    return state


def _run_daily_unlocked(
    context: DailyContext,
    *,
    actions: DailyActions,
    capacity_probe: Callable[
        [DailyContext, Mapping[str, Any] | None],
        Mapping[str, Any],
    ] = build_capacity_preflight,
) -> dict[str, Any]:
    """新しい日次実行を開始し、同じrun IDを上書きしない。"""

    if context.state_root.exists():
        raise DailyOrchestrationError("run_exists", "同じrun_idの日次stateが既にあります")
    _validate_context_derived_paths(context)
    _verify_pending_news_source(context, None)
    _ensure_collection_binding(context, create=True)
    public_collection = (
        context.repository
        / "analysis-results"
        / "collections"
        / context.collection_id
    )
    if public_collection.exists():
        raise DailyOrchestrationError(
            "public_collection_exists",
            "新規runと同じ公開collectionが既に存在します",
        )
    context.state_root.mkdir(parents=True)
    _validate_context_derived_paths(context)
    _atomic_json(context.state_root / "request.json", context.request.public())
    state = _new_state(context)
    _write_state(context, state)
    if not _apply_capacity_preflight(context, state, capacity_probe):
        return state
    return _execute(context, state, actions)


def run_daily(
    context: DailyContext,
    *,
    actions: DailyActions,
    capacity_probe: Callable[
        [DailyContext, Mapping[str, Any] | None],
        Mapping[str, Any],
    ] = build_capacity_preflight,
) -> dict[str, Any]:
    """run単位lockを取得して新しい日次解析を開始する。"""

    with _run_lock(context):
        return _run_daily_unlocked(
            context,
            actions=actions,
            capacity_probe=capacity_probe,
        )


def _resume_daily_unlocked(
    context: DailyContext,
    *,
    actions: DailyActions,
    capacity_probe: Callable[
        [DailyContext, Mapping[str, Any] | None],
        Mapping[str, Any],
    ] = build_capacity_preflight,
) -> dict[str, Any]:
    """保存済みstateの未完・再試行可能stageだけを再開する。"""

    _validate_context_derived_paths(context)
    state = _load_state(context)
    _ensure_collection_binding(context, create=False)
    _verify_pending_news_source(context, state)
    if not _apply_capacity_preflight(context, state, capacity_probe):
        return state
    return _execute(context, state, actions)


def resume_daily(
    context: DailyContext,
    *,
    actions: DailyActions,
    capacity_probe: Callable[
        [DailyContext, Mapping[str, Any] | None],
        Mapping[str, Any],
    ] = build_capacity_preflight,
) -> dict[str, Any]:
    """run単位lockを取得して未完stageだけを再開する。"""

    with _run_lock(context):
        return _resume_daily_unlocked(
            context,
            actions=actions,
            capacity_probe=capacity_probe,
        )


def drive_daily(
    context: DailyContext,
    *,
    actions: DailyActions,
    max_cycles: int,
    capacity_probe: Callable[
        [DailyContext, Mapping[str, Any] | None],
        Mapping[str, Any],
    ] = build_capacity_preflight,
) -> dict[str, Any]:
    """容量停止、非再試行partial、完了のいずれかまで有界自動再開する。"""

    if not 1 <= max_cycles <= MAX_DRIVE_CYCLES:
        raise DailyOrchestrationError(
            "drive_cycle_limit_invalid",
            f"max_cyclesは1以上{MAX_DRIVE_CYCLES}以下で指定してください",
        )
    with _run_lock(context):
        state = (
            _resume_daily_unlocked(
                context,
                actions=actions,
                capacity_probe=capacity_probe,
            )
            if context.state_root.exists()
            else _run_daily_unlocked(
                context,
                actions=actions,
                capacity_probe=capacity_probe,
            )
        )
        cycles = 1
        while cycles < max_cycles and state["status"] != "complete":
            remediation = state.get("capacity_remediation")
            if (
                isinstance(remediation, Mapping)
                and remediation.get("reason") in CAPACITY_STOP_REASONS
                and type(remediation.get("required_recovery_bytes")) is int
                and remediation["required_recovery_bytes"] > 0
            ):
                break
            retryable = any(
                record.get("retryable") is True
                and record.get("status") in {"partial", "failed"}
                for record in state["stages"].values()
                if isinstance(record, Mapping)
            )
            if not retryable:
                break
            before = _drive_progress_fingerprint(state)
            state = _resume_daily_unlocked(
                context,
                actions=actions,
                capacity_probe=capacity_probe,
            )
            cycles += 1
            if _drive_progress_fingerprint(state) == before:
                break
        return state


def _drive_progress_fingerprint(state: Mapping[str, Any]) -> str:
    """timestampとattempt回数を除き、解析上の意味が前進したかを判定する。"""

    stages = state.get("stages")
    if not isinstance(stages, Mapping):
        raise DailyOrchestrationError(
            "state_invalid",
            "drive進捗のstage状態が不正です",
        )
    normalized: dict[str, Any] = {}
    for name in STAGES:
        record = stages.get(name)
        if not isinstance(record, Mapping):
            raise DailyOrchestrationError(
                "state_invalid",
                "drive進捗のstage recordが不正です",
            )
        error = record.get("error")
        normalized[name] = {
            "status": record.get("status"),
            "retryable": record.get("retryable"),
            "result": record.get("result"),
            "error": {
                "code": error.get("code"),
                "message": error.get("message"),
            }
            if isinstance(error, Mapping)
            else None,
        }
    return _sha256_value(
        {
            "status": state.get("status"),
            "stages": normalized,
            "capacity_remediation": state.get("capacity_remediation"),
        }
    )


def verify_daily(context: DailyContext) -> dict[str, Any]:
    """stateを書き換えずrequest・実装・stage構造を再検証する。"""

    state = _load_state(context)
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "run_id": context.request.run_id,
        "status": state["status"],
        "valid": True,
        "request_sha256": state["request_sha256"],
        "implementation_sha256": state["implementation_sha256"],
        "stage_status": {name: state["stages"][name]["status"] for name in STAGES},
        "safety": dict(state["safety"]),
    }


def _validate_acquisition_tree_layout(
    context: DailyContext,
    *,
    selected_hashes: list[str] | None,
) -> None:
    """source rootを固定layoutへ限定し、未束縛entryとreparseを拒否する。"""

    root = context.source_root
    if not os.path.lexists(root):
        return
    _reject_reparse_components(root, label="MalwareBazaar source root")
    information = root.lstat()
    if not stat.S_ISDIR(information.st_mode):
        raise DailyOrchestrationError(
            "acquisition_tree_invalid",
            "MalwareBazaar source rootが通常directoryではありません",
        )
    selected = set(selected_hashes) if selected_hashes is not None else None
    if selected is not None and (
        len(selected) != len(selected_hashes)
        or any(SHA256_RE.fullmatch(value) is None for value in selected_hashes)
    ):
        raise DailyOrchestrationError(
            "acquisition_selection_invalid",
            "MalwareBazaar選定hash集合がcanonical形式ではありません",
        )
    try:
        with os.scandir(root) as iterator:
            entries = []
            for entry in iterator:
                entries.append(entry)
                if len(entries) > context.request.malwarebazaar_count + 2:
                    raise DailyOrchestrationError(
                        "acquisition_tree_entry_limit",
                        "MalwareBazaar source rootのentry件数が上限を超えています",
                    )
    except DailyOrchestrationError:
        raise
    except OSError as exc:
        raise DailyOrchestrationError(
            "acquisition_tree_invalid",
            "MalwareBazaar source rootを安全に列挙できません",
        ) from exc
    for entry in entries:
        path = Path(entry.path)
        try:
            item = path.lstat()
        except OSError as exc:
            raise DailyOrchestrationError(
                "acquisition_tree_invalid",
                "MalwareBazaar source entryを安全に確認できません",
            ) from exc
        reparse = entry.is_symlink() or bool(
            getattr(item, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        if reparse:
            raise DailyOrchestrationError(
                "acquisition_tree_reparse_forbidden",
                "MalwareBazaar source treeにreparse pointは使用できません",
            )
        if stat.S_ISREG(item.st_mode):
            if (
                entry.name not in {"manifest.json", "family-hints.json"}
                or item.st_nlink != 1
                or not 0 < item.st_size <= 16 * MIB
            ):
                raise DailyOrchestrationError(
                    "acquisition_tree_unbound_entry",
                    "MalwareBazaar source rootに未束縛fileがあります: "
                    f"{entry.name!r}",
                )
            continue
        if not stat.S_ISDIR(item.st_mode) or SHA256_RE.fullmatch(entry.name) is None:
            raise DailyOrchestrationError(
                "acquisition_tree_unbound_entry",
                "MalwareBazaar source rootに未束縛entryがあります",
            )
        if selected is not None and entry.name not in selected:
            raise DailyOrchestrationError(
                "acquisition_tree_unbound_entry",
                "選定hash集合に含まれないMalwareBazaar directoryがあります",
            )
        try:
            with os.scandir(path) as children:
                nested = list(children)
        except OSError as exc:
            raise DailyOrchestrationError(
                "acquisition_tree_invalid",
                "MalwareBazaar検体directoryを安全に列挙できません",
            ) from exc
        if len(nested) > 1:
            raise DailyOrchestrationError(
                "acquisition_tree_unbound_entry",
                "MalwareBazaar検体directoryに余分なentryがあります",
            )
        for child in nested:
            child_information = Path(child.path).lstat()
            child_reparse = child.is_symlink() or bool(
                getattr(child_information, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
            if (
                child_reparse
                or child.name != f"{entry.name}.zip"
                or not stat.S_ISREG(child_information.st_mode)
                or child_information.st_nlink != 1
                or not 0 < child_information.st_size <= SAMPLE_DOWNLOAD_MAX_BYTES
            ):
                raise DailyOrchestrationError(
                    "acquisition_tree_unbound_entry",
                    "MalwareBazaar検体directoryのarchive契約が不正です",
                )


def _acquisition_selection_binding_path(context: DailyContext) -> Path:
    return context.state_root / "acquisition-selection-binding.json"


def _bind_acquisition_selection(
    context: DailyContext,
    manifest: Mapping[str, Any],
) -> None:
    """選定commitmentをrun stateへ固定し、後続stageの差替えを拒否する。"""

    commitment = manifest.get("selection_commitment_sha256")
    selected = manifest.get("selected_hashes")
    if (
        not isinstance(commitment, str)
        or SHA256_RE.fullmatch(commitment) is None
        or not isinstance(selected, list)
        or len(selected) != context.request.malwarebazaar_count
        or len(set(selected)) != len(selected)
        or any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in selected)
    ):
        raise DailyOrchestrationError(
            "acquisition_selection_invalid",
            "MalwareBazaar選定commitmentをrunへ固定できません",
        )
    document = {
        "schema_version": 1,
        "request_sha256": _sha256_value(context.request.public()),
        "selection_commitment_sha256": commitment,
        "selected_hashes": selected,
        "automatic_source_deletion": False,
    }
    path = _acquisition_selection_binding_path(context)
    if path.is_file():
        try:
            existing = analysis_job_runner.load_json_object_strict(
                path,
                max_bytes=1024 * 1024,
            )
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise DailyOrchestrationError(
                "acquisition_selection_binding_invalid",
                "保存済みMalwareBazaar選定bindingを安全に読めません",
            ) from exc
        if existing != document:
            raise DailyOrchestrationError(
                "acquisition_selection_changed",
                "runへ固定したMalwareBazaar選定が変更されました",
            )
        return
    _atomic_json(path, document)


def _load_acquisition_manifest(
    context: DailyContext,
    *,
    require_binding: bool = True,
) -> dict[str, Any]:
    """MalwareBazaar取得manifestと全暗号化ZIPを再検証する。"""

    path = context.source_root / "manifest.json"
    try:
        document = analysis_job_runner.load_json_object_strict(
            path,
            max_bytes=16 * 1024 * 1024,
        )
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise DailyOrchestrationError(
            "acquisition_manifest_invalid",
            "MalwareBazaar取得manifestを安全に読めません",
        ) from exc
    import malwarebazaar_batch

    stored_selection_commitment = document.get("selection_commitment_sha256")
    if (
        not isinstance(stored_selection_commitment, str)
        or SHA256_RE.fullmatch(stored_selection_commitment) is None
        or stored_selection_commitment
        != malwarebazaar_batch._windows_selection_commitment(document)
    ):
        raise DailyOrchestrationError(
            "acquisition_selection_commitment_invalid",
            "MalwareBazaar選定manifestのcommitmentが一致しません",
        )
    count = context.request.malwarebazaar_count
    items = document.get("items")
    selected = document.get("selected_hashes")
    if (
        document.get("schema_version") != 1
        or document.get("selection_mode") != "windows_pe_newest"
        or document.get("requested") != count
        or document.get("complete") is not True
        or document.get("downloaded") != count
        or document.get("pending") != 0
        or document.get("max_download_bytes") != SAMPLE_DOWNLOAD_MAX_BYTES
        or document.get("max_total_download_bytes")
        != count * PREFLIGHT_SAMPLE_ARCHIVE_BYTES
        or document.get("minimum_free_bytes")
        != SAMPLE_DOWNLOAD_MINIMUM_FREE_BYTES
        or document.get("archives_remain_encrypted") is not True
        or document.get("samples_executed") is not False
        or not isinstance(items, list)
        or len(items) != count
        or not isinstance(selected, list)
        or len(selected) != count
    ):
        raise DailyOrchestrationError(
            "acquisition_manifest_incomplete",
            "MalwareBazaar取得manifestが日次件数・安全契約を満たしません",
        )
    observed: set[str] = set()
    observed_bytes = 0
    source_root = context.source_root.resolve(strict=True)
    for item in items:
        if not isinstance(item, Mapping):
            raise DailyOrchestrationError("acquisition_item_invalid", "取得itemがobjectではありません")
        digest = item.get("sha256")
        zip_digest = item.get("zip_sha256")
        zip_size = item.get("zip_size")
        if (
            not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or digest in observed
            or not isinstance(zip_digest, str)
            or SHA256_RE.fullmatch(zip_digest) is None
            or type(zip_size) is not int
            or not 0 < zip_size <= SAMPLE_DOWNLOAD_MAX_BYTES
        ):
            raise DailyOrchestrationError("acquisition_item_invalid", "取得itemのhashまたはsizeが不正です")
        observed.add(digest)
        observed_bytes += zip_size
        archive = Path(str(item.get("zip_path") or ""))
        try:
            archive = archive.resolve(strict=True)
            if archive != source_root / digest / f"{digest}.zip":
                raise ValueError("non-canonical archive path")
            analysis_job_runner._ensure_no_reparse(
                archive,
                code="daily_archive_reparse_forbidden",
                message="日次archiveにreparse pointを使用できません",
            )
            information = archive.lstat()
            actual_digest = analysis_job_runner._snapshot_digest_once(
                archive,
                expected_size=information.st_size,
            )
        except (analysis_job_runner.JobContractError, OSError, ValueError) as exc:
            raise DailyOrchestrationError(
                "acquisition_archive_invalid",
                "取得済み暗号化ZIPを安全に再検証できません",
            ) from exc
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or information.st_size != zip_size
            or actual_digest != zip_digest
        ):
            raise DailyOrchestrationError(
                "acquisition_archive_changed",
                "取得済み暗号化ZIPのsizeまたはSHA-256が一致しません",
            )
    if observed != set(selected):
        raise DailyOrchestrationError(
            "acquisition_selection_mismatch",
            "選定hash集合と取得item集合が一致しません",
        )
    if (
        observed_bytes > count * PREFLIGHT_SAMPLE_ARCHIVE_BYTES
        or document.get("observed_download_bytes") != observed_bytes
    ):
        raise DailyOrchestrationError(
            "acquisition_download_quota_mismatch",
            "取得済み暗号化ZIPの合計byte数がrequest固定quotaと一致しません",
        )
    _validate_acquisition_tree_layout(
        context,
        selected_hashes=selected,
    )
    binding_path = _acquisition_selection_binding_path(context)
    if binding_path.is_file():
        try:
            binding = analysis_job_runner.load_json_object_strict(
                binding_path,
                max_bytes=1024 * 1024,
            )
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise DailyOrchestrationError(
                "acquisition_selection_binding_invalid",
                "保存済みMalwareBazaar選定bindingを安全に読めません",
            ) from exc
        if (
            set(binding)
            != {
                "schema_version",
                "request_sha256",
                "selection_commitment_sha256",
                "selected_hashes",
                "automatic_source_deletion",
            }
            or binding.get("schema_version") != 1
            or
            binding.get("request_sha256") != _sha256_value(context.request.public())
            or binding.get("selection_commitment_sha256")
            != stored_selection_commitment
            or binding.get("selected_hashes") != selected
            or binding.get("automatic_source_deletion") is not False
        ):
            raise DailyOrchestrationError(
                "acquisition_selection_changed",
                "runへ固定したMalwareBazaar選定と取得manifestが一致しません",
            )
    elif require_binding:
        raise DailyOrchestrationError(
            "acquisition_selection_binding_missing",
            "MalwareBazaar選定のrun bindingがありません",
        )
    return document


def _production_news_intake(context: DailyContext) -> StageOutcome:
    import daily_news_malware_intake

    _verify_context_news_source(context)
    staging_base = context.state_root / "news-public-staging"
    arguments = [
        "--tech-memo",
        os.fspath(context.intelligence_root.joinpath(*PurePosixPath(context.request.tech_memo).parts)),
        "--date",
        context.request.news_source_date,
        "--analysis-date",
        context.request.analysis_date,
        "--source-manifest-sha256",
        context.request.source_manifest_sha256,
        "--private-output",
        os.fspath(context.daily_news_private_output),
        "--public-output",
        os.fspath(staging_base),
        "--malwarebazaar-count",
        str(context.request.malwarebazaar_count),
        "--max-sample-downloads",
        str(context.request.malwarebazaar_count),
        "--max-sample-download-bytes",
        str(SAMPLE_DOWNLOAD_MAX_BYTES),
        "--max-sample-download-total-bytes",
        str(context.request.malwarebazaar_count * PREFLIGHT_SAMPLE_ARCHIVE_BYTES),
        "--minimum-free-bytes",
        str(SAMPLE_DOWNLOAD_MINIMUM_FREE_BYTES),
    ]
    if context.request.network["provider_lookups"]:
        arguments.append("--allow-provider-lookups")
    if context.request.network["sample_download"]:
        arguments.extend(("--allow-sample-download", "--run-static-analysis"))
    try:
        exit_code = daily_news_malware_intake.main(arguments)
    except SystemExit as exc:
        raise DailyOrchestrationError(
            "news_intake_failed",
            "日次news取込CLIが安全な終了codeを返しませんでした",
        ) from exc
    _verify_context_news_source(context)
    if exit_code not in {0, 20}:
        raise DailyOrchestrationError(
            "news_intake_failed",
            "日次news取込が固定安全契約を満たしませんでした",
        )
    publication = (
        _promote_news_public_staging(context, staging_base)
        if exit_code == 0
        else None
    )
    return StageOutcome(
        status="complete" if exit_code == 0 else "partial",
        retryable=False,
        result={
            "source_date": context.request.news_source_date,
            "analysis_date": context.request.analysis_date,
            "exit_code": exit_code,
            "provider_lookups": context.request.network["provider_lookups"],
            "sample_download": context.request.network["sample_download"],
            "public_promotion": publication,
            "sample_executed": False,
        },
    )


def _promote_news_public_staging(
    context: DailyContext,
    staging_base: Path,
) -> dict[str, Any]:
    """source再検証後の固定8成果物だけをfile単位でatomic公開する。"""

    staging = staging_base / context.request.news_source_date
    _reject_reparse_components(staging, label="daily news public staging")
    if not staging.is_dir():
        raise DailyOrchestrationError(
            "news_public_staging_missing",
            "日次news公開stagingが生成されませんでした",
        )
    try:
        children = sorted(staging.iterdir(), key=lambda path: path.name.casefold())
    except OSError as exc:
        raise DailyOrchestrationError(
            "news_public_staging_invalid",
            "日次news公開stagingを列挙できません",
        ) from exc
    if {path.name for path in children} != NEWS_PUBLIC_FILES:
        raise DailyOrchestrationError(
            "news_public_staging_invalid",
            "日次news公開stagingのfile集合が固定契約と一致しません",
        )
    snapshots: list[tuple[Path, bytes]] = []
    records: list[dict[str, Any]] = []
    for path in children:
        try:
            raw = analysis_job_runner._read_regular_file_once(
                path,
                max_bytes=64 * MIB,
            )
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise DailyOrchestrationError(
                "news_public_staging_invalid",
                "日次news公開成果物を安全なsnapshotへ固定できません",
            ) from exc
        snapshots.append((path, raw))
        records.append(
            {
                "name": path.name,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    final = (
        context.repository
        / "analysis-results"
        / "research"
        / "daily-news-malware"
        / context.request.news_source_date
    )
    _reject_reparse_components(final, label="daily news public output")
    final.mkdir(parents=True, exist_ok=True)
    _reject_reparse_components(final, label="daily news public output")
    for path, raw in snapshots:
        analysis_job_runner._atomic_bytes(final / path.name, raw)
    return {
        "status": "verified_source_then_atomic_file_promotion",
        "file_count": len(records),
        "commitment_sha256": _sha256_value(records),
        "staging_retained": True,
    }


def _production_malwarebazaar_acquisition(context: DailyContext) -> StageOutcome:
    import malwarebazaar_batch

    context.source_root.mkdir(parents=True, exist_ok=True)
    _validate_acquisition_tree_layout(context, selected_hashes=None)
    if context.request.network["sample_download"]:
        auth_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "")
        if not auth_key:
            raise DailyOrchestrationError(
                "malwarebazaar_credential_unavailable",
                "MalwareBazaar取得用の環境credentialがありません",
            )
        excluded = malwarebazaar_batch.manifest_hashes(
            [
                context.repository / "analysis-results" / "catalog" / "cases.json",
                context.repository / "analysis-results" / "malware",
            ]
        )
        options = {
            "exclude": excluded,
            "file_types": malwarebazaar_batch.WINDOWS_FILE_TYPES,
            "query_limit": int(context.request.limits["query_limit"]),
            "max_download_bytes": SAMPLE_DOWNLOAD_MAX_BYTES,
            "max_total_download_bytes": (
                context.request.malwarebazaar_count
                * PREFLIGHT_SAMPLE_ARCHIVE_BYTES
            ),
            "minimum_free_bytes": SAMPLE_DOWNLOAD_MINIMUM_FREE_BYTES,
        }
        selected = malwarebazaar_batch.download_windows(
            context.request.malwarebazaar_count,
            context.source_root,
            auth_key,
            selection_only=True,
            **options,
        )
        if len(selected.get("selected_hashes", [])) != context.request.malwarebazaar_count:
            raise DailyOrchestrationError(
                "malwarebazaar_selection_incomplete",
                "MalwareBazaarのWindows選定件数が不足しています",
            )
        _validate_acquisition_tree_layout(
            context,
            selected_hashes=selected["selected_hashes"],
        )
        _bind_acquisition_selection(context, selected)
        downloaded = malwarebazaar_batch.download_windows(
            context.request.malwarebazaar_count,
            context.source_root,
            auth_key,
            selection_only=False,
            expected_selection_commitment_sha256=selected[
                "selection_commitment_sha256"
            ],
            **options,
        )
        if downloaded.get("selection_commitment_sha256") != selected.get(
            "selection_commitment_sha256"
        ):
            raise DailyOrchestrationError(
                "acquisition_selection_changed",
                "MalwareBazaar取得中に選定commitmentが変更されました",
            )
    elif not (context.source_root / "manifest.json").is_file():
        raise DailyOrchestrationError(
            "sample_download_not_authorized",
            "取得済みmanifestがなく、sample downloadも有効ではありません",
        )
    if not context.request.network["sample_download"]:
        provisional_manifest = _load_acquisition_manifest(
            context,
            require_binding=False,
        )
        _bind_acquisition_selection(context, provisional_manifest)
    manifest = _load_acquisition_manifest(context)
    hints = malwarebazaar_batch.write_verification_family_hints(
        context.source_root / "manifest.json"
    )
    if hints.get("schema_version") != 1:
        raise DailyOrchestrationError(
            "family_hint_manifest_invalid",
            "family hint manifestを生成できませんでした",
        )
    return StageOutcome(
        status="complete",
        result={
            "selected": len(manifest["selected_hashes"]),
            "downloaded": manifest["downloaded"],
            "pending": manifest["pending"],
            "selection_commitment_sha256": manifest[
                "selection_commitment_sha256"
            ],
            "archives_remain_encrypted": True,
            "sample_executed": False,
        },
    )


def _static_request(context: DailyContext) -> tuple[Any, Any]:
    import daily_news_malware_intake

    manifest = _load_acquisition_manifest(context)
    source_root = context.source_root.resolve(strict=True)
    inputs: list[str] = []
    for item in manifest["items"]:
        archive = Path(str(item["zip_path"])).resolve(strict=True)
        inputs.append(archive.relative_to(source_root).as_posix())
    provisional = analysis_job_runner.validate_request_object(
        {
            "schema_version": analysis_job_runner.SCHEMA_VERSION,
            "job_id": "daily-cache-key-provisional",
            "inputs": inputs,
            "family_hint_manifest": "family-hints.json",
            "options": {
                "archive_mode": "malwarebazaar",
                "max_files": max(context.request.malwarebazaar_count * 4, 64),
                "max_static_layers": 6,
                "retry_max_static_layers": 10,
            },
        }
    )
    identity = daily_news_malware_intake._daily_static_input_identity(
        analysis_job_runner,
        provisional,
        source_root,
    )
    job_id = f"{context.collection_id}-{identity.cache_key_sha256[:12]}"
    request = analysis_job_runner.validate_request_object(
        {**provisional.public(), "job_id": job_id}
    )
    confirmed = daily_news_malware_intake._daily_static_input_identity(
        analysis_job_runner,
        request,
        source_root,
    )
    if confirmed.cache_key_sha256 != identity.cache_key_sha256:
        raise DailyOrchestrationError(
            "static_cache_identity_changed",
            "日次静的解析cache identityがrequest確定中に変化しました",
        )
    return request, confirmed


def _static_job_result(context: DailyContext, request: Any) -> dict[str, Any]:
    job_dir = context.jobs_root / request.job_id
    try:
        return analysis_job_runner.load_json_object_strict(
            job_dir / "result.json",
            max_bytes=analysis_job_runner.MAX_SUMMARY_BYTES,
        )
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise DailyOrchestrationError(
            "static_result_invalid",
            "日次静的解析resultを安全に読めません",
        ) from exc


def _production_static_analysis(context: DailyContext) -> StageOutcome:
    request, identity = _static_request(context)
    context.jobs_root.mkdir(parents=True, exist_ok=True)
    job_dir = context.jobs_root / request.job_id
    if job_dir.exists():
        temporary_root = context.work_root / "completed-job-verification"
        temporary_root.mkdir(parents=True, exist_ok=True)
        try:
            analysis_job_runner.revalidate_completed_job(
                context.jobs_root,
                request,
                temporary_root=temporary_root,
                expected_timeout_seconds=int(context.request.limits["static_timeout_seconds"]),
            )
        except analysis_job_runner.JobContractError as exc:
            raise DailyOrchestrationError(
                "existing_static_job_invalid",
                "既存日次jobの完全再検証に失敗しました",
            ) from exc
    else:
        exit_code = analysis_job_runner.run_job(
            request,
            input_root=context.source_root,
            jobs_root=context.jobs_root,
            timeout_seconds=int(context.request.limits["static_timeout_seconds"]),
        )
        if exit_code not in {0, 20}:
            raise DailyOrchestrationError(
                "static_job_failed",
                "標準job runnerが日次解析を完了できませんでした",
            )
    result = _static_job_result(context, request)
    analysis_state = result.get("analysis_state")
    if analysis_state not in {"complete", "partial"}:
        raise DailyOrchestrationError(
            "static_result_invalid",
            "日次静的解析の終端状態が不正です",
        )
    return StageOutcome(
        status="complete" if analysis_state == "complete" else "partial",
        retryable=False,
        result={
            "job_id": request.job_id,
            "analysis_state": analysis_state,
            "input_snapshot_manifest_sha256": identity.input_snapshot_manifest_sha256,
            "family_hint_manifest_sha256": identity.family_hint_manifest_sha256,
            "implementation_cache_key_sha256": identity.cache_key_sha256,
            "sample_executed": False,
            "network_contacted": False,
        },
    )


def _analysis_contract_sha256(job_analysis: Path) -> str:
    cases = job_analysis / "cases"
    fingerprints: set[str] = set()
    try:
        case_roots = sorted(path for path in cases.iterdir() if path.is_dir())
    except OSError as exc:
        raise DailyOrchestrationError("static_cases_invalid", "静的解析caseを列挙できません") from exc
    for case in case_roots:
        try:
            report = analysis_job_runner.load_json_object_strict(
                case / "report.json",
                max_bytes=analysis_job_runner.MAX_SUMMARY_BYTES,
            )
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise DailyOrchestrationError("static_cases_invalid", "静的解析reportを検証できません") from exc
        contract = report.get("analysis_contract")
        fingerprint = contract.get("sha256") if isinstance(contract, Mapping) else None
        if not isinstance(fingerprint, str) or SHA256_RE.fullmatch(fingerprint) is None:
            raise DailyOrchestrationError("static_contract_invalid", "静的解析契約SHA-256が不正です")
        fingerprints.add(fingerprint)
    if len(fingerprints) != 1:
        raise DailyOrchestrationError(
            "static_contract_mixed",
            "日次caseの静的解析契約が単一値へ収束していません",
        )
    return fingerprints.pop()


def _production_publication(context: DailyContext) -> StageOutcome:
    import publish_one_shot_collection

    request, _identity = _static_request(context)
    job_analysis = context.jobs_root / request.job_id / "analysis"
    contract_sha256 = _analysis_contract_sha256(job_analysis)
    result = publish_one_shot_collection.publish(
        context.repository,
        context.source_root / "manifest.json",
        [job_analysis],
        context.collection_id,
        allow_function_staging=True,
        expected_contract_sha256=contract_sha256,
    )
    return StageOutcome(
        status="complete",
        result={
            "collection_id": context.collection_id,
            "case_count": result.get("cases"),
            "analysis_contract_sha256": contract_sha256,
            "publication_stage": result.get("publication_stage"),
        },
    )


def _production_ghidra(context: DailyContext) -> StageOutcome:
    import ghidra_function_batch

    context.ghidra_private_output.mkdir(parents=True, exist_ok=True)
    context.ghidra_sample_root.mkdir(parents=True, exist_ok=True)
    arguments = [
        "--repository",
        os.fspath(context.repository),
        "--collection",
        os.fspath(context.repository / "analysis-results" / "collections" / context.collection_id),
        "--sample-root",
        os.fspath(context.source_root),
        "--prepared-input-root",
        os.fspath(context.ghidra_sample_root),
        "--private-output",
        os.fspath(context.ghidra_private_output),
        "--mcp-url",
        "http://127.0.0.1:8089",
        "--project-root",
        f"/daily/{context.collection_id}",
        "--minimum-free-bytes",
        str(context.request.limits["ghidra_minimum_free_bytes"]),
        "--disk-guard-path",
        os.fspath(context.ghidra_project_store),
    ]
    maximum = context.request.limits["ghidra_max_new_programs"]
    if maximum is not None:
        arguments.extend(("--max-new-programs", str(maximum)))
    result = ghidra_function_batch.run(ghidra_function_batch.build_parser().parse_args(arguments))
    status = result.get("status")
    if status not in {"complete", "ghidra_chunk_pending"}:
        raise DailyOrchestrationError("ghidra_result_invalid", "Ghidra一括解析の状態が不正です")
    return StageOutcome(
        status="complete" if status == "complete" else "partial",
        retryable=status == "ghidra_chunk_pending",
        result={
            "status": status,
            "stop_reason": result.get("stop_reason"),
            "unique_pe_programs": result.get("unique_pe_programs"),
            "complete_programs": result.get("complete_programs"),
            "pending_program_count": len(result.get("pending_programs", [])),
            "postprocessing_pending": result.get("postprocessing_pending", False),
            "resume_mode": result.get("resume_mode"),
            "disk_space": result.get("disk_space", {}),
            "sample_executed": False,
            "network_contacted": False,
            "arbitrary_ghidra_scripts_enabled": False,
        },
    )


def _run_fixed_python(
    context: DailyContext,
    *,
    stage: str,
    arguments: list[str],
    timeout_seconds: int,
) -> None:
    """固定repository scriptをshellなしで実行し、秘密をargvへ追加しない。"""

    log_root = context.state_root / "process-logs"
    log_root.mkdir(parents=True, exist_ok=True)
    stdout_path = log_root / f"{stage}.stdout.log"
    stderr_path = log_root / f"{stage}.stderr.log"
    try:
        completed = analysis_job_runner._run_process_with_bounded_output(
            [sys.executable, "-B", *arguments],
            cwd=context.repository,
            env=dict(os.environ),
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            maximum_stdout_bytes=8 * MIB,
        )
    except subprocess.TimeoutExpired as exc:
        raise DailyOrchestrationError(
            f"{stage}_timeout",
            f"{stage}が固定時間内に完了しませんでした",
        ) from exc
    except (analysis_job_runner.JobContractError, OSError, RuntimeError, ValueError) as exc:
        raise DailyOrchestrationError(
            f"{stage}_process_failed",
            f"{stage}の固定process境界を維持できませんでした",
        ) from exc
    analysis_job_runner._atomic_bytes(stdout_path, completed.stdout)
    analysis_job_runner._atomic_bytes(stderr_path, completed.stderr)
    if (
        completed.stdout_observed_bytes > 8 * MIB
        or completed.stderr_observed_bytes > 8 * MIB
    ):
        raise DailyOrchestrationError(
            f"{stage}_log_limit_exceeded",
            f"{stage}のprocess logがsize上限を超えました",
        )
    if completed.returncode != 0:
        raise DailyOrchestrationError(
            f"{stage}_failed",
            f"{stage}が非0終了しました",
        )


def _production_c2_monitoring(context: DailyContext) -> StageOutcome:
    import build_all_c2_monitoring_targets

    output = (
        context.repository
        / "analysis-results"
        / "research"
        / "c2-monitoring"
        / context.request.analysis_date
    )
    targets_path = output / "targets.json"
    inventory_path = output / "candidate-inventory.json"
    public_daily_summary = (
        context.repository
        / "analysis-results"
        / "research"
        / "daily-news-malware"
        / context.request.news_source_date
        / "ioc-summary.json"
    )
    staged_daily_summary = (
        context.state_root
        / "news-public-staging"
        / context.request.news_source_date
        / "ioc-summary.json"
    )
    daily_source_summary_path = None
    if not public_daily_summary.is_file() and staged_daily_summary.is_file():
        _verify_context_news_source(context)
        _reject_reparse_components(
            staged_daily_summary,
            label="daily news staged C2 handoff",
        )
        daily_source_summary_path = staged_daily_summary
    plan, inventory = build_all_c2_monitoring_targets.build_inventory(
        context.repository / "analysis-results",
        generated_date=context.request.analysis_date,
        daily_source_date=context.request.news_source_date,
        daily_source_summary_path=daily_source_summary_path,
    )
    output.mkdir(parents=True, exist_ok=True)
    analysis_job_runner.atomic_json(targets_path, plan)
    analysis_job_runner.atomic_json(inventory_path, inventory)
    target_count = plan.get("inventory_summary", {}).get("effective_target_count")
    if not context.request.network["c2_monitoring"]:
        return StageOutcome(
            status="partial",
            retryable=False,
            result={
                "status": "targets_built_live_monitoring_not_authorized",
                "target_count": target_count,
                "daily_source_date": context.request.news_source_date,
                "network_contacted": False,
            },
        )
    if not context.allow_live_c2:
        raise DailyOrchestrationError(
            "live_c2_not_authorized",
            "C2ライブ監視には現在の実行で明示許可が必要です",
        )
    context.maxmind_cache.mkdir(parents=True, exist_ok=True)
    _run_fixed_python(
        context,
        stage="c2_monitoring",
        timeout_seconds=7200,
        arguments=[
            os.fspath(context.repository / "analysis-framework" / "common" / "run_c2_monitoring_pipeline.py"),
            "--targets",
            os.fspath(targets_path),
            "--output-directory",
            os.fspath(output),
            "--history-root",
            os.fspath(output.parent),
            "--maxmind-cache-dir",
            os.fspath(context.maxmind_cache),
            "--refresh-maxmind-databases",
            "--maxmind-max-build-age-hours",
            "24",
            "--allow-network",
        ],
    )
    try:
        result = analysis_job_runner.load_json_object_strict(
            output / "monitoring-results.json",
            max_bytes=64 * 1024 * 1024,
        )
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise DailyOrchestrationError(
            "c2_monitoring_result_invalid",
            "C2監視resultを安全に検証できません",
        ) from exc
    return StageOutcome(
        status="complete",
        result={
            "status": "completed",
            "target_count": result.get("target_count"),
            "state_counts": result.get("state_counts"),
            "daily_source_handoff_count": len(result.get("daily_source_handoffs", [])),
            "network_contacted": True,
            "sample_executed": False,
        },
    )


def _production_validation(context: DailyContext) -> StageOutcome:
    import validate_daily_analysis

    result = validate_daily_analysis.validate_daily_analysis(
        context.repository,
        context.request.analysis_date,
        context.request.news_source_date,
        context.request.malwarebazaar_count,
    )
    lanes = result.get("lanes")
    quality = result.get("quality_gates")
    upstream_pending = False
    if context.request.stages["ghidra"]:
        progress_path = context.ghidra_private_output / "run-progress.json"
        try:
            progress = analysis_job_runner.load_json_object_strict(
                progress_path,
                max_bytes=1024 * 1024,
            )
            upstream_pending = progress.get("status") == "ghidra_chunk_pending"
        except (analysis_job_runner.JobContractError, OSError):
            upstream_pending = True
    return StageOutcome(
        status="complete" if result.get("complete") is True else "partial",
        retryable=result.get("complete") is not True and upstream_pending,
        result={
            "complete": result.get("complete") is True,
            "finding_count": result.get("finding_count"),
            "lanes": {
                str(item.get("name")): item.get("complete") is True
                for item in lanes
                if isinstance(item, Mapping)
            } if isinstance(lanes, list) else {},
            "quality_gates": {
                str(item.get("name")): item.get("complete") is True
                for item in quality
                if isinstance(item, Mapping)
            } if isinstance(quality, list) else {},
            "sample_executed": False,
            "network_contacted": False,
        },
    )


def _tree_size(path: Path, *, maximum_entries: int = 500_000) -> int:
    """linkを辿らず、archive staging容量の安全側上限を計算する。"""

    pending = [analysis_job_runner._extended_length_path(path)]
    entries = 0
    total = 0
    while pending:
        current = pending.pop()
        information = current.lstat()
        if current.is_symlink() or bool(
            getattr(information, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise DailyOrchestrationError(
                "archive_source_reparse_forbidden",
                "archive sourceにreparse pointは使用できません",
            )
        entries += 1
        if entries > maximum_entries:
            raise DailyOrchestrationError(
                "archive_source_entry_limit",
                "archive sourceのentry件数が上限を超えました",
            )
        if stat.S_ISDIR(information.st_mode):
            pending.extend(sorted(current.iterdir(), reverse=True))
        elif stat.S_ISREG(information.st_mode) and information.st_nlink == 1:
            total += information.st_size
        else:
            raise DailyOrchestrationError(
                "archive_source_type_invalid",
                "archive sourceは通常fileまたはdirectoryに限定します",
            )
    return total


def _verified_archive_report(path: Path, target: str) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        report = analysis_job_runner.load_json_object_strict(path, max_bytes=1024 * 1024)
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise DailyOrchestrationError(
            "archive_report_invalid",
            "S3 archive reportを安全に読めません",
        ) from exc
    s3 = report.get("s3_verification")
    if (
        report.get("status") != "verified"
        or report.get("target") != target
        or report.get("local_source_deleted") is not False
        or not isinstance(report.get("archive_sha256"), str)
        or SHA256_RE.fullmatch(report["archive_sha256"]) is None
        or not isinstance(report.get("manifest_sha256"), str)
        or SHA256_RE.fullmatch(report["manifest_sha256"]) is None
        or not isinstance(s3, Mapping)
        or s3.get("server_side_encryption") != "AES256"
    ):
        raise DailyOrchestrationError(
            "archive_report_invalid",
            "S3 archive reportがremote検証・source保持契約を満たしません",
        )
    return report


def _archive_binding_path(context: DailyContext, target: str) -> Path:
    return context.state_root / "archive-bindings" / f"{target}.json"


def _bounded_datastore_target(value: str) -> str:
    """datastoreの128文字契約へ、元のtarget全体をhashで束縛して収める。"""

    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value):
        raise DailyOrchestrationError(
            "archive_target_invalid",
            "S3 archive targetの文字種が不正です",
        )
    if len(value) <= MAX_DATASTORE_TARGET_LENGTH:
        return value
    suffix = hashlib.sha256(value.encode("ascii")).hexdigest()[:24]
    prefix_length = MAX_DATASTORE_TARGET_LENGTH - len(suffix) - 1
    prefix = value[:prefix_length].rstrip("._-")
    if not prefix:
        raise DailyOrchestrationError(
            "archive_target_invalid",
            "S3 archive targetを安全に短縮できません",
        )
    return f"{prefix}-{suffix}"


def _source_commitment(source: Path) -> tuple[str, int, int]:
    import archive_analysis_datastore

    files = archive_analysis_datastore.collect_source_files([source])
    records = [
        {"path": item.archive_name, "size": item.size, "sha256": item.sha256}
        for item in files
    ]
    return _sha256_value(records), len(records), sum(item.size for item in files)


def _archive_one(context: DailyContext, *, role: str, source: Path, target: str) -> dict[str, Any]:
    import archive_analysis_datastore

    target = _bounded_datastore_target(target)
    report_path = context.state_root / "archive-reports" / f"{target}.json"
    binding_path = _archive_binding_path(context, target)
    existing = _verified_archive_report(report_path, target)
    if existing is not None and binding_path.is_file():
        try:
            binding = analysis_job_runner.load_json_object_strict(
                binding_path,
                max_bytes=1024 * 1024,
            )
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise DailyOrchestrationError(
                "archive_binding_invalid",
                "S3 archive source bindingを安全に読めません",
            ) from exc
        commitment, file_count, total_size = _source_commitment(source)
        if (
            binding.get("target") != target
            or binding.get("source_role") != role
            or binding.get("source_tree_sha256") != commitment
            or binding.get("file_count") != file_count
            or binding.get("total_size") != total_size
            or binding.get("archive_report_sha256") != _sha256_file(report_path)
        ):
            raise DailyOrchestrationError(
                "archive_source_changed",
                "S3検証後にlocal sourceが変更されたため別archiveが必要です",
            )
        return {
            "target": target,
            "source_role": role,
            "status": "verified_reused",
            "archive_sha256": existing["archive_sha256"],
            "manifest_sha256": existing["manifest_sha256"],
            "source_tree_sha256": commitment,
        }
    commitment, file_count, total_size = _source_commitment(source)
    exit_code = archive_analysis_datastore.main(
        [
            "--target",
            target,
            "--source",
            os.fspath(source),
            "--report",
            os.fspath(report_path),
        ]
    )
    if exit_code != 0:
        raise DailyOrchestrationError(
            "archive_upload_failed",
            "解析datastoreへの保管が完了しませんでした",
        )
    report = _verified_archive_report(report_path, target)
    if report is None:
        raise DailyOrchestrationError(
            "archive_report_missing",
            "S3 upload後の検証reportがありません",
        )
    after, after_count, after_size = _source_commitment(source)
    if (after, after_count, after_size) != (commitment, file_count, total_size):
        raise DailyOrchestrationError(
            "archive_source_changed",
            "S3 archive作成中にlocal sourceが変更されました",
        )
    binding = {
        "schema_version": 1,
        "target": target,
        "source_role": role,
        "source_tree_sha256": commitment,
        "file_count": file_count,
        "total_size": total_size,
        "archive_report_sha256": _sha256_file(report_path),
        "local_source_deleted": False,
    }
    _atomic_json(binding_path, binding)
    return {
        "target": target,
        "source_role": role,
        "status": "verified",
        "archive_sha256": report["archive_sha256"],
        "manifest_sha256": report["manifest_sha256"],
        "source_tree_sha256": commitment,
    }


def _production_private_archive(context: DailyContext) -> StageOutcome:
    if not context.request.network["datastore_upload"]:
        return StageOutcome(
            status="partial",
            retryable=False,
            result={
                "status": "datastore_upload_not_authorized",
                "local_source_deleted": False,
                "automatic_source_deletion": False,
            },
        )
    upstream_failed = False
    if context.state_root.exists():
        state = _load_state(context)
        upstream_failed = any(
            state["stages"][name]["status"] == "failed"
            for name in STAGES
            if name != "private_archive"
        )
    candidates: list[tuple[str, Path, str]] = []
    static_input_enabled = any(
        context.request.stages[name]
        for name in (
            "malwarebazaar_acquisition",
            "static_analysis",
            "publication",
            "ghidra",
        )
    )
    if static_input_enabled and (context.source_root.exists() or not upstream_failed):
        candidates.append(
            (
                "source",
                context.source_root,
                _bounded_datastore_target(
                    f"{context.collection_id}-{context.request.run_id}-source"
                ),
            )
        )
    if context.request.stages["static_analysis"] or context.request.stages["publication"]:
        try:
            request, _identity = _static_request(context)
        except DailyOrchestrationError:
            if not upstream_failed:
                raise
        else:
            job_path = context.jobs_root / request.job_id
            if job_path.exists() or not upstream_failed:
                candidates.append(
                    (
                        "one_shot_job",
                        job_path,
                        _bounded_datastore_target(
                            f"{context.collection_id}-{context.request.run_id}-one-shot-job"
                        ),
                    )
                )
    if context.request.stages["news_intake"] and (
        context.daily_news_private_output.exists() or not upstream_failed
    ):
        candidates.append(
            (
                "daily_news",
                context.daily_news_private_output,
                _bounded_datastore_target(
                    f"daily-news-malware-{context.request.news_source_date}-{context.request.run_id}"
                ),
            )
        )
    ghidra_progress = context.ghidra_private_output / "run-progress.json"
    ghidra_complete = False
    if ghidra_progress.is_file():
        try:
            progress = analysis_job_runner.load_json_object_strict(
                ghidra_progress,
                max_bytes=1024 * 1024,
            )
            ghidra_complete = progress.get("status") == "complete"
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise DailyOrchestrationError(
                "ghidra_progress_invalid",
                "Ghidra進捗を安全に確認できません",
            ) from exc
    ghidra_has_data = False
    if context.ghidra_private_output.is_dir():
        try:
            with os.scandir(context.ghidra_private_output) as iterator:
                ghidra_has_data = next(iterator, None) is not None
        except OSError as exc:
            raise DailyOrchestrationError(
                "ghidra_progress_invalid",
                "Ghidra private結果を安全に確認できません",
            ) from exc
    if ghidra_has_data:
        ghidra_commitment, _file_count, _total_size = _source_commitment(
            context.ghidra_private_output
        )
        generation = "final" if ghidra_complete else "checkpoint"
        candidates.append(
            (
                "ghidra_static_results" if ghidra_complete else "ghidra_checkpoint",
                context.ghidra_private_output,
                (
                    _bounded_datastore_target(
                        f"{context.collection_id}-{context.request.run_id}-ghidra-"
                        f"{generation}-{ghidra_commitment[:16]}"
                    )
                ),
            )
        )
    if not candidates:
        return StageOutcome(
            status="partial",
            retryable=upstream_failed,
            result={
                "status": (
                    "upstream_failed_without_private_checkpoint_data"
                    if upstream_failed
                    else "no_private_analysis_producer_enabled"
                ),
                "local_source_deleted": False,
                "automatic_source_deletion": False,
            },
        )
    missing = [role for role, source, _target in candidates if not source.exists()]
    if missing:
        raise DailyOrchestrationError(
            "archive_source_missing",
            "S3保管対象の解析dataがありません",
        )
    required = max(_tree_size(source) for _role, source, _target in candidates)
    free = shutil.disk_usage(tempfile.gettempdir()).free
    reserve = 512 * 1024 * 1024
    if free < required + reserve:
        return StageOutcome(
            status="partial",
            retryable=True,
            result={
                "status": "archive_staging_capacity_insufficient",
                "required_staging_bytes": required,
                "minimum_reserve_bytes": reserve,
                "observed_free_bytes": free,
                "local_source_deleted": False,
                "automatic_source_deletion": False,
            },
        )
    generation_candidates: list[tuple[str, Path, str]] = []
    for role, source, target in candidates:
        commitment, _file_count, _total_size = _source_commitment(source)
        generation_candidates.append(
            (
                role,
                source,
                _bounded_datastore_target(f"{target}-{commitment[:16]}"),
            )
        )
    archived = [
        _archive_one(context, role=role, source=source, target=target)
        for role, source, target in generation_candidates
    ]
    if upstream_failed:
        return StageOutcome(
            status="partial",
            retryable=True,
            result={
                "status": "upstream_failed_private_checkpoint_verified",
                "verified_targets": archived,
                "ghidra_checkpoint_archived": ghidra_has_data,
                "local_source_deleted": False,
                "automatic_source_deletion": False,
            },
        )
    if not ghidra_complete and context.request.stages["ghidra"]:
        return StageOutcome(
            status="partial",
            retryable=True,
            result={
                "status": "upstream_ghidra_pending",
                "verified_targets": archived,
                "ghidra_checkpoint_archived": ghidra_has_data,
                "local_source_deleted": False,
                "automatic_source_deletion": False,
            },
        )
    return StageOutcome(
        status="complete",
        result={
            "status": "verified",
            "verified_targets": archived,
            "ghidra_checkpoint_archived": ghidra_has_data,
            "local_source_deleted": False,
            "automatic_source_deletion": False,
        },
    )


PRODUCTION_ACTIONS = DailyActions(
    news_intake=_production_news_intake,
    malwarebazaar_acquisition=_production_malwarebazaar_acquisition,
    static_analysis=_production_static_analysis,
    publication=_production_publication,
    ghidra=_production_ghidra,
    c2_monitoring=_production_c2_monitoring,
    validation=_production_validation,
    private_archive=_production_private_archive,
)


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語化する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("positional arguments:", "位置引数:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このhelpを表示して終了します")
        )


def _add_context_arguments(parser: argparse.ArgumentParser, *, request_required: bool) -> None:
    if request_required:
        parser.add_argument("--request", required=True, type=Path, help="日次request JSON")
    parser.add_argument("--repository", required=True, type=Path, help="解析repository root")
    parser.add_argument(
        "--intelligence-root",
        required=True,
        type=Path,
        help="tech-memo相対pathの基準となるoperator管理root",
    )
    parser.add_argument("--private-root", required=True, type=Path, help="非公開解析dataを置くrepository外root")
    parser.add_argument("--work-root", required=True, type=Path, help="jobとcheckpointを置くrepository外root")
    parser.add_argument(
        "--ghidra-project-store",
        required=True,
        type=Path,
        help="Ghidra projectを保持するrepository外directory",
    )
    parser.add_argument(
        "--allow-live-c2",
        action="store_true",
        help="request側のnetwork.c2_monitoring=trueに加え、現在の実行で限定ライブ監視を明示許可します",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = JapaneseArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema", help="日次request JSON Schemaを出力します")
    draft = commands.add_parser(
        "draft-request",
        help="最新の完全なtech-memo sourceから標準requestを生成します",
    )
    draft.add_argument("--intelligence-root", required=True, type=Path)
    draft.add_argument("--tech-memo", default="tech-memo")
    draft.add_argument("--analysis-date", default=date.today().isoformat())
    draft.add_argument("--run-id")
    draft.add_argument("--malwarebazaar-count", type=int, default=50)
    plan = commands.add_parser("plan", help="副作用なしで固定stageとnetwork境界を表示します")
    _add_context_arguments(plan, request_required=True)
    preflight = commands.add_parser(
        "preflight",
        help="network接触前にsource、authorization、全filesystem容量を検証します",
    )
    _add_context_arguments(preflight, request_required=True)
    run = commands.add_parser("run", help="新しい日次解析checkpointを作成して実行します")
    _add_context_arguments(run, request_required=True)
    resume = commands.add_parser("resume", help="未完または再試行可能stageだけを再開します")
    _add_context_arguments(resume, request_required=True)
    drive = commands.add_parser(
        "drive",
        help="容量停止または完了までGhidra chunkとretryを有界自動再開します",
    )
    _add_context_arguments(drive, request_required=True)
    drive.add_argument("--max-cycles", type=int, default=64)
    verify = commands.add_parser("verify", help="保存済みstateと実装契約をread-only検証します")
    _add_context_arguments(verify, request_required=True)
    status = commands.add_parser("status", help="保存済み日次stateを表示します")
    status.add_argument("--work-root", required=True, type=Path)
    status.add_argument("--run-id", required=True)
    return parser


def _print_json(value: Any, *, stream: Any | None = None) -> None:
    print(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False),
        file=sys.stdout if stream is None else stream,
    )


def _exit_code(status: str) -> int:
    return 0 if status == "complete" else 20 if status == "partial" else 1


def read_status(work_root: Path, run_id: str) -> dict[str, Any]:
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise DailyOrchestrationError("run_id_invalid", "run_idの形式が不正です")
    root = _absolute(work_root)
    _reject_reparse_components(root, label="work root")
    try:
        state = analysis_job_runner.load_json_object_strict(
            root / "daily-orchestrations" / run_id / "state.json",
            max_bytes=MAX_STATE_BYTES,
        )
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise DailyOrchestrationError("state_invalid", "保存済み日次stateを安全に読めません") from exc
    if (
        set(state) != STATE_KEYS
        or state.get("safety") != _expected_safety()
        or state.get("status") not in {"running", "partial", "complete", "failed"}
        or not _capacity_semantics_valid(state.get("capacity_remediation"))
        or state.get("schema_version") != STATE_SCHEMA_VERSION
        or state.get("run_id") != run_id
        or not isinstance(state.get("stages"), Mapping)
        or set(state["stages"]) != set(STAGES)
    ):
        raise DailyOrchestrationError("state_invalid", "保存済み日次stateの境界が不正です")
    for record in state["stages"].values():
        if (
            not isinstance(record, Mapping)
            or set(record) != {"status", "attempts", "retryable", "result", "error"}
            or record.get("status") not in {"pending", "running", "complete", "partial", "failed", "skipped"}
            or type(record.get("attempts")) is not int
            or record.get("attempts") < 0
            or type(record.get("retryable")) is not bool
            or not isinstance(record.get("result"), Mapping)
        ):
            raise DailyOrchestrationError("state_invalid", "保存済み日次stageの境界が不正です")
    return state


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            _print_json(request_json_schema())
            return 0
        if args.command == "draft-request":
            _print_json(
                draft_request_document(
                    intelligence_root=args.intelligence_root,
                    tech_memo=args.tech_memo,
                    analysis_date=args.analysis_date,
                    run_id=args.run_id,
                    malwarebazaar_count=args.malwarebazaar_count,
                )
            )
            return 0
        if args.command == "status":
            state = read_status(args.work_root, args.run_id)
            _print_json(state)
            return _exit_code(str(state.get("status")))
        request = load_request(args.request)
        context = _validate_context(
            request,
            repository=args.repository,
            intelligence_root=args.intelligence_root,
            private_root=args.private_root,
            work_root=args.work_root,
            ghidra_project_store=args.ghidra_project_store,
            allow_live_c2=args.allow_live_c2,
            create_roots=args.command in {"run", "resume", "drive"},
        )
        if args.command == "plan":
            _print_json(
                build_plan(
                    request,
                    preflight=build_preflight_report(context),
                )
            )
            return 0
        if args.command == "preflight":
            result = build_preflight_report(context)
            _print_json(result)
            return 0 if result["ready"] else 20
        if args.command == "run":
            state = run_daily(context, actions=PRODUCTION_ACTIONS)
            _print_json(state)
            return _exit_code(state["status"])
        if args.command == "resume":
            state = resume_daily(context, actions=PRODUCTION_ACTIONS)
            _print_json(state)
            return _exit_code(state["status"])
        if args.command == "drive":
            state = drive_daily(
                context,
                actions=PRODUCTION_ACTIONS,
                max_cycles=args.max_cycles,
            )
            _print_json(state)
            return _exit_code(state["status"])
        result = verify_daily(context)
        _print_json(result)
        return _exit_code(result["status"])
    except DailyOrchestrationError as exc:
        _print_json(
            {"ok": False, "error": {"code": exc.code, "message": str(exc)}},
            stream=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
