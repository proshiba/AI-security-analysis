#!/usr/bin/env python3
"""WebUI／ローカルAPIから安全に呼び出せる静的解析ジョブrunner。"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from analysis_contract import (
    case_integrity_errors,
    ensure_no_reparse_components,
    ensure_tree_without_reparse,
    resolve_case_artifact,
)
from bounded_process import ProcessContainment, TERMINATION_WAIT_SECONDS, run_bounded
from follow_on_commitment import canonical_multiset_commitment
import job_artifact_schemas
import orchestration_outcome
import runtime_contract


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
MAX_FOLLOW_ON_ARTIFACTS = 64
MAX_FOLLOW_ON_EDGES = 128
MAX_FOLLOW_ON_DEPTH = 4
MAX_FOLLOW_ON_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FOLLOW_ON_PAYLOAD_SIZE = 128 * 1024 * 1024
MAX_FOLLOW_ON_WALL_SECONDS = 300
MAX_FOLLOW_ON_CHILD_SECONDS = 120
MAX_FOLLOW_ON_OMITTED_METADATA = 4_096
DEFAULT_TIMEOUT_SECONDS = 6 * 60 * 60
MAX_TIMEOUT_SECONDS = 24 * 60 * 60
PIPE_DRAIN_CHUNK_BYTES = 64 * 1024
OUTPUT_MONITOR_INTERVAL_SECONDS = 0.5
RUNTIME_PREFLIGHT_TIMEOUT_SECONDS = 30
MAX_RUNTIME_PREFLIGHT_ACTIVE_PROCESSES = 4
MAX_RUNTIME_PREFLIGHT_MEMORY_BYTES = 1024 * 1024 * 1024
INPUT_MANIFEST_TIMEOUT_SECONDS = 5 * 60
MAX_ANALYZER_ACTIVE_PROCESSES = 32
MAX_ANALYZER_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
MAX_INPUT_MANIFEST_ACTIVE_PROCESSES = 4
MAX_INPUT_MANIFEST_MEMORY_BYTES = 1024 * 1024 * 1024
MAX_INPUT_MANIFEST_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_ANALYSIS_CONTRACT_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_INPUT_SNAPSHOT_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_TRUSTED_TOOL_MANIFEST_BYTES = 1024 * 1024
MAX_TRUSTED_TOOL_BINARY_BYTES = 128 * 1024 * 1024
INPUT_SNAPSHOT_CHUNK_BYTES = 1024 * 1024
PRIVATE_TEMP_DIRECTORY_NAME = ".private-temp"
RUNTIME_IMPORT_PROBE = runtime_contract.isolated_import_probe_source()
INPUT_MANIFEST_WORKER = r"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import analyze_sample as analyzer

request = json.load(sys.stdin)
if set(request) != {
    'schema_version', 'inputs', 'output', 'registry', 'family_hint_manifest',
    'options', 'password', 'trusted_tools',
} or request.get('schema_version') != 1:
    raise ValueError('invalid input manifest worker request')
options = request['options']
trusted_tools = request['trusted_tools']
if (
    not isinstance(trusted_tools, dict)
    or set(trusted_tools) != {'upx', 'sevenzip', 'diec'}
    or trusted_tools.get('diec') is not None
    or any(
        value is not None
        and (
            not isinstance(value, str)
            or not value
            or not Path(value).is_absolute()
        )
        for value in (trusted_tools.get('upx'), trusted_tools.get('sevenzip'))
    )
):
    raise ValueError('invalid trusted static tool paths')
upx = Path(trusted_tools['upx']) if trusted_tools['upx'] is not None else None
sevenzip = (
    Path(trusted_tools['sevenzip'])
    if trusted_tools['sevenzip'] is not None
    else None
)
paths = analyzer.collect_inputs(
    [Path(value) for value in request['inputs']],
    Path(request['output']),
    int(options['max_files']),
)
if options['archive_mode'] == 'malwarebazaar':
    paths = [path for path in paths if path.suffix.casefold() == '.zip']
records = []
for path in paths:
    try:
        unit = analyzer.read_input_unit(
            path,
            password=request['password'],
            archive_mode=options['archive_mode'],
            max_file_size=int(options['max_file_size']),
        )
        records.append({
            'source_name': path.name,
            'unit_source_name': unit.source_name,
            'sha256': hashlib.sha256(unit.data).hexdigest(),
            'read_succeeded': True,
        })
    except Exception:
        records.append({
            'source_name': path.name,
            'unit_source_name': None,
            'sha256': None,
            'read_succeeded': False,
        })
specs = analyzer.discover_handlers()
manifest_path = (
    Path(request['family_hint_manifest'])
    if request['family_hint_manifest'] is not None
    else None
)
_manifest, family_hint_identity = analyzer._load_family_hint_manifest(manifest_path)
root_contract = analyzer._build_analysis_contract(
    registry=Path(request['registry']),
    specs=specs,
    archive_mode=options['archive_mode'],
    forced_family=options['family'],
    minimum_confidence=options['minimum_confidence'],
    upx=upx,
    sevenzip=sevenzip,
    diec=None,
    force_container_probe=options['force_container_probe'] is True,
    max_static_layers=int(options['max_static_layers']),
    retry_max_static_layers=options['retry_max_static_layers'],
    archive_password=request['password'],
    assessment_only=options['assessment_only'] is True,
    max_file_size=int(options['max_file_size']),
    string_scan_limit=int(options['string_scan_limit']),
    family_hint_manifest_identity=family_hint_identity,
)
child_contract = analyzer._build_follow_on_analysis_contract(
    registry=Path(request['registry']),
    specs=specs,
    minimum_confidence=options['minimum_confidence'],
    upx=upx,
    sevenzip=sevenzip,
    diec=None,
    force_container_probe=options['force_container_probe'] is True,
    max_static_layers=int(options['max_static_layers']),
    retry_max_static_layers=options['retry_max_static_layers'],
    archive_password=request['password'],
    string_scan_limit=int(options['string_scan_limit']),
    family_hint_manifest_identity=family_hint_identity,
)
json.dump(
    {
        'schema_version': 1,
        'input_manifest': records,
        'root_analysis_contract': root_contract,
        'follow_on_analysis_contract': child_contract,
    },
    sys.stdout,
    ensure_ascii=False,
    separators=(',', ':'),
    allow_nan=False,
)
"""

JOB_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
FAMILY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TOOL_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TRUSTED_STATIC_TOOL_IDS = ("upx", "sevenzip")
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
    "automation_resolved",
    "automation_partial",
    "automation_unknown",
    "candidate_handler_attempts",
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
DERIVED_COUNT_KEYS = (
    "analyzed",
    "identified",
    "unknown_or_ambiguous",
    "complete",
    "triaged_unknown",
    "partial",
    "failed",
    "resumed",
)
ROOT_CASE_KEYS = frozenset(
    {
        "sha256",
        "source_name",
        "family",
        "selected_family",
        "selected_families",
        "automation_family",
        "automation_state",
        "candidate_handler_attempts",
        "ai_used",
        "campaign",
        "handler_succeeded",
        "handler_failed",
        "handler_no_evidence",
        "handler_ambiguous",
        "handler_incompatible",
        "analysis_stage_failed",
        "analysis_stage_partial",
        "case_state",
        "report",
        "resumed",
    }
)
FOLLOW_ON_STATUSES = frozenset(
    {
        "complete",
        "partial",
        "failed",
        "no_retained_payloads",
        "disabled_assessment_only",
        "disabled_repository_output",
    }
)
FOLLOW_ON_NODE_STATES = frozenset(
    {
        "root",
        "queued",
        "analyzed",
        "resumed_complete",
        "timeout",
        "failed",
        "wall_clock_limit",
        "incomplete_case_omitted",
    }
)
FOLLOW_ON_EDGE_STATUSES = frozenset(
    {
        "cycle_excluded",
        "depth_limit",
        "payload_size_limit",
        "shared_sha256_excluded",
        "shared_sha256_reused_complete",
        "shared_sha256_reused_incomplete",
        "artifact_count_limit",
        "total_bytes_limit",
        "child_complete",
        "child_incomplete",
    }
)
ACTIVE_FOLLOW_ON_EDGE_STATUSES = frozenset(
    {
        "child_complete",
        "child_incomplete",
    }
)
FOLLOW_ON_OMISSION_REASONS = frozenset(
    {
        "verified_output_edge_limit",
        "verified_output_read_bytes_limit",
        "verified_output_read_wall_clock_limit",
        "artifact_verification_failed",
    }
)
SUMMARY_SETTINGS_KEYS = frozenset(
    {
        "archive_mode",
        "forced_family",
        "minimum_confidence",
        "assessment_only",
        "max_files",
        "max_file_size",
        "string_scan_limit",
        "family_hint_manifest",
        "static_tools",
        "force_container_probe",
        "max_static_layers",
        "retry_max_static_layers",
        "resume",
        "follow_on_fixed_point",
    }
)
SUMMARY_KEYS = frozenset(
    {
        "schema_version",
        "counts",
        "catalog",
        "analysis_contract",
        "follow_on_analysis_contract",
        "requirements_policy",
        "follow_on_analysis",
        "cases",
        "derived_cases",
        "derived_counts",
        "duplicates",
        "errors",
        "settings",
        "executed_sample",
        "network_contacted",
        "ai_used",
    }
)
FOLLOW_ON_MINIMAL_DOCUMENT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "roots",
        "nodes",
        "edges",
        "omitted_metadata",
        "omitted_metadata_commitments",
        "errors",
        "executed_sample",
        "network_contacted",
        "ai_used",
    }
)
FOLLOW_ON_SEALED_DOCUMENT_KEYS = FOLLOW_ON_MINIMAL_DOCUMENT_KEYS | {
    "limits",
    "analysis_contract_sha256",
}
FOLLOW_ON_OPERATIONAL_DOCUMENT_KEYS = FOLLOW_ON_SEALED_DOCUMENT_KEYS | {
    "queued_artifact_count",
    "queued_total_bytes",
    "verified_read_count",
    "verified_read_bytes",
    "parent_promotion_enabled",
    "promoted_parent_sha256",
    "wall_clock_exhausted",
}
FOLLOW_ON_DOCUMENT_KEYS_BY_STATUS = {
    "complete": FOLLOW_ON_OPERATIONAL_DOCUMENT_KEYS,
    "partial": FOLLOW_ON_OPERATIONAL_DOCUMENT_KEYS,
    "no_retained_payloads": FOLLOW_ON_OPERATIONAL_DOCUMENT_KEYS,
    "disabled_repository_output": FOLLOW_ON_SEALED_DOCUMENT_KEYS | {"wall_clock_exhausted"},
    "disabled_assessment_only": FOLLOW_ON_MINIMAL_DOCUMENT_KEYS,
    "failed": FOLLOW_ON_MINIMAL_DOCUMENT_KEYS,
}
FOLLOW_ON_NODE_KEYS_BY_STATE = {
    "root": frozenset({"sha256", "depth", "state"}),
    "queued": frozenset({"sha256", "depth", "size", "state"}),
    "timeout": frozenset({"sha256", "depth", "size", "state"}),
    "wall_clock_limit": frozenset({"sha256", "depth", "size", "state"}),
    "analyzed": frozenset({"sha256", "depth", "size", "state", "case_state"}),
    "resumed_complete": frozenset({"sha256", "depth", "size", "state", "case_state"}),
    "incomplete_case_omitted": frozenset({"sha256", "depth", "size", "state", "case_state"}),
    "failed": frozenset({"sha256", "depth", "size", "state", "error_type"}),
}


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
class SourceFileBinding:
    """入力検証時点の通常fileと、その同一性・変更検知用metadata。"""

    path: Path
    information: os.stat_result


@dataclass(frozen=True)
class InputRecord:
    """入力境界検証の公開可能な集計。"""

    relative_path: str
    kind: str
    file_count: int
    analyzer_file_count: int
    total_bytes: int
    source_files: tuple[SourceFileBinding, ...] = field(
        default=(),
        repr=False,
        compare=False,
    )

    def public(self) -> dict[str, Any]:
        """絶対pathを含まないJSON表現を返す。"""

        return {
            "relative_path": self.relative_path,
            "kind": self.kind,
            "file_count": self.file_count,
            "analyzer_file_count": self.analyzer_file_count,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True)
class SnapshotInput:
    """production子processへ渡すjob-private入力snapshot。"""

    index: int
    source_relative_path: str
    path: Path
    snapshot_relative_path: str
    size: int
    sha256: str

    def public(self) -> dict[str, Any]:
        """元の絶対pathを含めず監査用manifestへ保存する。"""

        return {
            "index": self.index,
            "source_relative_path": self.source_relative_path,
            "snapshot_relative_path": self.snapshot_relative_path,
            "source_name": self.path.name,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class InputSnapshotBundle:
    """snapshot群と、改ざん検知に使う固定manifest。"""

    inputs: tuple[SnapshotInput, ...]
    manifest_path: Path
    manifest_relative_path: str
    manifest_sha256: str
    manifest_document: Mapping[str, Any] = field(repr=False, compare=False)


@dataclass(frozen=True)
class JobPrivateTempBinding:
    """解析出力quota配下へ固定したjob-private一時directory。"""

    path: Path
    information: os.stat_result = field(repr=False, compare=False)


@dataclass(frozen=True)
class TrustedToolConfiguration:
    """Web requestから分離したoperator管理manifestとraw SHA-256 pin。"""

    manifest_path: Path
    manifest_sha256: str


@dataclass(frozen=True)
class TrustedToolSource:
    """operator manifestへpinされた外部静的tool source。"""

    tool_id: str
    path: Path
    size: int
    sha256: str
    information: os.stat_result = field(repr=False, compare=False)

    def identity(self) -> dict[str, Any]:
        """絶対pathを含まない解析契約用identityを返す。"""

        return {"name": self.path.name, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class TrustedToolPolicy:
    """検証済みoperator manifestとtool source集合。"""

    profile_id: str
    operator_manifest_sha256: str
    tools: Mapping[str, TrustedToolSource | None] = field(repr=False, compare=False)

    def identities(self) -> dict[str, dict[str, Any] | None]:
        """検証時に絶対pathを公開せずtool identityだけを返す。"""

        return {
            "upx": self.tools["upx"].identity() if self.tools["upx"] else None,
            "sevenzip": (self.tools["sevenzip"].identity() if self.tools["sevenzip"] else None),
            "diec": None,
        }


@dataclass(frozen=True)
class TrustedToolSnapshot:
    """job-privateに固定した実行fileと公開可能なidentity。"""

    tool_id: str
    path: Path
    snapshot_relative_path: str
    size: int
    sha256: str

    def identity(self) -> dict[str, Any]:
        """解析契約へ結合するbinary identityを返す。"""

        return {"name": self.path.name, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class TrustedToolBundle:
    """job-private tool snapshot群と正規化済みprovenance manifest。"""

    profile_id: str
    operator_manifest_sha256: str
    tools: Mapping[str, TrustedToolSnapshot | None] = field(repr=False, compare=False)
    manifest_path: Path
    manifest_relative_path: str
    manifest_sha256: str
    manifest_document: Mapping[str, Any] = field(repr=False, compare=False)

    def identities(self) -> dict[str, dict[str, Any] | None]:
        """UPX／7zzと、無効を維持するDIECの契約identityを返す。"""

        return {
            "upx": self.tools["upx"].identity() if self.tools["upx"] else None,
            "sevenzip": (self.tools["sevenzip"].identity() if self.tools["sevenzip"] else None),
            "diec": None,
        }

    def provenance(self) -> dict[str, Any]:
        """絶対pathを含めず、job成果物へ固定する信頼済みツール情報を返す。"""

        return {
            "profile_id": self.profile_id,
            "operator_manifest_sha256": self.operator_manifest_sha256,
            "snapshot_manifest_sha256": self.manifest_sha256,
            "tools": self.identities(),
        }


@dataclass(frozen=True)
class ExpectedInputUnit:
    """production実行前に固定した、analyzer単位の入力照合record。"""

    source_name: str
    unit_source_name: str | None
    sha256: str | None
    read_succeeded: bool

    def public(self) -> dict[str, Any]:
        "監査用bundleへ保存できる固定schema表現を返す。"

        return {
            "source_name": self.source_name,
            "unit_source_name": self.unit_source_name,
            "sha256": self.sha256,
            "read_succeeded": self.read_succeeded,
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


def _parse_finite_float(value: str) -> float:
    """指数表記のoverflowを含む非有限floatをJSON境界で拒否する。"""

    parsed = float(value)
    if not math.isfinite(parsed):
        _reject_non_finite(value)
    return parsed


def _parse_bounded_json_int(value: str) -> int:
    """Pythonのglobal制限へ依存せず、JSON整数の桁数を小さく固定する。"""

    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 128:
        raise JobContractError("json_invalid", "JSON整数の桁数が上限を超えています")
    return int(value)


def _ensure_json_depth(value: Any, *, maximum_depth: int = 128) -> None:
    """再帰を使わず、JSON containerの入れ子を有界にする。"""

    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > maximum_depth:
            raise JobContractError("json_invalid", "JSONの入れ子が深すぎます")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def _stat_has_reparse_attribute(information: os.stat_result) -> bool:
    return bool(
        int(getattr(information, "st_file_attributes", 0)) & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    )


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
            parse_int=_parse_bounded_json_int,
            parse_float=_parse_finite_float,
            parse_constant=_reject_non_finite,
        )
    except UnicodeDecodeError as exc:
        raise JobContractError("json_not_utf8", "JSONはBOMなしUTF-8で保存してください") from exc
    except (json.JSONDecodeError, RecursionError) as exc:
        if isinstance(exc, RecursionError):
            raise JobContractError("json_invalid", "JSONの入れ子が深すぎます") from exc
        raise JobContractError("json_invalid", f"JSON構文が不正です: line {exc.lineno}, column {exc.colno}") from exc
    if not isinstance(value, dict):
        raise JobContractError("json_root_not_object", "JSON rootはobjectである必要があります")
    _ensure_json_depth(value)
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


def _is_safe_public_text(
    value: Any,
    *,
    maximum_characters: int,
    source_name: bool = False,
) -> bool:
    """JSON公開文字列の制御文字、path separator、過大値を拒否する。"""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum_characters
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    if source_name and (value in {".", ".."} or "/" in value or "\\" in value or value != value.strip()):
        return False
    return True


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


def _job_request_numeric_option_schemas() -> dict[str, Any]:
    """数値optionのJSON Schemaをhard limitから生成する。"""

    return {
        "max_files": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_DISCOVERED_FILES,
            "default": DEFAULT_OPTIONS["max_files"],
        },
        "max_file_size": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_FILE_SIZE,
            "default": DEFAULT_OPTIONS["max_file_size"],
        },
        "string_scan_limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_STRING_SCAN_LIMIT,
            "default": DEFAULT_OPTIONS["string_scan_limit"],
        },
        "max_static_layers": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_STATIC_LAYERS,
            "default": DEFAULT_OPTIONS["max_static_layers"],
        },
        "retry_max_static_layers": {
            "anyOf": [
                {"type": "null"},
                {"type": "integer", "minimum": 1, "maximum": MAX_RETRY_STATIC_LAYERS},
            ],
            "default": None,
            "description": "指定時はmax_static_layersより大きい値だけを許可します。",
        },
    }


def _job_request_options_json_schema() -> dict[str, Any]:
    """allowlist optionのJSON Schemaを生成する。"""

    properties = {
        "archive_mode": {
            "type": "string",
            "enum": ["auto", "raw", "malwarebazaar"],
            "default": DEFAULT_OPTIONS["archive_mode"],
        },
        "family": {
            "anyOf": [
                {"type": "null"},
                {"type": "string", "enum": sorted(_registered_families())},
            ],
            "default": None,
        },
        "minimum_confidence": {
            "type": "string",
            "enum": ["low", "medium", "high"],
            "default": DEFAULT_OPTIONS["minimum_confidence"],
        },
        "assessment_only": {
            "type": "boolean",
            "default": DEFAULT_OPTIONS["assessment_only"],
        },
        "force_container_probe": {
            "type": "boolean",
            "default": DEFAULT_OPTIONS["force_container_probe"],
        },
    }
    properties.update(_job_request_numeric_option_schemas())
    return {
        "type": "object",
        "additionalProperties": False,
        "default": {},
        "properties": properties,
    }


def job_request_json_schema() -> dict[str, Any]:
    """WebUIとAPI adapterが共有するrequest用JSON Schemaを返す。"""

    relative_path = {
        "type": "string",
        "minLength": 1,
        "maxLength": 512,
        "description": (
            "input-rootからのPOSIX形式相対path。予約名、component、reparseの詳細検証はrunnerがfail-closedで行います。"
        ),
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://local.invalid/ai-security-analysis/job-request-v1.schema.json",
        "title": "ローカル静的解析ジョブ要求",
        "description": "AI、外部通信、検体実行を使わない静的解析ジョブの受付契約です。",
        "type": "object",
        "additionalProperties": False,
        "required": sorted(REQUIRED_TOP_LEVEL_KEYS),
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "job_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": JOB_ID_RE.pattern,
            },
            "inputs": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_REQUEST_INPUTS,
                "uniqueItems": True,
                "items": dict(relative_path),
            },
            "family_hint_manifest": {
                "anyOf": [{"type": "null"}, dict(relative_path)],
                "default": None,
            },
            "options": _job_request_options_json_schema(),
        },
    }


def load_job_request(path: Path) -> JobRequest:
    """fileから厳格なジョブ要求を読む。"""

    return validate_request_object(load_json_object_strict(path, max_bytes=MAX_REQUEST_BYTES))


def load_job_request_from_stdin(stream: Any | None = None) -> JobRequest:
    """WebUI adapter向けにrequest JSONを有界stdinから厳格に読む。"""

    source = sys.stdin.buffer if stream is None else stream
    try:
        data = source.read(MAX_REQUEST_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise JobContractError(
            "request_stdin_unreadable",
            "stdinからjob requestを読み取れません",
        ) from exc
    if not isinstance(data, bytes):
        raise JobContractError(
            "request_stdin_not_binary",
            "stdin job requestはUTF-8 bytesで渡してください",
        )
    if len(data) == 0 or len(data) > MAX_REQUEST_BYTES:
        raise JobContractError(
            "json_size_out_of_bounds",
            f"JSON sizeは1..{MAX_REQUEST_BYTES} bytesで指定してください",
        )
    return validate_request_object(_decode_json_object_strict(data))


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
    repository = REPOSITORY_ROOT.resolve(strict=True)
    if _paths_overlap(repository, prospective_jobs):
        raise JobContractError(
            "jobs_root_repository_forbidden",
            "jobs-rootは解析repositoryと相互に含まれない外部directoryへ分離してください",
        )
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
    if _paths_overlap(repository, jobs_resolved):
        raise JobContractError(
            "jobs_root_repository_forbidden",
            "jobs-rootは解析repositoryと相互に含まれない外部directoryへ分離してください",
        )
    return input_resolved, jobs_resolved


def _scan_directory(
    path: Path,
    *,
    max_file_size: int,
    analyzer_suffix: str | None,
) -> tuple[int, int, int, tuple[SourceFileBinding, ...]]:
    """全entryを安全確認し、総件数と実解析対象件数を同一走査で返す。"""

    _ensure_tree_no_reparse(
        path,
        max_entries=MAX_TREE_ENTRIES,
        code="input_tree_reparse_forbidden",
        message="入力treeにreparse pointを使用できません",
    )
    pending = [path]
    file_count = 0
    analyzer_file_count = 0
    total_bytes = 0
    source_files: list[SourceFileBinding] = []
    while pending:
        directory = pending.pop()
        _ensure_no_reparse(
            directory,
            code="input_tree_reparse_forbidden",
            message="入力treeにreparse pointを使用できません",
        )
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
                info = Path(entry.path).lstat()
            except OSError as exc:
                raise JobContractError("input_unreadable", "入力entryを安全に確認できません") from exc
            if not stat.S_ISREG(info.st_mode) or _stat_has_reparse_attribute(info):
                raise JobContractError("unsupported_input_entry", "通常file以外の入力は使用できません")
            if info.st_nlink != 1:
                raise JobContractError(
                    "input_hardlink_forbidden",
                    "hardlinkされた入力fileは使用できません",
                )
            if info.st_size > max_file_size:
                raise JobContractError("input_file_too_large", f"入力fileが{max_file_size} bytes上限を超えています")
            file_count += 1
            if analyzer_suffix is None or Path(entry.name).suffix.casefold() == analyzer_suffix:
                analyzer_file_count += 1
            total_bytes += info.st_size
            source_files.append(SourceFileBinding(Path(entry.path).resolve(strict=True), info))
    return file_count, total_bytes, analyzer_file_count, tuple(source_files)


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
        try:
            info = resolved.lstat()
        except OSError as exc:
            raise JobContractError("input_unreadable", "入力pathを安全に確認できません") from exc
        if stat.S_ISREG(info.st_mode):
            if _stat_has_reparse_attribute(info):
                raise JobContractError("unsupported_input_entry", "通常file以外の入力は使用できません")
            if info.st_nlink != 1:
                raise JobContractError(
                    "input_hardlink_forbidden",
                    "hardlinkされた入力fileは使用できません",
                )
            if info.st_size > request.options["max_file_size"]:
                raise JobContractError(
                    "input_file_too_large",
                    f"入力fileが{request.options['max_file_size']} bytes上限を超えています: {relative}",
                )
            file_count, total_bytes, kind = 1, info.st_size, "file"
            analyzer_file_count = int(
                request.options["archive_mode"] != "malwarebazaar" or resolved.suffix.casefold() == ".zip"
            )
            source_files = (SourceFileBinding(resolved, info),)
        elif stat.S_ISDIR(info.st_mode):
            file_count, total_bytes, analyzer_file_count, source_files = _scan_directory(
                resolved,
                max_file_size=request.options["max_file_size"],
                analyzer_suffix=(".zip" if request.options["archive_mode"] == "malwarebazaar" else None),
            )
            kind = "directory"
        else:
            raise JobContractError("unsupported_input_entry", "通常file／directory以外の入力は使用できません")
        resolved_inputs.append(resolved)
        records.append(
            InputRecord(
                relative,
                kind,
                file_count,
                analyzer_file_count,
                total_bytes,
                source_files,
            )
        )

    total_files = sum(item.file_count for item in records)
    total_bytes = sum(item.total_bytes for item in records)
    if total_files == 0:
        raise JobContractError("no_input_files", "解析対象fileがありません")
    if total_files > request.options["max_files"]:
        raise JobContractError("input_count_exceeded", f"入力file数が{request.options['max_files']}件を超えています")
    if total_bytes > MAX_TOTAL_INPUT_BYTES:
        raise JobContractError("total_input_size_exceeded", f"入力合計が{MAX_TOTAL_INPUT_BYTES} bytesを超えています")
    if request.options["archive_mode"] == "malwarebazaar" and sum(item.analyzer_file_count for item in records) == 0:
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


def _input_stat_matches(
    expected: os.stat_result,
    observed: os.stat_result,
    *,
    compare_ctime: bool = True,
) -> bool:
    """検証時fileと同一で、内容変更を示すmetadata差分がないか確認する。"""

    return (
        stat.S_ISREG(observed.st_mode)
        and not _stat_has_reparse_attribute(observed)
        and observed.st_nlink == 1
        and _same_file_identity(expected, observed)
        and expected.st_size == observed.st_size
        and expected.st_mtime_ns == observed.st_mtime_ns
        and (not compare_ctime or expected.st_ctime_ns == observed.st_ctime_ns)
    )


def _selected_source_bindings(
    request: JobRequest,
    records: Sequence[InputRecord],
) -> list[SourceFileBinding]:
    """analyzer.collect_inputsと同じcanonical path順で解析対象を固定する。"""

    all_bindings = [binding for record in records for binding in record.source_files]
    if len(all_bindings) != sum(record.file_count for record in records):
        raise JobContractError(
            "input_snapshot_failed",
            "入力検証metadataが完全ではありません",
        )
    selected = [
        binding
        for binding in all_bindings
        if request.options["archive_mode"] != "malwarebazaar" or binding.path.suffix.casefold() == ".zip"
    ]
    selected.sort(key=lambda item: str(item.path).casefold())
    normalized = [str(item.path).casefold() for item in selected]
    if len(normalized) != len(set(normalized)):
        raise JobContractError(
            "input_snapshot_failed",
            "入力fileのcanonical pathが重複しています",
        )
    if not selected or len(selected) > request.options["max_files"]:
        raise JobContractError(
            "input_snapshot_failed",
            "snapshot対象file数が契約範囲外です",
        )
    return selected


def _snapshot_digest_once(path: Path, *, expected_size: int) -> str:
    """snapshotを単一handleで再読込し、path差替えと変更を検出する。"""

    _ensure_no_reparse(
        path,
        code="input_snapshot_reparse_forbidden",
        message="入力snapshotにreparse pointは使用できません",
    )
    try:
        before = path.lstat()
    except OSError as exc:
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshotが見つからないか確認できません",
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or _stat_has_reparse_attribute(before)
        or before.st_nlink != 1
        or before.st_size != expected_size
    ):
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshotのfile属性が変更されました",
        )
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshotを安全に開けません",
        ) from exc
    digest = hashlib.sha256()
    copied = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if not _input_stat_matches(before, opened, compare_ctime=False):
                raise JobContractError(
                    "input_snapshot_changed",
                    "入力snapshotがopen前に差し替えられました",
                )
            while True:
                chunk = handle.read(INPUT_SNAPSHOT_CHUNK_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > expected_size:
                    raise JobContractError(
                        "input_snapshot_changed",
                        "入力snapshotのsizeが増加しました",
                    )
                digest.update(chunk)
            after_handle = os.fstat(handle.fileno())
    except JobContractError:
        raise
    except OSError as exc:
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshotを安全に読めません",
        ) from exc
    try:
        after_path = path.lstat()
    except OSError as exc:
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshotが読込中に差し替えられました",
        ) from exc
    if (
        copied != expected_size
        or not _input_stat_matches(opened, after_handle)
        or not _input_stat_matches(before, after_path)
    ):
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshotが読込中に変更されました",
        )
    return digest.hexdigest()


def _copy_bound_source_to_snapshot(
    binding: SourceFileBinding,
    destination: Path,
) -> tuple[int, str]:
    """検証済みsourceを単一handleからchunk copyし、同directoryでatomic固定する。"""

    source = binding.path
    expected = binding.information
    _ensure_no_reparse(
        source,
        code="input_reparse_forbidden",
        message="入力sourceにreparse pointは使用できません",
    )
    try:
        before = source.lstat()
    except OSError as exc:
        raise JobContractError(
            "input_changed_after_validation",
            "入力fileが検証後に削除または差し替えられました",
        ) from exc
    if not _input_stat_matches(expected, before):
        raise JobContractError(
            "input_changed_after_validation",
            "入力fileが検証後に変更されました",
        )
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise JobContractError(
            "input_changed_after_validation",
            "入力fileを安全に開けません",
        ) from exc
    destination.parent.mkdir(parents=True, exist_ok=False)
    _ensure_no_reparse(
        destination.parent,
        code="input_snapshot_reparse_forbidden",
        message="入力snapshot directoryにreparse pointは使用できません",
    )
    try:
        destination_parent = destination.parent.lstat()
    except OSError as exc:
        raise JobContractError(
            "input_snapshot_failed",
            "入力snapshot directoryを確認できません",
        ) from exc
    if not stat.S_ISDIR(destination_parent.st_mode) or _stat_has_reparse_attribute(destination_parent):
        raise JobContractError(
            "input_snapshot_reparse_forbidden",
            "入力snapshot directoryが通常directoryではありません",
        )
    temporary_name: str | None = None
    digest = hashlib.sha256()
    copied = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as source_handle:
            opened = os.fstat(source_handle.fileno())
            if not _input_stat_matches(expected, opened, compare_ctime=False):
                raise JobContractError(
                    "input_changed_after_validation",
                    "入力fileがopen前に差し替えられました",
                )
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as destination_handle:
                temporary_name = destination_handle.name
                while True:
                    chunk = source_handle.read(INPUT_SNAPSHOT_CHUNK_BYTES)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > expected.st_size:
                        raise JobContractError(
                            "input_changed_after_validation",
                            "入力fileのsizeが検証後に増加しました",
                        )
                    destination_handle.write(chunk)
                    digest.update(chunk)
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
            after_handle = os.fstat(source_handle.fileno())
        try:
            after_path = source.lstat()
        except OSError as exc:
            raise JobContractError(
                "input_changed_after_validation",
                "入力fileがcopy中に差し替えられました",
            ) from exc
        if (
            copied != expected.st_size
            or not _input_stat_matches(opened, after_handle)
            or not _input_stat_matches(expected, after_path)
        ):
            raise JobContractError(
                "input_changed_after_validation",
                "入力fileがcopy中に変更されました",
            )
        if destination.exists():
            raise JobContractError(
                "input_snapshot_collision",
                "入力snapshotの出力先が既に存在します",
            )
        try:
            parent_before_replace = destination.parent.lstat()
        except OSError as exc:
            raise JobContractError(
                "input_snapshot_changed",
                "入力snapshot directoryがcopy中に差し替えられました",
            ) from exc
        if (
            not stat.S_ISDIR(parent_before_replace.st_mode)
            or _stat_has_reparse_attribute(parent_before_replace)
            or not _same_file_identity(destination_parent, parent_before_replace)
        ):
            raise JobContractError(
                "input_snapshot_changed",
                "入力snapshot directoryがcopy中に変更されました",
            )
        os.replace(temporary_name, destination)
        temporary_name = None
        parent_after_replace = destination.parent.lstat()
        if (
            not stat.S_ISDIR(parent_after_replace.st_mode)
            or _stat_has_reparse_attribute(parent_after_replace)
            or not _same_file_identity(destination_parent, parent_after_replace)
        ):
            raise JobContractError(
                "input_snapshot_changed",
                "入力snapshot directoryがatomic replace中に変更されました",
            )
        os.chmod(destination, stat.S_IREAD)
    except JobContractError:
        raise
    except OSError as exc:
        raise JobContractError(
            "input_snapshot_failed",
            "入力snapshotを安全に作成できません",
        ) from exc
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass
    snapshot_digest = _snapshot_digest_once(destination, expected_size=copied)
    if snapshot_digest != digest.hexdigest():
        raise JobContractError(
            "input_snapshot_changed",
            "作成直後の入力snapshot hashが一致しません",
        )
    return copied, snapshot_digest


def stage_input_snapshots(
    request: JobRequest,
    records: Sequence[InputRecord],
    *,
    input_root: Path,
    job_dir: Path,
) -> InputSnapshotBundle:
    """production入力をjob-private directoryへ固定し、元pathを以後使わない。"""

    bindings = _selected_source_bindings(request, records)
    for binding in bindings:
        if not _is_within(binding.path, input_root):
            raise JobContractError(
                "input_snapshot_failed",
                "入力sourceがinput-root外です",
            )
    required_bytes = sum(binding.information.st_size for binding in bindings)
    try:
        free_bytes = shutil.disk_usage(job_dir).free
    except OSError as exc:
        raise JobContractError(
            "input_snapshot_disk_check_failed",
            "入力snapshot用の空き容量を確認できません",
        ) from exc
    if free_bytes < (required_bytes + MAX_INPUT_SNAPSHOT_MANIFEST_BYTES + MIN_FREE_DISK_RESERVE_BYTES):
        raise JobContractError(
            "input_snapshot_disk_reserve_exceeded",
            "入力snapshot作成後のdisk reserveを確保できません",
        )
    samples_root = job_dir / "contract-inputs" / "samples"
    samples_root.mkdir(parents=True, exist_ok=False)
    _ensure_no_reparse(
        samples_root,
        code="input_snapshot_reparse_forbidden",
        message="入力snapshot rootにreparse pointは使用できません",
    )
    snapshot_inputs: list[SnapshotInput] = []
    for index, binding in enumerate(bindings):
        destination = samples_root / f"{index:06d}" / binding.path.name
        size, digest = _copy_bound_source_to_snapshot(binding, destination)
        try:
            source_relative = binding.path.relative_to(input_root).as_posix()
        except ValueError as exc:
            raise JobContractError(
                "input_snapshot_failed",
                "入力sourceがinput-root外です",
            ) from exc
        snapshot_relative = destination.relative_to(job_dir).as_posix()
        snapshot_inputs.append(
            SnapshotInput(
                index=index,
                source_relative_path=source_relative,
                path=destination,
                snapshot_relative_path=snapshot_relative,
                size=size,
                sha256=digest,
            )
        )
    manifest_document = {
        "schema_version": SCHEMA_VERSION,
        "archive_mode": request.options["archive_mode"],
        "file_count": len(snapshot_inputs),
        "total_bytes": sum(item.size for item in snapshot_inputs),
        "files": [item.public() for item in snapshot_inputs],
    }
    manifest_relative_path = "contract-inputs/input-snapshot-manifest.json"
    manifest_path = job_dir / manifest_relative_path
    atomic_json(manifest_path, manifest_document)
    manifest_payload = _read_regular_file_once(
        manifest_path,
        max_bytes=MAX_INPUT_SNAPSHOT_MANIFEST_BYTES,
    )
    if _decode_json_object_strict(manifest_payload) != manifest_document:
        raise JobContractError(
            "input_snapshot_failed",
            "入力snapshot manifestの再検証に失敗しました",
        )
    bundle = InputSnapshotBundle(
        inputs=tuple(snapshot_inputs),
        manifest_path=manifest_path,
        manifest_relative_path=manifest_relative_path,
        manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
        manifest_document=manifest_document,
    )
    verify_input_snapshot_bundle(bundle, job_dir=job_dir)
    return bundle


def verify_input_snapshot_bundle(bundle: InputSnapshotBundle, *, job_dir: Path) -> None:
    """各consumerの直前・直後にsnapshot群とmanifestの不変性を再確認する。"""

    manifest_payload = _read_regular_file_once(
        bundle.manifest_path,
        max_bytes=MAX_INPUT_SNAPSHOT_MANIFEST_BYTES,
    )
    if (
        hashlib.sha256(manifest_payload).hexdigest() != bundle.manifest_sha256
        or _decode_json_object_strict(manifest_payload) != bundle.manifest_document
    ):
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshot manifestが変更されました",
        )
    samples_root = job_dir / "contract-inputs" / "samples"
    _ensure_tree_no_reparse(
        samples_root,
        max_entries=MAX_TREE_ENTRIES,
        code="input_snapshot_reparse_forbidden",
        message="入力snapshot treeにreparse pointは使用できません",
    )
    expected_entries: set[str] = set()
    for item in bundle.inputs:
        relative = item.path.relative_to(samples_root)
        expected_entries.add(relative.as_posix())
        expected_entries.update(parent.as_posix() for parent in relative.parents if parent != Path("."))
        if _snapshot_digest_once(item.path, expected_size=item.size) != item.sha256:
            raise JobContractError(
                "input_snapshot_changed",
                "入力snapshotのSHA-256が変更されました",
            )
    try:
        actual_entries = {path.relative_to(samples_root).as_posix() for path in samples_root.rglob("*")}
    except OSError as exc:
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshot treeを再列挙できません",
        ) from exc
    if actual_entries != expected_entries:
        raise JobContractError(
            "input_snapshot_changed",
            "入力snapshot treeに追加・削除されたentryがあります",
        )


def load_trusted_tool_policy(
    configuration: TrustedToolConfiguration,
    *,
    forbidden_roots: Sequence[Path] = (),
) -> TrustedToolPolicy:
    """operator manifestとbinary pinをstrictかつ単一handleで検証する。"""

    if not isinstance(configuration, TrustedToolConfiguration):
        raise JobContractError(
            "trusted_tool_configuration_invalid",
            "trusted tool設定はTrustedToolConfigurationで指定してください",
        )
    expected_manifest_sha256 = configuration.manifest_sha256
    if not isinstance(expected_manifest_sha256, str) or SHA256_RE.fullmatch(expected_manifest_sha256) is None:
        raise JobContractError(
            "trusted_tool_manifest_pin_invalid",
            "trusted tool manifest SHA-256 pinが不正です",
        )
    manifest_path = _absolute_path(configuration.manifest_path)
    if not manifest_path.is_absolute():  # pragma: no cover - _absolute_pathの最終防御
        raise JobContractError(
            "trusted_tool_manifest_path_invalid",
            "trusted tool manifestは絶対pathで指定してください",
        )
    payload = _read_regular_file_once(
        manifest_path,
        max_bytes=MAX_TRUSTED_TOOL_MANIFEST_BYTES,
    )
    if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), expected_manifest_sha256):
        raise JobContractError(
            "trusted_tool_manifest_pin_mismatch",
            "trusted tool manifestのraw SHA-256がoperator pinと一致しません",
        )
    document = _decode_json_object_strict(payload)
    if set(document) != {"schema_version", "profile_id", "platform", "tools"}:
        raise JobContractError(
            "trusted_tool_manifest_invalid",
            "trusted tool manifestのtop-level schemaが不正です",
        )
    profile_id = document.get("profile_id")
    platform_record = document.get("platform")
    raw_tools = document.get("tools")
    if (
        document.get("schema_version") != SCHEMA_VERSION
        or not isinstance(profile_id, str)
        or TOOL_PROFILE_RE.fullmatch(profile_id) is None
        or not isinstance(platform_record, dict)
        or set(platform_record) != {"sys_platform", "machine"}
        or not isinstance(raw_tools, dict)
        or set(raw_tools) != set(TRUSTED_STATIC_TOOL_IDS)
    ):
        raise JobContractError(
            "trusted_tool_manifest_invalid",
            "trusted tool manifestのfield schemaが不正です",
        )
    expected_platform = {
        "sys_platform": sys.platform.casefold(),
        "machine": platform.machine().casefold(),
    }
    observed_platform = {
        key: value.casefold() if isinstance(value, str) else None for key, value in platform_record.items()
    }
    if observed_platform != expected_platform:
        raise JobContractError(
            "trusted_tool_platform_mismatch",
            "trusted tool manifestのOS／architectureが現在hostと一致しません",
        )

    forbidden = [root.resolve(strict=False) for root in forbidden_roots]
    forbidden.append(REPOSITORY_ROOT.resolve(strict=True))
    sources: dict[str, TrustedToolSource | None] = {}
    seen_paths: set[str] = set()
    for tool_id in TRUSTED_STATIC_TOOL_IDS:
        raw = raw_tools[tool_id]
        if raw is None:
            sources[tool_id] = None
            continue
        if not isinstance(raw, dict) or set(raw) != {"path", "size", "sha256"}:
            raise JobContractError(
                "trusted_tool_manifest_invalid",
                f"{tool_id}のtool schemaが不正です",
            )
        raw_path = raw.get("path")
        size = raw.get("size")
        digest = raw.get("sha256")
        if (
            not isinstance(raw_path, str)
            or not raw_path
            or len(raw_path) > 1_024
            or "\x00" in raw_path
            or not Path(raw_path).is_absolute()
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= MAX_TRUSTED_TOOL_BINARY_BYTES
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
        ):
            raise JobContractError(
                "trusted_tool_manifest_invalid",
                f"{tool_id}のpath／size／SHA-256 pinが不正です",
            )
        source_path = _absolute_path(Path(raw_path))
        _ensure_no_reparse(
            source_path,
            code="trusted_tool_reparse_forbidden",
            message=f"{tool_id}のpathにreparse pointは使用できません",
        )
        try:
            information = source_path.lstat()
        except OSError as exc:
            raise JobContractError(
                "trusted_tool_unavailable",
                f"{tool_id}のbinaryを安全に確認できません",
            ) from exc
        if (
            not stat.S_ISREG(information.st_mode)
            or _stat_has_reparse_attribute(information)
            or information.st_nlink != 1
            or information.st_size != size
        ):
            raise JobContractError(
                "trusted_tool_binary_invalid",
                f"{tool_id}はpinされた単一link通常fileではありません",
            )
        resolved_source = source_path.resolve(strict=True)
        if any(_is_within(resolved_source, root) for root in forbidden):
            raise JobContractError(
                "trusted_tool_root_forbidden",
                f"{tool_id}はinput／job／repositoryと分離したtool rootへ配置してください",
            )
        folded_path = str(resolved_source).casefold()
        if folded_path in seen_paths:
            raise JobContractError(
                "trusted_tool_duplicate_binary",
                "異なるtool IDで同じbinary pathを共有できません",
            )
        seen_paths.add(folded_path)
        actual_digest = _snapshot_digest_once(resolved_source, expected_size=size)
        if not hmac.compare_digest(actual_digest, digest):
            raise JobContractError(
                "trusted_tool_binary_pin_mismatch",
                f"{tool_id} binaryのSHA-256がoperator pinと一致しません",
            )
        sources[tool_id] = TrustedToolSource(
            tool_id=tool_id,
            path=resolved_source,
            size=size,
            sha256=digest,
            information=information,
        )
    if all(source is None for source in sources.values()):
        raise JobContractError(
            "trusted_tool_manifest_empty",
            "trusted tool manifestではUPXまたは7zzを1件以上有効にしてください",
        )
    return TrustedToolPolicy(
        profile_id=profile_id,
        operator_manifest_sha256=expected_manifest_sha256,
        tools=sources,
    )


def stage_trusted_tool_bundle(
    policy: TrustedToolPolicy,
    *,
    job_dir: Path,
) -> TrustedToolBundle:
    """pin済みtoolを単一handleからjob-private launcherへ固定する。"""

    tools_root = job_dir / "contract-inputs" / "static-tools"
    snapshots: dict[str, TrustedToolSnapshot | None] = {}
    for tool_id in TRUSTED_STATIC_TOOL_IDS:
        source = policy.tools[tool_id]
        if source is None:
            snapshots[tool_id] = None
            continue
        launcher_name = f"{tool_id}.exe" if os.name == "nt" else tool_id
        destination = tools_root / tool_id / launcher_name
        try:
            size, digest = _copy_bound_source_to_snapshot(
                SourceFileBinding(path=source.path, information=source.information),
                destination,
            )
            os.chmod(destination, stat.S_IREAD | stat.S_IEXEC)
        except JobContractError as exc:
            raise JobContractError(
                "trusted_tool_snapshot_failed",
                f"{tool_id} binaryをjob-private snapshotへ固定できません",
            ) from exc
        except OSError as exc:
            raise JobContractError(
                "trusted_tool_snapshot_failed",
                f"{tool_id} launcherへ実行権限を設定できません",
            ) from exc
        if size != source.size or not hmac.compare_digest(digest, source.sha256):
            raise JobContractError(
                "trusted_tool_snapshot_mismatch",
                f"{tool_id} snapshotがoperator pinと一致しません",
            )
        snapshots[tool_id] = TrustedToolSnapshot(
            tool_id=tool_id,
            path=destination.resolve(strict=True),
            snapshot_relative_path=destination.relative_to(job_dir).as_posix(),
            size=size,
            sha256=digest,
        )
    manifest_relative_path = "contract-inputs/trusted-static-tools.json"
    manifest_path = job_dir / manifest_relative_path
    manifest_document = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": policy.profile_id,
        "operator_manifest_sha256": policy.operator_manifest_sha256,
        "platform": {
            "sys_platform": sys.platform.casefold(),
            "machine": platform.machine().casefold(),
        },
        "tools": {
            tool_id: (
                {
                    **snapshots[tool_id].identity(),
                    "snapshot_relative_path": snapshots[tool_id].snapshot_relative_path,
                }
                if snapshots[tool_id] is not None
                else None
            )
            for tool_id in TRUSTED_STATIC_TOOL_IDS
        },
        "diec": None,
    }
    atomic_json(manifest_path, manifest_document)
    payload = _read_regular_file_once(
        manifest_path,
        max_bytes=MAX_TRUSTED_TOOL_MANIFEST_BYTES,
    )
    bundle = TrustedToolBundle(
        profile_id=policy.profile_id,
        operator_manifest_sha256=policy.operator_manifest_sha256,
        tools=snapshots,
        manifest_path=manifest_path,
        manifest_relative_path=manifest_relative_path,
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
        manifest_document=manifest_document,
    )
    verify_trusted_tool_bundle(bundle, job_dir=job_dir)
    return bundle


def verify_trusted_tool_bundle(bundle: TrustedToolBundle, *, job_dir: Path) -> None:
    """各workerの直前・直後にtool snapshotとmanifestを完全再検証する。"""

    try:
        payload = _read_regular_file_once(
            bundle.manifest_path,
            max_bytes=MAX_TRUSTED_TOOL_MANIFEST_BYTES,
        )
    except JobContractError as exc:
        raise JobContractError(
            "trusted_tool_snapshot_changed",
            "trusted tool provenance manifestを安全に再検証できません",
        ) from exc
    if (
        not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), bundle.manifest_sha256)
        or _decode_json_object_strict(payload) != bundle.manifest_document
    ):
        raise JobContractError(
            "trusted_tool_snapshot_changed",
            "trusted tool provenance manifestが変更されました",
        )
    tools_root = job_dir / "contract-inputs" / "static-tools"
    expected_tool_entries: set[str] = set()
    for tool_id in TRUSTED_STATIC_TOOL_IDS:
        snapshot = bundle.tools[tool_id]
        if snapshot is None:
            continue
        try:
            snapshot_digest = _snapshot_digest_once(
                snapshot.path,
                expected_size=snapshot.size,
            )
        except JobContractError as exc:
            raise JobContractError(
                "trusted_tool_snapshot_changed",
                f"{tool_id} snapshotを安全に再検証できません",
            ) from exc
        if snapshot_digest != snapshot.sha256:
            raise JobContractError(
                "trusted_tool_snapshot_changed",
                f"{tool_id} snapshotのSHA-256が変更されました",
            )
        relative = snapshot.path.relative_to(tools_root)
        expected_tool_entries.add(relative.as_posix())
        expected_tool_entries.update(parent.as_posix() for parent in relative.parents if parent != Path("."))
    _ensure_tree_no_reparse(
        tools_root,
        max_entries=16,
        code="trusted_tool_reparse_forbidden",
        message="trusted tool snapshot treeにreparse pointは使用できません",
    )
    try:
        actual_tool_entries = {path.relative_to(tools_root).as_posix() for path in tools_root.rglob("*")}
    except OSError as exc:
        raise JobContractError(
            "trusted_tool_snapshot_changed",
            "trusted tool snapshot treeを再列挙できません",
        ) from exc
    if actual_tool_entries != expected_tool_entries:
        raise JobContractError(
            "trusted_tool_snapshot_changed",
            "trusted tool snapshot treeに追加・削除されたentryがあります",
        )


def _trusted_tool_paths(
    bundle: TrustedToolBundle | None,
) -> tuple[Path | None, Path | None, Path | None]:
    """analyzerの既存UPX／7-Zip／DIEC引数順へ安全に変換する。"""

    if bundle is None:
        return None, None, None
    upx = bundle.tools["upx"]
    sevenzip = bundle.tools["sevenzip"]
    return (
        upx.path if upx is not None else None,
        sevenzip.path if sevenzip is not None else None,
        None,
    )


def _expected_trusted_tool_identities(
    bundle: TrustedToolBundle | None,
) -> dict[str, dict[str, Any] | None]:
    """契約へ封印すべきUPX・7zz・DIEC identityを返す。"""

    if bundle is None:
        return {"upx": None, "sevenzip": None, "diec": None}
    return bundle.identities()


def verify_analysis_contract_trusted_tools(
    root_contract: Mapping[str, Any],
    follow_on_contract: Mapping[str, Any],
    *,
    trusted_tools: TrustedToolBundle | None,
) -> None:
    """隔離workerが返したtool identityをoperator契約と独立照合する。"""

    expected = _expected_trusted_tool_identities(trusted_tools)
    for label, contract in (
        ("root", root_contract),
        ("follow_on", follow_on_contract),
    ):
        settings = contract.get("settings")
        if not isinstance(settings, Mapping) or settings.get("static_tools") != expected:
            raise JobContractError(
                "trusted_tool_contract_mismatch",
                f"{label}解析契約のstatic tool identityがoperator契約と一致しません",
            )


def build_analyzer_argv(
    request: JobRequest,
    inputs: Sequence[Path],
    output: Path,
    *,
    python_executable: Path | None = None,
    family_hint_manifest: Path | None = None,
    trusted_tools: TrustedToolBundle | None = None,
) -> list[str]:
    """固定scriptとallowlist optionだけからshellを介さないargvを作る。"""

    executable = Path(python_executable or sys.executable).resolve(strict=True)
    argv = [str(executable), "-I", "-B", str(ANALYZER)]
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
    upx, sevenzip, diec = _trusted_tool_paths(trusted_tools)
    if upx is not None:
        argv.extend(("--upx", str(upx)))
    if sevenzip is not None:
        argv.extend(("--sevenzip", str(sevenzip)))
    if diec is not None:  # pragma: no cover - DIECは意図的に無効化している
        raise JobContractError(
            "trusted_tool_configuration_invalid",
            "DIECは信頼済み静的ツール契約では有効化できません",
        )
    if options["assessment_only"]:
        argv.append("--assessment-only")
    if options["force_container_probe"]:
        argv.append("--force-container-probe")
    if options["retry_max_static_layers"] is not None:
        argv.extend(("--retry-max-static-layers", str(options["retry_max_static_layers"])))
    return argv


def _validated_private_temp_path(path: Path) -> Path:
    """明示された一時directoryをreparseではない既存directoryへ限定する。"""

    absolute = _absolute_path(path)
    _ensure_no_reparse(
        absolute,
        code="private_temp_reparse_forbidden",
        message="job-private一時directoryにreparse pointは使用できません",
    )
    try:
        information = absolute.lstat()
    except OSError as exc:
        raise JobContractError(
            "private_temp_unavailable",
            "job-private一時directoryを安全に確認できません",
        ) from exc
    if not stat.S_ISDIR(information.st_mode) or _stat_has_reparse_attribute(information):
        raise JobContractError(
            "private_temp_invalid",
            "job-private一時pathは通常directoryで指定してください",
        )
    return absolute.resolve(strict=True)


def prepare_job_private_temp(analysis_output: Path) -> JobPrivateTempBinding:
    """解析output内に所有者限定の一時directoryを排他的に作成する。"""

    _ensure_no_reparse(
        analysis_output,
        code="analysis_output_reparse_forbidden",
        message="解析出力pathにreparse pointは使用できません",
    )
    path = analysis_output / PRIVATE_TEMP_DIRECTORY_NAME
    try:
        path.mkdir(mode=0o700, exist_ok=False)
        os.chmod(path, 0o700)
        information = path.lstat()
    except OSError as exc:
        raise JobContractError(
            "private_temp_create_failed",
            "job-private一時directoryを作成できません",
        ) from exc
    if not stat.S_ISDIR(information.st_mode) or _stat_has_reparse_attribute(information):
        raise JobContractError(
            "private_temp_invalid",
            "job-private一時pathは通常directoryではありません",
        )
    if os.name != "nt" and stat.S_IMODE(information.st_mode) & 0o077:
        raise JobContractError(
            "private_temp_permissions_invalid",
            "job-private一時directoryを所有者限定にできません",
        )
    return JobPrivateTempBinding(path=path.resolve(strict=True), information=information)


def build_sanitized_environment(
    *,
    python_executable: Path | None = None,
    temporary_root: Path | None = None,
) -> dict[str, str]:
    """API keyやPython注入設定を子processへ渡さない最小環境を作る。"""

    executable = Path(python_executable or sys.executable).resolve(strict=True)
    environment: dict[str, str] = {}
    for key in ("SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "PATHEXT"):
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
    if temporary_root is not None:
        private_temp = str(_validated_private_temp_path(temporary_root))
        environment.update(
            {
                "TEMP": private_temp,
                "TMP": private_temp,
                "TMPDIR": private_temp,
            }
        )
    return environment


@cache
def validate_analyzer_runtime() -> dict[str, Any]:
    """同じinterpreterと最小環境でfull analyzer／handler依存を事前検証する。"""

    executable = Path(sys.executable).resolve(strict=True)
    environment = build_sanitized_environment(python_executable=executable)
    commands = (
        [str(executable), "-I", "-B", "-c", RUNTIME_IMPORT_PROBE],
        [str(executable), "-I", "-B", str(ANALYZER), "--runtime-preflight"],
    )
    for argv in commands:
        try:
            completed = run_bounded(
                argv,
                cwd=REPOSITORY_ROOT,
                env=environment,
                shell=False,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=RUNTIME_PREFLIGHT_TIMEOUT_SECONDS,
                require_containment=True,
                maximum_active_processes=MAX_RUNTIME_PREFLIGHT_ACTIVE_PROCESSES,
                maximum_memory_bytes=MAX_RUNTIME_PREFLIGHT_MEMORY_BYTES,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
            raise JobContractError(
                "runtime_dependency_unavailable",
                "静的解析用Python環境の事前検証を完了できません",
            ) from exc
        if completed.returncode != 0:
            raise JobContractError(
                "runtime_dependency_unavailable",
                "静的解析用Python環境にrequirementsのsystem／venv依存がありません",
            )
    return {
        "python_implementation": sys.implementation.name,
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "user_site_enabled": False,
        "analyzer_import_verified": True,
        "automatic_handler_catalog_discovered": True,
        "handler_dependencies_verified_on_demand": True,
        "nested_worker_runtime_verified": True,
    }


def build_expected_follow_on_contract(request: JobRequest) -> dict[str, Any]:
    """WebUIが固定したoptionと現在コードから子解析契約を独立再計算する。"""

    raise JobContractError(
        "isolated_contract_context_required",
        "解析契約は入力を含むisolated bundle workerでのみ構築できます",
    )


def build_expected_analysis_contracts(
    request: JobRequest,
    *,
    family_hint_manifest: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """要求、固定manifest、現在コードからroot／child契約を独立再計算する。"""

    raise JobContractError(
        "isolated_contract_context_required",
        "解析契約は入力を含むisolated bundle workerでのみ構築できます",
    )


def build_expected_analysis_bundle(
    request: JobRequest,
    inputs: Sequence[Path],
    analysis_output: Path,
    *,
    family_hint_manifest: Path | None,
    temporary_root: Path | None = None,
    trusted_tools: TrustedToolBundle | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[ExpectedInputUnit]]:
    """isolated analyzer workerで契約と入力manifestを一度に固定する。"""

    upx, sevenzip, diec = _trusted_tool_paths(trusted_tools)
    private_request = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "inputs": [str(path) for path in inputs],
            "output": str(analysis_output),
            "registry": str(REGISTRY),
            "family_hint_manifest": (str(family_hint_manifest) if family_hint_manifest is not None else None),
            "options": dict(request.options),
            "password": "infected",
            "trusted_tools": {
                "upx": str(upx) if upx is not None else None,
                "sevenzip": str(sevenzip) if sevenzip is not None else None,
                "diec": str(diec) if diec is not None else None,
            },
        },
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    try:
        completed = _run_process_with_bounded_output(
            [
                str(Path(sys.executable).resolve(strict=True)),
                "-I",
                "-B",
                "-c",
                INPUT_MANIFEST_WORKER,
                str(COMMON_ROOT),
            ],
            cwd=REPOSITORY_ROOT,
            env=build_sanitized_environment(temporary_root=temporary_root),
            shell=False,
            check=False,
            stdin_payload=private_request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=INPUT_MANIFEST_TIMEOUT_SECONDS,
            maximum_stdout_bytes=MAX_INPUT_MANIFEST_RESPONSE_BYTES,
            maximum_active_processes=MAX_INPUT_MANIFEST_ACTIVE_PROCESSES,
            maximum_memory_bytes=MAX_INPUT_MANIFEST_MEMORY_BYTES,
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        raise JobContractError(
            "input_manifest_failed",
            "isolated production契約workerを完了できません",
        ) from exc
    if completed.returncode != 0 or completed.stdout_truncated or completed.stderr_truncated:
        raise JobContractError(
            "input_manifest_failed",
            "isolated production契約workerが安全に完了しませんでした",
        )
    document = _decode_json_object_strict(completed.stdout)
    if (
        set(document)
        != {
            "schema_version",
            "input_manifest",
            "root_analysis_contract",
            "follow_on_analysis_contract",
        }
        or document.get("schema_version") != SCHEMA_VERSION
    ):
        raise JobContractError("input_manifest_failed", "isolated worker response schemaが不正です")
    root_contract = document.get("root_analysis_contract")
    follow_on_contract = document.get("follow_on_analysis_contract")
    raw_manifest = document.get("input_manifest")
    if (
        not isinstance(root_contract, dict)
        or root_contract.get("schema_version") != SCHEMA_VERSION
        or not isinstance(root_contract.get("sha256"), str)
        or SHA256_RE.fullmatch(root_contract["sha256"]) is None
        or not isinstance(follow_on_contract, dict)
        or follow_on_contract.get("schema_version") != SCHEMA_VERSION
        or not isinstance(follow_on_contract.get("sha256"), str)
        or SHA256_RE.fullmatch(follow_on_contract["sha256"]) is None
        or not isinstance(raw_manifest, list)
        or len(raw_manifest) > MAX_DISCOVERED_FILES
    ):
        raise JobContractError("input_manifest_failed", "isolated worker契約値が不正です")
    manifest: list[ExpectedInputUnit] = []
    for item in raw_manifest:
        if not isinstance(item, dict) or set(item) != {
            "source_name",
            "unit_source_name",
            "sha256",
            "read_succeeded",
        }:
            raise JobContractError("input_manifest_failed", "isolated input record schemaが不正です")
        source_name = item.get("source_name")
        unit_source_name = item.get("unit_source_name")
        digest = item.get("sha256")
        read_succeeded = item.get("read_succeeded")
        if (
            not _is_safe_public_text(
                source_name,
                maximum_characters=512,
                source_name=True,
            )
            or type(read_succeeded) is not bool
            or (
                read_succeeded
                and (
                    not _is_safe_public_text(
                        unit_source_name,
                        maximum_characters=512,
                        source_name=True,
                    )
                    or not isinstance(digest, str)
                    or SHA256_RE.fullmatch(digest) is None
                )
            )
            or (not read_succeeded and (unit_source_name is not None or digest is not None))
        ):
            raise JobContractError("input_manifest_failed", "isolated input record fieldが不正です")
        manifest.append(
            ExpectedInputUnit(
                source_name=source_name,
                unit_source_name=unit_source_name,
                sha256=digest,
                read_succeeded=read_succeeded,
            )
        )
    return root_contract, follow_on_contract, manifest


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
        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8"),
    )


def persist_analysis_contract_bundle(
    job_dir: Path,
    *,
    root_contract: Mapping[str, Any],
    follow_on_contract: Mapping[str, Any],
    input_manifest: Sequence[ExpectedInputUnit],
) -> tuple[str, str]:
    """実行前に固定した入力とroot／child契約を監査用に保存する。"""

    relative_path = "contract-inputs/analysis-contract-bundle.json"
    path = job_dir / Path(relative_path)
    document = {
        "schema_version": SCHEMA_VERSION,
        "input_manifest": [item.public() for item in input_manifest],
        "root_analysis_contract": dict(root_contract),
        "follow_on_analysis_contract": dict(follow_on_contract),
    }
    atomic_json(path, document)
    payload = _read_regular_file_once(path, max_bytes=MAX_ANALYSIS_CONTRACT_BUNDLE_BYTES)
    if _decode_json_object_strict(payload) != document:
        raise JobContractError(
            "analysis_contract_bundle_failed",
            "保存した解析契約bundleの再検証に失敗しました",
        )
    return relative_path, hashlib.sha256(payload).hexdigest()


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
    encoded = json.dumps(
        request.public(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
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


@dataclass
class _PipeWrite:
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


def _drain_pipe(
    stream: Any,
    capture: _PipeCapture,
    maximum_bytes: int = MAX_LOG_BYTES,
) -> None:
    """pipeをEOFまで消費し、先頭1 MiBだけをmemoryへ保持する。"""

    try:
        while True:
            chunk = stream.read(PIPE_DRAIN_CHUNK_BYTES)
            if not chunk:
                break
            remaining = maximum_bytes - len(capture.retained)
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


def _write_pipe(stream: Any, payload: bytes, state: _PipeWrite) -> None:
    """stdinを専用threadで送信し、block中も親のdeadline監視を止めない。"""

    try:
        stream.write(payload)
        stream.flush()
    except BaseException as exc:  # noqa: BLE001 - worker thread境界で親へ伝搬する
        state.error = exc
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _close_process_pipes(
    process: subprocess.Popen[bytes],
    threads: Sequence[threading.Thread],
) -> None:
    """live I/O threadが所有していないpipeだけをbest-effortで閉じる。"""

    live_owners = {thread.name for thread in threads if thread.is_alive()}
    streams = (
        ("analysis-stdin-writer", process.stdin),
        ("analysis-stdout-drain", process.stdout),
        ("analysis-stderr-drain", process.stderr),
    )
    for owner, stream in streams:
        if owner in live_owners:
            continue
        if stream is None:
            continue
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _join_process_threads(threads: Sequence[threading.Thread]) -> None:
    """開始済みI/O threadだけを、全体で有界時間内に回収する。"""

    deadline = time.monotonic() + TERMINATION_WAIT_SECONDS
    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        thread.join(timeout=remaining)


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
    stdin_payload: bytes | None = None,
    maximum_stdout_bytes: int = MAX_LOG_BYTES,
    maximum_active_processes: int = MAX_ANALYZER_ACTIVE_PROCESSES,
    maximum_memory_bytes: int = MAX_ANALYZER_MEMORY_BYTES,
) -> _BoundedProcessResult:
    """子孫treeを所有し、logと解析出力を有界に保ってprocessを実行する。"""

    if shell is not False or stdout is not subprocess.PIPE or stderr is not subprocess.PIPE:
        raise ValueError("bounded runnerはshell=Falseとstdout/stderr=PIPEだけを許可します")
    if (
        isinstance(maximum_stdout_bytes, bool)
        or not isinstance(maximum_stdout_bytes, int)
        or not 1 <= maximum_stdout_bytes <= MAX_SUMMARY_BYTES
    ):
        raise ValueError("maximum_stdout_bytesが不正です")
    if monitored_output is not None:
        validate_analysis_output_tree(monitored_output)
        if shutil.disk_usage(monitored_output).free <= MIN_FREE_DISK_RESERVE_BYTES:
            raise JobContractError(
                "analysis_output_disk_reserve_exceeded",
                f"job filesystemの空き容量が{MIN_FREE_DISK_RESERVE_BYTES} bytes以下です",
            )
    containment = ProcessContainment(
        maximum_active_processes=maximum_active_processes,
        maximum_memory_bytes=maximum_memory_bytes,
    )
    platform_options = containment.popen_options()
    stdout_capture = _PipeCapture(bytearray())
    stderr_capture = _PipeCapture(bytearray())
    stdin_state = _PipeWrite() if stdin_payload is not None else None
    started_threads: list[threading.Thread] = []
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        shell=False,
        stdin=subprocess.PIPE if stdin_payload is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **platform_options,
    )
    try:
        # Popen直後から、Job割当・thread初期化・stdin送信も同じwall-clockへ含める。
        deadline = time.monotonic() + timeout
        containment.attach(process)
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen契約の最終確認
            raise RuntimeError("stdout/stderr pipeを確立できません")
        threads = [
            threading.Thread(
                target=_drain_pipe,
                args=(process.stdout, stdout_capture, maximum_stdout_bytes),
                daemon=True,
                name="analysis-stdout-drain",
            ),
            threading.Thread(
                target=_drain_pipe,
                args=(process.stderr, stderr_capture),
                daemon=True,
                name="analysis-stderr-drain",
            ),
        ]
        if stdin_payload is not None:
            if process.stdin is None:  # pragma: no cover - Popen契約の最終防御
                raise RuntimeError("stdin pipeを確立できませんでした")
            if stdin_state is None:  # pragma: no cover - 内部状態の最終防御
                raise RuntimeError("stdin送信状態を初期化できませんでした")
            threads.append(
                threading.Thread(
                    target=_write_pipe,
                    args=(process.stdin, stdin_payload, stdin_state),
                    daemon=True,
                    name="analysis-stdin-writer",
                )
            )
        for thread in threads:
            thread.start()
            started_threads.append(thread)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            if stdin_state is not None and stdin_state.error is not None:
                raise RuntimeError("private worker requestを送信できませんでした") from stdin_state.error
            try:
                return_code = process.wait(timeout=min(OUTPUT_MONITOR_INTERVAL_SECONDS, remaining))
                containment.close(strict=True)
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
        try:
            containment.abort()
        finally:
            _join_process_threads(started_threads)
            _close_process_pipes(process, started_threads)
        raise subprocess.TimeoutExpired(
            command,
            timeout,
            output=bytes(stdout_capture.retained),
            stderr=bytes(stderr_capture.retained),
        ) from original_timeout
    except BaseException:
        try:
            containment.abort()
        except BaseException:
            pass
        _join_process_threads(started_threads)
        _close_process_pipes(process, started_threads)
        raise

    _join_process_threads(started_threads)
    if any(thread.is_alive() for thread in started_threads):
        containment.abort()
        _join_process_threads(started_threads)
        _close_process_pipes(process, started_threads)
        raise RuntimeError("process I/O threadが時間内に終了しませんでした")
    for capture in (stdout_capture, stderr_capture):
        if capture.error is not None:
            raise RuntimeError("stdout/stderr drainに失敗しました") from capture.error
    if stdin_state is not None and stdin_state.error is not None:
        raise RuntimeError("private worker requestを送信できませんでした") from stdin_state.error
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
                raise JobContractError(
                    "analysis_output_entry_forbidden", "解析出力には通常file／directoryだけを許可します"
                )
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


def finalize_job_private_temp(
    binding: JobPrivateTempBinding,
    *,
    analysis_output: Path,
) -> None:
    """quotaとtree安全性を再検証し、空のjob-private一時directoryだけを除去する。"""

    # 一時展開中のfileも、通常の解析成果物と同じjob単位quotaへ含める。
    validate_analysis_output_tree(analysis_output)
    path = binding.path
    _ensure_no_reparse(
        path,
        code="private_temp_reparse_forbidden",
        message="job-private一時directoryにreparse pointが含まれています",
    )
    try:
        current = path.lstat()
    except OSError as exc:
        raise JobContractError(
            "private_temp_changed",
            "job-private一時directoryが解析中に変更されました",
        ) from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or _stat_has_reparse_attribute(current)
        or not _same_file_identity(binding.information, current)
    ):
        raise JobContractError(
            "private_temp_changed",
            "job-private一時directoryのidentityが解析中に変更されました",
        )
    try:
        with os.scandir(path) as iterator:
            residual = next(iterator, None)
    except OSError as exc:
        raise JobContractError(
            "private_temp_unreadable",
            "job-private一時directoryを安全に列挙できません",
        ) from exc
    if residual is not None:
        raise JobContractError(
            "private_temp_not_empty",
            "解析process終了後もjob-private一時directoryに残存entryがあります",
        )
    try:
        path.rmdir()
    except OSError as exc:
        raise JobContractError(
            "private_temp_changed",
            "空のjob-private一時directoryを安全に除去できません",
        ) from exc


def _validated_follow_on_artifact(
    summary_path: Path,
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    """summaryが参照するfollow-on graphを単一handleで検証する。"""

    reference = summary.get("follow_on_analysis")
    reference_keys = {
        "artifact",
        "sha256",
        "status",
        "node_count",
        "edge_count",
        "error_count",
    }
    if not isinstance(reference, dict) or set(reference) != reference_keys:
        raise JobContractError("summary_invalid", "follow_on_analysis参照schemaが不正です")
    digest = reference.get("sha256")
    if (
        reference.get("artifact") != "follow-on-analysis.json"
        or not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        or reference.get("status") not in FOLLOW_ON_STATUSES
    ):
        raise JobContractError("summary_invalid", "follow_on_analysis参照fieldが不正です")
    for key in ("node_count", "edge_count", "error_count"):
        value = reference.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise JobContractError("summary_invalid", f"follow_on_analysis.{key}が不正です")

    artifact_path = summary_path.parent / "follow-on-analysis.json"
    raw = _read_regular_file_once(artifact_path, max_bytes=MAX_SUMMARY_BYTES)
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest):
        raise JobContractError("summary_invalid", "follow-on artifactのSHA-256が一致しません")
    document = _decode_json_object_strict(raw)
    if (
        document.get("schema_version") != SCHEMA_VERSION
        or document.get("status") != reference["status"]
        or document.get("executed_sample") is not False
        or document.get("network_contacted") is not False
        or document.get("ai_used") is not False
    ):
        raise JobContractError("analyzer_safety_contract_failed", "follow-on安全契約が不正です")
    expected_document_keys = FOLLOW_ON_DOCUMENT_KEYS_BY_STATUS.get(str(document.get("status")))
    if expected_document_keys is None or set(document) != expected_document_keys:
        raise JobContractError("summary_invalid", "follow-on top-level schemaが不正です")
    contract_sha256 = document.get("analysis_contract_sha256")
    contract_required = document["status"] in {
        "complete",
        "partial",
        "no_retained_payloads",
        "disabled_repository_output",
    }
    if contract_required and (not isinstance(contract_sha256, str) or SHA256_RE.fullmatch(contract_sha256) is None):
        raise JobContractError("summary_invalid", "follow-on解析契約SHA-256がありません")
    if contract_sha256 is not None and (
        not isinstance(contract_sha256, str) or SHA256_RE.fullmatch(contract_sha256) is None
    ):
        raise JobContractError("summary_invalid", "follow-on解析契約SHA-256が不正です")
    operational_status = document["status"] in {
        "complete",
        "partial",
        "no_retained_payloads",
    }
    expected_limits = {
        "maximum_artifacts": MAX_FOLLOW_ON_ARTIFACTS,
        "maximum_edges": MAX_FOLLOW_ON_EDGES,
        "maximum_depth": MAX_FOLLOW_ON_DEPTH,
        "maximum_total_bytes": MAX_FOLLOW_ON_TOTAL_BYTES,
        "maximum_payload_size": MAX_FOLLOW_ON_PAYLOAD_SIZE,
        "maximum_wall_seconds": MAX_FOLLOW_ON_WALL_SECONDS,
        "maximum_child_seconds": MAX_FOLLOW_ON_CHILD_SECONDS,
        "maximum_omitted_metadata": MAX_FOLLOW_ON_OMITTED_METADATA,
    }
    if contract_required and document.get("limits") != expected_limits:
        raise JobContractError("summary_invalid", "follow-on hard limitが実装契約と一致しません")
    counter_keys = (
        "queued_artifact_count",
        "queued_total_bytes",
        "verified_read_count",
        "verified_read_bytes",
    )
    if operational_status:
        for key in counter_keys:
            value = document.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise JobContractError("summary_invalid", f"follow-on {key}が不正です")
        if (
            type(document.get("parent_promotion_enabled")) is not bool
            or type(document.get("wall_clock_exhausted")) is not bool
            or document["queued_artifact_count"] > MAX_FOLLOW_ON_ARTIFACTS
            or document["queued_total_bytes"] > MAX_FOLLOW_ON_TOTAL_BYTES
            or document["verified_read_count"] > MAX_FOLLOW_ON_EDGES
            or document["verified_read_bytes"] > MAX_FOLLOW_ON_TOTAL_BYTES
        ):
            raise JobContractError("summary_invalid", "follow-on実行状態が不正です")
    roots = document.get("roots")
    nodes = document.get("nodes")
    edges = document.get("edges")
    errors = document.get("errors")
    omitted_metadata = document.get("omitted_metadata")
    omitted_commitments = document.get("omitted_metadata_commitments")
    if not all(
        isinstance(value, list)
        for value in (
            roots,
            nodes,
            edges,
            errors,
            omitted_metadata,
            omitted_commitments,
        )
    ):
        raise JobContractError("summary_invalid", "follow-on graph arrayがありません")
    if (
        roots != sorted(set(roots))
        or any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in roots)
        or any(not isinstance(value, str) or len(value) > 512 for value in errors)
        or len(nodes) != reference["node_count"]
        or len(edges) != reference["edge_count"]
        or len(errors) != reference["error_count"]
        or len(edges) > MAX_FOLLOW_ON_EDGES
        or len(omitted_metadata) > MAX_FOLLOW_ON_OMITTED_METADATA
    ):
        raise JobContractError("summary_count_mismatch", "follow-on graph件数またはrootが不正です")

    node_depths: dict[str, int] = {}
    node_states: dict[str, str] = {}
    node_case_states: dict[str, str | None] = {}
    for node in nodes:
        if not isinstance(node, dict):
            raise JobContractError("summary_invalid", "follow-on nodeがobjectではありません")
        node_digest = node.get("sha256")
        depth = node.get("depth")
        node_state = node.get("state")
        expected_node_keys = FOLLOW_ON_NODE_KEYS_BY_STATE.get(str(node_state))
        if (
            expected_node_keys is None
            or set(node) != expected_node_keys
            or not isinstance(node_digest, str)
            or SHA256_RE.fullmatch(node_digest) is None
            or node_digest in node_depths
            or isinstance(depth, bool)
            or not isinstance(depth, int)
            or not 0 <= depth <= 4
            or node_state not in FOLLOW_ON_NODE_STATES
        ):
            raise JobContractError("summary_invalid", "follow-on node fieldが不正です")
        node_depths[node_digest] = depth
        node_states[node_digest] = str(node_state)
        case_state = node.get("case_state")
        if case_state is not None and case_state not in {
            "complete",
            "triaged_unknown",
            "partial",
            "failed",
        }:
            raise JobContractError("summary_invalid", "follow-on node case_stateが不正です")
        size = node.get("size")
        if depth == 0:
            if node["state"] != "root" or size is not None or case_state is not None:
                raise JobContractError("summary_invalid", "follow-on root nodeが不正です")
        elif isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_FOLLOW_ON_PAYLOAD_SIZE:
            raise JobContractError("summary_invalid", "follow-on child node sizeが不正です")
        if node_state == "failed" and not _is_safe_public_text(
            node.get("error_type"),
            maximum_characters=128,
        ):
            raise JobContractError("summary_invalid", "follow-on node error_typeが不正です")
        node_case_states[node_digest] = case_state
    node_roots = {value for value, depth in node_depths.items() if depth == 0}
    disabled_or_failed = document["status"] in {
        "disabled_assessment_only",
        "disabled_repository_output",
        "failed",
    }
    if (disabled_or_failed and (nodes or edges)) or (not disabled_or_failed and set(roots) != node_roots):
        raise JobContractError("summary_invalid", "follow-on rootとdepth 0 nodeが一致しません")
    non_root_nodes = [node for node in nodes if node["depth"] > 0]
    if len(non_root_nodes) > MAX_FOLLOW_ON_ARTIFACTS:
        raise JobContractError("summary_invalid", "follow-on child node上限を超えています")
    if operational_status and (
        document["queued_artifact_count"] != len(non_root_nodes)
        or document["queued_total_bytes"] != sum(node["size"] for node in non_root_nodes)
        or document["queued_artifact_count"] > document["verified_read_count"]
        or document["queued_total_bytes"] > document["verified_read_bytes"]
        or document["verified_read_count"] > len(edges)
    ):
        raise JobContractError("summary_count_mismatch", "follow-on counterがgraphと一致しません")
    promoted_parents = document.get("promoted_parent_sha256")
    if operational_status and (
        not isinstance(promoted_parents, list)
        or promoted_parents != sorted(set(promoted_parents))
        or any(
            not isinstance(value, str) or SHA256_RE.fullmatch(value) is None or value not in node_depths
            for value in promoted_parents
        )
    ):
        raise JobContractError("summary_invalid", "follow-on promoted parent一覧が不正です")

    commitment_keys = {"parent_sha256", "count", "sha256"}
    commitment_parents: list[str] = []
    for commitment in omitted_commitments:
        if not isinstance(commitment, dict) or set(commitment) != commitment_keys:
            raise JobContractError("summary_invalid", "follow-on commitment schemaが不正です")
        parent_digest = commitment.get("parent_sha256")
        count = commitment.get("count")
        commitment_sha256 = commitment.get("sha256")
        if (
            not isinstance(parent_digest, str)
            or SHA256_RE.fullmatch(parent_digest) is None
            or parent_digest not in node_depths
            or isinstance(count, bool)
            or not isinstance(count, int)
            or not 1 <= count <= (1 << 63) - 1
            or not isinstance(commitment_sha256, str)
            or SHA256_RE.fullmatch(commitment_sha256) is None
            or f"{parent_digest}:verified_output_omitted_metadata_limit" not in errors
        ):
            raise JobContractError("summary_invalid", "follow-on commitment fieldが不正です")
        commitment_parents.append(parent_digest)
    if commitment_parents != sorted(set(commitment_parents)):
        raise JobContractError("summary_invalid", "follow-on commitmentが重複または未整列です")
    if omitted_commitments:
        if (
            document["status"] != "partial"
            or document.get("parent_promotion_enabled") is not False
            or promoted_parents != []
        ):
            raise JobContractError(
                "summary_invalid",
                "commitmentを持つgraphはpartialかつ親昇格禁止である必要があります",
            )
    elif operational_status and document.get("parent_promotion_enabled") is not True:
        raise JobContractError("summary_invalid", "commitmentがないgraphの親昇格状態が不正です")
    if not operational_status and omitted_commitments:
        raise JobContractError("summary_invalid", "非実行graphにcommitmentは指定できません")

    omission_keys = {
        "parent_sha256",
        "sha256",
        "size",
        "path",
        "role",
        "kind",
        "reason",
    }
    for omission in omitted_metadata:
        if not isinstance(omission, dict) or set(omission) != omission_keys:
            raise JobContractError("summary_invalid", "follow-on omission schemaが不正です")
        parent_digest = omission.get("parent_sha256")
        payload_digest = omission.get("sha256")
        size = omission.get("size")
        reason = omission.get("reason")
        expected_error_marker = (
            f"{parent_digest}:artifact_verification_failed:{payload_digest}"
            if reason == "artifact_verification_failed"
            else f"{parent_digest}:{reason}"
        )
        try:
            normalized_path = _normalize_relative_input(omission.get("path"))
        except JobContractError as exc:
            raise JobContractError("summary_invalid", "follow-on omission pathが不正です") from exc
        if (
            not isinstance(parent_digest, str)
            or SHA256_RE.fullmatch(parent_digest) is None
            or parent_digest not in node_depths
            or not isinstance(payload_digest, str)
            or SHA256_RE.fullmatch(payload_digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_ANALYSIS_OUTPUT_BYTES
            or normalized_path != omission["path"]
            or not _is_safe_public_text(
                omission.get("role"),
                maximum_characters=128,
            )
            or not _is_safe_public_text(
                omission.get("kind"),
                maximum_characters=128,
            )
            or reason not in FOLLOW_ON_OMISSION_REASONS
            or expected_error_marker not in errors
        ):
            raise JobContractError("summary_invalid", "follow-on omission fieldが不正です")
        if reason == "verified_output_read_wall_clock_limit" and document.get("wall_clock_exhausted") is not True:
            raise JobContractError(
                "summary_invalid",
                "wall clock omissionにはwall_clock_exhaustedが必要です",
            )

    edge_keys = {
        "parent_sha256",
        "child_sha256",
        "depth",
        "path",
        "role",
        "kind",
        "size",
        "status",
    }
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != edge_keys:
            raise JobContractError("summary_invalid", "follow-on edge schemaが不正です")
        depth = edge.get("depth")
        size = edge.get("size")
        try:
            normalized_path = _normalize_relative_input(edge.get("path"))
        except JobContractError as exc:
            raise JobContractError("summary_invalid", "follow-on edge pathが不正です") from exc
        if (
            not isinstance(edge.get("parent_sha256"), str)
            or SHA256_RE.fullmatch(edge["parent_sha256"]) is None
            or not isinstance(edge.get("child_sha256"), str)
            or SHA256_RE.fullmatch(edge["child_sha256"]) is None
            or isinstance(depth, bool)
            or not isinstance(depth, int)
            or not 1 <= depth <= 5
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_ANALYSIS_OUTPUT_BYTES
            or normalized_path != edge["path"]
            or not isinstance(edge.get("role"), str)
            or not 1 <= len(edge["role"]) <= 128
            or not isinstance(edge.get("kind"), str)
            or not 1 <= len(edge["kind"]) <= 128
            or edge.get("status") not in FOLLOW_ON_EDGE_STATUSES
            or edge["parent_sha256"] not in node_depths
            or depth != node_depths[edge["parent_sha256"]] + 1
        ):
            raise JobContractError("summary_invalid", "follow-on edge fieldが不正です")
        if edge["status"] in ACTIVE_FOLLOW_ON_EDGE_STATUSES and (
            edge["child_sha256"] not in node_depths or node_depths[edge["child_sha256"]] != depth
        ):
            raise JobContractError("summary_invalid", "active follow-on edgeのchild nodeが不正です")
        if edge["status"] in {
            "child_complete",
            "child_incomplete",
        } and (
            edge["child_sha256"] not in node_depths
            or node_depths[edge["child_sha256"]] != depth
            or edge["size"] > MAX_FOLLOW_ON_PAYLOAD_SIZE
        ):
            raise JobContractError("summary_invalid", "follow-on analyzed edgeが不正です")
        if edge["status"] == "child_complete" and (
            node_states[edge["child_sha256"]] not in {"analyzed", "resumed_complete"}
            or node_case_states[edge["child_sha256"]] != "complete"
        ):
            raise JobContractError("summary_invalid", "follow-on complete edgeのcase状態が不正です")
        if edge["status"] == "child_incomplete" and (
            node_states[edge["child_sha256"]] in {"analyzed", "resumed_complete"}
            and node_case_states[edge["child_sha256"]] == "complete"
        ):
            raise JobContractError("summary_invalid", "follow-on incomplete edgeのcase状態が不正です")
        if edge["status"] in {
            "shared_sha256_reused_complete",
            "shared_sha256_reused_incomplete",
        } and (edge["child_sha256"] not in node_depths or edge["size"] > MAX_FOLLOW_ON_PAYLOAD_SIZE):
            raise JobContractError("summary_invalid", "follow-on reused edgeが不正です")
        if edge["status"] == "shared_sha256_reused_complete" and (
            node_depths[edge["child_sha256"]] > 0
            and (
                node_states[edge["child_sha256"]] not in {"analyzed", "resumed_complete"}
                or node_case_states[edge["child_sha256"]] != "complete"
            )
        ):
            raise JobContractError("summary_invalid", "follow-on reused complete edgeのcase状態が不正です")
        if edge["status"] == "shared_sha256_reused_incomplete" and (
            node_depths[edge["child_sha256"]] > 0
            and node_states[edge["child_sha256"]] in {"analyzed", "resumed_complete"}
            and node_case_states[edge["child_sha256"]] == "complete"
        ):
            raise JobContractError("summary_invalid", "follow-on reused incomplete edgeのcase状態が不正です")
    status = document["status"]
    if omitted_metadata and status != "partial":
        raise JobContractError(
            "summary_invalid",
            "omitted metadataがあるgraphはpartialである必要があります",
        )
    if omitted_commitments and status != "partial":
        raise JobContractError(
            "summary_invalid",
            "omitted metadata commitmentがあるgraphはpartialである必要があります",
        )
    if status == "complete" and (
        not edges
        or errors
        or document.get("wall_clock_exhausted") is not False
        or any(
            edge["status"]
            not in {
                "child_complete",
                "shared_sha256_reused_complete",
            }
            or edge["child_sha256"] not in node_depths
            or (
                node_depths[edge["child_sha256"]] > 0
                and (
                    node_states[edge["child_sha256"]] not in {"analyzed", "resumed_complete"}
                    or node_case_states[edge["child_sha256"]] != "complete"
                )
            )
            for edge in edges
        )
    ):
        raise JobContractError("summary_invalid", "complete follow-on graphに未完了edgeがあります")
    if status == "no_retained_payloads" and (
        edges
        or errors
        or document.get("queued_artifact_count") != 0
        or document.get("queued_total_bytes") != 0
        or document.get("wall_clock_exhausted") is not False
    ):
        raise JobContractError("summary_invalid", "no_retained_payloadsとgraph内容が矛盾します")
    document["_validated_node_depths"] = node_depths
    document["_validated_node_states"] = node_states
    document["_validated_node_case_states"] = node_case_states
    return document


def _automation_state_from_outcome(outcome: Mapping[str, Any]) -> str:
    """analyze_sample.pyと同じ規則でWebUI公開用の自動化状態を求める。"""

    resolution = outcome.get("family_resolution")
    resolution_status = resolution.get("status") if isinstance(resolution, Mapping) else None
    blockers = set(outcome.get("blockers") or [])
    if outcome.get("status") == "complete" and resolution_status == "resolved":
        return "resolved"
    if resolution_status in {"unresolved", "ambiguous"} and blockers.issubset({"family_resolution"}):
        return "unknown"
    return "partial"


def _validated_derived_case_report(
    summary_path: Path,
    item: Mapping[str, Any],
    *,
    analysis_contract: Mapping[str, Any],
    node_state: str,
    node_case_state: str | None,
    derived: bool = True,
) -> dict[str, Any]:
    """子ケースのseal・成果物・契約・lineageとsummary内容を再検証する。"""

    digest = str(item["sha256"])
    case_dir = summary_path.parent / "cases" / digest
    try:
        ensure_no_reparse_components(case_dir)
        if not case_dir.is_dir() or case_dir.resolve(strict=True).parent != (summary_path.parent / "cases").resolve(
            strict=True
        ):
            raise ValueError("derived case directory boundary mismatch")
        report = load_json_object_strict(
            case_dir / "report.json",
            max_bytes=MAX_SUMMARY_BYTES,
        )
    except (JobContractError, OSError, ValueError) as exc:
        raise JobContractError("summary_invalid", "derived case reportを安全に読めません") from exc

    contract = report.get("analysis_contract")
    if not isinstance(contract, dict) or contract != dict(analysis_contract):
        raise JobContractError("summary_invalid", "derived case解析契約が一致しません")
    try:
        integrity_errors = case_integrity_errors(
            case_dir,
            report,
            expected_digest=digest,
            expected_contract=analysis_contract,
            require_resumable=False,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise JobContractError("summary_invalid", "derived case整合性を検証できません") from exc
    if integrity_errors:
        detail = ",".join(integrity_errors[:3])
        raise JobContractError("summary_invalid", f"derived case整合性エラー: {detail}")

    sample = report.get("sample")
    classification = report.get("classification")
    case_state = report.get("case_state")
    if (
        not isinstance(sample, Mapping)
        or sample.get("sha256") != digest
        or sample.get("source_name") != item["source_name"]
        or not isinstance(classification, Mapping)
        or not isinstance(case_state, Mapping)
        or case_state.get("status") != item["case_state"]
    ):
        raise JobContractError("summary_invalid", "case reportとsummaryが一致しません")
    lineage = report.get("follow_on_lineage")
    if derived and (
        node_state not in {"analyzed", "resumed_complete"}
        or node_case_state != item["case_state"]
        or item["resumed"] is not (node_state == "resumed_complete")
        or not isinstance(lineage, Mapping)
        or set(lineage) != {"schema_version", "depth", "parent_sha256", "root_kind"}
        or lineage.get("schema_version") != 1
        or lineage.get("depth") != item["follow_on_depth"]
        or lineage.get("root_kind") != "retained_terminal_or_final_payload"
        or item["parent_sha256"] != [lineage.get("parent_sha256")]
    ):
        raise JobContractError("summary_invalid", "derived case reportとlineageが一致しません")
    if not derived and lineage is not None:
        raise JobContractError("summary_invalid", "root caseにfollow-on lineageがあります")

    try:
        outcome = load_json_object_strict(
            case_dir / "orchestration.json",
            max_bytes=MAX_SUMMARY_BYTES,
        )
        candidate = load_json_object_strict(
            case_dir / "candidate-handler-assessment.json",
            max_bytes=MAX_SUMMARY_BYTES,
        )
    except (JobContractError, OSError, ValueError) as exc:
        raise JobContractError("summary_invalid", "derived case成果物を安全に読めません") from exc
    executions = report.get("handler_executions")
    if not isinstance(executions, list) or any(not isinstance(value, Mapping) for value in executions):
        raise JobContractError("summary_invalid", "derived case handler実行記録が不正です")
    statuses = [value.get("status") for value in executions]
    planned_attempt_count = candidate.get("planned_attempt_count")
    if isinstance(planned_attempt_count, bool) or not isinstance(planned_attempt_count, int):
        raise JobContractError("summary_invalid", "derived case候補試行件数が不正です")
    resolution = outcome.get("family_resolution")
    if case_state.get("status") == "complete" and (
        outcome.get("status") != "complete" or outcome.get("blockers") != []
    ):
        raise JobContractError(
            "summary_invalid",
            "complete caseとorchestration outcomeが一致しません",
        )
    expected = {
        "family": classification.get("family"),
        "selected_family": classification.get("selected_family"),
        "selected_families": classification.get("selected_families") or [],
        "automation_family": resolution.get("family") if isinstance(resolution, Mapping) else None,
        "automation_state": _automation_state_from_outcome(outcome),
        "candidate_handler_attempts": planned_attempt_count,
        "campaign": classification.get("campaign"),
        "handler_succeeded": sum(value == "succeeded" for value in statuses),
        "handler_failed": sum(value in {"failed", "preflight_failed"} for value in statuses),
        "handler_no_evidence": sum(value == "no_evidence" for value in statuses),
        "handler_ambiguous": sum(value == "ambiguous_evidence" for value in statuses),
        "handler_incompatible": sum(value == "incompatible_input_format" for value in statuses),
        "analysis_stage_failed": report.get("generic_triage") == "failed",
        "analysis_stage_partial": report.get("generic_triage") == "partial",
    }
    if any(item.get(key) != value for key, value in expected.items()):
        raise JobContractError("summary_invalid", "derived case summaryがreport内容と一致しません")
    return report


def _observed_root_counts(cases: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """検証済みroot case recordから公開集計を再計算する。"""

    numeric_fields = (
        "candidate_handler_attempts",
        "handler_succeeded",
        "handler_failed",
        "handler_no_evidence",
        "handler_ambiguous",
        "handler_incompatible",
    )
    for item in cases:
        selected = item.get("selected_families")
        if (
            not isinstance(item, Mapping)
            or set(item) != ROOT_CASE_KEYS
            or not isinstance(item.get("source_name"), str)
            or not item["source_name"]
            or not isinstance(selected, list)
            or selected != sorted(set(selected))
            or any(not isinstance(value, str) or FAMILY_RE.fullmatch(value) is None for value in selected)
            or item.get("automation_state") not in {"resolved", "partial", "unknown"}
            or item.get("case_state")
            not in {
                "complete",
                "triaged_unknown",
                "partial",
                "failed",
                "assessment_only_complete",
            }
            or item.get("ai_used") is not False
            or type(item.get("resumed")) is not bool
            or type(item.get("analysis_stage_failed")) is not bool
            or type(item.get("analysis_stage_partial")) is not bool
            or any(
                isinstance(item.get(field), bool) or not isinstance(item.get(field), int) or item[field] < 0
                for field in numeric_fields
            )
        ):
            raise JobContractError("summary_invalid", "root case record schemaが不正です")
    return {
        "analyzed": len(cases),
        "identified": sum(bool(item["selected_families"]) for item in cases),
        "unknown_or_ambiguous": sum(not item["selected_families"] for item in cases),
        "automation_resolved": sum(item["automation_state"] == "resolved" for item in cases),
        "automation_partial": sum(item["automation_state"] == "partial" for item in cases),
        "automation_unknown": sum(item["automation_state"] == "unknown" for item in cases),
        "candidate_handler_attempts": sum(item["candidate_handler_attempts"] for item in cases),
        "handler_successes": sum(item["handler_succeeded"] for item in cases),
        "handler_failures": sum(item["handler_failed"] for item in cases),
        "handler_no_evidence": sum(item["handler_no_evidence"] for item in cases),
        "handler_ambiguous": sum(item["handler_ambiguous"] for item in cases),
        "handler_incompatible": sum(item["handler_incompatible"] for item in cases),
        "analysis_stage_failures": sum(item["analysis_stage_failed"] for item in cases),
        "analysis_stage_partial": sum(item["analysis_stage_partial"] for item in cases),
        "complete": sum(item["case_state"] == "complete" for item in cases),
        "triaged_unknown": sum(item["case_state"] == "triaged_unknown" for item in cases),
        "partial": sum(item["case_state"] == "partial" for item in cases),
        "failed": sum(item["case_state"] == "failed" for item in cases),
        "resumed": sum(item["resumed"] for item in cases),
    }


def _validate_root_reused_edges(
    follow_on: Mapping[str, Any],
    *,
    node_depths: Mapping[str, int],
    root_states: Mapping[str, str],
) -> None:
    """depth 0 rootを参照するshared edgeをseal検証済みroot状態へ結び付ける。"""

    for edge in follow_on["edges"]:
        child_digest = edge["child_sha256"]
        if node_depths.get(child_digest) != 0:
            continue
        if edge["status"] == "shared_sha256_reused_complete" and (root_states.get(child_digest) != "complete"):
            raise JobContractError(
                "summary_invalid",
                "root再利用complete edgeとroot case状態が一致しません",
            )
        if edge["status"] == "shared_sha256_reused_incomplete" and (root_states.get(child_digest) == "complete"):
            raise JobContractError(
                "summary_invalid",
                "root再利用incomplete edgeとroot case状態が一致しません",
            )


def _hash_regular_artifact(
    path: Path,
    *,
    expected_size: int,
    maximum_size: int,
    deadline: float | None = None,
) -> str:
    """単一handleで通常fileをstream hashし、読取中の差替えを拒否する。"""

    _ensure_no_reparse(
        path,
        code="summary_invalid",
        message="follow-on payload pathにreparse pointがあります",
    )
    try:
        before = path.lstat()
    except OSError as exc:
        raise JobContractError("summary_invalid", "follow-on payloadを確認できません") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or _stat_has_reparse_attribute(before)
        or before.st_nlink != 1
        or isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or not 0 < expected_size <= maximum_size
        or before.st_size != expected_size
    ):
        raise JobContractError("summary_invalid", "follow-on payloadのfile境界が不正です")

    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise JobContractError("summary_invalid", "follow-on payloadを開けません") from exc
    digest = hashlib.sha256()
    observed = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or _stat_has_reparse_attribute(opened)
                or opened.st_nlink != 1
                or opened.st_size != expected_size
                or not _same_file_identity(before, opened)
            ):
                raise JobContractError("summary_invalid", "follow-on payload handleが不正です")
            while observed < expected_size:
                if deadline is not None and time.monotonic() >= deadline:
                    raise JobContractError(
                        "summary_validation_timeout",
                        "follow-on payload再検証が時間上限を超えました",
                    )
                chunk = handle.read(min(1024 * 1024, expected_size - observed))
                if not chunk:
                    break
                observed += len(chunk)
                digest.update(chunk)
            if handle.read(1):
                raise JobContractError("summary_invalid", "follow-on payload sizeが増加しました")
            after_handle = os.fstat(handle.fileno())
    except JobContractError:
        raise
    except OSError as exc:
        raise JobContractError("summary_invalid", "follow-on payloadを読めません") from exc
    try:
        after_path = path.lstat()
    except OSError as exc:
        raise JobContractError("summary_invalid", "follow-on payloadが読取中に消失しました") from exc
    if (
        observed != expected_size
        or opened.st_size != observed
        or after_handle.st_size != observed
        or opened.st_mtime_ns != after_handle.st_mtime_ns
        or opened.st_ctime_ns != after_handle.st_ctime_ns
        or not _same_file_identity(opened, after_path)
        or after_path.st_nlink != 1
        or _stat_has_reparse_attribute(after_path)
    ):
        raise JobContractError("summary_invalid", "follow-on payloadが読取中に変更されました")
    return digest.hexdigest()


def _retained_outputs_from_validated_case(
    summary_path: Path,
    digest: str,
    report: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """seal検証済みcaseのselected／candidate wrapperから保持metadataを読む。"""

    case_dir = summary_path.parent / "cases" / digest
    wrappers: list[Mapping[str, Any]] = []
    for execution in report.get("handler_executions") or []:
        if not isinstance(execution, Mapping) or not isinstance(execution.get("result"), str):
            continue
        wrapper_path = resolve_case_artifact(case_dir, execution["result"])
        wrappers.append(load_json_object_strict(wrapper_path, max_bytes=MAX_SUMMARY_BYTES))
    candidate_path = resolve_case_artifact(case_dir, "candidate-handler-assessment.json")
    candidate = load_json_object_strict(candidate_path, max_bytes=MAX_SUMMARY_BYTES)
    for family in candidate.get("families") or []:
        if not isinstance(family, Mapping):
            continue
        for attempt in family.get("attempts") or []:
            wrapper = attempt.get("result") if isinstance(attempt, Mapping) else None
            if isinstance(wrapper, Mapping):
                wrappers.append(wrapper)

    outputs: list[dict[str, Any]] = []
    for wrapper in wrappers:
        supplied = wrapper.get("verified_binary_outputs")
        if supplied is None:
            continue
        if (
            not isinstance(supplied, Sequence)
            or isinstance(supplied, (str, bytes, bytearray))
            or len(supplied) > MAX_FOLLOW_ON_ARTIFACTS
        ):
            raise JobContractError(
                "summary_invalid",
                "保持payload metadataのschemaが不正です",
            )
        audit = orchestration_outcome._verified_output_audit(  # noqa: SLF001
            wrapper.get("verified_binary_output_audit"),
            output_count=len(supplied),
        )
        if supplied and audit is None:
            raise JobContractError(
                "summary_invalid",
                "保持payload auditが不正です",
            )
        if audit is None:
            continue
        parsed = [
            orchestration_outcome._verified_binary_output(value)  # noqa: SLF001
            for value in supplied
        ]
        if any(value is None for value in parsed):
            raise JobContractError(
                "summary_invalid",
                "保持payload metadataを検証できません",
            )
        outputs.extend(value for value in parsed if value is not None)
    return outputs


def _validated_case_handler_records(
    summary_path: Path,
    digest: str,
    report: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """seal検証済みcaseからoutcome再計算用handler recordを復元する。"""

    from handler_catalog import discover_handlers  # noqa: PLC0415

    case_dir = summary_path.parent / "cases" / digest
    family_by_handler = {spec.id: spec.family for spec in discover_handlers()}
    records: list[dict[str, Any]] = []
    for execution in report.get("handler_executions") or []:
        if not isinstance(execution, Mapping):
            raise JobContractError("summary_invalid", "selected handler recordが不正です")
        handler_id = execution.get("handler_id")
        family = family_by_handler.get(handler_id)
        relative = execution.get("result")
        if family is None or not isinstance(relative, str):
            continue
        wrapper = load_json_object_strict(
            resolve_case_artifact(case_dir, relative),
            max_bytes=MAX_SUMMARY_BYTES,
        )
        records.append(
            {
                "source": "selected_family_analysis",
                "family": family,
                "handler_id": handler_id,
                "status": execution.get("status"),
                "selected_evidence": execution.get("selected_evidence"),
                "selected_layer_sha256": execution.get("selected_layer_sha256"),
                "verified_binary_outputs": wrapper.get("verified_binary_outputs"),
                "verified_binary_output_audit": wrapper.get("verified_binary_output_audit"),
                "result": wrapper,
            }
        )
    candidate = load_json_object_strict(
        resolve_case_artifact(case_dir, "candidate-handler-assessment.json"),
        max_bytes=MAX_SUMMARY_BYTES,
    )
    for family_result in candidate.get("families") or []:
        if not isinstance(family_result, Mapping):
            raise JobContractError("summary_invalid", "candidate family recordが不正です")
        family = family_result.get("family")
        for attempt in family_result.get("attempts") or []:
            if not isinstance(attempt, Mapping):
                raise JobContractError("summary_invalid", "candidate handler recordが不正です")
            wrapper = attempt.get("result")
            if not isinstance(wrapper, Mapping):
                continue
            supplied_source = attempt.get("source")
            source = (
                supplied_source if isinstance(supplied_source, str) and supplied_source else "candidate_verification"
            )
            records.append(
                {
                    "source": source,
                    "family": family,
                    "handler_id": attempt.get("handler_id"),
                    "status": attempt.get("status"),
                    "handler_evidence": attempt.get("handler_evidence"),
                    "detector_corroboration": attempt.get("detector_corroboration"),
                    "selected_layer_sha256": (
                        attempt.get("selected_layer_sha256") or (attempt.get("layer") or {}).get("sha256")
                    ),
                    "verified_binary_outputs": wrapper.get("verified_binary_outputs"),
                    "verified_binary_output_audit": wrapper.get("verified_binary_output_audit"),
                    "result": wrapper,
                }
            )
    return records


def _recomputed_parent_promotion_outputs(
    summary_path: Path,
    *,
    parent_digest: str,
    parent_report: Mapping[str, Any],
    resolved_family: str,
    top_children: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """resolved familyのwrapperと内部proofから親の必須payload集合を再計算する。"""

    records = _validated_case_handler_records(
        summary_path,
        parent_digest,
        parent_report,
    )
    outputs = orchestration_outcome.summarize_handler_outputs(
        records,
        family_filter=resolved_family,
    )
    required = outputs.get("retained_terminal_payload_sha256")
    verified = outputs.get("terminal_payload_sha256")
    if not isinstance(required, list) or not required or required != sorted(set(required)) or verified != required:
        raise JobContractError(
            "summary_invalid",
            "resolved familyの保持payloadが全て厳格completeではありません",
        )

    for record in records:
        if str(record.get("family")).casefold() != resolved_family.casefold():
            continue
        if orchestration_outcome.assess_handler_record(record).get("accepted") is not True:
            continue
        supplied = record.get("verified_binary_outputs")
        if not isinstance(supplied, Sequence) or isinstance(supplied, (str, bytes, bytearray)):
            continue
        parsed = [
            orchestration_outcome._verified_binary_output(value)  # noqa: SLF001
            for value in supplied
        ]
        if any(value is None for value in parsed):
            raise JobContractError("summary_invalid", "resolved wrapper outputが不正です")
        wrapper_digests = sorted({value["sha256"] for value in parsed if value is not None})
        if not wrapper_digests:
            continue
        audit = orchestration_outcome._verified_output_audit(  # noqa: SLF001
            record.get("verified_binary_output_audit"),
            output_count=len(supplied),
        )
        wrapper = record.get("result")
        internal = wrapper.get("follow_on_analysis_proof") if isinstance(wrapper, Mapping) else None
        children = internal.get("children") if isinstance(internal, Mapping) else None
        if (
            audit is None
            or audit.get("analysis_complete") is not True
            or not isinstance(internal, Mapping)
            or set(internal) != {"schema_version", "status", "children"}
            or internal.get("schema_version") != 1
            or internal.get("status") != "all_retained_payloads_strict_complete"
            or not isinstance(children, list)
        ):
            raise JobContractError("summary_invalid", "resolved wrapper内部proofが不正です")
        internal_digests = [child.get("sha256") if isinstance(child, Mapping) else None for child in children]
        if internal_digests != wrapper_digests or any(
            not isinstance(child, Mapping) or dict(child) != dict(top_children.get(str(child.get("sha256"))) or {})
            for child in children
        ):
            raise JobContractError(
                "summary_invalid",
                "resolved wrapper内部proofと保持payload集合が完全一致しません",
            )
    return outputs


def _validate_follow_on_edge_provenance(
    summary_path: Path,
    *,
    follow_on: Mapping[str, Any],
    validated_case_reports: Mapping[str, Mapping[str, Any]],
    deadline: float | None = None,
) -> None:
    """全edgeを親のseal済みwrapper metadataと実payload hashへ結び付ける。"""

    expected_by_parent: dict[str, Counter[tuple[str, str, str, str, int]]] = {}
    hash_cache: dict[tuple[str, str, str, int], str] = {}
    for parent_digest, parent_report in validated_case_reports.items():
        try:
            retained_outputs = _retained_outputs_from_validated_case(summary_path, parent_digest, parent_report)
        except (JobContractError, OSError, TypeError, ValueError) as exc:
            raise JobContractError(
                "summary_invalid",
                "follow-on parent wrapperを安全に検証できません",
            ) from exc
        expected_by_parent[parent_digest] = Counter(
            (
                value["sha256"],
                value["path"],
                value["role"],
                value["kind"],
                value["size"],
            )
            for value in retained_outputs
        )

    verified_bytes = 0
    for edge in follow_on["edges"]:
        parent_digest = edge["parent_sha256"]
        parent_report = validated_case_reports.get(parent_digest)
        if not isinstance(parent_report, Mapping):
            raise JobContractError("summary_invalid", "follow-on edgeのparent reportが未検証です")
        identity = (
            edge["child_sha256"],
            edge["path"],
            edge["role"],
            edge["kind"],
            edge["size"],
        )
        if expected_by_parent[parent_digest][identity] <= 0:
            raise JobContractError(
                "summary_invalid",
                "follow-on edgeが親wrapperの保持metadataと一致しません",
            )
        expected_by_parent[parent_digest][identity] -= 1
        cache_key = (
            parent_digest,
            edge["path"],
            edge["child_sha256"],
            edge["size"],
        )
        if cache_key not in hash_cache:
            if deadline is not None and time.monotonic() >= deadline:
                raise JobContractError(
                    "summary_validation_timeout",
                    "follow-on edge再検証が時間上限を超えました",
                )
            if verified_bytes + edge["size"] > MAX_FOLLOW_ON_TOTAL_BYTES:
                raise JobContractError(
                    "summary_invalid",
                    "follow-on edge再検証が合計size上限を超えます",
                )
            try:
                payload_path = resolve_case_artifact(
                    summary_path.parent / "cases" / parent_digest,
                    edge["path"],
                )
            except (OSError, TypeError, ValueError) as exc:
                raise JobContractError(
                    "summary_invalid",
                    "follow-on edge payload pathが不正です",
                ) from exc
            hash_cache[cache_key] = _hash_regular_artifact(
                payload_path,
                expected_size=edge["size"],
                maximum_size=MAX_FOLLOW_ON_TOTAL_BYTES,
                deadline=deadline,
            )
            verified_bytes += edge["size"]
        if not hmac.compare_digest(hash_cache[cache_key], edge["child_sha256"]):
            raise JobContractError("summary_invalid", "follow-on edge payload hashが一致しません")
    for omission in follow_on["omitted_metadata"]:
        parent_digest = omission["parent_sha256"]
        if parent_digest not in validated_case_reports:
            raise JobContractError(
                "summary_invalid",
                "follow-on omissionのparent reportが未検証です",
            )
        identity = (
            omission["sha256"],
            omission["path"],
            omission["role"],
            omission["kind"],
            omission["size"],
        )
        if expected_by_parent[parent_digest][identity] <= 0:
            raise JobContractError(
                "summary_invalid",
                "follow-on omissionが親wrapperの保持metadataと一致しません",
            )
        expected_by_parent[parent_digest][identity] -= 1

    expected_commitments: list[dict[str, Any]] = []
    for parent_digest in sorted(expected_by_parent):
        remaining = {identity: count for identity, count in expected_by_parent[parent_digest].items() if count > 0}
        commitment = canonical_multiset_commitment(remaining)
        if commitment is not None:
            expected_commitments.append(
                {
                    "parent_sha256": parent_digest,
                    "count": commitment["count"],
                    "sha256": commitment["sha256"],
                }
            )
    supplied_commitments = follow_on.get("omitted_metadata_commitments", [])
    if not isinstance(supplied_commitments, list) or len(supplied_commitments) != len(expected_commitments):
        raise JobContractError(
            "summary_invalid",
            "保持payload残余commitment件数が再計算値と一致しません",
        )
    commitment_keys = {"parent_sha256", "count", "sha256"}
    for supplied, expected in zip(
        supplied_commitments,
        expected_commitments,
        strict=True,
    ):
        if (
            not isinstance(supplied, Mapping)
            or set(supplied) != commitment_keys
            or supplied.get("parent_sha256") != expected["parent_sha256"]
            or supplied.get("count") != expected["count"]
            or not isinstance(supplied.get("sha256"), str)
            or not hmac.compare_digest(supplied["sha256"], expected["sha256"])
        ):
            raise JobContractError(
                "summary_invalid",
                "保持payload残余commitmentが再計算値と一致しません",
            )
    if (
        follow_on.get("verified_read_count") != len(hash_cache)
        or follow_on.get("verified_read_bytes") != verified_bytes
    ):
        raise JobContractError(
            "summary_count_mismatch",
            "follow-on再読取りcounterが実検証値と一致しません",
        )


def _validate_parent_promotion_proofs(
    summary_path: Path,
    *,
    follow_on: Mapping[str, Any],
    follow_on_contract: Mapping[str, Any],
    validated_case_reports: Mapping[str, Mapping[str, Any]],
    node_case_states: Mapping[str, str | None],
) -> None:
    """親昇格proofをgraph、厳格completeな親子case、品質gateへ再結合する。"""

    promoted_parent_hashes = set(follow_on.get("promoted_parent_sha256") or [])
    proof_bearing_hashes = {
        digest for digest, report in validated_case_reports.items() if report.get("follow_on_promotion") is not None
    }
    if promoted_parent_hashes != proof_bearing_hashes:
        raise JobContractError(
            "summary_invalid",
            "昇格parent集合とfollow_on_promotion proof集合が一致しません",
        )

    complete_edges_by_parent: dict[str, set[str]] = {}
    for edge in follow_on["edges"]:
        if edge["status"] in {"child_complete", "shared_sha256_reused_complete"}:
            complete_edges_by_parent.setdefault(edge["parent_sha256"], set()).add(edge["child_sha256"])

    outcome_cache: dict[str, dict[str, Any]] = {}

    def load_outcome(digest: str) -> dict[str, Any]:
        if digest not in outcome_cache:
            outcome_cache[digest] = load_json_object_strict(
                summary_path.parent / "cases" / digest / "orchestration.json",
                max_bytes=MAX_SUMMARY_BYTES,
            )
        return outcome_cache[digest]

    for parent_digest in sorted(promoted_parent_hashes):
        report = validated_case_reports.get(parent_digest)
        proof = report.get("follow_on_promotion") if isinstance(report, Mapping) else None
        children = proof.get("children") if isinstance(proof, Mapping) else None
        parent_outcome = load_outcome(parent_digest)
        parent_resolution = parent_outcome.get("family_resolution")
        if (
            not isinstance(report, Mapping)
            or (report.get("case_state") or {}).get("status") != "complete"
            or parent_outcome.get("status") != "complete"
            or parent_outcome.get("blockers") != []
            or not isinstance(parent_resolution, Mapping)
            or parent_resolution.get("status") != "resolved"
            or not isinstance(proof, Mapping)
            or set(proof)
            != {
                "schema_version",
                "status",
                "child_analysis_contract_sha256",
                "children",
            }
            or proof.get("schema_version") != 1
            or proof.get("status") != "verified_children_linked"
            or proof.get("child_analysis_contract_sha256") != follow_on_contract["sha256"]
            or not isinstance(children, list)
            or not children
        ):
            raise JobContractError("summary_invalid", "parent promotion proofが不正です")
        proof_digests: list[str] = []
        for child_proof in children:
            if (
                not isinstance(child_proof, Mapping)
                or set(child_proof)
                != {
                    "sha256",
                    "analysis_contract_sha256",
                    "report_semantic_sha256",
                }
                or child_proof.get("analysis_contract_sha256") != follow_on_contract["sha256"]
            ):
                raise JobContractError("summary_invalid", "parent child proofが不正です")
            child_digest = child_proof.get("sha256")
            child_report = validated_case_reports.get(child_digest)
            child_outcome = (
                load_outcome(child_digest)
                if isinstance(child_digest, str) and child_digest in validated_case_reports
                else None
            )
            if (
                not isinstance(child_digest, str)
                or child_digest not in complete_edges_by_parent.get(parent_digest, set())
                or not isinstance(child_report, Mapping)
                or (child_report.get("case_state") or {}).get("status") != "complete"
                or node_case_states.get(child_digest) != "complete"
                or not isinstance(child_outcome, Mapping)
                or child_outcome.get("status") != "complete"
                or child_outcome.get("blockers") != []
                or child_report.get("report_semantic_sha256") != child_proof.get("report_semantic_sha256")
            ):
                raise JobContractError("summary_invalid", "parent child proofがgraphと一致しません")
            proof_digests.append(child_digest)
        if proof_digests != sorted(set(proof_digests)):
            raise JobContractError("summary_invalid", "parent child proofが重複または未整列です")
        top_children = {str(child["sha256"]): child for child in children if isinstance(child, Mapping)}
        resolved_family = parent_resolution.get("family")
        if not isinstance(resolved_family, str):
            raise JobContractError("summary_invalid", "parent resolved familyが不正です")
        recomputed_outputs = _recomputed_parent_promotion_outputs(
            summary_path,
            parent_digest=parent_digest,
            parent_report=report,
            resolved_family=resolved_family,
            top_children=top_children,
        )
        if parent_outcome.get("outputs") != recomputed_outputs:
            raise JobContractError(
                "summary_invalid",
                "parent outcome outputsがresolved wrapper再計算値と一致しません",
            )
        terminal_digests = (parent_outcome.get("outputs") or {}).get("terminal_payload_sha256")
        required_digests = recomputed_outputs.get("retained_terminal_payload_sha256")
        if terminal_digests != proof_digests or required_digests != proof_digests:
            raise JobContractError("summary_invalid", "parent promotion proofと品質gateが一致しません")


def _expected_summary_settings(
    options: Mapping[str, Any],
    analysis_contract: Mapping[str, Any],
) -> dict[str, Any]:
    """request optionとsealed root契約からsummary.settingsを独立再構築する。"""

    contract_settings = analysis_contract.get("settings")
    if not isinstance(contract_settings, Mapping):
        raise JobContractError("summary_invalid", "root解析契約settingsが不正です")
    static_tools = contract_settings.get("static_tools")
    if not isinstance(static_tools, Mapping):
        raise JobContractError("summary_invalid", "root解析契約のstatic_toolsが不正です")
    return {
        "archive_mode": options.get("archive_mode"),
        "forced_family": options.get("family"),
        "minimum_confidence": options.get("minimum_confidence"),
        "assessment_only": options.get("assessment_only"),
        "max_files": options.get("max_files"),
        "max_file_size": options.get("max_file_size"),
        "string_scan_limit": options.get("string_scan_limit"),
        "family_hint_manifest": contract_settings.get("family_hint_manifest"),
        "static_tools": dict(static_tools),
        "force_container_probe": options.get("force_container_probe"),
        "max_static_layers": options.get("max_static_layers"),
        "retry_max_static_layers": options.get("retry_max_static_layers"),
        "resume": False,
        "follow_on_fixed_point": options.get("assessment_only") is False,
    }


def _validate_summary_input_records(
    summary: Mapping[str, Any],
    *,
    root_hashes: set[str],
    expected_input_manifest: Sequence[ExpectedInputUnit] | None,
) -> None:
    """case／duplicate／errorを固定入力manifestへexact照合する。"""

    duplicates = summary["duplicates"]
    errors = summary["errors"]
    for item in duplicates:
        if (
            not isinstance(item, dict)
            or set(item) != {"source_name", "sha256"}
            or not _is_safe_public_text(
                item.get("source_name"),
                maximum_characters=512,
                source_name=True,
            )
            or not isinstance(item.get("sha256"), str)
            or SHA256_RE.fullmatch(item["sha256"]) is None
            or item["sha256"] not in root_hashes
        ):
            raise JobContractError("summary_invalid", "duplicate record schemaまたはroot参照が不正です")
    for item in errors:
        if (
            not isinstance(item, dict)
            or set(item) != {"source_name", "error"}
            or not _is_safe_public_text(
                item.get("source_name"),
                maximum_characters=512,
                source_name=True,
            )
            or not _is_safe_public_text(
                item.get("error"),
                maximum_characters=4_096,
            )
        ):
            raise JobContractError("summary_invalid", "error record schemaが不正です")
    if expected_input_manifest is None:
        return

    case_counter: Counter[tuple[str, str]] = Counter()
    for item in summary["cases"]:
        if (
            not isinstance(item, Mapping)
            or not _is_safe_public_text(
                item.get("source_name"),
                maximum_characters=512,
                source_name=True,
            )
            or not isinstance(item.get("sha256"), str)
            or SHA256_RE.fullmatch(item["sha256"]) is None
        ):
            raise JobContractError("summary_invalid", "root case入力identityが不正です")
        case_counter[(item["source_name"], item["sha256"])] += 1
    duplicate_counter = Counter((item["source_name"], item["sha256"]) for item in duplicates)
    error_counter = Counter(item["source_name"] for item in errors)

    seen: set[str] = set()
    expected_duplicates: Counter[tuple[str, str]] = Counter()
    primary_records: list[ExpectedInputUnit] = []
    read_failure_sources: list[str] = []
    for record in expected_input_manifest:
        if not record.read_succeeded:
            read_failure_sources.append(record.source_name)
            continue
        if record.sha256 is None or record.unit_source_name is None or SHA256_RE.fullmatch(record.sha256) is None:
            raise JobContractError("summary_invalid", "固定入力manifestが不正です")
        if record.sha256 in seen:
            expected_duplicates[(record.source_name, record.sha256)] += 1
            continue
        seen.add(record.sha256)
        primary_records.append(record)
    if duplicate_counter != expected_duplicates:
        raise JobContractError(
            "summary_invalid",
            "duplicatesが固定入力manifestと一致しません",
        )
    for source_name in read_failure_sources:
        if error_counter[source_name] <= 0:
            raise JobContractError(
                "summary_invalid",
                "入力読込みerrorが固定入力manifestと一致しません",
            )
        error_counter[source_name] -= 1
    for record in primary_records:
        case_key = (str(record.unit_source_name), str(record.sha256))
        if case_counter[case_key] > 0:
            case_counter[case_key] -= 1
        elif error_counter[record.source_name] > 0:
            error_counter[record.source_name] -= 1
        else:
            raise JobContractError(
                "summary_invalid",
                "root case／errorが固定入力manifestと一致しません",
            )
    if any(case_counter.values()) or any(error_counter.values()):
        raise JobContractError(
            "summary_invalid",
            "case／errorに固定入力manifest外のrecordがあります",
        )


def _validated_summary(
    path: Path,
    *,
    expected_input_files: int,
    expected_analysis_contract: Mapping[str, Any] | None = None,
    expected_follow_on_contract: Mapping[str, Any] | None = None,
    expected_options: Mapping[str, Any] | None = None,
    expected_input_manifest: Sequence[ExpectedInputUnit] | None = None,
    verify_root_cases: bool = False,
) -> tuple[dict[str, Any], dict[str, int]]:
    validation_deadline = time.monotonic() + MAX_FOLLOW_ON_WALL_SECONDS if verify_root_cases else None
    summary = load_json_object_strict(path, max_bytes=MAX_SUMMARY_BYTES)
    if set(summary) != SUMMARY_KEYS:
        raise JobContractError("summary_invalid", "summary.jsonのtop-level schemaが不正です")
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
    if not isinstance(raw_counts, dict) or set(raw_counts) != set(SUMMARY_COUNT_KEYS):
        raise JobContractError("summary_invalid", "summary.jsonにcounts objectがありません")
    counts: dict[str, int] = {}
    for key in SUMMARY_COUNT_KEYS:
        value = raw_counts[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise JobContractError("summary_invalid", f"summary counts.{key}が非負整数ではありません")
        counts[key] = value
    for key, expected_type in (("cases", list), ("duplicates", list), ("errors", list)):
        if not isinstance(summary.get(key), expected_type):
            raise JobContractError("summary_invalid", f"summary.{key}はarrayである必要があります")
    follow_on = _validated_follow_on_artifact(path, summary)
    follow_on_contract = summary.get("follow_on_analysis_contract")
    if (
        not isinstance(follow_on_contract, dict)
        or follow_on_contract.get("schema_version") != SCHEMA_VERSION
        or not isinstance(follow_on_contract.get("sha256"), str)
        or SHA256_RE.fullmatch(follow_on_contract["sha256"]) is None
        or (
            follow_on.get("analysis_contract_sha256") is not None
            and follow_on["analysis_contract_sha256"] != follow_on_contract["sha256"]
        )
        or (expected_follow_on_contract is not None and follow_on_contract != dict(expected_follow_on_contract))
    ):
        raise JobContractError("summary_invalid", "follow-on完全解析契約が一致しません")
    derived_cases = summary.get("derived_cases")
    raw_derived_counts = summary.get("derived_counts")
    if (
        not isinstance(derived_cases, list)
        or not isinstance(raw_derived_counts, dict)
        or set(raw_derived_counts) != set(DERIVED_COUNT_KEYS)
    ):
        raise JobContractError(
            "summary_invalid",
            "summary.derived_cases／derived_countsがありません",
        )
    derived_counts: dict[str, int] = {}
    for key in DERIVED_COUNT_KEYS:
        value = raw_derived_counts.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise JobContractError(
                "summary_invalid",
                f"summary derived_counts.{key}が非負整数ではありません",
            )
        derived_counts[key] = value
    derived_keys = {
        "sha256",
        "source_name",
        "family",
        "selected_family",
        "selected_families",
        "automation_family",
        "automation_state",
        "candidate_handler_attempts",
        "ai_used",
        "campaign",
        "handler_succeeded",
        "handler_failed",
        "handler_no_evidence",
        "handler_ambiguous",
        "handler_incompatible",
        "analysis_stage_failed",
        "analysis_stage_partial",
        "case_state",
        "report",
        "resumed",
        "case_origin",
        "follow_on_depth",
        "parent_sha256",
    }
    root_hash_list = [item.get("sha256") if isinstance(item, dict) else None for item in summary["cases"]]
    if (
        any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in root_hash_list)
        or len(set(root_hash_list)) != len(root_hash_list)
        or sorted(root_hash_list) != follow_on["roots"]
    ):
        raise JobContractError("summary_invalid", "root case SHA-256とfollow-on rootsが一致しません")
    root_hashes = set(root_hash_list)
    if expected_input_manifest is not None and len(expected_input_manifest) != expected_input_files:
        raise JobContractError(
            "summary_invalid",
            "固定入力manifest件数が検証済み入力件数と一致しません",
        )
    _validate_summary_input_records(
        summary,
        root_hashes=root_hashes,
        expected_input_manifest=expected_input_manifest,
    )
    validated_case_reports: dict[str, dict[str, Any]] = {}
    root_contract = summary.get("analysis_contract")
    if verify_root_cases or expected_analysis_contract is not None:
        if (
            not isinstance(root_contract, dict)
            or root_contract.get("schema_version") != SCHEMA_VERSION
            or not isinstance(root_contract.get("sha256"), str)
            or SHA256_RE.fullmatch(root_contract["sha256"]) is None
            or (expected_analysis_contract is not None and root_contract != dict(expected_analysis_contract))
        ):
            raise JobContractError("summary_invalid", "root完全解析契約が不正です")
    if verify_root_cases:
        contract_settings = root_contract.get("settings")
        summary_settings = summary.get("settings")
        if (
            not isinstance(contract_settings, Mapping)
            or type(contract_settings.get("assessment_only")) is not bool
            or expected_options is None
            or not isinstance(summary_settings, dict)
            or set(summary_settings) != SUMMARY_SETTINGS_KEYS
            or summary_settings != _expected_summary_settings(expected_options, root_contract)
        ):
            raise JobContractError(
                "summary_invalid",
                "assessment_only設定がroot解析契約と一致しません",
            )
        expected_assessment_only = contract_settings["assessment_only"]
        if (expected_assessment_only and follow_on["status"] != "disabled_assessment_only") or (
            not expected_assessment_only
            and follow_on["status"] in {"disabled_assessment_only", "disabled_repository_output"}
        ):
            raise JobContractError(
                "summary_invalid",
                "follow-on状態が解析要求と一致しません",
            )
        for item in summary["cases"]:
            digest = item.get("sha256") if isinstance(item, dict) else None
            if (
                not isinstance(item, dict)
                or not isinstance(digest, str)
                or item.get("report") != f"cases/{digest}/report.json"
                or item.get("ai_used") is not False
            ):
                raise JobContractError("summary_invalid", "root case summaryが不正です")
            validated_case_reports[digest] = _validated_derived_case_report(
                path,
                item,
                analysis_contract=root_contract,
                node_state="",
                node_case_state=None,
                derived=False,
            )
        observed_root = _observed_root_counts(summary["cases"])
        if any(counts[key] != value for key, value in observed_root.items()):
            raise JobContractError(
                "summary_count_mismatch",
                "root countsがseal検証済みcase内容と一致しません",
            )
    node_depths = follow_on.pop("_validated_node_depths")
    node_states = follow_on.pop("_validated_node_states")
    node_case_states = follow_on.pop("_validated_node_case_states")
    active_edges = {
        (edge["parent_sha256"], edge["child_sha256"])
        for edge in follow_on["edges"]
        if edge["status"] in ACTIVE_FOLLOW_ON_EDGE_STATUSES
    }
    derived_hashes: set[str] = set()
    for item in derived_cases:
        if not isinstance(item, dict) or set(item) != derived_keys:
            raise JobContractError("summary_invalid", "derived case schemaが一致しません")
        digest = item.get("sha256")
        parents = item.get("parent_sha256")
        selected = item.get("selected_families")
        numeric_fields = (
            "candidate_handler_attempts",
            "handler_succeeded",
            "handler_failed",
            "handler_no_evidence",
            "handler_ambiguous",
            "handler_incompatible",
        )
        family_fields = ("family", "selected_family", "automation_family")
        if (
            not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or digest in root_hashes
            or digest in derived_hashes
            or item.get("case_origin") != "derived_follow_on"
            or not isinstance(item.get("follow_on_depth"), int)
            or isinstance(item.get("follow_on_depth"), bool)
            or not 1 <= item["follow_on_depth"] <= 4
            or not isinstance(parents, list)
            or not parents
            or parents != sorted(set(parents))
            or any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in parents)
            or not isinstance(selected, list)
            or any(not isinstance(value, str) or FAMILY_RE.fullmatch(value) is None for value in selected)
            or selected != sorted(set(selected))
            or any(
                item.get(field) is not None
                and (not isinstance(item.get(field), str) or FAMILY_RE.fullmatch(item[field]) is None)
                for field in family_fields
            )
            or item.get("automation_state") not in {"resolved", "partial", "unknown"}
            or any(
                isinstance(item.get(field), bool) or not isinstance(item.get(field), int) or item[field] < 0
                for field in numeric_fields
            )
            or type(item.get("analysis_stage_failed")) is not bool
            or type(item.get("analysis_stage_partial")) is not bool
            or item.get("case_state") not in {"complete", "triaged_unknown", "partial", "failed"}
            or item.get("ai_used") is not False
            or type(item.get("resumed")) is not bool
            or item.get("report") != f"cases/{digest}/report.json"
            or item.get("source_name") != f"follow-on-{digest[:16]}.bin"
            or node_depths.get(digest) != item.get("follow_on_depth")
        ):
            raise JobContractError("summary_invalid", "derived case fieldが不正です")
        validated_case_reports[digest] = _validated_derived_case_report(
            path,
            item,
            analysis_contract=follow_on_contract,
            node_state=node_states.get(digest, ""),
            node_case_state=node_case_states.get(digest),
        )
        derived_hashes.add(digest)
    expected_derived_hashes = {
        digest
        for digest, state in node_states.items()
        if node_depths[digest] > 0 and state in {"analyzed", "resumed_complete"}
    }
    if derived_hashes != expected_derived_hashes:
        raise JobContractError(
            "summary_count_mismatch",
            "follow-on完成node集合とderived_casesが一致しません",
        )
    if verify_root_cases and follow_on["status"] in {
        "complete",
        "partial",
        "no_retained_payloads",
    }:
        _validate_follow_on_edge_provenance(
            path,
            follow_on=follow_on,
            validated_case_reports=validated_case_reports,
            deadline=validation_deadline,
        )
        root_states = {item["sha256"]: item["case_state"] for item in summary["cases"]}
        _validate_root_reused_edges(
            follow_on,
            node_depths=node_depths,
            root_states=root_states,
        )
    _validate_parent_promotion_proofs(
        path,
        follow_on=follow_on,
        follow_on_contract=follow_on_contract,
        validated_case_reports=validated_case_reports,
        node_case_states=node_case_states,
    )
    known_hashes = root_hashes | derived_hashes
    if any(
        parent not in known_hashes
        or node_depths.get(parent) != item["follow_on_depth"] - 1
        or (parent, item["sha256"]) not in active_edges
        for item in derived_cases
        for parent in item["parent_sha256"]
    ):
        raise JobContractError("summary_invalid", "derived parent_sha256がjob内caseを参照していません")
    observed_derived = {
        "analyzed": len(derived_cases),
        "identified": sum(bool(item["selected_families"]) for item in derived_cases),
        "unknown_or_ambiguous": sum(not item["selected_families"] for item in derived_cases),
        "complete": sum(item["case_state"] == "complete" for item in derived_cases),
        "triaged_unknown": sum(item["case_state"] == "triaged_unknown" for item in derived_cases),
        "partial": sum(item["case_state"] == "partial" for item in derived_cases),
        "failed": sum(item["case_state"] == "failed" for item in derived_cases),
        "resumed": sum(item["resumed"] for item in derived_cases),
    }
    if observed_derived != derived_counts:
        raise JobContractError("summary_count_mismatch", "derived countsがcase内容と一致しません")
    if len(derived_cases) != derived_counts["analyzed"]:
        raise JobContractError("summary_count_mismatch", "derived_cases件数がanalyzedと一致しません")
    if derived_counts["identified"] + derived_counts["unknown_or_ambiguous"] != derived_counts["analyzed"]:
        raise JobContractError("summary_count_mismatch", "derived family分類件数が一致しません")
    derived_terminal = sum(derived_counts[key] for key in ("complete", "triaged_unknown", "partial", "failed"))
    if derived_terminal != derived_counts["analyzed"] or derived_counts["resumed"] > derived_counts["analyzed"]:
        raise JobContractError("summary_count_mismatch", "derived case状態件数が一致しません")
    if counts["input_files"] != expected_input_files:
        raise JobContractError("summary_count_mismatch", "summary input_filesが検証済み入力file数と一致しません")
    if counts["input_files"] != counts["analyzed"] + counts["duplicates"] + counts["errors"]:
        raise JobContractError(
            "summary_count_mismatch", "analyzed、duplicates、errorsの合計がinput_filesと一致しません"
        )
    if counts["identified"] + counts["unknown_or_ambiguous"] != counts["analyzed"]:
        raise JobContractError("summary_count_mismatch", "family分類件数の合計がanalyzedと一致しません")
    if (
        counts["automation_resolved"] + counts["automation_partial"] + counts["automation_unknown"]
        != counts["analyzed"]
    ):
        raise JobContractError("summary_count_mismatch", "automation状態件数がanalyzedと一致しません")
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


def _run_job_impl(
    request: JobRequest,
    *,
    input_root: Path,
    jobs_root: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    run_process: Callable[..., subprocess.CompletedProcess[bytes]] | None,
    trusted_tool_configuration: TrustedToolConfiguration | None = None,
) -> int:
    """productionまたは隔離済みtest seamからジョブ本体を実行する。"""

    if not isinstance(request, JobRequest):
        raise JobContractError("invalid_request_type", "requestはJobRequestで指定してください")
    request = validate_request_object(request.public())
    timeout_seconds = _bounded_integer(
        timeout_seconds,
        name="timeout_seconds",
        maximum=MAX_TIMEOUT_SECONDS,
    )
    input_root, jobs_root = validate_roots(input_root, jobs_root, create_jobs_root=True)
    trusted_tool_policy = (
        load_trusted_tool_policy(
            trusted_tool_configuration,
            forbidden_roots=(input_root, jobs_root),
        )
        if trusted_tool_configuration is not None
        else None
    )
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
    private_temp = prepare_job_private_temp(analysis_output)
    created = utc_now()
    atomic_json(job_dir / "request.json", request.public())
    _write_status(job_dir, state="queued", terminal=False, created_at_utc=created)
    _write_progress(job_dir, phase="queued", percent=0, message="ジョブ要求を受理しました")

    records: list[InputRecord] = []
    started: str | None = None
    trusted_tool_bundle: TrustedToolBundle | None = None
    try:
        _write_status(job_dir, state="validating", terminal=False, created_at_utc=created)
        _write_progress(job_dir, phase="validating_inputs", percent=10, message="入力境界と上限を検証しています")
        if trusted_tool_policy is not None:
            trusted_tool_bundle = stage_trusted_tool_bundle(
                trusted_tool_policy,
                job_dir=job_dir,
            )
            verify_trusted_tool_bundle(trusted_tool_bundle, job_dir=job_dir)
        inputs, records = validate_inputs(request, input_root)
        family_hint_manifest, family_hint_manifest_sha256 = stage_family_hint_manifest(
            request,
            input_root,
            inputs,
            job_dir,
        )
        total_files = sum(item.analyzer_file_count for item in records)
        total_bytes = sum(item.total_bytes for item in records)
        analyzer_inputs = inputs
        input_snapshot_bundle: InputSnapshotBundle | None = None
        input_snapshot_manifest: str | None = None
        input_snapshot_manifest_sha256: str | None = None
        expected_analysis_contract: dict[str, Any] | None = None
        expected_follow_on_contract: dict[str, Any] | None = None
        expected_input_manifest: list[ExpectedInputUnit] | None = None
        analysis_contract_bundle: str | None = None
        analysis_contract_bundle_sha256: str | None = None
        if run_process is None:
            validate_analyzer_runtime()
            input_snapshot_bundle = stage_input_snapshots(
                request,
                records,
                input_root=input_root,
                job_dir=job_dir,
            )
            analyzer_inputs = [item.path for item in input_snapshot_bundle.inputs]
            input_snapshot_manifest = input_snapshot_bundle.manifest_relative_path
            input_snapshot_manifest_sha256 = input_snapshot_bundle.manifest_sha256
            if len(analyzer_inputs) != total_files:
                raise JobContractError(
                    "input_snapshot_failed",
                    "入力snapshot件数が検証済みanalyzer対象件数と一致しません",
                )
            verify_input_snapshot_bundle(input_snapshot_bundle, job_dir=job_dir)
            if trusted_tool_bundle is not None:
                verify_trusted_tool_bundle(trusted_tool_bundle, job_dir=job_dir)
            (
                expected_analysis_contract,
                expected_follow_on_contract,
                expected_input_manifest,
            ) = build_expected_analysis_bundle(
                request,
                analyzer_inputs,
                analysis_output,
                family_hint_manifest=family_hint_manifest,
                temporary_root=private_temp.path,
                trusted_tools=trusted_tool_bundle,
            )
            verify_analysis_contract_trusted_tools(
                expected_analysis_contract,
                expected_follow_on_contract,
                trusted_tools=trusted_tool_bundle,
            )
            verify_input_snapshot_bundle(input_snapshot_bundle, job_dir=job_dir)
            if trusted_tool_bundle is not None:
                verify_trusted_tool_bundle(trusted_tool_bundle, job_dir=job_dir)
            (
                analysis_contract_bundle,
                analysis_contract_bundle_sha256,
            ) = persist_analysis_contract_bundle(
                job_dir,
                root_contract=expected_analysis_contract,
                follow_on_contract=expected_follow_on_contract,
                input_manifest=expected_input_manifest,
            )
            verify_input_snapshot_bundle(input_snapshot_bundle, job_dir=job_dir)
            if trusted_tool_bundle is not None:
                verify_trusted_tool_bundle(trusted_tool_bundle, job_dir=job_dir)
        argv = build_analyzer_argv(
            request,
            analyzer_inputs,
            analysis_output,
            family_hint_manifest=family_hint_manifest,
            trusted_tools=trusted_tool_bundle,
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
            "env": build_sanitized_environment(temporary_root=private_temp.path),
            "shell": False,
            "check": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "timeout": timeout_seconds,
        }
        if run_process is None:
            if input_snapshot_bundle is None:
                raise JobContractError(
                    "input_snapshot_failed",
                    "production入力snapshotが作成されていません",
                )
            verify_input_snapshot_bundle(input_snapshot_bundle, job_dir=job_dir)
            if trusted_tool_bundle is not None:
                verify_trusted_tool_bundle(trusted_tool_bundle, job_dir=job_dir)
            completed = _run_process_with_bounded_output(
                argv,
                monitored_output=analysis_output,
                maximum_active_processes=MAX_ANALYZER_ACTIVE_PROCESSES,
                maximum_memory_bytes=MAX_ANALYZER_MEMORY_BYTES,
                **process_kwargs,
            )
            verify_input_snapshot_bundle(input_snapshot_bundle, job_dir=job_dir)
            if trusted_tool_bundle is not None:
                verify_trusted_tool_bundle(trusted_tool_bundle, job_dir=job_dir)
        else:
            completed = run_process(argv, **process_kwargs)
        if trusted_tool_bundle is not None:
            verify_trusted_tool_bundle(trusted_tool_bundle, job_dir=job_dir)
        finalize_job_private_temp(private_temp, analysis_output=analysis_output)
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
        validated_summary, counts = _validated_summary(
            analysis_output / "summary.json",
            expected_input_files=total_files,
            expected_analysis_contract=expected_analysis_contract,
            expected_follow_on_contract=expected_follow_on_contract,
            expected_options=request.options if run_process is None else None,
            expected_input_manifest=expected_input_manifest,
            verify_root_cases=run_process is None,
        )
        follow_on_status = validated_summary["follow_on_analysis"]["status"]
        summary_partial = counts["errors"] + counts["triaged_unknown"] + counts["partial"] + counts[
            "failed"
        ] + validated_summary["derived_counts"]["triaged_unknown"] > 0 or follow_on_status not in {
            "complete",
            "no_retained_payloads",
            "disabled_assessment_only",
        }
        expected_exit_code = 20 if summary_partial else 0
        if completed.returncode != expected_exit_code:
            raise JobContractError(
                "analyzer_exit_summary_mismatch",
                "analyzer終了codeと検証済みsummary状態が一致しません",
            )
        partial = summary_partial
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
                "trusted_static_tools": (trusted_tool_bundle.provenance() if trusted_tool_bundle is not None else None),
                "counts": counts,
                "derived_counts": validated_summary["derived_counts"],
                "follow_on_analysis": validated_summary["follow_on_analysis"],
                "artifacts": {
                    "analysis_summary": "analysis/summary.json",
                    "follow_on_analysis": "analysis/follow-on-analysis.json",
                    "family_hint_manifest": (
                        "contract-inputs/family-hint-manifest.json" if family_hint_manifest is not None else None
                    ),
                    "family_hint_manifest_sha256": family_hint_manifest_sha256,
                    "analysis_contract_bundle": analysis_contract_bundle,
                    "analysis_contract_bundle_sha256": analysis_contract_bundle_sha256,
                    "input_snapshot_manifest": input_snapshot_manifest,
                    "input_snapshot_manifest_sha256": input_snapshot_manifest_sha256,
                    "trusted_static_tools_manifest": (
                        trusted_tool_bundle.manifest_relative_path if trusted_tool_bundle is not None else None
                    ),
                    "trusted_static_tools_manifest_sha256": (
                        trusted_tool_bundle.manifest_sha256 if trusted_tool_bundle is not None else None
                    ),
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
            derived_files=validated_summary["derived_counts"]["analyzed"],
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
    finally:
        # timeoutやworker起動失敗でも、空のjob-private一時directoryだけは
        # 非再帰で片付ける。残存物、差替え、link、quota違反は削除せず、
        # 元の失敗理由を隠さないためここではcleanup失敗を伝播させない。
        try:
            if private_temp.path.exists():
                finalize_job_private_temp(
                    private_temp,
                    analysis_output=analysis_output,
                )
        except (JobContractError, OSError):
            pass


def run_job(
    request: JobRequest,
    *,
    input_root: Path,
    jobs_root: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    trusted_tool_configuration: TrustedToolConfiguration | None = None,
) -> int:
    """検証を省略できないproductionジョブ入口。"""

    return _run_job_impl(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=timeout_seconds,
        run_process=None,
        trusted_tool_configuration=trusted_tool_configuration,
    )


def _run_job_for_test(
    request: JobRequest,
    *,
    input_root: Path,
    jobs_root: Path,
    timeout_seconds: int,
    run_process: Callable[..., subprocess.CompletedProcess[bytes]],
    trusted_tool_configuration: TrustedToolConfiguration | None = None,
) -> int:
    """外部公開契約に含めない、unit test専用process injection入口。"""

    return _run_job_impl(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=timeout_seconds,
        run_process=run_process,
        trusted_tool_configuration=trusted_tool_configuration,
    )


def validate_job(
    request: JobRequest,
    *,
    input_root: Path,
    jobs_root: Path,
    trusted_tool_configuration: TrustedToolConfiguration | None = None,
) -> dict[str, Any]:
    """成果物を書かず、入力境界と安全なruntime importだけを検証する。"""

    if not isinstance(request, JobRequest):
        raise JobContractError("invalid_request_type", "requestはJobRequestで指定してください")
    request = validate_request_object(request.public())
    input_root, jobs_root = validate_roots(input_root, jobs_root, create_jobs_root=False)
    trusted_tool_policy = (
        load_trusted_tool_policy(
            trusted_tool_configuration,
            forbidden_roots=(input_root, jobs_root),
        )
        if trusted_tool_configuration is not None
        else None
    )
    inputs, records = validate_inputs(request, input_root)
    family_hint_manifest = validate_family_hint_manifest(request, input_root, inputs)
    runtime = validate_analyzer_runtime()
    return {
        "schema_version": SCHEMA_VERSION,
        "job_id": request.job_id,
        "valid": True,
        "request_sha256": _request_digest(request),
        "inputs": [item.public() for item in records],
        "family_hint_manifest": request.family_hint_manifest,
        "family_hint_manifest_validated": family_hint_manifest is not None,
        "trusted_static_tools": (
            {
                "profile_id": trusted_tool_policy.profile_id,
                "operator_manifest_sha256": (trusted_tool_policy.operator_manifest_sha256),
                "tools": trusted_tool_policy.identities(),
            }
            if trusted_tool_policy is not None
            else None
        ),
        "resolved_input_count": len(inputs),
        "jobs_root_exists": jobs_root.exists(),
        "network_or_live_options_allowed": False,
        "sample_execution_allowed": False,
        "ai_used": False,
        "runtime": runtime,
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
            try:
                snapshot[name.removesuffix(".json")] = load_json_object_strict(path, max_bytes=limit)
            except JobContractError as exc:
                raise JobContractError(
                    "job_state_invalid",
                    "job状態JSONの安全な読取またはstrict JSON検証に失敗しました",
                ) from exc
    if "status" not in snapshot or "progress" not in snapshot:
        raise JobContractError("job_state_incomplete", "status.jsonまたはprogress.jsonがありません")
    try:
        job_artifact_schemas.validate_job_artifact_document(
            "snapshot",
            snapshot,
            expected_job_id=job_id,
        )
    except job_artifact_schemas.JobArtifactValidationError as exc:
        raise JobContractError(
            "job_state_invalid",
            "job状態JSONのschemaまたは相互整合性が不正です",
        ) from exc
    return snapshot


def _timeout_type(value: str) -> int:
    try:
        parsed = int(value)
        return _bounded_integer(parsed, name="timeout_seconds", maximum=MAX_TIMEOUT_SECONDS)
    except JobContractError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout-secondsは整数で指定してください") from exc


def _add_trusted_tool_arguments(parser: argparse.ArgumentParser) -> None:
    """Web request外のoperator専用tool契約引数を追加する。"""

    parser.add_argument(
        "--trusted-tools-manifest",
        type=Path,
        help="operatorが管理する信頼済みUPX／7zz manifestのpath。request JSONからは指定できません。",
    )
    parser.add_argument(
        "--trusted-tools-manifest-sha256",
        help="manifest raw bytesの小文字SHA-256 pin。manifest指定時は必須です。",
    )


def _trusted_tool_configuration_from_args(
    args: argparse.Namespace,
) -> TrustedToolConfiguration | None:
    """CLIのmanifest pathとraw SHA-256 pinをpairとしてfail-closedに読む。"""

    manifest = getattr(args, "trusted_tools_manifest", None)
    digest = getattr(args, "trusted_tools_manifest_sha256", None)
    if manifest is None and digest is None:
        return None
    if manifest is None or digest is None:
        raise JobContractError(
            "trusted_tool_configuration_incomplete",
            "trusted tool manifestとSHA-256 pinは同時に指定してください",
        )
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise JobContractError(
            "trusted_tool_manifest_pin_invalid",
            "trusted tool manifest SHA-256 pinは小文字64桁で指定してください",
        )
    return TrustedToolConfiguration(
        manifest_path=manifest,
        manifest_sha256=digest,
    )


def build_parser() -> argparse.ArgumentParser:
    """ローカルjob runnerのCLI parserを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    schema_parser = commands.add_parser(
        "schema",
        help="WebUI／API向けrequest JSON Schemaを出力します",
    )
    schema_parser.add_argument(
        "--artifact",
        choices=("request", *job_artifact_schemas.ARTIFACT_KINDS),
        default="request",
        help="出力する契約。省略時は後方互換のrequest schemaです。",
    )
    validate = commands.add_parser("validate", help="要求、入力、出力境界、解析runtimeを検証します")
    validate.add_argument(
        "--request",
        required=True,
        type=Path,
        help="UTF-8 JSON job request。'-'は有界stdinから読みます。",
    )
    validate.add_argument("--input-root", required=True, type=Path, help="検体を置く専用root。")
    validate.add_argument("--jobs-root", required=True, type=Path, help="job成果物を置く専用root。")
    _add_trusted_tool_arguments(validate)

    run = commands.add_parser("run", help="検証済み要求を同期実行します")
    run.add_argument(
        "--request",
        required=True,
        type=Path,
        help="UTF-8 JSON job request。'-'は有界stdinから読みます。",
    )
    run.add_argument("--input-root", required=True, type=Path, help="検体を置く専用root。")
    run.add_argument("--jobs-root", required=True, type=Path, help="job成果物を置く専用root。")
    run.add_argument(
        "--timeout-seconds",
        type=_timeout_type,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"静的解析の時間上限。既定{DEFAULT_TIMEOUT_SECONDS}秒、最大{MAX_TIMEOUT_SECONDS}秒。",
    )
    _add_trusted_tool_arguments(run)

    status_parser = commands.add_parser("status", help="atomic JSONから現在状態を読みます")
    status_parser.add_argument("--jobs-root", required=True, type=Path, help="job成果物を置く専用root。")
    status_parser.add_argument("--job-id", required=True, help="取得するjob ID。")
    return parser


def _print_json(value: Any, *, stream: Any | None = None) -> None:
    destination = sys.stdout if stream is None else stream
    print(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False),
        file=destination,
    )


def main(argv: list[str] | None = None) -> int:
    """CLIを実行し、machine-readableな結果またはerrorを返す。"""

    args = build_parser().parse_args(argv)
    try:
        if args.command == "schema":
            schema = (
                job_request_json_schema()
                if args.artifact == "request"
                else job_artifact_schemas.job_artifact_json_schema(args.artifact)
            )
            _print_json(schema)
            return 0
        if args.command == "status":
            _print_json(read_job_snapshot(args.jobs_root, args.job_id))
            return 0
        request = load_job_request_from_stdin() if args.request == Path("-") else load_job_request(args.request)
        trusted_tool_configuration = _trusted_tool_configuration_from_args(args)
        if args.command == "validate":
            _print_json(
                validate_job(
                    request,
                    input_root=args.input_root,
                    jobs_root=args.jobs_root,
                    trusted_tool_configuration=trusted_tool_configuration,
                )
            )
            return 0
        return run_job(
            request,
            input_root=args.input_root,
            jobs_root=args.jobs_root,
            timeout_seconds=args.timeout_seconds,
            trusted_tool_configuration=trusted_tool_configuration,
        )
    except JobContractError as exc:
        _print_json({"ok": False, "error": {"code": exc.code, "message": str(exc)}}, stream=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
