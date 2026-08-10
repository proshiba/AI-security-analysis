#!/usr/bin/env python3
"""WebUI／ローカルAPI向け解析ジョブ成果物のJSON Schemaを提供する。"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ID_ROOT = "https://schemas.ai-security-analysis.local/analysis-job/v1"

MAX_REQUEST_INPUTS = 64
MAX_DISCOVERED_FILES = 1_000
MAX_TOTAL_INPUT_BYTES = 2 * 1024 * 1024 * 1024
MAX_FOLLOW_ON_ARTIFACTS = 64
MAX_FOLLOW_ON_NODES = MAX_DISCOVERED_FILES + MAX_FOLLOW_ON_ARTIFACTS
MAX_FOLLOW_ON_EDGES = 128
MAX_ANALYSIS_OUTPUT_ENTRIES = 100_000
MAX_ANALYSIS_OUTPUT_BYTES = 1024 * 1024 * 1024
MAX_TRUSTED_TOOL_BINARY_BYTES = 128 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 24 * 60 * 60
MAX_HANDLER_EVENTS = MAX_DISCOVERED_FILES * 64

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
FOLLOW_ON_STATUSES = (
    "complete",
    "partial",
    "failed",
    "no_retained_payloads",
    "disabled_assessment_only",
    "disabled_repository_output",
)
ARTIFACT_KINDS = ("status", "progress", "result", "snapshot")


def _strict_object(
    properties: Mapping[str, Any],
    *,
    required: Sequence[str] | None = None,
) -> dict[str, Any]:
    """未定義fieldを拒否するobject schemaを返す。"""

    return {
        "type": "object",
        "properties": dict(properties),
        "required": list(properties) if required is None else list(required),
        "additionalProperties": False,
    }


def _common_definitions() -> dict[str, Any]:
    """全成果物で共有するprimitive／小object定義を生成する。"""

    return {
        "utc_timestamp": {
            "type": "string",
            "format": "date-time",
            "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
        },
        "job_id": {
            "type": "string",
            "pattern": r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$",
            "minLength": 1,
            "maxLength": 64,
        },
        "sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
        "relative_path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 512,
            "pattern": r"^(?!/)(?![A-Za-z]:)(?!.*\\)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))[^\u0000-\u001f]+$",
        },
        "error": _strict_object(
            {
                "code": {
                    "type": "string",
                    "pattern": r"^[a-z][a-z0-9_]{0,127}$",
                },
                "message": {"type": "string", "minLength": 1, "maxLength": 4096},
            }
        ),
        "input_record": _strict_object(
            {
                "relative_path": {"$ref": "#/$defs/relative_path"},
                "kind": {"enum": ["file", "directory"]},
                "file_count": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_DISCOVERED_FILES,
                },
                "analyzer_file_count": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_DISCOVERED_FILES,
                },
                "total_bytes": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_TOTAL_INPUT_BYTES,
                },
            }
        ),
        "input_records": {
            "type": "array",
            "items": {"$ref": "#/$defs/input_record"},
            "maxItems": MAX_REQUEST_INPUTS,
        },
        "nullable_relative_path": {"oneOf": [{"type": "null"}, {"$ref": "#/$defs/relative_path"}]},
    }


def _schema_document(identifier: str, title: str, body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": f"{SCHEMA_ID_ROOT}/{identifier}.schema.json",
        "title": title,
        "$defs": _common_definitions(),
        **dict(body),
    }


def _status_branch(
    state: str,
    *,
    terminal: bool,
    started: str,
    finished: str,
    result: str,
    error: str,
) -> dict[str, Any]:
    timestamp = {"$ref": "#/$defs/utc_timestamp"}
    nullable_timestamp = {"oneOf": [{"type": "null"}, timestamp]}
    started_schema = {
        "null": {"type": "null"},
        "timestamp": timestamp,
        "nullable": nullable_timestamp,
    }[started]
    finished_schema = {
        "null": {"type": "null"},
        "timestamp": timestamp,
    }[finished]
    result_schema = {
        "null": {"type": "null"},
        "result": {"const": "result.json"},
    }[result]
    error_schema = {
        "null": {"type": "null"},
        "error": {"$ref": "#/$defs/error"},
    }[error]
    return _strict_object(
        {
            "schema_version": {"const": SCHEMA_VERSION},
            "job_id": {"$ref": "#/$defs/job_id"},
            "state": {"const": state},
            "terminal": {"const": terminal},
            "created_at_utc": timestamp,
            "started_at_utc": started_schema,
            "finished_at_utc": finished_schema,
            "progress_path": {"const": "progress.json"},
            "result_path": result_schema,
            "error": error_schema,
        }
    )


def _status_body() -> dict[str, Any]:
    return {
        "oneOf": [
            _status_branch(
                state,
                terminal=False,
                started="null",
                finished="null",
                result="null",
                error="null",
            )
            for state in ("queued", "validating")
        ]
        + [
            _status_branch(
                "running",
                terminal=False,
                started="timestamp",
                finished="null",
                result="null",
                error="null",
            )
        ]
        + [
            _status_branch(
                state,
                terminal=True,
                started="timestamp",
                finished="timestamp",
                result="result",
                error="null",
            )
            for state in ("completed", "completed_partial")
        ]
        + [
            _status_branch(
                "failed",
                terminal=True,
                started="nullable",
                finished="timestamp",
                result="result",
                error="error",
            ),
            _status_branch(
                "timed_out",
                terminal=True,
                started="nullable",
                finished="timestamp",
                result="result",
                error="error",
            ),
        ]
    }


def status_json_schema() -> dict[str, Any]:
    """status.json用Draft 2020-12 Schemaを返す。"""

    return _schema_document("status", "静的解析ジョブ状態", _status_body())


def _progress_branch(
    phase: str,
    percent: int,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "schema_version": {"const": SCHEMA_VERSION},
        "job_id": {"$ref": "#/$defs/job_id"},
        "phase": {"const": phase},
        "percent": {"const": percent},
        "message": {"type": "string", "minLength": 1, "maxLength": 4096},
        "updated_at_utc": {"$ref": "#/$defs/utc_timestamp"},
    }
    properties.update(extra or {})
    return _strict_object(properties)


def _progress_body() -> dict[str, Any]:
    file_count = {
        "type": "integer",
        "minimum": 0,
        "maximum": MAX_DISCOVERED_FILES,
    }
    return {
        "oneOf": [
            _progress_branch("queued", 0),
            _progress_branch("validating_inputs", 10),
            _progress_branch(
                "static_analysis",
                30,
                {
                    "total_files": file_count,
                    "total_bytes": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAX_TOTAL_INPUT_BYTES,
                    },
                },
            ),
            _progress_branch("validating_results", 90),
            *(
                _progress_branch(
                    phase,
                    100,
                    {
                        "completed_files": file_count,
                        "derived_files": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": MAX_FOLLOW_ON_ARTIFACTS,
                        },
                        "total_files": file_count,
                    },
                )
                for phase in ("completed", "completed_partial")
            ),
            _progress_branch("failed", 100),
            _progress_branch("timed_out", 100),
        ]
    }


def progress_json_schema() -> dict[str, Any]:
    """progress.json用Draft 2020-12 Schemaを返す。"""

    return _schema_document("progress", "静的解析ジョブ進捗", _progress_body())


def _counts_schema(keys: Sequence[str], *, derived: bool = False) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for key in keys:
        maximum = MAX_FOLLOW_ON_ARTIFACTS if derived else MAX_DISCOVERED_FILES
        if not derived and key in {
            "candidate_handler_attempts",
            "handler_successes",
            "handler_failures",
            "handler_no_evidence",
            "handler_ambiguous",
            "handler_incompatible",
        }:
            maximum = MAX_HANDLER_EVENTS
        properties[key] = {"type": "integer", "minimum": 0, "maximum": maximum}
    return _strict_object(properties)


def _follow_on_reference_schema() -> dict[str, Any]:
    return _strict_object(
        {
            "artifact": {"const": "follow-on-analysis.json"},
            "sha256": {"$ref": "#/$defs/sha256"},
            "status": {"enum": list(FOLLOW_ON_STATUSES)},
            "node_count": {"type": "integer", "minimum": 0, "maximum": MAX_FOLLOW_ON_NODES},
            "edge_count": {"type": "integer", "minimum": 0, "maximum": MAX_FOLLOW_ON_EDGES},
            "error_count": {"type": "integer", "minimum": 0, "maximum": MAX_ANALYSIS_OUTPUT_ENTRIES},
        }
    )


def _analysis_output_schema() -> dict[str, Any]:
    entry_count = {"type": "integer", "minimum": 0, "maximum": MAX_ANALYSIS_OUTPUT_ENTRIES}
    return _strict_object(
        {
            "entries": entry_count,
            "files": entry_count,
            "directories": entry_count,
            "total_bytes": {"type": "integer", "minimum": 0, "maximum": MAX_ANALYSIS_OUTPUT_BYTES},
        }
    )


def _trusted_tool_identity_schema() -> dict[str, Any]:
    """公開成果物へ絶対pathを出さないstatic tool identity schemaを返す。"""

    return _strict_object(
        {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 255,
                "pattern": r"^[^/\\\u0000-\u001f]+$",
            },
            "size": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_TRUSTED_TOOL_BINARY_BYTES,
            },
            "sha256": {"$ref": "#/$defs/sha256"},
        }
    )


def _trusted_tool_provenance_schema() -> dict[str, Any]:
    identity_or_null = {"oneOf": [{"type": "null"}, _trusted_tool_identity_schema()]}
    return _strict_object(
        {
            "profile_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": r"^[a-z0-9][a-z0-9._-]{0,63}$",
            },
            "operator_manifest_sha256": {"$ref": "#/$defs/sha256"},
            "snapshot_manifest_sha256": {"$ref": "#/$defs/sha256"},
            "tools": _strict_object(
                {
                    "upx": identity_or_null,
                    "sevenzip": identity_or_null,
                    "diec": {"type": "null"},
                }
            ),
        }
    )


def _artifact_branch(
    *,
    family_manifest: bool,
    contract_bundle: bool,
    trusted_tools: bool,
) -> dict[str, Any]:
    nullable = {"type": "null"}
    return _strict_object(
        {
            "analysis_summary": {"const": "analysis/summary.json"},
            "follow_on_analysis": {"const": "analysis/follow-on-analysis.json"},
            "family_hint_manifest": (
                {"const": "contract-inputs/family-hint-manifest.json"} if family_manifest else nullable
            ),
            "family_hint_manifest_sha256": ({"$ref": "#/$defs/sha256"} if family_manifest else nullable),
            "analysis_contract_bundle": (
                {"const": "contract-inputs/analysis-contract-bundle.json"} if contract_bundle else nullable
            ),
            "analysis_contract_bundle_sha256": ({"$ref": "#/$defs/sha256"} if contract_bundle else nullable),
            "input_snapshot_manifest": (
                {"const": "contract-inputs/input-snapshot-manifest.json"} if contract_bundle else nullable
            ),
            "input_snapshot_manifest_sha256": ({"$ref": "#/$defs/sha256"} if contract_bundle else nullable),
            "trusted_static_tools_manifest": (
                {"const": "contract-inputs/trusted-static-tools.json"} if trusted_tools else nullable
            ),
            "trusted_static_tools_manifest_sha256": ({"$ref": "#/$defs/sha256"} if trusted_tools else nullable),
            "stdout": {"const": "stdout.log"},
            "stderr": {"const": "stderr.log"},
            "stdout_truncated": {"type": "boolean"},
            "stderr_truncated": {"type": "boolean"},
            "analysis_output": _analysis_output_schema(),
        }
    )


def _artifacts_schema(*, trusted_tools: bool) -> dict[str, Any]:
    return {
        "oneOf": [
            _artifact_branch(
                family_manifest=family_manifest,
                contract_bundle=contract_bundle,
                trusted_tools=trusted_tools,
            )
            for family_manifest in (False, True)
            for contract_bundle in (False, True)
        ]
    }


def _success_process_schema(exit_code: int) -> dict[str, Any]:
    return _strict_object(
        {
            "exit_code": {"const": exit_code},
            "shell": {"const": False},
            "script": {"const": "analysis-framework/common/analyze_sample.py"},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS},
        }
    )


def _failure_process_schema(*, timeout: bool) -> dict[str, Any]:
    exit_code: dict[str, Any] = {"type": "null"}
    if not timeout:
        exit_code = {
            "oneOf": [
                {"type": "null"},
                {"type": "integer", "minimum": -(2**31), "maximum": 2**32 - 1},
            ]
        }
    return _strict_object({"exit_code": exit_code, "shell": {"const": False}})


def _success_safety_schema() -> dict[str, Any]:
    return _strict_object(
        {
            "network_or_live_options_allowed": {"const": False},
            "sample_execution_allowed": {"const": False},
            "summary_safety_contract_verified": {"const": True},
            "executed_sample": {"const": False},
            "network_contacted": {"const": False},
            "ai_used": {"const": False},
        }
    )


def _failure_safety_schema() -> dict[str, Any]:
    return _strict_object(
        {
            "network_or_live_options_allowed": {"const": False},
            "sample_execution_allowed": {"const": False},
            "ai_used": {"const": False},
            "summary_safety_contract_verified": {"const": False},
        }
    )


def _successful_result_branch(
    analysis_state: str,
    exit_code: int,
    *,
    trusted_tools: bool,
) -> dict[str, Any]:
    return _strict_object(
        {
            "schema_version": {"const": SCHEMA_VERSION},
            "job_id": {"$ref": "#/$defs/job_id"},
            "request_sha256": {"$ref": "#/$defs/sha256"},
            "accepted": {"const": True},
            "analysis_state": {"const": analysis_state},
            "inputs": {
                "type": "array",
                "items": {"$ref": "#/$defs/input_record"},
                "minItems": 1,
                "maxItems": MAX_REQUEST_INPUTS,
            },
            "family_hint_manifest": {"$ref": "#/$defs/nullable_relative_path"},
            "trusted_static_tools": (_trusted_tool_provenance_schema() if trusted_tools else {"type": "null"}),
            "counts": _counts_schema(SUMMARY_COUNT_KEYS),
            "derived_counts": _counts_schema(DERIVED_COUNT_KEYS, derived=True),
            "follow_on_analysis": _follow_on_reference_schema(),
            "artifacts": _artifacts_schema(trusted_tools=trusted_tools),
            "process": _success_process_schema(exit_code),
            "safety": _success_safety_schema(),
            "finished_at_utc": {"$ref": "#/$defs/utc_timestamp"},
        }
    )


def _failed_result_branch(analysis_state: str) -> dict[str, Any]:
    return _strict_object(
        {
            "schema_version": {"const": SCHEMA_VERSION},
            "job_id": {"$ref": "#/$defs/job_id"},
            "request_sha256": {"$ref": "#/$defs/sha256"},
            "accepted": {"const": False},
            "analysis_state": {"const": analysis_state},
            "inputs": {
                "type": "array",
                "items": {"$ref": "#/$defs/input_record"},
                "minItems": 1 if analysis_state == "timed_out" else 0,
                "maxItems": MAX_REQUEST_INPUTS,
            },
            "family_hint_manifest": {"$ref": "#/$defs/nullable_relative_path"},
            "process": _failure_process_schema(timeout=analysis_state == "timed_out"),
            "safety": _failure_safety_schema(),
            "error": {"$ref": "#/$defs/error"},
            "finished_at_utc": {"$ref": "#/$defs/utc_timestamp"},
        }
    )


def _result_body() -> dict[str, Any]:
    return {
        "oneOf": [
            *(
                _successful_result_branch(
                    "complete",
                    0,
                    trusted_tools=trusted_tools,
                )
                for trusted_tools in (False, True)
            ),
            *(
                _successful_result_branch(
                    "partial",
                    20,
                    trusted_tools=trusted_tools,
                )
                for trusted_tools in (False, True)
            ),
            _failed_result_branch("failed"),
            _failed_result_branch("timed_out"),
        ]
    }


def result_json_schema() -> dict[str, Any]:
    """result.json用Draft 2020-12 Schemaを返す。"""

    return _schema_document("result", "静的解析ジョブ結果", _result_body())


def read_job_snapshot_json_schema() -> dict[str, Any]:
    """read_job_snapshot返却値用Draft 2020-12 Schemaを返す。

    result.jsonはstatus.jsonより先にatomic置換されるため、非終端statusと
    resultが同居する短い遷移状態も正規のsnapshotとして許可する。
    """

    definitions = _common_definitions()
    definitions.update(
        {
            "status_document": _status_body(),
            "progress_document": _progress_body(),
            "result_document": _result_body(),
        }
    )
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": f"{SCHEMA_ID_ROOT}/snapshot.schema.json",
        "title": "静的解析ジョブのatomic snapshot",
        "$defs": definitions,
        **_strict_object(
            {
                "schema_version": {"const": SCHEMA_VERSION},
                "job_id": {"$ref": "#/$defs/job_id"},
                "status": {"$ref": "#/$defs/status_document"},
                "progress": {"$ref": "#/$defs/progress_document"},
                "result": {"$ref": "#/$defs/result_document"},
            },
            required=("schema_version", "job_id", "status", "progress"),
        ),
    }


def job_artifact_json_schema(kind: str) -> dict[str, Any]:
    """成果物名から対応するSchemaを返す。"""

    builders = {
        "status": status_json_schema,
        "progress": progress_json_schema,
        "result": result_json_schema,
        "snapshot": read_job_snapshot_json_schema,
    }
    try:
        return builders[kind]()
    except KeyError as exc:
        raise ValueError(f"未対応の成果物種別です: {kind}") from exc


class JobArtifactValidationError(ValueError):
    """成果物が公開Schemaまたはsnapshot整合性に違反したことを表す。"""

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")


def _validation_error(path: str, reason: str) -> JobArtifactValidationError:
    return JobArtifactValidationError(path, reason)


def _json_scalar_equal(value: Any, expected: Any) -> bool:
    """JSONのbooleanとintegerを混同せずconst／enumを比較する。"""

    if expected is None or isinstance(expected, (bool, int, float, str)):
        return type(value) is type(expected) and value == expected
    return value == expected


def _resolve_local_reference(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    prefix = "#/$defs/"
    if not reference.startswith(prefix) or "/" in reference[len(prefix) :]:
        raise RuntimeError(f"未対応のSchema参照です: {reference}")
    definition = root.get("$defs", {}).get(reference[len(prefix) :])
    if not isinstance(definition, Mapping):
        raise RuntimeError(f"Schema参照先がありません: {reference}")
    return definition


def _validate_schema_instance(
    schema: Mapping[str, Any],
    value: Any,
    *,
    root: Mapping[str, Any],
    path: str,
    depth: int = 0,
) -> None:
    """成果物Schemaで使用するDraft 2020-12 subsetを依存なしで検証する。"""

    if depth > 128:
        raise _validation_error(path, "入れ子が深すぎます")
    reference = schema.get("$ref")
    if isinstance(reference, str):
        _validate_schema_instance(
            _resolve_local_reference(root, reference),
            value,
            root=root,
            path=path,
            depth=depth + 1,
        )
        return

    branches = schema.get("oneOf")
    if isinstance(branches, list):
        matched = 0
        for branch in branches:
            if not isinstance(branch, Mapping):
                raise RuntimeError("oneOf branchがobjectではありません")
            try:
                _validate_schema_instance(
                    branch,
                    value,
                    root=root,
                    path=path,
                    depth=depth + 1,
                )
            except JobArtifactValidationError:
                continue
            matched += 1
        if matched != 1:
            raise _validation_error(path, "状態別Schemaへ一意に一致しません")
        return

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            raise _validation_error(path, "objectではありません")
    elif expected_type == "array":
        if not isinstance(value, list):
            raise _validation_error(path, "arrayではありません")
    elif expected_type == "string":
        if not isinstance(value, str):
            raise _validation_error(path, "stringではありません")
    elif expected_type == "integer":
        if type(value) is not int:
            raise _validation_error(path, "integerではありません")
    elif expected_type == "boolean":
        if type(value) is not bool:
            raise _validation_error(path, "booleanではありません")
    elif expected_type == "null" and value is not None:
        raise _validation_error(path, "nullではありません")

    if "const" in schema and not _json_scalar_equal(value, schema["const"]):
        raise _validation_error(path, "固定値と一致しません")
    enum = schema.get("enum")
    if isinstance(enum, list) and not any(_json_scalar_equal(value, item) for item in enum):
        raise _validation_error(path, "許可値ではありません")

    if isinstance(value, str):
        minimum_length = schema.get("minLength")
        maximum_length = schema.get("maxLength")
        if isinstance(minimum_length, int) and len(value) < minimum_length:
            raise _validation_error(path, "文字列が短すぎます")
        if isinstance(maximum_length, int) and len(value) > maximum_length:
            raise _validation_error(path, "文字列が長すぎます")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            raise _validation_error(path, "文字列patternに一致しません")
        if schema.get("format") == "date-time":
            try:
                datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as exc:
                raise _validation_error(path, "UTC日時が不正です") from exc

    if type(value) is int:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int) and value < minimum:
            raise _validation_error(path, "整数が下限未満です")
        if isinstance(maximum, int) and value > maximum:
            raise _validation_error(path, "整数が上限超過です")

    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            raise _validation_error(path, "array要素数が下限未満です")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            raise _validation_error(path, "array要素数が上限超過です")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_schema_instance(
                    item_schema,
                    item,
                    root=root,
                    path=f"{path}[{index}]",
                    depth=depth + 1,
                )

    if isinstance(value, dict):
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            return
        required = schema.get("required", [])
        if not isinstance(required, list):
            raise RuntimeError("requiredがarrayではありません")
        missing = [key for key in required if key not in value]
        if missing:
            raise _validation_error(path, "必須fieldがありません")
        if schema.get("additionalProperties") is False:
            unknown = set(value) - set(properties)
            if unknown:
                raise _validation_error(path, "未知fieldが含まれます")
        for key, property_schema in properties.items():
            if key not in value:
                continue
            if not isinstance(property_schema, Mapping):
                raise RuntimeError("property Schemaがobjectではありません")
            _validate_schema_instance(
                property_schema,
                value[key],
                root=root,
                path=f"{path}.{key}",
                depth=depth + 1,
            )


_TERMINAL_RESULT_STATE = {
    "completed": "complete",
    "completed_partial": "partial",
    "failed": "failed",
    "timed_out": "timed_out",
}
_PROGRESS_PHASES_BY_STATUS = {
    # read_job_snapshotはstatus→progress→resultの順で読むため、先に読んだ
    # statusより後のphase／resultが同じsnapshotへ入ることを許可する。
    "queued": {
        "queued",
        "validating_inputs",
        "static_analysis",
        "validating_results",
        "completed",
        "completed_partial",
        "failed",
        "timed_out",
    },
    "validating": {
        "queued",
        "validating_inputs",
        "static_analysis",
        "validating_results",
        "completed",
        "completed_partial",
        "failed",
        "timed_out",
    },
    "running": {
        "validating_inputs",
        "static_analysis",
        "validating_results",
        "completed",
        "completed_partial",
        "failed",
        "timed_out",
    },
    "completed": {"completed"},
    "completed_partial": {"completed_partial"},
    "failed": {"failed"},
    "timed_out": {"timed_out"},
}


def _validate_result_semantics(value: Mapping[str, Any]) -> None:
    """JSON Schemaで表現しにくいresult内のcross-field整合を検証する。"""

    if value.get("accepted") is not True:
        return
    provenance = value.get("trusted_static_tools")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, Mapping):  # schema検証後の防御的確認
        raise _validation_error("$.artifacts", "artifactsが不正です")
    artifact_digest = artifacts.get("trusted_static_tools_manifest_sha256")
    if provenance is None:
        if artifact_digest is not None:
            raise _validation_error(
                "$.artifacts.trusted_static_tools_manifest_sha256",
                "tool provenanceなしでmanifest hashを指定できません",
            )
        return
    if not isinstance(provenance, Mapping) or provenance.get("snapshot_manifest_sha256") != artifact_digest:
        raise _validation_error(
            "$.trusted_static_tools.snapshot_manifest_sha256",
            "tool provenanceとartifact manifest hashが一致しません",
        )


def _validate_snapshot_semantics(value: Mapping[str, Any]) -> None:
    job_id = value["job_id"]
    status = value["status"]
    progress = value["progress"]
    result = value.get("result")
    for name, document in (("status", status), ("progress", progress)):
        if document["job_id"] != job_id:
            raise _validation_error(f"$.{name}.job_id", "snapshotのjob_idと一致しません")
    if result is not None and result["job_id"] != job_id:
        raise _validation_error("$.result.job_id", "snapshotのjob_idと一致しません")
    if result is not None:
        _validate_result_semantics(result)

    state = status["state"]
    phase = progress["phase"]
    if phase not in _PROGRESS_PHASES_BY_STATUS[state]:
        raise _validation_error("$.progress.phase", "statusから到達できないphaseです")

    expected_from_status = _TERMINAL_RESULT_STATE.get(state)
    expected_from_progress = _TERMINAL_RESULT_STATE.get(phase)
    if expected_from_status is not None:
        if result is None:
            raise _validation_error("$.result", "terminal statusにはresultが必要です")
        if result["analysis_state"] != expected_from_status:
            raise _validation_error("$.result.analysis_state", "terminal statusと一致しません")
    if expected_from_progress is not None:
        if result is None:
            raise _validation_error("$.result", "terminal progressにはresultが必要です")
        if result["analysis_state"] != expected_from_progress:
            raise _validation_error("$.result.analysis_state", "terminal progressと一致しません")


def validate_job_artifact_document(
    kind: str,
    value: Any,
    *,
    expected_job_id: str | None = None,
) -> None:
    """成果物を公開Schemaとsnapshot遷移規則でfail-closedに検証する。

    外部入力の値をerror messageへ含めない。snapshotでは各内包文書のjob ID、
    status／progress／resultを照合する。非終端statusとresultの同居は、
    status→progress→resultという読取順で生じるatomic遷移として許可する。
    """

    schema = job_artifact_json_schema(kind)
    _validate_schema_instance(schema, value, root=schema, path="$")
    if not isinstance(value, Mapping):  # Schema検証後の型絞り込み
        raise _validation_error("$", "objectではありません")
    if expected_job_id is not None and value["job_id"] != expected_job_id:
        raise _validation_error("$.job_id", "要求されたjob_idと一致しません")
    if kind == "result":
        _validate_result_semantics(value)
    if kind == "snapshot":
        _validate_snapshot_semantics(value)


def build_parser() -> argparse.ArgumentParser:
    """解析ジョブ成果物Schemaを選択するCLI parserを構築する。"""

    parser = argparse.ArgumentParser(description="解析ジョブ成果物のJSON Schemaを出力します。")
    parser.add_argument("kind", choices=ARTIFACT_KINDS, help="出力する成果物Schema。")
    return parser


def main(argv: list[str] | None = None) -> int:
    """指定された成果物のJSON Schemaを標準出力へ書き出す。"""

    args = build_parser().parse_args(argv)
    json.dump(
        job_artifact_json_schema(args.kind),
        sys.stdout,
        ensure_ascii=False,
        indent=2,
        allow_nan=False,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI入口
    raise SystemExit(main())
