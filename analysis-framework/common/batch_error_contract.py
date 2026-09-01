"""one-shot解析の検体単位errorを秘密値なしの固定schemaへ正規化する。"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

SHA256_RE = re.compile(r"[0-9a-f]{64}")
EXCEPTION_TYPE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,127}")
PUBLIC_EXCEPTION_TYPES = frozenset(
    {
        "ArithmeticError",
        "EOFError",
        "FileExistsError",
        "FileNotFoundError",
        "IsADirectoryError",
        "MemoryError",
        "NotADirectoryError",
        "OSError",
        "OverflowError",
        "PermissionError",
        "RuntimeError",
        "TimeoutError",
        "TypeError",
        "UnicodeError",
        "ValueError",
    }
)
STAGE_ERROR_CODES = {
    "input_read": "input_read_failed",
    "resume_validation": "resume_validation_failed",
    "root_static_analysis": "root_static_analysis_failed",
}
_MESSAGE_PREFIXES = {
    "input_read": "入力を安全に読み込めませんでした",
    "resume_validation": "既存caseの再開検証を完了できませんでした",
    "root_static_analysis": "root静的解析を完了できませんでした",
}
MAX_INPUT_INDEX = 999_999
RECORD_KEYS = frozenset({"input_index", "sha256", "stage", "error_code", "message"})


class BatchErrorContractError(ValueError):
    """batch error recordが固定契約に違反した場合に送出する。"""


def _valid_input_index(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_INPUT_INDEX


def build_record(
    *,
    input_index: int,
    stage: str,
    error: BaseException,
    sha256: str | None = None,
) -> dict[str, Any]:
    """例外本文を保持せず、安定したstage/error codeへ変換する。"""

    if not _valid_input_index(input_index):
        raise BatchErrorContractError("input_indexが不正です")
    if stage not in STAGE_ERROR_CODES:
        raise BatchErrorContractError("未登録のbatch error stageです")
    if sha256 is not None and (not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None):
        raise BatchErrorContractError("sha256が不正です")
    exception_type = type(error).__name__
    if (
        type(error).__module__ != "builtins"
        or exception_type not in PUBLIC_EXCEPTION_TYPES
        or EXCEPTION_TYPE_RE.fullmatch(exception_type) is None
    ):
        exception_type = "Exception"
    return {
        "input_index": input_index,
        "sha256": sha256,
        "stage": stage,
        "error_code": STAGE_ERROR_CODES[stage],
        "message": f"{_MESSAGE_PREFIXES[stage]} ({exception_type})",
    }


def validate_record(value: object) -> dict[str, Any]:
    """固定key、stage/code対応、message形式、SHA-256をfail-closedで検証する。"""

    if not isinstance(value, Mapping) or set(value) != RECORD_KEYS:
        raise BatchErrorContractError("batch error record schemaが不正です")
    input_index = value.get("input_index")
    sha256 = value.get("sha256")
    stage = value.get("stage")
    error_code = value.get("error_code")
    message = value.get("message")
    if not _valid_input_index(input_index):
        raise BatchErrorContractError("batch error input_indexが不正です")
    if not isinstance(stage, str) or stage not in STAGE_ERROR_CODES:
        raise BatchErrorContractError("batch error stageが不正です")
    if error_code != STAGE_ERROR_CODES[stage]:
        raise BatchErrorContractError("batch error stageとerror_codeが一致しません")
    if sha256 is not None and (not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None):
        raise BatchErrorContractError("batch error sha256が不正です")
    prefix = re.escape(_MESSAGE_PREFIXES[stage])
    if not isinstance(message, str) or re.fullmatch(rf"{prefix} \(([A-Za-z][A-Za-z0-9_]{{0,127}})\)", message) is None:
        raise BatchErrorContractError("batch error messageが不正です")
    return dict(value)
