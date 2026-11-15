"""例外本文・locals・絶対pathを含まない有界のprivate失敗位置を生成する。"""

from __future__ import annotations

import os
import re
import stat
from collections import deque
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import Any

MAXIMUM_FRAMES = 16
MAXIMUM_SCANNED_FRAMES = 128
MAXIMUM_LINE = 1_000_000
MAXIMUM_DIAGNOSTIC_BYTES = 16 * 1024
ARTIFACT_NAME = "analysis-failure-diagnostic.private.json"
WORKER_ARTIFACT_NAME = "failure-diagnostic.private.json"
_COMPONENT_RE = re.compile(
    r"^(?:analysis-framework/(?:common|classifiers|registry|malware)|extractors|unpackers)/"
    r"[A-Za-z0-9_./-]+\.py$"
)
FUNCTION_NAMES = frozenset(
    {
        "unknown", "main", "run_batch", "analyze_unit", "verify", "capture",
        "_execute_cli", "_direct_cli_worker_main", "_run_isolated_cli",
        "_run_follow_on_fixed_point", "_case_result_from_disk", "_case_retained_payloads",
        "_atomic_replace_json", "_encoded_json_document", "_verify_external_analysis_component",
        "verify_implementation_snapshot", "read_implementation_source",
        "discover_implementation_sources", "build_implementation_commitment",
        "build_terminal_payload_acquisition", "_validate_root_case_states", "_validate_nodes",
        "_validate_edges", "_validate_omissions", "_validate_commitments", "_validate_errors",
        "_array", "_sha256", "_bounded_integer", "_safe_public_text", "_relative_path",
        "_snapshot_sevenzip_for_direct_cli", "verify_snapshot_tree",
    }
)
_EXCEPTION_TYPES = {
    ValueError: "ValueError", TypeError: "TypeError", RuntimeError: "RuntimeError",
    OSError: "OSError", MemoryError: "MemoryError", TimeoutError: "TimeoutError",
    AttributeError: "AttributeError", KeyError: "KeyError", IndexError: "IndexError",
    ImportError: "ImportError", AssertionError: "AssertionError",
    KeyboardInterrupt: "KeyboardInterrupt", SystemExit: "SystemExit",
}
EXCEPTION_NAMES = frozenset(_EXCEPTION_TYPES.values()) | {"OtherException"}


def _valid_component(component: object) -> bool:
    return (
        isinstance(component, str)
        and 0 < len(component) <= 256
        and _COMPONENT_RE.fullmatch(component) is not None
        and all(part not in {"", ".", ".."} for part in component.split("/"))
    )


def _component(filename: object, repository_root: Path) -> str:
    if not isinstance(filename, str) or not filename or len(filename) > 4096:
        return "unknown"
    try:
        supplied = Path(filename)
        if not supplied.is_absolute():
            return "unknown"
        absolute = Path(os.path.abspath(supplied))
        root = Path(os.path.abspath(repository_root)).resolve(strict=True)
        resolved = absolute.resolve(strict=True)
        if absolute != resolved:
            return "unknown"
        information = absolute.lstat()
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or getattr(information, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            return "unknown"
        relative = absolute.relative_to(root).as_posix()
    except (OSError, TypeError, ValueError):
        return "unknown"
    return relative if _valid_component(relative) else "unknown"


def build_diagnostic(error: BaseException, *, repository_root: Path) -> dict[str, Any]:
    """exception message、args、locals、source本文を参照せず位置だけを生成する。"""

    frames: deque[dict[str, Any]] = deque(maxlen=MAXIMUM_FRAMES)
    traceback = error.__traceback__
    scanned = 0
    visited: set[int] = set()
    while isinstance(traceback, TracebackType) and scanned < MAXIMUM_SCANNED_FRAMES:
        identity = id(traceback)
        if identity in visited:
            break
        visited.add(identity)
        component = _component(traceback.tb_frame.f_code.co_filename, repository_root)
        function = traceback.tb_frame.f_code.co_name
        line = traceback.tb_lineno
        trusted = component != "unknown"
        frames.append(
            {
                "component": component,
                "function": function if trusted and function in FUNCTION_NAMES else "unknown",
                "line": line if trusted and type(line) is int and 1 <= line <= MAXIMUM_LINE else None,
            }
        )
        scanned += 1
        traceback = traceback.tb_next
    return {
        "schema_version": 1,
        "kind": "sanitized_private_exception_location",
        "exception_type": _EXCEPTION_TYPES.get(type(error), "OtherException"),
        "frames": list(frames),
        "frames_truncated": scanned > MAXIMUM_FRAMES or traceback is not None,
        "exception_message_included": False,
        "locals_or_arguments_included": False,
        "absolute_path_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def validate_diagnostic(value: object) -> dict[str, Any]:
    """workerから受け取る診断を固定schema・有界位置情報だけへ限定する。"""

    expected = {
        "schema_version", "kind", "exception_type", "frames", "frames_truncated",
        "exception_message_included", "locals_or_arguments_included", "absolute_path_included",
        "sample_executed", "network_contacted",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("kind") != "sanitized_private_exception_location"
        or not isinstance(value.get("exception_type"), str)
        or value["exception_type"] not in EXCEPTION_NAMES
        or type(value.get("frames_truncated")) is not bool
        or not isinstance(value.get("frames"), list)
        or len(value["frames"]) > MAXIMUM_FRAMES
        or any(value.get(key) is not False for key in (
            "exception_message_included", "locals_or_arguments_included", "absolute_path_included",
            "sample_executed", "network_contacted",
        ))
    ):
        raise ValueError("private失敗診断のschemaが不正です")
    for frame in value["frames"]:
        if not isinstance(frame, dict) or set(frame) != {"component", "function", "line"}:
            raise ValueError("private失敗診断のframe schemaが不正です")
        component, function, line = frame["component"], frame["function"], frame["line"]
        if (
            (component != "unknown" and not _valid_component(component))
            or not isinstance(function, str)
            or function not in FUNCTION_NAMES
            or (component == "unknown" and (function != "unknown" or line is not None))
            or (line is not None and (type(line) is not int or not 1 <= line <= MAXIMUM_LINE))
        ):
            raise ValueError("private失敗診断の位置が許可domain外です")
    return dict(value)
