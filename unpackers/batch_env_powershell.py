"""Batch環境変数からPowerShell stdinへ渡す定数payloadを静的復元する。

shellやPowerShellは起動しない。quoted ``set`` の単一定数値、既知のPowerShell
実行file fallback、``echo %%VAR%% | "%EXE%" ... -`` が一意に結び付く場合だけ
payload文字列を返す。
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass

IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
PROFILE_NAME = "batch-constant-environment-powershell-stdin-v1"
_SET_RE = re.compile(
    rf'^\s*@?set\s+"({IDENTIFIER})=([^\r\n]*)"\s*$',
    re.IGNORECASE,
)
_SINK_RE = re.compile(
    rf'^\s*echo\s+%%({IDENTIFIER})%%\s*\|\s*"%({IDENTIFIER})%"\s+'
    r"-windowstyle\s+hidden\s+-\s*$",
    re.IGNORECASE,
)
_POWERSHELL_PATH_RE = re.compile(
    r"^%systemroot%\\(?:syswow64|system32)\\windowspowershell\\v1\.0\\powershell\.exe$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class BatchEnvPowershellLimits:
    """定数Batch profileのhard limit。"""

    max_input_bytes: int = 2 * 1024 * 1024
    max_lines: int = 50_000
    max_line_characters: int = 2 * 1024 * 1024
    max_payload_bytes: int = 2 * 1024 * 1024
    max_assignments: int = 50_000
    max_work_units: int = 8 * 1024 * 1024


DEFAULT_LIMITS = BatchEnvPowershellLimits()


def _base_report(
    limits: BatchEnvPowershellLimits,
    *,
    status: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "profile": PROFILE_NAME,
        "candidate_set_complete": False,
        "candidate_set_truncated": False,
        "candidate_count": 0,
        "limits": asdict(limits),
        "candidates": [],
        "rejections": {},
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "cmd_started": False,
            "powershell_started": False,
            "environment_modified": False,
            "raw_source_included": False,
            "raw_payload_included": False,
        },
    }


def _decode(data: bytes) -> tuple[str, str] | None:
    encodings = (
        ("utf-16-le", data[2:]) if data.startswith(b"\xff\xfe") else None,
        ("utf-8-sig", data),
        ("cp1252", data),
    )
    for candidate in encodings:
        if candidate is None:
            continue
        encoding, source = candidate
        try:
            text = source.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\x00" not in text:
            return text, encoding
    return None


def _validate_powershell(value: str, *, maximum_bytes: int) -> dict[str, object] | None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if not 256 <= len(encoded) <= maximum_bytes or "\x00" in value:
        return None
    if re.search(r"%[A-Za-z_][A-Za-z0-9_]*%|![A-Za-z_][A-Za-z0-9_]*!", value):
        return None
    if not all(character.isprintable() or character in "\r\n\t" for character in value):
        return None
    lowered = value.casefold()
    anchors = {
        "variable": "$" in value,
        "statement_separator": ";" in value,
        "type_or_attribute": "[" in value and "]" in value,
        "function": "function" in lowered,
        "powershell_member": "::" in value or "get-" in lowered,
    }
    if sum(anchors.values()) < 4:
        return None
    return {
        "format": "bounded_powershell_source",
        "anchor_count": sum(anchors.values()),
        "anchors": sorted(name for name, present in anchors.items() if present),
        "line_count": len(value.splitlines()) or 1,
    }


def recover_batch_env_powershell(
    data: bytes,
    *,
    limits: BatchEnvPowershellLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """定数環境変数をPowerShell stdinへ渡すBatch profileだけを復元する。"""

    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    if len(data) > limits.max_input_bytes:
        return _base_report(limits, status="input_limit_exceeded"), []
    decoded = _decode(data)
    if decoded is None:
        return _base_report(limits, status="text_decode_failed"), []
    text, encoding = decoded
    lines = text.splitlines()
    if len(lines) > limits.max_lines:
        report = _base_report(limits, status="limit_exceeded")
        report.update(
            {
                "encoding": encoding,
                "limit": "max_lines",
                "candidate_set_truncated": True,
            }
        )
        return report, []
    if any(len(line) > limits.max_line_characters for line in lines):
        report = _base_report(limits, status="limit_exceeded")
        report.update(
            {
                "encoding": encoding,
                "limit": "max_line_characters",
                "candidate_set_truncated": True,
            }
        )
        return report, []
    assignments: dict[str, list[tuple[int, str]]] = {}
    assignment_count = 0
    sinks: list[tuple[int, str, str]] = []
    work_units = len(data)
    for line_number, line in enumerate(lines, 1):
        match = _SET_RE.fullmatch(line)
        if match is not None:
            assignment_count += 1
            if assignment_count > limits.max_assignments:
                report = _base_report(limits, status="limit_exceeded")
                report.update(
                    {
                        "encoding": encoding,
                        "limit": "max_assignments",
                        "candidate_set_truncated": True,
                    }
                )
                return report, []
            assignments.setdefault(match.group(1).casefold(), []).append(
                (line_number, match.group(2))
            )
        sink = _SINK_RE.fullmatch(line)
        if sink is not None:
            sinks.append((line_number, sink.group(1), sink.group(2)))

    rejections: Counter[str] = Counter()
    candidates: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for sink_line, payload_name, launcher_name in sinks:
        payload_assignments = assignments.get(payload_name.casefold(), [])
        if len(payload_assignments) != 1:
            rejections["ambiguous_payload_assignment"] += 1
            continue
        launcher_assignments = assignments.get(launcher_name.casefold(), [])
        if not 1 <= len(launcher_assignments) <= 2 or not all(
            _POWERSHELL_PATH_RE.fullmatch(value) is not None
            for _, value in launcher_assignments
        ):
            rejections["unreviewed_launcher_assignment"] += 1
            continue
        payload_line, payload_text = payload_assignments[0]
        validation = _validate_powershell(
            payload_text,
            maximum_bytes=limits.max_payload_bytes,
        )
        if validation is None:
            rejections["payload_validation_failed"] += 1
            continue
        payload = payload_text.encode("utf-8")
        work_units += len(payload)
        if work_units > limits.max_work_units:
            report = _base_report(limits, status="limit_exceeded")
            report.update(
                {
                    "encoding": encoding,
                    "limit": "max_work_units",
                    "candidate_set_truncated": True,
                    "rejections": dict(sorted(rejections.items())),
                }
            )
            return report, []
        digest = hashlib.sha256(payload).hexdigest()
        if digest in seen:
            rejections["duplicate_payload"] += 1
            continue
        seen.add(digest)
        candidates.append(
            {
                "payload_assignment_line": payload_line,
                "sink_line": sink_line,
                "launcher_assignment_count": len(launcher_assignments),
                "payload_size": len(payload),
                "payload_sha256": digest,
                "payload_validation": validation,
            }
        )
        artifacts.append(("batch-environment-powershell.ps1", payload))

    status = "artifacts_recovered" if artifacts else "pattern_not_found"
    if not artifacts and rejections:
        status = "candidates_rejected"
    report = _base_report(limits, status=status)
    report.update(
        {
            "encoding": encoding,
            "line_count": len(lines),
            "assignment_count": assignment_count,
            "sink_count": len(sinks),
            "work_units": work_units,
            "candidate_count": len(candidates),
            "candidate_set_complete": True,
            "candidates": candidates,
            "rejections": dict(sorted(rejections.items())),
            "evaluation_boundary": {
                "operations_used": [
                    "quoted_set_constant",
                    "known_powershell_path_fallback",
                    "exact_echo_pipe_sink",
                ],
                "environment_expansion_performed": False,
                "shell_interpretation_performed": False,
            },
        }
    )
    return report, artifacts
